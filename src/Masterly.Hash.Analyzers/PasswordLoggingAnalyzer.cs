using System.Collections.Generic;
using System.Collections.Immutable;
using Masterly.Hash.Analyzers.Internal;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Operations;

namespace Masterly.Hash.Analyzers
{
    /// <summary>
    /// MH0004: a password-named string, or the result of <c>SensitiveString.Reveal()</c>, flows into
    /// Microsoft.Extensions.Logging, <c>Console.Write[Line]</c>, or <c>Debug</c>/<c>Trace</c> output, directly,
    /// through string concatenation, <c>string.Format</c>/<c>Concat</c>/<c>Join</c>, or an interpolated string.
    /// </summary>
    [DiagnosticAnalyzer(LanguageNames.CSharp)]
    public sealed class PasswordLoggingAnalyzer : DiagnosticAnalyzer
    {
        private const int MaxDepth = 8;

        /// <inheritdoc />
        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics { get; } =
            ImmutableArray.Create(Descriptors.PasswordLogged);

        /// <inheritdoc />
        public override void Initialize(AnalysisContext context)
        {
            context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);
            context.EnableConcurrentExecution();
            context.RegisterCompilationStartAction(start =>
            {
                Compilation compilation = start.Compilation;
                var state = new State(
                    compilation.GetTypeByMetadataName("Microsoft.Extensions.Logging.LoggerExtensions"),
                    compilation.GetTypeByMetadataName("Microsoft.Extensions.Logging.ILogger"),
                    compilation.GetTypeByMetadataName("System.Console"),
                    compilation.GetTypeByMetadataName("System.Diagnostics.Debug"),
                    compilation.GetTypeByMetadataName("System.Diagnostics.Trace"),
                    compilation.GetTypeByMetadataName("Masterly.Hash.SensitiveString"));
                start.RegisterOperationAction(c => AnalyzeInvocation(c, state), OperationKind.Invocation);
            });
        }

        private static void AnalyzeInvocation(OperationAnalysisContext context, State state)
        {
            var invocation = (IInvocationOperation)context.Operation;
            if (!IsSink(invocation.TargetMethod, state))
                return;

            var found = new List<(IOperation Operation, string Name)>();
            foreach (IArgumentOperation argument in invocation.Arguments)
            {
                if (argument.ArgumentKind != ArgumentKind.DefaultValue)
                    Collect(argument.Value, state, found, 0);
            }

            string sink = invocation.TargetMethod.ContainingType.Name + "." + invocation.TargetMethod.Name;
            foreach ((IOperation operation, string name) in found)
            {
                context.ReportDiagnostic(Diagnostic.Create(
                    Descriptors.PasswordLogged, operation.Syntax.GetLocation(), name, sink));
            }
        }

        private static bool IsSink(IMethodSymbol method, State state)
        {
            INamedTypeSymbol? type = method.ContainingType;
            string name = method.Name;
            if (OperationHelpers.IsType(type, state.LoggerExtensions))
                return name.StartsWith("Log", System.StringComparison.Ordinal) || name == "BeginScope";
            if (OperationHelpers.IsType(type, state.ILogger))
                return name == "Log" || name == "BeginScope";
            if (OperationHelpers.IsType(type, state.Console))
                return name == "Write" || name == "WriteLine";
            if (OperationHelpers.IsType(type, state.Debug) || OperationHelpers.IsType(type, state.Trace))
            {
                return name.StartsWith("Write", System.StringComparison.Ordinal)
                    || name.StartsWith("Trace", System.StringComparison.Ordinal)
                    || name == "Print"
                    || name == "Fail";
            }

            return false;
        }

        /// <summary>Follows the ways a string value can end up in the logged text.</summary>
        private static void Collect(IOperation operation, State state, List<(IOperation, string)> found, int depth)
        {
            if (depth > MaxDepth)
                return;
            IOperation value = OperationHelpers.Unwrap(operation);
            switch (value)
            {
                case ILocalReferenceOperation _:
                case IParameterReferenceOperation _:
                case IFieldReferenceOperation _:
                case IPropertyReferenceOperation _:
                    ISymbol? symbol = OperationHelpers.GetReferencedSymbol(value);
                    if (symbol != null && IsTextual(OperationHelpers.GetSymbolType(symbol)) && NameMatcher.Password.IsMatch(symbol.Name))
                        found.Add((value, symbol.Name));
                    return;

                case IInvocationOperation invocation:
                    CollectFromInvocation(invocation, state, found, depth);
                    return;

                // "a" + b + "c" + d ... is a left-nested tree as deep as the number of terms; flatten it iteratively
                // so a long concatenation (a logged connection string) costs one level of depth, not one per term.
                case IBinaryOperation binary when binary.OperatorKind == BinaryOperatorKind.Add:
                    var pending = new Stack<IOperation>();
                    pending.Push(binary);
                    while (pending.Count > 0)
                    {
                        IOperation term = OperationHelpers.Unwrap(pending.Pop());
                        if (term is IBinaryOperation add && add.OperatorKind == BinaryOperatorKind.Add)
                        {
                            pending.Push(add.RightOperand);
                            pending.Push(add.LeftOperand);
                        }
                        else
                        {
                            Collect(term, state, found, depth + 1);
                        }
                    }

                    return;

                case IInterpolatedStringHandlerCreationOperation handler:
                    Collect(handler.Content, state, found, depth + 1);
                    return;

                case IInterpolatedStringOperation interpolated:
                    foreach (IInterpolatedStringContentOperation part in interpolated.Parts)
                    {
                        if (part is IInterpolationOperation interpolation)
                            Collect(interpolation.Expression, state, found, depth + 1);
                        else if (part is IInterpolatedStringAppendOperation append && append.AppendCall is IInvocationOperation call)
                            CollectArguments(call, state, found, depth);
                    }

                    return;

                case IArrayCreationOperation array when array.Initializer != null:
                    foreach (IOperation element in array.Initializer.ElementValues)
                        Collect(element, state, found, depth + 1);
                    return;

                case IConditionalOperation conditional:
                    Collect(conditional.WhenTrue, state, found, depth + 1);
                    if (conditional.WhenFalse != null)
                        Collect(conditional.WhenFalse, state, found, depth + 1);
                    return;

                case ICoalesceOperation coalesce:
                    Collect(coalesce.Value, state, found, depth + 1);
                    Collect(coalesce.WhenNull, state, found, depth + 1);
                    return;
            }
        }

        private static void CollectFromInvocation(IInvocationOperation invocation, State state, List<(IOperation, string)> found, int depth)
        {
            IMethodSymbol method = invocation.TargetMethod;

            // Revealing a SensitiveString into a log defeats its redaction, whatever the variable is called.
            if (method.Name == "Reveal" && OperationHelpers.IsType(method.ContainingType, state.SensitiveString))
            {
                string name = invocation.Instance != null && OperationHelpers.GetReferencedSymbol(invocation.Instance) is ISymbol s
                    ? s.Name + ".Reveal()"
                    : "SensitiveString.Reveal()";
                found.Add((invocation, name));
                return;
            }

            // string.Format / Concat / Join copy their arguments into the result.
            if (method.ContainingType?.SpecialType == SpecialType.System_String
                && (method.Name == "Format" || method.Name == "Concat" || method.Name == "Join"))
            {
                CollectArguments(invocation, state, found, depth);
                return;
            }

            // password.ToString(), password.Trim(), password.ToCharArray(), ... on a string keep the value.
            if (invocation.Instance != null
                && invocation.Instance.Type?.SpecialType == SpecialType.System_String
                && IsTextual(method.ReturnType))
            {
                Collect(invocation.Instance, state, found, depth + 1);
                return;
            }

            // GetPassword() returning a string.
            if (IsTextual(method.ReturnType) && NameMatcher.Password.IsMatch(method.Name))
                found.Add((invocation, method.Name));
        }

        private static void CollectArguments(IInvocationOperation invocation, State state, List<(IOperation, string)> found, int depth)
        {
            foreach (IArgumentOperation argument in invocation.Arguments)
            {
                if (argument.ArgumentKind != ArgumentKind.DefaultValue)
                    Collect(argument.Value, state, found, depth + 1);
            }
        }

        private static bool IsTextual(ITypeSymbol? type) =>
            type != null
            && (type.SpecialType == SpecialType.System_String
                || (type is IArrayTypeSymbol array && array.ElementType.SpecialType == SpecialType.System_Char));

        private sealed class State
        {
            public State(
                INamedTypeSymbol? loggerExtensions,
                INamedTypeSymbol? logger,
                INamedTypeSymbol? console,
                INamedTypeSymbol? debug,
                INamedTypeSymbol? trace,
                INamedTypeSymbol? sensitiveString)
            {
                LoggerExtensions = loggerExtensions;
                ILogger = logger;
                Console = console;
                Debug = debug;
                Trace = trace;
                SensitiveString = sensitiveString;
            }

            public INamedTypeSymbol? LoggerExtensions { get; }
            public INamedTypeSymbol? ILogger { get; }
            public INamedTypeSymbol? Console { get; }
            public INamedTypeSymbol? Debug { get; }
            public INamedTypeSymbol? Trace { get; }
            public INamedTypeSymbol? SensitiveString { get; }
        }
    }
}
