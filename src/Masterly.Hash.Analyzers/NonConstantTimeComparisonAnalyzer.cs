using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using Masterly.Hash.Analyzers.Internal;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Operations;

namespace Masterly.Hash.Analyzers
{
    /// <summary>
    /// MH0002: a hash, MAC, signature, token or other secret is compared with an early-exit comparison
    /// (<c>==</c>, <c>!=</c>, <c>string.Equals</c>, <c>string.Compare[Ordinal]</c>, <c>SequenceEqual</c>).
    /// </summary>
    [DiagnosticAnalyzer(LanguageNames.CSharp)]
    public sealed class NonConstantTimeComparisonAnalyzer : DiagnosticAnalyzer
    {
        /// <summary>Diagnostic property set when the <c>CryptographicOperations.FixedTimeEquals</c> code fix applies.</summary>
        public const string FixKey = "MH0002.Fix";

        /// <summary><see cref="FixKey"/> value.</summary>
        public const string FixFixedTimeEquals = "FixedTimeEquals";

        private const int MaxUnwrapDepth = 3;

        private static readonly HashSet<string> ValuePreservingMethods = new HashSet<string>
        {
            "ToBase64String", "ToHexString", "ToHexStringLower", "GetString", "GetBytes", "ToString", "AsSpan", "AsMemory",
            "ToArray", "ToCharArray", "Trim", "TrimStart", "TrimEnd", "ToLower", "ToLowerInvariant", "ToUpper", "ToUpperInvariant",
        };

        /// <inheritdoc />
        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics { get; } =
            ImmutableArray.Create(Descriptors.NonConstantTimeComparison);

        /// <inheritdoc />
        public override void Initialize(AnalysisContext context)
        {
            context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);
            context.EnableConcurrentExecution();
            context.RegisterCompilationStartAction(start =>
            {
                Compilation compilation = start.Compilation;
                var state = new State(
                    compilation.GetTypeByMetadataName("System.Linq.Enumerable"),
                    compilation.GetTypeByMetadataName("System.MemoryExtensions"),
                    compilation.GetTypeByMetadataName("System.Span`1"),
                    compilation.GetTypeByMetadataName("System.ReadOnlySpan`1"),
                    HasFixedTimeEquals(compilation));

                start.RegisterOperationAction(AnalyzeBinary, OperationKind.Binary);
                start.RegisterOperationAction(c => AnalyzeInvocation(c, state), OperationKind.Invocation);
            });
        }

        private static bool HasFixedTimeEquals(Compilation compilation)
        {
            INamedTypeSymbol? type = compilation.GetTypeByMetadataName("System.Security.Cryptography.CryptographicOperations");
            return type != null && type.GetMembers("FixedTimeEquals").OfType<IMethodSymbol>().Any(m =>
                m.IsStatic && m.DeclaredAccessibility == Accessibility.Public && m.Parameters.Length == 2);
        }

        private static void AnalyzeBinary(OperationAnalysisContext context)
        {
            var binary = (IBinaryOperation)context.Operation;
            if (binary.OperatorKind != BinaryOperatorKind.Equals && binary.OperatorKind != BinaryOperatorKind.NotEquals)
                return;
            if (binary.LeftOperand.Type?.SpecialType != SpecialType.System_String
                || binary.RightOperand.Type?.SpecialType != SpecialType.System_String)
                return;

            Report(context, binary.Syntax, binary.OperatorKind == BinaryOperatorKind.Equals ? "==" : "!=",
                new[] { binary.LeftOperand, binary.RightOperand }, null);
        }

        private static void AnalyzeInvocation(OperationAnalysisContext context, State state)
        {
            var invocation = (IInvocationOperation)context.Operation;
            IMethodSymbol method = invocation.TargetMethod;

            if (method.ContainingType?.SpecialType == SpecialType.System_String
                && (method.Name == "Equals" || method.Name == "CompareOrdinal" || method.Name == "Compare"))
            {
                var operands = new List<IOperation>();
                if (!method.IsStatic && invocation.Instance != null)
                    operands.Add(invocation.Instance);
                foreach (IArgumentOperation argument in invocation.Arguments)
                {
                    if (argument.ArgumentKind != ArgumentKind.DefaultValue
                        && argument.Parameter?.Type.SpecialType == SpecialType.System_String)
                        operands.Add(argument.Value);
                }

                if (operands.Count >= 2)
                    Report(context, invocation.Syntax, "string." + method.Name, operands, null);
                return;
            }

            if (method.Name != "SequenceEqual" || method.TypeArguments.Length != 1)
                return;
            INamedTypeSymbol? containing = method.ContainingType;
            if (!OperationHelpers.IsType(containing, state.Enumerable) && !OperationHelpers.IsType(containing, state.MemoryExtensions))
                return;
            SpecialType element = method.TypeArguments[0].SpecialType;
            if (element != SpecialType.System_Byte && element != SpecialType.System_Char)
                return;

            IArgumentOperation[] ordered = invocation.Arguments.OrderBy(a => a.Parameter?.Ordinal ?? 0).ToArray();
            if (ordered.Length < 2)
                return;
            IOperation[] pair = { ordered[0].Value, ordered[1].Value };

            ImmutableDictionary<string, string?>? properties = null;
            if (state.HasFixedTimeEquals
                && element == SpecialType.System_Byte
                && ordered.Length == 2
                && ordered.All(a => a.ArgumentKind == ArgumentKind.Explicit)
                && pair.All(p => IsByteBuffer(OperationHelpers.Unwrap(p).Type, state))
                && (OperationHelpers.IsType(containing, state.MemoryExtensions) || pair.All(IsProvablyNotNull)))
            {
                properties = ImmutableDictionary<string, string?>.Empty.Add(FixKey, FixFixedTimeEquals);
            }

            Report(context, invocation.Syntax, "SequenceEqual", pair, properties);
        }

        /// <summary>
        /// <c>Enumerable.SequenceEqual</c> throws on a <c>null</c> array, but <c>FixedTimeEquals</c> converts it to an
        /// empty span, so a rewrite would turn "null fails" into "null equals empty" (fail open). The fix is therefore
        /// offered for <c>Enumerable.SequenceEqual</c> only when the nullable flow state proves both operands non-null
        /// (nullable context enabled, no <c>!</c> suppression). <c>MemoryExtensions.SequenceEqual</c> already works on
        /// spans, where <c>null</c> is empty, so its behavior does not change.
        /// </summary>
        private static bool IsProvablyNotNull(IOperation operand)
        {
            IOperation value = OperationHelpers.Unwrap(operand);
            if (value is IArrayCreationOperation)
                return true;
            if (!(value.Syntax is ExpressionSyntax syntax) || value.SemanticModel == null)
                return false;
            for (ExpressionSyntax e = syntax; ; )
            {
                if (e.IsKind(SyntaxKind.SuppressNullableWarningExpression))
                    return false;
                if (e is ParenthesizedExpressionSyntax parenthesized)
                {
                    e = parenthesized.Expression;
                    continue;
                }

                break;
            }

            for (SyntaxNode? parent = syntax.Parent; parent is ExpressionSyntax outer; parent = outer.Parent)
            {
                if (outer.IsKind(SyntaxKind.SuppressNullableWarningExpression))
                    return false;
                if (!(outer is ParenthesizedExpressionSyntax))
                    break;
            }

            return value.SemanticModel.GetTypeInfo(syntax).Nullability.FlowState == NullableFlowState.NotNull;
        }

        private static bool IsByteBuffer(ITypeSymbol? type, State state)
        {
            if (OperationHelpers.IsByteArray(type))
                return true;
            return type is INamedTypeSymbol named
                && named.TypeArguments.Length == 1
                && named.TypeArguments[0].SpecialType == SpecialType.System_Byte
                && (OperationHelpers.IsType(named, state.Span) || OperationHelpers.IsType(named, state.ReadOnlySpan));
        }

        private static void Report(
            OperationAnalysisContext context,
            SyntaxNode syntax,
            string comparison,
            IReadOnlyList<IOperation> operands,
            ImmutableDictionary<string, string?>? properties)
        {
            foreach (IOperation operand in operands)
            {
                if (OperationHelpers.IsNullOrEmptyConstant(operand))
                    return;
            }

            foreach (IOperation operand in operands)
            {
                string? name = FindSecretName(operand, 0);
                if (name != null)
                {
                    context.ReportDiagnostic(Diagnostic.Create(
                        Descriptors.NonConstantTimeComparison, syntax.GetLocation(), properties, name, comparison));
                    return;
                }
            }
        }

        /// <summary>
        /// The secret-looking name an operand refers to, looking through value-preserving calls such as
        /// <c>Convert.ToBase64String(hash)</c>, <c>hash.AsSpan()</c> or <c>token.Trim()</c>.
        /// </summary>
        private static string? FindSecretName(IOperation operand, int depth)
        {
            IOperation value = OperationHelpers.Unwrap(operand);

            // mac?.SequenceEqual(other): the receiver is the operand of the enclosing conditional access.
            if (value is IConditionalAccessInstanceOperation)
            {
                for (IOperation? parent = value.Parent; parent != null; parent = parent.Parent)
                {
                    if (parent is IConditionalAccessOperation conditional)
                    {
                        value = OperationHelpers.Unwrap(conditional.Operation);
                        break;
                    }
                }
            }

            ISymbol? symbol = OperationHelpers.GetReferencedSymbol(value);
            if (symbol != null && NameMatcher.Secret.IsMatch(symbol.Name))
                return symbol.Name;

            if (depth >= MaxUnwrapDepth
                || !(value is IInvocationOperation invocation)
                || !ValuePreservingMethods.Contains(invocation.TargetMethod.Name))
                return null;
            if (invocation.Instance != null)
            {
                string? fromInstance = FindSecretName(invocation.Instance, depth + 1);
                if (fromInstance != null)
                    return fromInstance;
            }

            return invocation.Arguments.Length > 0 && invocation.Arguments[0].ArgumentKind != ArgumentKind.DefaultValue
                ? FindSecretName(invocation.Arguments[0].Value, depth + 1)
                : null;
        }

        private sealed class State
        {
            public State(
                INamedTypeSymbol? enumerable,
                INamedTypeSymbol? memoryExtensions,
                INamedTypeSymbol? span,
                INamedTypeSymbol? readOnlySpan,
                bool hasFixedTimeEquals)
            {
                Enumerable = enumerable;
                MemoryExtensions = memoryExtensions;
                Span = span;
                ReadOnlySpan = readOnlySpan;
                HasFixedTimeEquals = hasFixedTimeEquals;
            }

            public INamedTypeSymbol? Enumerable { get; }
            public INamedTypeSymbol? MemoryExtensions { get; }
            public INamedTypeSymbol? Span { get; }
            public INamedTypeSymbol? ReadOnlySpan { get; }
            public bool HasFixedTimeEquals { get; }
        }
    }
}
