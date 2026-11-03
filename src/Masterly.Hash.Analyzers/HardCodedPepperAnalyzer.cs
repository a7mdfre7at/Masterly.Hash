using System.Collections.Immutable;
using Masterly.Hash.Analyzers.Internal;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Operations;

namespace Masterly.Hash.Analyzers
{
    /// <summary>
    /// MH0003: a string literal, constant byte array, UTF-8 literal or <c>Convert.FromBase64String(literal)</c> is
    /// passed to <c>Masterly.Hash.Pepper.HmacPepper</c> or assigned to something named pepper, hmacKey, secretKey
    /// or signingKey, or returned from a property or method with such a name. Literal fallbacks
    /// (<c>env ?? "dev-pepper"</c>, <c>cond ? literal : other</c>) count, and so does a zero-filled
    /// <c>new byte[32]</c> passed directly as <c>HmacPepper</c> key material.
    /// </summary>
    [DiagnosticAnalyzer(LanguageNames.CSharp)]
    public sealed class HardCodedPepperAnalyzer : DiagnosticAnalyzer
    {
        /// <inheritdoc />
        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics { get; } =
            ImmutableArray.Create(Descriptors.HardCodedPepper);

        /// <inheritdoc />
        public override void Initialize(AnalysisContext context)
        {
            context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);
            context.EnableConcurrentExecution();
            context.RegisterCompilationStartAction(start =>
            {
                Compilation compilation = start.Compilation;
                var state = new State(
                    compilation.GetTypeByMetadataName("Masterly.Hash.Pepper.HmacPepper"),
                    compilation.GetTypeByMetadataName("System.Convert"),
                    compilation.GetTypeByMetadataName("System.Text.Encoding"));

                if (state.HmacPepper != null)
                {
                    start.RegisterOperationAction(c => AnalyzePepperCreation(c, state), OperationKind.ObjectCreation);
                    start.RegisterOperationAction(c => AnalyzePepperFactory(c, state), OperationKind.Invocation);
                }

                start.RegisterOperationAction(c => AnalyzeDeclarator(c, state), OperationKind.VariableDeclarator);
                start.RegisterOperationAction(c => AnalyzeFieldInitializer(c, state), OperationKind.FieldInitializer);
                start.RegisterOperationAction(c => AnalyzePropertyInitializer(c, state), OperationKind.PropertyInitializer);
                start.RegisterOperationAction(c => AnalyzeAssignment(c, state), OperationKind.SimpleAssignment);
                start.RegisterOperationAction(c => AnalyzeReturn(c, state), OperationKind.Return);
            });
        }

        private static void AnalyzePepperCreation(OperationAnalysisContext context, State state)
        {
            var creation = (IObjectCreationOperation)context.Operation;
            if (!OperationHelpers.IsType(creation.Constructor?.ContainingType, state.HmacPepper))
                return;
            AnalyzePepperArguments(context, creation.Arguments, state);
        }

        private static void AnalyzePepperFactory(OperationAnalysisContext context, State state)
        {
            var invocation = (IInvocationOperation)context.Operation;
            if (invocation.TargetMethod.IsStatic
                && invocation.TargetMethod.Name == "FromBase64"
                && OperationHelpers.IsType(invocation.TargetMethod.ContainingType, state.HmacPepper))
                AnalyzePepperArguments(context, invocation.Arguments, state);
        }

        private static void AnalyzePepperArguments(OperationAnalysisContext context, ImmutableArray<IArgumentOperation> arguments, State state)
        {
            foreach (IArgumentOperation argument in arguments)
            {
                ITypeSymbol? parameterType = argument.Parameter?.Type;
                if (parameterType == null || argument.ArgumentKind == ArgumentKind.DefaultValue)
                    continue;

                // The key id ("k1") is an identifier, not a secret.
                if (parameterType.SpecialType == SpecialType.System_String)
                    continue;

                if (OperationHelpers.IsByteArray(parameterType))
                {
                    if (IsHardCoded(argument.Value, state, zeroFilledArrayIsKey: true))
                        Report(context, argument.Value, "pepper key");
                    continue;
                }

                // IReadOnlyDictionary<string, byte[]> / IReadOnlyDictionary<string, string>: inspect the values.
                if (OperationHelpers.Unwrap(argument.Value) is IObjectCreationOperation dictionary && dictionary.Initializer != null)
                {
                    foreach (IOperation initializer in dictionary.Initializer.Initializers)
                    {
                        IOperation? value = initializer switch
                        {
                            ISimpleAssignmentOperation assignment => assignment.Value,
                            IInvocationOperation add when add.Arguments.Length > 0 => add.Arguments[add.Arguments.Length - 1].Value,
                            _ => null,
                        };
                        if (value != null && IsHardCoded(value, state, zeroFilledArrayIsKey: true))
                            Report(context, value, "pepper key");
                    }
                }
            }
        }

        private static void AnalyzeDeclarator(OperationAnalysisContext context, State state)
        {
            var declarator = (IVariableDeclaratorOperation)context.Operation;
            IOperation? value = declarator.Initializer?.Value;
            if (value == null && declarator.Parent is IVariableDeclarationOperation declaration)
                value = declaration.Initializer?.Value;
            if (value != null && NameMatcher.Key.IsMatch(declarator.Symbol.Name) && IsHardCoded(value, state))
                Report(context, value, "'" + declarator.Symbol.Name + "'");
        }

        private static void AnalyzeFieldInitializer(OperationAnalysisContext context, State state)
        {
            var initializer = (IFieldInitializerOperation)context.Operation;
            foreach (IFieldSymbol field in initializer.InitializedFields)
            {
                if (NameMatcher.Key.IsMatch(field.Name) && IsHardCoded(initializer.Value, state))
                {
                    Report(context, initializer.Value, "'" + field.Name + "'");
                    return;
                }
            }
        }

        private static void AnalyzePropertyInitializer(OperationAnalysisContext context, State state)
        {
            var initializer = (IPropertyInitializerOperation)context.Operation;
            foreach (IPropertySymbol property in initializer.InitializedProperties)
            {
                if (NameMatcher.Key.IsMatch(property.Name) && IsHardCoded(initializer.Value, state))
                {
                    Report(context, initializer.Value, "'" + property.Name + "'");
                    return;
                }
            }
        }

        private static void AnalyzeAssignment(OperationAnalysisContext context, State state)
        {
            var assignment = (ISimpleAssignmentOperation)context.Operation;
            ISymbol? target = assignment.Target switch
            {
                ILocalReferenceOperation local => local.Local,
                IFieldReferenceOperation field => field.Field,
                IPropertyReferenceOperation property when !property.Property.IsIndexer => property.Property,
                _ => null,
            };
            if (target != null && NameMatcher.Key.IsMatch(target.Name) && IsHardCoded(assignment.Value, state))
                Report(context, assignment.Value, "'" + target.Name + "'");
        }

        /// <summary><c>static byte[] Pepper => Convert.FromBase64String("...");</c> and <c>string GetSigningKey() { return "..."; }</c>.</summary>
        private static void AnalyzeReturn(OperationAnalysisContext context, State state)
        {
            var ret = (IReturnOperation)context.Operation;
            if (ret.ReturnedValue == null)
                return;

            // A return inside a lambda or local function belongs to that function, not to the containing member.
            for (IOperation? ancestor = ret.Parent; ancestor != null; ancestor = ancestor.Parent)
            {
                if (ancestor is IAnonymousFunctionOperation || ancestor is ILocalFunctionOperation)
                    return;
            }

            if (!(context.ContainingSymbol is IMethodSymbol method))
                return;
            string name = method.AssociatedSymbol is IPropertySymbol property ? property.Name : method.Name;
            if (NameMatcher.Key.IsMatch(name) && IsHardCoded(ret.ReturnedValue, state))
                Report(context, ret.ReturnedValue, "'" + name + "'");
        }

        private static void Report(OperationAnalysisContext context, IOperation value, string what) =>
            context.ReportDiagnostic(Diagnostic.Create(Descriptors.HardCodedPepper, value.Syntax.GetLocation(), what));

        /// <summary>
        /// True for values fixed at compile time: non-empty string constants, arrays whose elements are all
        /// constants, collection expressions of literals, <c>"..."u8</c>, and <c>Convert.FromBase64String</c>,
        /// <c>Convert.FromHexString</c> or <c>Encoding.X.GetBytes</c> applied to one of those. A <c>??</c> fallback or
        /// either branch of a conditional that is hard-coded counts too: a missing environment variable must not
        /// silently fall back to a key that ships in the binary.
        /// <para>
        /// With <paramref name="zeroFilledArrayIsKey"/>, <c>new byte[N]</c> without an initializer (an all-zero key)
        /// also counts. That is only used where the array is the key material itself (an <c>HmacPepper</c>
        /// argument); a local named <c>pepper</c> created as <c>new byte[32]</c> is normally filled with random bytes
        /// next, so it is not reported.
        /// </para>
        /// </summary>
        internal static bool IsHardCoded(IOperation operation, State state, bool zeroFilledArrayIsKey = false) =>
            IsHardCoded(operation, state, zeroFilledArrayIsKey, 0);

        private const int MaxDepth = 8;

        private static bool IsHardCoded(IOperation operation, State state, bool zeroFilledArrayIsKey, int depth)
        {
            if (depth > MaxDepth)
                return false;

            if (operation.Syntax is CollectionExpressionSyntax collection)
                return IsLiteralCollection(collection);

            IOperation value = OperationHelpers.Unwrap(operation);
            if (value.Syntax is CollectionExpressionSyntax innerCollection)
                return IsLiteralCollection(innerCollection);

            if (value.ConstantValue.HasValue)
                return value.ConstantValue.Value is string s && s.Length > 0;

            switch (value)
            {
                case IUtf8StringOperation utf8:
                    return utf8.Value.Length > 0;

                case ICoalesceOperation coalesce:
                    return IsHardCoded(coalesce.WhenNull, state, zeroFilledArrayIsKey, depth + 1);

                case IConditionalOperation conditional when conditional.WhenFalse != null:
                    return IsHardCoded(conditional.WhenTrue, state, zeroFilledArrayIsKey, depth + 1)
                        || IsHardCoded(conditional.WhenFalse, state, zeroFilledArrayIsKey, depth + 1);

                case IArrayCreationOperation array:
                    if (array.Initializer == null)
                        return zeroFilledArrayIsKey && IsPositiveConstantLength(array);
                    if (array.Initializer.ElementValues.Length == 0)
                        return false;
                    foreach (IOperation element in array.Initializer.ElementValues)
                    {
                        if (!element.ConstantValue.HasValue)
                            return false;
                    }

                    return true;

                case IInvocationOperation invocation:
                    IMethodSymbol method = invocation.TargetMethod;
                    if (method.Name == "ToArray" && invocation.Instance != null)
                        return IsHardCoded(invocation.Instance, state, zeroFilledArrayIsKey: false, depth + 1);
                    if (invocation.Arguments.Length != 1)
                        return false;
                    bool decodes =
                        (OperationHelpers.IsType(method.ContainingType, state.Convert)
                            && (method.Name == "FromBase64String" || method.Name == "FromHexString"))
                        || OperationHelpers.IsEncodingGetBytes(invocation, state.Encoding);
                    return decodes && IsHardCoded(invocation.Arguments[0].Value, state, zeroFilledArrayIsKey: false, depth + 1);

                default:
                    return false;
            }
        }

        private static bool IsPositiveConstantLength(IArrayCreationOperation array) =>
            array.DimensionSizes.Length == 1
            && array.DimensionSizes[0].ConstantValue.HasValue
            && array.DimensionSizes[0].ConstantValue.Value is int length
            && length > 0;

        private static bool IsLiteralCollection(CollectionExpressionSyntax collection)
        {
            if (collection.Elements.Count == 0)
                return false;
            foreach (CollectionElementSyntax element in collection.Elements)
            {
                if (!(element is ExpressionElementSyntax expression) || !IsLiteral(expression.Expression))
                    return false;
            }

            return true;
        }

        private static bool IsLiteral(ExpressionSyntax expression)
        {
            while (expression is CastExpressionSyntax cast)
                expression = cast.Expression;
            return expression is LiteralExpressionSyntax
                || (expression is PrefixUnaryExpressionSyntax unary
                    && unary.IsKind(SyntaxKind.UnaryMinusExpression)
                    && unary.Operand is LiteralExpressionSyntax);
        }

        internal sealed class State
        {
            public State(INamedTypeSymbol? hmacPepper, INamedTypeSymbol? convert, INamedTypeSymbol? encoding)
            {
                HmacPepper = hmacPepper;
                Convert = convert;
                Encoding = encoding;
            }

            public INamedTypeSymbol? HmacPepper { get; }
            public INamedTypeSymbol? Convert { get; }
            public INamedTypeSymbol? Encoding { get; }
        }
    }
}
