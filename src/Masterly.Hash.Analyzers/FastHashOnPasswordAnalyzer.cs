using System.Collections.Generic;
using System.Collections.Immutable;
using System.Threading;
using Masterly.Hash.Analyzers.Internal;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Operations;

namespace Masterly.Hash.Analyzers
{
    /// <summary>
    /// MH0001: a fast hash (MD5, SHA-1, SHA-2, SHA-3, HMAC) is applied to something named like a password.
    /// </summary>
    [DiagnosticAnalyzer(LanguageNames.CSharp)]
    public sealed class FastHashOnPasswordAnalyzer : DiagnosticAnalyzer
    {
        /// <summary>Diagnostic property set when the <c>Password.Hash</c> code fix applies.</summary>
        public const string FixKey = "MH0001.Fix";

        /// <summary><see cref="FixKey"/> value: replace the hashing call itself (its result is assigned to <c>var</c>).</summary>
        public const string FixReplaceCall = "Call";

        /// <summary><see cref="FixKey"/> value: replace the byte-to-string conversion that wraps the hashing call.</summary>
        public const string FixReplaceWrapper = "Wrapper";

        private const int MaxStorageDepth = 3;

        private static readonly string[] StaticHashTypes =
        {
            "MD5", "SHA1", "SHA256", "SHA384", "SHA512", "SHA3_256", "SHA3_384", "SHA3_512",
            "HMACMD5", "HMACSHA1", "HMACSHA256", "HMACSHA384", "HMACSHA512", "HMACSHA3_256", "HMACSHA3_384", "HMACSHA3_512",
        };

        /// <inheritdoc />
        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics { get; } =
            ImmutableArray.Create(Descriptors.FastHashOnPassword);

        /// <inheritdoc />
        public override void Initialize(AnalysisContext context)
        {
            context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);
            context.EnableConcurrentExecution();
            context.RegisterCompilationStartAction(start =>
            {
                Compilation compilation = start.Compilation;
                INamedTypeSymbol? hashAlgorithm = compilation.GetTypeByMetadataName("System.Security.Cryptography.HashAlgorithm");
                INamedTypeSymbol? hmac = compilation.GetTypeByMetadataName("System.Security.Cryptography.HMAC");
                INamedTypeSymbol? keyed = compilation.GetTypeByMetadataName("System.Security.Cryptography.KeyedHashAlgorithm");
                var staticTypes = new HashSet<INamedTypeSymbol>(SymbolEqualityComparer.Default);
                foreach (string name in StaticHashTypes)
                {
                    INamedTypeSymbol? type = compilation.GetTypeByMetadataName("System.Security.Cryptography." + name);
                    if (type != null)
                        staticTypes.Add(type);
                }

                if (hashAlgorithm == null && staticTypes.Count == 0)
                    return;

                var state = new State(
                    hashAlgorithm,
                    hmac,
                    keyed,
                    staticTypes,
                    compilation.GetTypeByMetadataName("System.Text.Encoding"),
                    compilation.GetTypeByMetadataName("System.Convert"),
                    compilation.GetTypeByMetadataName("System.BitConverter"),
                    OperationHelpers.HasPasswordHash(compilation));

                start.RegisterOperationAction(c => AnalyzeInvocation(c, state), OperationKind.Invocation);
                start.RegisterOperationAction(c => AnalyzeCreation(c, state), OperationKind.ObjectCreation);
            });
        }

        private static void AnalyzeInvocation(OperationAnalysisContext context, State state)
        {
            var invocation = (IInvocationOperation)context.Operation;
            IMethodSymbol method = invocation.TargetMethod;
            string? algorithm = null;
            if (method.IsStatic)
            {
                if ((method.Name == "HashData" || method.Name == "TryHashData" || method.Name == "HashDataAsync")
                    && state.StaticTypes.Contains(method.ContainingType.OriginalDefinition))
                    algorithm = method.ContainingType.Name;
            }
            else if ((method.Name == "ComputeHash" || method.Name == "TryComputeHash" || method.Name == "ComputeHashAsync")
                && OperationHelpers.DerivesFrom(method.ContainingType, state.HashAlgorithm))
            {
                algorithm = invocation.Instance?.Type?.Name ?? method.ContainingType.Name;
            }

            if (algorithm == null)
                return;

            string? passwordName = FindPassword(invocation.Arguments, state, context.CancellationToken);
            if (passwordName == null)
                return;

            ImmutableDictionary<string, string?> properties = ImmutableDictionary<string, string?>.Empty;
            string? fix = GetFix(invocation, state);
            if (fix != null)
                properties = properties.Add(FixKey, fix);

            context.ReportDiagnostic(Diagnostic.Create(
                Descriptors.FastHashOnPassword, invocation.Syntax.GetLocation(), properties, algorithm, passwordName));
        }

        private static void AnalyzeCreation(OperationAnalysisContext context, State state)
        {
            var creation = (IObjectCreationOperation)context.Operation;
            INamedTypeSymbol? type = creation.Constructor?.ContainingType;
            if (type == null)
                return;
            bool isHmac = state.StaticTypes.Contains(type.OriginalDefinition) || OperationHelpers.DerivesFrom(type, state.Hmac);
            if (!isHmac || !OperationHelpers.DerivesFrom(type, state.HashAlgorithm))
                return;

            string? passwordName = FindPassword(creation.Arguments, state, context.CancellationToken);
            if (passwordName != null)
            {
                context.ReportDiagnostic(Diagnostic.Create(
                    Descriptors.FastHashOnPassword, creation.Syntax.GetLocation(), type.Name, passwordName));
            }
        }

        private static string? FindPassword(ImmutableArray<IArgumentOperation> arguments, State state, CancellationToken cancellationToken)
        {
            foreach (IArgumentOperation argument in arguments)
            {
                if (argument.ArgumentKind == ArgumentKind.DefaultValue || IsOutputParameter(argument.Parameter))
                    continue;
                IOperation value = OperationHelpers.Unwrap(argument.Value);
                string? name = FindPasswordIn(value);
                if (name != null)
                    return name;

                // byte[] bytes = Encoding.UTF8.GetBytes(password); SHA256.HashData(bytes);
                if (value is ILocalReferenceOperation local
                    && GetLocalInitializer(local, cancellationToken) is IInvocationOperation init
                    && OperationHelpers.IsEncodingGetBytes(init, state.Encoding))
                {
                    name = FindPasswordIn(init.Arguments[0].Value);
                    if (name != null)
                        return name;
                }
            }

            return null;
        }

        /// <summary>
        /// Output buffers (<c>destination</c> of <c>HashData(source, destination)</c>, <c>out bytesWritten</c>) receive the
        /// digest; their names say nothing about what is hashed.
        /// </summary>
        private static bool IsOutputParameter(IParameterSymbol? parameter) =>
            parameter != null
            && (parameter.RefKind == RefKind.Out
                || parameter.RefKind == RefKind.Ref
                || parameter.Name == "destination"
                || parameter.Name == "cancellationToken");

        private static string? FindPasswordIn(IOperation operation)
        {
            foreach (IOperation descendant in OperationHelpers.DescendantsAndSelf(operation))
            {
                ISymbol? symbol = OperationHelpers.GetReferencedSymbol(descendant);
                if (symbol != null && NameMatcher.Password.IsMatch(symbol.Name))
                    return symbol.Name;
            }

            return null;
        }

        private static IOperation? GetLocalInitializer(ILocalReferenceOperation local, CancellationToken cancellationToken)
        {
            SemanticModel? model = local.SemanticModel;
            if (model == null)
                return null;
            foreach (SyntaxReference reference in local.Local.DeclaringSyntaxReferences)
            {
                if (reference.SyntaxTree != model.SyntaxTree)
                    continue;
                if (reference.GetSyntax(cancellationToken) is VariableDeclaratorSyntax declarator && declarator.Initializer != null)
                {
                    IOperation? init = model.GetOperation(declarator.Initializer.Value, cancellationToken);
                    return init == null ? null : OperationHelpers.Unwrap(init);
                }
            }

            return null;
        }

        /// <summary>
        /// The <c>Password.Hash(x)</c> fix applies to <c>H(Encoding.X.GetBytes(x))</c> where the result is either
        /// converted to a string (<c>Convert.ToBase64String</c>, <c>Convert.ToHexString</c>, <c>BitConverter.ToString</c>)
        /// or assigned to an implicitly typed local; in both cases the string returned by <c>Password.Hash</c> type-checks.
        /// <para>
        /// <c>Password.Hash</c> is salted with fresh randomness, so it is only a drop-in replacement where the value is
        /// being produced for storage: returned, assigned to a field, property or local, or used to initialize one.
        /// When the value is compared (<c>stored == Convert.ToBase64String(H(...))</c>), passed to another call (a
        /// pre-hash fed to another hasher, a database query), or the local holding it is, the rewrite would compile but
        /// never match again, so no fix is offered. Keyed hashes (HMAC) are not rewritten either: that would silently
        /// drop the key.
        /// </para>
        /// </summary>
        private static string? GetFix(IInvocationOperation hash, State state)
        {
            if (!state.HasPasswordHash || hash.TargetMethod.Name == "TryHashData" || hash.TargetMethod.Name == "TryComputeHash")
                return null;
            if (hash.Arguments.Length != 1 || !OperationHelpers.IsByteArray(hash.Type))
                return null;
            if (OperationHelpers.DerivesFrom(hash.TargetMethod.ContainingType, state.KeyedHashAlgorithm)
                || (hash.Instance != null && OperationHelpers.DerivesFrom(hash.Instance.Type, state.KeyedHashAlgorithm)))
                return null;
            if (!(hash.Syntax is InvocationExpressionSyntax hashSyntax) || hashSyntax.ArgumentList.Arguments.Count != 1)
                return null;
            if (!(OperationHelpers.Unwrap(hash.Arguments[0].Value) is IInvocationOperation getBytes)
                || !OperationHelpers.IsEncodingGetBytes(getBytes, state.Encoding)
                || getBytes.Syntax != hashSyntax.ArgumentList.Arguments[0].Expression
                || !(getBytes.Syntax is InvocationExpressionSyntax getBytesSyntax)
                || getBytesSyntax.ArgumentList.Arguments.Count != 1)
                return null;

            // Convert.ToBase64String(H(...)) and friends.
            IOperation? parent = hash.Parent;
            if (parent is IArgumentOperation argument && argument.Parent is IInvocationOperation wrapper && IsStringWrapper(wrapper, state)
                && hashSyntax.Parent is ArgumentSyntax argumentSyntax && argumentSyntax.Parent?.Parent == wrapper.Syntax)
                return IsStorageUse(wrapper, 0) ? FixReplaceWrapper : null;

            // var hash = H(...);
            if (hashSyntax.Parent is EqualsValueClauseSyntax equals
                && equals.Parent is VariableDeclaratorSyntax declarator
                && declarator.Parent is VariableDeclarationSyntax declaration
                && declaration.Type.IsVar
                && declaration.Variables.Count == 1
                && declaration.Parent is LocalDeclarationStatementSyntax)
            {
                return IsStorageUse(hash, 0) ? FixReplaceCall : null;
            }

            return null;
        }

        /// <summary>
        /// True when the value of <paramref name="operation"/> only flows into storage: it is returned, assigned to a
        /// field or property, or held in a local whose every use is itself a storage use. Anything else (an operand of
        /// <c>==</c>, a receiver or argument of <c>Equals</c>, <c>Compare</c>, <c>SequenceEqual</c> or any other call)
        /// means the value is consumed in a way that a randomly salted <c>Password.Hash</c> would break.
        /// </summary>
        private static bool IsStorageUse(IOperation operation, int depth)
        {
            if (depth > MaxStorageDepth)
                return false;

            IOperation current = operation;
            while (current.Parent is IConversionOperation conversion)
                current = conversion;

            switch (current.Parent)
            {
                // A member that returns the hash stores it; a lambda (users.Where(u => ...), Func<string, string>
                // legacy hasher) or local function usually feeds it straight into a comparison, so it does not count.
                case IReturnOperation ret:
                    for (IOperation? ancestor = ret.Parent; ancestor != null; ancestor = ancestor.Parent)
                    {
                        if (ancestor is IAnonymousFunctionOperation || ancestor is ILocalFunctionOperation)
                            return false;
                    }

                    return true;

                case ISimpleAssignmentOperation assignment when assignment.Value == current:
                    if (!(assignment.Parent is IExpressionStatementOperation))
                        return false;
                    switch (assignment.Target)
                    {
                        case IFieldReferenceOperation _:
                            return true;
                        case IPropertyReferenceOperation property:
                            return !property.Property.IsIndexer;
                        case ILocalReferenceOperation local:
                            return LocalUsesAreStorage(assignment, local.Local, depth);
                        default:
                            return false;
                    }

                case IVariableInitializerOperation initializer:
                    return initializer.Parent is IVariableDeclaratorOperation declarator
                        && LocalUsesAreStorage(initializer, declarator.Symbol, depth);

                // `static readonly string H = Hash(...)` / `public string H { get; } = Hash(...)`: stored in a member.
                case IFieldInitializerOperation _:
                case IPropertyInitializerOperation _:
                    return true;

                default:
                    return false;
            }
        }

        private static bool LocalUsesAreStorage(IOperation origin, ILocalSymbol local, int depth)
        {
            IOperation root = origin;
            while (root.Parent != null)
                root = root.Parent;

            foreach (IOperation descendant in OperationHelpers.DescendantsAndSelf(root))
            {
                if (!(descendant is ILocalReferenceOperation reference)
                    || reference.IsDeclaration
                    || !SymbolEqualityComparer.Default.Equals(reference.Local, local))
                    continue;

                // h = ...; overwrites the value rather than reading it.
                if (reference.Parent is ISimpleAssignmentOperation write && write.Target == reference)
                    continue;
                if (!IsStorageUse(reference, depth + 1))
                    return false;
            }

            return true;
        }

        private static bool IsStringWrapper(IInvocationOperation wrapper, State state)
        {
            if (wrapper.Arguments.Length != 1 || wrapper.Type?.SpecialType != SpecialType.System_String)
                return false;
            INamedTypeSymbol type = wrapper.TargetMethod.ContainingType;
            string name = wrapper.TargetMethod.Name;
            if (OperationHelpers.IsType(type, state.Convert))
                return name == "ToBase64String" || name == "ToHexString" || name == "ToHexStringLower";
            return OperationHelpers.IsType(type, state.BitConverter) && name == "ToString";
        }

        private sealed class State
        {
            public State(
                INamedTypeSymbol? hashAlgorithm,
                INamedTypeSymbol? hmac,
                INamedTypeSymbol? keyedHashAlgorithm,
                HashSet<INamedTypeSymbol> staticTypes,
                INamedTypeSymbol? encoding,
                INamedTypeSymbol? convert,
                INamedTypeSymbol? bitConverter,
                bool hasPasswordHash)
            {
                HashAlgorithm = hashAlgorithm;
                Hmac = hmac;
                KeyedHashAlgorithm = keyedHashAlgorithm;
                StaticTypes = staticTypes;
                Encoding = encoding;
                Convert = convert;
                BitConverter = bitConverter;
                HasPasswordHash = hasPasswordHash;
            }

            public INamedTypeSymbol? HashAlgorithm { get; }
            public INamedTypeSymbol? Hmac { get; }
            public INamedTypeSymbol? KeyedHashAlgorithm { get; }
            public HashSet<INamedTypeSymbol> StaticTypes { get; }
            public INamedTypeSymbol? Encoding { get; }
            public INamedTypeSymbol? Convert { get; }
            public INamedTypeSymbol? BitConverter { get; }
            public bool HasPasswordHash { get; }
        }
    }
}
