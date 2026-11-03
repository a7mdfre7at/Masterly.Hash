using System.Collections.Immutable;
using System.Linq;
using Masterly.Hash.Analyzers.Internal;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Operations;

namespace Masterly.Hash.Analyzers
{
    /// <summary>
    /// MH0006 (Info): a call to the Masterly.Hash 1.x <c>Hash.ComputeHash</c> / <c>IHash.ComputeHash</c>, which
    /// produces a single-pass salted SHA-2 hash.
    /// </summary>
    [DiagnosticAnalyzer(LanguageNames.CSharp)]
    public sealed class ObsoleteApiAnalyzer : DiagnosticAnalyzer
    {
        /// <summary>Diagnostic property set when the <c>Password.Hash(plainText)</c> code fix applies.</summary>
        public const string FixKey = "MH0006.Fix";

        /// <summary><see cref="FixKey"/> value.</summary>
        public const string FixPasswordHash = "PasswordHash";

        /// <inheritdoc />
        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics { get; } =
            ImmutableArray.Create(Descriptors.ObsoleteApi);

        /// <inheritdoc />
        public override void Initialize(AnalysisContext context)
        {
            context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);
            context.EnableConcurrentExecution();
            context.RegisterCompilationStartAction(start =>
            {
                Compilation compilation = start.Compilation;
                INamedTypeSymbol? hash = compilation.GetTypeByMetadataName("Masterly.Hash.Hash");
                INamedTypeSymbol? iHash = compilation.GetTypeByMetadataName("Masterly.Hash.IHash");
                if (hash == null && iHash == null)
                    return;
                bool hasPasswordHash = OperationHelpers.HasPasswordHash(compilation);

                start.RegisterOperationAction(c =>
                {
                    var invocation = (IInvocationOperation)c.Operation;
                    IMethodSymbol method = invocation.TargetMethod;
                    if (method.Name != "ComputeHash" || method.IsStatic)
                        return;
                    INamedTypeSymbol? containing = method.ContainingType;
                    if (!OperationHelpers.DerivesFrom(containing, hash) && !OperationHelpers.IsType(containing, iHash))
                        return;

                    ImmutableDictionary<string, string?> properties = ImmutableDictionary<string, string?>.Empty;
                    int explicitArguments = invocation.Arguments.Count(a => a.ArgumentKind != ArgumentKind.DefaultValue);
                    if (hasPasswordHash
                        && explicitArguments == 1
                        && invocation.Arguments.Any(a => a.ArgumentKind == ArgumentKind.Explicit && a.Parameter?.Ordinal == 0)
                        && method.ReturnType.SpecialType == SpecialType.System_String)
                    {
                        properties = properties.Add(FixKey, FixPasswordHash);
                    }

                    c.ReportDiagnostic(Diagnostic.Create(
                        Descriptors.ObsoleteApi,
                        invocation.Syntax.GetLocation(),
                        properties,
                        containing!.Name + ".ComputeHash",
                        "Password.Hash"));
                }, OperationKind.Invocation);
            });
        }
    }
}
