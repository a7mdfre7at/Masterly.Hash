using System.Collections.Generic;
using System.Collections.Immutable;
using System.Globalization;
using Masterly.Hash.Analyzers.Internal;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Operations;

namespace Masterly.Hash.Analyzers
{
    /// <summary>
    /// MH0005: <c>new Rfc2898DeriveBytes(...)</c> or <c>Rfc2898DeriveBytes.Pbkdf2(...)</c> with a constant iteration
    /// count below <see cref="MinimumIterations"/>, with MD5 or SHA-1 as the PRF, or through a constructor that
    /// silently defaults to HMAC-SHA1 and/or 1,000 iterations.
    /// </summary>
    [DiagnosticAnalyzer(LanguageNames.CSharp)]
    public sealed class WeakPbkdf2Analyzer : DiagnosticAnalyzer
    {
        /// <summary>The smallest iteration count that is not reported.</summary>
        public const int MinimumIterations = 100_000;

        /// <inheritdoc />
        public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics { get; } =
            ImmutableArray.Create(Descriptors.WeakPbkdf2);

        /// <inheritdoc />
        public override void Initialize(AnalysisContext context)
        {
            context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);
            context.EnableConcurrentExecution();
            context.RegisterCompilationStartAction(start =>
            {
                INamedTypeSymbol? rfc2898 = start.Compilation.GetTypeByMetadataName("System.Security.Cryptography.Rfc2898DeriveBytes");
                if (rfc2898 == null)
                    return;
                INamedTypeSymbol? hashAlgorithmName = start.Compilation.GetTypeByMetadataName("System.Security.Cryptography.HashAlgorithmName");

                start.RegisterOperationAction(c =>
                {
                    var creation = (IObjectCreationOperation)c.Operation;
                    if (creation.Constructor != null && OperationHelpers.IsType(creation.Constructor.ContainingType, rfc2898))
                        Analyze(c, creation.Constructor, creation.Arguments, creation.Syntax, hashAlgorithmName, isConstructor: true);
                }, OperationKind.ObjectCreation);

                start.RegisterOperationAction(c =>
                {
                    var invocation = (IInvocationOperation)c.Operation;
                    IMethodSymbol method = invocation.TargetMethod;
                    if (method.IsStatic && method.Name == "Pbkdf2" && OperationHelpers.IsType(method.ContainingType, rfc2898))
                        Analyze(c, method, invocation.Arguments, invocation.Syntax, hashAlgorithmName, isConstructor: false);
                }, OperationKind.Invocation);
            });
        }

        private static void Analyze(
            OperationAnalysisContext context,
            IMethodSymbol method,
            ImmutableArray<IArgumentOperation> arguments,
            SyntaxNode syntax,
            INamedTypeSymbol? hashAlgorithmName,
            bool isConstructor)
        {
            bool hasIterations = false;
            bool hasAlgorithm = false;
            var problems = new List<string>();

            foreach (IParameterSymbol parameter in method.Parameters)
            {
                if (parameter.Type.SpecialType == SpecialType.System_Int32 && parameter.Name == "iterations")
                    hasIterations = true;
                else if (OperationHelpers.IsType(parameter.Type, hashAlgorithmName))
                    hasAlgorithm = true;
            }

            foreach (IArgumentOperation argument in arguments)
            {
                IParameterSymbol? parameter = argument.Parameter;
                if (parameter == null)
                    continue;

                if (parameter.Type.SpecialType == SpecialType.System_Int32 && parameter.Name == "iterations")
                {
                    IOperation value = argument.Value;
                    if (value.ConstantValue.HasValue && value.ConstantValue.Value is int iterations && iterations < MinimumIterations)
                    {
                        problems.Add(string.Format(
                            CultureInfo.InvariantCulture,
                            "{0:N0} iterations is below the minimum of {1:N0}",
                            iterations,
                            MinimumIterations));
                    }
                }
                else if (OperationHelpers.IsType(parameter.Type, hashAlgorithmName))
                {
                    string? weak = GetWeakAlgorithm(argument.Value, hashAlgorithmName);
                    if (weak != null)
                        problems.Add(weak + " is a weak PBKDF2 PRF; use SHA256 or SHA512");
                }
            }

            if (isConstructor && !hasIterations)
                problems.Add("this constructor defaults to 1,000 iterations");
            if (isConstructor && !hasAlgorithm)
                problems.Add("this constructor defaults to HMAC-SHA1");

            if (problems.Count > 0)
            {
                context.ReportDiagnostic(Diagnostic.Create(
                    Descriptors.WeakPbkdf2, syntax.GetLocation(), string.Join("; ", problems)));
            }
        }

        /// <summary><c>HashAlgorithmName.MD5</c> / <c>.SHA1</c>, or <c>new HashAlgorithmName("MD5"|"SHA1")</c>.</summary>
        private static string? GetWeakAlgorithm(IOperation operation, INamedTypeSymbol? hashAlgorithmName)
        {
            IOperation value = OperationHelpers.Unwrap(operation);
            string? name = null;
            if (value is IPropertyReferenceOperation property
                && property.Property.IsStatic
                && OperationHelpers.IsType(property.Property.ContainingType, hashAlgorithmName))
            {
                name = property.Property.Name;
            }
            else if (value is IObjectCreationOperation creation
                && OperationHelpers.IsType(creation.Type, hashAlgorithmName)
                && creation.Arguments.Length == 1
                && creation.Arguments[0].Value.ConstantValue.HasValue)
            {
                name = creation.Arguments[0].Value.ConstantValue.Value as string;
            }

            if (name == null)
                return null;
            string upper = name.ToUpperInvariant();
            return upper == "MD5" || upper == "SHA1" ? upper : null;
        }
    }
}
