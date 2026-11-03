using System.Collections.Immutable;
using System.Composition;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CodeActions;
using Microsoft.CodeAnalysis.CodeFixes;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Operations;

namespace Masterly.Hash.Analyzers.CodeFixes
{
    /// <summary>
    /// MH0002 fix: replaces <c>a.SequenceEqual(b)</c> on byte arrays or byte spans with
    /// <c>CryptographicOperations.FixedTimeEquals(a, b)</c>. Offered only when the compilation has that API
    /// and the edit compiles. For <c>Enumerable.SequenceEqual</c> the analyzer offers it only when both arrays are
    /// provably non-null, because <c>FixedTimeEquals</c> treats <c>null</c> as empty where <c>SequenceEqual</c> throws.
    /// </summary>
    [ExportCodeFixProvider(Microsoft.CodeAnalysis.LanguageNames.CSharp, Name = nameof(FixedTimeEqualsCodeFixProvider))]
    [Shared]
    public sealed class FixedTimeEqualsCodeFixProvider : CodeFixProvider
    {
        /// <summary>Title of the code action.</summary>
        public const string Title = "Use CryptographicOperations.FixedTimeEquals";

        /// <inheritdoc />
        public override ImmutableArray<string> FixableDiagnosticIds { get; } = ImmutableArray.Create(DiagnosticIds.NonConstantTimeComparison);

        /// <inheritdoc />
        public override FixAllProvider GetFixAllProvider() => WellKnownFixAllProviders.BatchFixer;

        /// <inheritdoc />
        public override async Task RegisterCodeFixesAsync(CodeFixContext context)
        {
            foreach (Diagnostic diagnostic in context.Diagnostics)
            {
                if (!diagnostic.Properties.TryGetValue(NonConstantTimeComparisonAnalyzer.FixKey, out string? mode)
                    || mode != NonConstantTimeComparisonAnalyzer.FixFixedTimeEquals)
                    continue;

                Document? fixedDocument = await ComputeFixAsync(context.Document, diagnostic, context.CancellationToken).ConfigureAwait(false);
                if (fixedDocument == null)
                    continue;

                context.RegisterCodeFix(
                    CodeAction.Create(Title, _ => Task.FromResult(fixedDocument), equivalenceKey: Title),
                    diagnostic);
            }
        }

        private static async Task<Document?> ComputeFixAsync(Document document, Diagnostic diagnostic, CancellationToken cancellationToken)
        {
            SyntaxNode? root = await document.GetSyntaxRootAsync(cancellationToken).ConfigureAwait(false);
            SemanticModel? model = await document.GetSemanticModelAsync(cancellationToken).ConfigureAwait(false);
            if (model == null
                || !(root?.FindNode(diagnostic.Location.SourceSpan, getInnermostNodeForTie: true) is InvocationExpressionSyntax invocationSyntax))
                return null;

            // a?.SequenceEqual(b) produces bool?; leave it alone.
            if (invocationSyntax.Expression is MemberBindingExpressionSyntax)
                return null;
            if (!(model.GetOperation(invocationSyntax, cancellationToken) is IInvocationOperation invocation)
                || invocation.Arguments.Length != 2)
                return null;

            ExpressionSyntax[] operands = invocation.Arguments
                .OrderBy(a => a.Parameter?.Ordinal ?? 0)
                .Select(a => a.Value.Syntax as ExpressionSyntax)
                .Where(e => e != null)
                .Select(e => e!)
                .ToArray();
            if (operands.Length != 2)
                return null;

            return await CodeFixHelpers.TryReplaceWithStaticCallAsync(
                document,
                invocationSyntax,
                "System.Security.Cryptography",
                "CryptographicOperations",
                "FixedTimeEquals",
                operands,
                cancellationToken).ConfigureAwait(false);
        }
    }
}
