using System.Collections.Immutable;
using System.Composition;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CodeActions;
using Microsoft.CodeAnalysis.CodeFixes;
using Microsoft.CodeAnalysis.CSharp.Syntax;

namespace Masterly.Hash.Analyzers.CodeFixes
{
    /// <summary>
    /// MH0006 fix: replaces <c>hasher.ComputeHash(plainText)</c> (1.x API, plaintext argument only) with
    /// <c>Password.Hash(plainText)</c>.
    /// </summary>
    [ExportCodeFixProvider(Microsoft.CodeAnalysis.LanguageNames.CSharp, Name = nameof(ObsoleteApiCodeFixProvider))]
    [Shared]
    public sealed class ObsoleteApiCodeFixProvider : CodeFixProvider
    {
        /// <summary>Title of the code action.</summary>
        public const string Title = "Use Masterly.Hash.Password.Hash";

        /// <inheritdoc />
        public override ImmutableArray<string> FixableDiagnosticIds { get; } = ImmutableArray.Create(DiagnosticIds.ObsoleteApi);

        /// <inheritdoc />
        public override FixAllProvider GetFixAllProvider() => WellKnownFixAllProviders.BatchFixer;

        /// <inheritdoc />
        public override async Task RegisterCodeFixesAsync(CodeFixContext context)
        {
            foreach (Diagnostic diagnostic in context.Diagnostics)
            {
                if (!diagnostic.Properties.TryGetValue(ObsoleteApiAnalyzer.FixKey, out string? mode)
                    || mode != ObsoleteApiAnalyzer.FixPasswordHash)
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
            if (!(root?.FindNode(diagnostic.Location.SourceSpan, getInnermostNodeForTie: true) is InvocationExpressionSyntax invocation)
                || invocation.ArgumentList.Arguments.Count != 1
                || invocation.Expression is MemberBindingExpressionSyntax)
                return null;

            return await CodeFixHelpers.TryReplaceWithStaticCallAsync(
                document,
                invocation,
                "Masterly.Hash",
                "Password",
                "Hash",
                new[] { invocation.ArgumentList.Arguments[0].Expression },
                cancellationToken).ConfigureAwait(false);
        }
    }
}
