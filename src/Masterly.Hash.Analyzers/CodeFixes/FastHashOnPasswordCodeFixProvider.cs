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
    /// MH0001 fix: replaces <c>Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(password)))</c> (or
    /// <c>var h = SHA256.HashData(Encoding.UTF8.GetBytes(password));</c>) with <c>Password.Hash(password)</c>.
    /// Offered only when the result is consumed as a string or an implicitly typed local, the edit compiles, the
    /// value only flows into storage (never into a comparison, where a randomly salted hash would never match), and
    /// the hash is not keyed (rewriting an HMAC would drop the key). The analyzer decides this and sets the property.
    /// </summary>
    [ExportCodeFixProvider(Microsoft.CodeAnalysis.LanguageNames.CSharp, Name = nameof(FastHashOnPasswordCodeFixProvider))]
    [Shared]
    public sealed class FastHashOnPasswordCodeFixProvider : CodeFixProvider
    {
        /// <summary>Title of the code action.</summary>
        public const string Title = "Use Masterly.Hash.Password.Hash";

        /// <inheritdoc />
        public override ImmutableArray<string> FixableDiagnosticIds { get; } = ImmutableArray.Create(DiagnosticIds.FastHashOnPassword);

        /// <inheritdoc />
        public override FixAllProvider GetFixAllProvider() => WellKnownFixAllProviders.BatchFixer;

        /// <inheritdoc />
        public override async Task RegisterCodeFixesAsync(CodeFixContext context)
        {
            foreach (Diagnostic diagnostic in context.Diagnostics)
            {
                if (!diagnostic.Properties.TryGetValue(FastHashOnPasswordAnalyzer.FixKey, out string? mode) || mode == null)
                    continue;

                Document? fixedDocument = await ComputeFixAsync(context.Document, diagnostic, mode, context.CancellationToken).ConfigureAwait(false);
                if (fixedDocument == null)
                    continue;

                context.RegisterCodeFix(
                    CodeAction.Create(Title, _ => Task.FromResult(fixedDocument), equivalenceKey: Title),
                    diagnostic);
            }
        }

        private static async Task<Document?> ComputeFixAsync(Document document, Diagnostic diagnostic, string mode, CancellationToken cancellationToken)
        {
            SyntaxNode? root = await document.GetSyntaxRootAsync(cancellationToken).ConfigureAwait(false);
            if (!(root?.FindNode(diagnostic.Location.SourceSpan, getInnermostNodeForTie: true) is InvocationExpressionSyntax hash))
                return null;
            if (hash.ArgumentList.Arguments.Count != 1
                || !(hash.ArgumentList.Arguments[0].Expression is InvocationExpressionSyntax getBytes)
                || getBytes.ArgumentList.Arguments.Count != 1)
                return null;

            SyntaxNode target = hash;
            if (mode == FastHashOnPasswordAnalyzer.FixReplaceWrapper)
            {
                if (!(hash.Parent is ArgumentSyntax argument
                    && argument.Parent is ArgumentListSyntax list
                    && list.Parent is InvocationExpressionSyntax wrapper))
                    return null;
                target = wrapper;
            }
            else if (mode != FastHashOnPasswordAnalyzer.FixReplaceCall)
            {
                return null;
            }

            return await CodeFixHelpers.TryReplaceWithStaticCallAsync(
                document,
                target,
                "Masterly.Hash",
                "Password",
                "Hash",
                new[] { getBytes.ArgumentList.Arguments[0].Expression },
                cancellationToken).ConfigureAwait(false);
        }
    }
}
