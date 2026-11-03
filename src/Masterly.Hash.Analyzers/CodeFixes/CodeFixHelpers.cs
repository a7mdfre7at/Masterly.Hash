using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Simplification;

namespace Masterly.Hash.Analyzers.CodeFixes
{
    internal static class CodeFixHelpers
    {
        /// <summary>
        /// Replaces <paramref name="target"/> with <c>global::{ns}.{type}.{method}(arguments)</c>, adding
        /// <c>using {ns};</c> when the simple type name is not already in scope and would not bind to something else.
        /// The qualified name carries <see cref="Simplifier.Annotation"/>, so it is shortened only where that is safe.
        /// Returns <c>null</c> when the edit would add compiler errors, so a fix is never offered that does not type-check.
        /// </summary>
        public static async Task<Document?> TryReplaceWithStaticCallAsync(
            Document document,
            SyntaxNode target,
            string namespaceName,
            string typeName,
            string methodName,
            IReadOnlyList<ExpressionSyntax> arguments,
            CancellationToken cancellationToken)
        {
            SyntaxNode? root = await document.GetSyntaxRootAsync(cancellationToken).ConfigureAwait(false);
            SemanticModel? model = await document.GetSemanticModelAsync(cancellationToken).ConfigureAwait(false);
            if (root == null || model == null)
                return null;

            ExpressionSyntax typeExpression = SyntaxFactory.ParseExpression("global::" + namespaceName + "." + typeName)
                .WithAdditionalAnnotations(Simplifier.Annotation);
            ExpressionSyntax replacement = SyntaxFactory.InvocationExpression(
                    SyntaxFactory.MemberAccessExpression(
                        SyntaxKind.SimpleMemberAccessExpression, typeExpression, SyntaxFactory.IdentifierName(methodName)),
                    SyntaxFactory.ArgumentList(SyntaxFactory.SeparatedList(
                        arguments.Select(a => SyntaxFactory.Argument(a.WithoutTrivia())))))
                .WithTriviaFrom(target);

            SyntaxNode replaced = root.ReplaceNode(target, replacement);
            int errorsBefore = CountErrors(model, cancellationToken);

            if (NeedsUsing(model, target.SpanStart, namespaceName + "." + typeName, typeName, cancellationToken)
                && AddUsing(replaced, namespaceName) is SyntaxNode withUsing)
            {
                Document? candidate = await SimplifyIfCompilesAsync(document.WithSyntaxRoot(withUsing), errorsBefore, cancellationToken).ConfigureAwait(false);
                if (candidate != null)
                    return candidate;
            }

            return await SimplifyIfCompilesAsync(document.WithSyntaxRoot(replaced), errorsBefore, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>Shortens the annotated name where that binds to the same symbol, then checks for new errors.</summary>
        private static async Task<Document?> SimplifyIfCompilesAsync(Document document, int errorsBefore, CancellationToken cancellationToken)
        {
            Document simplified = await Simplifier.ReduceAsync(document, Simplifier.Annotation, cancellationToken: cancellationToken).ConfigureAwait(false);
            SemanticModel? model = await simplified.GetSemanticModelAsync(cancellationToken).ConfigureAwait(false);
            return model != null && CountErrors(model, cancellationToken) <= errorsBefore ? simplified : null;
        }

        private static int CountErrors(SemanticModel model, CancellationToken cancellationToken) =>
            model.GetDiagnostics(cancellationToken: cancellationToken).Count(d => d.Severity == DiagnosticSeverity.Error);

        /// <summary>True when <paramref name="simpleName"/> binds to nothing at <paramref name="position"/>.</summary>
        private static bool NeedsUsing(SemanticModel model, int position, string metadataName, string simpleName, CancellationToken cancellationToken)
        {
            SymbolInfo info = model.GetSpeculativeSymbolInfo(
                position, SyntaxFactory.IdentifierName(simpleName), SpeculativeBindingOption.BindAsExpression);
            if (info.Symbol != null || info.CandidateSymbols.Length > 0)
                return false;
            INamedTypeSymbol? type = model.Compilation.GetTypeByMetadataName(metadataName);
            cancellationToken.ThrowIfCancellationRequested();
            return type != null;
        }

        /// <summary>
        /// Adds <c>using {ns};</c> next to the existing usings (compilation unit, or the first namespace that has
        /// usings), keeping System-first alphabetical order. Returns null if the using already exists there.
        /// </summary>
        private static SyntaxNode? AddUsing(SyntaxNode root, string namespaceName)
        {
            if (!(root is CompilationUnitSyntax unit))
                return null;

            SyntaxTrivia newLine = root.DescendantTrivia().FirstOrDefault(t => t.IsKind(SyntaxKind.EndOfLineTrivia));
            if (newLine == default)
                newLine = SyntaxFactory.CarriageReturnLineFeed;

            UsingDirectiveSyntax directive = SyntaxFactory.UsingDirective(SyntaxFactory.ParseName(namespaceName))
                .NormalizeWhitespace()
                .WithTrailingTrivia(newLine);

            BaseNamespaceDeclarationSyntax? ns = unit.Usings.Count == 0
                ? unit.DescendantNodes().OfType<BaseNamespaceDeclarationSyntax>().FirstOrDefault(n => n.Usings.Count > 0)
                : null;

            SyntaxList<UsingDirectiveSyntax> usings = ns?.Usings ?? unit.Usings;
            if (usings.Any(u => u.Alias == null && u.StaticKeyword.IsKind(SyntaxKind.None) && u.Name?.ToString() == namespaceName))
                return null;

            int index = 0;
            while (index < usings.Count && Compare(usings[index], namespaceName) < 0)
                index++;

            // Match the neighbour's indentation (usings inside a block namespace are indented).
            if (usings.Count > 0)
            {
                SyntaxTriviaList neighbour = usings[Math.Min(index, usings.Count - 1)].GetLeadingTrivia();
                int start = neighbour.Count;
                while (start > 0 && neighbour[start - 1].IsKind(SyntaxKind.WhitespaceTrivia))
                    start--;
                directive = directive.WithLeadingTrivia(neighbour.Skip(start));
            }

            SyntaxList<UsingDirectiveSyntax> updated = usings.Insert(index, directive);

            if (ns != null)
                return unit.ReplaceNode(ns, ns.WithUsings(updated));

            if (usings.Count == 0)
            {
                // Keep the file's leading trivia (header comments) above the new using.
                SyntaxTriviaList leading = unit.GetLeadingTrivia();
                CompilationUnitSyntax stripped = unit.WithoutLeadingTrivia();
                directive = directive.WithLeadingTrivia(leading).WithTrailingTrivia(newLine, newLine);
                return stripped.WithUsings(SyntaxFactory.SingletonList(directive));
            }

            return unit.WithUsings(updated);
        }

        private static int Compare(UsingDirectiveSyntax existing, string namespaceName)
        {
            // Global usings must precede the others; aliases and static usings conventionally follow.
            if (existing.GlobalKeyword.IsKind(SyntaxKind.GlobalKeyword))
                return -1;
            if (existing.Alias != null || !existing.StaticKeyword.IsKind(SyntaxKind.None))
                return 1;
            string name = existing.Name?.ToString() ?? string.Empty;
            bool existingSystem = name == "System" || name.StartsWith("System.", StringComparison.Ordinal);
            bool newSystem = namespaceName == "System" || namespaceName.StartsWith("System.", StringComparison.Ordinal);
            if (existingSystem != newSystem)
                return existingSystem ? -1 : 1;
            return string.Compare(name, namespaceName, StringComparison.OrdinalIgnoreCase);
        }
    }
}
