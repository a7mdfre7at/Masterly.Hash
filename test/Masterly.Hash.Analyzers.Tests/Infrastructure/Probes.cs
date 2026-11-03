using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CodeActions;
using Microsoft.CodeAnalysis.CodeFixes;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Text;

namespace Masterly.Hash.Analyzers.Tests.Infrastructure;

/// <summary>
/// Runs an analyzer against a compilation that references only the running runtime's System.Private.CoreLib, which
/// has no System.Security.Cryptography, System.Linq, System.Console or Rfc2898DeriveBytes. That is the only way to
/// reach the "the types I match are not in this compilation" bail-outs, because every reference-assembly set the
/// testing library resolves offline (net8.0, netstandard2.0) contains them.
/// </summary>
internal static class CoreLibOnly
{
    private static readonly MetadataReference CoreLib = MetadataReference.CreateFromFile(typeof(object).Assembly.Location);

    public static CSharpCompilation Compile(string source)
    {
        CSharpCompilation compilation = CSharpCompilation.Create(
            "CoreLibOnly",
            new[] { CSharpSyntaxTree.ParseText(source, new CSharpParseOptions(LanguageVersion.CSharp12)) },
            new[] { CoreLib },
            new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary, nullableContextOptions: NullableContextOptions.Enable));
        Assert.Empty(compilation.GetDiagnostics().Where(d => d.Severity == DiagnosticSeverity.Error));
        return compilation;
    }

    public static Task<ImmutableArray<Diagnostic>> AnalyzeAsync(DiagnosticAnalyzer analyzer, CSharpCompilation compilation) =>
        compilation.WithAnalyzers(ImmutableArray.Create(analyzer)).GetAnalyzerDiagnosticsAsync(CancellationToken.None);
}

/// <summary>
/// Calls a <see cref="CodeFixProvider"/> directly with a hand-made diagnostic. The analyzers only ever attach a fix
/// property to a diagnostic whose location has the shape the fixer expects, so the fixers' "cannot apply here" guards
/// are only reachable with a diagnostic the analyzer would not produce (a stale diagnostic after an edit, or one that
/// a different version of the analyzer produced).
/// </summary>
internal sealed class CodeFixProbe : System.IDisposable
{
    private readonly AdhocWorkspace _workspace;

    private CodeFixProbe(AdhocWorkspace workspace, Document document)
    {
        _workspace = workspace;
        Document = document;
    }

    public Document Document { get; }

    public static async Task<CodeFixProbe> CreateAsync(string source)
    {
        ImmutableArray<MetadataReference> references =
            await References.Net80.ResolveAsync(LanguageNames.CSharp, CancellationToken.None);
        var workspace = new AdhocWorkspace();
        Project project = workspace.AddProject("Probe", LanguageNames.CSharp)
            .WithCompilationOptions(new CSharpCompilationOptions(
                OutputKind.DynamicallyLinkedLibrary, nullableContextOptions: NullableContextOptions.Enable))
            .WithParseOptions(new CSharpParseOptions(LanguageVersion.CSharp12))
            .AddMetadataReferences(references);
        project = project.AddDocument("MasterlyHashStubs.cs", Stubs.MasterlyHash).Project;
        return new CodeFixProbe(workspace, project.AddDocument("Test.cs", source));
    }

    /// <summary>
    /// A diagnostic of <paramref name="descriptor"/> on the <paramref name="occurrence"/>-th (0-based) occurrence of
    /// <paramref name="text"/>, carrying <paramref name="fixKey"/> = <paramref name="fixValue"/> when a key is given.
    /// </summary>
    public async Task<Diagnostic> DiagnosticAtAsync(
        DiagnosticDescriptor descriptor, string text, string? fixKey, string? fixValue, int occurrence = 0)
    {
        SyntaxTree tree = (await Document.GetSyntaxTreeAsync())!;
        string source = (await tree.GetTextAsync()).ToString();
        int start = -1;
        for (int i = 0; i <= occurrence; i++)
        {
            start = source.IndexOf(text, start + 1, System.StringComparison.Ordinal);
            Assert.True(start >= 0, "'" + text + "' occurrence " + occurrence + " not found in the source.");
        }

        ImmutableDictionary<string, string?> properties = fixKey == null
            ? ImmutableDictionary<string, string?>.Empty
            : ImmutableDictionary<string, string?>.Empty.Add(fixKey, fixValue);
        return Diagnostic.Create(descriptor, Location.Create(tree, new TextSpan(start, text.Length)), properties);
    }

    public async Task<IReadOnlyList<CodeAction>> GetActionsAsync(CodeFixProvider provider, Diagnostic diagnostic)
    {
        var actions = new List<CodeAction>();
        var context = new CodeFixContext(Document, diagnostic, (action, _) => actions.Add(action), CancellationToken.None);
        await provider.RegisterCodeFixesAsync(context);
        return actions;
    }

    /// <summary>The text of <see cref="Document"/> after applying <paramref name="action"/>.</summary>
    public async Task<string> ApplyAsync(CodeAction action)
    {
        ImmutableArray<CodeActionOperation> operations = await action.GetOperationsAsync(CancellationToken.None);
        Solution changed = operations.OfType<ApplyChangesOperation>().Single().ChangedSolution;
        return (await changed.GetDocument(Document.Id)!.GetTextAsync()).ToString();
    }

    public void Dispose() => _workspace.Dispose();
}
