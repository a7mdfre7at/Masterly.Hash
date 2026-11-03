using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CodeFixes;
using Microsoft.CodeAnalysis.Diagnostics;

namespace Masterly.Hash.Analyzers.Tests;

public class DescriptorTests
{
    private static readonly Assembly AnalyzerAssembly = typeof(FastHashOnPasswordAnalyzer).Assembly;

    private static IEnumerable<DiagnosticAnalyzer> Analyzers() =>
        AnalyzerAssembly.GetTypes()
            .Where(t => !t.IsAbstract && typeof(DiagnosticAnalyzer).IsAssignableFrom(t))
            .Select(t => (DiagnosticAnalyzer)Activator.CreateInstance(t)!);

    private static IEnumerable<DiagnosticDescriptor> Descriptors() => Analyzers().SelectMany(a => a.SupportedDiagnostics);

    [Fact]
    public void SixRules_EachReportedByExactlyOneAnalyzer()
    {
        string[] ids = Descriptors().Select(d => d.Id).OrderBy(i => i, StringComparer.Ordinal).ToArray();
        Assert.Equal(new[] { "MH0001", "MH0002", "MH0003", "MH0004", "MH0005", "MH0006" }, ids);
    }

    [Fact]
    public void Descriptors_AreSecurityWithHelpLinks()
    {
        foreach (DiagnosticDescriptor d in Descriptors())
        {
            Assert.Equal("Security", d.Category);
            Assert.True(d.IsEnabledByDefault);
            Assert.Equal("https://github.com/a7mdfre7at/Masterly.Hash/blob/master/docs/analyzers/" + d.Id + ".md", d.HelpLinkUri);
            Assert.False(string.IsNullOrWhiteSpace(d.Description.ToString()));
            Assert.Equal(d.Id == "MH0006" ? DiagnosticSeverity.Info : DiagnosticSeverity.Warning, d.DefaultSeverity);
        }
    }

    [Fact]
    public void Analyzers_AreCSharpOnly()
    {
        foreach (DiagnosticAnalyzer analyzer in Analyzers())
        {
            DiagnosticAnalyzerAttribute attribute = analyzer.GetType().GetCustomAttribute<DiagnosticAnalyzerAttribute>()!;
            Assert.Equal(new[] { LanguageNames.CSharp }, attribute.Languages);
        }
    }

    [Fact]
    public void CodeFixes_TargetKnownRules_AndSupportFixAll()
    {
        HashSet<string> ids = Descriptors().Select(d => d.Id).ToHashSet();
        CodeFixProvider[] fixes = AnalyzerAssembly.GetTypes()
            .Where(t => !t.IsAbstract && typeof(CodeFixProvider).IsAssignableFrom(t))
            .Select(t => (CodeFixProvider)Activator.CreateInstance(t)!)
            .ToArray();

        Assert.Equal(3, fixes.Length);
        foreach (CodeFixProvider fix in fixes)
        {
            Assert.All(fix.FixableDiagnosticIds, id => Assert.Contains(id, ids));
            Assert.NotNull(fix.GetFixAllProvider());
            Assert.NotNull(fix.GetType().GetCustomAttribute<ExportCodeFixProviderAttribute>());
        }
    }

    [Fact]
    public void WeakPbkdf2_Description_DoesNotPresentDetectionFloorAsRecommendation()
    {
        string description = new WeakPbkdf2Analyzer().SupportedDiagnostics[0].Description.ToString();

        // OWASP Password Storage Cheat Sheet: 600,000 (PBKDF2-HMAC-SHA256), 210,000 (PBKDF2-HMAC-SHA512).
        Assert.Contains("600,000", description, StringComparison.Ordinal);
        Assert.Contains("210,000", description, StringComparison.Ordinal);
        Assert.DoesNotContain("at least 100,000", description, StringComparison.Ordinal);
    }

    [Fact]
    public void EveryRule_HasDocsPage_AndReleaseEntry()
    {
        string root = FindRepoRoot();
        string unshipped = File.ReadAllText(Path.Combine(root, "src", "Masterly.Hash.Analyzers", "AnalyzerReleases.Unshipped.md"));
        foreach (DiagnosticDescriptor d in Descriptors())
        {
            string doc = Path.Combine(root, "docs", "analyzers", d.Id + ".md");
            Assert.True(File.Exists(doc), "Missing " + doc);
            Assert.StartsWith("# " + d.Id, File.ReadAllText(doc), StringComparison.Ordinal);
            string severity = d.DefaultSeverity == DiagnosticSeverity.Info ? "Info" : "Warning";
            Assert.Contains(d.Id + " | Security | " + severity + " |", unshipped, StringComparison.Ordinal);
        }
    }

    private static string FindRepoRoot()
    {
        for (DirectoryInfo? dir = new DirectoryInfo(AppContext.BaseDirectory); dir != null; dir = dir.Parent)
        {
            if (Directory.Exists(Path.Combine(dir.FullName, "src", "Masterly.Hash.Analyzers")))
                return dir.FullName;
        }

        throw new InvalidOperationException("Repository root not found.");
    }
}
