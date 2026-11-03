using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.CodeAnalysis.CodeFixes;
using Microsoft.CodeAnalysis.CSharp.Testing;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Testing;

namespace Masterly.Hash.Analyzers.Tests.Infrastructure;

internal static class References
{
    private static readonly string OfflineConfig = Path.Combine(AppContext.BaseDirectory, "offline.nuget.config");

    /// <summary>.NET 8 reference assemblies, resolved from the global packages folder only (no package sources).</summary>
    public static ReferenceAssemblies Net80 { get; } = ReferenceAssemblies.Net.Net80.WithNuGetConfigFilePath(OfflineConfig);

    /// <summary>netstandard2.0: no CryptographicOperations, no SHA256.HashData.</summary>
    public static ReferenceAssemblies NetStandard20 { get; } = ReferenceAssemblies.NetStandard.NetStandard20.WithNuGetConfigFilePath(OfflineConfig);
}

/// <summary>Runs an analyzer against source plus the Masterly.Hash and logging stubs.</summary>
internal static class AnalyzerVerifier<TAnalyzer>
    where TAnalyzer : DiagnosticAnalyzer, new()
{
    public static DiagnosticResult Diagnostic() => new DiagnosticResult(new TAnalyzer().SupportedDiagnostics[0]);

    public static Task VerifyAsync(string source, params DiagnosticResult[] expected) =>
        VerifyAsync(source, References.Net80, expected);

    public static Task VerifyAsync(string source, ReferenceAssemblies references, params DiagnosticResult[] expected)
    {
        var test = new CSharpAnalyzerTest<TAnalyzer, DefaultVerifier>
        {
            TestCode = source,
            ReferenceAssemblies = references,
        };
        test.TestState.Sources.Add(("/0/MasterlyHashStubs.cs", Stubs.MasterlyHash));
        test.TestState.Sources.Add(("/0/LoggingStubs.cs", Stubs.Logging));
        test.ExpectedDiagnostics.AddRange(expected);
        return test.RunAsync();
    }
}

/// <summary>Runs an analyzer and code fix. Pass <c>fixedSource == source</c> to assert that no fix is offered.</summary>
internal static class CodeFixVerifier<TAnalyzer, TCodeFix>
    where TAnalyzer : DiagnosticAnalyzer, new()
    where TCodeFix : CodeFixProvider, new()
{
    public static Task VerifyAsync(string source, string fixedSource, params DiagnosticResult[] expected) =>
        VerifyAsync(source, fixedSource, References.Net80, expected);

    public static Task VerifyAsync(string source, string fixedSource, ReferenceAssemblies references, params DiagnosticResult[] expected)
    {
        var test = new CSharpCodeFixTest<TAnalyzer, TCodeFix, DefaultVerifier>
        {
            TestCode = source,
            FixedCode = fixedSource,
            ReferenceAssemblies = references,
        };
        test.TestState.Sources.Add(("/0/MasterlyHashStubs.cs", Stubs.MasterlyHash));
        test.TestState.Sources.Add(("/0/LoggingStubs.cs", Stubs.Logging));
        test.FixedState.Sources.Add(("/0/MasterlyHashStubs.cs", Stubs.MasterlyHash));
        test.FixedState.Sources.Add(("/0/LoggingStubs.cs", Stubs.Logging));
        test.ExpectedDiagnostics.AddRange(expected);
        return test.RunAsync();
    }
}
