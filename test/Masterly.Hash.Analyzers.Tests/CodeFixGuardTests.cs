using System.Collections.Generic;
using System.Threading.Tasks;
using Masterly.Hash.Analyzers.CodeFixes;
using Masterly.Hash.Analyzers.Tests.Infrastructure;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CodeActions;

namespace Masterly.Hash.Analyzers.Tests;

/// <summary>
/// The code fixes re-check the syntax at the diagnostic location before rewriting it. A diagnostic whose location
/// or fix property does not match the expected shape (stale after an edit, or produced by another analyzer version)
/// must yield no code action rather than a broken edit. Each group starts with a well-formed diagnostic to show the
/// probe itself does register the fix.
/// </summary>
public class CodeFixGuardTests
{
    // ---------------------------------------------------------------- MH0001 Password.Hash

    private const string FastHashSource = """
        using System;
        using System.Security.Cryptography;
        using System.Text;
        using Masterly.Hash;

        class C
        {
            string Wrapped(string password) => Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(password)));

            object Local(string password)
            {
                var digest = SHA256.HashData(Encoding.UTF8.GetBytes(password));
                return digest;
            }

            byte[] FromBuffer(byte[] passwordBytes) => SHA256.HashData(passwordBytes);
        }
        """;

    private static DiagnosticDescriptor FastHash => Descriptors.FastHashOnPassword;

    private const string HashCall = "SHA256.HashData(Encoding.UTF8.GetBytes(password))";

    [Fact]
    public async Task FastHash_WellFormedDiagnostic_IsFixed()
    {
        using CodeFixProbe probe = await CodeFixProbe.CreateAsync(FastHashSource);
        Diagnostic wrapper = await probe.DiagnosticAtAsync(
            FastHash, HashCall, FastHashOnPasswordAnalyzer.FixKey, FastHashOnPasswordAnalyzer.FixReplaceWrapper);

        CodeAction action = Assert.Single(await probe.GetActionsAsync(new FastHashOnPasswordCodeFixProvider(), wrapper));
        Assert.Equal(
            FastHashSource.Replace(
                "=> Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(password)));",
                "=> Password.Hash(password);",
                System.StringComparison.Ordinal),
            await probe.ApplyAsync(action));
    }

    [Theory]
    [InlineData("Encoding.UTF8", 0, "the location is a member access, not an invocation")]
    [InlineData("SHA256.HashData(passwordBytes)", 0, "the hashed argument is not an Encoding.GetBytes call")]
    [InlineData("Encoding.UTF8.GetBytes(password)", 0, "the hashed argument of GetBytes is not an invocation")]
    public async Task FastHash_LocationWithoutTheExpectedShape_NoFix(string span, int occurrence, string reason)
    {
        using CodeFixProbe probe = await CodeFixProbe.CreateAsync(FastHashSource);
        Diagnostic diagnostic = await probe.DiagnosticAtAsync(
            FastHash, span, FastHashOnPasswordAnalyzer.FixKey, FastHashOnPasswordAnalyzer.FixReplaceCall, occurrence);

        IReadOnlyList<CodeAction> actions = await probe.GetActionsAsync(new FastHashOnPasswordCodeFixProvider(), diagnostic);

        Assert.True(actions.Count == 0, reason);
    }

    [Fact]
    public async Task FastHash_WrapperModeOnUnwrappedCall_NoFix()
    {
        // The second occurrence is "var digest = SHA256.HashData(...)": there is no wrapper call to replace.
        using CodeFixProbe probe = await CodeFixProbe.CreateAsync(FastHashSource);
        Diagnostic diagnostic = await probe.DiagnosticAtAsync(
            FastHash, HashCall, FastHashOnPasswordAnalyzer.FixKey, FastHashOnPasswordAnalyzer.FixReplaceWrapper, occurrence: 1);

        Assert.Empty(await probe.GetActionsAsync(new FastHashOnPasswordCodeFixProvider(), diagnostic));
    }

    [Theory]
    [InlineData("Replace")]
    [InlineData("")]
    [InlineData(null)]
    public async Task FastHash_UnknownFixMode_NoFix(string? mode)
    {
        using CodeFixProbe probe = await CodeFixProbe.CreateAsync(FastHashSource);
        Diagnostic diagnostic = await probe.DiagnosticAtAsync(
            FastHash, HashCall, FastHashOnPasswordAnalyzer.FixKey, mode, occurrence: 1);

        Assert.Empty(await probe.GetActionsAsync(new FastHashOnPasswordCodeFixProvider(), diagnostic));
    }

    // ---------------------------------------------------------------- MH0002 FixedTimeEquals

    private const string SequenceEqualSource = """
        using System.Linq;

        class C
        {
            static bool Check(byte[] mac) => mac.Length == 32;
            static bool Same(byte[] expectedMac, byte[]? other = null) => other != null && expectedMac.Length == other.Length;

            bool A(byte[] computed, byte[] expectedMac) => computed.SequenceEqual(expectedMac);
            bool B(byte[] expectedMac) => Check(expectedMac);
            bool D(byte[] expectedMac) => Same(expectedMac);
            int E(byte[] expectedMac) => expectedMac.Length;
        }
        """;

    private static DiagnosticDescriptor NonConstantTime => Descriptors.NonConstantTimeComparison;

    [Fact]
    public async Task FixedTimeEquals_WellFormedDiagnostic_IsFixed()
    {
        using CodeFixProbe probe = await CodeFixProbe.CreateAsync(SequenceEqualSource);
        Diagnostic diagnostic = await probe.DiagnosticAtAsync(NonConstantTime, "computed.SequenceEqual(expectedMac)",
            NonConstantTimeComparisonAnalyzer.FixKey, NonConstantTimeComparisonAnalyzer.FixFixedTimeEquals);

        CodeAction action = Assert.Single(await probe.GetActionsAsync(new FixedTimeEqualsCodeFixProvider(), diagnostic));

        // The fix reuses the document's line ending, and git (text=auto) checks this file out with CRLF on Windows.
        string newLine = SequenceEqualSource.Contains("\r\n", System.StringComparison.Ordinal) ? "\r\n" : "\n";
        Assert.Equal(
            SequenceEqualSource
                .Replace("using System.Linq;", $"using System.Linq;{newLine}using System.Security.Cryptography;", System.StringComparison.Ordinal)
                .Replace("=> computed.SequenceEqual(expectedMac);", "=> CryptographicOperations.FixedTimeEquals(computed, expectedMac);", System.StringComparison.Ordinal),
            await probe.ApplyAsync(action));
    }

    [Theory]
    [InlineData("expectedMac.Length", "the location is not an invocation")]
    [InlineData("Check(expectedMac)", "the call has one argument")]
    [InlineData("Same(expectedMac)", "the second operand is an omitted optional argument: the rewrite would not compile")]
    public async Task FixedTimeEquals_LocationWithoutTheExpectedShape_NoFix(string span, string reason)
    {
        using CodeFixProbe probe = await CodeFixProbe.CreateAsync(SequenceEqualSource);
        Diagnostic diagnostic = await probe.DiagnosticAtAsync(NonConstantTime, span,
            NonConstantTimeComparisonAnalyzer.FixKey, NonConstantTimeComparisonAnalyzer.FixFixedTimeEquals);

        IReadOnlyList<CodeAction> actions = await probe.GetActionsAsync(new FixedTimeEqualsCodeFixProvider(), diagnostic);

        Assert.True(actions.Count == 0, reason);
    }

    // ---------------------------------------------------------------- MH0006 Password.Hash

    [Theory]
    [InlineData("hasher.ComputeHash", "the location is a member access, not an invocation")]
    [InlineData("hasher.ComputeHash(plain, SupportedHash.SHA256)", "the call has more than the plaintext argument")]
    public async Task ObsoleteApi_LocationWithoutTheExpectedShape_NoFix(string span, string reason)
    {
        using CodeFixProbe probe = await CodeFixProbe.CreateAsync("""
            using Masterly.Hash;

            class C
            {
                string M(IHash hasher, string plain) => hasher.ComputeHash(plain, SupportedHash.SHA256);
            }
            """);
        Diagnostic diagnostic = await probe.DiagnosticAtAsync(Descriptors.ObsoleteApi, span,
            ObsoleteApiAnalyzer.FixKey, ObsoleteApiAnalyzer.FixPasswordHash);

        IReadOnlyList<CodeAction> actions = await probe.GetActionsAsync(new ObsoleteApiCodeFixProvider(), diagnostic);

        Assert.True(actions.Count == 0, reason);
    }
}
