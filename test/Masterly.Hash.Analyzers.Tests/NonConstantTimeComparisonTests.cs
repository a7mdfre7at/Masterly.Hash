using System.Threading.Tasks;
using Masterly.Hash.Analyzers.Tests.Infrastructure;
using Verify = Masterly.Hash.Analyzers.Tests.Infrastructure.AnalyzerVerifier<Masterly.Hash.Analyzers.NonConstantTimeComparisonAnalyzer>;
using VerifyFix = Masterly.Hash.Analyzers.Tests.Infrastructure.CodeFixVerifier<
    Masterly.Hash.Analyzers.NonConstantTimeComparisonAnalyzer,
    Masterly.Hash.Analyzers.CodeFixes.FixedTimeEqualsCodeFixProvider>;

namespace Masterly.Hash.Analyzers.Tests;

public class NonConstantTimeComparisonTests
{
    // ---------------------------------------------------------------- positives

    [Fact]
    public Task StringEqualityOperator_OnHash_Reports() => Verify.VerifyAsync("""
        class C
        {
            bool M(string storedHash, string computed) => {|#0:storedHash == computed|};
        }
        """,
        Verify.Diagnostic().WithLocation(0).WithArguments("storedHash", "=="));

    [Fact]
    public Task StringInequalityOperator_OnToken_Reports() => Verify.VerifyAsync("""
        class C
        {
            bool M(string provided, string expectedToken) => {|MH0002:provided != expectedToken|};
        }
        """);

    [Theory]
    [InlineData("signature")]
    [InlineData("digest")]
    [InlineData("mac")]
    [InlineData("hmac")]
    [InlineData("apiKey")]
    [InlineData("clientSecret")]
    [InlineData("hashedValue")]
    [InlineData("csrfToken")]
    public Task EverySecretWord_Reports(string name) => Verify.VerifyAsync($$"""
        class C
        {
            bool M(string {{name}}, string other) => {|MH0002:{{name}} == other|};
        }
        """);

    [Fact]
    public Task StringEquals_StaticAndInstance_Report() => Verify.VerifyAsync("""
        using System;

        class C
        {
            void M(string token, string header)
            {
                _ = {|MH0002:string.Equals(token, header)|};
                _ = {|MH0002:string.Equals(header, token, StringComparison.Ordinal)|};
                _ = {|MH0002:token.Equals(header)|};
            }
        }
        """);

    [Fact]
    public Task CompareOrdinal_Reports() => Verify.VerifyAsync("""
        class C
        {
            bool M(string signature, string header) => {|MH0002:string.CompareOrdinal(signature, header)|} == 0;
        }
        """);

    [Fact]
    public Task MemberAccess_ApiKeyProperty_Reports() => Verify.VerifyAsync("""
        class Client { public string ApiKey { get; set; } = ""; }

        class C
        {
            bool M(Client client, string presented) => {|MH0002:client.ApiKey == presented|};
        }
        """);

    [Fact]
    public Task LooksThroughBase64Conversion() => Verify.VerifyAsync("""
        using System;

        class C
        {
            bool M(byte[] mac, string header) => {|MH0002:Convert.ToBase64String(mac) == header|};
        }
        """);

    [Fact]
    public Task MethodReturningHash_Reports() => Verify.VerifyAsync("""
        class C
        {
            string ComputeHash(string s) => s;
            bool M(string input, string stored) => {|MH0002:ComputeHash(input) == stored|};
        }
        """);

    [Fact]
    public Task EnumerableSequenceEqual_OnBytes_Reports() => Verify.VerifyAsync("""
        using System.Linq;

        class C
        {
            bool M(byte[] computed, byte[] expectedMac) => {|MH0002:computed.SequenceEqual(expectedMac)|};
        }
        """);

    [Fact]
    public Task SpanSequenceEqual_OnBytes_Reports() => Verify.VerifyAsync("""
        using System;

        class C
        {
            bool M(ReadOnlySpan<byte> digest, ReadOnlySpan<byte> other) => {|MH0002:digest.SequenceEqual(other)|};
        }
        """);

    // ---------------------------------------------------------------- negatives

    [Fact]
    public Task NullDefaultAndEmptyComparisons_DoNotReport() => Verify.VerifyAsync("""
        class C
        {
            void M(string hash, string token, string? signature)
            {
                _ = hash == null;
                _ = null != hash;
                _ = token == "";
                _ = token == string.Empty;
                _ = signature == default;
                _ = string.Equals(token, null);
                _ = string.IsNullOrEmpty(hash);
            }
        }
        """);

    [Fact]
    public Task LengthAndNumericComparisons_DoNotReport() => Verify.VerifyAsync("""
        class C
        {
            void M(string hash, byte[] digest, byte[] mac)
            {
                _ = hash.Length == 64;
                _ = digest.Length != mac.Length;
                _ = hash.GetHashCode() == 0;
            }
        }
        """);

    /// <summary>Names ending in a metadata word (algorithm, type, name, ...) describe the secret, they are not it.</summary>
    [Theory]
    [InlineData("hashAlgorithm")]
    [InlineData("tokenType")]
    [InlineData("signatureScheme")]
    [InlineData("macAddress")]
    [InlineData("secretName")]
    [InlineData("hashtag")]
    [InlineData("machine")]
    [InlineData("tokenizer")]
    public Task MetadataNames_DoNotReport(string name) => Verify.VerifyAsync($$"""
        class C
        {
            bool M(string {{name}}, string other) => {{name}} == other;
        }
        """);

    [Fact]
    public Task UnrelatedNames_DoNotReport() => Verify.VerifyAsync("""
        using System.Linq;

        class C
        {
            void M(string userName, string other, byte[] payload, byte[] expected, int[] tokens, int[] others)
            {
                _ = userName == other;
                _ = payload.SequenceEqual(expected);
                _ = tokens.SequenceEqual(others);
            }
        }
        """);

    [Fact]
    public Task NameOf_DoesNotReport() => Verify.VerifyAsync("""
        class C
        {
            bool M(string token, string name) => nameof(token) == name;
        }
        """);

    // ---------------------------------------------------------------- code fix

    [Fact]
    public Task Fix_EnumerableSequenceEqual_WithExistingUsing() => VerifyFix.VerifyAsync("""
        using System.Linq;
        using System.Security.Cryptography;

        #nullable enable
        class C
        {
            bool M(byte[] computed, byte[] expectedMac)
            {
                return !{|MH0002:computed.SequenceEqual(expectedMac)|};
            }
        }
        """, """
        using System.Linq;
        using System.Security.Cryptography;

        #nullable enable
        class C
        {
            bool M(byte[] computed, byte[] expectedMac)
            {
                return !CryptographicOperations.FixedTimeEquals(computed, expectedMac);
            }
        }
        """);

    [Fact]
    public Task Fix_AddsUsing_WhenMissing() => VerifyFix.VerifyAsync("""
        using System.Linq;

        #nullable enable
        class C
        {
            bool M(byte[] computed, byte[] expectedMac) => {|MH0002:computed.SequenceEqual(expectedMac)|};
        }
        """, """
        using System.Linq;
        using System.Security.Cryptography;

        #nullable enable
        class C
        {
            bool M(byte[] computed, byte[] expectedMac) => CryptographicOperations.FixedTimeEquals(computed, expectedMac);
        }
        """);

    [Fact]
    public Task FixAll_TwoDiagnostics_AddSingleUsing() => VerifyFix.VerifyAsync("""
        using System.Linq;

        #nullable enable
        class C
        {
            bool A(byte[] mac, byte[] other) => {|MH0002:mac.SequenceEqual(other)|};
            bool B(byte[] digest, byte[] other) => {|MH0002:digest.SequenceEqual(other)|};
        }
        """, """
        using System.Linq;
        using System.Security.Cryptography;

        #nullable enable
        class C
        {
            bool A(byte[] mac, byte[] other) => CryptographicOperations.FixedTimeEquals(mac, other);
            bool B(byte[] digest, byte[] other) => CryptographicOperations.FixedTimeEquals(digest, other);
        }
        """);

    [Fact]
    public Task Fix_StaticForm_ArgumentOrderPreserved() => VerifyFix.VerifyAsync("""
        using System.Linq;
        using System.Security.Cryptography;

        #nullable enable
        class C
        {
            bool M(byte[] signature, byte[] other) => {|MH0002:Enumerable.SequenceEqual(second: other, first: signature)|};
        }
        """, """
        using System.Linq;
        using System.Security.Cryptography;

        #nullable enable
        class C
        {
            bool M(byte[] signature, byte[] other) => CryptographicOperations.FixedTimeEquals(signature, other);
        }
        """);

    [Fact]
    public Task Fix_Spans() => VerifyFix.VerifyAsync("""
        using System;
        using System.Security.Cryptography;

        class C
        {
            bool M(byte[] hash, Span<byte> computed) => {|MH0002:hash.AsSpan().SequenceEqual(computed)|};
        }
        """, """
        using System;
        using System.Security.Cryptography;

        class C
        {
            bool M(byte[] hash, Span<byte> computed) => CryptographicOperations.FixedTimeEquals(hash.AsSpan(), computed);
        }
        """);

    [Fact]
    public Task Fix_NotOffered_ForStrings() => VerifyFix.VerifyAsync("""
        class C
        {
            bool M(string hash, string other) => {|MH0002:hash == other|};
        }
        """, """
        class C
        {
            bool M(string hash, string other) => {|MH0002:hash == other|};
        }
        """);

    [Fact]
    public Task Fix_NotOffered_ForConditionalAccess() => VerifyFix.VerifyAsync("""
        using System.Linq;

        class C
        {
            bool M(byte[]? mac, byte[] other) => mac?{|MH0002:.SequenceEqual(other)|} == true;
        }
        """, """
        using System.Linq;

        class C
        {
            bool M(byte[]? mac, byte[] other) => mac?{|MH0002:.SequenceEqual(other)|} == true;
        }
        """);

    // Enumerable.SequenceEqual throws on a null array (fail closed); FixedTimeEquals treats null as an empty span, so
    // a rewrite could turn an exception into "null equals empty" (fail open). The fix needs proof of non-null.

    [Fact]
    public Task Fix_NotOffered_ForNullableOrSuppressedByteArrays() => VerifyFix.VerifyAsync("""
        using System.Linq;

        #nullable enable
        class C
        {
            bool A(byte[]? expectedMac, byte[] providedMac) => {|MH0002:expectedMac!.SequenceEqual(providedMac)|};
            bool B(byte[] computed, byte[]? expectedMac) => {|MH0002:computed.SequenceEqual(expectedMac!)|};
        }
        """, """
        using System.Linq;

        #nullable enable
        class C
        {
            bool A(byte[]? expectedMac, byte[] providedMac) => {|MH0002:expectedMac!.SequenceEqual(providedMac)|};
            bool B(byte[] computed, byte[]? expectedMac) => {|MH0002:computed.SequenceEqual(expectedMac!)|};
        }
        """);

    [Fact]
    public Task Fix_NotOffered_InNullableObliviousCode() => VerifyFix.VerifyAsync("""
        using System.Linq;

        #nullable disable
        class C
        {
            bool M(byte[] computed, byte[] expectedMac) => {|MH0002:computed.SequenceEqual(expectedMac)|};
        }
        """, """
        using System.Linq;

        #nullable disable
        class C
        {
            bool M(byte[] computed, byte[] expectedMac) => {|MH0002:computed.SequenceEqual(expectedMac)|};
        }
        """);

    [Fact]
    public Task Fix_Offered_WhenFlowAnalysisProvesNonNull() => VerifyFix.VerifyAsync("""
        using System.Linq;
        using System.Security.Cryptography;

        #nullable enable
        class C
        {
            bool M(byte[]? expectedMac, byte[] data, byte[] key)
            {
                if (expectedMac is null)
                    return false;
                return {|MH0002:HMACSHA256.HashData(key, data).SequenceEqual(expectedMac)|};
            }
        }
        """, """
        using System.Linq;
        using System.Security.Cryptography;

        #nullable enable
        class C
        {
            bool M(byte[]? expectedMac, byte[] data, byte[] key)
            {
                if (expectedMac is null)
                    return false;
                return CryptographicOperations.FixedTimeEquals(HMACSHA256.HashData(key, data), expectedMac);
            }
        }
        """);

    [Fact]
    public Task Fix_SpanSequenceEqual_OfferedEvenForNullableArrays() => VerifyFix.VerifyAsync("""
        using System;
        using System.Security.Cryptography;

        #nullable enable
        class C
        {
            // MemoryExtensions already treats a null array as an empty span, so the behavior is unchanged.
            bool M(byte[]? hash, ReadOnlySpan<byte> computed) => {|MH0002:computed.SequenceEqual(hash)|};
        }
        """, """
        using System;
        using System.Security.Cryptography;

        #nullable enable
        class C
        {
            // MemoryExtensions already treats a null array as an empty span, so the behavior is unchanged.
            bool M(byte[]? hash, ReadOnlySpan<byte> computed) => CryptographicOperations.FixedTimeEquals(computed, hash);
        }
        """);

    [Fact]
    public Task Fix_NotOffered_WithoutFixedTimeEqualsApi() => VerifyFix.VerifyAsync("""
        using System.Linq;

        class C
        {
            bool M(byte[] computed, byte[] expectedMac) => {|MH0002:computed.SequenceEqual(expectedMac)|};
        }
        """, """
        using System.Linq;

        class C
        {
            bool M(byte[] computed, byte[] expectedMac) => {|MH0002:computed.SequenceEqual(expectedMac)|};
        }
        """,
        References.NetStandard20);

    // ---------------------------------------------------------------- operand shapes

    [Fact]
    public Task SecretBehindInstanceStringMethod_Reports() => Verify.VerifyAsync("""
        class C
        {
            bool M(string token, string provided) => {|#0:token.Trim() == provided|};
        }
        """,
        Verify.Diagnostic().WithLocation(0).WithArguments("token", "=="));

    [Fact]
    public Task ValuePreservingCallOnNonSecret_DoesNotReport() => Verify.VerifyAsync("""
        class C
        {
            string Load() => "";
            bool M(string provided) => Load().ToString() == provided;
        }
        """);

    [Fact]
    public Task OtherOperatorsAndStringMembers_DoNotReport() => Verify.VerifyAsync("""
        class C
        {
            void M(string token, string other, string hash, object boxed)
            {
                _ = token + other;
                _ = hash.Length < other.Length;
                _ = token.Contains(other);
                _ = hash.StartsWith(other);
                // Reference equality on object, not a character-by-character comparison.
                _ = (object)token == boxed;
                _ = token == boxed;
            }
        }
        """);

    [Fact]
    public Task SequenceEqualFromAnotherType_DoesNotReport() => Verify.VerifyAsync("""
        static class ArrayCompare
        {
            public static bool SequenceEqual<T>(this T[] left, T[] right) => left.Length == right.Length;
        }

        class C
        {
            bool M(byte[] expectedMac, byte[] mac) => expectedMac.SequenceEqual(mac);
        }
        """);

    [Fact]
    public Task EmptySpanOperands_DoNotReport() => Verify.VerifyAsync("""
        using System;

        class C
        {
            void M(byte[] hash, string token)
            {
                // default(ReadOnlySpan<byte>) is not a compile-time constant; "" converts to a span through op_Implicit.
                _ = hash.AsSpan().SequenceEqual(default);
                _ = token.AsSpan().SequenceEqual("");
                _ = token.AsSpan().SequenceEqual(string.Empty);
            }
        }
        """);

    [Fact]
    public Task SpanOfLiteral_Reports() => Verify.VerifyAsync("""
        using System;

        class C
        {
            bool M(string token) => {|MH0002:token.AsSpan().SequenceEqual("expected")|};
        }
        """);

    [Fact]
    public Task OtherEmptyLookingMembers_StillReport() => Verify.VerifyAsync("""
        using System.Linq;

        static class Keys
        {
            public static readonly byte[] Empty = { 1 };
        }

        static class Buffers
        {
            public static T[] Empty<T>() => new T[1];
        }

        class C
        {
            void M(byte[] expectedMac)
            {
                _ = {|MH0002:expectedMac.SequenceEqual(Keys.Empty)|};
                _ = {|MH0002:expectedMac.SequenceEqual(Buffers.Empty<byte>())|};
            }
        }
        """);

    [Fact]
    public Task Fix_NotOffered_ForNonArrayEnumerables() => VerifyFix.VerifyAsync("""
        using System.Collections.Generic;
        using System.Linq;
        using System.Security.Cryptography;

        #nullable enable
        class C
        {
            bool M(List<byte> tokenBytes, byte[] expected) => {|MH0002:tokenBytes.SequenceEqual(expected)|};
        }
        """, """
        using System.Collections.Generic;
        using System.Linq;
        using System.Security.Cryptography;

        #nullable enable
        class C
        {
            bool M(List<byte> tokenBytes, byte[] expected) => {|MH0002:tokenBytes.SequenceEqual(expected)|};
        }
        """);

    [Fact]
    // The operands are taken from the operations' syntax, so redundant parentheses are dropped.
    public Task Fix_ArrayCreationAndParenthesizedOperands_Offered() => VerifyFix.VerifyAsync("""
        using System.Linq;
        using System.Security.Cryptography;

        #nullable enable
        class C
        {
            bool A(byte[] expectedMac) => {|MH0002:expectedMac.SequenceEqual(new byte[] { 1, 2, 3 })|};
            bool B(byte[] expectedMac, byte[] computed) => {|MH0002:(expectedMac).SequenceEqual((computed))|};
        }
        """, """
        using System.Linq;
        using System.Security.Cryptography;

        #nullable enable
        class C
        {
            bool A(byte[] expectedMac) => CryptographicOperations.FixedTimeEquals(expectedMac, new byte[] { 1, 2, 3 });
            bool B(byte[] expectedMac, byte[] computed) => CryptographicOperations.FixedTimeEquals(expectedMac, computed);
        }
        """);

    [Fact]
    public Task Fix_NotOffered_ForSuppressionInsideParentheses() => VerifyFix.VerifyAsync("""
        using System.Linq;

        #nullable enable
        class C
        {
            bool M(byte[]? expectedMac, byte[] computed) => {|MH0002:computed.SequenceEqual((expectedMac!))|};
        }
        """, """
        using System.Linq;

        #nullable enable
        class C
        {
            bool M(byte[]? expectedMac, byte[] computed) => {|MH0002:computed.SequenceEqual((expectedMac!))|};
        }
        """);

    [Fact]
    public Task Fix_NotOffered_ForConditionalAccessOnNonNullableArray() => VerifyFix.VerifyAsync("""
        using System.Linq;

        #nullable enable
        class C
        {
            // a?.SequenceEqual(b) is bool?; FixedTimeEquals returns bool, so the call is left alone.
            bool? M(byte[] computed, byte[] expectedMac) => computed?{|MH0002:.SequenceEqual(expectedMac)|};
        }
        """, """
        using System.Linq;

        #nullable enable
        class C
        {
            // a?.SequenceEqual(b) is bool?; FixedTimeEquals returns bool, so the call is left alone.
            bool? M(byte[] computed, byte[] expectedMac) => computed?{|MH0002:.SequenceEqual(expectedMac)|};
        }
        """);

    private const string FixedTimeEqualsPolyfill = """
        namespace System.Security.Cryptography
        {
            public class CryptographicOperations
            {
                MEMBER
            }
        }
        """;

    private static Task VerifyWithPolyfill(string member, string source, string fixedSource)
    {
        string polyfill = FixedTimeEqualsPolyfill.Replace("MEMBER", member);
        var test = new Microsoft.CodeAnalysis.CSharp.Testing.CSharpCodeFixTest<
            NonConstantTimeComparisonAnalyzer, CodeFixes.FixedTimeEqualsCodeFixProvider, Microsoft.CodeAnalysis.Testing.DefaultVerifier>
        {
            TestCode = source,
            FixedCode = fixedSource,
            ReferenceAssemblies = References.NetStandard20,
        };
        test.TestState.Sources.Add(("/0/Polyfill.cs", polyfill));
        test.FixedState.Sources.Add(("/0/Polyfill.cs", polyfill));
        return test.RunAsync();
    }

    private const string PolyfillSource = """
        using System.Linq;

        #nullable enable
        class C
        {
            bool M(byte[] computed, byte[] expectedMac) => {|MH0002:computed.SequenceEqual(expectedMac)|};
        }
        """;

    [Fact]
    public Task Fix_UsesFixedTimeEqualsPolyfill_OnNetStandard() => VerifyWithPolyfill(
        // netstandard2.0 has no CryptographicOperations; a project-supplied polyfill with the same shape is used.
        "public static bool FixedTimeEquals(byte[] left, byte[] right) => left.Length == right.Length;",
        PolyfillSource,
        """
        using System.Linq;
        using System.Security.Cryptography;

        #nullable enable
        class C
        {
            bool M(byte[] computed, byte[] expectedMac) => CryptographicOperations.FixedTimeEquals(computed, expectedMac);
        }
        """);

    [Theory]
    [InlineData("public static bool FixedTimeEquals(byte[] left) => left.Length == 0;")]
    [InlineData("internal static bool FixedTimeEquals(byte[] left, byte[] right) => left.Length == right.Length;")]
    [InlineData("public static bool Compare(byte[] left, byte[] right) => left.Length == right.Length;")]
    [InlineData("public bool FixedTimeEquals(byte[] left, byte[] right) => left.Length == right.Length;")]
    public Task Fix_NotOffered_ForPolyfillWithoutTheExpectedShape(string member) =>
        VerifyWithPolyfill(member, PolyfillSource, PolyfillSource);
}
