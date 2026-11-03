using System.Collections.Immutable;
using System.Threading.Tasks;
using Masterly.Hash.Analyzers.Tests.Infrastructure;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Testing;
using Microsoft.CodeAnalysis.Testing;

namespace Masterly.Hash.Analyzers.Tests;

/// <summary>
/// Each analyzer resolves the framework or Masterly.Hash types it matches when the compilation starts, and must stay
/// silent (and not throw) when they are absent: a project without the cryptography assemblies, or without a reference
/// to Masterly.Hash, or with only part of its API.
/// </summary>
public class MissingTypesTests
{
    [Fact]
    public async Task FastHash_NoCryptographyTypes_LookalikeTypesDoNotReport()
    {
        CSharpCompilation compilation = CoreLibOnly.Compile("""
            using System.Text;

            namespace Crypto
            {
                public static class SHA256 { public static byte[] HashData(byte[] data) => data; }
            }

            class C
            {
                byte[] M(string password) => Crypto.SHA256.HashData(Encoding.UTF8.GetBytes(password));
            }
            """);
        Assert.Null(compilation.GetTypeByMetadataName("System.Security.Cryptography.HashAlgorithm"));
        Assert.Null(compilation.GetTypeByMetadataName("System.Security.Cryptography.SHA256"));

        Assert.Empty(await CoreLibOnly.AnalyzeAsync(new FastHashOnPasswordAnalyzer(), compilation));
    }

    [Fact]
    public async Task FastHash_StaticHashTypeWithoutHashAlgorithmBase_StillReportsStaticCalls()
    {
        // A trimmed or polyfilled framework can expose SHA256.HashData without the HashAlgorithm hierarchy. The static
        // one-shot call is still recognised; constructing an HMAC is not, because it cannot be proven to be a hash.
        CSharpCompilation compilation = CoreLibOnly.Compile("""
            using System.Text;

            namespace System.Security.Cryptography
            {
                public static class SHA256 { public static byte[] HashData(byte[] data) => data; }
                public sealed class HMACSHA256 { public HMACSHA256(byte[] key) { } }
            }

            class C
            {
                byte[] Digest(string password) => System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes(password));
                object Mac(byte[] passwordBytes) => new System.Security.Cryptography.HMACSHA256(passwordBytes);
            }
            """);
        Assert.Null(compilation.GetTypeByMetadataName("System.Security.Cryptography.HashAlgorithm"));

        ImmutableArray<Diagnostic> diagnostics = await CoreLibOnly.AnalyzeAsync(new FastHashOnPasswordAnalyzer(), compilation);

        Diagnostic diagnostic = Assert.Single(diagnostics);
        Assert.Equal("MH0001", diagnostic.Id);
        Assert.StartsWith("System.Security.Cryptography.SHA256.HashData(", diagnostic.Location.SourceTree!.GetText()
            .ToString(diagnostic.Location.SourceSpan));
    }

    [Fact]
    public async Task WeakPbkdf2_NoRfc2898DeriveBytes_DoesNotReport()
    {
        CSharpCompilation compilation = CoreLibOnly.Compile("""
            class Pbkdf2 { public Pbkdf2(string password, byte[] salt, int iterations) { } }

            class C
            {
                object M(string password, byte[] salt) => new Pbkdf2(password, salt, 1);
            }
            """);
        Assert.Null(compilation.GetTypeByMetadataName("System.Security.Cryptography.Rfc2898DeriveBytes"));

        Assert.Empty(await CoreLibOnly.AnalyzeAsync(new WeakPbkdf2Analyzer(), compilation));
    }

    [Fact]
    public async Task NonConstantTime_WithoutLinqOrCryptography_StringComparisonsStillReport()
    {
        // Enumerable, CryptographicOperations: absent. MemoryExtensions and spans live in CoreLib.
        CSharpCompilation compilation = CoreLibOnly.Compile("""
            class C
            {
                bool M(string token, string other) => token == other;
            }
            """);
        Assert.Null(compilation.GetTypeByMetadataName("System.Linq.Enumerable"));

        Diagnostic diagnostic = Assert.Single(await CoreLibOnly.AnalyzeAsync(new NonConstantTimeComparisonAnalyzer(), compilation));
        Assert.Equal("MH0002", diagnostic.Id);
    }

    [Fact]
    public Task ObsoleteApi_WithoutMasterlyHash_DoesNotReport()
    {
        // A project-local type that happens to be called Hash in another namespace.
        var test = new CSharpAnalyzerTest<ObsoleteApiAnalyzer, DefaultVerifier>
        {
            TestCode = """
                namespace Legacy { public class Hash { public string ComputeHash(string plainText) => plainText; } }

                class C
                {
                    string M(string plain) => new Legacy.Hash().ComputeHash(plain);
                }
                """,
            ReferenceAssemblies = References.Net80,
        };
        return test.RunAsync();
    }

    [Fact]
    public Task ObsoleteApi_InterfaceOnly_ReportsInterfaceCalls()
    {
        // Only IHash is in the compilation (an assembly that compiles against the interface alone).
        var test = new CSharpAnalyzerTest<ObsoleteApiAnalyzer, DefaultVerifier>
        {
            TestCode = """
                namespace Masterly.Hash
                {
                    public interface IHash { string ComputeHash(string plainText); }
                }

                namespace App
                {
                    public class LocalHasher { public string ComputeHash(string plainText) => plainText; }

                    class C
                    {
                        void M(Masterly.Hash.IHash hasher, LocalHasher local, string plain)
                        {
                            _ = {|MH0006:hasher.ComputeHash(plain)|};
                            _ = local.ComputeHash(plain);
                        }
                    }
                }
                """,
            ReferenceAssemblies = References.Net80,
        };
        return test.RunAsync();
    }

    /// <summary>
    /// The <c>Password.Hash</c> fix needs <c>public static string Hash(string)</c> on <c>Masterly.Hash.Password</c>;
    /// anything else (an older or unrelated <c>Password</c> type) means no fix is offered.
    /// </summary>
    [Theory]
    [InlineData("public string Hash(string password) => password;")]
    [InlineData("internal static string Hash(string password) => password;")]
    [InlineData("public static string Hash(string password, int cost) => password;")]
    [InlineData("public static string Hash(object password) => \"\";")]
    [InlineData("public static byte[] Hash(string password) => new byte[0];")]
    [InlineData("public static string Verify(string password) => password;")]
    public Task ObsoleteApi_PasswordHashWithWrongShape_NoFix(string member)
    {
        string stubs = """
            namespace Masterly.Hash
            {
                public class Password { MEMBER }
                public interface IHash { string ComputeHash(string plainText); }
            }
            """.Replace("MEMBER", member);
        const string source = """
            class C
            {
                string M(Masterly.Hash.IHash hasher, string plain) => {|MH0006:hasher.ComputeHash(plain)|};
            }
            """;
        var test = new CSharpCodeFixTest<ObsoleteApiAnalyzer, CodeFixes.ObsoleteApiCodeFixProvider, DefaultVerifier>
        {
            TestCode = source,
            FixedCode = source,
            ReferenceAssemblies = References.Net80,
        };
        test.TestState.Sources.Add(("/0/Stubs.cs", stubs));
        test.FixedState.Sources.Add(("/0/Stubs.cs", stubs));
        return test.RunAsync();
    }
}
