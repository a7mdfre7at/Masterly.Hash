using System.Threading.Tasks;
using Microsoft.CodeAnalysis;
using Verify = Masterly.Hash.Analyzers.Tests.Infrastructure.AnalyzerVerifier<Masterly.Hash.Analyzers.ObsoleteApiAnalyzer>;
using VerifyFix = Masterly.Hash.Analyzers.Tests.Infrastructure.CodeFixVerifier<
    Masterly.Hash.Analyzers.ObsoleteApiAnalyzer,
    Masterly.Hash.Analyzers.CodeFixes.ObsoleteApiCodeFixProvider>;

namespace Masterly.Hash.Analyzers.Tests;

public class ObsoleteApiTests
{
    [Fact]
    public Task ComputeHash_ReportsInfo() => Verify.VerifyAsync("""
        using Masterly.Hash;

        class C
        {
            string M(string plain) => {|#0:new Hash().ComputeHash(plain)|};
        }
        """,
        Verify.Diagnostic().WithLocation(0).WithSeverity(DiagnosticSeverity.Info).WithArguments("Hash.ComputeHash", "Password.Hash"));

    [Fact]
    public Task EveryOverload_ViaInterfaceAndSubclass_Reports() => Verify.VerifyAsync("""
        using Masterly.Hash;

        class MyHash : Hash { }

        class C
        {
            void M(IHash hasher, MyHash mine, string plain, byte[] salt)
            {
                _ = {|MH0006:hasher.ComputeHash(plain, SupportedHash.SHA256)|};
                _ = {|MH0006:hasher.ComputeHash(plain, salt)|};
                _ = {|MH0006:mine.ComputeHash(plain)|};
            }
        }
        """);

    [Fact]
    public Task VerifyAndUnrelatedComputeHash_DoNotReport() => Verify.VerifyAsync("""
        using System.Security.Cryptography;
        using Masterly.Hash;

        namespace Other { public class Hash { public string ComputeHash(string s) => s; } }

        class C
        {
            void M(IHash hasher, string plain, string stored, byte[] data)
            {
                _ = hasher.Verify(plain, stored);
                _ = new Other.Hash().ComputeHash(plain);
                using var sha = SHA256.Create();
                _ = sha.ComputeHash(data);
            }
        }
        """);

    [Fact]
    public Task Fix_PlainTextOnly_ReplacedWithPasswordHash() => VerifyFix.VerifyAsync("""
        using Masterly.Hash;

        class C
        {
            string M(IHash hasher, string plain)
            {
                string stored = {|MH0006:hasher.ComputeHash(plain)|};
                return stored;
            }
        }
        """, """
        using Masterly.Hash;

        class C
        {
            string M(IHash hasher, string plain)
            {
                string stored = Password.Hash(plain);
                return stored;
            }
        }
        """);

    [Fact]
    public Task Fix_NamedArgument_AndUsingAdded() => VerifyFix.VerifyAsync("""
        class C
        {
            string M(string plain) => {|MH0006:new Masterly.Hash.Hash().ComputeHash(plainText: plain)|};
        }
        """, """
        using Masterly.Hash;

        class C
        {
            string M(string plain) => Password.Hash(plain);
        }
        """);

    [Fact]
    public Task Fix_NotOffered_WhenAlgorithmOrSaltGiven() => VerifyFix.VerifyAsync("""
        using Masterly.Hash;

        class C
        {
            void M(IHash hasher, string plain, byte[] salt)
            {
                _ = {|MH0006:hasher.ComputeHash(plain, SupportedHash.SHA384)|};
                _ = {|MH0006:hasher.ComputeHash(plain, salt)|};
            }
        }
        """, """
        using Masterly.Hash;

        class C
        {
            void M(IHash hasher, string plain, byte[] salt)
            {
                _ = {|MH0006:hasher.ComputeHash(plain, SupportedHash.SHA384)|};
                _ = {|MH0006:hasher.ComputeHash(plain, salt)|};
            }
        }
        """);
}
