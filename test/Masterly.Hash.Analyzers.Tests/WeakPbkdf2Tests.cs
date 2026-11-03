using System.Threading.Tasks;
using Verify = Masterly.Hash.Analyzers.Tests.Infrastructure.AnalyzerVerifier<Masterly.Hash.Analyzers.WeakPbkdf2Analyzer>;

namespace Masterly.Hash.Analyzers.Tests;

public class WeakPbkdf2Tests
{
    // ---------------------------------------------------------------- positives

    [Fact]
    public Task DefaultingConstructors_Report() => Verify.VerifyAsync("""
        using System.Security.Cryptography;

        class C
        {
            void M(string password, byte[] salt)
            {
                _ = {|#0:new Rfc2898DeriveBytes(password, salt)|};
                _ = {|#1:new Rfc2898DeriveBytes(password, 16)|};
            }
        }
        """,
        Verify.Diagnostic().WithLocation(0).WithArguments("this constructor defaults to 1,000 iterations; this constructor defaults to HMAC-SHA1"),
        Verify.Diagnostic().WithLocation(1).WithArguments("this constructor defaults to 1,000 iterations; this constructor defaults to HMAC-SHA1"));

    [Fact]
    public Task IterationsWithoutAlgorithm_ReportsBoth() => Verify.VerifyAsync("""
        using System.Security.Cryptography;

        class C
        {
            Rfc2898DeriveBytes M(byte[] password, byte[] salt) => {|#0:new Rfc2898DeriveBytes(password, salt, 10000)|};
        }
        """,
        Verify.Diagnostic().WithLocation(0).WithArguments("10,000 iterations is below the minimum of 100,000; this constructor defaults to HMAC-SHA1"));

    [Fact]
    public Task SafeIterationsWithoutAlgorithm_ReportsSha1Default() => Verify.VerifyAsync("""
        using System.Security.Cryptography;

        class C
        {
            Rfc2898DeriveBytes M(string password, byte[] salt) => {|#0:new Rfc2898DeriveBytes(password, salt, 600_000)|};
        }
        """,
        Verify.Diagnostic().WithLocation(0).WithArguments("this constructor defaults to HMAC-SHA1"));

    [Fact]
    public Task LowConstantIterations_WithStrongPrf_Reports() => Verify.VerifyAsync("""
        using System.Security.Cryptography;

        class C
        {
            private const int Iterations = 50_000;

            void M(string password, byte[] salt)
            {
                _ = {|#0:new Rfc2898DeriveBytes(password, salt, 1000, HashAlgorithmName.SHA256)|};
                _ = {|#1:new Rfc2898DeriveBytes(password, salt, Iterations, HashAlgorithmName.SHA512)|};
            }
        }
        """,
        Verify.Diagnostic().WithLocation(0).WithArguments("1,000 iterations is below the minimum of 100,000"),
        Verify.Diagnostic().WithLocation(1).WithArguments("50,000 iterations is below the minimum of 100,000"));

    [Fact]
    public Task StaticPbkdf2_LowIterations_Reports() => Verify.VerifyAsync("""
        using System.Security.Cryptography;

        class C
        {
            byte[] M(string password, byte[] salt) =>
                {|#0:Rfc2898DeriveBytes.Pbkdf2(password, salt, 5000, HashAlgorithmName.SHA512, 32)|};
        }
        """,
        Verify.Diagnostic().WithLocation(0).WithArguments("5,000 iterations is below the minimum of 100,000"));

    [Fact]
    public Task WeakPrf_Reports() => Verify.VerifyAsync("""
        using System.Security.Cryptography;

        class C
        {
            void M(byte[] password, byte[] salt)
            {
                _ = {|#0:Rfc2898DeriveBytes.Pbkdf2(password, salt, 1_300_000, HashAlgorithmName.SHA1, 32)|};
                _ = {|#1:Rfc2898DeriveBytes.Pbkdf2(password, salt, 1_300_000, new HashAlgorithmName("MD5"), 32)|};
            }
        }
        """,
        Verify.Diagnostic().WithLocation(0).WithArguments("SHA1 is a weak PBKDF2 PRF; use SHA256 or SHA512"),
        Verify.Diagnostic().WithLocation(1).WithArguments("MD5 is a weak PBKDF2 PRF; use SHA256 or SHA512"));

    [Fact]
    public Task NamedArguments_AreMatchedByParameter() => Verify.VerifyAsync("""
        using System.Security.Cryptography;

        class C
        {
            byte[] M(string password, byte[] salt) =>
                {|#0:Rfc2898DeriveBytes.Pbkdf2(outputLength: 32, hashAlgorithm: HashAlgorithmName.SHA256, iterations: 99_999, salt: salt, password: password)|};
        }
        """,
        Verify.Diagnostic().WithLocation(0).WithArguments("99,999 iterations is below the minimum of 100,000"));

    // ---------------------------------------------------------------- negatives

    [Fact]
    public Task StrongParameters_DoNotReport() => Verify.VerifyAsync("""
        using System.Security.Cryptography;

        class C
        {
            void M(string password, byte[] salt, int configuredIterations)
            {
                _ = new Rfc2898DeriveBytes(password, salt, 600_000, HashAlgorithmName.SHA256);
                _ = new Rfc2898DeriveBytes(password, salt, 100_000, HashAlgorithmName.SHA512);
                _ = Rfc2898DeriveBytes.Pbkdf2(password, salt, 210_000, HashAlgorithmName.SHA512, 64);
                // Not a constant: cannot be judged at compile time.
                _ = Rfc2898DeriveBytes.Pbkdf2(password, salt, configuredIterations, HashAlgorithmName.SHA256, 32);
            }
        }
        """);

    [Fact]
    public Task UnrelatedDeriveBytes_DoNotReport() => Verify.VerifyAsync("""
        class Rfc2898DeriveBytes
        {
            public Rfc2898DeriveBytes(string password, byte[] salt) { }
        }

        class C
        {
            object M(string password, byte[] salt) => new Rfc2898DeriveBytes(password, salt);
        }
        """);

    [Fact]
    public Task AlgorithmNotKnownAtCompileTime_IsNotJudged() => Verify.VerifyAsync("""
        using System.Security.Cryptography;

        class C
        {
            void M(string password, byte[] salt, HashAlgorithmName configured, string configuredName)
            {
                _ = new Rfc2898DeriveBytes(password, salt, 600_000, configured);
                _ = Rfc2898DeriveBytes.Pbkdf2(password, salt, 600_000, new HashAlgorithmName(configuredName), 32);
                _ = Rfc2898DeriveBytes.Pbkdf2(password, salt, 600_000, default, 32);
            }
        }
        """);
}
