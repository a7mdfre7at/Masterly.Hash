using BenchmarkDotNet.Attributes;

namespace Masterly.Hash.Benchmarks
{
    /// <summary>Hash and Verify cost of each built-in profile.</summary>
    [MemoryDiagnoser]
    public class ProfileBenchmarks
    {
        private PasswordHasher _hasher = null!;
        private string _stored = null!;

        /// <summary>Built-in profile id under test.</summary>
        [Params("2026a", "2026c", "2026f")]
        public string ProfileId { get; set; } = "2026a";

        /// <summary>Creates the hasher and one stored hash to verify against.</summary>
        [GlobalSetup]
        public void Setup()
        {
            _hasher = BenchmarkData.Hasher(BenchmarkData.Profile(ProfileId));
            _stored = _hasher.Hash(BenchmarkData.Password);
            BenchmarkData.EnsureMatch(_hasher.Verify(BenchmarkData.Password, _stored), ProfileId);
        }

        /// <summary>Hashes a password (registration, password change).</summary>
        [Benchmark]
        public string Hash() => _hasher.Hash(BenchmarkData.Password);

        /// <summary>Verifies the correct password (successful login).</summary>
        [Benchmark]
        public PasswordVerificationResult Verify() => _hasher.Verify(BenchmarkData.Password, _stored);

        /// <summary>Verifies a wrong password (failed login); should cost the same as <see cref="Verify"/>.</summary>
        [Benchmark]
        public PasswordVerificationResult VerifyWrongPassword() => _hasher.Verify("wrong-password-1", _stored);
    }
}
