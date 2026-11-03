using BenchmarkDotNet.Attributes;

namespace Masterly.Hash.Benchmarks
{
    /// <summary>
    /// User-enumeration protection: <c>VerifyOrDummy(password, null)</c> for an unknown user should cost the same
    /// as a real verify, so the ratio column should be close to 1.00.
    /// </summary>
    [MemoryDiagnoser]
    public class VerifyOrDummyBenchmarks
    {
        private PasswordHasher _hasher = null!;
        private string _stored = null!;

        /// <summary>Creates the hasher and warms its dummy hash.</summary>
        [GlobalSetup]
        public void Setup()
        {
            _hasher = BenchmarkData.Hasher(HashProfile.Server2026a);
            _stored = _hasher.Hash(BenchmarkData.Password);
            BenchmarkData.EnsureMatch(_hasher.VerifyOrDummy(BenchmarkData.Password, _stored), "known user");
            _hasher.VerifyOrDummy(BenchmarkData.Password, null);
        }

        /// <summary>Known user, correct password.</summary>
        [Benchmark(Baseline = true)]
        public PasswordVerificationResult KnownUser() => _hasher.VerifyOrDummy(BenchmarkData.Password, _stored);

        /// <summary>Unknown user: the stored hash is null and a dummy hash is verified instead.</summary>
        [Benchmark]
        public PasswordVerificationResult UnknownUser() => _hasher.VerifyOrDummy(BenchmarkData.Password, null);
    }
}
