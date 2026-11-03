using BenchmarkDotNet.Attributes;
using Masterly.Hash.Legacy;

namespace Masterly.Hash.Benchmarks
{
    /// <summary>Verification of Masterly.Hash 1.x (salted SHA-512) hashes.</summary>
    [MemoryDiagnoser]
    public class LegacyBenchmarks
    {
        private PasswordHasher _noRehash = null!;
        private PasswordHasher _withRehash = null!;
        private string _v1 = null!;

        /// <summary>Creates a v1 hash with the 1.x API and the hashers that read it.</summary>
        [GlobalSetup]
        public void Setup()
        {
            _v1 = BenchmarkData.V1Hash(BenchmarkData.Password);
            _noRehash = BenchmarkData.Hasher(HashProfile.Server2026a, computeRehash: false);
            _withRehash = BenchmarkData.Hasher(HashProfile.Server2026a);
            BenchmarkData.EnsureMatch(_noRehash.Verify(BenchmarkData.Password, _v1), "v1 hash");
        }

        /// <summary>The raw v1 format check (tries SHA-512, SHA-384 and SHA-256).</summary>
        [Benchmark(Baseline = true)]
        public bool V1FormatVerify() => V1LegacyFormat.Instance.Verify(BenchmarkData.Password, _v1);

        /// <summary>Verify of a v1 hash through the hasher, without computing the replacement hash.</summary>
        [Benchmark]
        public PasswordVerificationResult V1Verify() => _noRehash.Verify(BenchmarkData.Password, _v1);

        /// <summary>Verify of a v1 hash including the upgrade to a 2026a hash (the real first login after upgrading).</summary>
        [Benchmark]
        public PasswordVerificationResult V1VerifyAndRehash() => _withRehash.Verify(BenchmarkData.Password, _v1);
    }
}
