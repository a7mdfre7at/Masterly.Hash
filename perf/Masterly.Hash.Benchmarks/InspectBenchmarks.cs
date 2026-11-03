using BenchmarkDotNet.Attributes;

namespace Masterly.Hash.Benchmarks
{
    /// <summary>Parse throughput: <c>Inspect</c> and <c>NeedsRehash</c> never run the KDF.</summary>
    [MemoryDiagnoser]
    public class InspectBenchmarks
    {
        private PasswordHasher _hasher = null!;
        private string _current = null!;
        private string _unpeppered = null!;
        private string _otherProfile = null!;
        private string _v1 = null!;
        private string _malformed = null!;

        /// <summary>Creates one hash of each kind.</summary>
        [GlobalSetup]
        public void Setup()
        {
            _hasher = BenchmarkData.Hasher(HashProfile.Constrained2026a, BenchmarkData.NewPepper());
            _current = _hasher.Hash(BenchmarkData.Password);
            _unpeppered = BenchmarkData.Hasher(HashProfile.Constrained2026a).Hash(BenchmarkData.Password);
            _otherProfile = BenchmarkData.Hasher(HashProfile.Fips2026a).Hash(BenchmarkData.Password);
            _v1 = BenchmarkData.V1Hash(BenchmarkData.Password);
            _malformed = "$mh$p=2026c$not*base64$" + new string('A', 43);
        }

        /// <summary>A current, peppered hash (the common case).</summary>
        [Benchmark(Baseline = true)]
        public HashInfo InspectCurrent() => _hasher.Inspect(_current);

        /// <summary>A hash written before the pepper was configured.</summary>
        [Benchmark]
        public HashInfo InspectUnpeppered() => _hasher.Inspect(_unpeppered);

        /// <summary>A hash with another built-in profile.</summary>
        [Benchmark]
        public HashInfo InspectOtherProfile() => _hasher.Inspect(_otherProfile);

        /// <summary>A Masterly.Hash 1.x hash (falls through to the legacy formats).</summary>
        [Benchmark]
        public HashInfo InspectV1() => _hasher.Inspect(_v1);

        /// <summary>A malformed <c>$mh$</c> string.</summary>
        [Benchmark]
        public HashInfo InspectMalformed() => _hasher.Inspect(_malformed);

        /// <summary><c>NeedsRehash</c> on a current, peppered hash.</summary>
        [Benchmark]
        public bool NeedsRehash() => _hasher.NeedsRehash(_current);
    }
}
