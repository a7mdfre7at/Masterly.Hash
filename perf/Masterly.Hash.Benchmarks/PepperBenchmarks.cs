using BenchmarkDotNet.Attributes;
using Masterly.Hash.Pepper;
using Masterly.Hash.Primitives;

namespace Masterly.Hash.Benchmarks
{
    /// <summary>Overhead of <see cref="HmacPepper"/> relative to the same profile without a pepper.</summary>
    [MemoryDiagnoser]
    public class PepperBenchmarks
    {
        private HmacPepper _pepper = null!;
        private PasswordHasher _plain = null!;
        private PasswordHasher _peppered = null!;
        private string _plainHash = null!;
        private string _pepperedHash = null!;
        private byte[] _encoded = null!;

        /// <summary>Built-in profile id under test.</summary>
        [Params("2026c")]
        public string ProfileId { get; set; } = "2026c";

        /// <summary>Creates a peppered and an unpeppered hasher with the same profile.</summary>
        [GlobalSetup]
        public void Setup()
        {
            HashProfile profile = BenchmarkData.Profile(ProfileId);
            _pepper = BenchmarkData.NewPepper();
            _plain = BenchmarkData.Hasher(profile);
            _peppered = BenchmarkData.Hasher(profile, _pepper);
            _plainHash = _plain.Hash(BenchmarkData.Password);
            _pepperedHash = _peppered.Hash(BenchmarkData.Password);
            _encoded = HashPrimitives.EncodePassword(BenchmarkData.Password);
            BenchmarkData.EnsureMatch(_peppered.Verify(BenchmarkData.Password, _pepperedHash), "peppered hash");
        }

        /// <summary>Zeroes the encoded password copy.</summary>
        [GlobalCleanup]
        public void Cleanup() => HashPrimitives.Zero(_encoded);

        /// <summary>The pepper on its own: one HMAC-SHA256 over the encoded password.</summary>
        [Benchmark]
        public byte[] PepperApply() => _pepper.Apply(_pepper.CurrentKeyId, _encoded);

        /// <summary>Verify without a pepper.</summary>
        [Benchmark(Baseline = true)]
        public PasswordVerificationResult VerifyPlain() => _plain.Verify(BenchmarkData.Password, _plainHash);

        /// <summary>Verify with an <see cref="HmacPepper"/>.</summary>
        [Benchmark]
        public PasswordVerificationResult VerifyPeppered() => _peppered.Verify(BenchmarkData.Password, _pepperedHash);
    }
}
