using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Masterly.Hash.Legacy;

namespace Masterly.Hash.Testing.Tests;

/// <summary>
/// Every constant in <see cref="KnownHashes"/> is checked three ways: it equals the deterministic factory output,
/// it equals an independent re-implementation written straight against the KDF libraries (not
/// <c>HashPrimitives</c>), and it verifies (or fails, as documented) with a real <see cref="PasswordHasher"/>.
/// </summary>
public class KnownHashesTests
{
    private static readonly byte[] Salt = Enumerable.Range(0, 16).Select(i => (byte)i).ToArray();

    private static PasswordHasher WithV1(V1Algorithm algorithm) => new FastPasswordHasher(o =>
    {
        o.LegacyFormats.Clear();
        o.LegacyFormats.Add(new V1LegacyFormat(algorithm));
    }).Inner;

    // ---- Independent reference implementations ----

    /// <summary>The Masterly.Hash 1.x algorithm, transcribed from 1.x <c>Hash.ComputeHash(string, byte[], SupportedHash)</c>.</summary>
    private static string ReferenceV1(string password, byte[] salt, V1Algorithm algorithm)
    {
        byte[] data = Encoding.UTF8.GetBytes(password).Concat(salt).ToArray();
        byte[] digest = algorithm switch
        {
            V1Algorithm.SHA256 => SHA256.HashData(data),
            V1Algorithm.SHA384 => SHA384.HashData(data),
            _ => SHA512.HashData(data),
        };
        return Convert.ToBase64String(digest.Concat(salt).ToArray());
    }

    private static byte[] ReferenceArgon2id(byte[] input, byte[] salt, int memoryKiB, int iterations)
    {
        using var argon2 = new Konscious.Security.Cryptography.Argon2id(input)
        {
            Salt = salt,
            MemorySize = memoryKiB,
            Iterations = iterations,
            DegreeOfParallelism = 1,
        };
        return argon2.GetBytes(32);
    }

    private static string B64(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=');

    private static string Phc(string parameters, byte[] tag) => "$mh$p=" + parameters + "$" + B64(Salt) + "$" + B64(tag);

    // ---- Basics ----

    [Fact]
    public void Passwords_AndSalts()
    {
        Assert.NotEqual(KnownHashes.Password, KnownHashes.WrongPassword);
        Assert.Equal(KnownHashes.Password, KnownHashes.WrongPassword, ignoreCase: true);
        Assert.Equal(Salt, KnownHashes.MhSalt);
        Assert.Equal(Encoding.UTF8.GetBytes("SomeSalt#$%"), KnownHashes.V1Salt);
        Assert.Equal(FakePepper.DefaultKeyId, KnownHashes.PepperKeyId);

        // The salt properties return fresh copies, so callers cannot corrupt them.
        KnownHashes.MhSalt[0] = 0xFF;
        Assert.Equal(0, KnownHashes.MhSalt[0]);
    }

    // ---- 1.x samples ----

    [Theory]
    [InlineData(V1Algorithm.SHA256, KnownHashes.V1Sha256)]
    [InlineData(V1Algorithm.SHA384, KnownHashes.V1Sha384)]
    [InlineData(V1Algorithm.SHA512, KnownHashes.V1Sha512)]
    public void V1Samples_MatchFactory_Reference_AndRealHasher(V1Algorithm algorithm, string sample)
    {
        Assert.Equal(sample, KnownHashes.CreateV1(KnownHashes.Password, KnownHashes.V1Salt, algorithm));
        Assert.Equal(sample, ReferenceV1(KnownHashes.Password, KnownHashes.V1Salt, algorithm));

        PasswordHasher hasher = WithV1(algorithm);
        PasswordVerificationResult ok = hasher.Verify(KnownHashes.Password, sample);
        Assert.Equal(VerificationStatus.SuccessRehashNeeded, ok.Status);
        Assert.Equal(RehashReason.LegacyFormat, ok.RehashReason);
        Assert.Equal(VerificationFailureReason.Mismatch, hasher.Verify(KnownHashes.WrongPassword, sample).FailureReason);

        // The default (auto-detecting) v1 format also accepts them, as does the static production facade.
        Assert.True(FastPasswordHasher.Shared.Verify(KnownHashes.Password, sample).IsMatch);
        Assert.True(Password.Verify(KnownHashes.Password, sample).IsMatch);
    }

    [Fact]
    public void CreateV1_MatchesReference_ForOtherInputs()
    {
        byte[] salt = { 1, 2, 3, 4, 5, 255 };
        foreach (V1Algorithm algorithm in Enum.GetValues<V1Algorithm>())
        {
            Assert.Equal(ReferenceV1("SomePaswword!@#", salt, algorithm), KnownHashes.CreateV1("SomePaswword!@#", salt, algorithm));
            Assert.Equal(ReferenceV1("pässwörd", Array.Empty<byte>(), algorithm), KnownHashes.CreateV1("pässwörd", Array.Empty<byte>(), algorithm));
        }
    }

    // ---- test-fast samples ----

    [Fact]
    public void TestFast_MatchesFactory_Reference_AndRealHasher()
    {
        Assert.Equal(KnownHashes.TestFast, KnownHashes.Create(FastPasswordHasher.Profile, KnownHashes.Password, Salt));
        Assert.Equal(KnownHashes.TestFast, Phc("test-fast", ReferenceArgon2id(Encoding.UTF8.GetBytes(KnownHashes.Password), Salt, 64, 1)));

        Assert.Equal(VerificationStatus.Success, FastPasswordHasher.Shared.Verify(KnownHashes.Password, KnownHashes.TestFast).Status);
        Assert.Equal(VerificationFailureReason.Mismatch, FastPasswordHasher.Shared.Verify(KnownHashes.WrongPassword, KnownHashes.TestFast).FailureReason);
    }

    [Fact]
    public void TestFastPeppered_MatchesFactory_Reference_AndRealHasher()
    {
        Assert.Equal(KnownHashes.TestFastPeppered, KnownHashes.Create(FastPasswordHasher.Profile, KnownHashes.Password, Salt, new FakePepper()));

        byte[] peppered = HMACSHA256.HashData(FakePepper.KeyFor(KnownHashes.PepperKeyId), Encoding.UTF8.GetBytes(KnownHashes.Password));
        Assert.Equal(KnownHashes.TestFastPeppered, Phc("test-fast,k=test-key", ReferenceArgon2id(peppered, Salt, 64, 1)));

        var hasher = new FastPasswordHasher(o => o.Pepper = new FakePepper());
        Assert.Equal(VerificationStatus.Success, hasher.Verify(KnownHashes.Password, KnownHashes.TestFastPeppered).Status);
        Assert.Equal(VerificationFailureReason.Mismatch, hasher.Verify(KnownHashes.WrongPassword, KnownHashes.TestFastPeppered).FailureReason);

        // Without the pepper configured the hasher cannot verify it.
        Assert.False(FastPasswordHasher.Shared.Verify(KnownHashes.Password, KnownHashes.TestFastPeppered).IsMatch);
    }

    [Fact]
    public void TestFastWrappedV1Sha512_MatchesFactory_TryWrap_Reference_AndRealHasher()
    {
        Assert.Equal(KnownHashes.TestFastWrappedV1Sha512,
            KnownHashes.CreateWrappedV1(FastPasswordHasher.Profile, KnownHashes.Password, KnownHashes.V1Salt, V1Algorithm.SHA512, Salt));

        // Reference: Argon2id over the inner SHA-512 digest; wp = algorithm byte (2 = SHA512) || 1.x salt.
        byte[] digest = SHA512.HashData(Encoding.UTF8.GetBytes(KnownHashes.Password).Concat(KnownHashes.V1Salt).ToArray());
        string wp = B64(new byte[] { (byte)V1Algorithm.SHA512 }.Concat(KnownHashes.V1Salt).ToArray());
        Assert.Equal(KnownHashes.TestFastWrappedV1Sha512, Phc("test-fast,w=v1,wp=" + wp, ReferenceArgon2id(digest, Salt, 64, 1)));

        PasswordHasher hasher = WithV1(V1Algorithm.SHA512);
        Assert.True(hasher.TryWrap(KnownHashes.V1Sha512, out string wrapped));
        Assert.Equal(KnownHashes.TestFastWrappedV1Sha512.Split('$')[2], wrapped.Split('$')[2]); // same parameters, random salt

        PasswordVerificationResult result = hasher.Verify(KnownHashes.Password, KnownHashes.TestFastWrappedV1Sha512);
        Assert.Equal(VerificationStatus.SuccessRehashNeeded, result.Status);
        Assert.Equal(RehashReason.Wrapped, result.RehashReason);
        Assert.Equal(VerificationFailureReason.Mismatch, hasher.Verify(KnownHashes.WrongPassword, KnownHashes.TestFastWrappedV1Sha512).FailureReason);
    }

    // ---- Production-profile samples (slow by design) ----

    [Fact]
    public void Server2026a_MatchesFactory_Reference_AndProductionHasher()
    {
        Assert.Equal(KnownHashes.Server2026a, KnownHashes.Create(HashProfile.Server2026a, KnownHashes.Password, Salt));
        Assert.Equal(KnownHashes.Server2026a, Phc("2026a", ReferenceArgon2id(Encoding.UTF8.GetBytes(KnownHashes.Password), Salt, 65536, 3)));

        var production = new PasswordHasher();
        Assert.Equal(VerificationStatus.Success, production.Verify(KnownHashes.Password, KnownHashes.Server2026a).Status);
        Assert.Equal(VerificationFailureReason.Mismatch, production.Verify(KnownHashes.WrongPassword, KnownHashes.Server2026a).FailureReason);
    }

    [Fact]
    public void Constrained2026a_MatchesFactory_Reference_AndProductionHasher()
    {
        Assert.Equal(KnownHashes.Constrained2026a, KnownHashes.Create(HashProfile.Constrained2026a, KnownHashes.Password, Salt));
        Assert.Equal(KnownHashes.Constrained2026a, Phc("2026c", ReferenceArgon2id(Encoding.UTF8.GetBytes(KnownHashes.Password), Salt, 19456, 2)));

        var production = new PasswordHasher(new PasswordHasherOptions { DefaultProfile = HashProfile.Constrained2026a });
        Assert.Equal(VerificationStatus.Success, production.Verify(KnownHashes.Password, KnownHashes.Constrained2026a).Status);
        Assert.Equal(VerificationFailureReason.Mismatch, production.Verify(KnownHashes.WrongPassword, KnownHashes.Constrained2026a).FailureReason);
    }

    [Fact]
    public void Fips2026a_MatchesFactory_Reference_AndProductionHasher()
    {
        Assert.Equal(KnownHashes.Fips2026a, KnownHashes.Create(HashProfile.Fips2026a, KnownHashes.Password, Salt));
        byte[] tag = Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(KnownHashes.Password), Salt, 210_000, HashAlgorithmName.SHA512, 64);
        Assert.Equal(KnownHashes.Fips2026a, Phc("2026f", tag));

        var production = new PasswordHasher(new PasswordHasherOptions { DefaultProfile = HashProfile.Fips2026a });
        Assert.Equal(VerificationStatus.Success, production.Verify(KnownHashes.Password, KnownHashes.Fips2026a).Status);
    }

    [Fact]
    public void ProductionSamples_AreUpgradedByFastHasher()
    {
        // The FastPasswordHasher accepts built-in profiles and flags them for rehash to test-fast.
        PasswordVerificationResult result = FastPasswordHasher.Shared.Verify(KnownHashes.Password, KnownHashes.Constrained2026a);
        Assert.Equal(RehashReason.OutdatedProfile, result.RehashReason);
        MasterlyHashAssert.UsesProfile(result.Rehash, FastPasswordHasher.ProfileId);
    }

    // ---- Failure samples ----

    [Theory]
    [InlineData(KnownHashes.UnknownProfile, VerificationFailureReason.UnknownProfile)]
    [InlineData(KnownHashes.Malformed, VerificationFailureReason.MalformedHash)]
    [InlineData(KnownHashes.UnknownFormat, VerificationFailureReason.UnknownFormat)]
    public void FailureSamples_FailAsDocumented_WithEveryHasher(string sample, VerificationFailureReason reason)
    {
        Assert.Equal(reason, FastPasswordHasher.Shared.Verify(KnownHashes.Password, sample).FailureReason);
        Assert.Equal(reason, new PasswordHasher().Verify(KnownHashes.Password, sample).FailureReason);
        Assert.Equal(reason, FastPasswordHasher.Shared.VerifyOrDummy(KnownHashes.Password, sample).FailureReason);
    }

    [Fact]
    public void SafetyProperty_ProductionRejectsEveryTestFastSample()
    {
        var production = new PasswordHasher();
        foreach (string sample in new[] { KnownHashes.TestFast, KnownHashes.TestFastPeppered, KnownHashes.TestFastWrappedV1Sha512 })
        {
            PasswordVerificationResult result = production.Verify(KnownHashes.Password, sample);
            Assert.False(result.IsMatch);
            Assert.Equal(VerificationFailureReason.UnknownProfile, result.FailureReason);
        }
    }

    // ---- Factories ----

    [Fact]
    public void Create_IsDeterministic_AndSaltSensitive()
    {
        byte[] other = (byte[])Salt.Clone();
        other[15] ^= 1;
        string a = KnownHashes.Create(FastPasswordHasher.Profile, "pw-123456", Salt);
        Assert.Equal(a, KnownHashes.Create(FastPasswordHasher.Profile, "pw-123456", Salt));
        Assert.NotEqual(a, KnownHashes.Create(FastPasswordHasher.Profile, "pw-123456", other));
        Assert.True(FastPasswordHasher.Shared.Verify("pw-123456", a).IsMatch);
    }

    [Fact]
    public void Create_NormalizesPassword_LikeTheHasher()
    {
        // U+212B ANGSTROM SIGN is NFKC-equivalent to U+00C5; the hasher normalizes, so must the factory.
        string stored = KnownHashes.Create(FastPasswordHasher.Profile, "Å-password", Salt);
        Assert.Equal(stored, KnownHashes.Create(FastPasswordHasher.Profile, "Å-password", Salt));
        Assert.True(FastPasswordHasher.Shared.Verify("Å-password", stored).IsMatch);
    }

    [Fact]
    public void Create_WithExplicitPepperKeyId()
    {
        var pepper = new FakePepper("k2", "k1");
        string stored = KnownHashes.Create(FastPasswordHasher.Profile, "pw-123456", Salt, pepper, "k1");
        MasterlyHashAssert.IsPeppered(stored, "k1");

        PasswordVerificationResult result = new FastPasswordHasher(o => o.Pepper = pepper).Verify("pw-123456", stored);
        Assert.Equal(RehashReason.OutdatedPepperKey, result.RehashReason);
    }

    [Fact]
    public void Create_ZeroesNothingTheCallerOwns()
    {
        byte[] salt = (byte[])Salt.Clone();
        KnownHashes.Create(FastPasswordHasher.Profile, "pw-123456", salt);
        Assert.Equal(Salt, salt);
    }

    [Fact]
    public void Create_ZeroesEncodedPassword_WhenPepperThrows()
    {
        var pepper = new CapturingThrowingPepper();
        Assert.Throws<InvalidOperationException>(() => KnownHashes.Create(FastPasswordHasher.Profile, "secret-pw", Salt, pepper));
        Assert.NotNull(pepper.Input);
        Assert.NotEmpty(pepper.Input!);
        Assert.All(pepper.Input!, b => Assert.Equal(0, b));
    }

    [Fact]
    public void TestFastWrappedV1Sha512_VerifiesWithDefaultLegacyFormats()
    {
        // The algorithm lives in wp[0], so the default auto-detecting V1LegacyFormat.Instance verifies it.
        PasswordVerificationResult result = FastPasswordHasher.Shared.Verify(KnownHashes.Password, KnownHashes.TestFastWrappedV1Sha512);
        Assert.Equal(VerificationStatus.SuccessRehashNeeded, result.Status);
        Assert.Equal(RehashReason.Wrapped, result.RehashReason);
        Assert.False(FastPasswordHasher.Shared.Verify(KnownHashes.WrongPassword, KnownHashes.TestFastWrappedV1Sha512).IsMatch);

        foreach (V1Algorithm algorithm in new[] { V1Algorithm.SHA256, V1Algorithm.SHA384 })
        {
            string wrapped = KnownHashes.CreateWrappedV1(FastPasswordHasher.Profile, KnownHashes.Password, KnownHashes.V1Salt, algorithm, Salt);
            Assert.True(FastPasswordHasher.Shared.Verify(KnownHashes.Password, wrapped).IsMatch);
        }
    }

    private sealed class CapturingThrowingPepper : Masterly.Hash.Pepper.IPasswordPepper
    {
        public byte[]? Input { get; private set; }
        public string CurrentKeyId => "k1";
        public bool IsKnownKey(string keyId) => keyId == "k1";
        public byte[] Apply(string keyId, byte[] input)
        {
            Input = input;
            throw new InvalidOperationException("pepper outage");
        }
        public System.Threading.Tasks.ValueTask<byte[]> ApplyAsync(string keyId, byte[] input, System.Threading.CancellationToken cancellationToken = default) =>
            new(Apply(keyId, input));
    }

    [Fact]
    public void Factories_ValidateArguments()
    {
        HashProfile p = FastPasswordHasher.Profile;
        Assert.Throws<ArgumentNullException>(() => KnownHashes.Create(null!, "pw", Salt));
        Assert.Throws<ArgumentNullException>(() => KnownHashes.Create(p, null!, Salt));
        Assert.Throws<ArgumentNullException>(() => KnownHashes.Create(p, "pw", null!));
        Assert.Throws<ArgumentException>(() => KnownHashes.Create(p, "", Salt));
        Assert.Throws<ArgumentException>(() => KnownHashes.Create(p, "pw", new byte[15]));
        Assert.Throws<ArgumentException>(() => KnownHashes.Create(p, "pw", Salt, new FakePepper(), "bad id"));
        Assert.Throws<ArgumentException>(() => KnownHashes.Create(p, "pw", Salt, new FakePepper(), "unknown"));
        Assert.Throws<ArgumentException>(() => KnownHashes.Create(p, "pw-123456", Salt, null, "k1")); // key id without a pepper

        Assert.Throws<ArgumentNullException>(() => KnownHashes.CreateV1(null!, Salt));
        Assert.Throws<ArgumentNullException>(() => KnownHashes.CreateV1("pw", null!));
        Assert.Throws<ArgumentOutOfRangeException>(() => KnownHashes.CreateV1("pw", Salt, (V1Algorithm)99));

        Assert.Throws<ArgumentNullException>(() => KnownHashes.CreateWrappedV1(null!, "pw", Salt, V1Algorithm.SHA512, Salt));
        Assert.Throws<ArgumentNullException>(() => KnownHashes.CreateWrappedV1(p, null!, Salt, V1Algorithm.SHA512, Salt));
        Assert.Throws<ArgumentNullException>(() => KnownHashes.CreateWrappedV1(p, "pw", null!, V1Algorithm.SHA512, Salt));
        Assert.Throws<ArgumentNullException>(() => KnownHashes.CreateWrappedV1(p, "pw", Salt, V1Algorithm.SHA512, null!));
        Assert.Throws<ArgumentException>(() => KnownHashes.CreateWrappedV1(p, "pw", Salt, V1Algorithm.SHA512, new byte[8]));
    }
}
