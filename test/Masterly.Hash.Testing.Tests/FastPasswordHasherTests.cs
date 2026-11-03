using System;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Masterly.Hash.Legacy;

namespace Masterly.Hash.Testing.Tests;

public class FastPasswordHasherTests
{
    private const string Pw = "hunter2-correct";

    [Fact]
    public void Profile_IsTheTinyTestFastArgon2idProfile()
    {
        HashProfile p = FastPasswordHasher.Profile;
        Assert.Equal("test-fast", FastPasswordHasher.ProfileId);
        Assert.Equal("test-fast", p.Id);
        Assert.Equal(HashAlgorithmKind.Argon2id, p.Algorithm);
        Assert.Equal(64, p.MemoryKiB);
        Assert.Equal(1, p.Iterations);
        Assert.Equal(1, p.Parallelism);
        Assert.False(p.MeetsRecommendedMinimum);
    }

    [Fact]
    public void Hash_UsesTestFast_AndVerifies()
    {
        var hasher = new FastPasswordHasher();
        string stored = hasher.Hash(Pw);

        Assert.StartsWith("$mh$p=test-fast$", stored);
        Assert.Equal(VerificationStatus.Success, hasher.Verify(Pw, stored).Status);
        Assert.Equal(VerificationFailureReason.Mismatch, hasher.Verify(Pw + "x", stored).FailureReason);
        Assert.False(hasher.NeedsRehash(stored));
        Assert.Same(FastPasswordHasher.Profile, hasher.DefaultProfile);
        Assert.Contains(hasher.Profiles, p => p.Id == "test-fast");
    }

    [Fact]
    public void Hash_IsSalted()
    {
        var hasher = new FastPasswordHasher();
        Assert.NotEqual(hasher.Hash(Pw), hasher.Hash(Pw));
    }

    [Fact]
    public void Hash_IsFast()
    {
        var hasher = new FastPasswordHasher();
        hasher.Hash(Pw); // warm up
        var sw = Stopwatch.StartNew();
        for (int i = 0; i < 50; i++)
            hasher.Verify(Pw, hasher.Hash(Pw));
        sw.Stop();
        // 100 KDF calls; a production profile would take tens of seconds. Generous bound for slow CI.
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(5), $"took {sw.Elapsed}");
    }

    [Fact]
    public void SafetyProperty_ProductionHasherRejectsTestFastHashes()
    {
        string stored = new FastPasswordHasher().Hash(Pw);
        var production = new PasswordHasher();

        PasswordVerificationResult result = production.Verify(Pw, stored);
        Assert.False(result.IsMatch);
        Assert.Equal(VerificationFailureReason.UnknownProfile, result.FailureReason);
        Assert.False(production.Inspect(stored).IsRecognized);
        Assert.False(production.NeedsRehash(stored));
        Assert.Equal(VerificationFailureReason.UnknownProfile, Password.Verify(Pw, stored).FailureReason);
    }

    [Fact]
    public void ProductionProfileHashes_Verify_AndAreFlaggedOutdated()
    {
        // Constrained2026a is the cheapest built-in Argon2id profile (19 MiB, t=2).
        string production = new PasswordHasher(new PasswordHasherOptions { DefaultProfile = HashProfile.Constrained2026a }).Hash(Pw);
        var fast = new FastPasswordHasher();

        PasswordVerificationResult result = fast.Verify(Pw, production);
        Assert.Equal(VerificationStatus.SuccessRehashNeeded, result.Status);
        Assert.Equal(RehashReason.OutdatedProfile, result.RehashReason);
        Assert.StartsWith("$mh$p=test-fast$", result.Rehash);
    }

    [Fact]
    public void CanHashWithBuiltInProfileExplicitly()
    {
        string stored = new FastPasswordHasher().Hash(Pw, HashProfile.Constrained2026a);
        Assert.StartsWith("$mh$p=2026c$", stored);
        Assert.True(new PasswordHasher().Verify(Pw, stored).IsMatch);
    }

    [Fact]
    public void LegacyV1Hashes_VerifyAndUpgrade_LikeProduction()
    {
        var fast = new FastPasswordHasher();
        PasswordVerificationResult result = fast.Verify(KnownHashes.Password, KnownHashes.V1Sha512);

        Assert.Equal(VerificationStatus.SuccessRehashNeeded, result.Status);
        Assert.Equal(RehashReason.LegacyFormat, result.RehashReason);
        Assert.Equal(VerificationStatus.Success, fast.Verify(KnownHashes.Password, result.Rehash!).Status);
    }

    [Fact]
    public void VerifyOrDummy_UnknownUser_FailsWithNoStoredHash()
    {
        var fast = new FastPasswordHasher();
        Assert.Equal(VerificationFailureReason.NoStoredHash, fast.VerifyOrDummy(Pw, null).FailureReason);
    }

    [Fact]
    public async Task AsyncMembers_MatchSyncBehaviour()
    {
        var fast = new FastPasswordHasher();
        string stored = await fast.HashAsync(Pw);
        Assert.Equal(VerificationStatus.Success, (await fast.VerifyAsync(Pw, stored)).Status);
        Assert.Equal(VerificationFailureReason.NoStoredHash, (await fast.VerifyOrDummyAsync(Pw, null)).FailureReason);
        Assert.True((await fast.VerifyOrDummyAsync(Pw, stored)).IsMatch);
    }

    [Fact]
    public void Configure_AddsPepper()
    {
        var fast = new FastPasswordHasher(o => o.Pepper = new FakePepper("k1"));
        string stored = fast.Hash(Pw);
        Assert.StartsWith("$mh$p=test-fast,k=k1$", stored);
        Assert.True(fast.Verify(Pw, stored).IsMatch);
    }

    [Fact]
    public void Configure_ChangingDefaultProfile_StillAcceptsTestFastHashes()
    {
        HashProfile other = HashProfile.Argon2id("test-fast2", 128, 1);
        string old = FastPasswordHasher.Shared.Hash(Pw);
        var upgraded = new FastPasswordHasher(o => o.DefaultProfile = other);

        PasswordVerificationResult result = upgraded.Verify(Pw, old);
        Assert.Equal(RehashReason.OutdatedProfile, result.RehashReason);
        Assert.StartsWith("$mh$p=test-fast2$", result.Rehash);
    }

    [Fact]
    public void Configure_DisablingWeakProfiles_Throws()
    {
        Assert.Throws<ArgumentException>(() => new FastPasswordHasher(o => o.AllowWeakProfiles = false));
    }

    [Fact]
    public void CreateOptions_HasTestDefaults()
    {
        PasswordHasherOptions options = FastPasswordHasher.CreateOptions();
        Assert.Same(FastPasswordHasher.Profile, options.DefaultProfile);
        Assert.True(options.AllowWeakProfiles);
        Assert.Equal(0, options.MaxConcurrency);
        Assert.Contains(FastPasswordHasher.Profile, options.AdditionalProfiles);
        Assert.Single(options.LegacyFormats);

        bool called = false;
        FastPasswordHasher.CreateOptions(o => called = o.AllowWeakProfiles);
        Assert.True(called);
    }

    [Fact]
    public void TryWrap_ForwardsToRealHasher()
    {
        var fast = new FastPasswordHasher(o =>
        {
            o.LegacyFormats.Clear();
            o.LegacyFormats.Add(new V1LegacyFormat(V1Algorithm.SHA512));
        });

        Assert.True(fast.TryWrap(KnownHashes.V1Sha512, out string wrapped));
        Assert.StartsWith("$mh$p=test-fast,w=v1,", wrapped);
        PasswordVerificationResult result = fast.Verify(KnownHashes.Password, wrapped);
        Assert.Equal(RehashReason.Wrapped, result.RehashReason);
        Assert.False(fast.TryWrap(KnownHashes.UnknownFormat, out _));
    }

    [Theory]
    [InlineData(KnownHashes.Malformed, VerificationFailureReason.MalformedHash)]
    [InlineData(KnownHashes.UnknownProfile, VerificationFailureReason.UnknownProfile)]
    [InlineData(KnownHashes.UnknownFormat, VerificationFailureReason.UnknownFormat)]
    [InlineData("", VerificationFailureReason.NoStoredHash)]
    [InlineData("$mh$", VerificationFailureReason.MalformedHash)]
    [InlineData("$mh$p=test-fast$$", VerificationFailureReason.MalformedHash)]
    public void Verify_BadStoredHashes_NeverThrow(string stored, VerificationFailureReason expected)
    {
        Assert.Equal(expected, FastPasswordHasher.Shared.Verify(Pw, stored).FailureReason);
    }

    [Fact]
    public void EmptyPassword_CannotBeHashed_AndNeverMatches()
    {
        var fast = FastPasswordHasher.Shared;
        Assert.Throws<ArgumentException>(() => fast.Hash(""));
        Assert.Equal(VerificationFailureReason.EmptyPassword, fast.Verify("", KnownHashes.TestFast).FailureReason);
    }

    [Fact]
    public void Shared_IsSingleton_AndInnerIsRealHasher()
    {
        Assert.Same(FastPasswordHasher.Shared, FastPasswordHasher.Shared);
        Assert.IsType<PasswordHasher>(FastPasswordHasher.Shared.Inner);
        Assert.Contains(FastPasswordHasher.Shared.Profiles, p => p.Id == "2026a");
        Assert.Contains(FastPasswordHasher.Shared.Profiles, p => p.Id == "2026c");
        Assert.Contains(FastPasswordHasher.Shared.Profiles, p => p.Id == "2026f");
    }

    [Fact]
    public void IsThreadSafe()
    {
        var fast = FastPasswordHasher.Shared;
        bool[] ok = new bool[64];
        Parallel.For(0, ok.Length, i =>
        {
            string pw = "password-" + i;
            ok[i] = fast.Verify(pw, fast.Hash(pw)).Status == VerificationStatus.Success;
        });
        Assert.True(ok.All(x => x));
    }
}
