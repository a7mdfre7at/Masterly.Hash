using System;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace Masterly.Hash.UnitTests;

public class PasswordHasherTests
{
    private const string Pw = "correct horse battery staple";

    [Fact]
    public void Hash_ThenVerify_Succeeds()
    {
        var hasher = TestHashers.Create();
        string stored = hasher.Hash(Pw);

        var result = hasher.Verify(Pw, stored);

        Assert.Equal(VerificationStatus.Success, result.Status);
        Assert.True(result.IsMatch);
        Assert.False(result.NeedsRehash);
        Assert.Null(result.Rehash);
    }

    [Fact]
    public void Verify_WrongPassword_FailsWithMismatch()
    {
        var hasher = TestHashers.Create();
        var result = hasher.Verify("wrong", hasher.Hash(Pw));

        Assert.False(result.IsMatch);
        Assert.Equal(VerificationFailureReason.Mismatch, result.FailureReason);
    }

    [Fact]
    public void Hash_IsPhcFormatWithProfileIdOnly()
    {
        string stored = TestHashers.Create().Hash(Pw);

        Assert.Matches(new Regex(@"^\$mh\$p=test-fast\$[A-Za-z0-9+/]{22}\$[A-Za-z0-9+/]{43}$"), stored);
        Assert.DoesNotContain("m=", stored);
        Assert.DoesNotContain("t=", stored);
    }

    [Fact]
    public void Hash_SamePasswordTwice_UsesDifferentSalts()
    {
        var hasher = TestHashers.Create();
        Assert.NotEqual(hasher.Hash(Pw), hasher.Hash(Pw));
    }

    [Fact]
    public void EmptyPassword_CannotBeHashed_AndNeverMatches()
    {
        var hasher = TestHashers.Create();
        Assert.Throws<ArgumentException>(() => hasher.Hash(""));
        Assert.Equal(VerificationFailureReason.EmptyPassword, hasher.Verify("", hasher.Hash("x")).FailureReason);

        // A 1.x hash of the empty password must not match (its rehash would be impossible).
        string legacyEmpty = TestHashers.Original1x("", new byte[8], Legacy.V1Algorithm.SHA512);
        Assert.Equal(VerificationFailureReason.EmptyPassword, hasher.Verify("", legacyEmpty).FailureReason);
        Assert.Equal(VerificationFailureReason.NoStoredHash, hasher.VerifyOrDummy("", null).FailureReason);
    }

    [Theory]
    [InlineData(" ")]
    [InlineData("pässwörd")]
    [InlineData("🔐🔑")]
    [InlineData("\0nul\0")]
    public void Hash_EdgeCasePasswords_RoundTrip(string password)
    {
        var hasher = TestHashers.Create();
        Assert.True(hasher.Verify(password, hasher.Hash(password)).IsMatch);
    }

    [Fact]
    public void Hash_NormalizesUnicodeWithNfkc()
    {
        var hasher = TestHashers.Create();
        string stored = hasher.Hash("ｐａｓｓ"); // full-width

        Assert.True(hasher.Verify("pass", stored).IsMatch);
        // Composed vs decomposed é.
        Assert.True(hasher.Verify("café", hasher.Hash("café")).IsMatch);
    }

    [Fact]
    public void Hash_NullPassword_Throws()
    {
        var hasher = TestHashers.Create();
        Assert.Throws<ArgumentNullException>(() => hasher.Hash(null!));
        Assert.Throws<ArgumentNullException>(() => hasher.Verify(null!, "x"));
    }

    [Fact]
    public void Hash_PasswordOverLimit_Throws_AndVerifyReportsTooLong()
    {
        var hasher = TestHashers.Create(o => o.MaxPasswordBytes = 64);
        string stored = hasher.Hash(new string('a', 64));

        Assert.Throws<ArgumentException>(() => hasher.Hash(new string('a', 65)));
        Assert.Equal(VerificationFailureReason.PasswordTooLong, hasher.Verify(new string('a', 65), stored).FailureReason);
    }

    [Fact]
    public void Hash_UnregisteredProfile_Throws()
    {
        var hasher = TestHashers.Create();
        Assert.Throws<ArgumentException>(() => hasher.Hash(Pw, TestHashers.Fast2));
    }

    [Fact]
    public void Verify_OutdatedProfile_ReturnsRehashWithCurrentProfile()
    {
        var old = TestHashers.Create();
        var current = TestHashers.Create(o =>
        {
            o.DefaultProfile = TestHashers.Fast2;
            o.AdditionalProfiles.Add(TestHashers.Fast);
        });

        var result = current.Verify(Pw, old.Hash(Pw));

        Assert.Equal(VerificationStatus.SuccessRehashNeeded, result.Status);
        Assert.Equal(RehashReason.OutdatedProfile, result.RehashReason);
        Assert.StartsWith("$mh$p=test-fast2$", result.Rehash);
        Assert.Equal(VerificationStatus.Success, current.Verify(Pw, result.Rehash!).Status);
    }

    [Fact]
    public void Verify_ComputeRehashDisabled_FlagsButDoesNotHash()
    {
        var current = TestHashers.Create(o =>
        {
            o.DefaultProfile = TestHashers.Fast2;
            o.AdditionalProfiles.Add(TestHashers.Fast);
            o.ComputeRehashOnVerify = false;
        });

        var result = current.Verify(Pw, TestHashers.Create().Hash(Pw));

        Assert.True(result.NeedsRehash);
        Assert.Null(result.Rehash);
    }

    [Fact]
    public void Verify_ProfileNotInAllowlist_FailsWithUnknownProfile()
    {
        var other = TestHashers.Create(o => o.DefaultProfile = TestHashers.Fast2);
        var hasher = TestHashers.Create();

        Assert.Equal(VerificationFailureReason.UnknownProfile, hasher.Verify(Pw, other.Hash(Pw)).FailureReason);
    }

    [Fact]
    public void Options_ProfileIdReusedWithDifferentParameters_Throws()
    {
        var impostor = HashProfile.Argon2id("2026a", memoryKiB: 64, iterations: 1);
        Assert.Throws<ArgumentException>(() => TestHashers.Create(o => o.AdditionalProfiles.Add(impostor)));
    }

    [Fact]
    public void Options_WeakProfileWithoutOptIn_Throws()
    {
        Assert.Throws<ArgumentException>(() => new PasswordHasher(new PasswordHasherOptions { DefaultProfile = TestHashers.Fast }));
    }

    [Theory]
    [InlineData("$mh$")]
    [InlineData("$mh$p=test-fast")]
    [InlineData("$mh$p=test-fast$$")]
    [InlineData("$mh$p=test-fast,m=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    [InlineData("$mh$p=test-fast,p=test-fast$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    [InlineData("$mh$p=TEST$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    [InlineData("$mh$p=test-fast$AAAAAAAAAAAAAAAAAAAAAA==$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    [InlineData("$mh$p=test-fast$AAAAAAAAAAAAAAAAAAAAAB$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")] // non-canonical
    [InlineData("$mh$p=test-fast$AAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")] // short salt
    [InlineData("$mh$p=test-fast,wp=AAAA$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")] // wp without w
    public void Verify_MalformedHash_FailsWithoutThrowing(string stored)
    {
        var result = TestHashers.Create().Verify(Pw, stored);
        Assert.Equal(VerificationFailureReason.MalformedHash, result.FailureReason);
    }

    [Fact]
    public void Verify_TamperedSaltOrTag_Mismatches()
    {
        var hasher = TestHashers.Create();
        string stored = hasher.Hash(Pw);
        string[] parts = stored.Split('$');

        string flip(string b64) => (b64[0] == 'A' ? 'B' : 'A') + b64.Substring(1);
        string badSalt = string.Join("$", parts[0], parts[1], parts[2], flip(parts[3]), parts[4]);
        string badTag = string.Join("$", parts[0], parts[1], parts[2], parts[3], flip(parts[4]));

        Assert.Equal(VerificationFailureReason.Mismatch, hasher.Verify(Pw, badSalt).FailureReason);
        Assert.Equal(VerificationFailureReason.Mismatch, hasher.Verify(Pw, badTag).FailureReason);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void Verify_NoStoredHash_Fails(string? stored)
    {
        Assert.Equal(VerificationFailureReason.NoStoredHash, TestHashers.Create().Verify(Pw, stored!).FailureReason);
    }

    [Fact]
    public void Verify_UnknownFormat_Fails()
    {
        Assert.Equal(VerificationFailureReason.UnknownFormat, TestHashers.Create().Verify(Pw, "not a hash").FailureReason);
    }

    [Fact]
    public void VerifyOrDummy_UnknownUser_FailsWithNoStoredHash()
    {
        var hasher = TestHashers.Create();
        var result = hasher.VerifyOrDummy(Pw, null);

        Assert.False(result.IsMatch);
        Assert.Equal(VerificationFailureReason.NoStoredHash, result.FailureReason);
    }

    [Fact]
    public void VerifyOrDummy_KnownUser_VerifiesNormally()
    {
        var hasher = TestHashers.Create();
        Assert.True(hasher.VerifyOrDummy(Pw, hasher.Hash(Pw)).IsMatch);
    }

    [Fact]
    public async Task AsyncApi_MatchesSyncApi()
    {
        var hasher = TestHashers.Create();
        string stored = await hasher.HashAsync(Pw);

        Assert.True(hasher.Verify(Pw, stored).IsMatch);
        Assert.True((await hasher.VerifyAsync(Pw, stored)).IsMatch);
        Assert.False((await hasher.VerifyAsync("nope", stored)).IsMatch);
        Assert.Equal(VerificationFailureReason.NoStoredHash, (await hasher.VerifyOrDummyAsync(Pw, null)).FailureReason);
    }

    [Fact]
    public void Inspect_DescribesHashes()
    {
        var hasher = TestHashers.Create();

        HashInfo current = hasher.Inspect(hasher.Hash(Pw));
        Assert.Equal("mh", current.Format);
        Assert.True(current.IsRecognized);
        Assert.Equal("test-fast", current.ProfileId);
        Assert.Same(TestHashers.Fast, current.Profile);
        Assert.False(current.NeedsRehash);

        HashInfo legacy = hasher.Inspect(TestHashers.Original1x(Pw, new byte[8], Legacy.V1Algorithm.SHA512));
        Assert.Equal("v1", legacy.Format);
        Assert.Equal(RehashReason.LegacyFormat, legacy.RehashReason);

        Assert.False(hasher.Inspect("garbage").IsRecognized);
        Assert.False(hasher.Inspect("$mh$p=nope$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").IsRecognized);
    }

    [Fact]
    public void BuiltInProfiles_AreAlwaysAccepted()
    {
        var hasher = TestHashers.Create();
        Assert.Contains(HashProfile.Server2026a, hasher.Profiles);
        Assert.Contains(HashProfile.Constrained2026a, hasher.Profiles);
        Assert.Contains(HashProfile.Fips2026a, hasher.Profiles);
    }

    [Fact]
    public void Profiles_InvalidParameters_Throw()
    {
        Assert.Throws<ArgumentException>(() => HashProfile.Argon2id("Bad Id", 65536, 3));
        Assert.Throws<ArgumentOutOfRangeException>(() => HashProfile.Argon2id("x", HashProfile.MaxMemoryKiB + 1, 3));
        Assert.Throws<ArgumentOutOfRangeException>(() => HashProfile.Argon2id("x", 65536, 0));
        Assert.Throws<ArgumentOutOfRangeException>(() => HashProfile.Argon2id("x", 65536, 3, saltLength: 8));
        Assert.Throws<ArgumentOutOfRangeException>(() => HashProfile.Pbkdf2Sha512("x", 0));
    }
}
