using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Masterly.Hash.Pepper;
using Masterly.Hash.Primitives;

namespace Masterly.Hash.Detection.Tests;

public class HoneywordServiceTests
{
    [Fact]
    public void Create_ProducesKTagsUnderOneSalt_AndVerifyFindsRealIndex()
    {
        HoneywordService service = TestSupport.Service();
        HoneywordRecord record = service.Create("Tr0ub4dor&3");

        Assert.Equal(20, record.SweetwordCount);
        Assert.InRange(record.RealIndex, 0, 19);
        (string parameters, byte[] salt, byte[][] tags) = TestSupport.Split(record.StoredHash);
        Assert.Equal("p=test", parameters);
        Assert.Equal(16, salt.Length);
        Assert.Equal(20, tags.Length);
        Assert.All(tags, t => Assert.Equal(32, t.Length));
        Assert.Equal(20, tags.Select(Convert.ToBase64String).Distinct().Count());

        Assert.Equal(record.RealIndex, service.Verify("Tr0ub4dor&3", record.StoredHash));
    }

    [Fact]
    public void Verify_WrongPassword_ReturnsMinusOne()
    {
        HoneywordService service = TestSupport.Service();
        HoneywordRecord record = service.Create("correct horse", 5);

        Assert.Equal(-1, service.Verify("wrong horse", record.StoredHash));
        HoneywordVerification detail = service.VerifyDetailed("wrong horse", record.StoredHash);
        Assert.Equal(HoneywordVerificationStatus.Mismatch, detail.Status);
        Assert.False(detail.IsSweetwordMatch);
        Assert.Equal(-1, detail.Index);
    }

    [Fact]
    public void Verify_Decoy_ReturnsItsIndex_WhichIsNotTheRealIndex()
    {
        HoneywordService service = TestSupport.Service(new FixedGenerator());
        HoneywordRecord record = service.Create("real-password", 6);

        var seen = new HashSet<int> { record.RealIndex };
        for (int i = 0; i < 5; i++)
        {
            int index = service.Verify(FixedGenerator.Decoy(i), record.StoredHash);
            Assert.InRange(index, 0, 5);
            Assert.NotEqual(record.RealIndex, index);
            Assert.True(seen.Add(index), "Each sweetword has its own index.");
        }
        Assert.Equal(6, seen.Count);
    }

    [Fact]
    public void Tags_MatchHashPrimitivesDeriveKey()
    {
        HoneywordService service = TestSupport.Service(new FixedGenerator());
        HoneywordRecord record = service.Create("real-password", 4);
        (_, byte[] salt, byte[][] tags) = TestSupport.Split(record.StoredHash);

        byte[] expected = HashPrimitives.DeriveKey(TestSupport.Fast, HashPrimitives.EncodePassword("real-password"), salt);
        Assert.Equal(expected, tags[record.RealIndex]);
    }

    /// <summary>
    /// PBKDF2-HMAC-SHA512 vector P="passwordPASSWORDpassword", S="saltSALTsaltSALTsaltSALTsaltSALTsalt", c=4096,
    /// dkLen=64, from the widely used PBKDF2-HMAC-SHA2 test vectors (Anti-weakpasswords, also used by the
    /// Botan and cryptsetup test suites). Verifies the stored format and KDF mapping end to end against a
    /// hand-built $mhw$ string.
    /// </summary>
    [Fact]
    public void KnownAnswer_Pbkdf2Sha512_HandBuiltHash()
    {
        byte[] expected = Convert.FromHexString(
            "8c0511f4c6e597c6ac6315d8f0362e225f3c501495ba23b868c005174dc4ee71" +
            "115b59f9e60cd9532fa33e0f75aefe30225c583a186cd82bd4daea9724a3d3b8");
        byte[] salt = Encoding.ASCII.GetBytes("saltSALTsaltSALTsaltSALTsaltSALTsalt");
        HashProfile profile = HashProfile.Pbkdf2Sha512("kat", 4096, saltLength: 36, tagLength: 64);
        var service = new HoneywordService(profile, Array.Empty<HashProfile>(), new HoneywordServiceOptions { AllowWeakProfiles = true });

        byte[] decoy = new byte[64];
        decoy[0] = 1;
        string stored = "$mhw$p=kat$" + HashPrimitives.ToB64(salt) + "$" + HashPrimitives.ToB64(decoy) + "," + HashPrimitives.ToB64(expected);

        Assert.Equal(1, service.Verify("passwordPASSWORDpassword", stored));
        Assert.Equal(-1, service.Verify("passwordPASSWORDpassworD", stored));
    }

    [Fact]
    public void Verify_CostsExactlyOneKdfCall_Create_CostsK()
    {
        HoneywordService service = TestSupport.Service();
        TestSupport.StrongBox calls = TestSupport.Count(service);

        HoneywordRecord record = service.Create("pa55word!", 20);
        Assert.Equal(20, calls.Value);

        calls.Value = 0;
        service.Verify("pa55word!", record.StoredHash);
        Assert.Equal(1, calls.Value);

        calls.Value = 0;
        service.Verify("not it", record.StoredHash);
        Assert.Equal(1, calls.Value);
    }

    [Fact]
    public void VerifyOrDummy_UnknownUser_StillDerivesOnce()
    {
        HoneywordService service = TestSupport.Service();
        TestSupport.StrongBox calls = TestSupport.Count(service);

        HoneywordVerification result = service.VerifyOrDummy("whatever", null);
        Assert.Equal(HoneywordVerificationStatus.NoStoredHash, result.Status);
        Assert.Equal(-1, result.Index);
        Assert.Equal(1, calls.Value);

        calls.Value = 0;
        Assert.Equal(HoneywordVerificationStatus.NoStoredHash, service.VerifyDetailed("whatever", null).Status);
        Assert.Equal(0, calls.Value);
    }

    [Fact]
    public void MalformedHash_DoesNotDerive()
    {
        HoneywordService service = TestSupport.Service();
        TestSupport.StrongBox calls = TestSupport.Count(service);
        Assert.Equal(-1, service.Verify("pw", "$mhw$garbage"));
        Assert.Equal(0, calls.Value);
    }

    public static IEnumerable<object[]> MalformedHashes()
    {
        string salt = HashPrimitives.ToB64(new byte[16]);
        string tag = HashPrimitives.ToB64(new byte[32]);
        string two = tag + "," + tag;
        string[] values =
        {
            "",
            "$",
            "$mhw$",
            "$mhw$$$",
            "$mhw$p=test",
            "$mhw$p=test$" + salt,
            "$mhw$p=test$" + salt + "$",
            "$mhw$p=test$" + salt + "$" + tag,                     // one tag only
            "$mhw$p=test$" + salt + "$" + two + "$",               // extra section
            "$mhw$p=test$" + salt + "$" + tag + ",",               // empty tag
            "$mhw$p=test$" + salt + "$," + tag,
            "$mhw$p=test$" + salt + "$" + tag + ",,"+ tag,
            "$mhw$p=test$" + salt + "$" + tag + ",!!!",            // bad base64
            "$mhw$p=test$" + salt + "=$" + two,                    // padded base64
            "$mhw$p=test$$" + two,                                 // empty salt
            "$mhw$p=TEST$" + salt + "$" + two,                     // invalid profile id
            "$mhw$p=$" + salt + "$" + two,
            "$mhw$q=test$" + salt + "$" + two,
            "$mhw$p=test,k=$" + salt + "$" + two,
            "$mhw$p=test,k=bad key$" + salt + "$" + two,
            "$mhw$p=test,x=1$" + salt + "$" + two,
            "$mhw$p=test,k=a,k=b$" + salt + "$" + two,
            "$mhw$p=test$" + HashPrimitives.ToB64(new byte[15]) + "$" + two,             // short salt
            "$mhw$p=test$" + salt + "$" + tag + "," + HashPrimitives.ToB64(new byte[31]), // short tag
            "$mh$p=test$" + salt + "$" + tag,                      // core format, not honeywords
            "$MHW$p=test$" + salt + "$" + two,
            " $mhw$p=test$" + salt + "$" + two,
            "$mhw$p=test$" + salt + "$" + string.Join(",", Enumerable.Repeat(tag, 101)), // > MaxSweetwordCount
            "$mhw$p=test$" + salt + "$" + new string('A', 100_000),
            "\0\0\0",
            "$mhw$p=test$\uD800$" + two,
        };
        return values.Select(v => new object[] { v });
    }

    [Theory]
    [MemberData(nameof(MalformedHashes))]
    public void Verify_MalformedHash_ReturnsMinusOneWithoutThrowing(string stored)
    {
        HoneywordService service = TestSupport.Service();
        Assert.Equal(-1, service.Verify("password", stored));
        HoneywordVerification detail = service.VerifyDetailed("password", stored);
        Assert.False(detail.IsSweetwordMatch);
        Assert.NotEqual(HoneywordVerificationStatus.Mismatch, detail.Status);
    }

    [Fact]
    public void Verify_UnknownProfile_IsRejected()
    {
        HoneywordService service = TestSupport.Service();
        string tag = HashPrimitives.ToB64(new byte[32]);
        string stored = "$mhw$p=nope$" + HashPrimitives.ToB64(new byte[16]) + "$" + tag + "," + tag;
        Assert.Equal(HoneywordVerificationStatus.UnknownProfile, service.VerifyDetailed("pw", stored).Status);
    }

    [Fact]
    public void Verify_HashFromAnotherService_WithDifferentAllowlist_IsUnknownProfile()
    {
        HoneywordRecord record = TestSupport.Service().Create("password", 3);
        var other = new HoneywordService(PasswordHasher.Default);
        Assert.Equal(HoneywordVerificationStatus.UnknownProfile, other.VerifyDetailed("password", record.StoredHash).Status);
    }

    [Fact]
    public void Verify_TamperedTags_ShiftOrBreakTheMatch()
    {
        HoneywordService service = TestSupport.Service();
        HoneywordRecord record = service.Create("password", 3);
        (string parameters, byte[] salt, byte[][] tags) = TestSupport.Split(record.StoredHash);

        tags[record.RealIndex][0] ^= 1;
        string tampered = "$mhw$" + parameters + "$" + HashPrimitives.ToB64(salt) + "$" + string.Join(",", tags.Select(HashPrimitives.ToB64));
        Assert.Equal(-1, service.Verify("password", tampered));

        tags[record.RealIndex][0] ^= 1;
        Array.Reverse(tags);
        string reversed = "$mhw$" + parameters + "$" + HashPrimitives.ToB64(salt) + "$" + string.Join(",", tags.Select(HashPrimitives.ToB64));
        Assert.Equal(2 - record.RealIndex, service.Verify("password", reversed));

        salt[0] ^= 1;
        tags = TestSupport.Split(record.StoredHash).Tags;
        string resalted = "$mhw$" + parameters + "$" + HashPrimitives.ToB64(salt) + "$" + string.Join(",", tags.Select(HashPrimitives.ToB64));
        Assert.Equal(-1, service.Verify("password", resalted));
    }

    [Fact]
    public void Create_UsesFreshSaltEachTime()
    {
        HoneywordService service = TestSupport.Service();
        string a = service.Create("same", 2).StoredHash;
        string b = service.Create("same", 2).StoredHash;
        Assert.NotEqual(TestSupport.Split(a).Salt, TestSupport.Split(b).Salt);
    }

    [Fact]
    public void Create_RealIndexIsSpreadAcrossPositions()
    {
        HoneywordService service = TestSupport.Service();
        var positions = new HashSet<int>();
        for (int i = 0; i < 60 && positions.Count < 3; i++)
            positions.Add(service.Create("password", 3).RealIndex);
        // Probability of missing a position in 60 uniform draws is about 3 * (2/3)^60, i.e. 1e-10.
        Assert.Equal(3, positions.Count);
    }

    [Fact]
    public void Password_IsNfkcNormalized_LikeTheCoreHasher()
    {
        HoneywordService service = TestSupport.Service();
        HoneywordRecord record = service.Create("ｐａｓｓ", 2); // full-width "pass"
        Assert.Equal(record.RealIndex, service.Verify("pass", record.StoredHash));

        HoneywordRecord composed = service.Create("café", 2);
        Assert.Equal(composed.RealIndex, service.Verify("café", composed.StoredHash));
    }

    [Fact]
    public void EmptyPassword_CannotBeCreated_AndNeverMatches()
    {
        HoneywordService service = TestSupport.Service();
        Assert.Throws<ArgumentException>(() => service.Create(""));
        Assert.Throws<ArgumentNullException>(() => service.Create(null!));

        HoneywordRecord record = service.Create("x", 2);
        Assert.Equal(-1, service.Verify("", record.StoredHash));
        Assert.Equal(HoneywordVerificationStatus.EmptyPassword, service.VerifyDetailed("", record.StoredHash).Status);
        Assert.Throws<ArgumentNullException>(() => service.Verify(null!, record.StoredHash));
    }

    [Fact]
    public void TooLongPassword_IsRejected()
    {
        HoneywordService service = TestSupport.Service(configure: o => o.MaxPasswordBytes = 64);
        Assert.Throws<ArgumentException>(() => service.Create(new string('a', 65)));

        HoneywordRecord record = service.Create(new string('a', 64), 2);
        Assert.Equal(record.RealIndex, service.Verify(new string('a', 64), record.StoredHash));
        Assert.Equal(HoneywordVerificationStatus.PasswordTooLong, service.VerifyDetailed(new string('a', 65), record.StoredHash).Status);
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(101)]
    public void Create_SweetwordCountOutOfRange_Throws(int k)
    {
        HoneywordService service = TestSupport.Service();
        Assert.Throws<ArgumentOutOfRangeException>(() => service.Create("password", k));
    }

    [Fact]
    public void Create_MinimumTwoSweetwords_Works()
    {
        HoneywordService service = TestSupport.Service();
        HoneywordRecord record = service.Create("password", 2);
        Assert.Equal(2, TestSupport.Split(record.StoredHash).Tags.Length);
        Assert.Equal(record.RealIndex, service.Verify("password", record.StoredHash));
    }

    [Fact]
    public void Create_RejectsBadGeneratorOutput()
    {
        Assert.Throws<InvalidOperationException>(() =>
            TestSupport.Service(new FixedGenerator((_, n) => new[] { "only-one" })).Create("pw", 4));
        Assert.Throws<InvalidOperationException>(() =>
            TestSupport.Service(new FixedGenerator((_, n) => Enumerable.Repeat("same", n).ToList())).Create("pw", 3));
        Assert.Throws<InvalidOperationException>(() =>
            TestSupport.Service(new FixedGenerator((real, n) => new[] { real, "x" })).Create("pw", 3));
        Assert.Throws<InvalidOperationException>(() =>
            TestSupport.Service(new FixedGenerator((_, n) => new[] { "", "x" })).Create("pw", 3));
        Assert.Throws<InvalidOperationException>(() =>
            TestSupport.Service(new FixedGenerator((_, n) => null!)).Create("pw", 3));
        // Decoy that only differs from the real password by normalization is a duplicate.
        Assert.Throws<InvalidOperationException>(() =>
            TestSupport.Service(new FixedGenerator((_, n) => new[] { "ｐｗ", "x" })).Create("pw", 3));
    }

    [Fact]
    public void Pepper_IsAppliedAndRecorded()
    {
        var pepper = new HmacPepper("k1", SHA256.HashData(Encoding.UTF8.GetBytes("pepper")));
        HoneywordService peppered = TestSupport.Service(configure: o => o.Pepper = pepper);
        HoneywordRecord record = peppered.Create("password", 3);

        Assert.StartsWith("$mhw$p=test,k=k1$", record.StoredHash);
        Assert.Equal(record.RealIndex, peppered.Verify("password", record.StoredHash));

        HoneywordService plain = TestSupport.Service();
        Assert.Equal(HoneywordVerificationStatus.UnknownPepperKey, plain.VerifyDetailed("password", record.StoredHash).Status);

        // Without the pepper the tags do not match the plain KDF output.
        (_, byte[] salt, byte[][] tags) = TestSupport.Split(record.StoredHash);
        Assert.NotEqual(HashPrimitives.DeriveKey(TestSupport.Fast, HashPrimitives.EncodePassword("password"), salt), tags[record.RealIndex]);
    }

    [Fact]
    public async Task AsyncApis_MatchSyncApis()
    {
        HoneywordService service = TestSupport.Service();
        HoneywordRecord record = await service.CreateAsync("async-pw", 4);
        Assert.Equal(record.RealIndex, (await service.VerifyDetailedAsync("async-pw", record.StoredHash)).Index);
        Assert.Equal(HoneywordVerificationStatus.Mismatch, (await service.VerifyDetailedAsync("nope", record.StoredHash)).Status);
        Assert.Equal(HoneywordVerificationStatus.NoStoredHash, (await service.VerifyOrDummyAsync("nope", null)).Status);
    }

    [Fact]
    public void Constructor_ExplicitAllowlist_EnforcesStrengthAndUniqueness()
    {
        Assert.Throws<ArgumentException>(() => new HoneywordService(TestSupport.Fast, Array.Empty<HashProfile>()));
        Assert.Throws<ArgumentException>(() => new HoneywordService(
            TestSupport.Fast,
            new[] { HashProfile.Argon2id("test", 128, 1) },
            new HoneywordServiceOptions { AllowWeakProfiles = true }));
        Assert.Throws<ArgumentNullException>(() => new HoneywordService(null!, Array.Empty<HashProfile>()));
        Assert.Throws<ArgumentNullException>(() => new HoneywordService(HashProfile.Server2026a, null!));
        Assert.Throws<ArgumentNullException>(() => new HoneywordService((PasswordHasher)null!));

        var strong = new HoneywordService(HashProfile.Server2026a, new[] { HashProfile.Fips2026a });
        Assert.Equal(HashProfile.Server2026a, strong.DefaultProfile);
        Assert.Equal(2, strong.Profiles.Count);
    }

    [Fact]
    public void Constructor_ValidatesOptions()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => TestSupport.Service(configure: o => o.MaxSweetwordCount = 1));
        Assert.Throws<ArgumentOutOfRangeException>(() => TestSupport.Service(configure: o => o.MaxSweetwordCount = HoneywordService.MaxSweetwordLimit + 1));
        Assert.Throws<ArgumentOutOfRangeException>(() => TestSupport.Service(configure: o => o.MaxPasswordBytes = 63));
        Assert.Throws<ArgumentOutOfRangeException>(() => TestSupport.Service(configure: o => o.MaxConcurrency = -1));
        Assert.Throws<ArgumentOutOfRangeException>(() => TestSupport.Service(configure: o => o.ConcurrencyTimeout = TimeSpan.Zero));
        Assert.Throws<ArgumentException>(() => TestSupport.Service(configure: o => o.Generator = null!));
    }

    [Fact]
    public void HasherConstructor_AcceptsAllHasherProfiles_AndDefaultsToTweaking()
    {
        HoneywordService service = TestSupport.Service();
        Assert.Equal("test", service.DefaultProfile.Id);
        Assert.Contains(service.Profiles, p => p.Id == "2026a");
        Assert.Contains(service.Profiles, p => p.Id == "2026f");
        Assert.Same(TweakingHoneywordGenerator.Default, service.Generator);
    }

    [Fact]
    public void IsHoneywordHash_ChecksPrefixOnly()
    {
        Assert.True(HoneywordService.IsHoneywordHash("$mhw$anything"));
        Assert.False(HoneywordService.IsHoneywordHash("$mh$p=2026a$a$b"));
        Assert.False(HoneywordService.IsHoneywordHash(null));
    }

    [Fact]
    public void Record_ToString_DoesNotLeakTheIndex()
    {
        HoneywordRecord record = TestSupport.Service().Create("password", 7);
        string text = record.ToString();
        Assert.Equal("HoneywordRecord (k=7)", text);
        Assert.DoesNotContain(record.StoredHash, text);
    }

    [Fact]
    public void Concurrency_ManyParallelVerifies_AreCorrect()
    {
        HoneywordService service = TestSupport.Service(configure: o => o.MaxConcurrency = 2);
        HoneywordRecord record = service.Create("parallel", 5);
        int[] results = new int[64];
        Parallel.For(0, results.Length, i => results[i] = service.Verify(i % 2 == 0 ? "parallel" : "other", record.StoredHash));
        for (int i = 0; i < results.Length; i++)
            Assert.Equal(i % 2 == 0 ? record.RealIndex : -1, results[i]);
    }
}
