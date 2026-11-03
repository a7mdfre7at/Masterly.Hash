using System;
using System.Security.Cryptography;
using System.Text;

namespace Masterly.Hash.Testing.Tests;

public class MasterlyHashAssertTests
{
    private const string Pw = "my-plaintext-password";

    private static MasterlyHashAssertionException Fails(Action action) =>
        Assert.Throws<MasterlyHashAssertionException>(action);

    // ---- IsMasterlyHash ----

    [Theory]
    [InlineData(KnownHashes.TestFast)]
    [InlineData(KnownHashes.TestFastPeppered)]
    [InlineData(KnownHashes.TestFastWrappedV1Sha512)]
    [InlineData(KnownHashes.Server2026a)]
    [InlineData(KnownHashes.Fips2026a)]
    [InlineData(KnownHashes.UnknownProfile)] // well-formed even though no hasher accepts it
    public void IsMasterlyHash_Passes(string value) => MasterlyHashAssert.IsMasterlyHash(value);

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(KnownHashes.V1Sha512)]
    [InlineData(KnownHashes.Malformed)]
    [InlineData(KnownHashes.UnknownFormat)]
    [InlineData("$mh$")]
    [InlineData("$mh$p=test-fast$AAECAwQFBgcICQoLDA0ODw")]
    [InlineData("$mh$p=test-fast$AAECAwQFBgcICQoLDA0ODw==$AAAA")]
    [InlineData("$mh$p=UPPER$AAAA$AAAA")]
    [InlineData("$mh$p=test-fast,x=1$AAAA$AAAA")]
    public void IsMasterlyHash_Fails(string? value) => Fails(() => MasterlyHashAssert.IsMasterlyHash(value));

    private static string B64(int length) => Convert.ToBase64String(new byte[length]).TrimEnd('=');

    public static TheoryData<string> WrongShapes() => new()
    {
        "$mh$p=2026a$AAAA$AAAA",                                   // 3-byte salt and tag
        "$mh$p=test-fast$" + B64(16) + "$AAAA",                    // 3-byte tag
        "$mh$p=test-fast$" + B64(8) + "$" + B64(32),               // short salt
        "$mh$p=2026a$" + B64(16) + "$" + B64(64),                  // tag length of 2026f, not 2026a
        "$mh$p=2026f$" + B64(16) + "$" + B64(32),                  // tag length of 2026a, not 2026f
        "$mh$p=retired-1999$AAAA$AAAA",                            // unknown profile, impossible lengths
        "$mh$p=retired-1999$" + B64(16) + "$" + B64(65),           // unknown profile, tag above 64 bytes
        "$mh$p=test-fast,k=test-key$" + B64(16) + "$" + B64(31),   // peppered, one byte short
    };

    [Theory]
    [MemberData(nameof(WrongShapes))]
    public void IsMasterlyHash_FailsForWrongSaltOrTagLength(string value)
    {
        Fails(() => MasterlyHashAssert.IsMasterlyHash(value));
        Fails(() => MasterlyHashAssert.IsPeppered(value));
        Fails(() => MasterlyHashAssert.IsNotPeppered(value));
    }

    [Fact]
    public void IsMasterlyHash_PassesForUnknownProfileWithPlausibleLengths()
    {
        MasterlyHashAssert.IsMasterlyHash("$mh$p=custom-1$" + B64(16) + "$" + B64(16));
        MasterlyHashAssert.IsMasterlyHash("$mh$p=custom-1,k=other-key$" + B64(64) + "$" + B64(64));
    }

    [Fact]
    public void IsMasterlyHash_AndUsesProfile_FailForEveryTruncation()
    {
        // A too-short database column truncates the hash; every prefix must be rejected, as every hasher rejects it.
        foreach (string sample in new[] { KnownHashes.Server2026a, KnownHashes.TestFast, KnownHashes.TestFastPeppered, KnownHashes.Fips2026a })
        {
            string profileId = sample.Split('$')[2].Split(',')[0].Substring(2);
            for (int n = 0; n < sample.Length; n++)
            {
                string truncated = sample.Substring(0, n);
                Fails(() => MasterlyHashAssert.IsMasterlyHash(truncated));
                Fails(() => MasterlyHashAssert.UsesProfile(truncated, profileId));
            }
        }

        // The reviewer's probe lengths: canonical base64 tags that production rejects as malformed.
        var production = new PasswordHasher();
        foreach (int n in new[] { 59, 63, 67, 71, 75 })
            Assert.Equal(VerificationFailureReason.MalformedHash, production.Verify(KnownHashes.Password, KnownHashes.Server2026a.Substring(0, n)).FailureReason);
    }

    [Fact]
    public void IsMasterlyHash_HugeInput_FailsWithoutThrowingOtherExceptions()
    {
        Fails(() => MasterlyHashAssert.IsMasterlyHash("$mh$p=test-fast$" + new string('A', 100_000) + "$AAAA"));
    }

    // ---- UsesProfile ----

    [Fact]
    public void UsesProfile_PassesAndFails()
    {
        MasterlyHashAssert.UsesProfile(KnownHashes.TestFast, "test-fast");
        MasterlyHashAssert.UsesProfile(KnownHashes.TestFast, FastPasswordHasher.Profile);
        MasterlyHashAssert.UsesProfile(KnownHashes.Server2026a, HashProfile.Server2026a);

        var ex = Fails(() => MasterlyHashAssert.UsesProfile(KnownHashes.TestFast, "2026a"));
        Assert.Contains("'2026a'", ex.Message);
        Assert.Contains("'test-fast'", ex.Message);
        Fails(() => MasterlyHashAssert.UsesProfile(KnownHashes.V1Sha512, "test-fast"));
        Fails(() => MasterlyHashAssert.UsesProfile(null, "test-fast"));
        Assert.Throws<ArgumentNullException>(() => MasterlyHashAssert.UsesProfile(KnownHashes.TestFast, (string)null!));
        Assert.Throws<ArgumentNullException>(() => MasterlyHashAssert.UsesProfile(KnownHashes.TestFast, (HashProfile)null!));
    }

    // ---- IsPeppered ----

    [Fact]
    public void IsPeppered_PassesAndFails()
    {
        MasterlyHashAssert.IsPeppered(KnownHashes.TestFastPeppered, "test-key");
        MasterlyHashAssert.IsPeppered(KnownHashes.TestFastPeppered);
        MasterlyHashAssert.IsNotPeppered(KnownHashes.TestFast);

        Assert.Contains("not peppered", Fails(() => MasterlyHashAssert.IsPeppered(KnownHashes.TestFast, "test-key")).Message);
        Assert.Contains("'other'", Fails(() => MasterlyHashAssert.IsPeppered(KnownHashes.TestFastPeppered, "other")).Message);
        Fails(() => MasterlyHashAssert.IsPeppered(KnownHashes.TestFast));
        Fails(() => MasterlyHashAssert.IsNotPeppered(KnownHashes.TestFastPeppered));
        Fails(() => MasterlyHashAssert.IsPeppered(KnownHashes.V1Sha512, "test-key"));
        Assert.Throws<ArgumentNullException>(() => MasterlyHashAssert.IsPeppered(KnownHashes.TestFastPeppered, null!));
    }

    // ---- NeedsRehash ----

    [Fact]
    public void NeedsRehash_PassesForOutdatedHashes()
    {
        var fast = FastPasswordHasher.Shared;
        MasterlyHashAssert.NeedsRehash(fast, KnownHashes.V1Sha512);
        MasterlyHashAssert.NeedsRehash(fast, KnownHashes.Server2026a);
        MasterlyHashAssert.DoesNotNeedRehash(fast, KnownHashes.TestFast);
        MasterlyHashAssert.DoesNotNeedRehash(new PasswordHasher(), KnownHashes.Server2026a);
    }

    [Fact]
    public void NeedsRehash_FailsForCurrentOrUnrecognizedHashes()
    {
        var fast = FastPasswordHasher.Shared;
        Assert.Contains("current", Fails(() => MasterlyHashAssert.NeedsRehash(fast, KnownHashes.TestFast)).Message);
        Assert.Contains("does not recognize", Fails(() => MasterlyHashAssert.NeedsRehash(fast, KnownHashes.UnknownProfile)).Message);
        Assert.Contains("does not recognize", Fails(() => MasterlyHashAssert.NeedsRehash(new PasswordHasher(), KnownHashes.TestFast)).Message);
        Fails(() => MasterlyHashAssert.NeedsRehash(fast, KnownHashes.Malformed));
        Fails(() => MasterlyHashAssert.NeedsRehash(fast, null));
        Fails(() => MasterlyHashAssert.NeedsRehash(fast, ""));
        Assert.Contains("OutdatedProfile", Fails(() => MasterlyHashAssert.DoesNotNeedRehash(fast, KnownHashes.Server2026a)).Message);
        Fails(() => MasterlyHashAssert.DoesNotNeedRehash(fast, KnownHashes.UnknownFormat));
        Assert.Throws<ArgumentNullException>(() => MasterlyHashAssert.NeedsRehash(null!, KnownHashes.TestFast));
    }

    // ---- Verifies ----

    [Fact]
    public void Verifies_AndDoesNotVerify()
    {
        var fast = FastPasswordHasher.Shared;
        Assert.Equal(VerificationStatus.Success, MasterlyHashAssert.Verifies(fast, KnownHashes.Password, KnownHashes.TestFast).Status);
        Assert.Equal(VerificationFailureReason.Mismatch, MasterlyHashAssert.DoesNotVerify(fast, KnownHashes.WrongPassword, KnownHashes.TestFast).FailureReason);

        Assert.Contains("Mismatch", Fails(() => MasterlyHashAssert.Verifies(fast, KnownHashes.WrongPassword, KnownHashes.TestFast)).Message);
        Fails(() => MasterlyHashAssert.Verifies(fast, KnownHashes.Password, KnownHashes.Malformed));
        Fails(() => MasterlyHashAssert.Verifies(fast, KnownHashes.Password, null));
        Fails(() => MasterlyHashAssert.DoesNotVerify(fast, KnownHashes.Password, KnownHashes.TestFast));
        Assert.Throws<ArgumentNullException>(() => MasterlyHashAssert.Verifies(fast, null!, KnownHashes.TestFast));
    }

    [Fact]
    public void Verifies_AndDoesNotVerify_ArgumentValidation()
    {
        var fast = FastPasswordHasher.Shared;

        Assert.Equal("hasher", Assert.Throws<ArgumentNullException>(() => MasterlyHashAssert.Verifies(null!, Pw, KnownHashes.TestFast)).ParamName);
        Assert.Equal("password", Assert.Throws<ArgumentNullException>(() => MasterlyHashAssert.Verifies(fast, null!, KnownHashes.TestFast)).ParamName);
        Assert.Equal("hasher", Assert.Throws<ArgumentNullException>(() => MasterlyHashAssert.DoesNotVerify(null!, Pw, KnownHashes.TestFast)).ParamName);
        Assert.Equal("password", Assert.Throws<ArgumentNullException>(() => MasterlyHashAssert.DoesNotVerify(fast, null!, KnownHashes.TestFast)).ParamName);
    }

    [Fact]
    public void DoesNotVerify_ReportsStatus_AndUnwrapsRecorders()
    {
        var recorder = new RecordingPasswordHasher();

        Assert.Contains("Success", Fails(() => MasterlyHashAssert.DoesNotVerify(recorder, KnownHashes.Password, KnownHashes.TestFast)).Message);
        Assert.Contains("SuccessRehashNeeded", Fails(() => MasterlyHashAssert.DoesNotVerify(recorder, KnownHashes.Password, KnownHashes.V1Sha512)).Message);
        Assert.Equal(VerificationFailureReason.NoStoredHash, MasterlyHashAssert.DoesNotVerify(recorder, KnownHashes.Password, null).FailureReason);
        Assert.Empty(recorder.Calls);
    }

    // ---- Failure descriptions ----

    [Fact]
    public void FailureMessage_NamesThePepperKey_WhenTheHasherCannotUseIt()
    {
        // FastPasswordHasher.Shared has no pepper, so it cannot verify a peppered hash.
        var ex = Fails(() => MasterlyHashAssert.NeedsRehash(FastPasswordHasher.Shared, KnownHashes.TestFastPeppered));

        Assert.Contains("does not recognize", ex.Message);
        Assert.Contains("format 'mh'", ex.Message);
        Assert.Contains("profile 'test-fast'", ex.Message);
        Assert.Contains($"pepper key '{KnownHashes.PepperKeyId}'", ex.Message);
        Assert.DoesNotContain("wraps", ex.Message);
    }

    [Fact]
    public void FailureMessage_NamesTheWrappedFormat()
    {
        var ex = Fails(() => MasterlyHashAssert.DoesNotNeedRehash(FastPasswordHasher.Shared, KnownHashes.TestFastWrappedV1Sha512));

        Assert.Contains("would be rehashed (Wrapped;", ex.Message);
        Assert.Contains("profile 'test-fast'", ex.Message);
        Assert.Contains("wraps 'v1'", ex.Message);
        Assert.DoesNotContain("pepper key", ex.Message);
    }

    [Fact]
    public void FailureMessage_UnrecognizedWrappedHash_NamesTheWrappedFormat()
    {
        var noLegacy = new FastPasswordHasher(o => o.LegacyFormats.Clear());

        var ex = Fails(() => MasterlyHashAssert.NeedsRehash(noLegacy, KnownHashes.TestFastWrappedV1Sha512));

        Assert.Contains("does not recognize", ex.Message);
        Assert.Contains("wraps 'v1'", ex.Message);
    }

    [Fact]
    public void FailureMessage_PepperedHashWithRetiredKey_NamesTheKey()
    {
        var rotated = new FastPasswordHasher(o => o.Pepper = new FakePepper("new-key", KnownHashes.PepperKeyId));

        var ex = Fails(() => MasterlyHashAssert.DoesNotNeedRehash(rotated, KnownHashes.TestFastPeppered));

        Assert.Contains("OutdatedPepperKey", ex.Message);
        Assert.Contains($"pepper key '{KnownHashes.PepperKeyId}'", ex.Message);
        MasterlyHashAssert.NeedsRehash(rotated, KnownHashes.TestFastPeppered);
    }

    [Fact]
    public void IsNotPlaintext_DetectsUrlSafeBase64()
    {
        const string password = "???>>>???"; // UTF-8 base64 "Pz8/Pj4+Pz8/" uses both '+' and '/'
        byte[] utf8 = Encoding.UTF8.GetBytes(password);
        string urlSafe = Convert.ToBase64String(utf8).Replace('+', '-').Replace('/', '_');
        Assert.Equal("Pz8_Pj4-Pz8_", urlSafe);

        Assert.Contains("base64", Fails(() => MasterlyHashAssert.IsNotPlaintext(urlSafe, password)).Message);
        Assert.Contains("base64", Fails(() => MasterlyHashAssert.IsNotPlaintext("token=" + urlSafe, password)).Message);
    }

    [Fact]
    public void IsNotPlaintext_ShortPassword_HexIsChecked_ShortBase64IsNot()
    {
        // "abc" is 3 bytes: hex "616263" is long enough to search for; base64 "YWJj" is not.
        Assert.Contains("hex", Fails(() => MasterlyHashAssert.IsNotPlaintext("id:616263", "abc")).Message);
        MasterlyHashAssert.IsNotPlaintext("id:YWJj", "abc");
    }

    [Fact]
    public void IsNotPlaintext_TwoBytePassword_OnlyLongEnoughEncodingsAreChecked()
    {
        // UTF-8 "ab" is 2 bytes: hex "6162" is too short to search for, but UTF-16LE hex "61006200" is not.
        MasterlyHashAssert.IsNotPlaintext("id:6162", "ab");
        Assert.Contains("hex", Fails(() => MasterlyHashAssert.IsNotPlaintext("id:61006200", "ab")).Message);
        Fails(() => MasterlyHashAssert.IsNotPlaintext("AB", "ab"));
    }

    // ---- IsNotPlaintext ----

    [Fact]
    public void IsNotPlaintext_PassesForRealHashes()
    {
        string stored = FastPasswordHasher.Shared.Hash(Pw);
        MasterlyHashAssert.IsNotPlaintext(stored, Pw);
        MasterlyHashAssert.IsNotPlaintext(KnownHashes.TestFast, KnownHashes.Password);
        MasterlyHashAssert.IsNotPlaintext(KnownHashes.V1Sha512, KnownHashes.Password); // salted (weak, but not a leak)
        MasterlyHashAssert.IsNotPlaintext(null, Pw);
    }

    [Theory]
    [InlineData(Pw)]
    [InlineData("MY-PLAINTEXT-PASSWORD")]
    [InlineData("{\"password\":\"my-plaintext-password\"}")]
    [InlineData("prefix:my-plaintext-password:suffix")]
    public void IsNotPlaintext_DetectsPlaintext(string stored)
    {
        var ex = Fails(() => MasterlyHashAssert.IsNotPlaintext(stored, Pw));
        Assert.DoesNotContain(Pw, ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void IsNotPlaintext_ShortPassword_OnlyEqualityIsChecked()
    {
        Fails(() => MasterlyHashAssert.IsNotPlaintext("abc", "abc"));
        MasterlyHashAssert.IsNotPlaintext("xxabcxx", "abc"); // too short for a reliable containment check
    }

    [Fact]
    public void IsNotPlaintext_DetectsEncodings()
    {
        byte[] utf8 = Encoding.UTF8.GetBytes(Pw);
        Fails(() => MasterlyHashAssert.IsNotPlaintext(Convert.ToBase64String(utf8), Pw));
        Fails(() => MasterlyHashAssert.IsNotPlaintext(Convert.ToBase64String(utf8).TrimEnd('='), Pw));
        Fails(() => MasterlyHashAssert.IsNotPlaintext(Convert.ToHexString(utf8), Pw));
        Fails(() => MasterlyHashAssert.IsNotPlaintext(Convert.ToHexString(utf8).ToLowerInvariant(), Pw));
    }

    [Fact]
    public void IsNotPlaintext_DetectsUtf16Forms()
    {
        byte[] utf16 = Encoding.Unicode.GetBytes(Pw);
        Fails(() => MasterlyHashAssert.IsNotPlaintext(Convert.ToBase64String(utf16), Pw));
        Fails(() => MasterlyHashAssert.IsNotPlaintext(Convert.ToHexString(utf16), Pw));
        foreach (byte[] digest in new[] { MD5.HashData(utf16), SHA1.HashData(utf16), SHA256.HashData(utf16), SHA384.HashData(utf16), SHA512.HashData(utf16) })
        {
            Fails(() => MasterlyHashAssert.IsNotPlaintext(Convert.ToHexString(digest), Pw));
            Fails(() => MasterlyHashAssert.IsNotPlaintext(Convert.ToBase64String(digest), Pw));
        }
    }

    [Fact]
    public void IsNotPlaintext_DetectsNfkcForms()
    {
        const string fullWidth = "\uFF50\uFF41\uFF53\uFF53\uFF57\uFF4F\uFF52\uFF44\uFF11\uFF12"; // "password12" in full-width forms
        string normalized = fullWidth.Normalize(NormalizationForm.FormKC);
        Assert.Equal("password12", normalized);
        Fails(() => MasterlyHashAssert.IsNotPlaintext(normalized, fullWidth));
        Fails(() => MasterlyHashAssert.IsNotPlaintext("user:" + normalized, fullWidth));
        byte[] nfkcUtf8 = Encoding.UTF8.GetBytes(normalized);
        Fails(() => MasterlyHashAssert.IsNotPlaintext(Convert.ToBase64String(nfkcUtf8), fullWidth));
        Fails(() => MasterlyHashAssert.IsNotPlaintext(Convert.ToHexString(SHA256.HashData(nfkcUtf8)), fullWidth));

        // A real hash of the same password is still fine.
        MasterlyHashAssert.IsNotPlaintext(FastPasswordHasher.Shared.Hash(fullWidth), fullWidth);
    }

    [Fact]
    public void IsNotPlaintext_InvalidUtf16Password_DoesNotThrowOtherExceptions()
    {
        const string lone = "abc\uD800def-ghi";
        MasterlyHashAssert.IsNotPlaintext(FastPasswordHasher.Shared.Hash("abcdef-ghi"), lone); // hashers reject lone surrogates
        Fails(() => MasterlyHashAssert.IsNotPlaintext("x" + lone, lone));
    }

    [Fact]
    public void IsNotPlaintext_IgnoresIdentifiersInsideMasterlyHashes()
    {
        // The password equals the pepper key id or profile id written into the hash: not a leak.
        string peppered = new FastPasswordHasher(o => o.Pepper = new FakePepper()).Hash("test-key");
        MasterlyHashAssert.IsNotPlaintext(peppered, "test-key");
        MasterlyHashAssert.IsNotPlaintext(FastPasswordHasher.Shared.Hash("test-fast"), "test-fast");
        MasterlyHashAssert.IsNotPlaintext(KnownHashes.TestFastWrappedV1Sha512, "test-fast,w=v1");

        // Outside a well-formed Masterly hash the whole value is still searched.
        Fails(() => MasterlyHashAssert.IsNotPlaintext("$mh$p=test-fast$broken:test-key", "test-key"));
        Fails(() => MasterlyHashAssert.IsNotPlaintext("test-key", "test-key"));
    }

    [Fact]
    public void IsNotPlaintext_DetectsEncodingsInsideMasterlyShapedValue()
    {
        // A value shaped like a Masterly hash whose "tag" is base64 of the password is still a leak.
        byte[] utf8 = Encoding.UTF8.GetBytes(Pw);
        string forged = "$mh$p=custom-1$" + B64(16) + "$" + Convert.ToBase64String(utf8).TrimEnd('=');
        Fails(() => MasterlyHashAssert.IsNotPlaintext(forged, Pw));
    }

    [Fact]
    public void IsNotPlaintext_DetectsUnsaltedDigests()
    {
        byte[] utf8 = Encoding.UTF8.GetBytes(Pw);
        foreach (byte[] digest in new[] { MD5.HashData(utf8), SHA1.HashData(utf8), SHA256.HashData(utf8), SHA384.HashData(utf8), SHA512.HashData(utf8) })
        {
            Fails(() => MasterlyHashAssert.IsNotPlaintext(Convert.ToHexString(digest).ToLowerInvariant(), Pw));
            Fails(() => MasterlyHashAssert.IsNotPlaintext("sha$" + Convert.ToBase64String(digest), Pw));
        }

        // A 1.x hash with an empty salt is just base64(SHA-512(password)).
        Fails(() => MasterlyHashAssert.IsNotPlaintext(KnownHashes.CreateV1(Pw, Array.Empty<byte>()), Pw));
    }

    // Known-answer digests of "abc": MD5 from RFC 1321 appendix A.5; SHA-1 and SHA-256 from FIPS 180-2 appendices A.1 and B.1.
    [Theory]
    [InlineData("900150983cd24fb0d6963f7d28e17f72", "MD5")]
    [InlineData("a9993e364706816aba3e25717850c26c9cd0d89d", "SHA-1")]
    [InlineData("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "SHA-256")]
    [InlineData("BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD", "SHA-256")]
    public void IsNotPlaintext_DetectsPublishedTestVectors(string stored, string algorithm)
    {
        var ex = Fails(() => MasterlyHashAssert.IsNotPlaintext(stored, "abc"));
        Assert.Contains(algorithm, ex.Message);
    }

    [Fact]
    public void IsNotPlaintext_ArgumentValidation()
    {
        Assert.Throws<ArgumentNullException>(() => MasterlyHashAssert.IsNotPlaintext("x", null!));
        Assert.Throws<ArgumentException>(() => MasterlyHashAssert.IsNotPlaintext("x", ""));
    }

    // ---- Recorder-based assertions ----

    [Fact]
    public void UsedVerifyOrDummyForUnknownUser_PassesAndFails()
    {
        var recorder = new RecordingPasswordHasher();
        Assert.Contains("none was recorded", Fails(() => MasterlyHashAssert.UsedVerifyOrDummyForUnknownUser(recorder)).Message);

        recorder.Verify(Pw, null!);
        Assert.Contains("Use VerifyOrDummy", Fails(() => MasterlyHashAssert.UsedVerifyOrDummyForUnknownUser(recorder)).Message);

        // A correct dummy call elsewhere must not mask the leaking Verify(password, null) path.
        recorder.VerifyOrDummy(Pw, null);
        Assert.Contains("Use VerifyOrDummy", Fails(() => MasterlyHashAssert.UsedVerifyOrDummyForUnknownUser(recorder)).Message);

        var clean = new RecordingPasswordHasher();
        clean.Verify(KnownHashes.Password, KnownHashes.TestFast); // known user: irrelevant
        clean.VerifyOrDummy(Pw, null);
        MasterlyHashAssert.UsedVerifyOrDummyForUnknownUser(clean);
        Assert.Throws<ArgumentNullException>(() => MasterlyHashAssert.UsedVerifyOrDummyForUnknownUser(null!));
    }

    [Fact]
    public async System.Threading.Tasks.Task UsedVerifyOrDummyForUnknownUser_FailsWhenAnyUnknownUserPathLeaks()
    {
        // Web login uses VerifyOrDummy; API login uses VerifyAsync(pw, null) and leaks account existence.
        var recorder = new RecordingPasswordHasher();
        await recorder.VerifyOrDummyAsync(Pw, null);
        await recorder.VerifyAsync(Pw, null!);
        Fails(() => MasterlyHashAssert.UsedVerifyOrDummyForUnknownUser(recorder));

        var empty = new RecordingPasswordHasher();
        empty.VerifyOrDummy(Pw, null);
        empty.Verify(Pw, "");
        Fails(() => MasterlyHashAssert.UsedVerifyOrDummyForUnknownUser(empty));

        // VerifyOrDummy(pw, "") skips the dummy work, so it does not count and is reported.
        var emptyDummy = new RecordingPasswordHasher();
        emptyDummy.VerifyOrDummy(Pw, "");
        Assert.Contains("Pass null", Fails(() => MasterlyHashAssert.UsedVerifyOrDummyForUnknownUser(emptyDummy)).Message);
    }

    [Fact]
    public void HasherAssertions_UnwrapRecorder_SoHistoryIsNotPolluted()
    {
        var recorder = new RecordingPasswordHasher();
        string persisted = recorder.Verify(KnownHashes.Password, KnownHashes.V1Sha512).Rehash!; // what the app stores
        int calls = recorder.Calls.Count;

        MasterlyHashAssert.Verifies(recorder, KnownHashes.Password, KnownHashes.V1Sha512);
        MasterlyHashAssert.DoesNotVerify(recorder, KnownHashes.WrongPassword, KnownHashes.V1Sha512);
        MasterlyHashAssert.NeedsRehash(recorder, KnownHashes.V1Sha512);
        MasterlyHashAssert.DoesNotNeedRehash(recorder, persisted);

        Assert.Equal(calls, recorder.Calls.Count);
        Assert.Single(recorder.RehashesIssued);
        MasterlyHashAssert.PersistedRehash(recorder, persisted);

        // Nested recorders are unwrapped too.
        var outer = new RecordingPasswordHasher(recorder);
        MasterlyHashAssert.Verifies(outer, KnownHashes.Password, KnownHashes.TestFast);
        Assert.Empty(outer.Calls);
        Assert.Equal(calls, recorder.Calls.Count);
    }

    [Fact]
    public void PersistedRehash_PassesAndFails()
    {
        var recorder = new RecordingPasswordHasher();
        Fails(() => MasterlyHashAssert.PersistedRehash(recorder, KnownHashes.TestFast));

        string rehash = recorder.Verify(KnownHashes.Password, KnownHashes.V1Sha512).Rehash!;
        MasterlyHashAssert.PersistedRehash(recorder, rehash);
        Fails(() => MasterlyHashAssert.PersistedRehash(recorder, KnownHashes.V1Sha512));
        Fails(() => MasterlyHashAssert.PersistedRehash(recorder, null));
        Assert.Throws<ArgumentNullException>(() => MasterlyHashAssert.PersistedRehash(null!, rehash));
    }

    [Fact]
    public void FailureMessages_NeverContainTheStoredValue()
    {
        string leaked = "plain-" + Guid.NewGuid().ToString("N");
        foreach (Action action in new Action[]
        {
            () => MasterlyHashAssert.IsMasterlyHash(leaked),
            () => MasterlyHashAssert.UsesProfile(leaked, "2026a"),
            () => MasterlyHashAssert.IsPeppered(leaked, "k1"),
            () => MasterlyHashAssert.NeedsRehash(FastPasswordHasher.Shared, leaked),
            () => MasterlyHashAssert.IsNotPlaintext(leaked, leaked),
        })
        {
            var ex = Fails(action);
            Assert.DoesNotContain(leaked, ex.Message, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void Exception_HasStandardConstructors()
    {
        var inner = new InvalidOperationException();
        var ex = new MasterlyHashAssertionException("m", inner);
        Assert.Equal("m", ex.Message);
        Assert.Same(inner, ex.InnerException);
    }
}
