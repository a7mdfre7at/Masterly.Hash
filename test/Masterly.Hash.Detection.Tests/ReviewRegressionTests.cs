using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Masterly.Hash.Detection.Internal;

namespace Masterly.Hash.Detection.Tests;

/// <summary>Regression tests for issues found in review.</summary>
public class ReviewRegressionTests
{
    // ---- Over-long passwords: known and unknown users do the same (zero) work ----

    [Fact]
    public void VerifyOrDummy_OverlongPassword_DerivesOnNeitherPath()
    {
        HoneywordService service = TestSupport.Service(configure: o => o.MaxPasswordBytes = 64);
        HoneywordRecord record = service.Create("password", 3);
        TestSupport.StrongBox calls = TestSupport.Count(service);

        // 100 is over the byte limit after normalization; 2000 is over the pre-normalization cap.
        foreach (int length in new[] { 100, 2000 })
        {
            string overlong = new string('a', length);
            Assert.Equal(HoneywordVerificationStatus.PasswordTooLong, service.VerifyOrDummy(overlong, record.StoredHash).Status);
            int knownUserCalls = calls.Value;
            Assert.Equal(HoneywordVerificationStatus.NoStoredHash, service.VerifyOrDummy(overlong, null).Status);
            int unknownUserCalls = calls.Value - knownUserCalls;

            Assert.Equal(0, knownUserCalls);
            Assert.Equal(knownUserCalls, unknownUserCalls);
        }

        // A normal-length password still costs exactly one derivation on both paths.
        service.VerifyOrDummy("password", record.StoredHash);
        service.VerifyOrDummy("password", null);
        Assert.Equal(2, calls.Value);
    }

    [Fact]
    public async Task LoginAsync_OverlongPassword_SameWorkForKnownAndUnknownUsers()
    {
        HoneywordService service = TestSupport.Service(configure: o => o.MaxPasswordBytes = 64);
        var login = new HoneywordLoginService(service, new InMemoryHoneychecker());
        string stored = await login.RegisterAsync("alice", "password", 3);
        TestSupport.StrongBox calls = TestSupport.Count(service);
        string overlong = new string('a', 2000);

        Assert.Equal(HoneywordLoginOutcome.Mismatch, (await login.LoginAsync("alice", overlong, stored)).Outcome);
        Assert.Equal(HoneywordLoginOutcome.Mismatch, (await login.LoginAsync("ghost", overlong, null)).Outcome);
        Assert.Equal(0, calls.Value);
    }

    [Fact]
    public void HugeExpandingPassword_IsRejectedBeforeNormalization()
    {
        // U+FDFA expands 18-fold under NFKC; a megabyte of it must be rejected without normalizing.
        HoneywordService service = TestSupport.Service();
        HoneywordRecord record = service.Create("password", 2);
        string huge = new string('ﷺ', 1024 * 1024);

        Assert.Equal(HoneywordVerificationStatus.PasswordTooLong, service.VerifyDetailed(huge, record.StoredHash).Status);
        Assert.Equal(HoneywordVerificationStatus.NoStoredHash, service.VerifyOrDummy(huge, null).Status);
        Assert.Throws<ArgumentException>(() => service.Create(huge, 2));
    }

    [Fact]
    public void PreNormalizationCap_DoesNotRejectPasswordsThatFitAfterNormalization()
    {
        // 100 x ("e" + combining acute) is 200 UTF-16 units and composes to 100 "é" = 200 UTF-8 bytes: exactly at
        // the limit, so the cheap pre-normalization length check must let it through.
        HoneywordService service = TestSupport.Service(configure: o => o.MaxPasswordBytes = 200);
        string decomposed = string.Concat(Enumerable.Repeat("é", 100));
        HoneywordRecord record = service.Create(decomposed, 2);
        Assert.Equal(record.RealIndex, service.Verify(decomposed, record.StoredHash));
    }

    // ---- Non-ASCII passwords get decoys of the same shape ----

    public static IEnumerable<object[]> NonAsciiCases()
    {
        string[] passwords = { "пароль", "كلمةالسر", "密码密码", "пароль1", "Пароль2024!", "κωδικός", "סיסמה", "パスワード", "비밀번호", "ÉtéÀ" };
        foreach (IHoneywordGenerator g in new IHoneywordGenerator[] { TweakingHoneywordGenerator.Default, PasswordModelHoneywordGenerator.Default })
            foreach (string p in passwords)
                yield return new object[] { g, p };
    }

    [Theory]
    [MemberData(nameof(NonAsciiCases))]
    public void NonAsciiPasswords_GetSameShapeDecoys_WithoutAppendedDigits(IHoneywordGenerator generator, string password)
    {
        IReadOnlyList<string> decoys = generator.GenerateDecoys(password, 19);

        Assert.Equal(19, decoys.Distinct(StringComparer.Ordinal).Count());
        Assert.DoesNotContain(password, decoys);
        foreach (string decoy in decoys)
        {
            // Same length (no suffix), and every position drawn from the same alphabet as the real character.
            Assert.Equal(password.Length, decoy.Length);
            for (int i = 0; i < password.Length; i++)
                Assert.True(SameShape(password[i], decoy[i]), $"position {i} of {decoy}");
        }
    }

    [Fact]
    public void NonAsciiPasswords_ThroughTheService_VerifyAndLookAlike()
    {
        HoneywordService service = TestSupport.Service(PasswordModelHoneywordGenerator.Default);
        HoneywordRecord record = service.Create("пароль", 20);
        Assert.Equal(record.RealIndex, service.Verify("пароль", record.StoredHash));
    }

    [Fact]
    public void ScriptAlphabets_AreCaseAndScriptPreserving_AndNfkcStable()
    {
        Assert.Null(ScriptAlphabets.For('a'));
        Assert.Null(ScriptAlphabets.For(' '));
        Assert.Null(ScriptAlphabets.For('́')); // combining mark
        Assert.Null(ScriptAlphabets.For('€')); // euro sign
        Assert.Null(ScriptAlphabets.For('\uD83D')); // surrogate half

        string cyrillicLower = ScriptAlphabets.For('п')!;
        Assert.Equal(32, cyrillicLower.Length);
        Assert.All(cyrillicLower, c => Assert.True(char.IsLower(c)));
        Assert.All(ScriptAlphabets.For('П')!, c => Assert.True(char.IsUpper(c)));
        Assert.DoesNotContain('×', ScriptAlphabets.For('À')!); // multiplication sign is not a letter
        Assert.Equal("٠١٢٣٤٥٦٧٨٩", ScriptAlphabets.For('٣'));

        // Generic fallback (Armenian): same category, same block.
        string armenian = ScriptAlphabets.For('ա')!;
        Assert.True(armenian.Length > 10);
        Assert.All(armenian, c => Assert.Equal(System.Globalization.UnicodeCategory.LowercaseLetter, char.GetUnicodeCategory(c)));

        foreach (char probe in "пΩאبअกßÀあア가中ա٣")
            Assert.All(ScriptAlphabets.For(probe)!, c => Assert.Equal(c.ToString(), c.ToString().Normalize(System.Text.NormalizationForm.FormKC)));
    }

    [Fact]
    public void Model_Fallback_RandomizesTheWholePassword_InsteadOfAppending()
    {
        // A one-word vocabulary forces the fallback; it must keep the shape (three lower-case letters) and not
        // cluster around the real password's prefix.
        IReadOnlyList<string> decoys = new PasswordModelHoneywordGenerator(new[] { "abc" }).GenerateDecoys("xyz", 19);
        Assert.All(decoys, d => Assert.Equal(TestSupport.Pattern("xyz"), TestSupport.Pattern(d)));
        Assert.True(decoys.Count(d => d.StartsWith("xy", StringComparison.Ordinal)) < 5);
    }

    // ---- Typo safety ----

    [Theory]
    [InlineData("monkey123", "monkey123", true)]
    [InlineData("monkey123", "monkey124", true)]   // substitution
    [InlineData("monkey123", "monkey12", true)]    // deletion
    [InlineData("monkey123", "monkey1234", true)]  // insertion
    [InlineData("monkey123", "monkey132", true)]   // adjacent transposition
    [InlineData("monkey123", "omnkey123", true)]   // transposition at the start
    [InlineData("monkey123", "monkey145", false)]
    [InlineData("monkey123", "monkey1", false)]
    [InlineData("monkey123", "monkey321", false)]
    [InlineData("ab", "ba", true)]
    [InlineData("a", "", true)]
    [InlineData("", "", true)]
    [InlineData("abc", "xyz", false)]
    public void TypoSafety_WithinOneEdit(string a, string b, bool expected)
    {
        Assert.Equal(expected, TypoSafety.WithinOneEdit(a, b));
        Assert.Equal(expected, TypoSafety.WithinOneEdit(b, a));
    }

    [Theory]
    [MemberData(nameof(GeneratorTests.GeneratorsAndPasswords), MemberType = typeof(GeneratorTests))]
    public void Decoys_AreNeverOneTypoFromTheRealPassword(IHoneywordGenerator generator, string password)
    {
        IReadOnlyList<string> decoys = generator.GenerateDecoys(password, 19);
        Assert.All(decoys, d => Assert.False(TypoSafety.WithinOneEdit(d, password), $"decoy {d} is one typo away"));
    }

    [Fact]
    public void Tweaking_ManyDecoys_ForMonkey123_AreTypoSafe()
    {
        // Reviewer's scenario: with plain tail-tweaking ~2% of single-digit typos hit a decoy.
        for (int round = 0; round < 20; round++)
        {
            IReadOnlyList<string> decoys = TweakingHoneywordGenerator.Default.GenerateDecoys("monkey123", 99);
            Assert.All(decoys, d => Assert.False(TypoSafety.WithinOneEdit(d, "monkey123")));
        }
    }

    // ---- Zero values are failures, and the real index never leaks ----

    [Fact]
    public void DefaultValues_AreFailures()
    {
        HoneywordVerification v = default;
        Assert.False(v.IsSweetwordMatch);
        Assert.Equal(HoneywordVerificationStatus.Mismatch, v.Status);
        Assert.Equal(-1, v.Index);
        Assert.Equal(HoneywordLoginOutcome.Mismatch, default(HoneywordLoginOutcome));
        Assert.Equal(0, (int)HoneywordVerificationStatus.Mismatch);
        Assert.Equal(0, (int)HoneywordLoginOutcome.Mismatch);
    }

    [Fact]
    public void Verification_ToString_DoesNotContainTheIndex()
    {
        HoneywordService service = TestSupport.Service(new FixedGenerator());
        HoneywordRecord record = service.Create("s3cret!", 20);
        HoneywordVerification v = service.VerifyDetailed("s3cret!", record.StoredHash);

        Assert.True(v.IsSweetwordMatch);
        Assert.Equal("SweetwordMatch", v.ToString());
        Assert.DoesNotContain(record.RealIndex.ToString(System.Globalization.CultureInfo.InvariantCulture), v.ToString());
    }

    [Fact]
    public async Task LoginSuccess_WithholdsTheRealIndex()
    {
        var login = new HoneywordLoginService(TestSupport.Service(new FixedGenerator()), new InMemoryHoneychecker());
        string stored = await login.RegisterAsync("alice", "s3cret!", 20);

        HoneywordLoginResult result = await login.LoginAsync("alice", "s3cret!", stored);
        Assert.True(result.IsSuccess);
        Assert.True(result.Verification.IsSweetwordMatch);
        Assert.Equal(-1, result.Verification.Index);
        Assert.Equal("Success", result.ToString());
        Assert.Equal("SweetwordMatch", result.Verification.ToString());

        // A decoy hit still reports the (non-secret) decoy index.
        HoneywordLoginResult breach = await login.LoginAsync("alice", FixedGenerator.Decoy(3), stored);
        Assert.Equal(HoneywordLoginOutcome.BreachDetected, breach.Outcome);
        Assert.InRange(breach.Verification.Index, 0, 19);
    }

    // ---- Account length caps ----

    [Fact]
    public void Detector_IgnoresOverlongAccounts_AndValidatesTheOption()
    {
        var detector = new CredentialStuffingDetector(new CredentialStuffingOptions { MaxAccountLength = 16, DistinctAccountThreshold = 2 });
        Assert.False(detector.RecordFailedLogin(new string('ﷺ', 17), "pw"));
        Assert.Equal(0, detector.TrackedFingerprintCount);
        Assert.False(detector.RecordFailedLogin(new string('a', 16), "pw"));
        Assert.Equal(1, detector.TrackedFingerprintCount);

        Assert.Equal(1024, new CredentialStuffingOptions().MaxAccountLength);
        Assert.Throws<ArgumentOutOfRangeException>(() => new CredentialStuffingDetector(new CredentialStuffingOptions { MaxAccountLength = 0 }));
        Assert.Throws<ArgumentOutOfRangeException>(() => new CredentialStuffingDetector(new CredentialStuffingOptions { MaxAccountLength = 1024 * 1024 + 1 }));
    }

    [Fact]
    public void HugeAccountName_IsRejectedWithoutNormalization()
    {
        string huge = new string('ﷺ', 4 * 1024 * 1024);
        var detector = new CredentialStuffingDetector();
        Assert.False(detector.RecordFailedLogin(huge, "pw"));

        var registry = new HoneyAccountRegistry(new[] { "admin" });
        Assert.False(registry.IsHoneyAccount(huge));
        Assert.False(registry.CheckLogin(huge));
        Assert.False(registry.Remove(huge));
        Assert.Throws<ArgumentException>(() => registry.Add(new string('a', HoneyAccountRegistry.MaxAccountLength + 1)));
        Assert.True(registry.Add(new string('a', HoneyAccountRegistry.MaxAccountLength)));
        Assert.True(registry.IsHoneyAccount(new string('A', HoneyAccountRegistry.MaxAccountLength)));
    }

    // ---- IsFlagged keeps a flagged fingerprint alive ----

    [Fact]
    public void IsFlagged_RefreshesRecency_SoBlockedSprayingIsNotEvicted()
    {
        var detector = new CredentialStuffingDetector(new CredentialStuffingOptions { DistinctAccountThreshold = 2, MaxTrackedFingerprints = 3 });
        var events = new List<CredentialStuffingDetectedEventArgs>();
        detector.StuffingDetected += (_, e) => events.Add(e);

        detector.RecordFailedLogin("a", "Winter2026!");
        Assert.True(detector.RecordFailedLogin("b", "Winter2026!"));

        // The app now blocks the flagged password without recording it, while other traffic churns the LRU.
        for (int i = 0; i < 50; i++)
        {
            Assert.True(detector.IsFlagged("Winter2026!"));
            detector.RecordFailedLogin("victim", "noise" + i);
        }

        Assert.True(detector.IsFlagged("Winter2026!"));
        Assert.Single(events);
        Assert.True(detector.EvictedCount > 0);
    }

    [Fact]
    public void IsFlagged_OnUnflaggedEntry_DoesNotRefreshIt()
    {
        var detector = new CredentialStuffingDetector(new CredentialStuffingOptions { DistinctAccountThreshold = 3, MaxTrackedFingerprints = 2 });
        detector.RecordFailedLogin("a", "p1");
        detector.RecordFailedLogin("a", "p2");
        Assert.False(detector.IsFlagged("p1")); // must not move p1 to the front
        detector.RecordFailedLogin("a", "p3"); // evicts p1, the least recently recorded

        Assert.Equal(2, detector.TrackedFingerprintCount);
        Assert.Equal(1, detector.EvictedCount);
        detector.RecordFailedLogin("b", "p2");
        Assert.Contains(detector.GetSnapshot(), s => s.DistinctAccountCount == 2); // p2 survived
    }

    /// <summary>ASCII: same class. Other scripts: drawn from the real character's alphabet. Otherwise: kept verbatim.</summary>
    private static bool SameShape(char real, char decoy)
    {
        CharClass cls = CharClasses.Of(real);
        if (cls != CharClass.Other)
            return CharClasses.Of(decoy) == cls;
        string? alphabet = ScriptAlphabets.For(real);
        return alphabet == null ? decoy == real : alphabet.IndexOf(decoy) >= 0;
    }
}
