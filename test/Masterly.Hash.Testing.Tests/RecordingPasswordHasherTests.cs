using System;
using System.Linq;
using System.Reflection;
using System.Threading.Tasks;
using Masterly.Hash.Legacy;

namespace Masterly.Hash.Testing.Tests;

public class RecordingPasswordHasherTests
{
    private const string Pw = "s3cret-Passw0rd";

    [Fact]
    public void Ctor_NullInner_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => new RecordingPasswordHasher(null!));
    }

    [Fact]
    public void Default_WrapsFastPasswordHasher()
    {
        var recorder = new RecordingPasswordHasher();
        Assert.IsType<FastPasswordHasher>(recorder.Inner);
        Assert.StartsWith("$mh$p=test-fast$", recorder.Hash(Pw));
    }

    [Fact]
    public void Hash_IsRecorded_WithFingerprintAndProducedHash()
    {
        var recorder = new RecordingPasswordHasher();
        string stored = recorder.Hash(Pw);

        PasswordHasherCall call = Assert.Single(recorder.Calls);
        Assert.Equal(1, call.Sequence);
        Assert.Equal(PasswordHasherOperation.Hash, call.Operation);
        Assert.False(call.IsAsync);
        Assert.Equal(stored, call.ProducedHash);
        Assert.Equal(recorder.Fingerprint(Pw), call.PasswordFingerprint);
        Assert.Null(call.ProfileId);
        Assert.Null(call.Result);
        Assert.Null(call.Status);
        Assert.Null(call.Exception);
        Assert.Same(call, recorder.LastCall);
    }

    [Fact]
    public void HashWithProfile_RecordsProfileId()
    {
        var recorder = new RecordingPasswordHasher();
        recorder.Hash(Pw, FastPasswordHasher.Profile);
        Assert.Equal("test-fast", recorder.LastCall!.ProfileId);
    }

    [Fact]
    public void PasswordIsNeverRecorded()
    {
        var recorder = new RecordingPasswordHasher();
        string stored = recorder.Hash(Pw);
        recorder.Verify(Pw, stored);
        recorder.VerifyOrDummy(Pw, null);

        foreach (PasswordHasherCall call in recorder.Calls)
        {
            Assert.DoesNotContain(Pw, call.ToString(), StringComparison.Ordinal);
            foreach (PropertyInfo property in typeof(PasswordHasherCall).GetProperties())
            {
                if (property.GetValue(call) is string s)
                    Assert.DoesNotContain(Pw, s, StringComparison.Ordinal);
            }
        }
    }

    [Fact]
    public void Fingerprint_IsKeyedPerRecorder_AndNotAPlainSha256()
    {
        var a = new RecordingPasswordHasher();
        var b = new RecordingPasswordHasher();
        string plainSha256 = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(Pw))).ToLowerInvariant();

        Assert.Equal(a.Fingerprint(Pw), a.Fingerprint(Pw));
        Assert.NotEqual(a.Fingerprint(Pw), b.Fingerprint(Pw));
        Assert.NotEqual(plainSha256, a.Fingerprint(Pw));
        Assert.NotEqual(a.Fingerprint(Pw), a.Fingerprint(Pw + "x"));
        Assert.Matches("^[0-9a-f]{64}$", a.Fingerprint(Pw));
        Assert.Throws<ArgumentNullException>(() => a.Fingerprint(null!));
    }

    [Fact]
    public void Fingerprint_UsesNormalizedPassword_LikeTheHasher()
    {
        var recorder = new RecordingPasswordHasher();
        // U+00E9 vs e + U+0301: NFKC-equal, so the hasher treats them as the same password.
        Assert.Equal(recorder.Fingerprint("café-pass"), recorder.Fingerprint("café-pass"));
    }

    [Fact]
    public void Verify_RecordsStoredHashAndResult()
    {
        var recorder = new RecordingPasswordHasher();
        string stored = recorder.Hash(Pw);
        recorder.Clear();

        recorder.Verify(Pw, stored);
        recorder.Verify("wrong", stored);

        Assert.Equal(2, recorder.Count(PasswordHasherOperation.Verify));
        PasswordHasherCall[] calls = recorder.CallsOf(PasswordHasherOperation.Verify).ToArray();
        Assert.Equal(VerificationStatus.Success, calls[0].Status);
        Assert.Equal(stored, calls[0].StoredHash);
        Assert.Equal(VerificationFailureReason.Mismatch, calls[1].Result!.FailureReason);
        Assert.Single(recorder.CallsWithPassword(Pw));
        Assert.Single(recorder.CallsWithPassword("wrong"));
        Assert.Empty(recorder.CallsWithPassword("never used"));
        Assert.True(calls[0].Sequence < calls[1].Sequence);
    }

    [Fact]
    public void RehashesIssued_CollectsRehashesFromVerify()
    {
        var recorder = new RecordingPasswordHasher();
        PasswordVerificationResult result = recorder.Verify(KnownHashes.Password, KnownHashes.V1Sha512);

        Assert.True(result.NeedsRehash);
        Assert.Equal(new[] { result.Rehash! }, recorder.RehashesIssued);
    }

    [Fact]
    public void VerifyOrDummy_UnknownUser_IsDetected()
    {
        var recorder = new RecordingPasswordHasher();
        Assert.False(recorder.UsedDummyVerification);

        recorder.VerifyOrDummy(Pw, KnownHashes.TestFast);
        Assert.False(recorder.UsedDummyVerification);

        recorder.VerifyOrDummy(Pw, null);
        Assert.True(recorder.UsedDummyVerification);
        Assert.True(recorder.LastCall!.IsUnknownUser);
        Assert.Equal(VerificationFailureReason.NoStoredHash, recorder.LastCall.Result!.FailureReason);
    }

    [Fact]
    public async Task AsyncCalls_AreRecordedAsAsync()
    {
        var recorder = new RecordingPasswordHasher();
        string stored = await recorder.HashAsync(Pw);
        await recorder.VerifyAsync(Pw, stored);
        await recorder.VerifyOrDummyAsync(Pw, null);

        Assert.All(recorder.Calls, c => Assert.True(c.IsAsync));
        Assert.Equal(new[] { PasswordHasherOperation.Hash, PasswordHasherOperation.Verify, PasswordHasherOperation.VerifyOrDummy },
            recorder.Calls.Select(c => c.Operation));
        Assert.True(recorder.UsedDummyVerification);
        Assert.Equal("VerifyOrDummyAsync", recorder.LastCall!.ToString().Split(' ')[1]);
    }

    [Fact]
    public void NeedsRehash_Inspect_TryWrap_AreRecorded()
    {
        var inner = new FastPasswordHasher(o =>
        {
            o.LegacyFormats.Clear();
            o.LegacyFormats.Add(new V1LegacyFormat(V1Algorithm.SHA512));
        });
        var recorder = new RecordingPasswordHasher(inner);

        Assert.True(recorder.NeedsRehash(KnownHashes.V1Sha512));
        HashInfo info = recorder.Inspect(KnownHashes.TestFast);
        Assert.True(recorder.TryWrap(KnownHashes.V1Sha512, out string wrapped));
        Assert.False(recorder.TryWrap(KnownHashes.UnknownFormat, out _));

        PasswordHasherCall[] calls = recorder.Calls.ToArray();
        Assert.Equal(PasswordHasherOperation.NeedsRehash, calls[0].Operation);
        Assert.True(calls[0].BooleanResult);
        Assert.Null(calls[0].PasswordFingerprint);
        Assert.Same(info, calls[1].Info);
        Assert.Equal(wrapped, calls[2].ProducedHash);
        Assert.Equal(KnownHashes.V1Sha512, calls[2].StoredHash);
        Assert.False(calls[3].BooleanResult);
        Assert.Null(calls[3].ProducedHash);
        Assert.Contains("-> True", calls[0].ToString());
    }

    [Fact]
    public void Exceptions_AreRecordedAndRethrown()
    {
        var recorder = new RecordingPasswordHasher();

        Assert.Throws<ArgumentException>(() => recorder.Hash(""));
        Assert.Throws<ArgumentNullException>(() => recorder.Hash(null!));
        Assert.Throws<ArgumentNullException>(() => recorder.Verify(null!, KnownHashes.TestFast));
        Assert.Throws<ArgumentNullException>(() => recorder.Hash(Pw, null!));

        PasswordHasherCall[] calls = recorder.Calls.ToArray();
        Assert.Equal(4, calls.Length);
        Assert.IsType<ArgumentException>(calls[0].Exception);
        Assert.NotNull(calls[0].PasswordFingerprint);
        Assert.Null(calls[1].PasswordFingerprint);
        Assert.IsType<ArgumentNullException>(calls[2].Exception);
        Assert.Null(calls[3].ProfileId);
        Assert.Contains("threw", calls[0].ToString());
    }

    [Fact]
    public async Task AsyncExceptions_AreRecordedAndRethrown()
    {
        var pepper = new FakePepper { ThrowOnApply = new TimeoutException() };
        var recorder = new RecordingPasswordHasher(new FastPasswordHasher(o => o.Pepper = pepper));

        await Assert.ThrowsAsync<TimeoutException>(() => recorder.HashAsync(Pw).AsTask());
        await Assert.ThrowsAsync<TimeoutException>(() => recorder.VerifyAsync(Pw, KnownHashes.TestFastPeppered).AsTask());

        Assert.All(recorder.Calls, c => Assert.IsType<TimeoutException>(c.Exception));
        Assert.All(recorder.Calls, c => Assert.True(c.IsAsync));
    }

    [Fact]
    public void BadStoredHashes_DoNotThrow_AndAreRecorded()
    {
        var recorder = new RecordingPasswordHasher();
        Assert.Equal(VerificationFailureReason.MalformedHash, recorder.Verify(Pw, KnownHashes.Malformed).FailureReason);
        Assert.Equal(VerificationFailureReason.NoStoredHash, recorder.Verify(Pw, null!).FailureReason);
        Assert.False(recorder.NeedsRehash(""));
        Assert.True(recorder.CallsOf(PasswordHasherOperation.Verify)[1].IsUnknownUser);
    }

    [Fact]
    public void Clear_ForgetsCalls_ButSequenceKeepsIncreasing()
    {
        var recorder = new RecordingPasswordHasher();
        recorder.Hash(Pw);
        recorder.Clear();
        Assert.Empty(recorder.Calls);
        Assert.Null(recorder.LastCall);

        recorder.Hash(Pw);
        Assert.Equal(2, recorder.LastCall!.Sequence);
    }

    [Fact]
    public void IsThreadSafe_AndOrdersBySequence()
    {
        var recorder = new RecordingPasswordHasher();
        Parallel.For(0, 100, i => recorder.Hash("password-" + i));

        var calls = recorder.Calls;
        Assert.Equal(100, calls.Count);
        Assert.Equal(Enumerable.Range(1, 100).Select(i => (long)i), calls.Select(c => c.Sequence));
    }

    [Fact]
    public void NeedsRehash_InnerThrows_IsRecordedAndRethrown()
    {
        var failure = new InvalidOperationException("inner NeedsRehash");
        var recorder = new RecordingPasswordHasher(new ThrowingHasher(failure));

        Assert.Same(failure, Assert.Throws<InvalidOperationException>(() => recorder.NeedsRehash(KnownHashes.TestFast)));

        PasswordHasherCall call = Assert.Single(recorder.Calls);
        Assert.Equal(PasswordHasherOperation.NeedsRehash, call.Operation);
        Assert.Same(failure, call.Exception);
        Assert.Equal(KnownHashes.TestFast, call.StoredHash);
        Assert.Null(call.BooleanResult);
        Assert.Null(call.PasswordFingerprint);
        Assert.False(call.IsAsync);
        Assert.Contains("threw", call.ToString());
    }

    [Fact]
    public void Inspect_InnerThrows_IsRecordedAndRethrown()
    {
        var failure = new InvalidOperationException("inner Inspect");
        var recorder = new RecordingPasswordHasher(new ThrowingHasher(failure));

        Assert.Same(failure, Assert.Throws<InvalidOperationException>(() => recorder.Inspect(KnownHashes.V1Sha512)));

        PasswordHasherCall call = Assert.Single(recorder.Calls);
        Assert.Equal(PasswordHasherOperation.Inspect, call.Operation);
        Assert.Same(failure, call.Exception);
        Assert.Equal(KnownHashes.V1Sha512, call.StoredHash);
        Assert.Null(call.Info);
    }

    [Fact]
    public void TryWrap_InnerThrows_IsRecordedAndRethrown()
    {
        var failure = new InvalidOperationException("inner TryWrap");
        var recorder = new RecordingPasswordHasher(new ThrowingHasher(failure));

        Assert.Same(failure, Assert.Throws<InvalidOperationException>(() => recorder.TryWrap(KnownHashes.V1Sha512, out _)));

        PasswordHasherCall call = Assert.Single(recorder.Calls);
        Assert.Equal(PasswordHasherOperation.TryWrap, call.Operation);
        Assert.Same(failure, call.Exception);
        Assert.Equal(KnownHashes.V1Sha512, call.StoredHash);
        Assert.Null(call.ProducedHash);
        Assert.Null(call.BooleanResult);
    }

    [Fact]
    public void Calls_AfterAnInnerFailure_KeepRecording()
    {
        var recorder = new RecordingPasswordHasher(new ThrowingHasher(new TimeoutException()));

        Assert.Throws<TimeoutException>(() => recorder.NeedsRehash("a"));
        Assert.Throws<TimeoutException>(() => recorder.Inspect("b"));
        Assert.Throws<TimeoutException>(() => recorder.TryWrap("c", out _));

        Assert.Equal(new[] { PasswordHasherOperation.NeedsRehash, PasswordHasherOperation.Inspect, PasswordHasherOperation.TryWrap },
            recorder.Calls.Select(c => c.Operation));
        Assert.Equal(new long[] { 1, 2, 3 }, recorder.Calls.Select(c => c.Sequence));
    }

    [Fact]
    public void RehashesIssued_SkipsCallsWithoutARehash()
    {
        var recorder = new RecordingPasswordHasher();
        string current = recorder.Hash(Pw);                                       // no Result at all
        recorder.Verify(Pw, current);                                             // Result without a rehash
        recorder.Verify("wrong", current);                                        // failed Result
        string rehash = recorder.Verify(KnownHashes.Password, KnownHashes.V1Sha512).Rehash!;
        recorder.NeedsRehash(current);

        Assert.Equal(new[] { rehash }, recorder.RehashesIssued);
    }

    // Surrogates are passed as code units: xunit replaces lone surrogates in serialized theory strings with U+FFFD.
    [Theory]
    [InlineData("", 0xD800, "")]       // lone high surrogate
    [InlineData("abc", 0xDC00, "def")] // lone low surrogate
    [InlineData("x", 0xDBFF, "")]      // last high surrogate
    public void Fingerprint_IllFormedPassword_IsRecordedLosslessly(string prefix, int surrogate, string suffix)
    {
        string illFormed = prefix + (char)surrogate + suffix;
        string replaced = prefix + '\uFFFD' + suffix;
        var recorder = new RecordingPasswordHasher();
        string stored = recorder.Hash(Pw);
        recorder.Clear();

        PasswordVerificationResult result = recorder.Verify(illFormed, stored);

        Assert.Equal(VerificationFailureReason.InvalidPassword, result.FailureReason);
        string fingerprint = recorder.Fingerprint(illFormed);
        Assert.Matches("^[0-9a-f]{64}$", fingerprint);
        Assert.Equal(fingerprint, recorder.Fingerprint(illFormed));
        Assert.Equal(fingerprint, Assert.Single(recorder.CallsWithPassword(illFormed)).PasswordFingerprint);

        // A lossy encoding would map every lone surrogate to U+FFFD; the recorder keeps them apart.
        Assert.NotEqual(fingerprint, recorder.Fingerprint(replaced));
        Assert.Empty(recorder.CallsWithPassword(replaced));
    }

    [Fact]
    public void Fingerprint_DistinctIllFormedPasswords_Differ()
    {
        var recorder = new RecordingPasswordHasher();

        string high = recorder.Fingerprint("\uD800");
        string otherHigh = recorder.Fingerprint("\uD801");
        string low = recorder.Fingerprint("\uDC00");

        Assert.NotEqual(high, otherHigh);
        Assert.NotEqual(high, low);
        Assert.NotEqual(otherHigh, low);
        // The 0xFF marker keeps ill-formed text from colliding with any well-formed password.
        Assert.NotEqual(high, recorder.Fingerprint("ÿ\u0000Ø"));
        Assert.Equal("password", Assert.Throws<ArgumentNullException>(() => recorder.Fingerprint(null!)).ParamName);
    }

    [Fact]
    public void Hash_IllFormedPassword_IsRecordedWithFingerprint_AndRethrown()
    {
        var recorder = new RecordingPasswordHasher();

        Assert.Throws<ArgumentException>(() => recorder.Hash("x\uD800"));

        PasswordHasherCall call = Assert.Single(recorder.Calls);
        Assert.IsType<ArgumentException>(call.Exception);
        Assert.Equal(recorder.Fingerprint("x\uD800"), call.PasswordFingerprint);
    }

    /// <summary>An inner hasher whose every method throws the given exception.</summary>
    private sealed class ThrowingHasher : IPasswordHasher
    {
        private readonly Exception _exception;

        public ThrowingHasher(Exception exception) => _exception = exception;

        public string Hash(string password) => throw _exception;
        public string Hash(string password, HashProfile profile) => throw _exception;
        public PasswordVerificationResult Verify(string password, string storedHash) => throw _exception;
        public PasswordVerificationResult VerifyOrDummy(string password, string? storedHash) => throw _exception;
        public ValueTask<string> HashAsync(string password, System.Threading.CancellationToken cancellationToken = default) => throw _exception;
        public ValueTask<PasswordVerificationResult> VerifyAsync(string password, string storedHash, System.Threading.CancellationToken cancellationToken = default) => throw _exception;
        public ValueTask<PasswordVerificationResult> VerifyOrDummyAsync(string password, string? storedHash, System.Threading.CancellationToken cancellationToken = default) => throw _exception;
        public bool NeedsRehash(string storedHash) => throw _exception;
        public HashInfo Inspect(string storedHash) => throw _exception;
        public bool TryWrap(string legacyHash, out string wrappedHash) => throw _exception;
    }
}
