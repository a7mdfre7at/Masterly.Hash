using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Masterly.Hash.Legacy;
using Masterly.Hash.Pepper;

namespace Masterly.Hash.Testing.Tests;

/// <summary>
/// Precise assertions that pin down behaviour the broader suites only exercise: exact failure messages, boundary
/// lengths, recorded call fields, and that async paths never capture the caller's synchronization context.
/// </summary>
public class MutationTests
{
    private const string Pw = "my-plaintext-password";

    /// <summary>"password12" in full-width forms; NFKC-normalizes to ASCII.</summary>
    private const string FullWidth10 = "\uFF50\uFF41\uFF53\uFF53\uFF57\uFF4F\uFF52\uFF44\uFF11\uFF12";

    /// <summary>"passwd" in full-width forms: six characters before and after NFKC.</summary>
    private const string FullWidth6 = "\uFF50\uFF41\uFF53\uFF53\uFF57\uFF44";

    private static readonly byte[] Salt = Enumerable.Range(0, 16).Select(i => (byte)i).ToArray();

    private static MasterlyHashAssertionException Fails(Action action) =>
        Assert.Throws<MasterlyHashAssertionException>(action);

    private static string B64(int length) => Convert.ToBase64String(new byte[length]).TrimEnd('=');

    // ======================================================================================================
    // Synchronization-context capture
    // ======================================================================================================

    /// <summary>Counts continuations posted to it and runs them on the thread pool.</summary>
    private sealed class CountingSynchronizationContext : SynchronizationContext
    {
        private int _posts;

        public int Posts => Volatile.Read(ref _posts);

        public override void Post(SendOrPostCallback d, object? state)
        {
            Interlocked.Increment(ref _posts);
            ThreadPool.QueueUserWorkItem(_ => d(state));
        }

        public override void Send(SendOrPostCallback d, object? state)
        {
            Interlocked.Increment(ref _posts);
            d(state);
        }
    }

    /// <summary>Starts <paramref name="start"/> with a counting context installed, then waits for it outside that context.</summary>
    private static async Task<int> PostsCapturedBy(Func<Task> start, Action? afterStart = null)
    {
        var context = new CountingSynchronizationContext();
        SynchronizationContext? previous = SynchronizationContext.Current;
        Task task;
        SynchronizationContext.SetSynchronizationContext(context);
        try
        {
            task = start();
        }
        finally
        {
            SynchronizationContext.SetSynchronizationContext(previous);
        }

        Assert.False(task.IsCompleted); // otherwise the test proves nothing
        afterStart?.Invoke();
        await task;
        return context.Posts;
    }

    /// <summary>Delegates to <see cref="FastPasswordHasher.Shared"/>; async members wait for <see cref="Release"/>.</summary>
    private sealed class GatedHasher : IPasswordHasher
    {
        private readonly TaskCompletionSource<bool> _gate = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly IPasswordHasher _inner = FastPasswordHasher.Shared;

        public void Release() => _gate.TrySetResult(true);

        public string Hash(string password) => _inner.Hash(password);
        public string Hash(string password, HashProfile profile) => _inner.Hash(password, profile);
        public PasswordVerificationResult Verify(string password, string storedHash) => _inner.Verify(password, storedHash);
        public PasswordVerificationResult VerifyOrDummy(string password, string? storedHash) => _inner.VerifyOrDummy(password, storedHash);

        public async ValueTask<string> HashAsync(string password, CancellationToken cancellationToken = default)
        {
            await _gate.Task.ConfigureAwait(false);
            return _inner.Hash(password);
        }

        public async ValueTask<PasswordVerificationResult> VerifyAsync(string password, string storedHash, CancellationToken cancellationToken = default)
        {
            await _gate.Task.ConfigureAwait(false);
            return _inner.Verify(password, storedHash);
        }

        public async ValueTask<PasswordVerificationResult> VerifyOrDummyAsync(string password, string? storedHash, CancellationToken cancellationToken = default)
        {
            await _gate.Task.ConfigureAwait(false);
            return _inner.VerifyOrDummy(password, storedHash);
        }

        public bool NeedsRehash(string storedHash) => _inner.NeedsRehash(storedHash);
        public HashInfo Inspect(string storedHash) => _inner.Inspect(storedHash);
        public bool TryWrap(string legacyHash, out string wrappedHash) => _inner.TryWrap(legacyHash, out wrappedHash);
    }

    private static async Task CapturingAwait(Task pending) => await pending; // ConfigureAwait(true): resumes on the context

    [Fact]
    public async Task CountingSynchronizationContext_SeesACapturingAwait()
    {
        // Control for the tests below: an await that captures the context is counted.
        var gate = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);

        int posts = await PostsCapturedBy(() => CapturingAwait(gate.Task), () => gate.SetResult(true));

        Assert.Equal(1, posts);
    }

    [Fact]
    public async Task FakePepper_ForceAsynchronous_DoesNotCaptureSynchronizationContext()
    {
        var pepper = new FakePepper("k1") { ForceAsynchronous = true };

        int posts = await PostsCapturedBy(() => pepper.ApplyAsync("k1", new byte[] { 1 }).AsTask());

        Assert.Equal(0, posts);
    }

    [Fact]
    public async Task FakePepper_AsyncDelay_DoesNotCaptureSynchronizationContext()
    {
        var pepper = new FakePepper("k1") { AsyncDelay = TimeSpan.FromMilliseconds(20) };
        Task<byte[]>? pending = null;

        int posts = await PostsCapturedBy(() => pending = pepper.ApplyAsync("k1", new byte[] { 1 }).AsTask());

        Assert.Equal(0, posts);
        Assert.Equal(pepper.Apply("k1", new byte[] { 1 }), await pending!);
    }

    [Fact]
    public async Task Recorder_HashAsync_DoesNotCaptureSynchronizationContext()
    {
        var inner = new GatedHasher();
        var recorder = new RecordingPasswordHasher(inner);

        int posts = await PostsCapturedBy(() => recorder.HashAsync(Pw).AsTask(), inner.Release);

        Assert.Equal(0, posts);
        PasswordHasherCall call = Assert.Single(recorder.Calls);
        Assert.True(call.IsAsync);
        Assert.Null(call.Exception);
        Assert.True(FastPasswordHasher.Shared.Verify(Pw, call.ProducedHash!).IsMatch);
    }

    [Fact]
    public async Task Recorder_VerifyAsync_DoesNotCaptureSynchronizationContext()
    {
        var inner = new GatedHasher();
        var recorder = new RecordingPasswordHasher(inner);

        int posts = await PostsCapturedBy(() => recorder.VerifyAsync(KnownHashes.Password, KnownHashes.TestFast).AsTask(), inner.Release);

        Assert.Equal(0, posts);
        PasswordHasherCall call = Assert.Single(recorder.Calls);
        Assert.True(call.IsAsync);
        Assert.Equal(VerificationStatus.Success, call.Status);
    }

    // ======================================================================================================
    // FakePepper
    // ======================================================================================================

    [Fact]
    public void FakePepper_RetireCurrentKey_HasExactMessage()
    {
        var pepper = new FakePepper("k1", "k0");
        var ex = Assert.Throws<InvalidOperationException>(() => pepper.RetireKey("k1"));
        Assert.Equal("The current key cannot be retired; rotate to another key first.", ex.Message);
    }

    [Fact]
    public void FakePepper_UnknownKey_HasExactMessage()
    {
        var pepper = new FakePepper("k1");
        Assert.Equal("Unknown pepper key 'nope'.", Assert.Throws<KeyNotFoundException>(() => pepper.Apply("nope", new byte[1])).Message);
        Assert.Equal("Unknown pepper key ''.", Assert.Throws<KeyNotFoundException>(() => pepper.Apply(null!, new byte[1])).Message);
    }

    [Fact]
    public void FakePepper_NullInput_IsRejectedBeforeAnythingElse()
    {
        var pepper = new FakePepper("k1");

        Assert.Equal("input", Assert.Throws<ArgumentNullException>(() => pepper.Apply("k1", null!)).ParamName);
        // An unknown key would otherwise surface as KeyNotFoundException.
        Assert.Equal("input", Assert.Throws<ArgumentNullException>(() => pepper.Apply("unknown", null!)).ParamName);
        Assert.Empty(pepper.KeyIdsUsed);
        Assert.Equal(2, pepper.ApplyCount);
    }

    [Theory]
    [InlineData("A")]
    [InlineData("Z")]
    [InlineData("a")]
    [InlineData("z")]
    [InlineData("0")]
    [InlineData("9")]
    [InlineData("-")]
    [InlineData("AZaz09-")]
    public void FakePepper_BoundaryCharacters_AreValidKeyIds(string keyId)
    {
        var pepper = new FakePepper(keyId);
        Assert.Equal(keyId, pepper.CurrentKeyId);
        Assert.Equal(32, pepper.Apply(keyId, new byte[1]).Length);

        var other = new FakePepper();
        other.AddKey(keyId);
        Assert.True(other.IsKnownKey(keyId));

        string stored = KnownHashes.Create(FastPasswordHasher.Profile, Pw, Salt, pepper);
        MasterlyHashAssert.IsPeppered(stored, keyId);
    }

    [Theory]
    [InlineData("@")] // 'A' - 1
    [InlineData("[")] // 'Z' + 1
    [InlineData("`")] // 'a' - 1
    [InlineData("{")] // 'z' + 1
    [InlineData("/")] // '0' - 1
    [InlineData(":")] // '9' + 1
    public void FakePepper_CharactersJustOutsideTheRanges_AreInvalid(string keyId)
    {
        Assert.Equal("currentKeyId", Assert.Throws<ArgumentException>(() => new FakePepper(keyId)).ParamName);
    }

    [Fact]
    public void FakePepper_KeyIdLength_IsOneTo32()
    {
        string max = new string('k', 32);
        var pepper = new FakePepper(max);
        Assert.Equal(max, pepper.CurrentKeyId);
        pepper.AddKey("x");
        Assert.True(pepper.IsKnownKey("x"));

        Assert.Equal("currentKeyId", Assert.Throws<ArgumentException>(() => new FakePepper(new string('k', 33))).ParamName);
        Assert.Equal("currentKeyId", Assert.Throws<ArgumentException>(() => new FakePepper("")).ParamName);
        Assert.Equal("otherKeyIds", Assert.Throws<ArgumentException>(() => new FakePepper("k1", new string('k', 33))).ParamName);
        Assert.Equal("keyId", Assert.Throws<ArgumentException>(() => pepper.AddKey(new string('k', 33))).ParamName);
        Assert.Equal("keyId", Assert.Throws<ArgumentException>(() => pepper.RotateTo("bad id")).ParamName);

        // KnownHashes uses the same rule for the key id it writes into the hash.
        MasterlyHashAssert.IsPeppered(KnownHashes.Create(FastPasswordHasher.Profile, Pw, Salt, pepper, "x"), "x");
        MasterlyHashAssert.IsPeppered(KnownHashes.Create(FastPasswordHasher.Profile, Pw, Salt, pepper, max), max);
    }

    // ======================================================================================================
    // KnownHashes
    // ======================================================================================================

    /// <summary>A pepper that claims to know every key, including ones that are not valid key ids.</summary>
    private sealed class PermissivePepper : IPasswordPepper
    {
        public PermissivePepper(string currentKeyId) => CurrentKeyId = currentKeyId;

        public string CurrentKeyId { get; }
        public bool IsKnownKey(string keyId) => true;
        public byte[] Apply(string keyId, byte[] input) => SHA256.HashData(input);
        public ValueTask<byte[]> ApplyAsync(string keyId, byte[] input, CancellationToken cancellationToken = default) => new(Apply(keyId, input));
    }

    [Fact]
    public void Create_EmptyPassword_IsRejectedAsPassword()
    {
        HashProfile p = FastPasswordHasher.Profile;
        Assert.Equal("password", Assert.Throws<ArgumentException>(() => KnownHashes.Create(p, "", Salt)).ParamName);
        // With a pepper the KDF input would be non-empty, so only the explicit check rejects it.
        Assert.Equal("password", Assert.Throws<ArgumentException>(() => KnownHashes.Create(p, "", Salt, new FakePepper())).ParamName);
    }

    [Fact]
    public void Create_ArgumentErrors_NameTheParameter()
    {
        HashProfile p = FastPasswordHasher.Profile;
        Assert.Equal("salt", Assert.Throws<ArgumentException>(() => KnownHashes.Create(p, Pw, new byte[15])).ParamName);
        Assert.Equal("pepperKeyId", Assert.Throws<ArgumentException>(() => KnownHashes.Create(p, Pw, Salt, null, "k1")).ParamName);
        Assert.Equal("pepperKeyId", Assert.Throws<ArgumentException>(() => KnownHashes.Create(p, Pw, Salt, new FakePepper(), "unknown")).ParamName);
        Assert.Equal("salt", Assert.Throws<ArgumentException>(() => KnownHashes.CreateWrappedV1(p, Pw, Salt, V1Algorithm.SHA512, new byte[8])).ParamName);
    }

    [Fact]
    public void Create_InvalidKeyId_IsRejectedEvenIfThePepperAcceptsIt()
    {
        HashProfile p = FastPasswordHasher.Profile;

        Assert.Equal("pepperKeyId", Assert.Throws<ArgumentException>(() => KnownHashes.Create(p, Pw, Salt, new PermissivePepper("bad id!"))).ParamName);
        Assert.Equal("pepperKeyId", Assert.Throws<ArgumentException>(() => KnownHashes.Create(p, Pw, Salt, new PermissivePepper("ok"), new string('k', 33))).ParamName);
        MasterlyHashAssert.IsPeppered(KnownHashes.Create(p, Pw, Salt, new PermissivePepper("ok")), "ok");
    }

    /// <summary>A pepper that computes what <see cref="FakePepper"/> does but keeps references to its input and output.</summary>
    private sealed class RetainingPepper : IPasswordPepper
    {
        private readonly FakePepper _inner = new FakePepper("k1");

        public byte[]? Input { get; private set; }
        public byte[]? Output { get; private set; }
        public string CurrentKeyId => _inner.CurrentKeyId;
        public bool IsKnownKey(string keyId) => _inner.IsKnownKey(keyId);

        public byte[] Apply(string keyId, byte[] input)
        {
            Input = input;
            Output = _inner.Apply(keyId, input);
            return Output;
        }

        public ValueTask<byte[]> ApplyAsync(string keyId, byte[] input, CancellationToken cancellationToken = default) => new(Apply(keyId, input));
    }

    [Fact]
    public void Create_WithPepper_ZeroesTheEncodedPasswordAndThePepperedKdfInput()
    {
        var pepper = new RetainingPepper();

        string stored = KnownHashes.Create(FastPasswordHasher.Profile, Pw, Salt, pepper);

        // The hash is still the one an ordinary FakePepper gives: zeroing happens after the KDF has run.
        Assert.Equal(KnownHashes.Create(FastPasswordHasher.Profile, Pw, Salt, new FakePepper("k1")), stored);
        Assert.Equal(Encoding.UTF8.GetByteCount(Pw), pepper.Input!.Length);
        Assert.All(pepper.Input!, b => Assert.Equal(0, b));
        // The pepper's output is the KDF input the factory owns once Apply returns; Derive must wipe it.
        Assert.Equal(32, pepper.Output!.Length);
        Assert.All(pepper.Output!, b => Assert.Equal(0, b));
    }

    [Fact]
    public void CreateV1_AndCreateWrappedV1_NullPassword_NameThePassword()
    {
        Assert.Equal("password", Assert.Throws<ArgumentNullException>(() => KnownHashes.CreateV1(null!, Salt)).ParamName);
        Assert.Equal("password", Assert.Throws<ArgumentNullException>(() =>
            KnownHashes.CreateWrappedV1(FastPasswordHasher.Profile, null!, Salt, V1Algorithm.SHA512, Salt)).ParamName);
    }

    // ======================================================================================================
    // MasterlyHashAssert: profile / pepper / rehash messages
    // ======================================================================================================

    [Fact]
    public void UsesProfile_WithHashProfile_ChecksTheProfile()
    {
        var ex = Fails(() => MasterlyHashAssert.UsesProfile(KnownHashes.TestFast, HashProfile.Server2026a));
        Assert.Equal("Expected a hash with profile '2026a', but it uses profile 'test-fast'.", ex.Message);
    }

    [Fact]
    public void IsPeppered_AndIsNotPeppered_HaveExactMessages()
    {
        Assert.Equal("Expected a peppered hash, but it is not peppered.",
            Fails(() => MasterlyHashAssert.IsPeppered(KnownHashes.TestFast)).Message);
        Assert.Equal("Expected an unpeppered hash, but it is peppered with key 'test-key'.",
            Fails(() => MasterlyHashAssert.IsNotPeppered(KnownHashes.TestFastPeppered)).Message);
    }

    [Fact]
    public void DoesNotNeedRehash_Unrecognized_HasExactMessage()
    {
        Assert.Equal("Expected a current hash, but the hasher does not recognize it (format 'mh', profile 'retired-1999').",
            Fails(() => MasterlyHashAssert.DoesNotNeedRehash(FastPasswordHasher.Shared, KnownHashes.UnknownProfile)).Message);
    }

    [Fact]
    public void RehashAssertions_NullStoredHash_HaveExactMessage()
    {
        const string expected = "Expected a stored hash, but the value is null.";
        Assert.Equal(expected, Fails(() => MasterlyHashAssert.NeedsRehash(FastPasswordHasher.Shared, null)).Message);
        Assert.Equal(expected, Fails(() => MasterlyHashAssert.DoesNotNeedRehash(FastPasswordHasher.Shared, null)).Message);
    }

    /// <summary>Verifies with <see cref="FastPasswordHasher.Shared"/>, treating a null password as <see cref="KnownHashes.Password"/>.</summary>
    private sealed class NullTolerantHasher : IPasswordHasher
    {
        private readonly IPasswordHasher _inner = FastPasswordHasher.Shared;

        public string Hash(string password) => _inner.Hash(password);
        public string Hash(string password, HashProfile profile) => _inner.Hash(password, profile);
        public PasswordVerificationResult Verify(string password, string storedHash) => _inner.Verify(password ?? KnownHashes.Password, storedHash);
        public PasswordVerificationResult VerifyOrDummy(string password, string? storedHash) => _inner.VerifyOrDummy(password ?? KnownHashes.Password, storedHash);
        public ValueTask<string> HashAsync(string password, CancellationToken cancellationToken = default) => _inner.HashAsync(password, cancellationToken);
        public ValueTask<PasswordVerificationResult> VerifyAsync(string password, string storedHash, CancellationToken cancellationToken = default) => _inner.VerifyAsync(password, storedHash, cancellationToken);
        public ValueTask<PasswordVerificationResult> VerifyOrDummyAsync(string password, string? storedHash, CancellationToken cancellationToken = default) => _inner.VerifyOrDummyAsync(password, storedHash, cancellationToken);
        public bool NeedsRehash(string storedHash) => _inner.NeedsRehash(storedHash);
        public HashInfo Inspect(string storedHash) => _inner.Inspect(storedHash);
        public bool TryWrap(string legacyHash, out string wrappedHash) => _inner.TryWrap(legacyHash, out wrappedHash);
    }

    [Fact]
    public void Verifies_AndDoesNotVerify_RejectNullPasswordThemselves()
    {
        // The hasher would accept a null password, so only the assertion's own guard rejects it.
        var lenient = new NullTolerantHasher();
        Assert.True(lenient.Verify(null!, KnownHashes.TestFast).IsMatch);

        Assert.Equal("password", Assert.Throws<ArgumentNullException>(() => MasterlyHashAssert.Verifies(lenient, null!, KnownHashes.TestFast)).ParamName);
        Assert.Equal("password", Assert.Throws<ArgumentNullException>(() => MasterlyHashAssert.DoesNotVerify(lenient, null!, KnownHashes.TestFast)).ParamName);
    }

    // ======================================================================================================
    // MasterlyHashAssert.IsNotPlaintext
    // ======================================================================================================

    private const string IsPlaintext = "The stored value is the password in plaintext.";
    private const string ContainsPlaintext = "The stored value contains the password in plaintext.";
    private const string ContainsEncoded = "The stored value contains the password, merely base64- or hex-encoded.";

    [Fact]
    public void IsNotPlaintext_StoredEqualsRawPasswordButNotItsNormalizedForm_IsPlaintext()
    {
        Assert.NotEqual(FullWidth10, FullWidth10.Normalize(NormalizationForm.FormKC));

        Assert.Equal(IsPlaintext, Fails(() => MasterlyHashAssert.IsNotPlaintext(FullWidth10, FullWidth10)).Message);
        Assert.Equal(IsPlaintext, Fails(() => MasterlyHashAssert.IsNotPlaintext("password12", FullWidth10)).Message);
        Assert.Equal(IsPlaintext, Fails(() => MasterlyHashAssert.IsNotPlaintext(Pw.ToUpperInvariant(), Pw)).Message);
    }

    [Fact]
    public void IsNotPlaintext_SixCharacterPassword_IsCheckedForContainment()
    {
        Assert.Equal("passwd", FullWidth6.Normalize(NormalizationForm.FormKC));

        // Raw form embedded (its normalized form is not).
        Assert.Equal(ContainsPlaintext, Fails(() => MasterlyHashAssert.IsNotPlaintext("x" + FullWidth6 + "x", FullWidth6)).Message);
        // Normalized form embedded (its raw form is not).
        Assert.Equal(ContainsPlaintext, Fails(() => MasterlyHashAssert.IsNotPlaintext("xpasswdx", FullWidth6)).Message);
        // Plain ASCII at the limit.
        Assert.Equal(ContainsPlaintext, Fails(() => MasterlyHashAssert.IsNotPlaintext("user=abcdef;", "abcdef")).Message);
    }

    [Fact]
    public void IsNotPlaintext_DetectsEncodingOfTheRawUtf8Bytes()
    {
        // UTF-8 of the raw (unnormalized) password differs from both UTF-16 and UTF-8 of the NFKC form.
        string hex = Convert.ToHexString(Encoding.UTF8.GetBytes(FullWidth10));
        Assert.Equal(ContainsEncoded, Fails(() => MasterlyHashAssert.IsNotPlaintext(hex, FullWidth10)).Message);
    }

    [Fact]
    public void IsNotPlaintext_DetectsUtf16Form_WhenItIsAsLongAsTheUtf8Form()
    {
        const string cyrillic = "\u043F\u0430\u0440\u043E\u043B\u044C"; // "пароль": two UTF-8 bytes per character
        Assert.Equal(Encoding.UTF8.GetByteCount(cyrillic), Encoding.Unicode.GetByteCount(cyrillic));

        string hex = Convert.ToHexString(Encoding.Unicode.GetBytes(cyrillic));
        Assert.Equal(ContainsEncoded, Fails(() => MasterlyHashAssert.IsNotPlaintext(hex, cyrillic)).Message);
        string b64 = Convert.ToBase64String(Encoding.Unicode.GetBytes(cyrillic));
        Assert.Equal(ContainsEncoded, Fails(() => MasterlyHashAssert.IsNotPlaintext(b64, cyrillic)).Message);
    }

    [Fact]
    public void IsNotPlaintext_DuplicateByteForms_DoNotCauseFalsePositives()
    {
        // For ASCII the NFKC UTF-8 form equals the UTF-8 form; a zero-filled salt and tag must not match anything.
        string zeros = "$mh$p=custom-1$" + B64(16) + "$" + B64(16);
        MasterlyHashAssert.IsMasterlyHash(zeros);
        MasterlyHashAssert.IsNotPlaintext(zeros, "abcdef");
        MasterlyHashAssert.IsNotPlaintext("0000000000000000AAAAAAAAAAAAAAAA", "abcdef");
    }

    [Fact]
    public void IsNotPlaintext_FourBytePassword_SixCharacterBase64_IsChecked()
    {
        Assert.Equal("YWJjZA", Convert.ToBase64String(Encoding.UTF8.GetBytes("abcd")).TrimEnd('='));
        Assert.Equal(ContainsEncoded, Fails(() => MasterlyHashAssert.IsNotPlaintext("id:YWJjZA", "abcd")).Message);
        Assert.Equal(ContainsEncoded, Fails(() => MasterlyHashAssert.IsNotPlaintext("id:YWJjZA==", "abcd")).Message);
    }

    [Theory]
    [InlineData("MD5")]
    [InlineData("SHA-1")]
    [InlineData("SHA-256")]
    [InlineData("SHA-384")]
    [InlineData("SHA-512")]
    public void IsNotPlaintext_UnsaltedDigest_MessageNamesTheAlgorithm(string algorithm)
    {
        byte[] utf8 = Encoding.UTF8.GetBytes(Pw);
#pragma warning disable CA5350, CA5351
        byte[] digest = algorithm switch
        {
            "MD5" => MD5.HashData(utf8),
            "SHA-1" => SHA1.HashData(utf8),
            "SHA-256" => SHA256.HashData(utf8),
            "SHA-384" => SHA384.HashData(utf8),
            _ => SHA512.HashData(utf8),
        };
#pragma warning restore CA5350, CA5351
        string expected = $"The stored value contains an unsalted {algorithm} digest of the password, which is reversible by lookup.";

        Assert.Equal(expected, Fails(() => MasterlyHashAssert.IsNotPlaintext(Convert.ToHexString(digest), Pw)).Message);
        Assert.Equal(expected, Fails(() => MasterlyHashAssert.IsNotPlaintext(Convert.ToBase64String(digest), Pw)).Message);
    }

    [Fact]
    public void IsNotPlaintext_MalformedMasterlyValue_IsSearchedWhole()
    {
        // Five '$'-separated parts, but not parseable: the identifiers are searched too.
        Assert.Null(FastPasswordHasher.Shared.Inspect(KnownHashes.Malformed).ProfileId);
        Assert.Equal(5, KnownHashes.Malformed.Split('$').Length);

        Assert.Equal(ContainsPlaintext, Fails(() => MasterlyHashAssert.IsNotPlaintext(KnownHashes.Malformed, "test-fast")).Message);
    }

    [Fact]
    public void IsNotPlaintext_SearchesTheWrapParameter()
    {
        const string wp = "AlNvbWVTYWx0IyQl";
        Assert.Contains(",wp=" + wp + "$", KnownHashes.TestFastWrappedV1Sha512);

        Assert.Equal(ContainsPlaintext, Fails(() => MasterlyHashAssert.IsNotPlaintext(KnownHashes.TestFastWrappedV1Sha512, wp)).Message);
        Assert.Equal(ContainsPlaintext, Fails(() => MasterlyHashAssert.IsNotPlaintext(KnownHashes.TestFastWrappedV1Sha512, "bWVTYWx0")).Message);
    }

    [Fact]
    public void IsNotPlaintext_OnlyTheWrapParameterOfTheParameterList_IsSearched()
    {
        // "p=test-fast" and "k=test-key" are configuration; no slice of them is a leak.
        MasterlyHashAssert.IsNotPlaintext(KnownHashes.TestFast, "est-fast");
        MasterlyHashAssert.IsNotPlaintext(KnownHashes.TestFastPeppered, "est-key");
        MasterlyHashAssert.IsNotPlaintext(KnownHashes.TestFastPeppered, "test-fast,k=test-key");
        MasterlyHashAssert.IsNotPlaintext(KnownHashes.TestFastWrappedV1Sha512, "est-fast");
    }

    [Fact]
    public void IsNotPlaintext_SearchesTheSalt()
    {
        string encoded = Convert.ToBase64String(Encoding.UTF8.GetBytes(Pw)).TrimEnd('=');
        string forged = "$mh$p=custom-1$" + encoded + "$" + B64(16);
        MasterlyHashAssert.IsMasterlyHash(forged);

        Assert.Equal(ContainsEncoded, Fails(() => MasterlyHashAssert.IsNotPlaintext(forged, Pw)).Message);
    }

    // ======================================================================================================
    // MasterlyHashAssert: recorder-based assertions
    // ======================================================================================================

    private const string NoDummy = "Expected a VerifyOrDummy call without a stored hash (unknown user), but none was recorded.";

    [Fact]
    public void UsedVerifyOrDummyForUnknownUser_IgnoresOtherOperationsWithoutAStoredHash()
    {
        var recorder = new RecordingPasswordHasher();
        recorder.Hash(Pw);
        recorder.Hash(Pw, FastPasswordHasher.Profile);
        Assert.Equal(NoDummy, Fails(() => MasterlyHashAssert.UsedVerifyOrDummyForUnknownUser(recorder)).Message);

        recorder.NeedsRehash("");
        recorder.Inspect("");
        recorder.TryWrap("", out _);
        Assert.Equal(NoDummy, Fails(() => MasterlyHashAssert.UsedVerifyOrDummyForUnknownUser(recorder)).Message);

        recorder.VerifyOrDummy(Pw, null);
        MasterlyHashAssert.UsedVerifyOrDummyForUnknownUser(recorder);
    }

    [Fact]
    public void PersistedRehash_HasExactMessages()
    {
        var recorder = new RecordingPasswordHasher();
        Assert.Equal("Expected a rehash to be persisted, but no verification returned a rehash.",
            Fails(() => MasterlyHashAssert.PersistedRehash(recorder, KnownHashes.TestFast)).Message);

        recorder.Verify(KnownHashes.Password, KnownHashes.V1Sha512);
        Assert.Equal("A verification returned a rehash, but the persisted hash is not that rehash. Store PasswordVerificationResult.Rehash after a successful login.",
            Fails(() => MasterlyHashAssert.PersistedRehash(recorder, KnownHashes.V1Sha512)).Message);
    }

    // ======================================================================================================
    // PasswordHasherCall
    // ======================================================================================================

    [Fact]
    public async Task PasswordHasherCall_ToString_NamesSyncAndAsyncOperations()
    {
        var recorder = new RecordingPasswordHasher();
        recorder.Hash(Pw);
        await recorder.HashAsync(Pw);
        recorder.Inspect(KnownHashes.TestFast);

        IReadOnlyList<PasswordHasherCall> calls = recorder.Calls;
        Assert.Equal("#1 Hash", calls[0].ToString());
        Assert.Equal("#2 HashAsync", calls[1].ToString());
        Assert.Equal("#3 Inspect", calls[2].ToString());

        var failing = new RecordingPasswordHasher(new AlwaysThrowingHasher(new TimeoutException()));
        Assert.Throws<TimeoutException>(() => failing.Hash(Pw));
        Assert.Equal("#1 Hash threw TimeoutException", failing.Calls[0].ToString());
    }

    [Fact]
    public void PasswordHasherCall_IsUnknownUser_OnlyForVerifyCalls()
    {
        var recorder = new RecordingPasswordHasher();
        recorder.Hash(Pw);
        recorder.Inspect("");
        recorder.VerifyOrDummy(Pw, null);
        recorder.Verify(Pw, null!);
        recorder.Verify(KnownHashes.Password, KnownHashes.TestFast);

        Assert.Equal(new[] { false, false, true, true, false }, recorder.Calls.Select(c => c.IsUnknownUser));
    }

    // ======================================================================================================
    // RecordingPasswordHasher: IsAsync and exception recording on every path
    // ======================================================================================================

    /// <summary>An inner hasher whose every member throws the given exception synchronously.</summary>
    private sealed class AlwaysThrowingHasher : IPasswordHasher
    {
        private readonly Exception _exception;

        public AlwaysThrowingHasher(Exception exception) => _exception = exception;

        public string Hash(string password) => throw _exception;
        public string Hash(string password, HashProfile profile) => throw _exception;
        public PasswordVerificationResult Verify(string password, string storedHash) => throw _exception;
        public PasswordVerificationResult VerifyOrDummy(string password, string? storedHash) => throw _exception;
        public ValueTask<string> HashAsync(string password, CancellationToken cancellationToken = default) => throw _exception;
        public ValueTask<PasswordVerificationResult> VerifyAsync(string password, string storedHash, CancellationToken cancellationToken = default) => throw _exception;
        public ValueTask<PasswordVerificationResult> VerifyOrDummyAsync(string password, string? storedHash, CancellationToken cancellationToken = default) => throw _exception;
        public bool NeedsRehash(string storedHash) => throw _exception;
        public HashInfo Inspect(string storedHash) => throw _exception;
        public bool TryWrap(string legacyHash, out string wrappedHash) => throw _exception;
    }

    [Fact]
    public void Recorder_SuccessfulSyncCalls_AreNotAsync()
    {
        // TryWrap needs a fixed-algorithm 1.x format.
        var recorder = new RecordingPasswordHasher(new FastPasswordHasher(o =>
        {
            o.LegacyFormats.Clear();
            o.LegacyFormats.Add(new V1LegacyFormat(V1Algorithm.SHA512));
        }));
        string stored = recorder.Hash(Pw);
        recorder.Hash(Pw, FastPasswordHasher.Profile);
        recorder.Verify(Pw, stored);
        recorder.VerifyOrDummy(Pw, null);
        recorder.NeedsRehash(stored);
        recorder.Inspect(stored);
        Assert.True(recorder.TryWrap(KnownHashes.V1Sha512, out string wrapped));

        IReadOnlyList<PasswordHasherCall> calls = recorder.Calls;
        Assert.Equal(7, calls.Count);
        Assert.All(calls, c => Assert.False(c.IsAsync));
        Assert.All(calls, c => Assert.Null(c.Exception));
        Assert.Equal(FastPasswordHasher.ProfileId, calls[1].ProfileId);
        Assert.Equal(false, calls[4].BooleanResult);
        Assert.Equal(FastPasswordHasher.ProfileId, calls[5].Info!.ProfileId);
        Assert.Equal(stored, calls[5].StoredHash);
        Assert.Equal(wrapped, calls[6].ProducedHash);
        Assert.Equal(true, calls[6].BooleanResult);
    }

    [Fact]
    public void Recorder_FailedSyncCalls_AreRecordedAsNotAsync()
    {
        var boom = new TimeoutException("boom");
        var recorder = new RecordingPasswordHasher(new AlwaysThrowingHasher(boom));

        Assert.Same(boom, Assert.Throws<TimeoutException>(() => recorder.Hash(Pw)));
        Assert.Same(boom, Assert.Throws<TimeoutException>(() => recorder.Hash(Pw, FastPasswordHasher.Profile)));
        Assert.Same(boom, Assert.Throws<TimeoutException>(() => recorder.Verify(Pw, "s")));
        Assert.Same(boom, Assert.Throws<TimeoutException>(() => recorder.VerifyOrDummy(Pw, null)));
        Assert.Same(boom, Assert.Throws<TimeoutException>(() => recorder.NeedsRehash("s")));
        Assert.Same(boom, Assert.Throws<TimeoutException>(() => recorder.Inspect("s")));
        Assert.Same(boom, Assert.Throws<TimeoutException>(() => recorder.TryWrap("s", out _)));

        IReadOnlyList<PasswordHasherCall> calls = recorder.Calls;
        Assert.Equal(7, calls.Count);
        Assert.All(calls, c => Assert.False(c.IsAsync));
        Assert.All(calls, c => Assert.Same(boom, c.Exception));
        Assert.Equal(FastPasswordHasher.ProfileId, calls[1].ProfileId);
    }

    [Fact]
    public async Task Recorder_FailedAsyncCalls_AreRecordedAsAsync()
    {
        var boom = new TimeoutException("boom");
        var recorder = new RecordingPasswordHasher(new AlwaysThrowingHasher(boom));

        Assert.Same(boom, await Assert.ThrowsAsync<TimeoutException>(() => recorder.HashAsync(Pw).AsTask()));
        Assert.Same(boom, await Assert.ThrowsAsync<TimeoutException>(() => recorder.VerifyAsync(Pw, "s").AsTask()));
        Assert.Same(boom, await Assert.ThrowsAsync<TimeoutException>(() => recorder.VerifyOrDummyAsync(Pw, null).AsTask()));

        IReadOnlyList<PasswordHasherCall> calls = recorder.Calls;
        Assert.Equal(new[] { PasswordHasherOperation.Hash, PasswordHasherOperation.Verify, PasswordHasherOperation.VerifyOrDummy }, calls.Select(c => c.Operation));
        Assert.All(calls, c => Assert.True(c.IsAsync));
        Assert.All(calls, c => Assert.Same(boom, c.Exception));
        Assert.All(calls, c => Assert.Equal(recorder.Fingerprint(Pw), c.PasswordFingerprint));
        Assert.Equal("s", calls[1].StoredHash);
        Assert.Equal("#1 HashAsync threw TimeoutException", calls[0].ToString());
    }
}
