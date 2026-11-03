using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace Masterly.Hash.Tokens.Tests;

/// <summary>
/// Exact-boundary, parameter-name and message assertions that pin behaviour the scenario tests only exercise loosely.
/// </summary>
public class MutationTests
{
    private const string Reset = "password-reset";

    private static readonly string KeyId32 = new string('a', HmacKeyRing.MaxKeyIdLength);

    private static SignedTokenService Service(HmacKeyRing? ring = null, Func<DateTimeOffset>? clock = null,
        Action<SignedTokenOptions>? configure = null)
    {
        var options = new SignedTokenOptions { Clock = clock ?? (() => TestKeys.T0) };
        configure?.Invoke(options);
        return new SignedTokenService(ring ?? TestKeys.Ring("k1", "k1"), options);
    }

    private static void AssertArgument(string paramName, string message, Action action)
    {
        var ex = Assert.ThrowsAny<ArgumentException>(action);
        Assert.Equal(paramName, ex.ParamName);
        Assert.StartsWith(message, ex.Message, StringComparison.Ordinal);
    }

    // ---------------------------------------------------------------- ApiKey

    [Fact]
    public void ApiKey_of_exactly_MaxLength_parses()
    {
        string prefix = new string('a', ApiKey.MaxPrefixLength);
        string key = ApiKey.Generate(prefix, ApiKey.MaxEntropyBytes);

        Assert.Equal(ApiKey.MaxLength, key.Length);
        Assert.Equal(125, ApiKey.MaxLength);
        Assert.True(ApiKey.TryParse(key, out ApiKeyParts? parts));
        Assert.Equal(prefix, parts!.Prefix);
        Assert.Equal(ApiKey.MaxEntropyBytes, parts.EntropyBytes);
        Assert.False(ApiKey.HasValidChecksum(key + "0"));
    }

    [Theory]
    [InlineData("A", true)]
    [InlineData("Z", true)]
    [InlineData("a", true)]
    [InlineData("z", true)]
    [InlineData("aZ", true)]
    [InlineData("az", true)]
    [InlineData("a0", true)]
    [InlineData("a9", true)]
    [InlineData("a0_9", true)]
    [InlineData("@", false)] // just below 'A'
    [InlineData("[", false)] // just above 'Z'
    [InlineData("`", false)] // just below 'a'
    [InlineData("{", false)] // just above 'z'
    [InlineData("a/", false)] // just below '0'
    [InlineData("a:", false)] // just above '9'
    [InlineData("a@", false)]
    [InlineData("a[", false)]
    [InlineData("a`", false)]
    [InlineData("a{", false)]
    public void ApiKey_prefix_character_class_boundaries(string prefix, bool valid)
    {
        Assert.Equal(valid, ApiKey.IsValidPrefix(prefix));
        if (valid)
            Assert.True(ApiKey.HasValidChecksum(ApiKey.Generate(prefix, ApiKey.MinEntropyBytes)));
    }

    [Fact]
    public void ApiKey_argument_messages()
    {
        AssertArgument("prefix",
            "Prefix must be 1-32 ASCII letters, digits and single underscores, start with a letter and not end with an underscore.",
            () => ApiKey.Generate("1bad"));

        var low = Assert.Throws<ArgumentOutOfRangeException>(() => ApiKey.Generate("mh", ApiKey.MinEntropyBytes - 1));
        Assert.Equal("entropyBytes", low.ParamName);
        Assert.Equal(ApiKey.MinEntropyBytes - 1, low.ActualValue);
        Assert.StartsWith("Entropy must be 16 to 64 bytes.", low.Message, StringComparison.Ordinal);

        var high = Assert.Throws<ArgumentOutOfRangeException>(() => ApiKey.Generate("mh", ApiKey.MaxEntropyBytes + 1));
        Assert.StartsWith("Entropy must be 16 to 64 bytes.", high.Message, StringComparison.Ordinal);
    }

    // ---------------------------------------------------------------- ApiKeyHasher

    [Fact]
    public void ApiKeyHasher_accepts_a_key_of_exactly_MaxApiKeyLength()
    {
        var hasher = new ApiKeyHasher(TestKeys.Ring("k1", "k1"));
        string key = new string('x', ApiKeyHasher.MaxApiKeyLength);

        string hash = hasher.ComputeLookupHash(key);
        Assert.Single(hasher.ComputeAllLookupHashes(key));
        Assert.True(hasher.Verify(key, hash));

        string tooLong = key + "x";
        Assert.False(hasher.Verify(tooLong, hash));
        AssertArgument("apiKey", "API key is longer than 1024 characters.", () => hasher.ComputeLookupHash(tooLong));
    }

    [Fact]
    public void ApiKeyHasher_handles_a_lookup_hash_with_a_32_character_key_id()
    {
        var hasher = new ApiKeyHasher(TestKeys.Ring(KeyId32, KeyId32));
        string hash = hasher.ComputeLookupHash("mh_secret");

        Assert.Equal(HmacKeyRing.MaxKeyIdLength + 1 + 43, hash.Length);
        Assert.True(hasher.Verify("mh_secret", hash));
        Assert.False(hasher.NeedsRehash(hash));
        Assert.True(ApiKeyHasher.TryGetKeyId(hash, out string keyId));
        Assert.Equal(KeyId32, keyId);
        Assert.True(ApiKeyHasher.TryGetKeyId(KeyId32.Substring(1) + hash.Substring(KeyId32.Length), out string shorter));
        Assert.Equal(KeyId32.Substring(1), shorter);

        // One character more is rejected unparsed.
        Assert.False(ApiKeyHasher.TryGetKeyId("b" + hash, out string none));
        Assert.Equal(string.Empty, none);
    }

    [Fact]
    public void ApiKeyHasher_argument_messages()
    {
        var hasher = new ApiKeyHasher(TestKeys.Ring("k1", "k1"));
        AssertArgument("apiKey", "API key cannot be empty.", () => hasher.ComputeLookupHash(""));
        AssertArgument("apiKey", "API key is not valid UTF-16.", () => hasher.ComputeLookupHash("a\uD800b"));
        AssertArgument("apiKey", "API key cannot be empty.", () => hasher.ComputeAllLookupHashes(""));
    }

    // ---------------------------------------------------------------- Base62 / Crc32

    [Fact]
    public void Base62_oversized_input_message()
    {
        AssertArgument("bytes", "At most 1024 bytes can be encoded.", () => Base62.Encode(new byte[Base62.MaxByteLength + 1]));
    }

    [Fact]
    public void Crc32_string_overload_reports_its_own_parameter_name()
    {
        var ex = Assert.Throws<ArgumentNullException>(() => Crc32.Compute((string)null!));
        Assert.Equal("text", ex.ParamName);
    }

    // ---------------------------------------------------------------- HmacKeyRing

    [Theory]
    [InlineData("A")]
    [InlineData("Z")]
    [InlineData("a")]
    [InlineData("z")]
    [InlineData("0")]
    [InlineData("9")]
    [InlineData("-")]
    [InlineData("AZaz09-")]
    public void HmacKeyRing_key_id_character_class_includes_range_ends(string keyId)
    {
        Assert.True(HmacKeyRing.IsValidKeyId(keyId));
        Assert.Equal(keyId, TestKeys.Ring(keyId, keyId).CurrentKeyId);
    }

    [Theory]
    [InlineData("@")]
    [InlineData("[")]
    [InlineData("`")]
    [InlineData("{")]
    [InlineData("/")]
    [InlineData(":")]
    public void HmacKeyRing_key_id_character_class_excludes_neighbours(string keyId) =>
        Assert.False(HmacKeyRing.IsValidKeyId(keyId));

    [Fact]
    public void HmacKeyRing_rejects_an_invalid_current_key_id_before_looking_at_the_keys()
    {
        byte[] key = TestKeys.Key("x");

        // The keys are invalid too; the current key id must still be blamed first.
        AssertArgument("currentKeyId", "Key id must match ^[A-Za-z0-9-]{1,32}$.",
            () => new HmacKeyRing("bad id", new Dictionary<string, byte[]> { ["also bad"] = key }));
        AssertArgument("currentKeyId", "Key id must match ^[A-Za-z0-9-]{1,32}$.",
            () => new HmacKeyRing("bad id", new Dictionary<string, byte[]> { ["k1"] = new byte[1] }));
        AssertArgument("currentKeyId", "Key id must match ^[A-Za-z0-9-]{1,32}$.",
            () => new HmacKeyRing("bad id", new Dictionary<string, byte[]> { ["k1"] = key }));
    }

    [Fact]
    public void HmacKeyRing_argument_messages()
    {
        byte[] key = TestKeys.Key("x");
        AssertArgument("keys", "Every key id must match ^[A-Za-z0-9-]{1,32}$.",
            () => new HmacKeyRing("k1", new Dictionary<string, byte[]> { ["k1"] = key, ["bad id"] = key }));
        AssertArgument("keys", "Key 'k1' must be at least 32 bytes.",
            () => new HmacKeyRing("k1", new Dictionary<string, byte[]> { ["k1"] = new byte[HmacKeyRing.MinKeyLength - 1] }));
        AssertArgument("currentKeyId", "Current key 'k2' is not in the key ring.",
            () => new HmacKeyRing("k2", new Dictionary<string, byte[]> { ["k1"] = key }));
        AssertArgument("base64Keys", "Key 'k1' is null.",
            () => HmacKeyRing.FromBase64("k1", new Dictionary<string, string> { ["k1"] = null! }));
    }

    // ---------------------------------------------------------------- InMemoryUsedTokenStore

    [Fact]
    public void InMemoryUsedTokenStore_reports_the_nonce_parameter()
    {
        var store = new InMemoryUsedTokenStore(() => TestKeys.T0);
        Assert.Equal("nonce", Assert.Throws<ArgumentNullException>(() => store.TryMarkUsed(null!, TestKeys.T0)).ParamName);
    }

    [Fact]
    public void InMemoryUsedTokenStore_does_not_purge_before_the_256th_operation()
    {
        var clock = new FakeClock(TestKeys.T0);
        var store = new InMemoryUsedTokenStore(clock.AsFunc());

        Assert.True(store.TryMarkUsed("old", TestKeys.T0));
        clock.Advance(TimeSpan.FromHours(1)); // "old" is now far past retainUntil + PurgeGrace
        Assert.True(store.TryMarkUsed("new", clock.Now.AddHours(1)));

        Assert.Equal(2, store.Count);
        Assert.True(store.Contains("old"));

        store.Purge();
        Assert.Equal(1, store.Count);
        Assert.False(store.Contains("old"));
    }

    // ---------------------------------------------------------------- SecureRandomString

    [Fact]
    public void SecureRandomString_accepts_exactly_MaxLength()
    {
        string value = SecureRandomString.Generate(SecureRandomString.MaxLength, SecureRandomString.Hex);
        Assert.Equal(SecureRandomString.MaxLength, value.Length);
        Assert.Equal("length",
            Assert.Throws<ArgumentOutOfRangeException>(() => SecureRandomString.Generate(SecureRandomString.MaxLength + 1)).ParamName);
    }

    [Fact]
    public void SecureRandomString_entropy_of_a_two_character_alphabet()
    {
        Assert.Equal(1.0, SecureRandomString.GetEntropyBits(1, 2), 10);
        Assert.Equal(7.0, SecureRandomString.GetEntropyBits(7, 2), 10);
        Assert.Equal("alphabetLength",
            Assert.Throws<ArgumentOutOfRangeException>(() => SecureRandomString.GetEntropyBits(1, 1)).ParamName);
    }

    [Fact]
    public void SecureRandomString_draws_one_batch_of_one_and_a_half_times_the_length_plus_16()
    {
        // With Hex (256 % 16 == 0) every random byte is accepted, so a length L <= 2720 needs exactly one RNG batch of
        // 1.5 * L + 16 bytes. Going from L = 1000 to L = 2000 therefore allocates 2000 * 2 more bytes for the char
        // buffer, 2000 * 2 more for the string and 1500 more random bytes: about 5500 bytes. A smaller batch (two
        // draws), a larger one, or a 4096-byte floor would change that difference by 400 bytes or more.
        static long Allocated(int length)
        {
            long before = GC.GetAllocatedBytesForCurrentThread();
            string value = SecureRandomString.Generate(length, SecureRandomString.Hex);
            long after = GC.GetAllocatedBytesForCurrentThread();
            Assert.Equal(length, value.Length);
            return after - before;
        }

        // Warm up so first-call type loading and JIT work are not counted.
        Allocated(1000);
        Allocated(2000);

        long delta = Allocated(2000) - Allocated(1000);
        Assert.InRange(delta, 5300, 5700);
    }

    [Fact]
    public void SecureRandomString_argument_messages()
    {
        AssertArgument("alphabet", "Alphabet must have 2 to 256 characters.", () => SecureRandomString.Generate(4, "a"));
        AssertArgument("alphabet", "Alphabet cannot contain surrogate characters.", () => SecureRandomString.Generate(4, "ab\uD800"));
        AssertArgument("alphabet", "Alphabet characters must be distinct; duplicates bias the output.",
            () => SecureRandomString.Generate(4, "aba"));
    }

    // ---------------------------------------------------------------- SignedTokenService: options

    [Fact]
    public void SignedTokenService_accepts_option_upper_and_lower_limits()
    {
        var service = Service(configure: o =>
        {
            o.MaxTokenLength = 16384;
            o.MaxSubjectBytes = 1;
            o.MaxLifetime = TimeSpan.FromDays(3650);
            o.ClockSkew = SignedTokenOptions.MaxClockSkew;
        });

        string token = service.Create(Reset, "u", TimeSpan.FromDays(3650));
        Assert.Equal(SignedTokenStatus.Valid, service.Validate(token, Reset, out SignedTokenPayload? payload));
        Assert.Equal("u", payload!.Subject);
        AssertArgument("subject", "Subject is longer than 1 UTF-8 bytes.", () => service.Create(Reset, "uu", TimeSpan.FromMinutes(1)));

        Assert.NotNull(Service(configure: o => o.MaxTokenLength = 256));
        Assert.NotNull(Service(configure: o => o.MaxSubjectBytes = 4096));
    }

    [Fact]
    public void SignedTokenService_option_messages()
    {
        AssertArgument("options", "Clock is required.", () => Service(configure: o => o.Clock = null!));
        AssertArgument("options", "ClockSkew must be between zero and one hour.",
            () => Service(configure: o => o.ClockSkew = TimeSpan.FromSeconds(-1)));
        AssertArgument("options", "MaxTokenLength must be 256 to 16384.", () => Service(configure: o => o.MaxTokenLength = 255));
        AssertArgument("options", "MaxTokenLength must be 256 to 16384.", () => Service(configure: o => o.MaxTokenLength = 16385));
        AssertArgument("options", "MaxSubjectBytes must be 1 to 4096.", () => Service(configure: o => o.MaxSubjectBytes = 0));
        AssertArgument("options", "MaxSubjectBytes must be 1 to 4096.", () => Service(configure: o => o.MaxSubjectBytes = 4097));
        AssertArgument("options", "MaxLifetime must be positive and at most 3650 days.",
            () => Service(configure: o => o.MaxLifetime = TimeSpan.Zero));
        AssertArgument("options", "MaxLifetime must be positive and at most 3650 days.",
            () => Service(configure: o => o.MaxLifetime = TimeSpan.FromDays(3650) + TimeSpan.FromTicks(1)));
    }

    // ---------------------------------------------------------------- SignedTokenService: Create / Validate limits

    [Fact]
    public void SignedTokenService_accepts_a_subject_of_exactly_MaxSubjectBytes()
    {
        var service = Service();
        string subject = new string('s', 512);

        string token = service.Create(Reset, subject, TimeSpan.FromMinutes(5));
        Assert.Equal(SignedTokenStatus.Valid, service.Validate(token, Reset, out SignedTokenPayload? payload));
        Assert.Equal(subject, payload!.Subject);

        AssertArgument("subject", "Subject is longer than 512 UTF-8 bytes.", () => service.Create(Reset, subject + "s", TimeSpan.FromMinutes(5)));
    }

    [Fact]
    public void SignedTokenService_accepts_a_lifetime_of_exactly_MaxLifetime()
    {
        var service = Service();
        string token = service.Create(Reset, "u", TimeSpan.FromDays(30));
        Assert.Equal(SignedTokenStatus.Valid, service.Validate(token, Reset, out SignedTokenPayload? payload));
        Assert.Equal(TestKeys.T0.AddDays(30), payload!.ExpiresAt);

        var ex = Assert.Throws<ArgumentOutOfRangeException>(() => service.Create(Reset, "u", TimeSpan.FromDays(30) + TimeSpan.FromTicks(1)));
        Assert.Equal("lifetime", ex.ParamName);
        Assert.StartsWith("Lifetime must be positive and at most MaxLifetime.", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void SignedTokenService_accepts_a_purpose_of_exactly_MaxPurposeLength()
    {
        var service = Service();
        string purpose = new string('p', SignedTokenService.MaxPurposeLength);

        string token = service.Create(purpose, "u", TimeSpan.FromMinutes(5));
        Assert.Equal(SignedTokenStatus.Valid, service.Validate(token, purpose, out _));

        AssertArgument("purpose", "Purpose is longer than 256 characters.", () => service.Create(purpose + "p", "u", TimeSpan.FromMinutes(5)));
        AssertArgument("expectedPurpose", "Purpose is longer than 256 characters.", () => service.Validate(token, purpose + "p", out _));
    }

    [Fact]
    public void SignedTokenService_argument_messages()
    {
        var service = Service();
        AssertArgument("purpose", "Purpose cannot be empty.", () => service.Create("", "u", TimeSpan.FromMinutes(5)));
        AssertArgument("expectedPurpose", "Purpose cannot be empty.", () => service.Validate("x", "", out _));
        AssertArgument("subject", "Subject cannot be empty.", () => service.Create(Reset, "", TimeSpan.FromMinutes(5)));
        AssertArgument("subject", "Value is not valid UTF-16.", () => service.Create(Reset, "a\uDC00", TimeSpan.FromMinutes(5)));
        AssertArgument("purpose", "Value is not valid UTF-16.", () => service.Create("p\uD800", "u", TimeSpan.FromMinutes(5)));
    }

    [Fact]
    public void SignedTokenService_token_of_exactly_MaxTokenLength_is_created_and_validated()
    {
        // 100 fixed bytes + 2 key-id bytes + 90 subject bytes = 192 bytes = exactly 256 base64url characters.
        var service = Service(configure: o => o.MaxTokenLength = 256);
        string subject = new string('s', 90);

        string token = service.Create(Reset, subject, TimeSpan.FromMinutes(5));
        Assert.Equal(256, token.Length);
        Assert.Equal(SignedTokenStatus.Valid, service.Validate(token, Reset, out SignedTokenPayload? payload));
        Assert.Equal(subject, payload!.Subject);
        Assert.Equal(SignedTokenStatus.Malformed, service.Validate(token + "A", Reset, out _));

        AssertArgument("subject", "The token would be longer than MaxTokenLength; shorten the subject.",
            () => service.Create(Reset, subject + "s", TimeSpan.FromMinutes(5)));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(HmacKeyRing.MaxKeyIdLength)]
    public void SignedTokenService_round_trips_key_ids_at_the_length_limits(int length)
    {
        string keyId = new string('k', length);
        var service = Service(TestKeys.Ring(keyId, keyId));

        string token = service.Create(Reset, "u", TimeSpan.FromMinutes(5));
        Assert.Equal(SignedTokenStatus.Valid, service.Validate(token, Reset, out SignedTokenPayload? payload));
        Assert.Equal(keyId, payload!.KeyId);
    }

    [Fact]
    public void SignedTokenService_accepts_a_token_issued_at_the_unix_epoch()
    {
        var service = Service(clock: () => DateTimeOffset.UnixEpoch);

        string token = service.Create(Reset, "u", TimeSpan.FromMinutes(5));
        Assert.Equal(SignedTokenStatus.Valid, service.Validate(token, Reset, out SignedTokenPayload? payload));
        Assert.Equal(DateTimeOffset.UnixEpoch, payload!.IssuedAt);
        Assert.Equal(DateTimeOffset.UnixEpoch.AddMinutes(5), payload.ExpiresAt);
    }

    [Fact]
    public void SignedTokenService_accepts_a_token_expiring_at_the_last_supported_second()
    {
        DateTimeOffset last = new DateTimeOffset(9999, 12, 31, 23, 59, 59, TimeSpan.Zero);
        var service = Service(clock: () => last.AddMinutes(-1));

        string token = service.Create(Reset, "u", TimeSpan.FromMinutes(1));
        Assert.Equal(SignedTokenStatus.Valid, service.Validate(token, Reset, out SignedTokenPayload? payload));
        Assert.Equal(last, payload!.ExpiresAt);
    }

    // ---------------------------------------------------------------- SignedTokenService: ConsumeAsync

    [Fact]
    public async Task ConsumeAsync_does_not_resume_on_the_callers_synchronization_context()
    {
        var service = Service();
        string token = service.Create(Reset, "u", TimeSpan.FromMinutes(5));
        var store = new PendingStore();
        var context = new CountingSynchronizationContext();

        SynchronizationContext? previous = SynchronizationContext.Current;
        ValueTask<SignedTokenResult> pending;
        SynchronizationContext.SetSynchronizationContext(context);
        try
        {
            pending = service.ConsumeAsync(token, Reset, store);
        }
        finally
        {
            SynchronizationContext.SetSynchronizationContext(previous);
        }

        Assert.False(pending.IsCompleted);
        store.Complete(true);
        SignedTokenResult result = await pending;

        Assert.Equal(SignedTokenStatus.Valid, result.Status);
        Assert.Equal(0, context.Posts);
    }

    private sealed class PendingStore : IUsedTokenStore
    {
        private readonly TaskCompletionSource<bool> _tcs = new TaskCompletionSource<bool>();

        public ValueTask<bool> TryMarkUsedAsync(string nonce, DateTimeOffset retainUntil, CancellationToken cancellationToken = default) =>
            new ValueTask<bool>(_tcs.Task);

        public void Complete(bool value) => _tcs.SetResult(value);
    }

    private sealed class CountingSynchronizationContext : SynchronizationContext
    {
        private int _posts;

        public int Posts => Volatile.Read(ref _posts);

        public override void Post(SendOrPostCallback d, object? state)
        {
            Interlocked.Increment(ref _posts);
            base.Post(d, state);
        }
    }
}
