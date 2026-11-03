using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Masterly.Hash.Tokens.Tests;

public class SignedTokenServiceTests
{
    private const string Reset = "password-reset";

    private static (SignedTokenService Service, FakeClock Clock) Create(HmacKeyRing? ring = null, Action<SignedTokenOptions>? configure = null)
    {
        var clock = new FakeClock(TestKeys.T0);
        var options = new SignedTokenOptions { Clock = clock.AsFunc() };
        configure?.Invoke(options);
        return (new SignedTokenService(ring ?? TestKeys.Ring("k1", "k1"), options), clock);
    }

    [Fact]
    public void RoundTripReturnsAuthenticatedPayload()
    {
        var (service, _) = Create();
        string token = service.Create(Reset, "user-42", TimeSpan.FromMinutes(30));

        Assert.Equal(SignedTokenStatus.Valid, service.Validate(token, Reset, out SignedTokenPayload? payload));
        Assert.NotNull(payload);
        Assert.Equal(SignedTokenService.CurrentVersion, payload!.Version);
        Assert.Equal("k1", payload.KeyId);
        Assert.Equal(Reset, payload.Purpose);
        Assert.Equal("user-42", payload.Subject);
        Assert.Equal(TestKeys.T0, payload.IssuedAt);
        Assert.Equal(TestKeys.T0.AddMinutes(30), payload.ExpiresAt);
        Assert.Equal(22, payload.Nonce.Length);
        Assert.Equal(SignedTokenService.NonceLength, TestKeys.FromBase64Url(payload.Nonce).Length);
    }

    [Fact]
    public void TokenIsUrlSafe()
    {
        var (service, _) = Create();
        for (int i = 0; i < 200; i++)
        {
            string token = service.Create(Reset, "user+" + i + "@example.com/é", TimeSpan.FromHours(1));
            Assert.All(token, c => Assert.True(char.IsAsciiLetterOrDigit(c) || c == '-' || c == '_', $"'{c}'"));
            Assert.Equal(token, Uri.EscapeDataString(token));
        }
    }

    [Fact]
    public void UnicodeSubjectRoundTrips()
    {
        var (service, _) = Create();
        const string subject = "ユーザー😀@例え.jp";
        string token = service.Create(Reset, subject, TimeSpan.FromMinutes(5));
        Assert.True(service.TryValidate(token, Reset, out SignedTokenPayload? payload));
        Assert.Equal(subject, payload!.Subject);
    }

    [Fact]
    public void EveryTokenHasAUniqueNonce()
    {
        var (service, _) = Create();
        var nonces = new HashSet<string>();
        var tokens = new HashSet<string>();
        for (int i = 0; i < 1000; i++)
        {
            string token = service.Create(Reset, "same-user", TimeSpan.FromMinutes(5));
            Assert.True(tokens.Add(token));
            Assert.True(service.TryValidate(token, Reset, out SignedTokenPayload? payload));
            Assert.True(nonces.Add(payload!.Nonce));
        }
    }

    [Fact]
    public void WireFormatMatchesDocumentedLayout()
    {
        // Build a token by hand from the layout in the SignedTokenService docs; the service must accept it.
        byte[] ringKey = TestKeys.Key("k1");
        var (service, _) = Create();
        byte[] nonce = Enumerable.Range(0, 16).Select(i => (byte)i).ToArray();
        string token = TestTokens.Build(ringKey, "k1", Reset, "alice", TestKeys.T0.ToUnixTimeSeconds(),
            TestKeys.T0.AddMinutes(10).ToUnixTimeSeconds(), nonce);

        Assert.Equal(SignedTokenStatus.Valid, service.Validate(token, Reset, out SignedTokenPayload? payload));
        Assert.Equal("alice", payload!.Subject);
        Assert.Equal(TestKeys.ToBase64Url(nonce), payload.Nonce);

        // And the service's own tokens decode to that layout.
        byte[] own = TestKeys.FromBase64Url(service.Create(Reset, "bob", TimeSpan.FromSeconds(90)));
        Assert.Equal(1, own[0]);
        Assert.Equal(2, own[1]);
        Assert.Equal("k1", Encoding.ASCII.GetString(own, 2, 2));
        Assert.Equal(SHA256.HashData(Encoding.UTF8.GetBytes(Reset)), own.Skip(4).Take(32).ToArray());
        Assert.Equal(TestKeys.T0.ToUnixTimeSeconds(), TestTokens.ReadInt64(own, 36));
        Assert.Equal(TestKeys.T0.ToUnixTimeSeconds() + 90, TestTokens.ReadInt64(own, 44));
        Assert.Equal(3, (own[68] << 8) | own[69]);
        Assert.Equal("bob", Encoding.UTF8.GetString(own, 70, 3));
        Assert.Equal(73 + 32, own.Length);
    }

    [Fact]
    public void WrongPurposeIsRejected()
    {
        var (service, _) = Create();
        string token = service.Create("email-confirm", "user-42", TimeSpan.FromMinutes(30));

        Assert.Equal(SignedTokenStatus.WrongPurpose, service.Validate(token, Reset, out SignedTokenPayload? payload));
        Assert.Null(payload);
        Assert.Equal(SignedTokenStatus.WrongPurpose, service.Validate(token, "Email-Confirm", out _));
        Assert.Equal(SignedTokenStatus.Valid, service.Validate(token, "email-confirm", out _));
        Assert.False(service.TryValidate(token, Reset, out _));
    }

    [Fact]
    public void ExpiryHonoursClockSkew()
    {
        var (service, clock) = Create(configure: o => o.ClockSkew = TimeSpan.FromSeconds(30));
        string token = service.Create(Reset, "u", TimeSpan.FromMinutes(10));

        clock.Advance(TimeSpan.FromMinutes(10));
        Assert.Equal(SignedTokenStatus.Valid, service.Validate(token, Reset, out _)); // within skew
        clock.Advance(TimeSpan.FromSeconds(29));
        Assert.Equal(SignedTokenStatus.Valid, service.Validate(token, Reset, out _));
        clock.Advance(TimeSpan.FromSeconds(1));
        Assert.Equal(SignedTokenStatus.Expired, service.Validate(token, Reset, out SignedTokenPayload? payload));
        Assert.NotNull(payload); // authenticated, so the caller may e.g. offer to resend
        Assert.Equal("u", payload!.Subject);
        Assert.False(service.TryValidate(token, Reset, out SignedTokenPayload? none));
        Assert.Null(none);

        clock.Advance(TimeSpan.FromDays(365));
        Assert.Equal(SignedTokenStatus.Expired, service.Validate(token, Reset, out _));
    }

    [Fact]
    public void ZeroSkewExpiresExactlyAtExpiry()
    {
        var (service, clock) = Create(configure: o => o.ClockSkew = TimeSpan.Zero);
        string token = service.Create(Reset, "u", TimeSpan.FromSeconds(60));
        clock.Advance(TimeSpan.FromSeconds(59));
        Assert.Equal(SignedTokenStatus.Valid, service.Validate(token, Reset, out _));
        clock.Advance(TimeSpan.FromSeconds(1));
        Assert.Equal(SignedTokenStatus.Expired, service.Validate(token, Reset, out _));
    }

    [Fact]
    public void LifetimeIsRoundedUpToWholeSeconds()
    {
        var (service, _) = Create();
        Assert.True(service.TryValidate(service.Create(Reset, "u", TimeSpan.FromMilliseconds(1)), Reset, out SignedTokenPayload? p));
        Assert.Equal(TestKeys.T0.AddSeconds(1), p!.ExpiresAt);
    }

    [Fact]
    public void TokenFromTheFutureIsNotYetValid()
    {
        var (issuer, issuerClock) = Create(configure: o => o.ClockSkew = TimeSpan.FromSeconds(30));
        issuerClock.Advance(TimeSpan.FromMinutes(5));
        string token = issuer.Create(Reset, "u", TimeSpan.FromMinutes(30));

        var (validator, validatorClock) = Create(configure: o => o.ClockSkew = TimeSpan.FromSeconds(30));
        Assert.Equal(SignedTokenStatus.NotYetValid, validator.Validate(token, Reset, out SignedTokenPayload? payload));
        Assert.Null(payload);

        validatorClock.Advance(TimeSpan.FromMinutes(5) - TimeSpan.FromSeconds(30));
        Assert.Equal(SignedTokenStatus.Valid, validator.Validate(token, Reset, out _));
    }

    [Fact]
    public void RotationKeepsOldTokensValid()
    {
        var (oldService, _) = Create(TestKeys.Ring("k1", "k1"));
        string oldToken = oldService.Create(Reset, "u", TimeSpan.FromHours(1));

        var (rotated, _) = Create(TestKeys.Ring("k2", "k1", "k2"));
        Assert.Equal("k2", rotated.CurrentKeyId);
        Assert.Equal(SignedTokenStatus.Valid, rotated.Validate(oldToken, Reset, out SignedTokenPayload? p));
        Assert.Equal("k1", p!.KeyId);

        string newToken = rotated.Create(Reset, "u", TimeSpan.FromHours(1));
        Assert.True(rotated.TryValidate(newToken, Reset, out SignedTokenPayload? q));
        Assert.Equal("k2", q!.KeyId);

        // The old-only service does not know k2; the retired-k1 service does not know k1.
        Assert.Equal(SignedTokenStatus.UnknownKey, oldService.Validate(newToken, Reset, out _));
        var (retired, _) = Create(TestKeys.Ring("k2", "k2"));
        Assert.Equal(SignedTokenStatus.UnknownKey, retired.Validate(oldToken, Reset, out _));
        Assert.Equal(SignedTokenStatus.Valid, retired.Validate(newToken, Reset, out _));
    }

    [Fact]
    public void SameKeyIdWithDifferentKeyIsInvalidSignature()
    {
        var (a, _) = Create(new HmacKeyRing("k1", TestKeys.Key("a")));
        var (b, _) = Create(new HmacKeyRing("k1", TestKeys.Key("b")));
        Assert.Equal(SignedTokenStatus.InvalidSignature, b.Validate(a.Create(Reset, "u", TimeSpan.FromHours(1)), Reset, out _));
    }

    [Fact]
    public void TagIsKeyedWithDerivedSubkeyNotTheRawRingKey()
    {
        byte[] ringKey = TestKeys.Key("k1");
        var (service, _) = Create();
        string forged = TestTokens.Build(ringKey, "k1", Reset, "alice", TestKeys.T0.ToUnixTimeSeconds(),
            TestKeys.T0.AddMinutes(10).ToUnixTimeSeconds(), new byte[16], deriveSubkey: false);
        Assert.Equal(SignedTokenStatus.InvalidSignature, service.Validate(forged, Reset, out _));
    }

    [Fact]
    public void EveryByteFlipIsRejected()
    {
        var (service, _) = Create();
        byte[] original = TestKeys.FromBase64Url(service.Create(Reset, "user-42", TimeSpan.FromHours(1)));
        var seen = new HashSet<SignedTokenStatus>();
        for (int i = 0; i < original.Length; i++)
        {
            foreach (byte mask in new byte[] { 0x01, 0x80, 0xFF })
            {
                byte[] copy = (byte[])original.Clone();
                copy[i] ^= mask;
                SignedTokenStatus status = service.Validate(TestKeys.ToBase64Url(copy), Reset, out SignedTokenPayload? payload);
                Assert.NotEqual(SignedTokenStatus.Valid, status);
                Assert.Null(payload);
                seen.Add(status);
            }
        }
        Assert.Contains(SignedTokenStatus.InvalidSignature, seen);
        Assert.Contains(SignedTokenStatus.Malformed, seen);
    }

    [Fact]
    public void EveryCharacterEditIsRejected()
    {
        var (service, _) = Create();
        string token = service.Create(Reset, "user-42", TimeSpan.FromHours(1));
        for (int i = 0; i < token.Length; i++)
        {
            foreach (char c in "Aa0-_+/=. ")
            {
                if (c == token[i])
                    continue;
                char[] chars = token.ToCharArray();
                chars[i] = c;
                // Changing only the unused low bits of the last character is rejected as non-canonical (Malformed).
                Assert.NotEqual(SignedTokenStatus.Valid, service.Validate(new string(chars), Reset, out _));
            }
        }
    }

    [Fact]
    public void TruncationAndExtensionAreRejected()
    {
        var (service, _) = Create();
        string token = service.Create(Reset, "user-42", TimeSpan.FromHours(1));
        for (int n = 0; n < token.Length; n++)
            Assert.NotEqual(SignedTokenStatus.Valid, service.Validate(token.Substring(0, n), Reset, out _));
        Assert.NotEqual(SignedTokenStatus.Valid, service.Validate(token + "A", Reset, out _));
        Assert.NotEqual(SignedTokenStatus.Valid, service.Validate(token + "AAAA", Reset, out _));
        Assert.NotEqual(SignedTokenStatus.Valid, service.Validate(token + "=", Reset, out _));
        Assert.NotEqual(SignedTokenStatus.Valid, service.Validate(" " + token, Reset, out _));
    }

    [Fact]
    public void SubjectCannotBeSwappedBetweenTokens()
    {
        var (service, _) = Create();
        byte[] alice = TestKeys.FromBase64Url(service.Create(Reset, "alice", TimeSpan.FromHours(1)));
        byte[] mallory = TestKeys.FromBase64Url(service.Create(Reset, "malry", TimeSpan.FromHours(1)));
        // Splice mallory's header onto alice's subject + tag (same lengths).
        byte[] spliced = mallory.Take(70).Concat(alice.Skip(70)).ToArray();
        Assert.Equal(SignedTokenStatus.InvalidSignature, service.Validate(TestKeys.ToBase64Url(spliced), Reset, out _));
    }

    public static TheoryData<string?> MalformedTokens() => new TheoryData<string?>
    {
        null,
        "",
        " ",
        "!!!!",
        "AAAA",
        "A",
        "AB",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl",
        "AQJrMQ==",
        new string('A', 2000),
        new string('-', 300),
        "𐀀",
        "a\0b",
    };

    [Theory]
    [MemberData(nameof(MalformedTokens))]
    public void MalformedTokensNeverThrow(string? token)
    {
        var (service, _) = Create();
        SignedTokenStatus status = service.Validate(token, Reset, out SignedTokenPayload? payload);
        Assert.NotEqual(SignedTokenStatus.Valid, status);
        Assert.Null(payload);
    }

    [Fact]
    public void RandomGarbageNeverThrows()
    {
        var (service, _) = Create();
        var rng = new Random(42);
        for (int i = 0; i < 5000; i++)
        {
            byte[] bytes = new byte[rng.Next(0, 300)];
            rng.NextBytes(bytes);
            if (bytes.Length > 1 && rng.Next(2) == 0)
            {
                bytes[0] = 1;
                bytes[1] = (byte)rng.Next(0, 40);
            }
            Assert.NotEqual(SignedTokenStatus.Valid, service.Validate(TestKeys.ToBase64Url(bytes), Reset, out _));
        }
    }

    [Fact]
    public void AuthenticatedButInconsistentFieldsAreMalformed()
    {
        byte[] key = TestKeys.Key("k1");
        var (service, _) = Create();
        long now = TestKeys.T0.ToUnixTimeSeconds();

        Assert.Equal(SignedTokenStatus.Malformed,
            service.Validate(TestTokens.Build(key, "k1", Reset, "u", now, now, new byte[16]), Reset, out _));
        Assert.Equal(SignedTokenStatus.Malformed,
            service.Validate(TestTokens.Build(key, "k1", Reset, "u", now, now - 10, new byte[16]), Reset, out _));
        Assert.Equal(SignedTokenStatus.Malformed,
            service.Validate(TestTokens.Build(key, "k1", Reset, "u", -5, now, new byte[16]), Reset, out _));
        Assert.Equal(SignedTokenStatus.Malformed,
            service.Validate(TestTokens.Build(key, "k1", Reset, "u", now, long.MaxValue, new byte[16]), Reset, out _));
        Assert.Equal(SignedTokenStatus.Malformed,
            service.Validate(TestTokens.Build(key, "k1", Reset, "u", now, now + 60, new byte[16], version: 2), Reset, out _));
        Assert.Equal(SignedTokenStatus.Malformed,
            service.Validate(TestTokens.Build(key, "k1", Reset, null, now, now + 60, new byte[16], rawSubject: new byte[] { 0xC3, 0x28 }), Reset, out _));
        Assert.Equal(SignedTokenStatus.Malformed,
            service.Validate(TestTokens.Build(key, "k1", Reset, null, now, now + 60, new byte[16], rawSubject: Array.Empty<byte>()), Reset, out _));
    }

    [Fact]
    public void MaxTokenLengthIsEnforced()
    {
        var (service, _) = Create(configure: o =>
        {
            o.MaxTokenLength = 256;
            o.MaxSubjectBytes = 4096;
        });
        Assert.Throws<ArgumentException>(() => service.Create(Reset, new string('a', 200), TimeSpan.FromMinutes(1)));
        string ok = service.Create(Reset, new string('a', 50), TimeSpan.FromMinutes(1));
        Assert.True(ok.Length <= 256);

        var (big, _) = Create(configure: o => o.MaxSubjectBytes = 4096);
        string longToken = big.Create(Reset, new string('a', 500), TimeSpan.FromMinutes(1));
        Assert.True(longToken.Length > 256);
        Assert.Equal(SignedTokenStatus.Malformed, service.Validate(longToken, Reset, out _));
        Assert.Equal(SignedTokenStatus.Valid, big.Validate(longToken, Reset, out _));
    }

    [Fact]
    public void SubjectSizeIsEnforcedOnBothSides()
    {
        var (small, _) = Create(configure: o => o.MaxSubjectBytes = 8);
        Assert.Throws<ArgumentException>(() => small.Create(Reset, "123456789", TimeSpan.FromMinutes(1)));
        Assert.Throws<ArgumentException>(() => small.Create(Reset, "ééééé", TimeSpan.FromMinutes(1))); // 10 UTF-8 bytes

        var (large, _) = Create();
        string token = large.Create(Reset, "123456789", TimeSpan.FromMinutes(1));
        Assert.Equal(SignedTokenStatus.Malformed, small.Validate(token, Reset, out _));
    }

    [Fact]
    public void CreateValidatesArguments()
    {
        var (service, _) = Create();
        Assert.Throws<ArgumentNullException>(() => service.Create(null!, "u", TimeSpan.FromMinutes(1)));
        Assert.Throws<ArgumentNullException>(() => service.Create(Reset, null!, TimeSpan.FromMinutes(1)));
        Assert.Throws<ArgumentException>(() => service.Create("", "u", TimeSpan.FromMinutes(1)));
        Assert.Throws<ArgumentException>(() => service.Create(new string('p', SignedTokenService.MaxPurposeLength + 1), "u", TimeSpan.FromMinutes(1)));
        Assert.Throws<ArgumentException>(() => service.Create(Reset, "", TimeSpan.FromMinutes(1)));
        Assert.Throws<ArgumentException>(() => service.Create(Reset, "\uD800", TimeSpan.FromMinutes(1)));
        Assert.Throws<ArgumentOutOfRangeException>(() => service.Create(Reset, "u", TimeSpan.Zero));
        Assert.Throws<ArgumentOutOfRangeException>(() => service.Create(Reset, "u", TimeSpan.FromSeconds(-1)));
        Assert.Throws<ArgumentOutOfRangeException>(() => service.Create(Reset, "u", TimeSpan.FromDays(31)));
        Assert.Throws<ArgumentNullException>(() => service.Validate("x", null!, out _));
        Assert.Throws<ArgumentException>(() => service.Validate("x", "", out _));
    }

    [Fact]
    public void OptionsAreValidated()
    {
        HmacKeyRing ring = TestKeys.Ring("k1", "k1");
        Assert.Throws<ArgumentNullException>(() => new SignedTokenService(null!));
        Assert.Throws<ArgumentNullException>(() => new SignedTokenService(ring, null!));
        Assert.Throws<ArgumentException>(() => new SignedTokenService(ring, new SignedTokenOptions { Clock = null! }));
        Assert.Throws<ArgumentException>(() => new SignedTokenService(ring, new SignedTokenOptions { ClockSkew = TimeSpan.FromSeconds(-1) }));
        Assert.Throws<ArgumentException>(() => new SignedTokenService(ring, new SignedTokenOptions { ClockSkew = TimeSpan.FromHours(2) }));
        Assert.Throws<ArgumentException>(() => new SignedTokenService(ring, new SignedTokenOptions { MaxTokenLength = 100 }));
        Assert.Throws<ArgumentException>(() => new SignedTokenService(ring, new SignedTokenOptions { MaxTokenLength = 100_000 }));
        Assert.Throws<ArgumentException>(() => new SignedTokenService(ring, new SignedTokenOptions { MaxSubjectBytes = 0 }));
        Assert.Throws<ArgumentException>(() => new SignedTokenService(ring, new SignedTokenOptions { MaxLifetime = TimeSpan.Zero }));
    }

    [Fact]
    public void OptionsAreCopied()
    {
        var clock = new FakeClock(TestKeys.T0);
        var options = new SignedTokenOptions { Clock = clock.AsFunc(), ClockSkew = TimeSpan.Zero };
        var service = new SignedTokenService(TestKeys.Ring("k1", "k1"), options);
        string token = service.Create(Reset, "u", TimeSpan.FromSeconds(10));

        options.ClockSkew = TimeSpan.FromHours(1);
        clock.Advance(TimeSpan.FromSeconds(10));
        Assert.Equal(SignedTokenStatus.Expired, service.Validate(token, Reset, out _));
    }

    [Fact]
    public void DefaultClockIsSystemTime()
    {
        var service = new SignedTokenService(TestKeys.Ring("k1", "k1"));
        DateTimeOffset before = DateTimeOffset.UtcNow.AddSeconds(-1);
        Assert.True(service.TryValidate(service.Create(Reset, "u", TimeSpan.FromMinutes(1)), Reset, out SignedTokenPayload? p));
        Assert.InRange(p!.IssuedAt, before, DateTimeOffset.UtcNow.AddSeconds(1));
    }

    [Fact]
    public void SubjectIsReadableButNotForgeable()
    {
        // Documented property: tokens are signed, not encrypted.
        var (service, _) = Create();
        byte[] raw = TestKeys.FromBase64Url(service.Create(Reset, "alice", TimeSpan.FromHours(1)));
        Assert.Contains("alice", Encoding.ASCII.GetString(raw));
    }

    [Fact]
    public async Task ConsumeAsyncEnforcesSingleUse()
    {
        var (service, clock) = Create();
        var store = new InMemoryUsedTokenStore(clock.AsFunc());
        string token = service.Create(Reset, "u", TimeSpan.FromMinutes(15));

        SignedTokenResult first = await service.ConsumeAsync(token, Reset, store);
        Assert.True(first.IsValid);
        Assert.Equal(SignedTokenStatus.Valid, first.Status);
        Assert.Equal("u", first.Payload!.Subject);
        Assert.True(store.Contains(first.Payload.Nonce));

        SignedTokenResult second = await service.ConsumeAsync(token, Reset, store);
        Assert.False(second.IsValid);
        Assert.Equal(SignedTokenStatus.AlreadyUsed, second.Status);

        // A different token for the same subject is still usable.
        Assert.True((await service.ConsumeAsync(service.Create(Reset, "u", TimeSpan.FromMinutes(15)), Reset, store)).IsValid);
        Assert.Equal(2, store.Count);
    }

    [Fact]
    public async Task ConsumeAsyncDoesNotRecordInvalidTokens()
    {
        var (service, clock) = Create();
        var store = new InMemoryUsedTokenStore(clock.AsFunc());
        string token = service.Create("email-confirm", "u", TimeSpan.FromMinutes(1));

        Assert.Equal(SignedTokenStatus.WrongPurpose, (await service.ConsumeAsync(token, Reset, store)).Status);
        Assert.Equal(SignedTokenStatus.Malformed, (await service.ConsumeAsync("garbage", Reset, store)).Status);
        clock.Advance(TimeSpan.FromHours(1));
        SignedTokenResult expired = await service.ConsumeAsync(token, "email-confirm", store);
        Assert.Equal(SignedTokenStatus.Expired, expired.Status);
        Assert.False(expired.IsValid);
        Assert.Equal(0, store.Count);
        await Assert.ThrowsAsync<ArgumentNullException>(async () => await service.ConsumeAsync(token, Reset, null!));
    }

    [Fact]
    public async Task ConsumeAsyncRetainsNonceUntilExpiryPlusTwiceSkewPlusMargin()
    {
        var (service, _) = Create(configure: o => o.ClockSkew = TimeSpan.FromSeconds(30));
        var store = new RecordingStore();
        string token = service.Create(Reset, "u", TimeSpan.FromMinutes(10));

        await service.ConsumeAsync(token, Reset, store);

        Assert.Equal(TestKeys.T0.AddMinutes(10).AddSeconds(60).AddMinutes(1), store.LastRetainUntil);
    }

    // Regression: a server whose clock lags by up to the skew accepts the token until expiry + skew on its own
    // clock, i.e. about expiry + 2 * skew in true time. The nonce must still be retained then.
    [Fact]
    public async Task NonceOutlivesAcceptanceOnALaggingServer()
    {
        TimeSpan skew = TimeSpan.FromSeconds(30);
        var (a, _) = Create(configure: o => o.ClockSkew = skew);
        var (b, clockB) = Create(configure: o => o.ClockSkew = skew);
        var store = new RecordingStore();
        string token = a.Create(Reset, "u", TimeSpan.FromMinutes(10));
        DateTimeOffset expires = TestKeys.T0.AddMinutes(10);

        Assert.True((await a.ConsumeAsync(token, Reset, store)).IsValid);

        // Server B lags true time by just under the skew. Find the last true instant at which B accepts the token.
        TimeSpan lag = skew - TimeSpan.FromSeconds(1);
        DateTimeOffset lastAccepted = expires;
        for (DateTimeOffset t = expires; t < expires + skew + skew + TimeSpan.FromSeconds(5); t = t.AddSeconds(1))
        {
            clockB.Now = t - lag;
            if (b.Validate(token, Reset, out _) == SignedTokenStatus.Valid)
                lastAccepted = t;
        }
        Assert.True(lastAccepted > expires + skew);
        Assert.True(store.LastRetainUntil > lastAccepted);
    }

    [Fact]
    public async Task RetainUntilDoesNotOverflowNearMaxDate()
    {
        var clock = new FakeClock(new DateTimeOffset(9999, 12, 31, 23, 0, 0, TimeSpan.Zero));
        var service = new SignedTokenService(TestKeys.Ring("k1", "k1"),
            new SignedTokenOptions { Clock = clock.AsFunc(), ClockSkew = TimeSpan.FromHours(1) });
        var store = new RecordingStore();
        string token = service.Create(Reset, "u", TimeSpan.FromMinutes(30));

        Assert.True((await service.ConsumeAsync(token, Reset, store)).IsValid);
        Assert.Equal(DateTimeOffset.MaxValue, store.LastRetainUntil);
    }

    [Fact]
    public async Task ConcurrentRedemptionSucceedsExactlyOnce()
    {
        var (service, clock) = Create();
        var store = new InMemoryUsedTokenStore(clock.AsFunc());
        string token = service.Create(Reset, "u", TimeSpan.FromMinutes(15));

        SignedTokenResult[] results = await Task.WhenAll(Enumerable.Range(0, 64)
            .Select(_ => Task.Run(async () => await service.ConsumeAsync(token, Reset, store))));

        Assert.Equal(1, results.Count(r => r.IsValid));
        Assert.Equal(63, results.Count(r => r.Status == SignedTokenStatus.AlreadyUsed));
    }

    private sealed class RecordingStore : IUsedTokenStore
    {
        public DateTimeOffset LastRetainUntil { get; private set; }

        public ValueTask<bool> TryMarkUsedAsync(string nonce, DateTimeOffset retainUntil, System.Threading.CancellationToken cancellationToken = default)
        {
            LastRetainUntil = retainUntil;
            return new ValueTask<bool>(true);
        }
    }
}

internal static class TestTokens
{
    public static string Build(byte[] ringKey, string keyId, string purpose, string? subject, long issued, long expires,
        byte[] nonce, byte version = 1, bool deriveSubkey = true, byte[]? rawSubject = null)
    {
        byte[] macKey = deriveSubkey
            ? HMACSHA256.HashData(ringKey, TestKeys.SubkeyInfo("Masterly.Hash.Tokens/SignedToken/v1"))
            : ringKey;
        return BuildWithMacKey(macKey, keyId, purpose, subject, issued, expires, nonce, version, rawSubject);
    }

    public static string BuildWithMacKey(byte[] macKey, string keyId, string purpose, string? subject, long issued,
        long expires, byte[] nonce, byte version = 1, byte[]? rawSubject = null)
    {
        byte[] subjectBytes = rawSubject ?? Encoding.UTF8.GetBytes(subject!);
        var body = new List<byte> { version, (byte)keyId.Length };
        body.AddRange(Encoding.ASCII.GetBytes(keyId));
        body.AddRange(SHA256.HashData(Encoding.UTF8.GetBytes(purpose)));
        AddInt64(body, issued);
        AddInt64(body, expires);
        body.AddRange(nonce);
        body.Add((byte)(subjectBytes.Length >> 8));
        body.Add((byte)subjectBytes.Length);
        body.AddRange(subjectBytes);

        body.AddRange(HMACSHA256.HashData(macKey, body.ToArray()));
        return TestKeys.ToBase64Url(body.ToArray());
    }

    public static long ReadInt64(byte[] buffer, int offset)
    {
        long value = 0;
        for (int i = 0; i < 8; i++)
            value = (value << 8) | buffer[offset + i];
        return value;
    }

    private static void AddInt64(List<byte> buffer, long value)
    {
        for (int shift = 56; shift >= 0; shift -= 8)
            buffer.Add((byte)(value >> shift));
    }
}
