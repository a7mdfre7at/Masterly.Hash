using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Masterly.Hash.Tokens.Tests;

public class ApiKeyHasherTests
{
    // RFC 4231 section 4.7, test case 6 (key longer than the block size; the only HMAC-SHA256 vector with a
    // key of at least 32 bytes and printable data): key = 0xaa x 131,
    // data = "Test Using Larger Than Block-Size Key - Hash Key First",
    // HMAC-SHA-256 = 60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54.
    [Fact]
    public void InternalHmacMatchesRfc4231KnownAnswer()
    {
        byte[] key = Enumerable.Repeat((byte)0xAA, 131).ToArray();
        byte[] data = Encoding.ASCII.GetBytes("Test Using Larger Than Block-Size Key - Hash Key First");
        byte[] expected = Convert.FromHexString("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");

        Assert.Equal(expected, Internal.Hmac.Sha256(key, data));
        Assert.Equal(expected, HMACSHA256.HashData(key, data));
    }

    // The lookup hash is HMAC-SHA256(lookupKey, UTF-8(apiKey)) with
    // lookupKey = HMAC-SHA256(ringKey, 0xFF || "Masterly.Hash.Tokens/ApiKeyLookup/v1"). Recomputed here with the
    // BCL HMACSHA256 (pinned by the RFC 4231 vector above) using the RFC 4231 test-case-6 key and data.
    [Fact]
    public void LookupHashIsHmacSha256UnderDerivedSubkey()
    {
        byte[] ringKey = Enumerable.Repeat((byte)0xAA, 131).ToArray();
        const string apiKey = "Test Using Larger Than Block-Size Key - Hash Key First";
        var hasher = new ApiKeyHasher(new HmacKeyRing("rfc4231", ringKey));

        byte[] lookupKey = HMACSHA256.HashData(ringKey, TestKeys.SubkeyInfo("Masterly.Hash.Tokens/ApiKeyLookup/v1"));
        byte[] expected = HMACSHA256.HashData(lookupKey, Encoding.UTF8.GetBytes(apiKey));

        string hash = hasher.ComputeLookupHash(apiKey);

        Assert.Equal("rfc4231:" + Convert.ToBase64String(expected).TrimEnd('='), hash);
        Assert.True(hasher.Verify(apiKey, hash));
        // The raw ring key is never used to MAC the API key.
        byte[] raw = Convert.FromHexString("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");
        Assert.NotEqual("rfc4231:" + Convert.ToBase64String(raw).TrimEnd('='), hash);
    }

    // Regression: when lookup hashes were keyed with the raw ring key, ComputeLookupHash(tokenLabel) returned the
    // token-signing subkey, so anyone who could read a lookup hash could forge password-reset tokens.
    [Theory]
    [InlineData("Masterly.Hash.Tokens/SignedToken/v1")]
    [InlineData("\u00FFMasterly.Hash.Tokens/SignedToken/v1")]
    [InlineData("Masterly.Hash.Tokens/ApiKeyLookup/v1")]
    [InlineData("\u00FFMasterly.Hash.Tokens/ApiKeyLookup/v1")]
    public void LookupHashNeverRevealsAnySubkey(string input)
    {
        byte[] ringKey = TestKeys.Key("k1");
        var ring = new HmacKeyRing("k1", ringKey);
        var hasher = new ApiKeyHasher(ring);
        byte[] leaked = Convert.FromBase64String(hasher.ComputeLookupHash(input).Substring(3) + "=");

        byte[] tokenSubkey = HMACSHA256.HashData(ringKey, TestKeys.SubkeyInfo("Masterly.Hash.Tokens/SignedToken/v1"));
        byte[] lookupSubkey = HMACSHA256.HashData(ringKey, TestKeys.SubkeyInfo("Masterly.Hash.Tokens/ApiKeyLookup/v1"));
        Assert.NotEqual(tokenSubkey, leaked);
        Assert.NotEqual(lookupSubkey, leaked);
        Assert.NotEqual(tokenSubkey, lookupSubkey);

        // A token forged with the leaked value as the MAC key is rejected.
        var service = new SignedTokenService(ring, new SignedTokenOptions { Clock = () => TestKeys.T0 });
        string forged = TestTokens.BuildWithMacKey(leaked, "k1", "password-reset", "admin",
            TestKeys.T0.ToUnixTimeSeconds(), TestKeys.T0.AddMinutes(10).ToUnixTimeSeconds(), new byte[16]);
        Assert.Equal(SignedTokenStatus.InvalidSignature, service.Validate(forged, "password-reset", out SignedTokenPayload? payload));
        Assert.Null(payload);

        // Sanity: the forging helper itself works with the real subkey.
        string genuine = TestTokens.BuildWithMacKey(tokenSubkey, "k1", "password-reset", "admin",
            TestKeys.T0.ToUnixTimeSeconds(), TestKeys.T0.AddMinutes(10).ToUnixTimeSeconds(), new byte[16]);
        Assert.Equal(SignedTokenStatus.Valid, service.Validate(genuine, "password-reset", out _));
    }

    [Fact]
    public void LookupHashFormatIsKeyIdColonUnpaddedBase64()
    {
        var hasher = new ApiKeyHasher(TestKeys.Ring("k1", "k1"));
        string hash = hasher.ComputeLookupHash(ApiKey.Generate("mh_live"));

        Assert.StartsWith("k1:", hash);
        string b64 = hash.Substring(3);
        Assert.Equal(43, b64.Length);
        Assert.DoesNotContain("=", b64);
        Assert.Equal(32, Convert.FromBase64String(b64 + "=").Length);
    }

    [Fact]
    public void LookupHashIsDeterministicAndKeyed()
    {
        string apiKey = ApiKey.Generate("mh_live");
        var a = new ApiKeyHasher(TestKeys.Ring("k1", "k1"));
        var b = new ApiKeyHasher(TestKeys.Ring("k1", "k1"));
        var other = new ApiKeyHasher(new HmacKeyRing("k1", TestKeys.Key("different")));

        Assert.Equal(a.ComputeLookupHash(apiKey), a.ComputeLookupHash(apiKey));
        Assert.Equal(a.ComputeLookupHash(apiKey), b.ComputeLookupHash(apiKey));
        Assert.NotEqual(a.ComputeLookupHash(apiKey), other.ComputeLookupHash(apiKey));
        Assert.NotEqual(a.ComputeLookupHash(apiKey), a.ComputeLookupHash(ApiKey.Generate("mh_live")));
        Assert.False(other.Verify(apiKey, a.ComputeLookupHash(apiKey)));
    }

    [Fact]
    public void LookupHashIsNotAnUnkeyedHash()
    {
        string apiKey = ApiKey.Generate("mh_live");
        var hasher = new ApiKeyHasher(TestKeys.Ring("k1", "k1"));
        string plainSha = Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(apiKey))).TrimEnd('=');
        Assert.NotEqual("k1:" + plainSha, hasher.ComputeLookupHash(apiKey));
    }

    [Fact]
    public void VerifyAcceptsOnlyTheRightKey()
    {
        var hasher = new ApiKeyHasher(TestKeys.Ring("k1", "k1"));
        string apiKey = ApiKey.Generate("mh_live");
        string stored = hasher.ComputeLookupHash(apiKey);

        Assert.True(hasher.Verify(apiKey, stored));
        Assert.False(hasher.Verify(ApiKey.Generate("mh_live"), stored));
        Assert.False(hasher.Verify(apiKey.ToUpperInvariant(), stored));
        Assert.False(hasher.Verify(apiKey + " ", stored));
        Assert.False(hasher.Verify(apiKey.Substring(0, apiKey.Length - 1), stored));
    }

    [Fact]
    public void TamperedLookupHashDoesNotVerify()
    {
        var hasher = new ApiKeyHasher(TestKeys.Ring("k1", "k1"));
        string apiKey = ApiKey.Generate("mh_live");
        string stored = hasher.ComputeLookupHash(apiKey);
        for (int i = 3; i < stored.Length; i++)
        {
            char[] chars = stored.ToCharArray();
            chars[i] = chars[i] == 'A' ? 'B' : 'A';
            Assert.False(hasher.Verify(apiKey, new string(chars)), $"position {i}");
        }
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(":")]
    [InlineData("k1")]
    [InlineData("k1:")]
    [InlineData(":AAAA")]
    [InlineData("k1:not base64!")]
    [InlineData("k1:AAAA")]
    [InlineData("$mh$p=2026a$AAAA$BBBB")]
    [MemberData(nameof(NearMissLookupHashes))]
    public void MalformedStoredHashNeverThrows(string? stored)
    {
        var hasher = new ApiKeyHasher(TestKeys.Ring("k1", "k1"));
        Assert.False(hasher.Verify(ApiKey.Generate("mh_live"), stored));
        Assert.True(hasher.NeedsRehash(stored));
        Assert.False(ApiKeyHasher.TryGetKeyId(stored, out string keyId));
        Assert.Equal(string.Empty, keyId);
    }

    private static readonly string ZeroTag = new string('A', 43); // 32 zero bytes, canonical unpadded base64

    public static TheoryData<string> NearMissLookupHashes() => new TheoryData<string>
    {
        "k1:" + ZeroTag + "=",                       // padding
        "k1:" + ZeroTag.Substring(1) + "B",          // non-canonical trailing bits
        "k1:" + ZeroTag + "A",                       // 33 bytes
        "k1:" + ZeroTag.Substring(2),                // 31 bytes
        "k1:" + ZeroTag.Substring(1) + "-",          // base64url character
        "k_1:" + ZeroTag,                            // invalid key id
        "k1 :" + ZeroTag,
        new string('k', 33) + ":" + ZeroTag,         // key id too long
        "k1:" + ZeroTag + "\n",
        new string('A', 100_000),
    };

    [Fact]
    public void WellFormedHashUnderUnknownKeyDoesNotVerify()
    {
        var hasher = new ApiKeyHasher(TestKeys.Ring("k1", "k1"));
        Assert.False(hasher.Verify("anything", "k9:" + ZeroTag));
        Assert.True(ApiKeyHasher.TryGetKeyId("k9:" + ZeroTag, out string id));
        Assert.Equal("k9", id);
        Assert.True(hasher.NeedsRehash("k9:" + ZeroTag));
        Assert.False(hasher.NeedsRehash("k1:" + ZeroTag));
    }

    [Fact]
    public void BadApiKeyInputToVerifyNeverThrows()
    {
        var hasher = new ApiKeyHasher(TestKeys.Ring("k1", "k1"));
        string stored = hasher.ComputeLookupHash("x");

        Assert.False(hasher.Verify(null, stored));
        Assert.False(hasher.Verify("", stored));
        Assert.False(hasher.Verify(new string('a', ApiKeyHasher.MaxApiKeyLength + 1), stored));
        Assert.False(hasher.Verify("\uD800", stored)); // lone surrogate
        Assert.False(hasher.Verify(new string('a', 1_000_000), new string('k', 1_000_000)));
    }

    [Fact]
    public void ComputeValidatesInput()
    {
        var hasher = new ApiKeyHasher(TestKeys.Ring("k1", "k1"));
        Assert.Throws<ArgumentNullException>(() => hasher.ComputeLookupHash(null!));
        Assert.Throws<ArgumentException>(() => hasher.ComputeLookupHash(""));
        Assert.Throws<ArgumentException>(() => hasher.ComputeLookupHash(new string('a', ApiKeyHasher.MaxApiKeyLength + 1)));
        Assert.Throws<ArgumentException>(() => hasher.ComputeLookupHash("\uDC00abc"));
        Assert.Throws<ArgumentNullException>(() => hasher.ComputeAllLookupHashes(null!));
        Assert.Throws<ArgumentException>(() => hasher.ComputeAllLookupHashes(""));
        Assert.Throws<ArgumentNullException>(() => new ApiKeyHasher(null!));
    }

    [Fact]
    public void ExceptionMessagesDoNotContainTheKey()
    {
        var hasher = new ApiKeyHasher(TestKeys.Ring("k1", "k1"));
        string secret = "mh_live_SECRET" + new string('x', ApiKeyHasher.MaxApiKeyLength);
        ArgumentException ex = Assert.Throws<ArgumentException>(() => hasher.ComputeLookupHash(secret));
        Assert.DoesNotContain("SECRET", ex.Message);
    }

    [Fact]
    public void RotationKeepsOldHashesVerifyingAndFlagsThemForRehash()
    {
        string apiKey = ApiKey.Generate("mh_live");
        var before = new ApiKeyHasher(TestKeys.Ring("k1", "k1"));
        string stored = before.ComputeLookupHash(apiKey);
        Assert.False(before.NeedsRehash(stored));

        var after = new ApiKeyHasher(TestKeys.Ring("k2", "k1", "k2"));
        Assert.True(after.Verify(apiKey, stored));
        Assert.True(after.NeedsRehash(stored));

        string rehashed = after.ComputeLookupHash(apiKey);
        Assert.StartsWith("k2:", rehashed);
        Assert.False(after.NeedsRehash(rehashed));
        Assert.True(after.Verify(apiKey, rehashed));
        Assert.True(ApiKeyHasher.TryGetKeyId(rehashed, out string keyId));
        Assert.Equal("k2", keyId);

        // Once k1 is retired, its hashes stop verifying.
        var retired = new ApiKeyHasher(TestKeys.Ring("k2", "k2"));
        Assert.False(retired.Verify(apiKey, stored));
        Assert.True(retired.Verify(apiKey, rehashed));
    }

    [Fact]
    public void ComputeAllLookupHashesCoversEveryKeyCurrentFirst()
    {
        string apiKey = ApiKey.Generate("mh_live");
        var ring = TestKeys.Ring("k2", "k1", "k2", "k3");
        var hasher = new ApiKeyHasher(ring);

        IReadOnlyList<string> all = hasher.ComputeAllLookupHashes(apiKey);

        Assert.Equal(3, all.Count);
        Assert.Equal(hasher.ComputeLookupHash(apiKey), all[0]);
        Assert.Equal(new[] { "k1", "k2", "k3" }, all.Select(h => h.Split(':')[0]).OrderBy(x => x, StringComparer.Ordinal));
        Assert.All(all, h => Assert.True(hasher.Verify(apiKey, h)));

        // A hash stored under any single key in the ring is one of the candidates.
        foreach (string id in new[] { "k1", "k2", "k3" })
        {
            string storedUnderId = new ApiKeyHasher(new HmacKeyRing(id, TestKeys.Key(id))).ComputeLookupHash(apiKey);
            Assert.Contains(storedUnderId, all);
        }
    }

    [Fact]
    public void SameKeyIdWithDifferentKeyMaterialDoesNotVerify()
    {
        string apiKey = ApiKey.Generate("mh_live");
        string stored = new ApiKeyHasher(new HmacKeyRing("k1", TestKeys.Key("a"))).ComputeLookupHash(apiKey);
        Assert.False(new ApiKeyHasher(new HmacKeyRing("k1", TestKeys.Key("b"))).Verify(apiKey, stored));
    }

    [Fact]
    public void HasherIsThreadSafe()
    {
        var hasher = new ApiKeyHasher(TestKeys.Ring("k1", "k1"));
        string[] keys = Enumerable.Range(0, 64).Select(_ => ApiKey.Generate("mh")).ToArray();
        string[] expected = keys.Select(hasher.ComputeLookupHash).ToArray();
        System.Threading.Tasks.Parallel.For(0, 2000, i =>
        {
            int k = i % keys.Length;
            Assert.Equal(expected[k], hasher.ComputeLookupHash(keys[k]));
            Assert.True(hasher.Verify(keys[k], expected[k]));
        });
    }
}
