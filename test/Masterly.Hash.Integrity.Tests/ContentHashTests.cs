using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using static Masterly.Hash.Integrity.Tests.TestUtil;

namespace Masterly.Hash.Integrity.Tests;

public class ContentHashTests
{
    // FIPS 180-2 Appendix B/C/D: one-block message "abc".
    private const string Sha256Abc = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    private const string Sha384Abc = "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7";
    private const string Sha512Abc = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";
    private const string Sha256Empty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    [Fact]
    public void KnownAnswers_Fips180()
    {
        Assert.Equal("sha256:" + Sha256Abc, ContentHasher.Compute(Utf8("abc")).ToString());
        Assert.Equal("sha384:" + Sha384Abc, ContentHasher.Compute(Utf8("abc"), ContentHashAlgorithm.Sha384).ToString());
        Assert.Equal("sha512:" + Sha512Abc, ContentHasher.Compute(Utf8("abc"), ContentHashAlgorithm.Sha512).ToString());
        Assert.Equal("sha256:" + Sha256Empty, ContentHasher.Compute(Array.Empty<byte>()).ToString());
    }

    [Fact]
    public void KnownAnswer_Rfc4231_TestCase6()
    {
        // RFC 4231 §4.7: 131-byte key of 0xaa, "Test Using Larger Than Block-Size Key - Hash Key First".
        byte[] key = Enumerable.Repeat((byte)0xaa, 131).ToArray();
        var mac = ContentHashAlgorithm.HmacSha256("rfc4231", key);
        ContentHash tag = ContentHasher.Compute(Utf8("Test Using Larger Than Block-Size Key - Hash Key First"), mac);
        Assert.Equal("hmac-sha256:rfc4231:60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54", tag.ToString());
        Assert.True(tag.IsKeyed);
        Assert.Equal("rfc4231", tag.KeyId);
    }

    [Fact]
    public void ParseRoundTrips()
    {
        foreach (ContentHashAlgorithm algorithm in new[] { ContentHashAlgorithm.Sha256, ContentHashAlgorithm.Sha384, ContentHashAlgorithm.Sha512, Hmac("k1") })
        {
            ContentHash hash = ContentHasher.Compute(Utf8("payload"), algorithm);
            ContentHash parsed = ContentHash.Parse(hash.ToString());
            Assert.Equal(hash, parsed);
            Assert.Equal(hash.ToString(), parsed.ToString());
            Assert.Equal(hash.GetHashCode(), parsed.GetHashCode());
            Assert.True(parsed.IsFrom(algorithm));
            Assert.Equal(algorithm.DigestLength, parsed.Digest.Length);
        }
    }

    [Theory]
    [InlineData("")]
    [InlineData(":")]
    [InlineData("sha256")]
    [InlineData("sha256:")]
    [InlineData("SHA256:" + Sha256Abc)]
    [InlineData("sha256:" + "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD")]
    [InlineData("sha256:" + Sha256Abc + "00")]
    [InlineData("sha256:" + "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015a")]
    [InlineData("sha256: " + Sha256Abc)]
    [InlineData(" sha256:" + Sha256Abc)]
    [InlineData("sha256:" + Sha256Abc + " ")]
    [InlineData("sha256:" + Sha256Abc + "\n")]
    [InlineData("sha256:k1:" + Sha256Abc)]
    [InlineData("md5:d41d8cd98f00b204e9800998ecf8427e")]
    [InlineData("sha384:" + Sha256Abc)]
    [InlineData("hmac-sha256:" + Sha256Abc)]
    [InlineData("hmac-sha256::" + Sha256Abc)]
    [InlineData("hmac-sha256:bad_id:" + Sha256Abc)]
    [InlineData("hmac-sha256:k1:k2:" + Sha256Abc)]
    [InlineData("-sha256:" + Sha256Abc)]
    [InlineData("sha256:zz7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")]
    public void TryParse_RejectsNonCanonical(string value)
    {
        Assert.False(ContentHash.TryParse(value, out ContentHash? result));
        Assert.Null(result);
        Assert.Throws<FormatException>(() => ContentHash.Parse(value));
    }

    [Fact]
    public void TryParse_NullAndHugeInputs_DoNotThrow()
    {
        Assert.False(ContentHash.TryParse(null, out _));
        Assert.Throws<ArgumentNullException>(() => ContentHash.Parse(null!));
        Assert.False(ContentHash.TryParse("sha256:" + new string('a', 1_000_000), out _));
        Assert.False(ContentHash.TryParse(new string(':', 10_000), out _));
    }

    [Fact]
    public void TryParse_RandomGarbage_NeverThrows()
    {
        var random = new Random(1234);
        const string alphabet = "sha256:-0123456789abcdefABCDEFhmc\0é ";
        for (int i = 0; i < 5000; i++)
        {
            char[] chars = new char[random.Next(0, 140)];
            for (int j = 0; j < chars.Length; j++)
                chars[j] = alphabet[random.Next(alphabet.Length)];
            ContentHash.TryParse(new string(chars), out _);
        }
    }

    [Fact]
    public void Equality_ComparesAlgorithmKeyIdAndDigest()
    {
        ContentHash a = ContentHasher.Compute(Utf8("x"));
        Assert.Equal(a, ContentHasher.Compute(Utf8("x")));
        Assert.NotEqual(a, ContentHasher.Compute(Utf8("y")));
        Assert.NotEqual(ContentHasher.Compute(Utf8("x"), Hmac("k1")), ContentHasher.Compute(Utf8("x"), Hmac("k2")));
        Assert.NotEqual(ContentHasher.Compute(Utf8("x"), Hmac("k1", "a")), ContentHasher.Compute(Utf8("x"), Hmac("k1", "b")));
        Assert.False(a.Equals(null));
        Assert.False(a.Equals("sha256"));
    }

    [Fact]
    public void Constructor_ValidatesAndCopies()
    {
        byte[] digest = new byte[32];
        var hash = new ContentHash(ContentHashAlgorithm.Sha256, digest);
        digest[0] = 1;
        Assert.Equal(0, hash.Digest.Span[0]);
        byte[] copy = hash.ToArray();
        copy[1] = 1;
        Assert.Equal(0, hash.Digest.Span[1]);
        Assert.Throws<ArgumentException>(() => new ContentHash(ContentHashAlgorithm.Sha256, new byte[31]));
        Assert.Throws<ArgumentNullException>(() => new ContentHash(null!, digest));
        Assert.Throws<ArgumentNullException>(() => new ContentHash(ContentHashAlgorithm.Sha256, null!));
    }

    [Fact]
    public void Json_RoundTripsAsString_AndRejectsInvalid()
    {
        ContentHash hash = ContentHasher.Compute(Utf8("abc"));
        string json = JsonSerializer.Serialize(hash);
        Assert.Equal("\"sha256:" + Sha256Abc + "\"", json);
        Assert.Equal(hash, JsonSerializer.Deserialize<ContentHash>(json));
        Assert.Null(JsonSerializer.Deserialize<ContentHash>("null"));
        Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<ContentHash>("\"sha256:00\""));
        Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<ContentHash>("42"));
        // Escaped lone surrogates must surface as JsonException, not InvalidOperationException.
        foreach (string bad in new[] { "\"\\udc00\"", "\"\\ud800\"", "\"sha256:\\ud800A\"" })
            Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<ContentHash>(bad));
    }

    [Fact]
    public void Hmac_RequiresLongKeyAndValidId_AndNeverPrintsKey()
    {
        Assert.Throws<ArgumentException>(() => ContentHashAlgorithm.HmacSha256("k1", new byte[31]));
        Assert.Throws<ArgumentException>(() => ContentHashAlgorithm.HmacSha256("bad id", new byte[32]));
        Assert.Throws<ArgumentException>(() => ContentHashAlgorithm.HmacSha256(new string('a', 33), new byte[32]));
        Assert.Throws<ArgumentNullException>(() => ContentHashAlgorithm.HmacSha256("k1", null!));

        byte[] key = Key("print");
        var mac = ContentHashAlgorithm.HmacSha256("k1", key);
        Assert.Equal("hmac-sha256:k1", mac.ToString());
        Assert.DoesNotContain(ToHex(key), mac.ToString());

        // The key is copied: changing the caller's array later does not change the MAC.
        ContentHash before = ContentHasher.Compute(Utf8("d"), mac);
        key[0] ^= 0xff;
        Assert.Equal(before, ContentHasher.Compute(Utf8("d"), mac));
    }

    [Fact]
    public void Registry_ResolvesUnkeyedOnly()
    {
        Assert.True(ContentHashAlgorithm.TryGet("sha256", out ContentHashAlgorithm? sha));
        Assert.Same(ContentHashAlgorithm.Sha256, sha);
        Assert.False(ContentHashAlgorithm.TryGet("hmac-sha256", out _));
        Assert.True(ContentHashAlgorithm.IsRegistered("hmac-sha256"));
        Assert.False(ContentHashAlgorithm.TryGet(null, out _));
        Assert.False(ContentHashAlgorithm.IsRegistered("nope"));
        ContentHashAlgorithm.Register(ContentHashAlgorithm.Sha256); // idempotent
        Assert.Throws<InvalidOperationException>(() => ContentHashAlgorithm.RegisterKeyedFamily("sha256", 32));
    }

    [Fact]
    public async Task Stream_MatchesByteArray_AcrossBufferBoundaries()
    {
        foreach (int size in new[] { 0, 1, ContentHasher.BufferSize - 1, ContentHasher.BufferSize, ContentHasher.BufferSize + 1, 3 * ContentHasher.BufferSize + 17 })
        {
            byte[] data = RandomNumberGenerator.GetBytes(size);
            ContentHash expected = new ContentHash(ContentHashAlgorithm.Sha256, SHA256.HashData(data));
            Assert.Equal(expected, ContentHasher.Compute(data));
            Assert.Equal(expected, await ContentHasher.ComputeAsync(new MemoryStream(data)));
            Assert.Equal(expected, await ContentHasher.ComputeAsync(new TrickleStream(data, 7), ContentHashAlgorithm.Sha256));
            Assert.Equal(expected, ContentHasher.Compute(new TrickleStream(data, 1000), ContentHashAlgorithm.Sha256));
        }
    }

    [Fact]
    public async Task Stream_StartsAtCurrentPositionAndIsLeftOpen()
    {
        byte[] data = Utf8("skipabc");
        var stream = new MemoryStream(data);
        stream.Position = 4;
        ContentHash hash = await ContentHasher.ComputeAsync(stream);
        Assert.Equal("sha256:" + Sha256Abc, hash.ToString());
        Assert.True(stream.CanRead);
    }

    [Fact]
    public async Task ComputeAsync_HonoursCancellation()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => ContentHasher.ComputeAsync(new MemoryStream(new byte[10]), cts.Token));
    }

    [Fact]
    public async Task Verify_TrueForMatch_FalseForAnyChange()
    {
        byte[] data = RandomNumberGenerator.GetBytes(100_000);
        ContentHash expected = ContentHasher.Compute(data, ContentHashAlgorithm.Sha512);

        Assert.True(ContentHasher.Verify(data, expected));
        Assert.True(await ContentHasher.VerifyAsync(new MemoryStream(data), expected));
        Assert.False(ContentHasher.Verify(Flip(data, 99_999), expected));
        Assert.False(await ContentHasher.VerifyAsync(new MemoryStream(data, 0, data.Length - 1), expected));
        Assert.False(await ContentHasher.VerifyAsync(new MemoryStream(Flip(data, 12345)), expected));
    }

    [Fact]
    public async Task Verify_Keyed_NeedsMatchingAlgorithm()
    {
        var mac = Hmac("k1");
        ContentHash tag = ContentHasher.Compute(Utf8("data"), mac);

        Assert.True(ContentHasher.Verify(Utf8("data"), tag, mac));
        Assert.True(await ContentHasher.VerifyAsync(new MemoryStream(Utf8("data")), tag, mac));
        // Same key id, different key (an attacker's key): rejected.
        Assert.False(ContentHasher.Verify(Utf8("data"), tag, Hmac("k1", "attacker")));
        // The stored hash is untrusted: no key, a different key id (rotation) or a different algorithm is a
        // failed verification, never an exception an attacker could use to abort a verification loop.
        Assert.False(ContentHasher.Verify(Utf8("data"), tag));
        Assert.False(ContentHasher.Verify(Utf8("data"), tag, Hmac("k2")));
        Assert.False(ContentHasher.Verify(Utf8("data"), ContentHasher.Compute(Utf8("data")), ContentHashAlgorithm.Sha512));
        Assert.False(await ContentHasher.VerifyAsync(new MemoryStream(Utf8("data")), tag));
        Assert.False(await ContentHasher.VerifyAsync(new MemoryStream(Utf8("data")), tag, Hmac("k2")));
    }

    [Fact]
    public async Task Verify_StoredHashSwappedToPlainHash_ReturnsFalse()
    {
        // Attacker with write access replaces a stored HMAC tag by a well-formed SHA-256 of tampered content.
        using var dir = new TempDirectory();
        string path = dir.Write("f.bin", Utf8("tampered"));
        var mac = Hmac("k1");
        ContentHash swapped = ContentHash.Parse(ContentHasher.Compute(Utf8("tampered")).ToString());

        Assert.False(ContentHasher.Verify(Utf8("tampered"), swapped, mac));
        Assert.False(await ContentHasher.VerifyAsync(new MemoryStream(Utf8("tampered")), swapped, mac));
        Assert.False(await ContentHasher.VerifyFileAsync(path, swapped, mac));
        // And the other way round: keyed stored value, caller without the key.
        Assert.False(await ContentHasher.VerifyFileAsync(path, ContentHasher.Compute(Utf8("tampered"), mac)));
    }

    [Fact]
    public async Task Files_ComputeAndVerify()
    {
        using var dir = new TempDirectory();
        string path = dir.Write("f.bin", Utf8("abc"));
        ContentHash hash = await ContentHasher.ComputeFileAsync(path);
        Assert.Equal("sha256:" + Sha256Abc, hash.ToString());
        Assert.True(await ContentHasher.VerifyFileAsync(path, hash));
        File.WriteAllText(path, "abd");
        Assert.False(await ContentHasher.VerifyFileAsync(path, hash));
        await Assert.ThrowsAsync<FileNotFoundException>(() => ContentHasher.ComputeFileAsync(Path.Combine(dir.Path, "missing")));
    }

    [Fact]
    public void Arguments_AreGuarded()
    {
        Assert.Throws<ArgumentNullException>(() => ContentHasher.Compute((byte[])null!));
        Assert.Throws<ArgumentNullException>(() => ContentHasher.Compute(Array.Empty<byte>(), null!));
        Assert.Throws<ArgumentNullException>(() => { _ = ContentHasher.ComputeAsync(null!); });
        Assert.Throws<ArgumentNullException>(() => { _ = ContentHasher.ComputeFileAsync(null!); });
        Assert.Throws<ArgumentNullException>(() => ContentHasher.Verify(null!, ContentHasher.Compute(Array.Empty<byte>())));
        Assert.Throws<ArgumentNullException>(() => { _ = ContentHasher.VerifyAsync(new MemoryStream(), null!); });
        var unreadable = new MemoryStream();
        unreadable.Dispose();
        Assert.Throws<ArgumentException>(() => { _ = ContentHasher.ComputeAsync(unreadable); });
    }

    [Fact]
    public void Digest_IsReusableAndGuarded()
    {
        using ContentDigest digest = ContentHashAlgorithm.Sha256.CreateDigest();
        digest.Append(Utf8("a"));
        digest.Append(Utf8("xbcx"), 1, 2);
        Assert.Equal(Sha256Abc, ToHex(digest.GetHashAndReset()));
        Assert.Equal(Sha256Empty, ToHex(digest.GetHashAndReset()));
        Assert.Throws<ArgumentOutOfRangeException>(() => digest.Append(new byte[2], 1, 2));
        Assert.Throws<ArgumentOutOfRangeException>(() => digest.Append(new byte[2], -1, 1));
        digest.Dispose();
        Assert.Throws<ObjectDisposedException>(() => digest.GetHashAndReset());
    }
}
