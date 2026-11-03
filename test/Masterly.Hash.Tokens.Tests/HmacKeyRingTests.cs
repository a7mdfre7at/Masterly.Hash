using System;
using System.Collections.Generic;

namespace Masterly.Hash.Tokens.Tests;

public class HmacKeyRingTests
{
    [Fact]
    public void ExposesCurrentKeyAndSortedIds()
    {
        HmacKeyRing ring = TestKeys.Ring("b", "c", "a", "b");
        Assert.Equal("b", ring.CurrentKeyId);
        Assert.Equal(new[] { "a", "b", "c" }, ring.KeyIds);
        Assert.True(ring.Contains("a"));
        Assert.False(ring.Contains("A"));
        Assert.False(ring.Contains(null));
    }

    [Fact]
    public void CopiesKeyMaterial()
    {
        byte[] key = TestKeys.Key("x");
        string apiKey = ApiKey.Generate("mh");
        var ring = new HmacKeyRing("x", key);
        string before = new ApiKeyHasher(ring).ComputeLookupHash(apiKey);

        Array.Clear(key, 0, key.Length);

        Assert.Equal(before, new ApiKeyHasher(ring).ComputeLookupHash(apiKey));
    }

    [Fact]
    public void RejectsShortKeys()
    {
        Assert.Throws<ArgumentException>(() => new HmacKeyRing("k", new byte[HmacKeyRing.MinKeyLength - 1]));
        Assert.Throws<ArgumentException>(() => new HmacKeyRing("k", Array.Empty<byte>()));
        _ = new HmacKeyRing("k", new byte[HmacKeyRing.MinKeyLength]);
    }

    [Theory]
    [InlineData("")]
    [InlineData("k:1")]
    [InlineData("k_1")]
    [InlineData("k 1")]
    [InlineData("ké")]
    [InlineData("abcdefghijabcdefghijabcdefghijabc")]
    public void RejectsInvalidKeyIds(string keyId)
    {
        Assert.False(HmacKeyRing.IsValidKeyId(keyId));
        Assert.Throws<ArgumentException>(() => new HmacKeyRing(keyId, TestKeys.Key("x")));
    }

    [Theory]
    [InlineData("k1")]
    [InlineData("2026-11")]
    [InlineData("A")]
    [InlineData("abcdefghijabcdefghijabcdefghijab")]
    public void AcceptsValidKeyIds(string keyId) => Assert.True(HmacKeyRing.IsValidKeyId(keyId));

    [Fact]
    public void ValidatesArguments()
    {
        var keys = new Dictionary<string, byte[]> { ["k1"] = TestKeys.Key("k1") };
        Assert.Throws<ArgumentNullException>(() => new HmacKeyRing(null!, keys));
        Assert.Throws<ArgumentNullException>(() => new HmacKeyRing("k1", (IReadOnlyDictionary<string, byte[]>)null!));
        Assert.Throws<ArgumentNullException>(() => new HmacKeyRing(null!, TestKeys.Key("k1")));
        Assert.Throws<ArgumentNullException>(() => new HmacKeyRing("k1", (byte[])null!));
        Assert.Throws<ArgumentException>(() => new HmacKeyRing("k2", keys));
        Assert.Throws<ArgumentException>(() => new HmacKeyRing("k1", new Dictionary<string, byte[]> { ["k1"] = null! }));
        Assert.Throws<ArgumentException>(() =>
            new HmacKeyRing("k1", new Dictionary<string, byte[]> { ["k1"] = TestKeys.Key("k1"), ["bad id"] = TestKeys.Key("x") }));
    }

    [Fact]
    public void ErrorMessagesNeverContainKeyMaterial()
    {
        var keys = new Dictionary<string, string> { ["k1"] = Convert.ToBase64String(new byte[] { 0xDE, 0xAD, 0xBE, 0xEF }) };
        ArgumentException ex = Assert.Throws<ArgumentException>(() => HmacKeyRing.FromBase64("k1", keys));
        Assert.DoesNotContain("3q2+7w", ex.Message);
    }

    [Fact]
    public void FromBase64BuildsEquivalentRing()
    {
        byte[] k1 = TestKeys.Key("k1");
        byte[] k2 = TestKeys.Key("k2");
        HmacKeyRing ring = HmacKeyRing.FromBase64("k2", new Dictionary<string, string>
        {
            ["k1"] = Convert.ToBase64String(k1),
            ["k2"] = Convert.ToBase64String(k2),
        });

        string apiKey = ApiKey.Generate("mh");
        Assert.Equal(new ApiKeyHasher(TestKeys.Ring("k2", "k1", "k2")).ComputeLookupHash(apiKey),
            new ApiKeyHasher(ring).ComputeLookupHash(apiKey));
        Assert.Equal(new[] { "k1", "k2" }, ring.KeyIds);
    }

    [Fact]
    public void FromBase64RejectsBadInput()
    {
        Assert.Throws<ArgumentNullException>(() => HmacKeyRing.FromBase64("k1", null!));
        Assert.Throws<FormatException>(() => HmacKeyRing.FromBase64("k1", new Dictionary<string, string> { ["k1"] = "not base64!" }));
        Assert.Throws<ArgumentException>(() => HmacKeyRing.FromBase64("k1", new Dictionary<string, string> { ["k1"] = null! }));
    }

    [Fact]
    public void GenerateKeyIsRandomAndLongEnough()
    {
        byte[] a = HmacKeyRing.GenerateKey();
        byte[] b = HmacKeyRing.GenerateKey();
        Assert.Equal(HmacKeyRing.MinKeyLength, a.Length);
        Assert.NotEqual(a, b);
        _ = new HmacKeyRing("k", a);
    }
}
