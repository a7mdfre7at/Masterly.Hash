using System;
using System.Text;
using Masterly.Hash.Tokens.Internal;

namespace Masterly.Hash.Tokens.Tests;

/// <summary>Edge paths not reached by the scenario tests.</summary>
public class CoverageGapTests
{
    [Fact]
    public void TryParse_rejects_a_random_part_above_the_maximum_entropy_even_with_a_valid_checksum()
    {
        // 88 base62 digits decode to 65 bytes: one more than MaxEntropyBytes, but still within MaxLength.
        string random = new string('0', Base62.GetEncodedLength(ApiKey.MaxEntropyBytes + 1));
        string body = "k_" + random;
        string key = body + Base62.EncodeUInt32(Crc32.Compute(Encoding.ASCII.GetBytes(body)));
        Assert.True(key.Length <= ApiKey.MaxLength);
        Assert.True(Base62.TryDecode(random, out byte[] decoded));
        Assert.Equal(ApiKey.MaxEntropyBytes + 1, decoded.Length);

        Assert.False(ApiKey.TryParse(key, out ApiKeyParts? parts));
        Assert.Null(parts);
        Assert.False(ApiKey.HasValidChecksum(key));
    }

    [Fact]
    public void ApiKeyHasher_exposes_its_key_ring()
    {
        HmacKeyRing ring = TestKeys.Ring("k1", "k1");
        var hasher = new ApiKeyHasher(ring);
        Assert.Same(ring, hasher.KeyRing);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void Base64Url_rejects_null_and_empty(string? value)
    {
        Assert.False(Base64Url.TryDecode(value, out byte[] bytes));
        Assert.Empty(bytes);
    }

    [Fact]
    public void Base64Url_rejects_the_standard_alphabet_and_round_trips_url_safe_text()
    {
        byte[] data = { 0xFB, 0xFF, 0xBF };
        string encoded = Base64Url.Encode(data);
        Assert.Equal("-_-_", encoded);
        Assert.True(Base64Url.TryDecode(encoded, out byte[] decoded));
        Assert.Equal(data, decoded);
        Assert.False(Base64Url.TryDecode("+/+/", out _));
    }

    [Fact]
    public void Create_rejects_a_clock_before_the_unix_epoch()
    {
        var service = new SignedTokenService(TestKeys.Ring("k1", "k1"),
            new SignedTokenOptions { Clock = () => new DateTimeOffset(1969, 12, 31, 23, 59, 59, TimeSpan.Zero) });

        var ex = Assert.Throws<InvalidOperationException>(() => service.Create("reset", "user", TimeSpan.FromMinutes(5)));
        Assert.Equal("The clock is outside the supported range.", ex.Message);
    }

    [Fact]
    public void Create_rejects_an_expiry_past_the_year_9999()
    {
        var service = new SignedTokenService(TestKeys.Ring("k1", "k1"),
            new SignedTokenOptions { Clock = () => new DateTimeOffset(9999, 12, 31, 23, 59, 0, TimeSpan.Zero) });

        var ex = Assert.Throws<InvalidOperationException>(() => service.Create("reset", "user", TimeSpan.FromMinutes(5)));
        Assert.Equal("The clock is outside the supported range.", ex.Message);

        // A lifetime that still ends inside the range is accepted.
        Assert.NotNull(service.Create("reset", "user", TimeSpan.FromSeconds(59)));
    }

    [Fact]
    public void Crc32_rejects_null_data()
    {
        Assert.Equal("data", Assert.Throws<ArgumentNullException>(() => Crc32.Compute((byte[])null!)).ParamName);
        Assert.Equal("data", Assert.Throws<ArgumentNullException>(() => Crc32.Compute(null!, 0, 0)).ParamName);
    }

    [Fact]
    public void GeneratedApiKey_rejects_null_parts()
    {
        Assert.Equal("plainText", Assert.Throws<ArgumentNullException>(() => new GeneratedApiKey(null!, "p", "h")).ParamName);
        Assert.Equal("prefix", Assert.Throws<ArgumentNullException>(() => new GeneratedApiKey("k", null!, "h")).ParamName);
        Assert.Equal("lookupHash", Assert.Throws<ArgumentNullException>(() => new GeneratedApiKey("k", "p", null!)).ParamName);
    }
}
