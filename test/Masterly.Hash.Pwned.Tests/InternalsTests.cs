using System;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Masterly.Hash.Pwned.Internal;

namespace Masterly.Hash.Pwned.Tests;

public class PwnedHashTests
{
    // Known-answer vectors:
    //  - SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8, the Pwned Passwords API documentation example
    //    (https://haveibeenpwned.com/API/v3#SearchingPwnedPasswordsByRange).
    //  - SHA-1("abc") = A9993E364706816ABA3E25717850C26C9CD0D89D, FIPS 180-2 Appendix A.1 / RFC 3174 section 7.3 test 1.
    [Theory]
    [InlineData("password", "5BAA6", "1E4C9B93F3F0682250B6CF8331B7EE68FD8")]
    [InlineData("abc", "A9993", "E364706816ABA3E25717850C26C9CD0D89D")]
    public void Known_answer_vectors(string password, string prefix, string suffix)
    {
        PwnedHash.Compute(password, out string actualPrefix, out byte[] packed);

        Assert.Equal(prefix, actualPrefix);
        byte[] expected = Pack(suffix);
        Assert.Equal(expected, packed);
    }

    [Fact]
    public void Packed_suffix_has_a_zero_trailing_nibble()
    {
        PwnedHash.Compute("password", out _, out byte[] packed);
        Assert.Equal(PwnedHash.SuffixBytes, packed.Length);
        Assert.Equal(0x80, packed[17]); // last hex digit '8' in the high nibble, low nibble zero
    }

    [Fact]
    public void Matches_bcl_sha1_over_utf8_for_many_inputs()
    {
        var rng = new Random(42);
        for (int i = 0; i < 200; i++)
        {
            var chars = new char[rng.Next(1, 40)];
            for (int j = 0; j < chars.Length; j++)
                chars[j] = (char)rng.Next(0x20, 0x3000);
            string password = new(chars);

            PwnedHash.Compute(password, out string prefix, out byte[] packed);
            Assert.Equal(Sha1Hex.Prefix(password), prefix);
            Assert.Equal(Pack(Sha1Hex.Suffix(password)), packed);
        }
    }

    [Fact]
    public void Suffix_parsing_is_case_insensitive()
    {
        byte[] upper = Pack("1E4C9B93F3F0682250B6CF8331B7EE68FD8");
        byte[] lower = Pack("1e4c9b93f3f0682250b6cf8331b7ee68fd8");
        Assert.Equal(upper, lower);
    }

    [Theory]
    [InlineData("")]
    [InlineData("1E4C9B93F3F0682250B6CF8331B7EE68FD")]
    [InlineData("1E4C9B93F3F0682250B6CF8331B7EE68FD8A")]
    [InlineData("1E4C9B93F3F0682250B6CF8331B7EE68FDG")]
    [InlineData("1E4C9B93F3F0682250B6CF8331B7EE68FD ")]
    [InlineData("-E4C9B93F3F0682250B6CF8331B7EE68FD8")]
    public void Invalid_suffixes_are_rejected(string text)
    {
        byte[] source = Encoding.ASCII.GetBytes(text);
        Assert.False(PwnedHash.TryParseSuffix(source, 0, source.Length, new byte[PwnedHash.SuffixBytes], 0));
    }

    internal static byte[] Pack(string suffix)
    {
        byte[] source = Encoding.ASCII.GetBytes(suffix);
        var packed = new byte[PwnedHash.SuffixBytes];
        Assert.True(PwnedHash.TryParseSuffix(source, 0, source.Length, packed, 0));
        return packed;
    }
}

public class RangeResponseTests
{
    private const string Suffix = "1E4C9B93F3F0682250B6CF8331B7EE68FD8";

    private static RangeResponse? Parse(string body)
    {
        byte[] bytes = Encoding.ASCII.GetBytes(body);
        return RangeResponse.TryParse(bytes, bytes.Length, out RangeResponse? r) ? r : null;
    }

    [Theory]
    [InlineData("1E4C9B93F3F0682250B6CF8331B7EE68FD8:3")]
    [InlineData("1E4C9B93F3F0682250B6CF8331B7EE68FD8:3\r\n")]
    [InlineData("1E4C9B93F3F0682250B6CF8331B7EE68FD8:3\n")]
    [InlineData("\r\n\r\n1E4C9B93F3F0682250B6CF8331B7EE68FD8:3\r\n\r\n")]
    [InlineData("  1E4C9B93F3F0682250B6CF8331B7EE68FD8:3 \t\r\n")]
    [InlineData("003D68EB55068C33ACE09247EE4C639306B:0\r\n1E4C9B93F3F0682250B6CF8331B7EE68FD8:3\r\n011053FD0102E94D6AE2F8B83D76FAF94F6:0")]
    public void Accepts_line_ending_and_whitespace_variants(string body)
    {
        RangeResponse range = Assert.IsType<RangeResponse>(Parse(body));
        Assert.Equal(1, range.Count);
        Assert.Equal(3, range.Lookup(PwnedHashTests.Pack(Suffix)));
    }

    [Fact]
    public void Drops_padding_entries()
    {
        RangeResponse range = Parse(Sha1Hex.Range(500, Suffix + ":3", "003D68EB55068C33ACE09247EE4C639306B:1"))!;
        Assert.Equal(2, range.Count);
    }

    [Fact]
    public void Lookup_of_absent_suffix_is_zero()
    {
        RangeResponse range = Parse("003D68EB55068C33ACE09247EE4C639306B:1")!;
        Assert.Equal(0, range.Lookup(PwnedHashTests.Pack(Suffix)));
        Assert.Equal(0, Parse("")!.Lookup(PwnedHashTests.Pack(Suffix)));
    }

    [Fact]
    public void Duplicate_suffixes_resolve_to_the_largest_count()
    {
        RangeResponse range = Parse(Suffix + ":3\r\n" + Suffix.ToLowerInvariant() + ":9\r\n" + Suffix + ":4")!;
        Assert.Equal(9, range.Lookup(PwnedHashTests.Pack(Suffix)));
    }

    [Fact]
    public void Accepts_18_digit_counts()
    {
        RangeResponse range = Parse(Suffix + ":999999999999999999")!;
        Assert.Equal(999_999_999_999_999_999L, range.Lookup(PwnedHashTests.Pack(Suffix)));
    }

    [Theory]
    [InlineData("1E4C9B93F3F0682250B6CF8331B7EE68FD8")]
    [InlineData(":3")]
    [InlineData("1E4C9B93F3F0682250B6CF8331B7EE68FD8:")]
    [InlineData("1E4C9B93F3F0682250B6CF8331B7EE68FD8:+3")]
    [InlineData("1E4C9B93F3F0682250B6CF8331B7EE68FD8:3.0")]
    [InlineData("1E4C9B93F3F0682250B6CF8331B7EE68FD8:3:4")]
    [InlineData("1E4C9B93F3F0682250B6CF8331B7EE68FD8:1000000000000000000")]
    [InlineData("1E4C9B93F3F0682250B6CF8331B7EE68FD8 :3")]
    [InlineData("1E4C9B93F3F0682250B6CF8331B7EE68FD8\r:3")]
    [InlineData("1E4C9B93F3F0682250B6CF8331B7EE68FD8:3\r\nnot a line")]
    [InlineData("5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8:3")]
    public void Rejects_malformed_lines(string body)
    {
        Assert.Null(Parse(body));
    }

    [Fact]
    public void Rejects_bad_arguments_without_throwing()
    {
        Assert.False(RangeResponse.TryParse(null!, 0, out _));
        Assert.False(RangeResponse.TryParse(new byte[4], 5, out _));
        Assert.False(RangeResponse.TryParse(new byte[4], -1, out _));
    }

    [Fact]
    public void Random_garbage_never_throws()
    {
        var rng = new Random(7);
        byte[] alphabet = Encoding.ASCII.GetBytes("0123456789ABCDEFabcdef:\r\n \tZ");
        for (int i = 0; i < 2000; i++)
        {
            var body = new byte[rng.Next(0, 300)];
            for (int j = 0; j < body.Length; j++)
                body[j] = i % 2 == 0 ? alphabet[rng.Next(alphabet.Length)] : (byte)rng.Next(256);
            if (RangeResponse.TryParse(body, body.Length, out RangeResponse? r))
                _ = r!.Lookup(PwnedHashTests.Pack(Suffix));
        }
    }

    [Fact]
    public void Dense_body_of_minimal_lines_fits_the_capacity_estimate()
    {
        // 35 hex + ':' + 1 digit with bare LF separators: the densest valid layout.
        string body = string.Join("\n", Enumerable.Range(0, 1000).Select(i => i.ToString("X35") + ":1"));
        RangeResponse range = Parse(body)!;
        Assert.Equal(1000, range.Count);
    }
}

public class RangeCacheTests
{
    private static RangeResponse Range(string body = "")
    {
        byte[] bytes = Encoding.ASCII.GetBytes(body);
        Assert.True(RangeResponse.TryParse(bytes, bytes.Length, out RangeResponse? r));
        return r!;
    }

    [Fact]
    public void Entries_expire_after_the_ttl()
    {
        TimeSpan now = TimeSpan.FromDays(1);
        var cache = new RangeCache(8, TimeSpan.FromSeconds(30), () => now);
        RangeResponse range = Range();
        cache.Set("5BAA6", range);

        Assert.True(cache.TryGet("5BAA6", out RangeResponse? hit));
        Assert.Same(range, hit);

        now += TimeSpan.FromSeconds(30);
        Assert.False(cache.TryGet("5BAA6", out RangeResponse? miss));
        Assert.Null(miss);
        Assert.Equal(0, cache.Count);
    }

    [Fact]
    public void Size_is_bounded_and_least_recently_used_is_evicted()
    {
        var cache = new RangeCache(3, TimeSpan.FromHours(1));
        cache.Set("00000", Range());
        cache.Set("00001", Range());
        cache.Set("00002", Range());
        Assert.True(cache.TryGet("00000", out _)); // 00000 becomes most recent

        cache.Set("00003", Range());

        Assert.Equal(3, cache.Count);
        Assert.False(cache.TryGet("00001", out _));
        Assert.True(cache.TryGet("00000", out _));
        Assert.True(cache.TryGet("00002", out _));
        Assert.True(cache.TryGet("00003", out _));
    }

    [Fact]
    public void Set_replaces_an_existing_entry()
    {
        var cache = new RangeCache(2, TimeSpan.FromHours(1));
        RangeResponse a = Range(), b = Range();
        cache.Set("5BAA6", a);
        cache.Set("5BAA6", b);
        Assert.Equal(1, cache.Count);
        Assert.True(cache.TryGet("5BAA6", out RangeResponse? hit));
        Assert.Same(b, hit);
    }

    [Fact]
    public void Clear_empties_the_cache()
    {
        var cache = new RangeCache(2, TimeSpan.FromHours(1));
        cache.Set("5BAA6", Range());
        cache.Clear();
        Assert.Equal(0, cache.Count);
        Assert.False(cache.TryGet("5BAA6", out _));
    }

    [Fact]
    public void Rejects_invalid_limits()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new RangeCache(0, TimeSpan.FromHours(1)));
        Assert.Throws<ArgumentOutOfRangeException>(() => new RangeCache(1, TimeSpan.Zero));
    }

    [Fact]
    public async Task Is_thread_safe_and_stays_bounded()
    {
        var cache = new RangeCache(16, TimeSpan.FromHours(1));
        RangeResponse range = Range();
        await Task.WhenAll(Enumerable.Range(0, 8).Select(t => Task.Run(() =>
        {
            for (int i = 0; i < 5000; i++)
            {
                string key = ((t * 7919 + i) % 64).ToString("X5");
                if (i % 3 == 0)
                    cache.Set(key, range);
                else
                    cache.TryGet(key, out _);
                if (i % 997 == 0)
                    cache.Clear();
            }
        })));
        Assert.InRange(cache.Count, 0, 16);
    }
}
