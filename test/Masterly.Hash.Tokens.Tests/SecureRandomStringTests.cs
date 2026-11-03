using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;

namespace Masterly.Hash.Tokens.Tests;

public class SecureRandomStringTests
{
    [Theory]
    [InlineData(SecureRandomString.Base62, 62)]
    [InlineData(SecureRandomString.UrlSafe, 64)]
    [InlineData(SecureRandomString.Hex, 16)]
    [InlineData(SecureRandomString.Digits, 10)]
    [InlineData(SecureRandomString.LowercaseAlphanumeric, 36)]
    [InlineData(SecureRandomString.Crockford32, 32)]
    public void BuiltInAlphabetsAreDistinct(string alphabet, int size)
    {
        Assert.Equal(size, alphabet.Length);
        Assert.Equal(size, alphabet.Distinct().Count());
    }

    [Fact]
    public void Crockford32ExcludesAmbiguousLetters() =>
        Assert.DoesNotContain(SecureRandomString.Crockford32, c => "ILOU".Contains(c));

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(17)]
    [InlineData(5000)]
    [InlineData(100_000)]
    public void ProducesRequestedLengthFromAlphabet(int length)
    {
        string value = SecureRandomString.Generate(length, SecureRandomString.Crockford32);
        Assert.Equal(length, value.Length);
        Assert.All(value, c => Assert.Contains(c, SecureRandomString.Crockford32));
    }

    [Fact]
    public void DefaultAlphabetIsBase62()
    {
        string value = SecureRandomString.Generate(1000);
        Assert.Equal(1000, value.Length);
        Assert.True(Base62.IsBase62(value));
    }

    [Fact]
    public void ValuesAreUnique()
    {
        var seen = new HashSet<string>();
        for (int i = 0; i < 5000; i++)
            Assert.True(seen.Add(SecureRandomString.Generate(22)));
    }

    [Fact]
    public void TwoCharacterAlphabetWorks()
    {
        string value = SecureRandomString.Generate(10_000, "01");
        int ones = value.Count(c => c == '1');
        // Binomial(10000, 0.5): sd = 50; 6 sd either side.
        Assert.InRange(ones, 4700, 5300);
    }

    [Fact]
    public void FullByteAlphabetWorks()
    {
        string alphabet = new string(Enumerable.Range(0x100, 256).Select(i => (char)i).ToArray());
        string value = SecureRandomString.Generate(5000, alphabet);
        Assert.All(value, c => Assert.InRange(c, (char)0x100, (char)0x1FF));
    }

    // Chi-square critical values at p = 1e-6 (Wilson-Hilferty approximation), so a correct generator fails
    // these tests about once in a million runs.
    [Theory]
    [InlineData(SecureRandomString.Base62, 2000, 129.0)]   // df 61
    [InlineData(SecureRandomString.Digits, 5000, 46.0)]    // df 9
    [InlineData(SecureRandomString.Crockford32, 2000, 85.0)] // df 31
    public void DistributionIsUniform(string alphabet, int perBucket, double critical)
    {
        string value = SecureRandomString.Generate(alphabet.Length * perBucket, alphabet);
        Assert.True(ChiSquare(Count(value, alphabet), perBucket) < critical);
    }

    [Fact]
    public void AlphabetWhereModuloWouldBeBiasedIsUniform()
    {
        // 200 symbols: a naive "byte % 200" makes symbols 0-55 twice as likely as the rest.
        string alphabet = new string(Enumerable.Range(0x4E00, 200).Select(i => (char)i).ToArray());
        const int perBucket = 1000;
        const double critical = 309.0; // df 199, p = 1e-6

        string value = SecureRandomString.Generate(alphabet.Length * perBucket, alphabet);
        int[] counts = Count(value, alphabet);
        Assert.True(ChiSquare(counts, perBucket) < critical);

        // The low symbols (which modulo would favour) are not over-represented.
        double lowMean = counts.Take(56).Average();
        double highMean = counts.Skip(56).Average();
        Assert.InRange(lowMean / highMean, 0.95, 1.05);

        // Sanity check of the test itself: the biased construction fails it decisively.
        byte[] raw = RandomNumberGenerator.GetBytes(alphabet.Length * perBucket);
        var biased = new int[alphabet.Length];
        foreach (byte b in raw)
            biased[b % alphabet.Length]++;
        Assert.True(ChiSquare(biased, perBucket) > critical * 10);
    }

    [Fact]
    public void EveryPositionIsUniform()
    {
        // Guards against position-dependent bias (e.g. reuse of a byte across characters).
        const int samples = 20_000;
        var counts = new int[8, 16];
        for (int s = 0; s < samples / 100; s++)
        {
            for (int k = 0; k < 100; k++)
            {
                string v = SecureRandomString.Generate(8, SecureRandomString.Hex);
                for (int p = 0; p < 8; p++)
                    counts[p, SecureRandomString.Hex.IndexOf(v[p])]++;
            }
        }
        for (int p = 0; p < 8; p++)
        {
            int[] row = Enumerable.Range(0, 16).Select(i => counts[p, i]).ToArray();
            Assert.True(ChiSquare(row, samples / 16.0) < 58.0, $"position {p}"); // df 15, p = 1e-6
        }
    }

    [Fact]
    public void ValidatesArguments()
    {
        Assert.Throws<ArgumentNullException>(() => SecureRandomString.Generate(1, null!));
        Assert.Throws<ArgumentOutOfRangeException>(() => SecureRandomString.Generate(-1));
        Assert.Throws<ArgumentOutOfRangeException>(() => SecureRandomString.Generate(SecureRandomString.MaxLength + 1));
        Assert.Throws<ArgumentException>(() => SecureRandomString.Generate(5, ""));
        Assert.Throws<ArgumentException>(() => SecureRandomString.Generate(5, "a"));
        Assert.Throws<ArgumentException>(() => SecureRandomString.Generate(5, "abca"));
        Assert.Throws<ArgumentException>(() => SecureRandomString.Generate(5, "ab😀"));
        Assert.Throws<ArgumentException>(() => SecureRandomString.Generate(5, new string(Enumerable.Range(0x100, 257).Select(i => (char)i).ToArray())));
        Assert.Throws<ArgumentException>(() => SecureRandomString.Generate(0, "a")); // alphabet checked even for length 0
    }

    [Theory]
    [InlineData(22, 62, 130.99)]
    [InlineData(32, 16, 128.0)]
    [InlineData(6, 10, 19.93)]
    [InlineData(0, 62, 0.0)]
    public void EntropyBits(int length, int alphabet, double expected) =>
        Assert.Equal(expected, SecureRandomString.GetEntropyBits(length, alphabet), 2);

    [Fact]
    public void EntropyBitsValidatesArguments()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => SecureRandomString.GetEntropyBits(-1, 10));
        Assert.Throws<ArgumentOutOfRangeException>(() => SecureRandomString.GetEntropyBits(1, 1));
    }

    private static int[] Count(string value, string alphabet)
    {
        var index = new Dictionary<char, int>();
        for (int i = 0; i < alphabet.Length; i++)
            index[alphabet[i]] = i;
        var counts = new int[alphabet.Length];
        foreach (char c in value)
            counts[index[c]]++;
        return counts;
    }

    private static double ChiSquare(int[] observed, double expected) =>
        observed.Sum(o => (o - expected) * (o - expected) / expected);
}
