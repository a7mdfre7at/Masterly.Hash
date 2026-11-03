using System;
using System.Collections.Generic;
using System.Linq;
using Masterly.Hash.Primitives;

namespace Masterly.Hash.BlindIndex.Tests;

public class BlindIndexMathTests
{
    [Theory]
    [InlineData(0, 16, 0)]
    [InlineData(1, 16, 0)]
    [InlineData(65_537, 16, 1)]
    [InlineData(10_000, 16, 0.152572631835937)]
    [InlineData(1_000_000, 32, 0.000232830410)]
    public void False_positives_per_query(long n, int bits, double expected)
    {
        Assert.Equal(expected, BlindIndexMath.ExpectedFalsePositivesPerQuery(n, bits), 9);
    }

    [Theory]
    [InlineData(0, 16, 0)]
    [InlineData(1, 16, 0)]
    [InlineData(2, 16, 1.0 / 65_536)]
    [InlineData(65_536, 32, 0.499992370605469)] // the classic birthday bound: ~2^(bits/2) values give ~1/2 expected pair
    public void Colliding_pairs(long n, int bits, double expected)
    {
        Assert.Equal(expected, BlindIndexMath.ExpectedCollidingPairs(n, bits), 9);
    }

    [Fact]
    public void Halving_bits_relationship()
    {
        // Every 8 extra bits divide the false-positive rate by exactly 256.
        for (int bits = 16; bits < 256; bits += 8)
        {
            double ratio = BlindIndexMath.ExpectedFalsePositivesPerQuery(1_000_000, bits)
                         / BlindIndexMath.ExpectedFalsePositivesPerQuery(1_000_000, bits + 8);
            Assert.Equal(256, ratio, 6);
        }
        Assert.True(BlindIndexMath.ExpectedFalsePositivesPerQuery(long.MaxValue, 256) > 0);
    }

    [Theory]
    [InlineData(10_000, 1.0, 16)]
    [InlineData(1_000_000, 1.0, 24)]
    [InlineData(1_000_000, 0.001, 32)]
    [InlineData(100_000_000, 0.001, 40)]
    [InlineData(100_000_000, 1e-30, 128)]
    [InlineData(long.MaxValue, 1e-300, 256)]
    public void MinimumOutputBits(long n, double target, int expected)
    {
        int bits = BlindIndexMath.MinimumOutputBits(n, target);
        Assert.Equal(expected, bits);
        if (bits < 256)
            Assert.True(BlindIndexMath.ExpectedFalsePositivesPerQuery(n, bits) <= target);
        if (bits > 16 && bits < 256)
            Assert.True(BlindIndexMath.ExpectedFalsePositivesPerQuery(n, bits - 8) > target);
    }

    [Fact]
    public void Invalid_math_inputs_throw()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => BlindIndexMath.ExpectedFalsePositivesPerQuery(-1, 64));
        Assert.Throws<ArgumentOutOfRangeException>(() => BlindIndexMath.ExpectedFalsePositivesPerQuery(10, 12));
        Assert.Throws<ArgumentOutOfRangeException>(() => BlindIndexMath.ExpectedCollidingPairs(10, 512));
        Assert.Throws<ArgumentOutOfRangeException>(() => BlindIndexMath.MinimumOutputBits(10, 0));
        Assert.Throws<ArgumentOutOfRangeException>(() => BlindIndexMath.MinimumOutputBits(10, double.NaN));
        Assert.Throws<ArgumentOutOfRangeException>(() => BlindIndexMath.MinimumOutputBits(10, double.PositiveInfinity));
        Assert.Throws<ArgumentOutOfRangeException>(() => BlindIndexMath.MinimumOutputBits(-1, 1));
    }

    /// <summary>
    /// Empirical sanity check that the truncated HMAC behaves like a uniform random function. With n = 20,000
    /// distinct values and 16-bit indexes the expected number of colliding pairs is n(n-1)/2^17 ~ 3051.6 (Poisson-like,
    /// standard deviation ~ 55), so a +/-15% band is more than 8 standard deviations wide.
    /// </summary>
    [Fact]
    public void Observed_collisions_match_birthday_math()
    {
        const int n = 20_000;
        BlindIndexer indexer = TestKeys.Single();
        var options = TestKeys.Bits(16);
        var buckets = new Dictionary<string, int>();
        for (int i = 0; i < n; i++)
        {
            string idx = indexer.Compute("user" + i + "@example.com", "users.email", options);
            buckets[idx] = buckets.TryGetValue(idx, out int c) ? c + 1 : 1;
        }

        double observedPairs = buckets.Values.Sum(c => c * (c - 1) / 2.0);
        double expectedPairs = BlindIndexMath.ExpectedCollidingPairs(n, 16);
        Assert.InRange(observedPairs, expectedPairs * 0.85, expectedPairs * 1.15);

        // A query for one value returns on average (n-1)/2^16 ~ 0.305 unrelated rows.
        double observedFpPerQuery = buckets.Values.Sum(c => (double)c * (c - 1)) / n;
        Assert.InRange(observedFpPerQuery, BlindIndexMath.ExpectedFalsePositivesPerQuery(n, 16) * 0.85, BlindIndexMath.ExpectedFalsePositivesPerQuery(n, 16) * 1.15);
    }

    [Fact]
    public void Output_bits_are_roughly_balanced()
    {
        // Each output bit should be set about half the time (binomial, n=4000: sd ~ 31.6, band = +/-6 sd).
        BlindIndexer indexer = TestKeys.Single();
        var counts = new int[64];
        const int n = 4000;
        for (int i = 0; i < n; i++)
        {
            HashPrimitives.TryFromB64(indexer.Compute("v" + i, "t.c").Substring(3), out byte[] tag);
            for (int b = 0; b < 64; b++)
                counts[b] += (tag[b / 8] >> (7 - b % 8)) & 1;
        }
        Assert.All(counts, c => Assert.InRange(c, n / 2 - 190, n / 2 + 190));
    }
}
