using System;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace Masterly.Hash.Tokens.Tests;

public class Base62Tests
{
    [Fact]
    public void AlphabetIsGmpOrder()
    {
        Assert.Equal(62, Base62.Alphabet.Length);
        Assert.Equal(62, Base62.Alphabet.Distinct().Count());
        Assert.StartsWith("0123456789ABC", Base62.Alphabet);
        Assert.EndsWith("xyz", Base62.Alphabet);
    }

    [Theory]
    [InlineData(0, 0)]
    [InlineData(1, 2)]
    [InlineData(4, 6)]
    [InlineData(16, 22)]
    [InlineData(32, 43)]
    [InlineData(64, 86)]
    public void EncodedLengths(int bytes, int chars) => Assert.Equal(chars, Base62.GetEncodedLength(bytes));

    [Fact]
    public void EncodedLengthIsTheExactMinimumForEverySupportedSize()
    {
        for (int n = 0; n <= Base62.MaxByteLength; n++)
        {
            int length = Base62.GetEncodedLength(n);
            BigInteger range = BigInteger.Pow(256, n);
            Assert.True(BigInteger.Pow(62, length) >= range, $"n={n}");
            if (length > 0)
                Assert.True(BigInteger.Pow(62, length - 1) < range, $"n={n}");
        }
    }

    [Theory]
    [InlineData(new byte[0], "")]
    [InlineData(new byte[] { 0x00 }, "00")]
    [InlineData(new byte[] { 0x01 }, "01")]
    [InlineData(new byte[] { 0x3D }, "0z")]       // 61
    [InlineData(new byte[] { 0x3E }, "10")]       // 62
    [InlineData(new byte[] { 0xFF }, "47")]       // 255 = 4*62 + 7
    [InlineData(new byte[] { 0x01, 0x00 }, "048")] // 256 = 4*62 + 8
    [InlineData(new byte[] { 0xFF, 0xFF, 0xFF, 0xFF }, "4gfFC3")] // 4294967295
    public void KnownVectors(byte[] input, string expected)
    {
        Assert.Equal(expected, Base62.Encode(input));
        Assert.True(Base62.TryDecode(expected, out byte[] decoded));
        Assert.Equal(input, decoded);
    }

    [Fact]
    public void MatchesBigIntegerReference()
    {
        for (int n = 1; n <= 80; n++)
        {
            byte[] input = RandomNumberGenerator.GetBytes(n);
            Assert.Equal(Reference(input), Base62.Encode(input));
        }
    }

    [Fact]
    public void RoundTripsAndPreservesLeadingZeros()
    {
        for (int n = 0; n <= 128; n++)
        {
            byte[] input = RandomNumberGenerator.GetBytes(n);
            if (n > 2)
            {
                input[0] = 0;
                input[1] = 0;
            }
            string encoded = Base62.Encode(input);
            Assert.Equal(Base62.GetEncodedLength(n), encoded.Length);
            Assert.True(Base62.TryDecode(encoded, out byte[] decoded));
            Assert.Equal(input, decoded);
        }
    }

    [Fact]
    public void ExtremesRoundTrip()
    {
        byte[] max = Enumerable.Repeat((byte)0xFF, Base62.MaxByteLength).ToArray();
        Assert.True(Base62.TryDecode(Base62.Encode(max), out byte[] decoded));
        Assert.Equal(max, decoded);
        Assert.Throws<ArgumentException>(() => Base62.Encode(new byte[Base62.MaxByteLength + 1]));
        Assert.Throws<ArgumentNullException>(() => Base62.Encode(null!));
        Assert.Throws<ArgumentOutOfRangeException>(() => Base62.GetEncodedLength(-1));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("0")]          // no byte count encodes to one character
    [InlineData("0000")]       // nor to four
    [InlineData("zz")]         // 3843 does not fit in one byte
    [InlineData("4gfFC4")]     // 2^32 does not fit in four bytes
    [InlineData("0-")]
    [InlineData("0 ")]
    [InlineData("0é")]
    [InlineData("0=")]
    public void TryDecodeRejectsInvalidInputWithoutThrowing(string? input)
    {
        Assert.False(Base62.TryDecode(input, out byte[] bytes));
        Assert.Empty(bytes);
    }

    [Fact]
    public void TryDecodeRejectsOversizedInput() =>
        Assert.False(Base62.TryDecode(new string('0', 20000), out _));

    [Fact]
    public void IsBase62()
    {
        Assert.True(Base62.IsBase62("abcXYZ019"));
        Assert.False(Base62.IsBase62(""));
        Assert.False(Base62.IsBase62(null));
        Assert.False(Base62.IsBase62("ab_c"));
    }

    private static string Reference(byte[] bigEndian)
    {
        var value = new BigInteger(bigEndian, isUnsigned: true, isBigEndian: true);
        var sb = new StringBuilder();
        while (value > 0)
        {
            sb.Insert(0, Base62.Alphabet[(int)(value % 62)]);
            value /= 62;
        }
        return sb.ToString().PadLeft(Base62.GetEncodedLength(bigEndian.Length), '0');
    }
}
