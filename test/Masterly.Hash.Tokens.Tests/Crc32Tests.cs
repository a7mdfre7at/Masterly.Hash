using System;
using System.Text;

namespace Masterly.Hash.Tokens.Tests;

public class Crc32Tests
{
    // Check value of CRC-32/ISO-HDLC (the IEEE / zlib CRC-32):
    // Greg Cook, "Catalogue of parametrised CRC algorithms", https://reveng.sourceforge.io/crc-catalogue/17plus.htm#crc.cat.crc-32-iso-hdlc
    [Fact]
    public void StandardCheckValue() =>
        Assert.Equal(0xCBF43926u, Crc32.Compute(Encoding.ASCII.GetBytes("123456789")));

    // Additional well-known values (identical output from zlib's crc32(), Python's zlib.crc32 and .NET's System.IO.Hashing.Crc32).
    [Theory]
    [InlineData("", 0x00000000u)]
    [InlineData("a", 0xE8B7BE43u)]
    [InlineData("abc", 0x352441C2u)]
    [InlineData("The quick brown fox jumps over the lazy dog", 0x414FA339u)]
    public void KnownValues(string input, uint expected) => Assert.Equal(expected, Crc32.Compute(input));

    [Fact]
    public void OffsetAndCountSelectASubrange()
    {
        byte[] data = Encoding.ASCII.GetBytes("xx123456789yy");
        Assert.Equal(0xCBF43926u, Crc32.Compute(data, 2, 9));
        Assert.Equal(0u, Crc32.Compute(data, 13, 0));
    }

    [Fact]
    public void ArgumentValidation()
    {
        Assert.Throws<ArgumentNullException>(() => Crc32.Compute((byte[])null!));
        Assert.Throws<ArgumentNullException>(() => Crc32.Compute((string)null!));
        Assert.Throws<ArgumentOutOfRangeException>(() => Crc32.Compute(new byte[4], -1, 1));
        Assert.Throws<ArgumentOutOfRangeException>(() => Crc32.Compute(new byte[4], 5, 0));
        Assert.Throws<ArgumentOutOfRangeException>(() => Crc32.Compute(new byte[4], 2, 3));
        Assert.Throws<ArgumentOutOfRangeException>(() => Crc32.Compute(new byte[4], 0, -1));
    }

    [Fact]
    public void DetectsEverySingleBitFlip()
    {
        byte[] data = Encoding.ASCII.GetBytes("mh_live_SomeRandomBody0123456789");
        uint original = Crc32.Compute(data);
        for (int i = 0; i < data.Length; i++)
        {
            for (int bit = 0; bit < 8; bit++)
            {
                data[i] ^= (byte)(1 << bit);
                Assert.NotEqual(original, Crc32.Compute(data));
                data[i] ^= (byte)(1 << bit);
            }
        }
    }
}
