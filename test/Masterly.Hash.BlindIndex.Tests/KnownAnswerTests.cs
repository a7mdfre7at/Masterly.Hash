using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Masterly.Hash.BlindIndex.Tests;

/// <summary>
/// Pins the wire format. Expected values were computed independently of .NET with CPython 3.13's
/// <c>hmac</c>/<c>hashlib</c>/<c>struct</c> modules from the format documented on <see cref="BlindIndexer"/>:
/// <c>HMAC-SHA256(key, tag || uint32_be(len(name)) || name || uint32_be(len(value)) || value)</c>, truncated, base64
/// without padding. HMAC-SHA256 itself is the BCL implementation (validated against RFC 4231 below).
/// </summary>
public class KnownAnswerTests
{
    private static readonly BlindIndexer Indexer = new("k1", TestKeys.Sequential);

    [Theory]
    [InlineData("alice@example.com", 64, "k1:J11Swgv2Zu4")]
    [InlineData("alice@example.com", 256, "k1:J11Swgv2Zu5XjK/pzYbVnpABU82E2My/Df16TW/BoZk")]
    [InlineData("alice@example.com", 16, "k1:J10")]
    public void Single_value_vectors(string value, int bits, string expected)
    {
        Assert.Equal(expected, Indexer.Compute(value, "users.email", TestKeys.Bits(bits)));
    }

    [Fact]
    public void Non_ascii_value_is_utf8_encoded()
    {
        Assert.Equal("k1:v+PawqzBZk8", Indexer.Compute("Jürgen محمد", "users.name"));
    }

    [Fact]
    public void Compound_vectors()
    {
        Assert.Equal("k1:4W6UjoOwGEk", Indexer.ComputeCompound("people.name_dob", "smith", "1990-01-01"));
        Assert.Equal("k1:xOsTtg", Indexer.ComputeCompound("people.name_dob", TestKeys.Bits(32), "", "x"));
    }

    [Fact]
    public void Default_options_are_64_bits_exact()
    {
        Assert.Equal(Indexer.Compute("alice@example.com", "users.email", TestKeys.Bits(64)), Indexer.Compute("alice@example.com", "users.email"));
    }

    [Fact]
    public void Matches_reference_construction_built_with_bcl()
    {
        byte[] key = TestKeys.Derived("ref");
        var indexer = new BlindIndexer("ref", key);
        foreach (string value in new[] { "a", "hello world", new string('x', 10_000), "\U0001F600" })
        {
            byte[] name = Encoding.UTF8.GetBytes("t.col");
            byte[] val = Encoding.UTF8.GetBytes(value);
            var message = new List<byte>(Encoding.ASCII.GetBytes("masterly-blind-index/v1"));
            message.AddRange(BigEndian(name.Length));
            message.AddRange(name);
            message.AddRange(BigEndian(val.Length));
            message.AddRange(val);
            byte[] mac = HMACSHA256.HashData(key, message.ToArray());
            string expected = "ref:" + Convert.ToBase64String(mac, 0, 12).TrimEnd('=');
            Assert.Equal(expected, indexer.Compute(value, "t.col", TestKeys.Bits(96)));
        }
    }

    // RFC 4231 section 4.3, test case 2: confirms the BCL HMAC-SHA256 the indexer relies on.
    [Fact]
    public void Rfc4231_test_case_2()
    {
        byte[] mac = HMACSHA256.HashData(Encoding.ASCII.GetBytes("Jefe"), Encoding.ASCII.GetBytes("what do ya want for nothing?"));
        Assert.Equal("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843", Convert.ToHexString(mac).ToLowerInvariant());
    }

    private static byte[] BigEndian(int value)
    {
        byte[] b = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(b, (uint)value);
        return b;
    }
}
