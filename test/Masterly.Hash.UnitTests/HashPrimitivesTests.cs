using System;
using System.Security.Cryptography;
using System.Text;
using Masterly.Hash.Internal;
using Masterly.Hash.Primitives;

namespace Masterly.Hash.UnitTests;

/// <summary>Argument validation and behaviour of the public <see cref="HashPrimitives"/> helpers.</summary>
public class HashPrimitivesTests
{
    private static readonly HashProfile FastPbkdf2 = HashProfile.Pbkdf2Sha512("kdf-test", 10);

    [Fact]
    public void FixedTimeEquals_Arrays_ComparesAndRejectsNull()
    {
        Assert.True(HashPrimitives.FixedTimeEquals(new byte[] { 1, 2 }, new byte[] { 1, 2 }));
        Assert.False(HashPrimitives.FixedTimeEquals(new byte[] { 1, 2 }, new byte[] { 1, 3 }));
        Assert.False(HashPrimitives.FixedTimeEquals(new byte[] { 1 }, new byte[] { 1, 2 }));
        Assert.Equal("left", Assert.Throws<ArgumentNullException>(() => HashPrimitives.FixedTimeEquals(null!, new byte[1])).ParamName);
        Assert.Equal("right", Assert.Throws<ArgumentNullException>(() => HashPrimitives.FixedTimeEquals(new byte[1], null!)).ParamName);
    }

    [Fact]
    public void IsWellFormedPassword_Null_Throws()
    {
        Assert.Equal("password", Assert.Throws<ArgumentNullException>(() => HashPrimitives.IsWellFormedPassword(null!)).ParamName);
        Assert.True(HashPrimitives.IsWellFormedPassword("ok"));
        Assert.False(HashPrimitives.IsWellFormedPassword("\uD800"));
    }

    [Fact]
    public void IdValidators_RejectNull()
    {
        Assert.False(HashPrimitives.IsValidProfileId(null!));
        Assert.False(HashPrimitives.IsValidKeyId(null!));
        Assert.False(HashPrimitives.IsValidFormatId(null!));
    }

    [Fact]
    public void Zero_ClearsBuffer_AndIgnoresNull()
    {
        byte[] buffer = { 1, 2, 3, 4 };

        HashPrimitives.Zero(buffer);
        HashPrimitives.Zero(null);

        Assert.Equal(new byte[4], buffer);
    }

    [Fact]
    public void RandomBytes_ReturnsRequestedLength_AndRejectsNegative()
    {
        Assert.Empty(HashPrimitives.RandomBytes(0));
        byte[] a = HashPrimitives.RandomBytes(32);
        Assert.Equal(32, a.Length);
        Assert.NotEqual(a, HashPrimitives.RandomBytes(32));
        Assert.Equal("length", Assert.Throws<ArgumentOutOfRangeException>(() => HashPrimitives.RandomBytes(-1)).ParamName);
    }

    [Fact]
    public void Pbkdf2_ValidatesArguments()
    {
        byte[] pw = { 1 }, salt = { 2 };

        Assert.Equal("password", Assert.Throws<ArgumentNullException>(() => HashPrimitives.Pbkdf2(HashAlgorithmName.SHA256, null!, salt, 1, 32)).ParamName);
        Assert.Equal("salt", Assert.Throws<ArgumentNullException>(() => HashPrimitives.Pbkdf2(HashAlgorithmName.SHA256, pw, null!, 1, 32)).ParamName);
        Assert.Equal("iterations", Assert.Throws<ArgumentOutOfRangeException>(() => HashPrimitives.Pbkdf2(HashAlgorithmName.SHA256, pw, salt, 0, 32)).ParamName);
        Assert.Equal("length", Assert.Throws<ArgumentOutOfRangeException>(() => HashPrimitives.Pbkdf2(HashAlgorithmName.SHA256, pw, salt, 1, 0)).ParamName);
    }

    [Theory]
    [InlineData("MD5")]
    [InlineData("SHA384")]
    [InlineData("SHA3_256")]
    public void Pbkdf2_UnsupportedPrf_Throws(string prf)
    {
        var ex = Assert.Throws<ArgumentOutOfRangeException>(() => HashPrimitives.Pbkdf2(new HashAlgorithmName(prf), new byte[] { 1 }, new byte[] { 2 }, 1, 32));
        Assert.Equal("prf", ex.ParamName);
        Assert.Equal(prf, ex.ActualValue);
    }

    [Theory]
    [InlineData("SHA1", 20)]
    [InlineData("SHA256", 32)]
    [InlineData("SHA512", 64)]
    public void Pbkdf2_SupportedPrfs_MatchTheBcl(string prf, int length)
    {
        var name = new HashAlgorithmName(prf);
        byte[] pw = Encoding.UTF8.GetBytes("password"), salt = Encoding.UTF8.GetBytes("salt");

        Assert.Equal(Rfc2898DeriveBytes.Pbkdf2(pw, salt, 3, name, length), HashPrimitives.Pbkdf2(name, pw, salt, 3, length));
    }

    [Fact]
    public void DeriveKey_ValidatesArguments()
    {
        byte[] input = { 1 }, salt = new byte[8];

        Assert.Equal("profile", Assert.Throws<ArgumentNullException>(() => HashPrimitives.DeriveKey(null!, input, salt)).ParamName);
        Assert.Equal("input", Assert.Throws<ArgumentNullException>(() => HashPrimitives.DeriveKey(FastPbkdf2, null!, salt)).ParamName);
        Assert.Equal("salt", Assert.Throws<ArgumentNullException>(() => HashPrimitives.DeriveKey(FastPbkdf2, input, null!)).ParamName);
        Assert.Equal("input", Assert.Throws<ArgumentException>(() => HashPrimitives.DeriveKey(FastPbkdf2, Array.Empty<byte>(), salt)).ParamName);
        Assert.Equal("salt", Assert.Throws<ArgumentException>(() => HashPrimitives.DeriveKey(FastPbkdf2, input, new byte[7])).ParamName);
    }

    [Fact]
    public void DeriveKey_IsTheProfileKdf()
    {
        byte[] input = { 1, 2, 3 }, salt = new byte[8];

        byte[] key = HashPrimitives.DeriveKey(FastPbkdf2, input, salt);

        Assert.Equal(FastPbkdf2.TagLength, key.Length);
        Assert.Equal(Rfc2898DeriveBytes.Pbkdf2(input, salt, 10, HashAlgorithmName.SHA512, 64), key);
    }

    [Fact]
    public void EncodePassword_IsUtf8OfNfkc_AndRejectsInvalidInput()
    {
        // "e" + COMBINING ACUTE ACCENT normalizes to U+00E9; the ligature "fi" (U+FB01) to "fi".
        Assert.Equal(new byte[] { 0xC3, 0xA9 }, HashPrimitives.EncodePassword("é"));
        Assert.Equal(Encoding.UTF8.GetBytes("fi"), HashPrimitives.EncodePassword("ﬁ"));
        Assert.Equal("password", Assert.Throws<ArgumentNullException>(() => HashPrimitives.EncodePassword(null!)).ParamName);
        Assert.Equal("password", Assert.Throws<ArgumentException>(() => HashPrimitives.EncodePassword("a\uD800b")).ParamName);
        Assert.Equal("password", Assert.Throws<ArgumentException>(() => HashPrimitives.EncodePassword("a￾")).ParamName);
    }

    [Fact]
    public void ToB64_IsUnpaddedStandardBase64()
    {
        Assert.Equal("/w", HashPrimitives.ToB64(new byte[] { 0xFF }));
        Assert.Equal("+/8", HashPrimitives.ToB64(new byte[] { 0xFB, 0xFF }));
        Assert.Equal(string.Empty, HashPrimitives.ToB64(Array.Empty<byte>()));
        Assert.Equal("bytes", Assert.Throws<ArgumentNullException>(() => HashPrimitives.ToB64(null!)).ParamName);
    }

    [Fact]
    public void TryFromB64_Null_ReturnsFalseAndEmpty()
    {
        Assert.False(HashPrimitives.TryFromB64(null!, out byte[] bytes));
        Assert.Empty(bytes);
    }

}
