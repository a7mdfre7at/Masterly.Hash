using System;
using System.Text;
using Masterly.Hash.Legacy;

namespace Masterly.Hash.UnitTests;

/// <summary>The deliberately-obsolete 1.x <see cref="Hash"/> API.</summary>
public class ObsoleteHashTests
{
    private const string Pw = "SomePaswword!@#";
    private static readonly byte[] Salt = { 9, 8, 7, 6, 5, 4, 3, 2, 1 };

    public static TheoryData<SupportedHash, V1Algorithm, int> Algorithms() => new TheoryData<SupportedHash, V1Algorithm, int>
    {
        { SupportedHash.SHA256, V1Algorithm.SHA256, 32 },
        { SupportedHash.SHA384, V1Algorithm.SHA384, 48 },
        { SupportedHash.SHA512, V1Algorithm.SHA512, 64 },
    };

    [Theory]
    [MemberData(nameof(Algorithms))]
    public void ComputeHash_ByteSalt_IsByteForByteThe1xAlgorithm(SupportedHash hash, V1Algorithm algorithm, int digestSize)
    {
        string computed = new Hash().ComputeHash(Pw, Salt, hash);

        Assert.Equal(TestHashers.Original1x(Pw, Salt, algorithm), computed);
        Assert.Equal(digestSize + Salt.Length, Convert.FromBase64String(computed).Length);
    }

    [Theory]
    [MemberData(nameof(Algorithms))]
    public void ComputeHash_StringSalt_UsesUtf8OfTheSalt(SupportedHash hash, V1Algorithm algorithm, int digestSize)
    {
        const string salt = "SomeSalt#$%ü";
        var api = new Hash();

        string computed = api.ComputeHash(Pw, salt, hash);

        Assert.Equal(TestHashers.Original1x(Pw, Encoding.UTF8.GetBytes(salt), algorithm), computed);
        Assert.Equal(api.ComputeHash(Pw, Encoding.UTF8.GetBytes(salt), hash), computed);
        Assert.Equal(digestSize + Encoding.UTF8.GetByteCount(salt), Convert.FromBase64String(computed).Length);
        Assert.True(api.Verify(Pw, computed, hash));
    }

    [Theory]
    [MemberData(nameof(Algorithms))]
    public void ComputeHash_RandomSalt_VerifiesWithTheSameAlgorithmOnly(SupportedHash hash, V1Algorithm algorithm, int digestSize)
    {
        var api = new Hash();

        string computed = api.ComputeHash(Pw, hash);

        Assert.Equal(digestSize + 16, Convert.FromBase64String(computed).Length);
        Assert.NotEqual(computed, api.ComputeHash(Pw, hash));
        Assert.True(api.Verify(Pw, computed, hash));
        Assert.False(api.Verify(Pw + "x", computed, hash));
        Assert.True(new V1LegacyFormat(algorithm).Verify(Pw, computed));

        foreach (SupportedHash other in Enum.GetValues<SupportedHash>())
        {
            if (other != hash)
                Assert.False(api.Verify(Pw, computed, other));
        }
    }

    [Fact]
    public void Defaults_AreSha512()
    {
        IHash api = new Hash();

        Assert.Equal(TestHashers.Original1x(Pw, Salt, V1Algorithm.SHA512), api.ComputeHash(Pw, Salt));
        Assert.Equal(api.ComputeHash(Pw, Encoding.UTF8.GetBytes("s")), api.ComputeHash(Pw, "s"));
        string random = api.ComputeHash(Pw);
        Assert.Equal(64 + 16, Convert.FromBase64String(random).Length);
        Assert.True(api.Verify(Pw, random));
    }

    [Fact]
    public void NullArguments()
    {
        var api = new Hash();

        Assert.Equal("plainText", Assert.Throws<ArgumentNullException>(() => api.ComputeHash(null!, Salt)).ParamName);
        Assert.Equal("plainText", Assert.Throws<ArgumentNullException>(() => api.ComputeHash(null!)).ParamName);
        Assert.Equal("saltBytes", Assert.Throws<ArgumentNullException>(() => api.ComputeHash(Pw, (byte[])null!)).ParamName);
        Assert.Equal("salt", Assert.Throws<ArgumentNullException>(() => api.ComputeHash(Pw, (string)null!)).ParamName);
        Assert.Equal("plainText", Assert.Throws<ArgumentNullException>(() => api.Verify(null!, "x")).ParamName);
        Assert.False(api.Verify(Pw, null!));
    }

    [Fact]
    public void Verify_NonHash_ReturnsFalse()
    {
        var api = new Hash();
        Assert.False(api.Verify(Pw, "not a hash"));
        Assert.False(api.Verify(Pw, string.Empty));
    }
}
