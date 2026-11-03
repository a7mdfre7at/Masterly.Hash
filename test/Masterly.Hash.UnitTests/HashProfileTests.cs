using System;

namespace Masterly.Hash.UnitTests;

public class HashProfileTests
{
    [Theory]
    [InlineData(0)]
    [InlineData(17)]
    public void Argon2id_ParallelismOutOfRange_Throws(int parallelism)
    {
        var ex = Assert.Throws<ArgumentOutOfRangeException>(() => HashProfile.Argon2id("x", 65536, 3, parallelism));
        Assert.Equal("parallelism", ex.ParamName);
        Assert.Equal(parallelism, ex.ActualValue);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(16)]
    public void Argon2id_ParallelismBounds_AreAccepted(int parallelism)
    {
        Assert.Equal(parallelism, HashProfile.Argon2id("x", 65536, 3, parallelism).Parallelism);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(65)]
    public void Argon2id_IterationsOutOfRange_Throws(int iterations)
    {
        Assert.Equal("iterations", Assert.Throws<ArgumentOutOfRangeException>(() => HashProfile.Argon2id("x", 65536, iterations)).ParamName);
    }

    [Theory]
    [InlineData(15, 2)]                          // below 8 KiB per lane
    [InlineData(HashProfile.MaxMemoryKiB + 1, 1)]
    public void Argon2id_MemoryOutOfRange_Throws(int memoryKiB, int parallelism)
    {
        Assert.Equal("memoryKiB", Assert.Throws<ArgumentOutOfRangeException>(() => HashProfile.Argon2id("x", memoryKiB, 1, parallelism)).ParamName);
    }

    [Theory]
    [InlineData(15)]
    [InlineData(65)]
    public void TagLengthOutOfRange_Throws(int tagLength)
    {
        Assert.Equal("tagLength", Assert.Throws<ArgumentOutOfRangeException>(() => HashProfile.Argon2id("x", 65536, 3, tagLength: tagLength)).ParamName);
        Assert.Equal("tagLength", Assert.Throws<ArgumentOutOfRangeException>(() => HashProfile.Pbkdf2Sha512("x", 1000, tagLength: tagLength)).ParamName);
    }

    [Theory]
    [InlineData(15)]
    [InlineData(65)]
    public void SaltLengthOutOfRange_Throws(int saltLength)
    {
        Assert.Equal("saltLength", Assert.Throws<ArgumentOutOfRangeException>(() => HashProfile.Pbkdf2Sha512("x", 1000, saltLength: saltLength)).ParamName);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("-x")]
    [InlineData("abcdefghijklmnopqrstuvwxyz0123456")] // 33 characters
    public void InvalidId_Throws(string? id)
    {
        Assert.Equal("id", Assert.Throws<ArgumentException>(() => HashProfile.Pbkdf2Sha512(id!, 1000)).ParamName);
        Assert.Equal("id", Assert.Throws<ArgumentException>(() => HashProfile.Argon2id(id!, 65536, 3)).ParamName);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(10_000_001)]
    public void Pbkdf2_IterationsOutOfRange_Throws(int iterations)
    {
        var ex = Assert.Throws<ArgumentOutOfRangeException>(() => HashProfile.Pbkdf2Sha512("x", iterations));
        Assert.Equal("iterations", ex.ParamName);
        Assert.Equal(iterations, ex.ActualValue);
    }

    [Fact]
    public void Pbkdf2_CreatesProfile_WithFixedArgon2Fields()
    {
        HashProfile profile = HashProfile.Pbkdf2Sha512("legacy-fips", 10_000_000, saltLength: 32, tagLength: 48);

        Assert.Equal("legacy-fips", profile.Id);
        Assert.Equal(HashAlgorithmKind.Pbkdf2Sha512, profile.Algorithm);
        Assert.Equal(0, profile.MemoryKiB);
        Assert.Equal(10_000_000, profile.Iterations);
        Assert.Equal(1, profile.Parallelism);
        Assert.Equal(32, profile.SaltLength);
        Assert.Equal(48, profile.TagLength);
        Assert.True(profile.MeetsRecommendedMinimum);
        Assert.False(HashProfile.Pbkdf2Sha512("weak", 209_999).MeetsRecommendedMinimum);
        Assert.True(HashProfile.Pbkdf2Sha512("ok", 210_000).MeetsRecommendedMinimum);
    }

    [Fact]
    public void Argon2id_MeetsRecommendedMinimum_ChecksMemoryAndIterations()
    {
        Assert.True(HashProfile.Argon2id("a", 19456, 2).MeetsRecommendedMinimum);
        Assert.False(HashProfile.Argon2id("a", 19455, 2).MeetsRecommendedMinimum);
        Assert.False(HashProfile.Argon2id("a", 19456, 1).MeetsRecommendedMinimum);
    }

    [Fact]
    public void Equality_IsByValue()
    {
        HashProfile a = HashProfile.Argon2id("same", 1024, 2);
        HashProfile b = HashProfile.Argon2id("same", 1024, 2);
        HashProfile differentParams = HashProfile.Argon2id("same", 2048, 2);
        HashProfile differentAlgorithm = HashProfile.Pbkdf2Sha512("same", 2);

        Assert.True(a.Equals(b));
        Assert.True(a.Equals((object)b));
        Assert.Equal(a.GetHashCode(), b.GetHashCode());
        Assert.False(a.Equals(differentParams));
        Assert.False(a.Equals((object)differentParams));
        Assert.False(a.Equals(differentAlgorithm));
        Assert.False(a.Equals((HashProfile?)null));
        Assert.False(a.Equals((object?)null));
        Assert.False(a.Equals("same"));
        Assert.False(a.Equals(HashProfile.Argon2id("other", 1024, 2)));
    }

    [Fact]
    public void ToString_DescribesParameters()
    {
        Assert.Equal("2026a (Argon2id m=65536KiB t=3 p=1)", HashProfile.Server2026a.ToString());
        Assert.Equal("2026f (PBKDF2-SHA512 i=210000)", HashProfile.Fips2026a.ToString());
    }
}
