using System;
using System.Threading;
using System.Threading.Tasks;
using Masterly.Hash.Legacy;
using Masterly.Hash.Pepper;

namespace Masterly.Hash.UnitTests;

/// <summary>Validation of <see cref="PasswordHasherOptions"/> by the <see cref="PasswordHasher"/> constructor.</summary>
public class PasswordHasherOptionsTests
{
    [Fact]
    public void NullOptions_Throws()
    {
        Assert.Equal("options", Assert.Throws<ArgumentNullException>(() => new PasswordHasher(null!)).ParamName);
    }

    [Fact]
    public void NullDefaultProfile_Throws()
    {
        var ex = Assert.Throws<ArgumentException>(() => TestHashers.Create(o => o.DefaultProfile = null!));
        Assert.Equal("options", ex.ParamName);
        Assert.Contains("DefaultProfile", ex.Message);
    }

    [Fact]
    public void NullAdditionalProfile_Throws()
    {
        var ex = Assert.Throws<ArgumentException>(() => TestHashers.Create(o => o.AdditionalProfiles.Add(null!)));
        Assert.Contains("Profiles cannot contain null", ex.Message);
    }

    [Fact]
    public void NullLegacyFormat_Throws()
    {
        var ex = Assert.Throws<ArgumentException>(() => TestHashers.Create(o => o.LegacyFormats.Add(null!)));
        Assert.Equal("options", ex.ParamName);
        Assert.Contains("LegacyFormats contains null", ex.Message);
    }

    [Theory]
    [InlineData("Upper")]
    [InlineData("-leading-dash")]
    [InlineData("under_score")]
    [InlineData("")]
    public void LegacyFormat_InvalidId_Throws(string id)
    {
        var ex = Assert.Throws<ArgumentException>(() => TestHashers.Create(o => o.LegacyFormats.Add(new NamedFormat(id))));
        Assert.Equal("options", ex.ParamName);
        Assert.Contains($"'{id}'", ex.Message);
    }

    [Fact]
    public void LegacyFormat_RegisteredTwice_Throws()
    {
        // The default list already contains V1LegacyFormat.Instance ("v1").
        var ex = Assert.Throws<ArgumentException>(() => TestHashers.Create(o => o.LegacyFormats.Add(new V1LegacyFormat(V1Algorithm.SHA256))));
        Assert.Equal("options", ex.ParamName);
        Assert.Contains("registered twice", ex.Message);
    }

    [Fact]
    public void Pepper_WithInvalidCurrentKeyId_Throws()
    {
        var ex = Assert.Throws<ArgumentException>(() => TestHashers.Create(o => o.Pepper = new BadKeyIdPepper()));
        Assert.Equal("options", ex.ParamName);
        Assert.Contains("CurrentKeyId", ex.Message);
    }

    [Theory]
    [InlineData(63)]
    [InlineData(1024 * 1024 + 1)]
    [InlineData(0)]
    public void MaxPasswordBytes_OutOfRange_Throws(int value)
    {
        var ex = Assert.Throws<ArgumentOutOfRangeException>(() => TestHashers.Create(o => o.MaxPasswordBytes = value));
        Assert.Equal("options", ex.ParamName);
        Assert.Equal(value, ex.ActualValue);
    }

    [Theory]
    [InlineData(64)]
    [InlineData(1024 * 1024)]
    public void MaxPasswordBytes_Bounds_AreAccepted(int value)
    {
        Assert.Equal(value, TestHashers.Create(o => o.MaxPasswordBytes = value).MaxPasswordBytes);
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(int.MinValue)]
    public void MaxConcurrency_Negative_Throws(int value)
    {
        var ex = Assert.Throws<ArgumentOutOfRangeException>(() => TestHashers.Create(o => o.MaxConcurrency = value));
        Assert.Equal("options", ex.ParamName);
        Assert.Equal(value, ex.ActualValue);
        Assert.Contains("MaxConcurrency", ex.Message);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-5)]
    public void ConcurrencyTimeout_ZeroOrNegative_Throws(int milliseconds)
    {
        TimeSpan timeout = TimeSpan.FromMilliseconds(milliseconds);
        var ex = Assert.Throws<ArgumentOutOfRangeException>(() => TestHashers.Create(o => o.ConcurrencyTimeout = timeout));
        Assert.Equal("options", ex.ParamName);
        Assert.Equal(timeout, ex.ActualValue);
        Assert.Contains("ConcurrencyTimeout", ex.Message);
    }

    [Fact]
    public void ConcurrencyTimeout_Infinite_IsAccepted()
    {
        PasswordHasher hasher = TestHashers.Create(o => o.ConcurrencyTimeout = Timeout.InfiniteTimeSpan);
        Assert.True(hasher.Verify("pw", hasher.Hash("pw")).IsMatch);
    }

    [Fact]
    public void DefaultProfile_ReflectsOptions()
    {
        Assert.Same(TestHashers.Fast, TestHashers.Create().DefaultProfile);
        Assert.Same(HashProfile.Server2026a, new PasswordHasher().DefaultProfile);
    }

    [Fact]
    public void Options_AreCopied_LaterChangesHaveNoEffect()
    {
        var options = new PasswordHasherOptions { DefaultProfile = TestHashers.Fast, AllowWeakProfiles = true };
        var hasher = new PasswordHasher(options);
        options.DefaultProfile = TestHashers.Fast2;
        options.MaxPasswordBytes = 64;

        Assert.Same(TestHashers.Fast, hasher.DefaultProfile);
        Assert.Equal(1024, hasher.MaxPasswordBytes);
    }

    private sealed class NamedFormat : ILegacyHashFormat
    {
        public NamedFormat(string id) => Id = id;
        public string Id { get; }
        public bool CanHandle(string storedHash) => false;
        public bool Verify(string password, string storedHash) => false;

        public bool TryExtractWrapInput(string storedHash, out byte[] digest, out byte[] parameter)
        {
            digest = parameter = Array.Empty<byte>();
            return false;
        }

        public byte[] ComputeWrapInput(string password, byte[] parameter) => throw new NotSupportedException();
    }

    private sealed class BadKeyIdPepper : IPasswordPepper
    {
        public string CurrentKeyId => "bad key id";
        public bool IsKnownKey(string keyId) => true;
        public byte[] Apply(string keyId, byte[] input) => input;
        public ValueTask<byte[]> ApplyAsync(string keyId, byte[] input, CancellationToken cancellationToken = default) => new ValueTask<byte[]>(input);
    }
}
