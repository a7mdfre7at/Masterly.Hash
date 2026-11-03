using System;
using Masterly.Hash.Legacy;

namespace Masterly.Hash.UnitTests;

public class PasswordVerificationResultTests
{
    [Fact]
    public void ToString_DescribesEachOutcome_WithoutTheRehash()
    {
        PasswordHasher hasher = TestHashers.Create();
        string stored = hasher.Hash("pw");

        PasswordVerificationResult success = hasher.Verify("pw", stored);
        PasswordVerificationResult failed = hasher.Verify("wrong", stored);
        PasswordVerificationResult rehash = hasher.Verify("pw", TestHashers.Original1x("pw", new byte[8], V1Algorithm.SHA256));

        Assert.Equal("Success", success.ToString());
        Assert.Equal("Failed (Mismatch)", failed.ToString());
        Assert.Equal("SuccessRehashNeeded (LegacyFormat)", rehash.ToString());
        Assert.NotNull(rehash.Rehash);
        Assert.DoesNotContain(rehash.Rehash!, rehash.ToString());
    }

    [Fact]
    public void Flags_FollowStatus()
    {
        PasswordHasher hasher = TestHashers.Create();
        string stored = hasher.Hash("pw");

        PasswordVerificationResult success = hasher.Verify("pw", stored);
        Assert.True(success.IsMatch);
        Assert.False(success.NeedsRehash);
        Assert.Equal(VerificationFailureReason.None, success.FailureReason);
        Assert.Equal(RehashReason.None, success.RehashReason);
        Assert.Null(success.Rehash);

        PasswordVerificationResult failed = hasher.Verify("pw", string.Empty);
        Assert.False(failed.IsMatch);
        Assert.False(failed.NeedsRehash);
        Assert.Equal(VerificationFailureReason.NoStoredHash, failed.FailureReason);
    }
}

public class HashInfoTests
{
    [Fact]
    public void Constructor_NullFormat_Throws()
    {
        Assert.Equal("format", Assert.Throws<ArgumentNullException>(() => new HashInfo(null!, false, null, null, null, null, RehashReason.None)).ParamName);
    }

    [Fact]
    public void Constructor_StoresEveryField()
    {
        var info = new HashInfo(HashInfo.NativeFormat, true, "2026a", HashProfile.Server2026a, "k1", "v1", RehashReason.Wrapped);

        Assert.Equal("mh", info.Format);
        Assert.True(info.IsNative);
        Assert.True(info.IsRecognized);
        Assert.Equal("2026a", info.ProfileId);
        Assert.Same(HashProfile.Server2026a, info.Profile);
        Assert.Equal("k1", info.PepperKeyId);
        Assert.Equal("v1", info.WrappedFormat);
        Assert.Equal(RehashReason.Wrapped, info.RehashReason);
        Assert.True(info.NeedsRehash);
        Assert.False(new HashInfo("unknown", false, null, null, null, null, RehashReason.None).NeedsRehash);
    }
}
