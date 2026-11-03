using System;
using System.Threading.Tasks;

namespace Masterly.Hash.UnitTests;

/// <summary>The <see cref="SensitiveString"/> overloads in <see cref="PasswordHasherExtensions"/>.</summary>
public class PasswordHasherExtensionsTests
{
    private static readonly SensitiveString Secret = new SensitiveString("hunter2");

    [Fact]
    public void VerifyOrDummy_SensitiveString_VerifiesAndProtectsUnknownUsers()
    {
        IPasswordHasher hasher = TestHashers.Create();
        string stored = hasher.Hash(Secret);

        Assert.Equal(VerificationStatus.Success, hasher.VerifyOrDummy(Secret, stored).Status);
        Assert.Equal(VerificationFailureReason.Mismatch, hasher.VerifyOrDummy(new SensitiveString("nope"), stored).FailureReason);
        Assert.Equal(VerificationFailureReason.NoStoredHash, hasher.VerifyOrDummy(Secret, null).FailureReason);
    }

    [Fact]
    public async Task AsyncOverloads_SensitiveString_RoundTrip()
    {
        IPasswordHasher hasher = TestHashers.Create();

        string stored = await hasher.HashAsync(Secret);

        Assert.StartsWith("$mh$p=test-fast$", stored);
        Assert.Equal(VerificationStatus.Success, (await hasher.VerifyAsync(Secret, stored)).Status);
        Assert.Equal(VerificationFailureReason.Mismatch, (await hasher.VerifyAsync(new SensitiveString("nope"), stored)).FailureReason);
        Assert.Equal(VerificationStatus.Success, (await hasher.VerifyOrDummyAsync(Secret, stored)).Status);
        Assert.Equal(VerificationFailureReason.NoStoredHash, (await hasher.VerifyOrDummyAsync(Secret, null)).FailureReason);
    }

    [Fact]
    public async Task NullHasher_Throws()
    {
        IPasswordHasher hasher = null!;

        Assert.Equal("hasher", Assert.Throws<ArgumentNullException>(() => hasher.Hash(Secret)).ParamName);
        Assert.Equal("hasher", Assert.Throws<ArgumentNullException>(() => hasher.Verify(Secret, "x")).ParamName);
        Assert.Equal("hasher", Assert.Throws<ArgumentNullException>(() => hasher.VerifyOrDummy(Secret, null)).ParamName);
        Assert.Equal("hasher", (await Assert.ThrowsAsync<ArgumentNullException>(async () => await hasher.HashAsync(Secret))).ParamName);
        Assert.Equal("hasher", (await Assert.ThrowsAsync<ArgumentNullException>(async () => await hasher.VerifyAsync(Secret, "x"))).ParamName);
        Assert.Equal("hasher", (await Assert.ThrowsAsync<ArgumentNullException>(async () => await hasher.VerifyOrDummyAsync(Secret, null))).ParamName);
    }

    [Fact]
    public async Task NullPassword_Throws()
    {
        IPasswordHasher hasher = TestHashers.Create();
        SensitiveString password = null!;

        Assert.Equal("password", Assert.Throws<ArgumentNullException>(() => hasher.Hash(password)).ParamName);
        Assert.Equal("password", Assert.Throws<ArgumentNullException>(() => hasher.Verify(password, "x")).ParamName);
        Assert.Equal("password", Assert.Throws<ArgumentNullException>(() => hasher.VerifyOrDummy(password, null)).ParamName);
        Assert.Equal("password", (await Assert.ThrowsAsync<ArgumentNullException>(async () => await hasher.HashAsync(password))).ParamName);
        Assert.Equal("password", (await Assert.ThrowsAsync<ArgumentNullException>(async () => await hasher.VerifyAsync(password, "x"))).ParamName);
        Assert.Equal("password", (await Assert.ThrowsAsync<ArgumentNullException>(async () => await hasher.VerifyOrDummyAsync(password, null))).ParamName);
    }
}
