using System.Threading.Tasks;

namespace Masterly.Hash.UnitTests;

/// <summary>
/// The <see cref="Password"/> static facade over <see cref="PasswordHasher.Default"/>.
/// Uses the production profile, so each hash costs a few hundred ms; keep the number of hashes small.
/// </summary>
public class PasswordFacadeTests
{
    private const string Pw = "correct horse battery staple";

    [Fact]
    public void SensitiveStringOverloads_HashAndVerify_WithTheDefaultProfile()
    {
        var secret = new SensitiveString(Pw);

        string stored = Password.Hash(secret);

        Assert.StartsWith("$mh$p=2026a$", stored);
        Assert.Equal(VerificationStatus.Success, Password.Verify(secret, stored).Status);
        Assert.Equal(VerificationFailureReason.Mismatch, Password.Verify(new SensitiveString(Pw + "!"), stored).FailureReason);
    }

    [Fact]
    public async Task AsyncApi_HashesAndVerifies()
    {
        string stored = await Password.HashAsync(Pw);

        Assert.StartsWith("$mh$p=2026a$", stored);
        Assert.Equal(VerificationStatus.Success, (await Password.VerifyAsync(Pw, stored)).Status);
        Assert.Equal(VerificationFailureReason.Mismatch, (await Password.VerifyAsync("wrong", stored)).FailureReason);
        Assert.Equal(VerificationStatus.Success, (await Password.VerifyOrDummyAsync(Pw, stored)).Status);
        Assert.Equal(VerificationFailureReason.NoStoredHash, (await Password.VerifyOrDummyAsync(Pw, null)).FailureReason);
    }

    [Fact]
    public void VerifyOrDummy_VerifiesKnownUsers_AndFailsUnknownUsers()
    {
        string stored = Password.Hash(Pw);

        Assert.Equal(VerificationStatus.Success, Password.VerifyOrDummy(Pw, stored).Status);
        Assert.Equal(VerificationFailureReason.Mismatch, Password.VerifyOrDummy("wrong", stored).FailureReason);
        PasswordVerificationResult unknown = Password.VerifyOrDummy(Pw, null);
        Assert.False(unknown.IsMatch);
        Assert.Equal(VerificationFailureReason.NoStoredHash, unknown.FailureReason);
    }

    [Fact]
    public void NeedsRehash_AndInspect_DescribeStoredHashes()
    {
        string current = Password.Hash(Pw);
        string constrained = Password.Hash(Pw, HashProfile.Constrained2026a);

        Assert.False(Password.NeedsRehash(current));
        Assert.True(Password.NeedsRehash(constrained));
        Assert.False(Password.NeedsRehash("not a hash"));

        HashInfo info = Password.Inspect(constrained);
        Assert.True(info.IsNative);
        Assert.True(info.IsRecognized);
        Assert.Equal("2026c", info.ProfileId);
        Assert.Same(HashProfile.Constrained2026a, info.Profile);
        Assert.Equal(RehashReason.OutdatedProfile, info.RehashReason);

        HashInfo unknown = Password.Inspect("not a hash");
        Assert.Equal(HashInfo.UnknownFormat, unknown.Format);
        Assert.False(unknown.IsRecognized);
    }
}
