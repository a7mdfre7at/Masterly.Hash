using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using Masterly.Hash.Pepper.HashiCorpVault;

namespace Masterly.Hash.Pepper.HashiCorpVault.Tests;

public class EndToEndTests
{
    private const string Pw = "Tr0ub4dor&3";

    [Fact]
    public async Task HashAndVerify_ThroughVault()
    {
        var handler = new FakeTransitHandler(1);
        var hasher = Vault.Hasher(Vault.Pepper(handler));

        string stored = await hasher.HashAsync(Pw);

        Assert.StartsWith("$mh$p=test,k=v1$", stored);
        Assert.Equal(VerificationStatus.Success, (await hasher.VerifyAsync(Pw, stored)).Status);
        Assert.Equal(VerificationFailureReason.Mismatch, (await hasher.VerifyAsync("wrong", stored)).FailureReason);
        Assert.Equal(3, handler.Requests.Count);
    }

    [Fact]
    public void SyncHasherApi_Works()
    {
        var hasher = Vault.Hasher(Vault.Pepper(new FakeTransitHandler(1)));
        string stored = hasher.Hash(Pw);
        Assert.True(hasher.Verify(Pw, stored).IsMatch);
        Assert.False(hasher.Verify("nope", stored).IsMatch);
    }

    [Fact]
    public async Task Rotation_OldVersionVerifies_AndRehashesToNewVersion()
    {
        var handler = new FakeTransitHandler(1, 2);
        string stored = await Vault.Hasher(Vault.Pepper(handler, 1)).HashAsync(Pw);

        var rotated = Vault.Hasher(Vault.Pepper(handler, 2));
        PasswordVerificationResult result = await rotated.VerifyAsync(Pw, stored);

        Assert.Equal(VerificationStatus.SuccessRehashNeeded, result.Status);
        Assert.Equal(RehashReason.OutdatedPepperKey, result.RehashReason);
        Assert.StartsWith("$mh$p=test,k=v2$", result.Rehash);
        Assert.Equal(VerificationStatus.Success, (await rotated.VerifyAsync(Pw, result.Rehash!)).Status);

        int[] versions = handler.Requests.Select(r => r.Body.Contains("\"key_version\":1") ? 1 : 2).ToArray();
        Assert.Equal(new[] { 1, 1, 2, 2 }, versions);
    }

    [Fact]
    public async Task RollingDeploy_OldInstanceWithRaisedMax_VerifiesNewHashes()
    {
        var handler = new FakeTransitHandler(1, 2);
        string fromNewInstance = await Vault.Hasher(Vault.Pepper(handler, 2)).HashAsync(Pw);

        var oldInstance = Vault.Hasher(Vault.Pepper(handler, 1, o => o.MaxKeyVersion = 2));
        PasswordVerificationResult result = await oldInstance.VerifyAsync(Pw, fromNewInstance);

        Assert.True(result.IsMatch);
        Assert.Equal(RehashReason.OutdatedPepperKey, result.RehashReason);
    }

    [Fact]
    public async Task RetiredVersion_FailsAsUnknownKey_WithoutCallingVault()
    {
        var handler = new FakeTransitHandler(1, 2);
        string stored = await Vault.Hasher(Vault.Pepper(handler, 1)).HashAsync(Pw);
        handler.Requests.Clear();

        var retired = Vault.Hasher(Vault.Pepper(handler, 2, o => o.MinKeyVersion = 2));
        PasswordVerificationResult result = await retired.VerifyAsync(Pw, stored);

        Assert.Equal(VerificationFailureReason.UnknownPepperKey, result.FailureReason);
        Assert.Empty(handler.Requests);
    }

    [Fact]
    public async Task DifferentTransitKey_Mismatches()
    {
        string stored = await Vault.Hasher(Vault.Pepper(new FakeTransitHandler(1))).HashAsync(Pw);
        var other = new FakeTransitHandler();
        other.SetKey(1, new byte[32]);
        Assert.Equal(VerificationFailureReason.Mismatch, (await Vault.Hasher(Vault.Pepper(other)).VerifyAsync(Pw, stored)).FailureReason);
    }

    [Fact]
    public async Task VaultDown_HashAndVerifyThrowUnavailable_NotMismatch()
    {
        var handler = new FakeTransitHandler(1);
        var hasher = Vault.Hasher(Vault.Pepper(handler));
        string stored = await hasher.HashAsync(Pw);
        handler.Down = true;

        await Assert.ThrowsAsync<PepperUnavailableException>(() => hasher.VerifyAsync(Pw, stored).AsTask());
        await Assert.ThrowsAsync<PepperUnavailableException>(() => hasher.HashAsync(Pw).AsTask());
        Assert.Throws<PepperUnavailableException>(() => hasher.Verify(Pw, stored));
    }

    [Fact]
    public async Task MalformedStoredHash_NeverCallsVault_AndNeverThrows()
    {
        var handler = new FakeTransitHandler(1) { Down = true };
        var hasher = Vault.Hasher(Vault.Pepper(handler));

        foreach (string bad in new[] { "", "$mh$", "$mh$p=test,k=v1$", "$mh$p=test,k=v0$AAAAAAAAAAAAAAAAAAAAAA$AAAA", "$mh$p=test,k=bad id$x$y", "garbage" })
            Assert.False((await hasher.VerifyAsync(Pw, bad)).IsMatch);
        Assert.Empty(handler.Requests);
    }

    [Fact]
    public async Task PepperedHash_CannotBeVerifiedWithoutPepper()
    {
        string stored = await Vault.Hasher(Vault.Pepper(new FakeTransitHandler(1))).HashAsync(Pw);
        var unpeppered = new PasswordHasher(new PasswordHasherOptions { DefaultProfile = HashProfile.Argon2id("test", 64, 1), AllowWeakProfiles = true });
        Assert.Equal(VerificationFailureReason.UnknownPepperKey, unpeppered.Verify(Pw, stored).FailureReason);
    }

    [Fact]
    public async Task VaultSeesNormalizedPasswordBytes()
    {
        var handler = new FakeTransitHandler(1);
        var hasher = Vault.Hasher(Vault.Pepper(handler));
        await hasher.HashAsync("ﬁ"); // U+FB01 ligature normalizes (NFKC) to "fi"

        RecordedRequest req = Assert.Single(handler.Requests);
        Assert.Contains("\"input\":\"" + System.Convert.ToBase64String(Primitives.HashPrimitives.EncodePassword("fi")) + "\"", req.Body);
    }
}
