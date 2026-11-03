using System;
using System.Threading.Tasks;
using Masterly.Hash.Pepper.AzureKeyVault;

namespace Masterly.Hash.Pepper.AzureKeyVault.Tests;

public class EndToEndTests
{
    private const string Pw = "Tr0ub4dor&3";
    private const string Secret = "password-pepper";

    private readonly FakeSecretClient _client = new();
    private readonly TestClock _clock = new();

    private Task<AzureKeyVaultPepper> Pepper() =>
        Kv.Create(_client, _clock, o =>
        {
            o.SecretName = Secret;
            o.RefreshInterval = TimeSpan.FromMinutes(5);
            o.ActivationDelay = TimeSpan.FromMinutes(15);
        });

    [Fact]
    public async Task HashAndVerify()
    {
        string v1 = _client.AddVersion(Secret, Kv.NewKeyB64(), _clock.Now.AddDays(-30));
        var hasher = Kv.Hasher(await Pepper());

        string stored = await hasher.HashAsync(Pw);

        Assert.StartsWith("$mh$p=test,k=" + v1 + "$", stored);
        Assert.Equal(VerificationStatus.Success, (await hasher.VerifyAsync(Pw, stored)).Status);
        Assert.Equal(VerificationStatus.Success, hasher.Verify(Pw, stored).Status);
        Assert.Equal(VerificationFailureReason.Mismatch, hasher.Verify("wrong", stored).FailureReason);
    }

    [Fact]
    public async Task Rotation_ByAddingSecretVersion()
    {
        string v1 = _client.AddVersion(Secret, Kv.NewKeyB64(), _clock.Now.AddDays(-30));
        AzureKeyVaultPepper pepper = await Pepper();
        var hasher = Kv.Hasher(pepper);
        string stored = hasher.Hash(Pw);

        // An operator adds a new version. Within one refresh interval every instance knows it...
        string v2 = _client.AddVersion(Secret, Kv.NewKeyB64(), _clock.Now);
        _clock.Advance(TimeSpan.FromMinutes(6));
        _ = pepper.IsKnownKey(v2);
        await Kv.Settle(pepper);
        Assert.True(pepper.IsKnownKey(v2));
        Assert.Equal(v1, pepper.CurrentKeyId);
        Assert.Equal(VerificationStatus.Success, hasher.Verify(Pw, stored).Status);

        // ...and once the activation delay has passed it becomes current, so old hashes are upgraded on login.
        _clock.Advance(TimeSpan.FromMinutes(10));
        _ = pepper.CurrentKeyId;
        await Kv.Settle(pepper);
        Assert.Equal(v2, pepper.CurrentKeyId);

        PasswordVerificationResult result = hasher.Verify(Pw, stored);
        Assert.Equal(VerificationStatus.SuccessRehashNeeded, result.Status);
        Assert.Equal(RehashReason.OutdatedPepperKey, result.RehashReason);
        Assert.StartsWith("$mh$p=test,k=" + v2 + "$", result.Rehash);
        Assert.Equal(VerificationStatus.Success, hasher.Verify(Pw, result.Rehash!).Status);
    }

    [Fact]
    public async Task DisablingVersion_RevokesIt()
    {
        string v1 = _client.AddVersion(Secret, Kv.NewKeyB64(), _clock.Now.AddDays(-30));
        _client.AddVersion(Secret, Kv.NewKeyB64(), _clock.Now.AddDays(-1));
        AzureKeyVaultPepper pepper = await Kv.Create(_client, _clock, o => { o.SecretName = Secret; o.CurrentKeyId = v1; });
        string stored = await Kv.Hasher(pepper).HashAsync(Pw);

        _client.SetEnabled(Secret, v1, false);
        AzureKeyVaultPepper afterRevoke = await Pepper();

        Assert.Equal(VerificationFailureReason.UnknownPepperKey, (await Kv.Hasher(afterRevoke).VerifyAsync(Pw, stored)).FailureReason);
    }

    [Fact]
    public async Task OtherVaultWithSameVersionId_Mismatches()
    {
        string v1 = _client.AddVersion(Secret, Kv.NewKeyB64(), _clock.Now.AddDays(-30));
        string stored = await Kv.Hasher(await Pepper()).HashAsync(Pw);

        var otherVault = new FakeSecretClient();
        Assert.Equal(v1, otherVault.AddVersion(Secret, Kv.NewKeyB64(), _clock.Now.AddDays(-30)));
        AzureKeyVaultPepper other = await Kv.Create(otherVault, _clock, o => o.SecretName = Secret);

        Assert.Equal(VerificationFailureReason.Mismatch, (await Kv.Hasher(other).VerifyAsync(Pw, stored)).FailureReason);
    }

    [Fact]
    public async Task KeyVaultOutage_AfterLoad_DoesNotAffectLogins()
    {
        _client.AddVersion(Secret, Kv.NewKeyB64(), _clock.Now.AddDays(-30));
        AzureKeyVaultPepper pepper = await Pepper();
        var hasher = Kv.Hasher(pepper);
        string stored = hasher.Hash(Pw);

        _client.Fail = new Azure.RequestFailedException(503, "down", "ServiceUnavailable", null);
        _clock.Advance(TimeSpan.FromHours(1));
        Assert.True(hasher.Verify(Pw, stored).IsMatch);
        await Kv.Settle(pepper);
        Assert.True((await hasher.VerifyAsync(Pw, stored)).IsMatch);
        Assert.NotNull(pepper.LastRefreshError);
    }

    [Fact]
    public async Task MapMode_EndToEnd_Rotation()
    {
        _client.AddVersion("pepper-2026", Kv.NewKeyB64(), _clock.Now.AddDays(-30));
        _client.AddVersion("pepper-2027", Kv.NewKeyB64(), _clock.Now.AddDays(-1));

        AzureKeyVaultPepper p1 = await Kv.Create(_client, _clock, o =>
        {
            o.Keys["2026"] = new AzureKeyVaultSecretReference("pepper-2026");
            o.CurrentKeyId = "2026";
        });
        string stored = await Kv.Hasher(p1).HashAsync(Pw);
        Assert.Contains(",k=2026$", stored);

        AzureKeyVaultPepper p2 = await Kv.Create(_client, _clock, o =>
        {
            o.Keys["2026"] = new AzureKeyVaultSecretReference("pepper-2026");
            o.Keys["2027"] = new AzureKeyVaultSecretReference("pepper-2027");
            o.CurrentKeyId = "2027";
        });
        PasswordVerificationResult result = await Kv.Hasher(p2).VerifyAsync(Pw, stored);
        Assert.Equal(RehashReason.OutdatedPepperKey, result.RehashReason);
        Assert.Contains(",k=2027$", result.Rehash);
    }
}
