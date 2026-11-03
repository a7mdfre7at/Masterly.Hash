using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Azure;
using Masterly.Hash.Pepper.AzureKeyVault;

namespace Masterly.Hash.Pepper.AzureKeyVault.Tests;

/// <summary>
/// Revocation must fail closed. When Key Vault answers, its answer is applied, even if no current key is left.
/// Only failures to reach Key Vault keep the cached keys.
/// </summary>
public class RevocationTests
{
    private const string Pw = "Tr0ub4dor&3";
    private const string Secret = "password-pepper";
    private static readonly byte[] Input = Encoding.UTF8.GetBytes("correct horse battery staple");

    private readonly FakeSecretClient _client = new();
    private readonly TestClock _clock = new();
    private readonly List<Exception> _reported = new();

    private Task<AzureKeyVaultPepper> Versions(Action<AzureKeyVaultPepperOptions>? configure = null) =>
        Kv.Create(_client, _clock, o =>
        {
            o.SecretName = Secret;
            o.RefreshInterval = TimeSpan.FromMinutes(5);
            o.OnRefreshFailed = ex => { lock (_reported) _reported.Add(ex); };
            configure?.Invoke(o);
        });

    private async Task BackgroundRefresh(AzureKeyVaultPepper pepper)
    {
        _clock.Advance(TimeSpan.FromMinutes(6));
        _ = pepper.IsKnownKey("trigger");
        await Kv.Settle(pepper);
    }

    [Fact]
    public async Task DisablingPinnedCurrentVersion_InPlace_RevokesIt_AndFailsClosedForWrites()
    {
        string v1 = _client.AddVersion(Secret, Kv.NewKeyB64(), _clock.Now.AddDays(-30));
        string v2 = _client.AddVersion(Secret, Kv.NewKeyB64(), _clock.Now.AddDays(-20));
        AzureKeyVaultPepper pepper = await Versions(o => o.CurrentKeyId = v1);
        PasswordHasher hasher = Kv.Hasher(pepper);
        string storedV1 = await hasher.HashAsync(Pw);
        Assert.Contains(",k=" + v1 + "$", storedV1);

        // Incident response: v1 is compromised and gets disabled. The same running instance must stop trusting it.
        _client.SetEnabled(Secret, v1, false);
        await BackgroundRefresh(pepper);

        Assert.False(pepper.IsKnownKey(v1));
        Assert.True(pepper.IsKnownKey(v2));
        Assert.Equal(new[] { v2 }, pepper.KeyIds);
        Assert.Equal(VerificationFailureReason.UnknownPepperKey, (await hasher.VerifyAsync(Pw, storedV1)).FailureReason);
        Assert.Equal(VerificationFailureReason.UnknownPepperKey, hasher.Verify(Pw, storedV1).FailureReason);

        // The pinned key is gone, so nothing may be written with it (or silently with another key).
        var ex = Assert.Throws<PepperUnavailableException>(() => pepper.CurrentKeyId);
        Assert.Contains(v1, ex.Message);
        await Assert.ThrowsAsync<PepperUnavailableException>(() => hasher.HashAsync(Pw).AsTask());

        // Reported, and visible to health checks.
        Assert.IsType<PepperUnavailableException>(Assert.Single(_reported));
        Assert.NotNull(pepper.LastRefreshError);

        // Explicit refresh also reports the degraded state.
        await Assert.ThrowsAsync<PepperUnavailableException>(() => pepper.RefreshAsync());
        Assert.False(pepper.IsKnownKey(v1));
    }

    [Fact]
    public async Task DisablingInUseUnpinnedVersion_SwitchesToRemainingKey_AndRevokesIt()
    {
        string v1 = _client.AddVersion(Secret, Kv.NewKeyB64(), _clock.Now.AddDays(-30));
        AzureKeyVaultPepper pepper = await Versions();
        PasswordHasher hasher = Kv.Hasher(pepper);
        string storedV1 = await hasher.HashAsync(Pw);

        string v2 = _client.AddVersion(Secret, Kv.NewKeyB64(), _clock.Now);
        _client.SetEnabled(Secret, v1, false);
        await pepper.RefreshAsync(); // healthy result: no exception

        Assert.False(pepper.IsKnownKey(v1));
        Assert.Equal(v2, pepper.CurrentKeyId); // oldest usable fallback while v2 is still inside its activation delay
        Assert.Equal(VerificationFailureReason.UnknownPepperKey, (await hasher.VerifyAsync(Pw, storedV1)).FailureReason);
        Assert.Contains(",k=" + v2 + "$", await hasher.HashAsync(Pw));
        Assert.Null(pepper.LastRefreshError);
    }

    [Fact]
    public async Task DisablingEveryVersion_IsAKillSwitch()
    {
        string v1 = _client.AddVersion(Secret, Kv.NewKeyB64(), _clock.Now.AddDays(-30));
        string v2 = _client.AddVersion(Secret, Kv.NewKeyB64(), _clock.Now.AddDays(-20));
        AzureKeyVaultPepper pepper = await Versions();
        PasswordHasher hasher = Kv.Hasher(pepper);
        string stored = await hasher.HashAsync(Pw);

        _client.SetEnabled(Secret, v1, false);
        _client.SetEnabled(Secret, v2, false);
        var ex = await Assert.ThrowsAsync<PepperUnavailableException>(() => pepper.RefreshAsync());
        Assert.Contains("no enabled versions", ex.Message);

        Assert.Empty(pepper.KeyIds);
        Assert.False(pepper.IsKnownKey(v1));
        Assert.False(pepper.IsKnownKey(v2));
        Assert.Equal(VerificationFailureReason.UnknownPepperKey, (await hasher.VerifyAsync(Pw, stored)).FailureReason);
        Assert.Throws<PepperUnavailableException>(() => pepper.CurrentKeyId);
        await Assert.ThrowsAsync<PepperUnavailableException>(() => hasher.HashAsync(Pw).AsTask());

        _clock.Advance(AzureKeyVaultPepper.RemovedKeyGrace + TimeSpan.FromSeconds(1));
        Assert.Throws<KeyNotFoundException>(() => pepper.Apply(v1, Input));
    }

    [Fact]
    public async Task DeletingTheWholeSecret_RevokesEveryVersion()
    {
        string v1 = _client.AddVersion(Secret, Kv.NewKeyB64(), _clock.Now.AddDays(-30));
        AzureKeyVaultPepper pepper = await Versions();
        PasswordHasher hasher = Kv.Hasher(pepper);
        string stored = await hasher.HashAsync(Pw);

        _client.DeleteSecret(Secret);
        await BackgroundRefresh(pepper);

        Assert.False(pepper.IsKnownKey(v1));
        Assert.Equal(VerificationFailureReason.UnknownPepperKey, (await hasher.VerifyAsync(Pw, stored)).FailureReason);
        Assert.Throws<PepperUnavailableException>(() => pepper.CurrentKeyId);
        // A new hasher (e.g. after a restart) refuses to start without a usable current key.
        Assert.Throws<PepperUnavailableException>(() => Kv.Hasher(pepper));
        Assert.Contains("404", Assert.Single(_reported).Message);
    }

    [Fact]
    public async Task AllRemainingVersionsExpired_KeepsVerifying_ButFailsClosedForWrites()
    {
        string v1 = _client.AddVersion(Secret, Kv.NewKeyB64(), _clock.Now.AddDays(-30), expiresOn: _clock.Now.AddHours(1));
        AzureKeyVaultPepper pepper = await Versions();
        PasswordHasher hasher = Kv.Hasher(pepper);
        string stored = await hasher.HashAsync(Pw);

        _clock.Advance(TimeSpan.FromHours(2));
        await Assert.ThrowsAsync<PepperUnavailableException>(() => pepper.RefreshAsync());

        Assert.True(pepper.IsKnownKey(v1)); // expired keys still verify; they are just never current
        Assert.Equal(VerificationFailureReason.Mismatch, (await hasher.VerifyAsync("wrong", stored)).FailureReason);
        Assert.Throws<PepperUnavailableException>(() => pepper.CurrentKeyId);
    }

    [Fact]
    public async Task RecoversAfterOperatorFixesKeyVault()
    {
        string v1 = _client.AddVersion(Secret, Kv.NewKeyB64(), _clock.Now.AddDays(-30));
        AzureKeyVaultPepper pepper = await Versions();
        _client.SetEnabled(Secret, v1, false);
        await Assert.ThrowsAsync<PepperUnavailableException>(() => pepper.RefreshAsync());

        string v2 = _client.AddVersion(Secret, Kv.NewKeyB64(), _clock.Now);
        await pepper.RefreshAsync();

        Assert.Equal(v2, pepper.CurrentKeyId);
        Assert.Null(pepper.LastRefreshError);
        Assert.False(pepper.IsKnownKey(v1));
    }

    [Fact]
    public async Task MalformedNewVersion_IsSkipped_AndDoesNotBlockRevocationOrRotation()
    {
        string v1 = _client.AddVersion(Secret, Kv.NewKeyB64(), _clock.Now.AddDays(-30));
        string v2 = _client.AddVersion(Secret, Kv.NewKeyB64(), _clock.Now.AddDays(-20));
        AzureKeyVaultPepper pepper = await Versions();
        Assert.Equal(v2, pepper.CurrentKeyId);

        string bad = _client.AddVersion(Secret, "not base64 !!", _clock.Now.AddDays(-1));
        _client.SetEnabled(Secret, v1, false);
        await BackgroundRefresh(pepper);

        Assert.False(pepper.IsKnownKey(v1)); // revocation applied despite the bad version
        Assert.False(pepper.IsKnownKey(bad));
        Assert.Equal(v2, pepper.CurrentKeyId);
        Exception reported = Assert.Single(_reported);
        Assert.Contains(bad, reported.Message);
        Assert.DoesNotContain("not base64", reported.ToString());
        Assert.NotNull(pepper.LastRefreshError);
    }

    [Fact]
    public async Task MalformedVersion_AtStartup_IsSkipped_WhenAUsableCurrentKeyExists()
    {
        string good = _client.AddVersion(Secret, Kv.NewKeyB64(), _clock.Now.AddDays(-30));
        string bad = _client.AddVersion(Secret, Convert.ToBase64String(new byte[8]), _clock.Now.AddDays(-20));

        AzureKeyVaultPepper pepper = await Versions();

        Assert.Equal(good, pepper.CurrentKeyId);
        Assert.False(pepper.IsKnownKey(bad));
        Assert.IsType<PepperUnavailableException>(pepper.LastRefreshError);
    }

    [Fact]
    public async Task UnreadableNewVersion_403_IsSkipped()
    {
        string v1 = _client.AddVersion(Secret, Kv.NewKeyB64(), _clock.Now.AddDays(-30));
        AzureKeyVaultPepper pepper = await Versions();
        string v2 = _client.AddVersion(Secret, Kv.NewKeyB64(), _clock.Now.AddDays(-1));
        _client.GetFailure = v => v == v2 ? new RequestFailedException(403, "Operation get is not allowed on a disabled secret.", "Forbidden", null) : null;

        var ex = await Assert.ThrowsAsync<PepperUnavailableException>(() => pepper.RefreshAsync());

        Assert.Contains("403", ex.Message);
        Assert.False(pepper.IsKnownKey(v2));
        Assert.Equal(v1, pepper.CurrentKeyId);
    }

    [Fact]
    public async Task TransientFailureFetchingNewVersion_KeepsCachedRing()
    {
        string v1 = _client.AddVersion(Secret, Kv.NewKeyB64(), _clock.Now.AddDays(-30));
        string v2 = _client.AddVersion(Secret, Kv.NewKeyB64(), _clock.Now.AddDays(-20));
        AzureKeyVaultPepper pepper = await Versions();

        string v3 = _client.AddVersion(Secret, Kv.NewKeyB64(), _clock.Now.AddDays(-1));
        _client.SetEnabled(Secret, v1, false);
        _client.GetFailure = v => v == v3 ? new RequestFailedException(503, "busy", "ServiceUnavailable", null) : null;

        // Not an authoritative answer about v3: the whole refresh fails and is retried; nothing is published.
        await Assert.ThrowsAsync<PepperUnavailableException>(() => pepper.RefreshAsync());
        Assert.True(pepper.IsKnownKey(v1));
        Assert.Equal(v2, pepper.CurrentKeyId);

        _client.GetFailure = null;
        await pepper.RefreshAsync();
        Assert.False(pepper.IsKnownKey(v1));
        Assert.True(pepper.IsKnownKey(v3));
    }

    // ---------- race between the hasher's key check and its Apply call ----------

    [Fact]
    public async Task Apply_AcceptsKeyRemovedByLatestRefresh_OnlyWithinGrace()
    {
        string v1 = _client.AddVersion(Secret, Kv.NewKeyB64(), _clock.Now.AddDays(-30));
        string v2 = _client.AddVersion(Secret, Kv.NewKeyB64(), _clock.Now.AddDays(-20));
        AzureKeyVaultPepper pepper = await Versions();
        byte[] expected = pepper.Apply(v1, Input);

        _client.SetEnabled(Secret, v1, false);
        await pepper.RefreshAsync();

        Assert.False(pepper.IsKnownKey(v1));
        Assert.Equal(expected, pepper.Apply(v1, Input));
        Assert.Equal(expected, await pepper.ApplyAsync(v1, Input));

        _clock.Advance(AzureKeyVaultPepper.RemovedKeyGrace + TimeSpan.FromSeconds(1));
        Assert.Throws<KeyNotFoundException>(() => pepper.Apply(v1, Input));
        Assert.NotNull(pepper.Apply(v2, Input));
    }

    [Fact]
    public async Task Verify_DoesNotThrow_WhenRefreshRemovesKeyBetweenIsKnownKeyAndApply()
    {
        string v1 = _client.AddVersion(Secret, Kv.NewKeyB64(), _clock.Now.AddDays(-30));
        string v2 = _client.AddVersion(Secret, Kv.NewKeyB64(), _clock.Now.AddDays(-20));
        AzureKeyVaultPepper pepper = await Versions(o => o.CurrentKeyId = v1);
        string stored = await Kv.Hasher(pepper).HashAsync(Pw);

        // A second, unpinned instance (current = v2) verifies; the refresh that revokes v1 lands exactly after the
        // hasher's IsKnownKey(v1) check and before its ApplyAsync(v1) call.
        AzureKeyVaultPepper unpinned = await Versions();
        Assert.Equal(v2, unpinned.CurrentKeyId);
        var racing = new RefreshAfterCheck(unpinned, () => _client.SetEnabled(Secret, v1, false));
        PasswordHasher hasher = Kv.Hasher(racing);

        PasswordVerificationResult result = await hasher.VerifyAsync(Pw, stored);

        Assert.True(result.IsMatch);
        Assert.Equal(RehashReason.OutdatedPepperKey, result.RehashReason);
        Assert.Contains(",k=" + v2 + "$", result.Rehash);
        Assert.False(unpinned.IsKnownKey(v1));
    }

    [Fact]
    public async Task Hash_DoesNotThrow_WhenRefreshRemovesCurrentKeyBetweenCurrentKeyIdAndApply()
    {
        string v1 = _client.AddVersion(Secret, Kv.NewKeyB64(), _clock.Now.AddDays(-30));
        _client.AddVersion(Secret, Kv.NewKeyB64(), _clock.Now.AddDays(-20));
        AzureKeyVaultPepper pepper = await Versions(o => o.ActivationDelay = TimeSpan.FromDays(25));
        Assert.Equal(v1, pepper.CurrentKeyId);
        var racing = new RefreshAfterCheck(pepper, () => _client.SetEnabled(Secret, v1, false));
        PasswordHasher hasher = Kv.Hasher(racing);
        racing.Armed = true; // the hasher constructor read CurrentKeyId already

        string stored = await hasher.HashAsync(Pw);

        Assert.Contains(",k=" + v1 + "$", stored);
    }

    /// <summary>
    /// Decorator that, right after the hasher's first IsKnownKey or CurrentKeyId check, changes Key Vault and runs a
    /// refresh to completion. This reproduces deterministically the race the grace period covers.
    /// </summary>
    private sealed class RefreshAfterCheck(AzureKeyVaultPepper inner, Action change) : IPasswordPepper
    {
        public bool Armed { get; set; }

        public string CurrentKeyId
        {
            get
            {
                string id = inner.CurrentKeyId;
                Fire();
                return id;
            }
        }

        public bool IsKnownKey(string keyId)
        {
            Armed = true;
            bool known = inner.IsKnownKey(keyId);
            Fire();
            return known;
        }

        public byte[] Apply(string keyId, byte[] input) => inner.Apply(keyId, input);

        public ValueTask<byte[]> ApplyAsync(string keyId, byte[] input, CancellationToken cancellationToken = default) =>
            inner.ApplyAsync(keyId, input, cancellationToken);

        private void Fire()
        {
            if (!Armed)
                return;
            Armed = false;
            change();
            try
            {
                inner.RefreshAsync().GetAwaiter().GetResult();
            }
            catch (PepperUnavailableException)
            {
                // A degraded result is still applied; the test only cares about the race.
            }
        }
    }
}
