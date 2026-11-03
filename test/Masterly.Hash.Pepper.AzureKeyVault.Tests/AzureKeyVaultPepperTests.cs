using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Azure;
using Masterly.Hash.Pepper.AzureKeyVault;

namespace Masterly.Hash.Pepper.AzureKeyVault.Tests;

public class AzureKeyVaultPepperTests
{
    private const string Secret = "password-pepper";
    private static readonly byte[] Input = Encoding.UTF8.GetBytes("correct horse battery staple");

    private readonly FakeSecretClient _client = new();
    private readonly TestClock _clock = new();

    private Task<AzureKeyVaultPepper> Versions(Action<AzureKeyVaultPepperOptions>? configure = null) =>
        Kv.Create(_client, _clock, o => { o.SecretName = Secret; configure?.Invoke(o); });

    // ---------- versions mode ----------

    [Fact]
    public async Task Versions_LoadsEnabledVersions_AndComputesHmacLocally()
    {
        byte[] key = HmacPepper.GenerateKey();
        string v1 = _client.AddVersion(Secret, Convert.ToBase64String(key), _clock.Now.AddDays(-30));

        AzureKeyVaultPepper pepper = await Versions();

        Assert.Equal(v1, pepper.CurrentKeyId);
        Assert.Equal(32, v1.Length);
        Assert.True(pepper.IsKnownKey(v1));
        Assert.Equal(HMACSHA256.HashData(key, Input), pepper.Apply(v1, Input));
        Assert.Equal(HMACSHA256.HashData(key, Input), await pepper.ApplyAsync(v1, Input));
        Assert.Equal(_clock.Now, pepper.LastRefreshed);
        Assert.Null(pepper.LastRefreshError);
    }

    // RFC 4231, section 4.7 (test case 6): HMAC-SHA-256 with a 131-byte key of 0xaa.
    [Fact]
    public async Task KnownAnswer_Rfc4231TestCase6()
    {
        string v = _client.AddVersion(Secret, Convert.ToBase64String(Enumerable.Repeat((byte)0xaa, 131).ToArray()), _clock.Now.AddDays(-1));
        AzureKeyVaultPepper pepper = await Versions();

        byte[] mac = pepper.Apply(v, Encoding.ASCII.GetBytes("Test Using Larger Than Block-Size Key - Hash Key First"));

        Assert.Equal(Convert.FromHexString("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"), mac);
    }

    [Fact]
    public async Task Versions_NewVersionIsKnownImmediately_ButCurrentOnlyAfterActivationDelay()
    {
        string old = _client.AddVersion(Secret, Kv.NewKeyB64(), _clock.Now.AddDays(-30));
        string fresh = _client.AddVersion(Secret, Kv.NewKeyB64(), _clock.Now.AddMinutes(-5));

        AzureKeyVaultPepper pepper = await Versions(o => o.ActivationDelay = TimeSpan.FromMinutes(15));

        Assert.Equal(old, pepper.CurrentKeyId);
        Assert.True(pepper.IsKnownKey(fresh));
        Assert.Equal(new[] { fresh, old }, pepper.KeyIds);

        _clock.Advance(TimeSpan.FromMinutes(11));
        await pepper.RefreshAsync();
        Assert.Equal(fresh, pepper.CurrentKeyId);
    }

    [Fact]
    public async Task Versions_OnlyNewVersions_UsesOldest()
    {
        string a = _client.AddVersion(Secret, Kv.NewKeyB64(), _clock.Now.AddMinutes(-2));
        _client.AddVersion(Secret, Kv.NewKeyB64(), _clock.Now.AddMinutes(-1));
        Assert.Equal(a, (await Versions()).CurrentKeyId);
    }

    [Fact]
    public async Task Versions_ZeroActivationDelay_UsesNewest()
    {
        _client.AddVersion(Secret, Kv.NewKeyB64(), _clock.Now.AddDays(-2));
        string b = _client.AddVersion(Secret, Kv.NewKeyB64(), _clock.Now);
        Assert.Equal(b, (await Versions(o => o.ActivationDelay = TimeSpan.Zero)).CurrentKeyId);
    }

    [Fact]
    public async Task Versions_DisabledVersionsAreNotLoaded()
    {
        string on = _client.AddVersion(Secret, Kv.NewKeyB64(), _clock.Now.AddDays(-30));
        string off = _client.AddVersion(Secret, Kv.NewKeyB64(), _clock.Now.AddDays(-20), enabled: false);

        AzureKeyVaultPepper pepper = await Versions();

        Assert.True(pepper.IsKnownKey(on));
        Assert.False(pepper.IsKnownKey(off));
        Assert.DoesNotContain("get:" + Secret + "/" + off, _client.Calls);
    }

    [Fact]
    public async Task Versions_NotYetValidOrExpired_AreKnownButNeverCurrent()
    {
        string good = _client.AddVersion(Secret, Kv.NewKeyB64(), _clock.Now.AddDays(-30));
        string expired = _client.AddVersion(Secret, Kv.NewKeyB64(), _clock.Now.AddDays(-20), expiresOn: _clock.Now.AddDays(-1));
        string future = _client.AddVersion(Secret, Kv.NewKeyB64(), _clock.Now.AddDays(-10), notBefore: _clock.Now.AddDays(5));

        AzureKeyVaultPepper pepper = await Versions();

        Assert.Equal(good, pepper.CurrentKeyId);
        Assert.True(pepper.IsKnownKey(expired));
        Assert.True(pepper.IsKnownKey(future));
    }

    [Fact]
    public async Task Versions_PinnedCurrentKeyId()
    {
        string a = _client.AddVersion(Secret, Kv.NewKeyB64(), _clock.Now.AddDays(-30));
        _client.AddVersion(Secret, Kv.NewKeyB64(), _clock.Now.AddDays(-20));
        Assert.Equal(a, (await Versions(o => o.CurrentKeyId = a)).CurrentKeyId);
    }

    [Fact]
    public async Task Versions_PinnedCurrentKeyIdMissing_Fails()
    {
        _client.AddVersion(Secret, Kv.NewKeyB64(), _clock.Now.AddDays(-30));
        await Assert.ThrowsAsync<PepperUnavailableException>(() => Versions(o => o.CurrentKeyId = "0123456789abcdef0123456789abcdef"));
    }

    [Fact]
    public async Task Versions_MaxVersions_KeepsNewest()
    {
        var ids = Enumerable.Range(0, 5).Select(i => _client.AddVersion(Secret, Kv.NewKeyB64(), _clock.Now.AddDays(-50 + i))).ToList();
        AzureKeyVaultPepper pepper = await Versions(o => o.MaxVersions = 3);

        Assert.Equal(ids.Skip(2).Reverse(), pepper.KeyIds);
        Assert.False(pepper.IsKnownKey(ids[0]));
        Assert.Equal(3, _client.GetCalls);
    }

    [Fact]
    public async Task Versions_NoEnabledVersions_Fails()
    {
        _client.AddVersion(Secret, Kv.NewKeyB64(), _clock.Now, enabled: false);
        var ex = await Assert.ThrowsAsync<PepperUnavailableException>(() => Versions());
        Assert.Contains("no enabled versions", ex.Message);
    }

    [Fact]
    public async Task Versions_AllExpired_Fails()
    {
        _client.AddVersion(Secret, Kv.NewKeyB64(), _clock.Now.AddDays(-9), expiresOn: _clock.Now.AddDays(-1));
        await Assert.ThrowsAsync<PepperUnavailableException>(() => Versions());
    }

    [Fact]
    public async Task Versions_MissingSecret_FailsWithStatus()
    {
        var ex = await Assert.ThrowsAsync<PepperUnavailableException>(() => Versions());
        Assert.Contains("404", ex.Message);
        Assert.Contains("SecretNotFound", ex.Message);
        Assert.IsType<RequestFailedException>(ex.InnerException);
    }

    public static IEnumerable<object[]> BadValues() => new[]
    {
        new object[] { "" },
        new object[] { "not base64 !!" },
        new object[] { Convert.ToBase64String(new byte[31]) },
        new object[] { "c2hvcnQ=" },
        new object[] { new string('A', 8196) },
    };

    [Theory]
    [MemberData(nameof(BadValues))]
    public async Task InvalidSecretValue_Fails_WithoutLeakingValue(string value)
    {
        _client.AddVersion(Secret, value, _clock.Now.AddDays(-1));
        var ex = await Assert.ThrowsAsync<PepperUnavailableException>(() => Versions());
        if (value.Length > 0)
            Assert.DoesNotContain(value, ex.ToString());
    }

    [Fact]
    public async Task AccessDenied_IsUnavailable_WithStatus()
    {
        _client.AddVersion(Secret, Kv.NewKeyB64(), _clock.Now.AddDays(-1));
        _client.Fail = new RequestFailedException(403, "Caller is not authorized", "Forbidden", null);
        var ex = await Assert.ThrowsAsync<PepperUnavailableException>(() => Versions());
        Assert.Contains("403", ex.Message);
        Assert.Contains("Forbidden", ex.Message);
    }

    [Fact]
    public async Task ErrorCodeWithControlCharacters_IsNotEchoed()
    {
        _client.AddVersion(Secret, Kv.NewKeyB64(), _clock.Now.AddDays(-1));
        _client.Fail = new RequestFailedException(500, "x", "evil\r\ncode", null);
        var ex = await Assert.ThrowsAsync<PepperUnavailableException>(() => Versions());
        Assert.DoesNotContain("evil", ex.Message);
    }

    [Fact]
    public async Task UnexpectedException_IsWrapped()
    {
        _client.AddVersion(Secret, Kv.NewKeyB64(), _clock.Now.AddDays(-1));
        _client.Fail = new InvalidOperationException("credential unavailable");
        var ex = await Assert.ThrowsAsync<PepperUnavailableException>(() => Versions());
        Assert.IsType<InvalidOperationException>(ex.InnerException);
    }

    [Fact]
    public async Task Timeout_IsUnavailable()
    {
        _client.AddVersion(Secret, Kv.NewKeyB64(), _clock.Now.AddDays(-1));
        _client.Delay = ct => Task.Delay(Timeout.Infinite, ct);
        var ex = await Assert.ThrowsAsync<PepperUnavailableException>(() => Versions(o => o.Timeout = TimeSpan.FromMilliseconds(100)));
        Assert.Contains("timeout", ex.Message);
    }

    [Fact]
    public async Task CallerCancellation_IsOperationCanceled()
    {
        _client.AddVersion(Secret, Kv.NewKeyB64(), _clock.Now.AddDays(-1));
        _client.Delay = ct => Task.Delay(Timeout.Infinite, ct);
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(100));
        var options = new AzureKeyVaultPepperOptions { SecretName = Secret };
        var ex = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => AzureKeyVaultPepper.CreateAsync(_client, options, cts.Token));
        Assert.IsNotType<PepperUnavailableException>(ex);
    }

    // ---------- caching and refresh ----------

    [Fact]
    public async Task Refresh_FetchesOnlyNewVersions()
    {
        _client.AddVersion(Secret, Kv.NewKeyB64(), _clock.Now.AddDays(-30));
        AzureKeyVaultPepper pepper = await Versions();
        Assert.Equal(1, _client.GetCalls);

        string v2 = _client.AddVersion(Secret, Kv.NewKeyB64(), _clock.Now);
        await pepper.RefreshAsync();
        await pepper.RefreshAsync();

        Assert.Equal(2, _client.GetCalls);
        Assert.Equal(3, _client.ListCalls);
        Assert.True(pepper.IsKnownKey(v2));
    }

    [Fact]
    public async Task Refresh_DropsDisabledAndDeletedVersions()
    {
        string a = _client.AddVersion(Secret, Kv.NewKeyB64(), _clock.Now.AddDays(-30));
        string b = _client.AddVersion(Secret, Kv.NewKeyB64(), _clock.Now.AddDays(-20));
        string c = _client.AddVersion(Secret, Kv.NewKeyB64(), _clock.Now.AddDays(-10));
        AzureKeyVaultPepper pepper = await Versions();

        _client.SetEnabled(Secret, a, false);
        _client.Delete(Secret, b);
        await pepper.RefreshAsync();

        Assert.False(pepper.IsKnownKey(a));
        Assert.False(pepper.IsKnownKey(b));
        Assert.Equal(c, pepper.CurrentKeyId);

        // Re-enabling a version reloads it from Key Vault (the cached copy was discarded).
        int gets = _client.GetCalls;
        _client.SetEnabled(Secret, a, true);
        await pepper.RefreshAsync();
        Assert.True(pepper.IsKnownKey(a));
        Assert.Equal(gets + 1, _client.GetCalls);
    }

    [Fact]
    public async Task BackgroundRefresh_TriggeredByUse_AfterInterval()
    {
        _client.AddVersion(Secret, Kv.NewKeyB64(), _clock.Now.AddDays(-30));
        AzureKeyVaultPepper pepper = await Versions(o => o.RefreshInterval = TimeSpan.FromMinutes(5));
        string v2 = _client.AddVersion(Secret, Kv.NewKeyB64(), _clock.Now);

        _clock.Advance(TimeSpan.FromMinutes(4));
        Assert.False(pepper.IsKnownKey(v2));
        Assert.Null(pepper.BackgroundRefresh);
        Assert.Equal(1, _client.ListCalls);

        _clock.Advance(TimeSpan.FromMinutes(2));
        _ = pepper.IsKnownKey(v2); // triggers the refresh; this call still sees the cached ring
        await Kv.Settle(pepper);

        Assert.True(pepper.IsKnownKey(v2));
        Assert.Equal(2, _client.ListCalls);
        Assert.Equal(_clock.Now, pepper.LastRefreshed);
    }

    [Fact]
    public async Task BackgroundRefresh_IsSingleFlight()
    {
        _client.AddVersion(Secret, Kv.NewKeyB64(), _clock.Now.AddDays(-30));
        AzureKeyVaultPepper pepper = await Versions();
        var release = new TaskCompletionSource();
        _client.Delay = _ => release.Task;
        _clock.Advance(TimeSpan.FromHours(1));

        for (int i = 0; i < 50; i++)
            _ = pepper.CurrentKeyId;
        await Task.WhenAll(Enumerable.Range(0, 50).Select(_ => Task.Run(() => pepper.IsKnownKey("x"))));
        release.SetResult();
        await Kv.Settle(pepper);

        Assert.Equal(2, _client.ListCalls);
    }

    [Fact]
    public async Task BackgroundRefreshFailure_KeepsCachedKeys_ReportsError_AndRetriesLater()
    {
        string v1 = _client.AddVersion(Secret, Kv.NewKeyB64(), _clock.Now.AddDays(-30));
        var reported = new List<Exception>();
        AzureKeyVaultPepper pepper = await Versions(o =>
        {
            o.RefreshInterval = TimeSpan.FromMinutes(5);
            o.OnRefreshFailed = ex => { lock (reported) reported.Add(ex); throw new InvalidOperationException("logger bug"); };
        });

        _client.Fail = new RequestFailedException(503, "Service unavailable", "ServiceUnavailable", null);
        _clock.Advance(TimeSpan.FromMinutes(6));
        _ = pepper.CurrentKeyId;
        await Kv.Settle(pepper);

        Assert.Equal(v1, pepper.CurrentKeyId);
        Assert.NotNull(pepper.Apply(v1, Input));
        Assert.IsType<PepperUnavailableException>(pepper.LastRefreshError);
        Assert.IsType<PepperUnavailableException>(Assert.Single(reported));

        // Retry is not immediate, but happens within FailedRefreshRetry even though RefreshInterval is longer.
        int lists = _client.ListCalls;
        _ = pepper.CurrentKeyId;
        await Kv.Settle(pepper);
        Assert.Equal(lists, _client.ListCalls);

        _client.Fail = null;
        _clock.Advance(AzureKeyVaultPepper.FailedRefreshRetry);
        _ = pepper.CurrentKeyId;
        await Kv.Settle(pepper);
        Assert.Equal(lists + 1, _client.ListCalls);
        Assert.Null(pepper.LastRefreshError);
    }

    [Fact]
    public async Task RefreshAsync_Failure_ThrowsAndKeepsCachedKeys()
    {
        string v1 = _client.AddVersion(Secret, Kv.NewKeyB64(), _clock.Now.AddDays(-30));
        AzureKeyVaultPepper pepper = await Versions();
        _client.Fail = new RequestFailedException(500, "boom", "InternalError", null);

        await Assert.ThrowsAsync<PepperUnavailableException>(() => pepper.RefreshAsync());

        Assert.True(pepper.IsKnownKey(v1));
        Assert.NotNull(pepper.LastRefreshError);
    }

    [Fact]
    public async Task InfiniteRefreshInterval_NeverRefreshes()
    {
        _client.AddVersion(Secret, Kv.NewKeyB64(), _clock.Now.AddDays(-30));
        AzureKeyVaultPepper pepper = await Versions(o => o.RefreshInterval = Timeout.InfiniteTimeSpan);
        _clock.Advance(TimeSpan.FromDays(3650));
        _ = pepper.CurrentKeyId;
        Assert.Null(pepper.BackgroundRefresh);
        Assert.Equal(1, _client.ListCalls);
    }

    [Fact]
    public async Task ApplyNeverCallsKeyVault()
    {
        string v1 = _client.AddVersion(Secret, Kv.NewKeyB64(), _clock.Now.AddDays(-30));
        AzureKeyVaultPepper pepper = await Versions();
        int calls = _client.Calls.Count;
        _client.Fail = new InvalidOperationException("must not be called");

        for (int i = 0; i < 10; i++)
            await pepper.ApplyAsync(v1, Input);

        Assert.Equal(calls, _client.Calls.Count);
    }

    [Fact]
    public async Task UnknownKey_ThrowsKeyNotFound()
    {
        _client.AddVersion(Secret, Kv.NewKeyB64(), _clock.Now.AddDays(-30));
        AzureKeyVaultPepper pepper = await Versions();
        Assert.Throws<KeyNotFoundException>(() => pepper.Apply("nope", Input));
        await Assert.ThrowsAsync<KeyNotFoundException>(() => pepper.ApplyAsync(null!, Input).AsTask());
        Assert.Throws<ArgumentNullException>(() => pepper.Apply(pepper.CurrentKeyId, null!));
        Assert.False(pepper.IsKnownKey(null!));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => pepper.ApplyAsync(pepper.CurrentKeyId, Input, new CancellationToken(true)).AsTask());
    }

    [Fact]
    public void Create_Sync_Works()
    {
        string v1 = _client.AddVersion(Secret, Kv.NewKeyB64(), DateTimeOffset.UtcNow.AddDays(-30));
        AzureKeyVaultPepper pepper = AzureKeyVaultPepper.Create(_client, new AzureKeyVaultPepperOptions { SecretName = Secret });
        Assert.Equal(v1, pepper.CurrentKeyId);
    }

    [Fact]
    public void Create_Sync_FailureThrowsUnavailable()
    {
        Assert.Throws<PepperUnavailableException>(() => AzureKeyVaultPepper.Create(_client, new AzureKeyVaultPepperOptions { SecretName = "missing" }));
    }

    // ---------- map mode ----------

    [Fact]
    public async Task Map_LoadsExplicitSecrets_AndPinsVersions()
    {
        byte[] k1 = HmacPepper.GenerateKey();
        byte[] k2 = HmacPepper.GenerateKey();
        string k1v = _client.AddVersion("pepper-k1", Convert.ToBase64String(k1), _clock.Now.AddDays(-30));
        _client.AddVersion("pepper-k2", Convert.ToBase64String(k2), _clock.Now.AddDays(-1));

        AzureKeyVaultPepper pepper = await Kv.Create(_client, _clock, o =>
        {
            o.Keys["k1"] = new AzureKeyVaultSecretReference("pepper-k1", k1v);
            o.Keys["k2"] = new AzureKeyVaultSecretReference("pepper-k2");
            o.CurrentKeyId = "k2";
        });

        Assert.Equal("k2", pepper.CurrentKeyId);
        Assert.Equal(HMACSHA256.HashData(k1, Input), pepper.Apply("k1", Input));
        Assert.Equal(HMACSHA256.HashData(k2, Input), pepper.Apply("k2", Input));
        Assert.Equal(new[] { "k1", "k2" }, pepper.KeyIds.OrderBy(x => x));

        // A later version of the unversioned secret does not change the loaded key, and map mode never refreshes.
        _client.AddVersion("pepper-k2", Kv.NewKeyB64(), _clock.Now);
        _clock.Advance(TimeSpan.FromDays(1));
        await pepper.RefreshAsync();
        _ = pepper.CurrentKeyId;
        Assert.Null(pepper.BackgroundRefresh);
        Assert.Equal(HMACSHA256.HashData(k2, Input), pepper.Apply("k2", Input));
        Assert.Equal(2, _client.GetCalls);
        Assert.Equal(0, _client.ListCalls);
    }

    [Fact]
    public async Task Map_MissingOrDisabledSecret_Fails()
    {
        string v = _client.AddVersion("pepper-k1", Kv.NewKeyB64(), _clock.Now, enabled: false);
        await Assert.ThrowsAsync<PepperUnavailableException>(() => Kv.Create(_client, _clock, o =>
        {
            o.Keys["k1"] = new AzureKeyVaultSecretReference("pepper-k1", v);
            o.CurrentKeyId = "k1";
        }));
        await Assert.ThrowsAsync<PepperUnavailableException>(() => Kv.Create(_client, _clock, o =>
        {
            o.Keys["k1"] = new AzureKeyVaultSecretReference("does-not-exist");
            o.CurrentKeyId = "k1";
        }));
    }

    // ---------- options validation ----------

    public static IEnumerable<object[]> InvalidOptions()
    {
        var r = new AzureKeyVaultSecretReference("s");
        var cases = new (string Name, Action<AzureKeyVaultPepperOptions> Configure)[]
        {
            ("neither", o => { }),
            ("both", o => { o.SecretName = "s"; o.Keys["k"] = r; o.CurrentKeyId = "k"; }),
            ("empty secret name", o => o.SecretName = ""),
            ("bad secret name", o => o.SecretName = "a_b"),
            ("long secret name", o => o.SecretName = new string('a', 128)),
            // A ^...$ regex accepts a trailing newline in .NET; ids and names must match in full.
            ("secret name with trailing newline", o => o.SecretName = "s\n"),
            ("pinned id with trailing newline", o => { o.SecretName = "s"; o.CurrentKeyId = "k1\n"; }),
            ("map key id with trailing newline", o => { o.Keys["k1\n"] = r; o.CurrentKeyId = "k1\n"; }),
            ("map version with trailing newline", o => { o.Keys["k"] = new AzureKeyVaultSecretReference("x", "v1\n"); o.CurrentKeyId = "k"; }),
            ("bad pinned id", o => { o.SecretName = "s"; o.CurrentKeyId = "bad id"; }),
            ("map without current", o => o.Keys["k"] = r),
            ("map current not mapped", o => { o.Keys["k"] = r; o.CurrentKeyId = "z"; }),
            ("map bad key id", o => { o.Keys["bad id"] = r; o.CurrentKeyId = "bad id"; }),
            ("map null ref", o => { o.Keys["k"] = null!; o.CurrentKeyId = "k"; }),
            ("map bad secret name", o => { o.Keys["k"] = new AzureKeyVaultSecretReference("x/y"); o.CurrentKeyId = "k"; }),
            ("map bad version", o => { o.Keys["k"] = new AzureKeyVaultSecretReference("x", "../v"); o.CurrentKeyId = "k"; }),
            ("refresh too small", o => { o.SecretName = "s"; o.RefreshInterval = TimeSpan.FromMilliseconds(10); }),
            ("refresh negative", o => { o.SecretName = "s"; o.RefreshInterval = TimeSpan.FromSeconds(-5); }),
            ("refresh huge", o => { o.SecretName = "s"; o.RefreshInterval = TimeSpan.FromDays(31); }),
            ("activation negative", o => { o.SecretName = "s"; o.ActivationDelay = TimeSpan.FromSeconds(-1); }),
            ("activation huge", o => { o.SecretName = "s"; o.ActivationDelay = TimeSpan.FromDays(366); }),
            ("max versions zero", o => { o.SecretName = "s"; o.MaxVersions = 0; }),
            ("max versions huge", o => { o.SecretName = "s"; o.MaxVersions = 501; }),
            ("timeout zero", o => { o.SecretName = "s"; o.Timeout = TimeSpan.Zero; }),
            ("timeout infinite", o => { o.SecretName = "s"; o.Timeout = Timeout.InfiniteTimeSpan; }),
            ("timeout huge", o => { o.SecretName = "s"; o.Timeout = TimeSpan.FromHours(1); }),
        };
        return cases.Select(c => new object[] { c.Name, c.Configure });
    }

    [Theory]
    [MemberData(nameof(InvalidOptions))]
    public async Task InvalidOptions_Throw_WithoutCallingKeyVault(string name, Action<AzureKeyVaultPepperOptions> configure)
    {
        var o = new AzureKeyVaultPepperOptions();
        configure(o);
        var ex = await Assert.ThrowsAsync<ArgumentException>(() => AzureKeyVaultPepper.CreateAsync(_client, o));
        Assert.Equal("options", ex.ParamName);
        Assert.Empty(_client.Calls);
        _ = name;
    }

    [Fact]
    public async Task NullArguments_Throw()
    {
        await Assert.ThrowsAsync<ArgumentNullException>(() => AzureKeyVaultPepper.CreateAsync(null!, new AzureKeyVaultPepperOptions { SecretName = "s" }));
        await Assert.ThrowsAsync<ArgumentNullException>(() => AzureKeyVaultPepper.CreateAsync(_client, null!));
        Assert.Throws<ArgumentNullException>(() => AzureKeyVaultPepper.Create(_client, null!));
        Assert.Throws<ArgumentNullException>(() => new AzureKeyVaultSecretReference(null!));
    }

    [Fact]
    public async Task Options_AreCopied()
    {
        _client.AddVersion(Secret, Kv.NewKeyB64(), _clock.Now.AddDays(-30));
        var o = new AzureKeyVaultPepperOptions { SecretName = Secret, RefreshInterval = Timeout.InfiniteTimeSpan };
        AzureKeyVaultPepper pepper = await AzureKeyVaultPepper.CreateWithClockAsync(_client, o, () => _clock.Now, CancellationToken.None);
        o.SecretName = "other";
        o.RefreshInterval = TimeSpan.FromSeconds(1);

        _clock.Advance(TimeSpan.FromHours(1));
        _ = pepper.CurrentKeyId;
        Assert.Null(pepper.BackgroundRefresh);
    }
}
