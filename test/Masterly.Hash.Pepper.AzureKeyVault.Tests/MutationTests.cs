using System;
using System.Collections.Generic;
using System.Reflection;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Azure;
using Azure.Security.KeyVault.Secrets;
using Masterly.Hash.Pepper.AzureKeyVault;

namespace Masterly.Hash.Pepper.AzureKeyVault.Tests;

/// <summary>Exact boundaries, messages and side effects that the scenario tests do not pin down.</summary>
public class MutationTests
{
    private const string Secret = "password-pepper";
    private static readonly Uri TestVaultUri = new("https://fake-vault.vault.azure.net/");
    private static readonly byte[] Input = Encoding.UTF8.GetBytes("correct horse battery staple");

    private readonly FakeSecretClient _client = new();
    private readonly TestClock _clock = new();

    private Task<AzureKeyVaultPepper> Versions(Action<AzureKeyVaultPepperOptions>? configure = null) =>
        Kv.Create(_client, _clock, o =>
        {
            o.SecretName = Secret;
            o.RefreshInterval = TimeSpan.FromMinutes(5);
            configure?.Invoke(o);
        });

    // ---------- options validation: messages and exact limits ----------

    public static TheoryData<string, Action<AzureKeyVaultPepperOptions>> InvalidOptionMessages() => new()
    {
        { "Set exactly one of SecretName (versions mode) and Keys (map mode).", o => { } },
        { "CurrentKeyId must match ^[A-Za-z0-9-]{1,32}$.", o => { o.SecretName = "s"; o.CurrentKeyId = "bad id"; } },
        { "SecretName must be 1-127 letters, digits or '-'.", o => o.SecretName = "a_b" },
        { "In map mode CurrentKeyId is required and must be a key in Keys.", o => o.Keys["k"] = new AzureKeyVaultSecretReference("s") },
        { "Secret reference for pepper key id 'k' has an invalid name or version.", o => { o.Keys["k"] = new AzureKeyVaultSecretReference("x/y"); o.CurrentKeyId = "k"; } },
        { "RefreshInterval must be between 1 second and 30 days, or Timeout.InfiniteTimeSpan.", o => { o.SecretName = "s"; o.RefreshInterval = TimeSpan.FromDays(30) + TimeSpan.FromTicks(1); } },
        { "ActivationDelay must be between zero and 365 days.", o => { o.SecretName = "s"; o.ActivationDelay = TimeSpan.FromDays(365) + TimeSpan.FromTicks(1); } },
        { "MaxVersions must be between 1 and 500.", o => { o.SecretName = "s"; o.MaxVersions = 501; } },
        { "Timeout must be greater than zero and at most 10 minutes.", o => { o.SecretName = "s"; o.Timeout = TimeSpan.FromMinutes(10) + TimeSpan.FromTicks(1); } },
    };

    [Theory]
    [MemberData(nameof(InvalidOptionMessages))]
    public async Task InvalidOptions_HaveDescriptiveMessages(string message, Action<AzureKeyVaultPepperOptions> configure)
    {
        var o = new AzureKeyVaultPepperOptions();
        configure(o);
        var ex = await Assert.ThrowsAsync<ArgumentException>(() => AzureKeyVaultPepper.CreateWithClockAsync(_client, o, () => _clock.Now, CancellationToken.None));
        Assert.Equal("options", ex.ParamName);
        Assert.Equal(message + " (Parameter 'options')", ex.Message);
        Assert.Empty(_client.Calls);
    }

    public static TheoryData<string, Action<AzureKeyVaultPepperOptions>> OptionsAtTheirLimits() => new()
    {
        { "refresh 30 days", o => o.RefreshInterval = TimeSpan.FromDays(30) },
        { "refresh 1 second", o => o.RefreshInterval = TimeSpan.FromSeconds(1) },
        { "activation 365 days", o => o.ActivationDelay = TimeSpan.FromDays(365) },
        { "activation zero", o => o.ActivationDelay = TimeSpan.Zero },
        { "max versions 1", o => o.MaxVersions = 1 },
        { "max versions 500", o => o.MaxVersions = 500 },
        { "timeout 10 minutes", o => o.Timeout = TimeSpan.FromMinutes(10) },
    };

    [Theory]
    [MemberData(nameof(OptionsAtTheirLimits))]
    public async Task Options_AtTheirLimits_AreAccepted(string name, Action<AzureKeyVaultPepperOptions> configure)
    {
        string v1 = _client.AddVersion(Secret, Kv.NewKeyB64(), _clock.Now.AddDays(-1));

        AzureKeyVaultPepper pepper = await Versions(configure);

        Assert.Equal(v1, pepper.CurrentKeyId);
        _ = name;
    }

    // ---------- synchronous Create is an initial load ----------

    [Fact]
    public void Create_Sync_WithASkippedVersion_SucceedsAndReportsTheProblem()
    {
        string good = _client.AddVersion(Secret, Kv.NewKeyB64(), DateTimeOffset.UtcNow.AddDays(-30));
        string bad = _client.AddVersion(Secret, "not base64 !!", DateTimeOffset.UtcNow.AddDays(-20));

        AzureKeyVaultPepper pepper = AzureKeyVaultPepper.Create(_client, new AzureKeyVaultPepperOptions { SecretName = Secret });

        Assert.Equal(good, pepper.CurrentKeyId);
        Assert.Equal($"Secret '{Secret}' version '{bad}' is not valid base64. It was skipped.", pepper.LastRefreshError!.Message);
    }

    // ---------- Apply ----------

    [Fact]
    public async Task Apply_NullInput_ThrowsArgumentNull_EvenWhenNoRingIsLoaded()
    {
        string v1 = _client.AddVersion(Secret, Kv.NewKeyB64(), _clock.Now.AddDays(-30));
        AzureKeyVaultPepper pepper = await Versions();
        _client.SetEnabled(Secret, v1, false);
        await Assert.ThrowsAsync<PepperUnavailableException>(() => pepper.RefreshAsync());

        var ex = Assert.Throws<ArgumentNullException>(() => pepper.Apply("unknown", null!));
        Assert.Equal("input", ex.ParamName);
    }

    [Fact]
    public async Task Apply_NullInput_DoesNotStartABackgroundRefresh()
    {
        string v1 = _client.AddVersion(Secret, Kv.NewKeyB64(), _clock.Now.AddDays(-30));
        AzureKeyVaultPepper pepper = await Versions();
        _clock.Advance(TimeSpan.FromMinutes(6));

        var ex = Assert.Throws<ArgumentNullException>(() => pepper.Apply(v1, null!));

        Assert.Equal("input", ex.ParamName);
        Assert.Null(pepper.BackgroundRefresh);
        Assert.Equal(1, _client.ListCalls);
    }

    [Fact]
    public async Task Apply_StartsABackgroundRefresh_WhenDue()
    {
        string v1 = _client.AddVersion(Secret, Kv.NewKeyB64(), _clock.Now.AddDays(-30));
        AzureKeyVaultPepper pepper = await Versions();
        _clock.Advance(TimeSpan.FromMinutes(6));

        Assert.NotNull(pepper.Apply(v1, Input));
        Assert.NotNull(pepper.BackgroundRefresh);
        await Kv.Settle(pepper);

        Assert.Equal(2, _client.ListCalls);
        Assert.Equal(_clock.Now, pepper.LastRefreshed);
    }

    [Fact]
    public async Task Apply_UnknownKey_WithNoRingLoaded_SaysWhichKey()
    {
        string v1 = _client.AddVersion(Secret, Kv.NewKeyB64(), _clock.Now.AddDays(-30));
        AzureKeyVaultPepper pepper = await Versions();
        _client.SetEnabled(Secret, v1, false);
        await Assert.ThrowsAsync<PepperUnavailableException>(() => pepper.RefreshAsync());

        var ex = Assert.Throws<KeyNotFoundException>(() => pepper.Apply("unknown", Input));
        Assert.Equal("Unknown pepper key 'unknown'.", ex.Message);
    }

    [Fact]
    public async Task Apply_RemovedKey_IsAcceptedAtExactlyTheGraceLimit()
    {
        string v1 = _client.AddVersion(Secret, Kv.NewKeyB64(), _clock.Now.AddDays(-30));
        _client.AddVersion(Secret, Kv.NewKeyB64(), _clock.Now.AddDays(-20));
        AzureKeyVaultPepper pepper = await Versions();
        byte[] expected = pepper.Apply(v1, Input);

        _client.SetEnabled(Secret, v1, false);
        await pepper.RefreshAsync();

        _clock.Advance(AzureKeyVaultPepper.RemovedKeyGrace);
        Assert.Equal(expected, pepper.Apply(v1, Input));

        _clock.Advance(TimeSpan.FromTicks(1));
        Assert.Throws<KeyNotFoundException>(() => pepper.Apply(v1, Input));
    }

    // ---------- load errors and messages ----------

    [Fact]
    public async Task UnexpectedException_IsWrapped_WithMessage()
    {
        _client.AddVersion(Secret, Kv.NewKeyB64(), _clock.Now.AddDays(-1));
        var inner = new InvalidOperationException("credential unavailable");
        _client.Fail = inner;

        var ex = await Assert.ThrowsAsync<PepperUnavailableException>(() => Versions());

        Assert.Equal("Loading pepper keys from Azure Key Vault failed.", ex.Message);
        Assert.Same(inner, ex.InnerException);
    }

    [Theory]
    [InlineData("XYZ")]
    [InlineData("Z")]
    [InlineData("az09AZ")]
    public async Task ErrorCode_WithBoundaryLetters_IsKept(string code)
    {
        _client.AddVersion(Secret, Kv.NewKeyB64(), _clock.Now.AddDays(-1));
        _client.Fail = new RequestFailedException(500, "boom", code, null);

        var ex = await Assert.ThrowsAsync<PepperUnavailableException>(() => Versions());

        Assert.Equal($"Azure Key Vault request failed (HTTP 500, {code}).", ex.Message);
    }

    [Fact]
    public async Task ErrorCode_WithForbiddenCharacters_IsReplaced()
    {
        _client.AddVersion(Secret, Kv.NewKeyB64(), _clock.Now.AddDays(-1));
        _client.Fail = new RequestFailedException(500, "boom", "evil\r\ncode", null);

        var ex = await Assert.ThrowsAsync<PepperUnavailableException>(() => Versions());

        Assert.Equal("Azure Key Vault request failed (HTTP 500, invalid error code).", ex.Message);
    }

    [Fact]
    public async Task ErrorCode_OfExactly64Characters_IsKeptWhole()
    {
        _client.AddVersion(Secret, Kv.NewKeyB64(), _clock.Now.AddDays(-1));
        string code = new string('Q', 64);
        _client.Fail = new RequestFailedException(500, "boom", code, null);

        var ex = await Assert.ThrowsAsync<PepperUnavailableException>(() => Versions());

        Assert.Equal($"Azure Key Vault request failed (HTTP 500, {code}).", ex.Message);
    }

    [Fact]
    public async Task AllEnabledVersionsMalformed_FailsWithCombinedMessage()
    {
        string bad = _client.AddVersion(Secret, "not base64 !!", _clock.Now.AddDays(-1));

        var ex = await Assert.ThrowsAsync<PepperUnavailableException>(() => Versions());

        Assert.Equal($"Secret '{Secret}' has no enabled version holding a valid pepper key. 1 more problem(s); see InnerException.", ex.Message);
        var all = Assert.IsType<AggregateException>(ex.InnerException);
        Assert.Equal(2, all.InnerExceptions.Count);
        Assert.Equal($"Secret '{Secret}' version '{bad}' is not valid base64. It was skipped.", all.InnerExceptions[1].Message);
    }

    [Fact]
    public async Task ThreeProblems_AreCountedAsTwoMore()
    {
        _client.AddVersion(Secret, "not base64 !!", _clock.Now.AddDays(-2));
        _client.AddVersion(Secret, Convert.ToBase64String(new byte[8]), _clock.Now.AddDays(-1));

        var ex = await Assert.ThrowsAsync<PepperUnavailableException>(() => Versions());

        Assert.Equal($"Secret '{Secret}' has no enabled version holding a valid pepper key. 2 more problem(s); see InnerException.", ex.Message);
    }

    [Fact]
    public async Task NoEnabledVersions_FailsWithExactMessage()
    {
        _client.AddVersion(Secret, Kv.NewKeyB64(), _clock.Now.AddDays(-1), enabled: false);

        var ex = await Assert.ThrowsAsync<PepperUnavailableException>(() => Versions());

        Assert.Equal($"Secret '{Secret}' has no enabled versions.", ex.Message);
    }

    [Fact]
    public async Task AllExpired_FailsWithExactMessage()
    {
        _client.AddVersion(Secret, Kv.NewKeyB64(), _clock.Now.AddDays(-2), expiresOn: _clock.Now.AddDays(-1));

        var ex = await Assert.ThrowsAsync<PepperUnavailableException>(() => Versions());

        Assert.Equal($"Secret '{Secret}' has no version that is enabled, active and not expired.", ex.Message);
    }

    [Fact]
    public async Task NotBefore_ExactlyNow_IsUsable()
    {
        string v1 = _client.AddVersion(Secret, Kv.NewKeyB64(), _clock.Now.AddDays(-1), notBefore: _clock.Now);

        AzureKeyVaultPepper pepper = await Versions();

        Assert.Equal(v1, pepper.CurrentKeyId);
        Assert.Null(pepper.LastRefreshError);
    }

    [Theory]
    [InlineData(403, "Forbidden")]
    [InlineData(404, "SecretNotFound")]
    public async Task UnreadableNewVersion_IsSkipped_AndTheRestIsApplied(int status, string code)
    {
        string v1 = _client.AddVersion(Secret, Kv.NewKeyB64(), _clock.Now.AddDays(-30));
        string v2 = _client.AddVersion(Secret, Kv.NewKeyB64(), _clock.Now.AddDays(-20));
        AzureKeyVaultPepper pepper = await Versions();
        string v3 = _client.AddVersion(Secret, Kv.NewKeyB64(), _clock.Now.AddDays(-1));
        _client.SetEnabled(Secret, v1, false);
        _client.GetFailure = v => v == v3 ? new RequestFailedException(status, "nope", code, null) : null;

        var ex = await Assert.ThrowsAsync<PepperUnavailableException>(() => pepper.RefreshAsync());

        Assert.Equal($"Secret '{Secret}' version '{v3}' could not be read (HTTP {status}, {code}); it was skipped.", ex.Message);
        Assert.Equal(status, Assert.IsType<RequestFailedException>(ex.InnerException).Status);
        // The listing answered, so the revocation of v1 is applied despite the unreadable version.
        Assert.False(pepper.IsKnownKey(v1));
        Assert.False(pepper.IsKnownKey(v3));
        Assert.Equal(v2, pepper.CurrentKeyId);
    }

    [Fact]
    public async Task SecretDeletedWhileListing_RevokesVersionsFromEarlierPages()
    {
        string v1 = new string('a', 32);
        var client = new GatedSecretClient
        {
            Versions = { Properties(v1, _clock.Now.AddDays(-30)) },
            ListFailure = new RequestFailedException(404, "gone", "SecretNotFound", null),
        };

        var ex = await Assert.ThrowsAsync<PepperUnavailableException>(() => CreateVersions(client));

        Assert.Equal($"Azure Key Vault request failed (HTTP 404, SecretNotFound): secret '{Secret}' was not found.", ex.Message);
        Assert.Same(client.ListFailure, ex.InnerException);
        Assert.Empty(client.Gets);
    }

    [Fact]
    public async Task RevokedVersion_IsZeroedInTheCache()
    {
        string v1 = _client.AddVersion(Secret, Kv.NewKeyB64(), _clock.Now.AddDays(-30));
        string v2 = _client.AddVersion(Secret, Kv.NewKeyB64(), _clock.Now.AddDays(-20));
        AzureKeyVaultPepper pepper = await Versions();
        FieldInfo field = typeof(AzureKeyVaultPepper).GetField("_versionCache", BindingFlags.NonPublic | BindingFlags.Instance)!;
        var cache = (Dictionary<string, byte[]>)field.GetValue(pepper)!;
        byte[] cachedV1 = cache[v1];
        byte[] cachedV2 = cache[v2];
        Assert.Contains(cachedV1, b => b != 0);

        _client.SetEnabled(Secret, v1, false);
        await pepper.RefreshAsync();

        Assert.False(cache.ContainsKey(v1));
        Assert.All(cachedV1, b => Assert.Equal(0, b));
        Assert.Contains(cachedV2, b => b != 0);
    }

    // ---------- library awaits never resume on the caller's synchronization context ----------

    [Fact]
    public async Task VersionsLoad_PendingListing_DoesNotResumeOnCallerContext()
    {
        var client = new GatedSecretClient { Versions = { Properties(new string('a', 32), _clock.Now.AddDays(-30)) }, ListGate = new(TaskCreationOptions.RunContinuationsAsynchronously) };

        int posts = await PostsWhileLoading(() => CreateVersions(client), client.ListGate);

        Assert.Equal(0, posts);
    }

    [Fact]
    public async Task VersionsLoad_PendingRead_DoesNotResumeOnCallerContext()
    {
        var client = new GatedSecretClient { Versions = { Properties(new string('a', 32), _clock.Now.AddDays(-30)) }, GetGate = new(TaskCreationOptions.RunContinuationsAsynchronously) };

        int posts = await PostsWhileLoading(() => CreateVersions(client), client.GetGate);

        Assert.Equal(0, posts);
    }

    [Fact]
    public async Task MapLoad_PendingRead_DoesNotResumeOnCallerContext()
    {
        var client = new GatedSecretClient { GetGate = new(TaskCreationOptions.RunContinuationsAsynchronously) };
        var options = new AzureKeyVaultPepperOptions { CurrentKeyId = "k1" };
        options.Keys["k1"] = new AzureKeyVaultSecretReference("pepper-k1");

        int posts = await PostsWhileLoading(
            () => AzureKeyVaultPepper.CreateWithClockAsync(client, options, () => _clock.Now, CancellationToken.None), client.GetGate);

        Assert.Equal(0, posts);
    }

    private static async Task<int> PostsWhileLoading(Func<Task<AzureKeyVaultPepper>> start, TaskCompletionSource gate)
    {
        var context = new CountingContext();
        SynchronizationContext? previous = SynchronizationContext.Current;
        Task<AzureKeyVaultPepper> load;
        SynchronizationContext.SetSynchronizationContext(context);
        try
        {
            load = start();
        }
        finally
        {
            SynchronizationContext.SetSynchronizationContext(previous);
        }

        Assert.False(load.IsCompleted); // suspended on the gated Key Vault call, with the caller's context current
        gate.SetResult();
        AzureKeyVaultPepper pepper = await load;
        Assert.NotNull(pepper.CurrentKeyId);
        return context.Posts;
    }

    private Task<AzureKeyVaultPepper> CreateVersions(SecretClient client) =>
        AzureKeyVaultPepper.CreateWithClockAsync(client, new AzureKeyVaultPepperOptions { SecretName = Secret }, () => _clock.Now, CancellationToken.None);

    private static SecretProperties Properties(string version, DateTimeOffset createdOn)
    {
        SecretProperties props = SecretModelFactory.SecretProperties(
            id: new Uri(TestVaultUri, $"secrets/{Secret}/{version}"), vaultUri: TestVaultUri, name: Secret, version: version,
            managed: false, keyId: null, createdOn: createdOn, updatedOn: createdOn, recoveryLevel: "Recoverable+Purgeable");
        props.Enabled = true;
        return props;
    }

    private sealed class CountingContext : SynchronizationContext
    {
        private int _posts;

        public int Posts => Volatile.Read(ref _posts);

        public override void Post(SendOrPostCallback d, object? state)
        {
            Interlocked.Increment(ref _posts);
            base.Post(d, state);
        }

        public override void Send(SendOrPostCallback d, object? state)
        {
            Interlocked.Increment(ref _posts);
            base.Send(d, state);
        }
    }

    /// <summary>
    /// Key Vault whose listing or reads can be held until a gate opens (without itself resuming on any context), and
    /// whose listing can fail after returning its versions.
    /// </summary>
    private sealed class GatedSecretClient : SecretClient
    {
        private readonly string _value = Kv.NewKeyB64();

        public List<SecretProperties> Versions { get; } = new();

        public TaskCompletionSource? ListGate { get; init; }

        public TaskCompletionSource? GetGate { get; init; }

        public Exception? ListFailure { get; init; }

        public List<string> Gets { get; } = new();

        public override AsyncPageable<SecretProperties> GetPropertiesOfSecretVersionsAsync(string name, CancellationToken cancellationToken = default) =>
            new GatedPageable(this);

        public override async Task<Response<KeyVaultSecret>> GetSecretAsync(string name, string? version = null, CancellationToken cancellationToken = default)
        {
            lock (Gets)
                Gets.Add(name + "/" + (version ?? "latest"));
            if (GetGate != null)
                await GetGate.Task.ConfigureAwait(false);
            SecretProperties props = SecretModelFactory.SecretProperties(
                id: new Uri(TestVaultUri, $"secrets/{name}/{version ?? "v"}"), vaultUri: TestVaultUri, name: name, version: version ?? "v",
                managed: false, keyId: null, createdOn: null, updatedOn: null, recoveryLevel: "Recoverable+Purgeable");
            props.Enabled = true;
            return Response.FromValue(SecretModelFactory.KeyVaultSecret(props, _value), new FakeResponse(200));
        }

        private sealed class GatedPageable(GatedSecretClient owner) : AsyncPageable<SecretProperties>
        {
            public override IAsyncEnumerable<Page<SecretProperties>> AsPages(string? continuationToken = null, int? pageSizeHint = null) =>
                throw new NotSupportedException();

            public override async IAsyncEnumerator<SecretProperties> GetAsyncEnumerator(CancellationToken cancellationToken = default)
            {
                if (owner.ListGate != null)
                    await owner.ListGate.Task.ConfigureAwait(false);
                foreach (SecretProperties p in owner.Versions)
                    yield return p;
                if (owner.ListFailure != null)
                    throw owner.ListFailure;
            }
        }
    }
}
