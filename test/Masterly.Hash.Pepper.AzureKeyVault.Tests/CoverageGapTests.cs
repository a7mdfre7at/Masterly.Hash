using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Azure;
using Azure.Security.KeyVault.Secrets;
using Masterly.Hash.Pepper.AzureKeyVault;

namespace Masterly.Hash.Pepper.AzureKeyVault.Tests;

/// <summary>Edge paths not reached by the scenario tests.</summary>
public class CoverageGapTests
{
    private const string Secret = "password-pepper";
    private static readonly Uri VaultUri = new("https://fake-vault.vault.azure.net/");
    private static readonly byte[] Input = Encoding.UTF8.GetBytes("correct horse battery staple");

    private readonly TestClock _clock = new();

    [Fact]
    public void Exception_constructors_set_message_and_inner_exception()
    {
        var plain = new PepperUnavailableException();
        Assert.Equal("The Azure Key Vault pepper is unavailable.", plain.Message);
        Assert.Null(plain.InnerException);

        Assert.Equal("custom", new PepperUnavailableException("custom").Message);

        var inner = new TimeoutException();
        var wrapped = new PepperUnavailableException("outer", inner);
        Assert.Equal("outer", wrapped.Message);
        Assert.Same(inner, wrapped.InnerException);
    }

    // ---------- map mode ----------

    [Fact]
    public async Task Map_InvalidSecondaryKeyId_IsRejected()
    {
        var client = new ScriptedSecretClient();
        var ex = await Assert.ThrowsAsync<ArgumentException>(() => Create(client, o =>
        {
            o.Keys["k"] = new AzureKeyVaultSecretReference("pepper-k");
            o.Keys["bad id"] = new AzureKeyVaultSecretReference("pepper-bad");
            o.CurrentKeyId = "k";
        }));

        Assert.Equal("options", ex.ParamName);
        Assert.StartsWith("Pepper key id 'bad id' must match ^[A-Za-z0-9-]{1,32}$.", ex.Message);
        Assert.Empty(client.Calls);
    }

    [Fact]
    public async Task Map_SecretReturnedAsDisabled_IsUnavailable_AndNotWrapped()
    {
        var client = new ScriptedSecretClient
        {
            Get = (name, version) => Secret_(name, version ?? "abc", Kv.NewKeyB64(), enabled: false),
        };

        var ex = await Assert.ThrowsAsync<PepperUnavailableException>(() => Create(client, o =>
        {
            o.Keys["k1"] = new AzureKeyVaultSecretReference("pepper-k1");
            o.CurrentKeyId = "k1";
        }));

        Assert.Equal("Secret 'pepper-k1' for pepper key id 'k1' is disabled.", ex.Message);
        Assert.Null(ex.InnerException);
    }

    [Fact]
    public async Task Map_NullResponse_IsReportedAsEmpty()
    {
        var client = new ScriptedSecretClient { Get = (_, _) => null };

        var ex = await Assert.ThrowsAsync<PepperUnavailableException>(() => Create(client, o =>
        {
            o.Keys["k1"] = new AzureKeyVaultSecretReference("pepper-k1");
            o.CurrentKeyId = "k1";
        }));

        Assert.Equal("Secret 'pepper-k1' for pepper key id 'k1' is empty or too long.", ex.Message);
    }

    [Fact]
    public async Task Map_EnabledFlagUnset_IsAccepted()
    {
        byte[] key = HmacPepper.GenerateKey();
        var client = new ScriptedSecretClient { Get = (name, version) => Secret_(name, "v1", Convert.ToBase64String(key), enabled: null) };

        AzureKeyVaultPepper pepper = await Create(client, o =>
        {
            o.Keys["k1"] = new AzureKeyVaultSecretReference("pepper-k1");
            o.CurrentKeyId = "k1";
        });

        Assert.Equal("k1", pepper.CurrentKeyId);
        Assert.Equal(HMACSHA256.HashData(key, Input), pepper.Apply("k1", Input));
    }

    // ---------- versions mode ----------

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public async Task RequestFailedWithoutErrorCode_SaysNoErrorCode(string? code)
    {
        var client = new FakeSecretClient();
        client.AddVersion(Secret, Kv.NewKeyB64(), _clock.Now.AddDays(-1));
        client.Fail = new RequestFailedException(500, "boom", code, null);

        var ex = await Assert.ThrowsAsync<PepperUnavailableException>(() => Create(client, o => o.SecretName = Secret));

        Assert.Equal("Azure Key Vault request failed (HTTP 500, no error code).", ex.Message);
        Assert.IsType<RequestFailedException>(ex.InnerException);
    }

    [Fact]
    public async Task LongErrorCode_IsTruncatedTo64Characters()
    {
        var client = new FakeSecretClient();
        client.AddVersion(Secret, Kv.NewKeyB64(), _clock.Now.AddDays(-1));
        string code = "Code-" + new string('x', 100);
        client.Fail = new RequestFailedException(429, "slow down", code, null);

        var ex = await Assert.ThrowsAsync<PepperUnavailableException>(() => Create(client, o => o.SecretName = Secret));

        Assert.Equal($"Azure Key Vault request failed (HTTP 429, {code.Substring(0, 64)}).", ex.Message);
    }

    [Theory]
    [InlineData("Code_with-all.allowed_0-9")]
    [InlineData("xyzABC")]
    public async Task ErrorCodeWithAllowedCharacters_IsKept(string code)
    {
        var client = new FakeSecretClient();
        client.AddVersion(Secret, Kv.NewKeyB64(), _clock.Now.AddDays(-1));
        client.Fail = new RequestFailedException(502, "bad gateway", code, null);

        var ex = await Assert.ThrowsAsync<PepperUnavailableException>(() => Create(client, o => o.SecretName = Secret));

        Assert.Equal($"Azure Key Vault request failed (HTTP 502, {code}).", ex.Message);
    }

    [Fact]
    public async Task Versions_VersionIdsThatAreNotValidKeyIds_AreSkippedAndReported()
    {
        string good = new string('a', 32);
        string tooLong = new string('b', 33); // a legal Key Vault version id, but longer than a pepper key id may be
        byte[] key = HmacPepper.GenerateKey();
        var client = new ScriptedSecretClient
        {
            Versions =
            {
                Properties(good, _clock.Now.AddDays(-2)),
                Properties(tooLong, _clock.Now.AddDays(-1)),
                Properties(null, _clock.Now.AddDays(-3)),
            },
            Get = (name, version) => Secret_(name, version!, Convert.ToBase64String(key)),
        };

        AzureKeyVaultPepper pepper = await Create(client, o => o.SecretName = Secret);

        Assert.Equal(good, pepper.CurrentKeyId);
        Assert.Equal(new[] { good }, pepper.KeyIds);
        Assert.False(pepper.IsKnownKey(tooLong));
        Assert.Equal(new[] { "list:" + Secret, "get:" + Secret + "/" + good }, client.Calls);

        var error = Assert.IsType<PepperUnavailableException>(pepper.LastRefreshError);
        Assert.StartsWith($"Secret '{Secret}' has a version id that is not a valid pepper key id; it was skipped.", error.Message);
        var all = Assert.IsType<AggregateException>(error.InnerException);
        Assert.Equal(2, all.InnerExceptions.Count);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Versions_NullGetResponseOrValue_IsSkippedAsEmpty(bool nullValue)
    {
        string good = new string('a', 32);
        string empty = new string('c', 32);
        byte[] key = HmacPepper.GenerateKey();
        Response<KeyVaultSecret>? emptyAnswer = nullValue ? Response.FromValue<KeyVaultSecret>(null!, new FakeResponse(200)) : null;
        var client = new ScriptedSecretClient
        {
            Versions = { Properties(good, _clock.Now.AddDays(-2)), Properties(empty, _clock.Now.AddDays(-1)) },
            Get = (name, version) => version == empty ? emptyAnswer : Secret_(name, version!, Convert.ToBase64String(key)),
        };

        AzureKeyVaultPepper pepper = await Create(client, o => o.SecretName = Secret);

        Assert.Equal(good, pepper.CurrentKeyId);
        Assert.False(pepper.IsKnownKey(empty));
        Assert.Equal($"Secret '{Secret}' version '{empty}' is empty or too long. It was skipped.", pepper.LastRefreshError!.Message);
    }

    [Fact]
    public async Task Versions_WithoutCreatedOn_SortByVersionDescending_AndCountAsActive()
    {
        string a = new string('a', 32);
        string b = new string('b', 32);
        var client = new ScriptedSecretClient
        {
            Versions = { Properties(a, null), Properties(b, null) },
            Get = (name, version) => Secret_(name, version!, Kv.NewKeyB64()),
        };

        AzureKeyVaultPepper pepper = await Create(client, o => o.SecretName = Secret);

        Assert.Equal(new[] { b, a }, pepper.KeyIds);
        Assert.Equal(b, pepper.CurrentKeyId);
        Assert.Null(pepper.LastRefreshError);
    }

    [Fact]
    public async Task Versions_ValidityWindow_IsHonoured()
    {
        string notYet = new string('d', 32);
        string expired = new string('e', 32);
        string inWindow = new string('f', 32);
        var client = new ScriptedSecretClient
        {
            Versions =
            {
                Properties(notYet, _clock.Now.AddDays(-1), notBefore: _clock.Now.AddDays(1)),
                Properties(expired, _clock.Now.AddDays(-2), expiresOn: _clock.Now),
                Properties(inWindow, _clock.Now.AddDays(-3), notBefore: _clock.Now.AddDays(-3), expiresOn: _clock.Now.AddDays(3)),
            },
            Get = (name, version) => Secret_(name, version!, Kv.NewKeyB64()),
        };

        AzureKeyVaultPepper pepper = await Create(client, o => o.SecretName = Secret);

        // Unusable versions stay in the ring (existing hashes keep verifying) but are never chosen as current.
        Assert.Equal(inWindow, pepper.CurrentKeyId);
        Assert.Equal(new[] { notYet, expired, inWindow }, pepper.KeyIds);
    }

    [Fact]
    public async Task FailedRefresh_WithShortRefreshInterval_RetriesAfterTheInterval()
    {
        var client = new FakeSecretClient();
        client.AddVersion(Secret, Kv.NewKeyB64(), _clock.Now.AddDays(-1));
        AzureKeyVaultPepper pepper = await Create(client, o =>
        {
            o.SecretName = Secret;
            o.RefreshInterval = TimeSpan.FromSeconds(1);
        });

        client.Fail = new RequestFailedException(503, "down", "ServiceUnavailable", null);
        await Assert.ThrowsAsync<PepperUnavailableException>(() => pepper.RefreshAsync());
        Assert.NotNull(pepper.LastRefreshError);
        int lists = client.ListCalls;

        // The retry is scheduled after the (shorter) refresh interval, not after FailedRefreshRetry.
        client.Fail = null;
        _clock.Advance(TimeSpan.FromSeconds(2));
        Assert.NotNull(pepper.CurrentKeyId);
        await Kv.Settle(pepper);

        Assert.Equal(lists + 1, client.ListCalls);
        Assert.Null(pepper.LastRefreshError);
        Assert.Equal(_clock.Now, pepper.LastRefreshed);
    }

    private Task<AzureKeyVaultPepper> Create(SecretClient client, Action<AzureKeyVaultPepperOptions> configure)
    {
        var options = new AzureKeyVaultPepperOptions();
        configure(options);
        return AzureKeyVaultPepper.CreateWithClockAsync(client, options, () => _clock.Now, CancellationToken.None);
    }

    private static SecretProperties Properties(string? version, DateTimeOffset? createdOn, DateTimeOffset? notBefore = null, DateTimeOffset? expiresOn = null)
    {
        SecretProperties props = SecretModelFactory.SecretProperties(
            id: new Uri(VaultUri, $"secrets/{Secret}/{version ?? "none"}"), vaultUri: VaultUri, name: Secret, version: version,
            managed: false, keyId: null, createdOn: createdOn, updatedOn: createdOn, recoveryLevel: "Recoverable+Purgeable");
        props.Enabled = true;
        props.NotBefore = notBefore;
        props.ExpiresOn = expiresOn;
        return props;
    }

    private static Response<KeyVaultSecret> Secret_(string name, string version, string value, bool? enabled = true)
    {
        SecretProperties props = SecretModelFactory.SecretProperties(
            id: new Uri(VaultUri, $"secrets/{name}/{version}"), vaultUri: VaultUri, name: name, version: version,
            managed: false, keyId: null, createdOn: null, updatedOn: null, recoveryLevel: "Recoverable+Purgeable");
        props.Enabled = enabled;
        return Response.FromValue(SecretModelFactory.KeyVaultSecret(props, value), new FakeResponse(200));
    }

    /// <summary>A Key Vault whose listing and reads are scripted per test, including answers a real vault never sends.</summary>
    private sealed class ScriptedSecretClient : SecretClient
    {
        public List<SecretProperties> Versions { get; } = new();

        public Func<string, string?, Response<KeyVaultSecret>?> Get { get; set; } = (_, _) => throw new InvalidOperationException("No reads expected.");

        public List<string> Calls { get; } = new();

        public override AsyncPageable<SecretProperties> GetPropertiesOfSecretVersionsAsync(string name, CancellationToken cancellationToken = default)
        {
            Calls.Add("list:" + name);
            return AsyncPageable<SecretProperties>.FromPages(new[] { Page<SecretProperties>.FromValues(Versions, null, new FakeResponse(200)) });
        }

        public override Task<Response<KeyVaultSecret>> GetSecretAsync(string name, string? version = null, CancellationToken cancellationToken = default)
        {
            Calls.Add("get:" + name + "/" + (version ?? "latest"));
            return Task.FromResult(Get(name, version)!);
        }
    }
}
