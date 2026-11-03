using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Azure;
using Azure.Core;
using Azure.Security.KeyVault.Secrets;
using Masterly.Hash.Pepper.AzureKeyVault;

namespace Masterly.Hash.Pepper.AzureKeyVault.Tests;

/// <summary>In-memory Key Vault. SecretClient's methods are virtual for exactly this purpose.</summary>
internal sealed class FakeSecretClient : SecretClient
{
    private static readonly Uri FakeVaultUri = new("https://fake-vault.vault.azure.net/");
    private readonly object _gate = new();
    private readonly Dictionary<string, List<(SecretProperties Properties, string Value)>> _secrets = new(StringComparer.OrdinalIgnoreCase);
    private int _versionCounter;

    public ConcurrentQueue<string> Calls { get; } = new();

    /// <summary>When set, every call throws this.</summary>
    public Exception? Fail { get; set; }

    /// <summary>When set, every call waits for this before answering.</summary>
    public Func<CancellationToken, Task>? Delay { get; set; }

    public int ListCalls => Calls.Count(c => c.StartsWith("list:", StringComparison.Ordinal));

    public int GetCalls => Calls.Count(c => c.StartsWith("get:", StringComparison.Ordinal));

    /// <summary>Adds a new version and returns its 32-hex-character id, like Key Vault does.</summary>
    public string AddVersion(string name, string value, DateTimeOffset createdOn, bool enabled = true, DateTimeOffset? notBefore = null, DateTimeOffset? expiresOn = null)
    {
        lock (_gate)
        {
            string version = (++_versionCounter).ToString("x32");
            SecretProperties props = SecretModelFactory.SecretProperties(
                id: new Uri(FakeVaultUri, $"secrets/{name}/{version}"), vaultUri: FakeVaultUri, name: name, version: version,
                managed: false, keyId: null, createdOn: createdOn, updatedOn: createdOn, recoveryLevel: "Recoverable+Purgeable");
            props.Enabled = enabled;
            props.NotBefore = notBefore;
            props.ExpiresOn = expiresOn;
            if (!_secrets.TryGetValue(name, out var list))
                _secrets[name] = list = new();
            list.Add((props, value));
            return version;
        }
    }

    public void SetEnabled(string name, string version, bool enabled)
    {
        lock (_gate)
            _secrets[name].Single(v => v.Properties.Version == version).Properties.Enabled = enabled;
    }

    public void Delete(string name, string version)
    {
        lock (_gate)
            _secrets[name].RemoveAll(v => v.Properties.Version == version);
    }

    /// <summary>Deletes the whole secret, so listing its versions answers 404.</summary>
    public void DeleteSecret(string name)
    {
        lock (_gate)
            _secrets.Remove(name);
    }

    /// <summary>When set and it returns an exception for a version id, getting that version throws it.</summary>
    public Func<string, Exception?>? GetFailure { get; set; }

    public override AsyncPageable<SecretProperties> GetPropertiesOfSecretVersionsAsync(string name, CancellationToken cancellationToken = default)
    {
        Calls.Enqueue("list:" + name);
        return new DelayedPageable(this, name, cancellationToken);
    }

    public override async Task<Response<KeyVaultSecret>> GetSecretAsync(string name, string? version = null, CancellationToken cancellationToken = default)
    {
        Calls.Enqueue("get:" + name + "/" + (version ?? "latest"));
        await Gate(cancellationToken);
        if (version != null && GetFailure?.Invoke(version) is Exception failure)
            throw failure;
        lock (_gate)
        {
            if (!_secrets.TryGetValue(name, out var list) || list.Count == 0)
                throw new RequestFailedException(404, "A secret with (name/id) " + name + " was not found in this key vault.", "SecretNotFound", null);
            var entry = version == null ? list.OrderBy(v => v.Properties.CreatedOn).Last() : list.SingleOrDefault(v => v.Properties.Version == version);
            if (entry.Properties == null)
                throw new RequestFailedException(404, "Secret version not found.", "SecretNotFound", null);
            if (entry.Properties.Enabled != true)
                throw new RequestFailedException(403, "Operation get is not allowed on a disabled secret.", "Forbidden", null);
            return Response.FromValue(SecretModelFactory.KeyVaultSecret(entry.Properties, entry.Value), new FakeResponse(200));
        }
    }

    public override Response<KeyVaultSecret> GetSecret(string name, string? version = null, CancellationToken cancellationToken = default) =>
        throw new NotSupportedException("The pepper must use the async API.");

    public override Pageable<SecretProperties> GetPropertiesOfSecretVersions(string name, CancellationToken cancellationToken = default) =>
        throw new NotSupportedException("The pepper must use the async API.");

    private async Task Gate(CancellationToken ct)
    {
        if (Delay != null)
            await Delay(ct);
        if (Fail != null)
            throw Fail;
    }

    private List<SecretProperties> Snapshot(string name)
    {
        lock (_gate)
        {
            if (!_secrets.TryGetValue(name, out var list))
                throw new RequestFailedException(404, "Secret not found: " + name, "SecretNotFound", null);
            // Key Vault does not return values when listing versions; it returns properties only.
            return list.Select(v => v.Properties).ToList();
        }
    }

    private sealed class DelayedPageable(FakeSecretClient owner, string name, CancellationToken ct) : AsyncPageable<SecretProperties>
    {
        public override async IAsyncEnumerable<Page<SecretProperties>> AsPages(string? continuationToken = null, int? pageSizeHint = null)
        {
            await owner.Gate(ct);
            List<SecretProperties> all = owner.Snapshot(name);
            // Two pages, to exercise paging.
            int half = all.Count / 2;
            yield return Page<SecretProperties>.FromValues(all.Take(half).ToList(), "next", new FakeResponse(200));
            yield return Page<SecretProperties>.FromValues(all.Skip(half).ToList(), null, new FakeResponse(200));
        }
    }
}

internal sealed class FakeResponse(int status) : Response
{
    public override int Status => status;
    public override string ReasonPhrase => "OK";
    public override System.IO.Stream? ContentStream { get; set; }
    public override string ClientRequestId { get; set; } = Guid.NewGuid().ToString();
    public override void Dispose() { }
    protected override bool ContainsHeader(string name) => false;
    protected override IEnumerable<HttpHeader> EnumerateHeaders() => Array.Empty<HttpHeader>();
    protected override bool TryGetHeader(string name, [NotNullWhen(true)] out string? value) { value = null; return false; }
    protected override bool TryGetHeaderValues(string name, [NotNullWhen(true)] out IEnumerable<string>? values) { values = null; return false; }
}

/// <summary>Manually advanced clock.</summary>
internal sealed class TestClock
{
    public DateTimeOffset Now { get; set; } = new(2026, 11, 2, 12, 0, 0, TimeSpan.Zero);
    public void Advance(TimeSpan by) => Now += by;
}

internal static class Kv
{
    public static string NewKeyB64() => Convert.ToBase64String(HmacPepper.GenerateKey());

    public static Task<AzureKeyVaultPepper> Create(FakeSecretClient client, TestClock clock, Action<AzureKeyVaultPepperOptions> configure)
    {
        var options = new AzureKeyVaultPepperOptions();
        configure(options);
        return AzureKeyVaultPepper.CreateWithClockAsync(client, options, () => clock.Now, CancellationToken.None);
    }

    public static PasswordHasher Hasher(IPasswordPepper pepper) =>
        new(new PasswordHasherOptions { DefaultProfile = HashProfile.Argon2id("test", 64, 1), AllowWeakProfiles = true, Pepper = pepper });

    /// <summary>Waits for any refresh the last call started in the background.</summary>
    public static async Task Settle(AzureKeyVaultPepper pepper)
    {
        Task? t = pepper.BackgroundRefresh;
        if (t != null)
            await t;
    }
}
