---
title: Azure Key Vault Pepper
sidebar_label: Azure Key Vault
description: Keep the pepper keys as Azure Key Vault secrets, load and refresh them in memory, rotate by adding a secret version and revoke by disabling one.
---

`Masterly.Hash.Pepper.AzureKeyVault` is an `IPasswordPepper` whose keys are stored as Azure Key Vault secrets. Key Vault cannot compute HMACs, so the provider loads the keys into application memory, caches them, refreshes them in the background and computes HMAC-SHA256 locally. After the initial load, hashing and verifying never wait on Key Vault.

```bash
dotnet add package Masterly.Hash.Pepper.AzureKeyVault
```

The package targets .NET 8 and depends on `Azure.Security.KeyVault.Secrets` 4.12.0, which brings in `Azure.Core` 1.64.0. You also need a credential, usually `DefaultAzureCredential` from `Azure.Identity`:

```bash
dotnet add package Azure.Identity
```

Use a current `Azure.Identity` (1.21.0 or later). With older versions, `DefaultAzureCredential` is defined in both `Azure.Core` and `Azure.Identity`, and the build fails with `CS0433`.

:::warning

This provider has a different trust model from the [HashiCorp Vault](./hashicorp-vault.md) and [AWS KMS](./aws-kms.md) peppers. There, the key never leaves the service. Here, the key is **in your process memory** while the application runs. A database leak alone does not expose it, but a memory dump, a debugger or code execution on the host does.

:::

## When to use it

Use the Key Vault pepper when:

- Your application runs in Azure and already uses Key Vault for secrets.
- You want login availability and latency to be independent of the secret store. Key Vault is needed at startup and for refreshes, not per login.
- You want rotation and revocation driven from Key Vault, without redeploying: add a secret version to rotate, disable one to revoke.

Consider something else when:

- A memory dump of the application host must not reveal the pepper. Use the Vault or KMS provider.
- You cannot start the application without Key Vault. `CreateAsync` throws if it cannot load a usable current key.

Because the HMAC is local, this provider works well with the synchronous API, including the [ASP.NET Core Identity](./aspnetcore-identity.md) adapter. [Peppers](./peppers.md) compares the options.

## How it works

The provider has two modes. Set exactly one of `SecretName` and `Keys`.

**Versions mode** (`SecretName`). One secret holds every pepper key. Each **enabled version** of that secret is a key, and its 32-character version id is the pepper key id stored in the hash: `$mh$p=2026a,k=3f1c9d0e8a7b4c2d9e6f1a0b5c4d3e2f$...`. You rotate by adding a version and revoke by disabling one. The version list is re-read in the background every `RefreshInterval`.

**Map mode** (`Keys`). You map your own key ids to secrets, optionally pinned to versions. The keys are loaded once, when the pepper is created, and never refreshed.

In both modes:

1. **`CreateAsync` loads the keys** and returns a ready pepper, or throws `PepperUnavailableException`.
2. **Every secret value is decoded** as base64 and must hold at least 32 bytes (`AzureKeyVaultPepper.MinKeyLength`).
3. **`Apply` and `ApplyAsync` compute HMAC-SHA256 locally** with the cached key. `ApplyAsync` completes synchronously.
4. **`IsKnownKey` checks the cached ring** and never calls Key Vault.

## Set up Azure

**1. Create the secret.** The value must be the base64 encoding of a random key of at least 32 bytes:

```bash title="Azure CLI"
az keyvault secret set --vault-name my-vault --name password-pepper \
  --value "$(openssl rand -base64 32)"
```

`masterly-hash pepper generate` prints a suitable value too (see [Command-Line Tool](./command-line-tool.md)), and so does `Convert.ToBase64String(HmacPepper.GenerateKey())` in code. Never set an expiry date on a version unless you rotate before it; see [What makes a version current](#what-makes-a-version-current).

**2. Give the application identity read access to secrets only.** Versions mode needs Get and List on secrets; map mode needs Get. On a vault that uses the Azure RBAC permission model, assign **Key Vault Secrets User**, scoped to the one secret:

```bash title="Azure CLI"
VAULT_ID=$(az keyvault show --name my-vault --query id --output tsv)

az role assignment create \
  --role "Key Vault Secrets User" \
  --assignee <application-principal-id> \
  --scope "$VAULT_ID/secrets/password-pepper"
```

With the older access-policy model instead:

```bash
az keyvault set-policy --name my-vault --object-id <application-principal-id> \
  --secret-permissions get list
```

Do not give the application Set, Delete or Purge on secrets. Rotation and revocation are operator tasks.

**3. Use a managed identity** for the application, so no client secret is needed to reach Key Vault. `DefaultAzureCredential` picks it up.

Turn on soft-delete and purge protection on the vault, so a deleted pepper secret can be recovered. Losing the pepper means losing every hash made with it.

## Versions mode

```csharp title="Program.cs"
using System;
using System.Threading;
using Azure.Identity;
using Azure.Security.KeyVault.Secrets;
using Masterly.Hash;
using Masterly.Hash.Pepper.AzureKeyVault;

SecretClient secretClient = new SecretClient(new Uri("https://my-vault.vault.azure.net/"), new DefaultAzureCredential());

using CancellationTokenSource startup = new CancellationTokenSource(TimeSpan.FromMinutes(1));
AzureKeyVaultPepper pepper = await AzureKeyVaultPepper.CreateAsync(secretClient, new AzureKeyVaultPepperOptions
{
    SecretName = "password-pepper",
}, startup.Token);

PasswordHasher hasher = new PasswordHasher(new PasswordHasherOptions { Pepper = pepper });
```

`CreateAsync` validates and copies the options, then loads the keys. It throws `ArgumentException` for invalid options without calling Key Vault, and `PepperUnavailableException` when it cannot load a usable current key. Call it at startup. `AzureKeyVaultPepper.Create(client, options)` is the synchronous version, for startup code that cannot await; it blocks on the initial load.

If the initial load finds a usable current key but has to skip some versions (an invalid value, or one it cannot read), `CreateAsync` succeeds and reports the skipped versions through `LastRefreshError`.

### What makes a version current

At every load and refresh, the provider lists the secret's versions and builds a key ring:

1. **Only enabled versions are loaded.** Disabled versions are not in the ring.
2. **The newest `MaxVersions` enabled versions are kept** (default 25), ordered by `CreatedOn`, newest first. Older ones are dropped.
3. **Each kept version is fetched once and cached.** Secret versions are immutable, so later refreshes only fetch versions they have not seen.
4. **The current key is chosen:**

| Situation | Current key |
|-----------|-------------|
| `CurrentKeyId` is set (pinned) | That version, if it is in the ring. Otherwise there is no current key. |
| A usable version was created at least `ActivationDelay` ago | The newest such version. |
| Every usable version is newer than `ActivationDelay` (for example a brand-new secret) | The oldest usable version. |
| No usable version | None. |

A version is **usable** when its `NotBefore` is not in the future and its `ExpiresOn` is not in the past. Versions that are expired or not yet valid stay in the ring and keep **verifying**, but they never become current. A version without `CreatedOn` counts as old enough.

The selection runs at load and refresh time, not on each call. A new version therefore becomes current on an instance at the first refresh after it is `ActivationDelay` old.

With no current key, `CurrentKeyId` throws `PepperUnavailableException`; see [Revocation fails closed](#revocation-fails-closed).

### Options

| Option | Default | Rules |
|--------|---------|-------|
| `SecretName` | `null` | Versions mode. 1 to 127 letters, digits or `-`. |
| `Keys` | empty | Map mode; see [Map mode](#map-mode). |
| `CurrentKeyId` | `null` | Versions mode: optional pin to one version id. Map mode: required, must be a key in `Keys`. Must match `^[A-Za-z0-9-]{1,32}$`. |
| `RefreshInterval` | 5 minutes | Versions mode. How often the version list is re-read. 1 second to 30 days, or `Timeout.InfiniteTimeSpan` to never refresh. |
| `ActivationDelay` | 15 minutes | Versions mode. How old (by `CreatedOn`) a version must be before it becomes current. 0 to 365 days. |
| `MaxVersions` | 25 | Versions mode. How many of the newest enabled versions are loaded. 1 to 500. |
| `Timeout` | 30 seconds | Limit for one load or refresh, covering every Key Vault request it makes. Greater than zero, at most 10 minutes. |
| `OnRefreshFailed` | `null` | `Action<Exception>` called when a **background** refresh fails or finds problems. Exceptions it throws are ignored. |

Secret values must be base64, at most 8192 characters, and decode to at least 32 bytes. Setting both `SecretName` and `Keys`, or neither, throws `ArgumentException` ("Set exactly one of SecretName (versions mode) and Keys (map mode).").

:::warning

`MaxVersions` limits how many rotations a hash survives. With the default of 25, only the 25 newest enabled versions are loaded, so a hash made under a version that has 25 or more newer enabled versions reports `UnknownPepperKey`. If you rotate often, raise `MaxVersions`, or disable versions deliberately once the [audit](#rotating-in-versions-mode) shows they are unused.

:::

## Register with dependency injection

`CreateAsync` is async, so create the pepper before building the host and register the instance. Top-level statements in `Program.cs` can await.

```csharp title="Program.cs"
using System;
using System.Threading;
using Azure.Identity;
using Azure.Security.KeyVault.Secrets;
using Masterly.Hash.DependencyInjection;
using Masterly.Hash.Pepper.AzureKeyVault;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);

// Assigned once the host is built; background refreshes before that are only visible through LastRefreshError.
ILogger? pepperLogger = null;

string vaultUri = builder.Configuration["KeyVault:Uri"]
    ?? throw new InvalidOperationException("KeyVault:Uri is not configured.");
SecretClient secretClient = new SecretClient(new Uri(vaultUri), new DefaultAzureCredential());

using CancellationTokenSource startup = new CancellationTokenSource(TimeSpan.FromMinutes(1));
AzureKeyVaultPepper pepper = await AzureKeyVaultPepper.CreateAsync(secretClient, new AzureKeyVaultPepperOptions
{
    SecretName = "password-pepper",
    OnRefreshFailed = exception => pepperLogger?.LogWarning(exception, "Refreshing the password pepper from Key Vault failed."),
}, startup.Token);

builder.Services.AddSingleton(pepper);
builder.Services.AddMasterlyHash().WithPepper(pepper);

WebApplication app = builder.Build();
pepperLogger = app.Services.GetRequiredService<ILoggerFactory>().CreateLogger("Masterly.Hash.Pepper.AzureKeyVault");
```

Registering the `AzureKeyVaultPepper` itself lets a health check or an admin endpoint call `RefreshAsync`, `LastRefreshError` and `KeyIds`. The exceptions passed to `OnRefreshFailed` never contain key material, so logging them is safe. [Dependency Injection](./dependency-injection.md) covers the builder in full.

## Rotating in versions mode

**1. Add a new secret version.**

```bash
az keyvault secret set --vault-name my-vault --name password-pepper \
  --value "$(openssl rand -base64 32)"
```

**2. Every instance learns it.** Each instance picks the version up on its next background refresh, so it is accepted for verification within about `RefreshInterval`. Until `ActivationDelay` has passed, it is not current anywhere, so no instance writes hashes with a key another instance does not know yet.

**3. It becomes current.** At the first refresh after the version is `ActivationDelay` old, each instance makes it the current key. With the defaults, that is 15 to about 20 minutes after you added it. New hashes now carry the new version id.

**4. Upgrade on login.** A successful verification of a hash under an older version returns `SuccessRehashNeeded` with `RehashReason.OutdatedPepperKey` and a fresh hash in `Rehash`. Store it, as described in [Upgrade on Login](./upgrade-on-login.md).

**5. Retire old versions** once no stored hash uses them. Count what is left with [`masterly-hash audit`](./command-line-tool.md) and `--pepper-key-ids` (current id first), or with a query. The key id is followed by `$`, or by `,` when the hash is wrapped:

```sql
SELECT COUNT(*) FROM Users
WHERE PasswordHash LIKE '$mh$%,k=3f1c9d0e8a7b4c2d9e6f1a0b5c4d3e2f$%'
   OR PasswordHash LIKE '$mh$%,k=3f1c9d0e8a7b4c2d9e6f1a0b5c4d3e2f,%';
```

Then disable the version (next section). `az keyvault secret list-versions --vault-name my-vault --name password-pepper` lists the version ids.

Keep `ActivationDelay` above `RefreshInterval` plus the clock skew between your hosts and Key Vault; `CreatedOn` is Key Vault's time and the comparison uses the host's clock. With `ActivationDelay` at zero, a new version becomes current on each instance at its own next refresh, and instances that have not refreshed yet report `UnknownPepperKey` for hashes written with it.

**Pinned current key.** If you set `CurrentKeyId`, the provider never switches the current key by itself. Add the version, wait at least one `RefreshInterval` so every instance has loaded it, then change the pin and redeploy.

## Revocation

To revoke a version, for example because it may have leaked, **disable** it:

```bash
az keyvault secret set-attributes --vault-name my-vault --name password-pepper \
  --version <version-id> --enabled false
```

After the next refresh, the version leaves the ring on every running instance, its cached key bytes are zeroed, and hashes that use it fail with `UnknownPepperKey`. Those users need a password reset. Deleting the whole secret (`az keyvault secret delete`) revokes every version at once.

Refreshes are triggered by use. An instance that had no traffic refreshes on its first call after `RefreshInterval`, and that call still runs on the old ring. To revoke immediately, call `RefreshAsync` on every instance, for example from an operator endpoint, or restart them. A health check that reads `CurrentKeyId` also keeps refreshes going on idle instances.

### Revocation fails closed

Whenever Key Vault answers the version listing, its answer is applied, even if it leaves no usable current key. Disabled and deleted versions always leave the ring.

| What happened in Key Vault | Result after the refresh |
|----------------------------|--------------------------|
| You disabled an old version | It is revoked; the current key is unchanged. |
| You disabled the current, unpinned version | It is revoked; the next usable version becomes current. |
| You disabled the pinned `CurrentKeyId` | It is revoked; there is no current key. |
| You disabled every version, or deleted the secret (HTTP 404 on the listing) | Every version is revoked; there is no current key. |
| No `CurrentKeyId` pin, and every remaining version is expired or not yet valid | Existing hashes keep verifying; there is no current key. |

**Without a current key**, `CurrentKeyId` throws `PepperUnavailableException`, so:

- New hashes cannot be written.
- A **successful** verification also throws, because the hasher reads the current key to decide whether to rehash. A wrong password still returns `Mismatch`.
- `VerifyOrDummy` for an unknown user throws, because its dummy hash uses the current key.
- Creating a new `PasswordHasher` with this pepper, or restarting, fails.

This lasts until you add a usable version or update the pin. Recovery needs no restart: the next refresh that finds a usable version restores the current key (`RefreshAsync` forces it).

Deleting the secret is recoverable while soft-delete holds it: `az keyvault secret recover` brings back every version, and the next refresh loads them again.

### Failures that keep the cached keys

Only failures to **reach** Key Vault keep the previous ring: network errors, timeouts, throttling, server errors, any other non-404 error on the listing, including HTTP 403, and any error other than 403 or 404 while reading a version the instance has not cached yet. The failure is recorded in `LastRefreshError`, reported to `OnRefreshFailed` for background refreshes, and the next background refresh is attempted after at most 1 minute (or `RefreshInterval`, if that is shorter).

:::note

Removing the application's RBAC role does **not** revoke the pepper on running instances. The listing then fails with HTTP 403, which counts as "could not reach", so the cached keys stay in use until the process restarts. Revoke key versions in Key Vault, not access to Key Vault.

:::

A single version that cannot be used is skipped and reported, without blocking the rest of the refresh:

- A value that is empty, longer than 8192 characters, not base64, or shorter than 32 bytes once decoded.
- A version that returns HTTP 403 or 404 when read (disabled or deleted after it was listed, or not readable by this identity).
- A version id that is not a valid pepper key id.

The rest of the refresh, including other rotations and revocations, is applied. No instance can have written hashes with a skipped version, so skipping it is safe.

### Calls in flight during a refresh

A refresh swaps the ring atomically. A hash or verify that checked `IsKnownKey` or `CurrentKeyId` just before a refresh removed its key still completes: `Apply` accepts a key removed by the most recent refresh for `AzureKeyVaultPepper.RemovedKeyGrace` (30 seconds) afterwards. After that, the removed key throws `KeyNotFoundException` from `Apply`.

## Map mode

Map explicit key ids to secrets. The keys are loaded once, when the pepper is created, and never refreshed; `RefreshAsync` does nothing and `RefreshInterval`, `ActivationDelay` and `MaxVersions` are ignored.

```csharp title="Program.cs"
using Masterly.Hash.Pepper.AzureKeyVault;

AzureKeyVaultPepperOptions options = new AzureKeyVaultPepperOptions { CurrentKeyId = "2026" };
options.Keys["2025"] = new AzureKeyVaultSecretReference("pepper-2025", "6a2b0c9d8e7f4a1b2c3d4e5f6a7b8c9d");
options.Keys["2026"] = new AzureKeyVaultSecretReference("pepper-2026");

// secretClient and startup are created as in the versions-mode example
AzureKeyVaultPepper pepper = await AzureKeyVaultPepper.CreateAsync(secretClient, options, startup.Token);
```

`AzureKeyVaultSecretReference(string name, string? version = null)` names a secret and, optionally, a version. Names are 1 to 127 letters, digits or `-`; versions are 1 to 64 letters or digits. A reference without a version loads whatever is the latest version at load time.

Rules for map mode:

- `CurrentKeyId` is required and must be a key in `Keys`.
- Every referenced secret must load. A missing, disabled, unreadable or invalid secret makes `CreateAsync` throw `PepperUnavailableException`. Remove an id from `Keys` **before** you disable its secret, or the next restart fails.
- To rotate, create a new secret, add it under a new id on every instance, then make that id current, the same two-step deployment as with [AWS KMS](./aws-kms.md#rotating-the-key).
- Revocation takes a configuration change and a restart.

:::danger

Never put new key material under an existing key id. If you add a version to an unversioned secret, the next restart loads different key material under the same id, and every hash stored with that id reports `Mismatch`. Pin versions, or create a new secret for each key.

:::

Use map mode when your key ids must be meaningful (`2026`) or when keys live in several secrets. Otherwise prefer versions mode: rotation and revocation then need no deployment.

## Exceptions

`Masterly.Hash.Pepper.AzureKeyVault.PepperUnavailableException` means the keys could not be loaded or no current key can be chosen. Messages carry secret names, version ids, HTTP status and error codes, never secret values.

| Member | Throws |
|--------|--------|
| `CreateAsync`, `Create` | `ArgumentNullException` (null client or options), `ArgumentException` (invalid options, before any Key Vault call), `PepperUnavailableException` (load failed or no usable current key), `OperationCanceledException` (your token was cancelled). |
| `CurrentKeyId` | `PepperUnavailableException` when there is no usable current key. |
| `RefreshAsync` | `PepperUnavailableException` when Key Vault could not be reached (cached keys kept), or when the applied result has problems (no current key, skipped versions). |
| `Apply`, `ApplyAsync` | `ArgumentNullException` (null input), `KeyNotFoundException` (key not loaded), `OperationCanceledException` from `ApplyAsync` with an already-cancelled token. |

Typical messages:

- Azure Key Vault did not answer within the configured timeout.
- Azure Key Vault request failed (HTTP *status*, *error code*).
- Secret '*name*' has no enabled versions.
- Secret '*name*' has no version that is enabled, active and not expired.
- CurrentKeyId '*id*' is not an enabled, usable version of secret '*name*'.
- Secret '*name*' version '*id*' must decode to at least 32 bytes. It was skipped.

When a load finds several problems, the first is the message and the rest are in an `AggregateException` as `InnerException` ("... 2 more problem(s); see InnerException.").

If your login endpoint should answer 503 while there is no current key, map this exception the same way as the [HashiCorp Vault](./hashicorp-vault.md#failure-handling) page shows, using the `Masterly.Hash.Pepper.AzureKeyVault` namespace. Each pepper package has its own `PepperUnavailableException` type; they share no base type besides `Exception`.

## Health check

`CurrentKeyId` tells you whether new hashes can be written, and `LastRefreshError` whether the last refresh failed or skipped versions:

```csharp title="KeyVaultPepperHealthCheck.cs"
using System;
using System.Threading;
using System.Threading.Tasks;
using Masterly.Hash.Pepper.AzureKeyVault;
using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace MyApp.Web;

/// <summary>Reports whether the Key Vault pepper has a current key and refreshes cleanly.</summary>
public sealed class KeyVaultPepperHealthCheck : IHealthCheck
{
    private readonly AzureKeyVaultPepper _pepper;

    /// <summary>Creates the check.</summary>
    public KeyVaultPepperHealthCheck(AzureKeyVaultPepper pepper)
    {
        _pepper = pepper;
    }

    /// <inheritdoc />
    public Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        try
        {
            _ = _pepper.CurrentKeyId;
        }
        catch (PepperUnavailableException exception)
        {
            return Task.FromResult(HealthCheckResult.Unhealthy("The password pepper has no usable current key.", exception));
        }

        Exception? lastError = _pepper.LastRefreshError;
        HealthCheckResult result = lastError == null
            ? HealthCheckResult.Healthy($"Keys loaded at {_pepper.LastRefreshed:O}.")
            : HealthCheckResult.Degraded("The last Key Vault refresh failed or skipped versions.", lastError);
        return Task.FromResult(result);
    }
}
```

```csharp title="Program.cs"
builder.Services.AddHealthChecks().AddCheck<KeyVaultPepperHealthCheck>("key-vault-pepper");
```

The check makes no Key Vault call of its own. Reading `CurrentKeyId` starts a background refresh when one is due, so regular probes keep idle instances current.

## Security notes

- **Where the key lives.** In Key Vault at rest, and in this process's memory while the application runs. A database leak alone does not expose it; a memory dump, a debugger or code execution on the host does.
- **What leaves the process.** Only Key Vault reads: listing versions and getting secrets. Passwords and pepper inputs never leave the process.
- **Availability.** Key Vault is needed for the initial load. Later outages keep the cached keys in use; answers from Key Vault, including revocations, are always applied.
- **Zeroing.** Decoded key buffers are zeroed when a version is dropped. Copies held inside the internal `HmacPepper` instances are freed by the garbage collector and are not zeroed. In .NET this is best effort; see the [Threat Model](./threat-model.md).
- **Same version id, different vault.** Version ids are random, but nothing ties a hash to a vault. Pointing an instance at a different vault whose secret happens to share a version id would make hashes report `Mismatch`, not an error.

## API summary

| Member | Description |
|--------|-------------|
| `static Task<AzureKeyVaultPepper> CreateAsync(SecretClient client, AzureKeyVaultPepperOptions options, CancellationToken cancellationToken = default)` | Validates the options, loads the keys and returns a ready pepper. |
| `static AzureKeyVaultPepper Create(SecretClient client, AzureKeyVaultPepperOptions options)` | Synchronous `CreateAsync`. Blocks on the initial load. |
| `string CurrentKeyId` | The current key id. Throws `PepperUnavailableException` when there is none. |
| `IReadOnlyList<string> KeyIds` | The loaded key ids, newest first in versions mode. |
| `DateTimeOffset LastRefreshed` | When the keys were last loaded from a Key Vault answer. |
| `Exception? LastRefreshError` | The error of the most recent refresh, or `null`. Never contains key material. |
| `bool IsKnownKey(string keyId)` | Checks the cached ring. No network call. |
| `byte[] Apply(string keyId, byte[] input)` | HMAC-SHA256 with the cached key. |
| `ValueTask<byte[]> ApplyAsync(string keyId, byte[] input, CancellationToken cancellationToken = default)` | Same as `Apply`; completes synchronously. |
| `Task RefreshAsync(CancellationToken cancellationToken = default)` | Versions mode: re-reads the version list now. Map mode: does nothing. |
| `const int MinKeyLength` | 32. |
| `static readonly TimeSpan RemovedKeyGrace` | 30 seconds. |

## See also

- [Peppers](./peppers.md): what a pepper protects against and how key ids and rotation work.
- [HashiCorp Vault](./hashicorp-vault.md) and [AWS KMS](./aws-kms.md): providers that keep the key inside the service.
- [Upgrade on Login](./upgrade-on-login.md): storing the rehash after a rotation.
- [Auditing Hash Tables](./auditing-hash-tables.md): finding hashes that still use an old key.
- [ASP.NET Core Identity](./aspnetcore-identity.md): using the pepper behind Identity's synchronous hasher.
- [Package README](https://github.com/a7mdfre7at/Masterly.Hash/blob/master/src/Masterly.Hash.Pepper.AzureKeyVault/README.md)
