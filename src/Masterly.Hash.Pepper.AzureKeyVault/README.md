# Masterly.Hash.Pepper.AzureKeyVault

![Masterly.Hash: password hashing you can't get wrong.](https://raw.githubusercontent.com/a7mdfre7at/Masterly.Hash/master/assets/banner.png)

A [Masterly.Hash](https://github.com/a7mdfre7at/Masterly.Hash) pepper whose keys are stored as **Azure Key Vault secrets**.

> **Trust model in one line:** Azure Key Vault cannot compute HMACs, so this provider **loads the pepper keys into
> application memory** and computes HMAC-SHA256 locally. That differs from the HashiCorp Vault and AWS KMS peppers,
> where the key never leaves the service.

## Install

```
dotnet add package Masterly.Hash.Pepper.AzureKeyVault
```

## Azure setup

```sh
az keyvault secret set --vault-name my-vault --name password-pepper --value "$(openssl rand -base64 32)"
```

Grant the application identity only **Get** and **List** on secrets, for example with the RBAC role *Key Vault Secrets User*.
Each secret value must be the base64 encoding of a random key of at least 32 bytes.

## Quickstart (versions mode)

Each enabled version of one secret is a pepper key, and its 32-character version id is the key id stored in the hash.

```csharp
using Azure.Identity;
using Azure.Security.KeyVault.Secrets;
using Masterly.Hash;
using Masterly.Hash.Pepper.AzureKeyVault;

var client = new SecretClient(new Uri("https://my-vault.vault.azure.net/"), new DefaultAzureCredential());
AzureKeyVaultPepper pepper = await AzureKeyVaultPepper.CreateAsync(client, new AzureKeyVaultPepperOptions
{
    SecretName = "password-pepper",
    // RefreshInterval = TimeSpan.FromMinutes(5), ActivationDelay = TimeSpan.FromMinutes(15), MaxVersions = 25,
    // OnRefreshFailed = ex => logger.LogWarning(ex, "Pepper refresh failed"),
});

var hasher = new PasswordHasher(new PasswordHasherOptions { Pepper = pepper });
```

`CreateAsync` loads the keys and throws `PepperUnavailableException` if it cannot, so call it at startup. A synchronous
`Create` is also available. After loading, hashing and verifying never call Key Vault.

### Rotation and revocation

1. Add a new secret version with `az keyvault secret set` again. Each instance picks it up on its next background refresh,
   which runs every `RefreshInterval` (default 5 min) and is triggered by use. Until then the instance keeps using the cached keys.
2. Once the version is older than `ActivationDelay` (default 15 min) it becomes the **current** key. Before that it is only
   accepted for verification. The delay gives every instance time to learn the new key before any instance writes hashes with it.
   Keep `ActivationDelay` larger than `RefreshInterval` plus clock skew.
3. Old hashes keep verifying and come back with `RehashReason.OutdatedPepperKey` and a fresh hash.
4. **Disable** (or delete) a version to revoke it. After the next refresh, which you can force with `RefreshAsync`,
   hashes that use it fail with `UnknownPepperKey` on every running instance.
   Expired and not-yet-valid versions are still accepted for verification but never become current.
   Only the newest `MaxVersions` enabled versions are loaded.

Revocation **fails closed**. Whenever Key Vault answers the version listing, that answer is applied, even when it leaves no
usable current key. Example cases: you disabled the pinned `CurrentKeyId`, disabled or deleted every version, or every
remaining version is expired. Revoked versions are dropped either way. Without a current key, `CurrentKeyId` throws
`PepperUnavailableException`, so no new hashes are written and successful logins also throw, because the hasher checks the
current key to decide on a rehash. This lasts until you add a usable version or update the pin. Constructing a new
`PasswordHasher`, or restarting, also fails in that state. An enabled version with an invalid value, or one that cannot be
read (HTTP 403/404), is skipped and reported through `OnRefreshFailed`. It does not block other rotations or revocations.
A call already in flight when a refresh removes its key still completes; `Apply` accepts a just-removed key for
`RemovedKeyGrace` (30 s).

Set `CurrentKeyId` to a version id to pin the current key instead of selecting it automatically.

## Map mode

Map explicit key ids to secrets. The keys are loaded once and never refreshed.

```csharp
var options = new AzureKeyVaultPepperOptions { CurrentKeyId = "2026" };
options.Keys["2025"] = new AzureKeyVaultSecretReference("pepper-2025", "3f1c...version");
options.Keys["2026"] = new AzureKeyVaultSecretReference("pepper-2026");   // latest version, pinned at load
```

Never put new key material under an existing key id. If you add a version to an unversioned secret, the next restart loads
different key material under the same id and every hash stored with that id stops verifying. Pin versions or create a new secret.

## Trust model

- **Where the key lives**: in Key Vault at rest, and **in this process's memory** while the application runs. A database leak
  alone does not expose it. A memory dump, a debugger or code execution on the host does. If that is not acceptable, use
  `Masterly.Hash.Pepper.HashiCorpVault` or `Masterly.Hash.Pepper.AwsKms`, which keep the key inside the service.
- **What leaves the process**: only Key Vault reads (list versions, get secret). Passwords and pepper inputs never leave it.
- **Availability**: Key Vault is needed only for the initial load. If a later refresh cannot reach Key Vault (network,
  timeout, throttling, server errors), the cached keys stay in use. The failure is exposed through `LastRefreshError` and
  `OnRefreshFailed`, and the refresh is retried within a minute. Answers from Key Vault, including revocations, are always
  applied (see above).
- **No secrets in errors**: exception messages carry secret names, version ids and HTTP status, never secret values. Decoded
  key buffers are zeroed when they are dropped. Copies held inside core `HmacPepper` instances are freed by the garbage
  collector and are not zeroed.
