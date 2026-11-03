---
title: "Peppers and Key Rotation"
sidebar_label: "Peppers"
description: "Mix a server-side secret into every hash, rotate its key without breaking logins, and write your own pepper."
---

A pepper is a secret key, kept outside the database, that is mixed into every password before it is hashed. A stolen copy of the users table is then useless on its own: without the key, an attacker cannot test a single guess offline. This page shows how to add a pepper, how to rotate its key, and what fails when a key is missing.

The pepper is optional and off by default. `PasswordHasherOptions.Pepper` is `null` until you set it.

## How a pepper is applied

With `HmacPepper` configured, the hasher computes:

```text
tag = KDF( HMAC-SHA256(pepperKey, UTF-8(NFKC(password))), salt )
```

where `KDF` is the profile's Argon2id or PBKDF2-HMAC-SHA512 (another `IPasswordPepper` replaces the HMAC step with its own keyed transform), and records the id of the key it used in the hash string, as `k=`:

```text
$mh$p=2026a,k=k2$<salt>$<tag>
```

The key itself is never stored. The key id is how rotation works: the hasher knows which key to use for each stored hash, so hashes made with an older key keep verifying while new hashes use the current one.

## When to use a pepper

Use a pepper when you can keep a key somewhere a database leak does not reach: environment variables or a secret store for `HmacPepper`, or a key service where the key never enters your process (see [Key management](#remote-key-services)). It protects against the most common breach, a leaked backup or a SQL injection that dumps the users table.

A pepper does not help if:

- **The key lives in the same database**, or in a backup taken with it. A leak then includes the key.
- **The attacker controls the application host.** They can read the key from memory, or the password as it arrives.

A pepper also makes the key a dependency of every login. If you lose the key, every hash made with it becomes unverifiable and those users must reset their passwords. Back the key up as carefully as you protect it.

## Adding a pepper

1. **Generate a key.** Run `masterly-hash pepper generate`, which prints a new random 32-byte key in base64 to standard output, or call `HmacPepper.GenerateKey()`. The tool does not store the key anywhere, so copy it straight into your secret store.

2. **Store it in a secret store.** Use Azure Key Vault, AWS Secrets Manager, user secrets in development, or environment variables. Never commit it to source control, and never store it in the database that holds the hashes.

3. **Configure the hasher.** Bind it from configuration:

   ```json title="appsettings.json (values supplied by your secret store)"
   {
     "MasterlyHash": {
       "Pepper": {
         "CurrentKeyId": "k1",
         "Keys": { "k1": "<base64 key>" }
       }
     }
   }
   ```

   ```csharp title="Program.cs"
   builder.Services.AddMasterlyHash(builder.Configuration.GetSection("MasterlyHash"));
   ```

   With environment variables, the same settings are `MasterlyHash__Pepper__CurrentKeyId=k1` and `MasterlyHash__Pepper__Keys__k1=<base64 key>`.

   Or create the pepper in code:

   ```csharp title="Program.cs"
   string k1 = builder.Configuration["Pepper:k1"]
       ?? throw new InvalidOperationException("Pepper key k1 is not configured.");

   builder.Services.AddMasterlyHash()
       .WithPepper(HmacPepper.FromBase64("k1", new Dictionary<string, string> { ["k1"] = k1 }));
   ```

4. **Deploy.** Existing unpeppered hashes keep verifying. Each one comes back from a successful login with `RehashReason.OutdatedPepperKey` and a peppered replacement in `Rehash`. See [Upgrade on login](./upgrade-on-login.md).

Without dependency injection, set the option directly:

```csharp
// key is a 32-byte key loaded from your secret store
PasswordHasher hasher = new PasswordHasher(new PasswordHasherOptions
{
    Pepper = new HmacPepper("k1", key),
});
```

## HmacPepper

`HmacPepper` (namespace `Masterly.Hash.Pepper`) is the local pepper. It computes HMAC-SHA256 with a key from an in-memory key ring.

| Member | Description |
|---|---|
| `HmacPepper(string currentKeyId, IReadOnlyDictionary<string, byte[]> keys)` | A key ring. `currentKeyId` is used for new hashes and must be in `keys`. |
| `HmacPepper(string keyId, byte[] key)` | A ring with a single key |
| `HmacPepper.FromBase64(string currentKeyId, IReadOnlyDictionary<string, string> base64Keys)` | A ring from base64 strings, for example bound from configuration |
| `HmacPepper.GenerateKey()` | A new random key of `MinKeyLength` bytes |
| `HmacPepper.MinKeyLength` | 32 bytes |
| `CurrentKeyId` | The key id used for new hashes |
| `IsKnownKey(string keyId)` | True if the ring contains `keyId` |
| `Apply(string keyId, byte[] input)` | HMAC-SHA256 of `input` with the key `keyId`, as a new 32-byte array |
| `ApplyAsync(string keyId, byte[] input, CancellationToken cancellationToken = default)` | The same, completed synchronously |

Rules the constructors enforce:

| Rule | Exception |
|---|---|
| Every key id, and `currentKeyId`, matches `^[A-Za-z0-9-]{1,32}$`. Ids are case-sensitive. | `ArgumentException` |
| Every key is at least 32 bytes. A `null` key is rejected. | `ArgumentException` |
| `currentKeyId` is in the ring | `ArgumentException` |
| `keys` or `base64Keys` is not `null` | `ArgumentNullException` |
| Each value passed to `FromBase64` is valid base64 | `FormatException` (from `Convert.FromBase64String`) |

The constructor copies the key bytes, so later changes to your arrays have no effect. The keys stay in process memory for the lifetime of the pepper.

## Configuration reference

`AddMasterlyHash(IConfiguration)` reads the pepper from the `Pepper` subsection and creates an `HmacPepper`:

| Key | Description |
|---|---|
| `Pepper:CurrentKeyId` | Key id used for new hashes. Must match `^[A-Za-z0-9-]{1,32}$` and be present in `Keys`. |
| `Pepper:Keys:<id>` | A key in standard base64 (padded or unpadded) that decodes to between 32 and 1024 bytes |

If both are empty, no pepper is configured. Otherwise every problem is a startup error (`OptionsValidationException`) that names the key by id and never includes key material:

- `CurrentKeyId` is missing, invalid, or not in `Keys`.
- `Keys` is empty, an id is invalid, or a value is not base64, decodes to fewer than 32 bytes, or to more than 1024 bytes.
- A misspelled key under the section, such as `Peper`, is an `InvalidOperationException` from the configuration binder, so a typo cannot silently turn the pepper off.

Configuration keys are case-insensitive, so two key ids that differ only by case cannot both be configured.

A pepper set in code (`WithPepper`, `Configure`) runs after the configuration is applied and replaces it. `WithPepper(Func<IServiceProvider, IPasswordPepper>)` creates the pepper from the container; the factory can run more than once (at startup validation and at first resolution), so keep it cheap and idempotent. See [Dependency injection](./dependency-injection.md).

## Rotating keys

Rotate the key when it may have been exposed, or on a schedule your policy sets. Rotation never invalidates a hash on its own: a hash made with an old key keeps verifying as long as that key is in the ring.

1. **Generate the new key** and store it in your secret store next to the old one.

2. **Add it to every instance, but do not make it current yet.**

   ```json
   "Pepper": {
     "CurrentKeyId": "k1",
     "Keys": { "k1": "<old key>", "k2": "<new key>" }
   }
   ```

   Deploy everywhere. Nothing changes for users.

3. **Make the new key current.**

   ```json
   "Pepper": {
     "CurrentKeyId": "k2",
     "Keys": { "k1": "<old key>", "k2": "<new key>" }
   }
   ```

   New hashes use `k2`. A successful login with a `k1` hash returns `RehashReason.OutdatedPepperKey` and a replacement under `k2`.

4. **Wait for the old key to drain.** Watch `masterly.hash.verifications` with `reason=OutdatedPepperKey`, and count the remaining `k=k1` hashes with `Inspect(storedHash).PepperKeyId`, `HashAudit` or `masterly-hash audit --pepper-key-ids k2,k1` (see [Auditing hash tables](./auditing-hash-tables.md)).

5. **Retire the old key** only when no hashes use it, or after the remaining users have been asked to reset their passwords.

Step 2 matters when more than one instance serves logins. If you make `k2` current on one instance before the others know it, a user upgraded there to a `k=k2` hash fails with `UnknownPepperKey` on every instance that has not been updated. The same applies to rolling back: a configuration without `k2` cannot verify hashes that were already upgraded to it.

:::danger

Removing a key from the ring locks out every user whose hash was made with it: verification fails with `VerificationFailureReason.UnknownPepperKey`, and only a password reset recovers the account. Changing the bytes of a key while keeping its id is worse: those hashes fail with `Mismatch`, indistinguishable from a wrong password. Never reuse a key id for a different key.

:::

## Failure modes

| Situation | Result |
|---|---|
| The stored hash names a key id the pepper does not know (removed, or not yet deployed) | `Failed`, `UnknownPepperKey` |
| The stored hash is peppered but no pepper is configured | `Failed`, `UnknownPepperKey` |
| The key id is known but its bytes changed | `Failed`, `Mismatch` |
| The stored hash is unpeppered and a pepper is configured | Verifies, `SuccessRehashNeeded`, `OutdatedPepperKey` |
| The stored hash uses a known, non-current key | Verifies, `SuccessRehashNeeded`, `OutdatedPepperKey` |
| `HmacPepper.Apply` called directly with an unknown key id | `KeyNotFoundException` |
| A remote pepper service is unreachable | The provider's exception propagates from `Hash`, `Verify` and their async versions |

`Inspect` reports a peppered hash as recognized only when the pepper knows its key id, so `NeedsRehash` is false for a hash with an unknown key.

## Remote key services

`HmacPepper` keeps keys in your process. Three packages keep the key in a managed service instead and implement `IPasswordPepper`:

| Package | Type | Where the key lives |
|---|---|---|
| `Masterly.Hash.Pepper.HashiCorpVault` | `HashiCorpVaultPepper` | Vault Transit; HMAC is computed by Vault and the key never leaves it. Key ids are Transit key versions, such as `v3`. |
| `Masterly.Hash.Pepper.AwsKms` | `AwsKmsPepper` | AWS KMS `GenerateMac`; the key never leaves KMS |
| `Masterly.Hash.Pepper.AzureKeyVault` | `AzureKeyVaultPepper` | Azure Key Vault secrets, loaded into process memory and used locally with HMAC-SHA256. In versions mode the version list is refreshed in the background and rotation is a new secret version; in map mode the keys are loaded once. |

Each throws its own `PepperUnavailableException` when the service cannot be used. See [HashiCorp Vault](./hashicorp-vault.md), [AWS KMS](./aws-kms.md) and [Azure Key Vault](./azure-key-vault.md).

The Vault Transit and KMS peppers add a network call to every hash and every verification. The Azure Key Vault pepper loads its keys up front, so `Apply` and `ApplyAsync` are local after creation. Use the async API (`HashAsync`, `VerifyAsync`, `VerifyOrDummyAsync`) with the remote providers: the async methods call `ApplyAsync`, while the sync methods call `Apply`, which blocks a thread on the network.

## Writing your own pepper

Implement `IPasswordPepper`:

```csharp
public interface IPasswordPepper
{
    string CurrentKeyId { get; }
    bool IsKnownKey(string keyId);
    byte[] Apply(string keyId, byte[] input);
    ValueTask<byte[]> ApplyAsync(string keyId, byte[] input, CancellationToken cancellationToken = default);
}
```

The contract:

- **`CurrentKeyId`** must always match `^[A-Za-z0-9-]{1,32}$`. The `PasswordHasher` constructor checks it once and throws `ArgumentException` if it does not. The hasher reads it again on every hash and on every successful verification (to decide on a rehash), so it may change at run time, as it does when the Azure Key Vault provider activates a new secret version.
- **`IsKnownKey`** returns true for every key id whose hashes can still be verified. The hasher checks it before applying the pepper and fails with `UnknownPepperKey` when it returns false.
- **`Apply` and `ApplyAsync`** return a keyed, deterministic transform of `input`, typically HMAC-SHA256. The same key id and input must always give the same output.
- **The implementation must be thread-safe.** One hasher, and therefore one pepper, serves every request.

:::danger

`Apply` and `ApplyAsync` must return a **new** array. The hasher zeroes `input` as soon as the call returns, so returning `input` itself, or a buffer that shares it, turns every KDF input into zeros, and then any password of the same length matches. Do not keep a reference to `input` either.

:::

The pepper runs outside the [concurrency gate](./limits-and-concurrency.md#the-concurrency-gate): a slow key service adds latency to each login but does not hold a hashing slot while it waits.

For tests, `FakePepper` from `Masterly.Hash.Testing` derives its keys from the key ids, counts sync and async calls, and can simulate delays and outages. Never use it in production. See [Testing](./testing.md).

## Security notes

- **Keep the key out of source code.** Analyzer MH0003 flags a pepper key written as a literal. See [Analyzers](./analyzers.md).
- **Keep the key away from the hashes.** A pepper stored in the same database, or in a backup taken with it, adds nothing.
- **The command-line tool never holds a key.** `inspect`, `audit` and `wrap` classify peppered hashes when you pass `--pepper-key-ids` (current key first, for example `k2,k1`), and `verify` cannot check them. See [Command-line tool](./command-line-tool.md).
- **Onion wrapping uses the pepper too.** `TryWrap` applies the current key to the legacy digest, so wrapped hashes are peppered as well. See [Onion wrapping](./onion-wrapping.md).
- **Memory is best effort.** The hasher zeroes the pepper input and output after use, but `HmacPepper` must keep its keys in memory to work. The Vault Transit and KMS providers keep the key out of your process entirely.

## See also

- [Upgrade on login](./upgrade-on-login.md): how `OutdatedPepperKey` hashes are replaced
- [HashiCorp Vault](./hashicorp-vault.md), [AWS KMS](./aws-kms.md), [Azure Key Vault](./azure-key-vault.md)
- [Dependency injection](./dependency-injection.md): `WithPepper` and the configuration section
- [Hash format](./hash-format.md): the `k=` parameter
- [Threat model](./threat-model.md)
