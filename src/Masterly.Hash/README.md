# Masterly.Hash

Password hashing you can't get wrong. Two methods, safe defaults, and existing hashes upgrade themselves on login.

```
dotnet add package Masterly.Hash
```

```csharp
using Masterly.Hash;

string stored = Password.Hash("hunter2");          // $mh$p=2026a$<salt>$<tag>

var result = Password.Verify("hunter2", stored);
if (result.IsMatch && result.Rehash is { } fresh)  // only when the stored hash is outdated
    user.PasswordHash = fresh;
```

## What you get

- **Argon2id** (RFC 9106) by default, PBKDF2-HMAC-SHA512 for NIST-only environments.
- **Dated profiles, not knobs.** The stored string carries a profile id (`2026a`), never cost parameters. Verification looks the id up in a compiled-in allowlist, so no database row can make `Verify` allocate 4 GiB or run with `t=1`.
- **Upgrade on login.** Hashes from an older profile, an older pepper key, or Masterly.Hash 1.x verify and come back with `Rehash` set.
- **Constant-time verification**, secrets zeroed after use, NFKC normalization (NIST SP 800-63B), 1024-byte input cap. Empty passwords and invalid UTF-16 are rejected rather than silently mangled.
- **User-enumeration protection:** `VerifyOrDummy(password, storedHashOrNull)` costs the same whether or not the user exists.
- **Login-flood protection:** a concurrency limit (default: processor count) so parallel Argon2 calls can't exhaust memory; excess calls wait, then throw `PasswordHasherBusyException` (map it to 503).
- **Peppers with key rotation** (`HmacPepper`, or Vault/KMS/Key Vault providers in separate packages).
- **Onion wrapping:** `TryWrap(legacyHash)` upgrades weak hashes offline, without the password.
- **`SensitiveString`** for request models: `ToString()`, the debugger and JSON output all show `***`.
- **Metrics** via `System.Diagnostics.Metrics` (meter `Masterly.Hash`) for OpenTelemetry.

## Profiles

| Profile | Id | Algorithm | Parameters | For |
|---|---|---|---|---|
| `HashProfile.Server2026a` (default) | `2026a` | Argon2id | m=64 MiB, t=3, p=1 | Web backends |
| `HashProfile.Constrained2026a` | `2026c` | Argon2id | m=19 MiB, t=2, p=1 | Serverless, small containers |
| `HashProfile.Fips2026a` | `2026f` | PBKDF2-HMAC-SHA512 | 210,000 iterations | NIST-approved primitives only |

A profile id is permanent. Stronger parameters ship as a new id in a new package version; existing hashes keep verifying and are rehashed on the next login.

## Configuration

```csharp
var hasher = new PasswordHasher(new PasswordHasherOptions
{
    DefaultProfile = HashProfile.Constrained2026a,
    Pepper = HmacPepper.FromBase64("k2", new Dictionary<string, string>
    {
        ["k1"] = config["Pepper:k1"],   // old key: still verifies, triggers rehash
        ["k2"] = config["Pepper:k2"],   // current key
    }),
    MaxConcurrency = 8,
});
```

Register it as a singleton (or use `Masterly.Hash.DependencyInjection`).

## Upgrading from 1.x

1.x hashes (`base64(SHA-2(password || salt) || salt)`) are accepted automatically. You don't need to know which SHA-2 variant produced them. The first successful login returns `Rehash`. The old `Hash`/`IHash` API still compiles but is marked `[Obsolete]`; its `Verify` is now constant-time and no longer throws when given the wrong algorithm.

To protect dormant accounts now, wrap their hashes offline. Wrapping needs the algorithm, which 1.x defaulted to SHA-512:

```csharp
var options = new PasswordHasherOptions();
options.LegacyFormats[0] = new V1LegacyFormat(V1Algorithm.SHA512);
var hasher = new PasswordHasher(options);
if (hasher.TryWrap(user.PasswordHash, out string wrapped)) user.PasswordHash = wrapped;
```

See the [migration guide](https://github.com/a7mdfre7at/Masterly.Hash/blob/master/docs/MIGRATION-1x.md).

## Security notes

- Verifying a legacy hash is much faster than Argon2, so response timing can show that an account still has a legacy hash. Migrate quickly, or wrap legacy hashes offline.
- `HmacPepper` keeps keys in process memory. Keep them out of the database; otherwise a database leak includes the pepper.
- The profile allowlist guards against resource exhaustion and misconfiguration. It does not protect against an attacker who can already write to your users table.

Full documentation: https://github.com/a7mdfre7at/Masterly.Hash
