# Masterly.Hash.DependencyInjection

`Microsoft.Extensions.DependencyInjection` integration for [Masterly.Hash](https://github.com/a7mdfre7at/Masterly.Hash).
It registers one thread-safe `PasswordHasher` singleton (also exposed as `IPasswordHasher`), binds its options
from `IConfiguration`, validates them at startup, and gives you a fluent builder for peppers, legacy formats and profiles.

## Install

```shell
dotnet add package Masterly.Hash.DependencyInjection
```

Targets `net8.0`. Depends on the 8.0.x `Microsoft.Extensions.*` abstractions, so it works on .NET 8 LTS hosts and later.

## Quickstart

```csharp
// Code-only
builder.Services.AddMasterlyHash();                                  // Argon2id 2026a defaults

// From configuration; code steps always win, whatever order they were registered in
builder.Services.AddMasterlyHash(builder.Configuration.GetSection("MasterlyHash"))
    .AddLegacyFormat(myLegacyFormat)                                  // verify and upgrade old hashes
    .WithPepper(sp => sp.GetRequiredService<MyVaultPepper>());         // or .WithPepper(IPasswordPepper)

// Use it
public sealed class LoginService(IPasswordHasher hasher) { /* hasher.VerifyOrDummyAsync(...) */ }
```

```json
"MasterlyHash": {
  "DefaultProfile": "2026a",
  "MaxConcurrency": 8,
  "ConcurrencyTimeout": "00:00:10",
  "MaxPasswordBytes": 1024,
  "ComputeRehashOnVerify": true,
  "Pepper": {
    "CurrentKeyId": "k2",
    "Keys": { "k1": "<base64, 32+ bytes>", "k2": "<base64, 32+ bytes>" }
  }
}
```

`DefaultProfile` accepts the built-in ids `2026a` (Argon2id 64 MiB), `2026c` (Argon2id 19 MiB) and `2026f`
(PBKDF2-SHA512). Custom profiles are code-only: `.UseProfile(HashProfile.Argon2id(...))`, and `.AddProfile(old)` keeps
older custom profiles verifiable. Every setting is optional; absent or empty values keep the library defaults.
Unknown or misspelled keys under the section (e.g. `Peper`) are startup errors, so a typo cannot silently drop the pepper.
`ConcurrencyTimeout` must be positive and at most `24.20:31:23.647`, or `-00:00:00.001` (infinite).

Builder methods: `Configure`, `Configure<TDep>`, `WithPepper` (instance or factory), `AddLegacyFormat` (instance or factory),
`UseProfile`, `AddProfile`. Satellite packages add their own extension methods on `MasterlyHashBuilder`.

`AddMasterlyHash` throws if `IPasswordHasher` or `PasswordHasher` is already registered by something else, because
that registration would ignore every option. To decorate the hasher, register your `IPasswordHasher` after `AddMasterlyHash`
and resolve `PasswordHasher` inside it.

## Validation

- Unknown profile ids, out-of-range limits, malformed or short pepper keys, and a `CurrentKeyId` missing from `Keys`
  fail with `OptionsValidationException`, listing every problem at once.
- With Microsoft.Extensions.Hosting 8.0+ the options are validated when the host starts (`ValidateOnStart`).
  On other hosts, call `serviceProvider.ValidateMasterlyHash()` after building the provider to fail fast.
- The hasher is built once, on first resolution. Configuration reloads do not affect an already-built hasher.

## Metrics

The hasher publishes `System.Diagnostics.Metrics` under `MasterlyHashBuilder.MeterName` (`"Masterly.Hash"`):

```csharp
builder.Services.AddOpenTelemetry()
    .WithMetrics(m => m.AddMeter(MasterlyHashBuilder.MeterName));
```

## Security notes

- Keep pepper keys in a secret store (Key Vault, user secrets, environment), never in `appsettings.json` in source control
  and never in the same database as the hashes. Generate keys with `HmacPepper.GenerateKey()`.
- Validation messages name keys by id only; key text and key bytes are never included. Decoded key buffers are zeroed after use.
- To rotate, add the new key, point `CurrentKeyId` at it, and keep the old key until every hash made with it has been rehashed
  on login. Removing a key makes those hashes fail with `UnknownPepperKey`.
- Configuration keys are case-insensitive, so pepper key ids that differ only by case cannot both be configured.
- Binding uses the reflection-based configuration binder; this package is not marked trimming/AOT-compatible.
  For Native AOT, configure options in code with `AddMasterlyHash(o => ...)`.
