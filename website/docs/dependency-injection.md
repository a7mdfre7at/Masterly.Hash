---
title: Dependency Injection
sidebar_label: Dependency Injection
description: Register one validated PasswordHasher singleton with AddMasterlyHash, bind it from appsettings.json and extend it with the fluent builder.
---

`Masterly.Hash.DependencyInjection` registers Masterly.Hash in `Microsoft.Extensions.DependencyInjection`. It adds one thread-safe `PasswordHasher` singleton, also exposed as `IPasswordHasher`, binds its options from `IConfiguration`, validates them at startup and gives you a fluent builder for peppers, legacy formats and profiles.

```bash
dotnet add package Masterly.Hash.DependencyInjection
```

The package targets `net8.0` and depends on the 8.0.x `Microsoft.Extensions.*` packages (`DependencyInjection.Abstractions`, `Options`, `Options.ConfigurationExtensions`, `Configuration.Abstractions` and `Configuration.Binder`), so it works on .NET 8 hosts and later.

| Type | Namespace | Role |
|------|-----------|------|
| `MasterlyHashServiceCollectionExtensions` (`AddMasterlyHash`) | `Microsoft.Extensions.DependencyInjection` | Registration. |
| `MasterlyHashServiceProviderExtensions` (`ValidateMasterlyHash`) | `Microsoft.Extensions.DependencyInjection` | Eager validation. |
| `MasterlyHashBuilder` | `Masterly.Hash.DependencyInjection` | Fluent builder returned by `AddMasterlyHash`. |
| `MasterlyHashConfiguration`, `MasterlyHashPepperConfiguration` | `Masterly.Hash.DependencyInjection` | The configuration model bound from `IConfiguration`. |
| `PasswordHasherOptionsValidator`, `MasterlyHashConfigurationValidator` | `Masterly.Hash.DependencyInjection` | `IValidateOptions<T>` implementations. |

Because `AddMasterlyHash` lives in `Microsoft.Extensions.DependencyInjection`, no extra `using` is needed to call it. Add `using Masterly.Hash.DependencyInjection;` only when you name the builder or the configuration types.

## Register the hasher

**1. Call `AddMasterlyHash`.** With no arguments you get the library defaults: Argon2id profile `2026a`, no pepper, the Masterly.Hash 1.x format accepted for migration.

```csharp title="Program.cs"
using Masterly.Hash;

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);

builder.Services.AddMasterlyHash();
```

**2. Inject `IPasswordHasher`.** The same instance is returned for `IPasswordHasher` and for the concrete `PasswordHasher`.

```csharp title="LoginService.cs"
using Masterly.Hash;

namespace MyApp.Accounts;

public sealed class LoginService
{
    private readonly IPasswordHasher _hasher;
    private readonly IUserStore _users;

    public LoginService(IPasswordHasher hasher, IUserStore users)
    {
        _hasher = hasher;
        _users = users;
    }

    public async Task<bool> LogInAsync(string userName, string password, CancellationToken cancellationToken)
    {
        // IUserStore is your own repository; FindPasswordHashAsync returns null for an unknown user.
        string? storedHash = await _users.FindPasswordHashAsync(userName, cancellationToken);

        PasswordVerificationResult result = await _hasher.VerifyOrDummyAsync(password, storedHash, cancellationToken);
        if (result.NeedsRehash && result.Rehash != null)
        {
            await _users.SavePasswordHashAsync(userName, result.Rehash, cancellationToken);
        }

        return result.IsMatch;
    }
}
```

`VerifyOrDummyAsync` does the same work for an unknown user as for a real one, so response time does not reveal which accounts exist. See [User enumeration](./user-enumeration.md) and [Upgrade on login](./upgrade-on-login.md).

## What `AddMasterlyHash` registers

| Service | Lifetime | Notes |
|---------|----------|-------|
| `PasswordHasher` | Singleton | Built once, on first resolution, from `IOptions<PasswordHasherOptions>`. |
| `IPasswordHasher` | Singleton | Forwards to the `PasswordHasher` registration, so both resolve to the same instance. |
| `IValidateOptions<PasswordHasherOptions>` | Singleton | `PasswordHasherOptionsValidator`. |
| `IValidateOptions<MasterlyHashConfiguration>` | Singleton | `MasterlyHashConfigurationValidator`. Only with the `IConfiguration` overload. |

Both option types are registered with `ValidateOnStart`.

Calling `AddMasterlyHash` more than once is safe. Later calls add configure steps but never register a second hasher.

:::warning

`AddMasterlyHash` throws `InvalidOperationException` if `IPasswordHasher` or `PasswordHasher` was already registered by something else before the first call. Such a registration would shadow the one `AddMasterlyHash` makes, and every option and builder call would be silently ignored. Remove the earlier registration, or register a decorator after the call (see [Decorating the hasher](#decorating-the-hasher)).

:::

## Configure in code

Pass a configure step, or chain builder methods. Steps run in the order they were registered.

```csharp title="Program.cs"
using Masterly.Hash;

builder.Services.AddMasterlyHash(options =>
{
    options.DefaultProfile = HashProfile.Constrained2026a;   // Argon2id 19 MiB
    options.MaxConcurrency = 4;
    options.ConcurrencyTimeout = TimeSpan.FromSeconds(5);
});
```

Every property of `PasswordHasherOptions` can be set this way:

| Option | Default | Meaning |
|--------|---------|---------|
| `DefaultProfile` | `HashProfile.Server2026a` (`2026a`) | Profile used for new hashes. Required. |
| `AdditionalProfiles` | empty | Custom profiles still accepted when verifying. The built-in profiles are always accepted. |
| `Pepper` | `null` | Optional `IPasswordPepper`. |
| `LegacyFormats` | `V1LegacyFormat.Instance` | Read-only formats accepted when verifying. |
| `MaxPasswordBytes` | `1024` | Longest password in UTF-8 bytes after NFKC normalization. Must be 64 to 1048576. |
| `MaxConcurrency` | `Environment.ProcessorCount` | Hashes computed at once. `0` disables the limit. Cannot be negative. |
| `ConcurrencyTimeout` | 30 seconds | How long a call waits for a free slot before throwing `PasswordHasherBusyException`. |
| `ComputeRehashOnVerify` | `true` | A successful verify of an outdated hash also returns the replacement hash. |
| `AllowWeakProfiles` | `false` | Accept profiles below the OWASP minimums. Only for tests. |

[Profiles](./profiles.md), [Peppers](./peppers.md) and [Limits and concurrency](./limits-and-concurrency.md) explain each setting in depth.

## The builder

`AddMasterlyHash` returns a `MasterlyHashBuilder`. Each method adds a configure step for `PasswordHasherOptions` and returns the builder, so calls chain.

```csharp title="Program.cs"
using Masterly.Hash;
using Masterly.Hash.Legacy;
using Masterly.Hash.Pepper.AwsKms;

// AwsKmsPepper is registered as a singleton elsewhere; the AWS KMS page shows how to create it.
builder.Services.AddMasterlyHash(builder.Configuration.GetSection("MasterlyHash"))
    .AddLegacyFormat(new BCryptFormat())
    .WithPepper(services => services.GetRequiredService<AwsKmsPepper>());
```

| Method | Effect |
|--------|--------|
| `Configure(Action<PasswordHasherOptions>)` | Adds a configure step. |
| `Configure<TDep>(Action<PasswordHasherOptions, TDep>)` | Adds a configure step that receives a service resolved from the container. `TDep` must be a reference type. |
| `WithPepper(IPasswordPepper)` | Uses this pepper for new hashes and to verify peppered ones. Replaces any earlier pepper. |
| `WithPepper(Func<IServiceProvider, IPasswordPepper>)` | Creates the pepper from the container. Throws `InvalidOperationException` ("The pepper factory returned null.") if the factory returns `null`. Replaces any earlier pepper. |
| `AddLegacyFormat(ILegacyHashFormat)` | Accepts hashes in a legacy format. Adding the same instance twice has no effect. |
| `AddLegacyFormat(Func<IServiceProvider, ILegacyHashFormat>)` | Creates the format from the container. Throws `InvalidOperationException` if the factory returns `null`. |
| `UseProfile(HashProfile)` | Uses this profile for new hashes. Overrides `DefaultProfile` from configuration. |
| `AddProfile(HashProfile)` | Keeps accepting hashes made with a custom profile that is no longer the default. Built-in profiles never need it. |
| `Services` | The underlying `IServiceCollection`, for extension methods. |
| `MeterName` | The constant `"Masterly.Hash"` (the same value as `PasswordHasher.MeterName`), the name of the metrics meter. See [Observability](./observability.md). |

Every method throws `ArgumentNullException` for a `null` argument.

:::note

The factory overloads run while the options are built. That can happen more than once: once for startup validation and once on first resolution. Keep factories cheap and idempotent, and register the pepper itself as a singleton so the factory only resolves it.

:::

:::tip

`AddLegacyFormat` appends the format to the end of `LegacyFormats`, after the built-in 1.x format. The 1.x format matches any plain base64 string, so for base64-shaped formats (ASP.NET Identity, unsalted digests) `Inspect` and `TryWrap` may report the 1.x format first. Verification is not affected. To insert formats ahead of the 1.x format, use the `Masterly.Hash.Legacy` extension inside a configure step instead: `.Configure(options => options.AddLegacyFormats(new DjangoPbkdf2Format()))`. See [Legacy formats](./legacy-formats.md).

:::

### Custom profiles

Custom profiles are code-only. Configuration can select only the built-in profile ids.

```csharp title="Program.cs"
using Masterly.Hash;

HashProfile previous = HashProfile.Argon2id("acme-2025", memoryKiB: 47104, iterations: 2);
HashProfile current = HashProfile.Argon2id("acme-2026", memoryKiB: 65536, iterations: 3);

builder.Services.AddMasterlyHash()
    .UseProfile(current)     // new hashes
    .AddProfile(previous);   // old hashes still verify and are upgraded on login
```

Profile ids are permanent. Registering a profile whose id is already used with different parameters (including a built-in id such as `2026a`) is a validation error. See [Profiles](./profiles.md).

## Bind from configuration

Pass an `IConfiguration` section to bind `MasterlyHashConfiguration` and map it onto the options:

```csharp title="Program.cs"
builder.Services.AddMasterlyHash(builder.Configuration.GetSection("MasterlyHash"));
```

The overload also takes an optional configure step that runs after the configuration is applied: `AddMasterlyHash(section, options => ...)`.

### The `MasterlyHash` section

```json title="appsettings.json"
{
  "MasterlyHash": {
    "DefaultProfile": "2026a",
    "MaxConcurrency": 8,
    "ConcurrencyTimeout": "00:00:10",
    "MaxPasswordBytes": 1024,
    "ComputeRehashOnVerify": true,
    "Pepper": {
      "CurrentKeyId": "k2",
      "Keys": {
        "k1": "<base64, at least 32 bytes>",
        "k2": "<base64, at least 32 bytes>"
      }
    }
  }
}
```

Every setting is optional. An absent value keeps the `PasswordHasherOptions` default.

| Key | Type | Maps to | Rules |
|-----|------|---------|-------|
| `DefaultProfile` | string | `DefaultProfile` | A built-in profile id: `2026a` (Argon2id, 64 MiB), `2026c` (Argon2id, 19 MiB) or `2026f` (PBKDF2-HMAC-SHA512). Surrounding whitespace is trimmed. Empty or whitespace keeps the default. Any other value is a startup error. |
| `MaxConcurrency` | integer | `MaxConcurrency` | `0` or more. `0` disables the limit. |
| `ConcurrencyTimeout` | TimeSpan string | `ConcurrencyTimeout` | Positive and at most `24.20:31:23.647` (`int.MaxValue` milliseconds, about 24.8 days), or `-00:00:00.001` for infinite. |
| `MaxPasswordBytes` | integer | `MaxPasswordBytes` | 64 to 1048576. |
| `ComputeRehashOnVerify` | boolean | `ComputeRehashOnVerify` | |
| `Pepper` | object | `Pepper` | When present and not empty, an `HmacPepper` is created from it. |
| `Pepper:CurrentKeyId` | string | `HmacPepper.CurrentKeyId` | Required when keys are configured. Must match `^[A-Za-z0-9-]{1,32}$` and be present in `Keys`. Trimmed. |
| `Pepper:Keys` | object | the key ring | Key id to standard base64 key. Padded or unpadded base64; surrounding whitespace is trimmed. Each key must decode to at least 32 (`HmacPepper.MinKeyLength`) and at most 1024 bytes. Each id must match `^[A-Za-z0-9-]{1,32}$`. At least one key. |

A `Pepper` section with no `CurrentKeyId` and no keys counts as absent: no pepper is configured.

### Environment variables and secret stores

Configuration keys map to environment variables with a double underscore, so a pepper key can come from the environment instead of a file:

```bash
MasterlyHash__Pepper__CurrentKeyId=k2
MasterlyHash__Pepper__Keys__k2=<base64>
```

The same keys work with user secrets, Azure App Configuration, or any other configuration provider. Generate a key with `HmacPepper.GenerateKey()` (32 random bytes) and encode it with `Convert.ToBase64String`.

:::danger

Never commit pepper keys to source control, and never store them in the same database as the hashes. A pepper only helps while an attacker who has your database does not also have the key. Keep keys in a secret store and load them through a configuration provider, or keep the key inside a KMS with [HashiCorp Vault](./hashicorp-vault.md), [AWS KMS](./aws-kms.md) or [Azure Key Vault](./azure-key-vault.md).

:::

### Rotating the configured pepper

**1. Add the new key** to `Keys` and point `CurrentKeyId` at it. New hashes use it; existing hashes still verify with the old key and report `RehashReason.OutdatedPepperKey`, so they are upgraded on the next login.

**2. Keep the old key** until every hash made with it has been rehashed. Use `IPasswordHasher.Inspect` to find them (see [Auditing hash tables](./auditing-hash-tables.md)).

**3. Remove the old key.** Hashes still made with it then fail verification with `VerificationFailureReason.UnknownPepperKey`. They never throw.

:::note

Configuration keys are case-insensitive, so two pepper key ids that differ only by case (`k1` and `K1`) cannot both be configured.

:::

### Code wins over configuration

The configuration is applied before every code configure step for `PasswordHasherOptions`, no matter when that step was registered: earlier or later builder calls, `services.Configure<PasswordHasherOptions>(...)`, or steps from other packages such as `AddMasterlyPasswordHasher`. Configuration never overwrites code.

```csharp title="Program.cs"
using Masterly.Hash;

// Registered first, still runs after the configuration.
builder.Services.AddMasterlyHash().UseProfile(HashProfile.Fips2026a);

// "DefaultProfile": "2026a" in appsettings.json is overridden; the other settings still apply.
builder.Services.AddMasterlyHash(builder.Configuration.GetSection("MasterlyHash"));
```

The same rule applies to the pepper: a `WithPepper` call replaces a pepper configured in `MasterlyHash:Pepper`.

The bound `MasterlyHashConfiguration` is also available as `IOptions<MasterlyHashConfiguration>`. It contains the pepper key text, so do not log or serialize it.

## Validation

Both the options and the bound configuration are validated, and every problem is reported at once.

| Problem | Exception |
|---------|-----------|
| Unknown or misspelled key under the section, such as `Peper` or `DefaultProfiel` | `InvalidOperationException` from the configuration binder. |
| A value that cannot be parsed, such as `"MaxConcurrency": "many"` | `InvalidOperationException` from the configuration binder. |
| Unknown profile id, out-of-range number, malformed or short pepper key, `CurrentKeyId` missing from `Keys` | `OptionsValidationException`, one failure per problem. |
| Invalid options set in code: `null` `DefaultProfile`, a weak profile without `AllowWeakProfiles`, a profile id reused with different parameters, a `null` or duplicate legacy format, a bad legacy format id (`^[a-z0-9][a-z0-9-]{0,31}$`), a bad pepper `CurrentKeyId`, out-of-range limits | `OptionsValidationException`. |

Unknown keys are errors on purpose: a typo such as `Peper` must not silently turn off the pepper.

`PasswordHasherOptionsValidator` applies the same rules as the `PasswordHasher` constructor, with one stricter rule: a finite `ConcurrencyTimeout` must be at most `int.MaxValue` milliseconds. Larger values pass the constructor but make the concurrency gate throw `ArgumentOutOfRangeException` on .NET 8 as soon as a call has to wait.

Validation messages name settings and key ids only. Key text and key bytes are never included, and an unknown `DefaultProfile` value is echoed only if it looks like a profile id, so a secret pasted into the wrong field is never logged. Decoded key buffers are zeroed after use.

### When validation runs

- **On hosts with `Microsoft.Extensions.Hosting` 8.0 or later** (ASP.NET Core, the Generic Host, Worker Services), validation runs when the host starts. A bad configuration stops the application before it serves a request.
- **Everywhere**, validation runs on the first resolution of the hasher.

On other hosts (console apps without the Generic Host, tests), call `ValidateMasterlyHash` right after building the provider:

```csharp title="Program.cs"
using Masterly.Hash;
using Microsoft.Extensions.DependencyInjection;

ServiceCollection services = new ServiceCollection();
services.AddMasterlyHash(configuration.GetSection("MasterlyHash"));

using ServiceProvider provider = services.BuildServiceProvider();
PasswordHasher hasher = provider.ValidateMasterlyHash();   // throws now, not on the first login
```

`ValidateMasterlyHash` builds `PasswordHasher` and `IPasswordHasher` and returns the hasher. It throws `OptionsValidationException` for invalid options or configuration, and `InvalidOperationException` if `AddMasterlyHash` was never called.

## Lifetime and reloads

The hasher is built once, on first resolution, from the final options. Later configuration changes, including reload-on-change of `appsettings.json`, do not affect an already-built hasher. To change the profile or rotate a configured pepper key, restart the application.

The singleton is thread-safe. Concurrent first resolutions build exactly one hasher.

## Decorating the hasher

To wrap the hasher (for auditing, for example), register your own `IPasswordHasher` after `AddMasterlyHash` and resolve the concrete `PasswordHasher` inside it. The last registration wins, and `AddMasterlyHash` leaves registrations made after its first call alone.

```csharp title="Program.cs"
using Masterly.Hash;

builder.Services.AddMasterlyHash(builder.Configuration.GetSection("MasterlyHash"));
builder.Services.AddSingleton<IPasswordHasher>(services =>
    new AuditingPasswordHasher(services.GetRequiredService<PasswordHasher>()));
```

`AuditingPasswordHasher` is your own class that implements `IPasswordHasher` and forwards every call.

## Native AOT and trimming

Binding uses the reflection-based configuration binder, so this package is not marked trimming- or AOT-compatible. For Native AOT, configure the options in code with `AddMasterlyHash(options => ...)` and do not use the `IConfiguration` overload.

## See also

- [Profiles](./profiles.md)
- [Peppers](./peppers.md)
- [Limits and concurrency](./limits-and-concurrency.md)
- [ASP.NET Core Identity](./aspnetcore-identity.md)
- [Observability](./observability.md)
- [API reference](./api-reference.md)
