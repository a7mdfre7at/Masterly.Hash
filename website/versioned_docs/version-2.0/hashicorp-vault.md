---
title: HashiCorp Vault Transit Pepper
sidebar_label: HashiCorp Vault
description: Compute the password pepper with the HashiCorp Vault Transit engine, so the HMAC key never leaves Vault, and rotate it by Transit key version.
---

`Masterly.Hash.Pepper.HashiCorpVault` is an `IPasswordPepper` whose HMAC is computed by the HashiCorp Vault Transit secrets engine. For every hash and verify, the hasher sends the password-derived pepper input to Vault's `hmac` endpoint, and Vault answers with an HMAC-SHA256 under a Transit key that never leaves Vault. Pepper key ids map to Transit key versions, so rotating the Transit key rotates the pepper.

```bash
dotnet add package Masterly.Hash.Pepper.HashiCorpVault
```

The package targets .NET 8, has no dependency besides `Masterly.Hash` and is marked AOT-compatible.

## When to use it

Use the Vault pepper when:

- You already run Vault, and your application can authenticate to it (token, AppRole, Kubernetes auth through Vault Agent).
- You want a database leak **and** an application memory dump to be useless for offline cracking. The key is not in your process, so neither exposes it.

Consider something else when:

- Vault availability is not at least as good as your login availability. Every hash and every verification needs Vault. If Vault is down, logins fail with HTTP 503 instead of working.
- You cannot accept that Vault sees the normalized password bytes. Transit computes the HMAC on the input you send, so Vault processes it on every request.
- Your login path must be synchronous. The pepper is async; the sync API blocks a thread-pool thread on every call (see [Load and latency](#load-and-latency)). This includes the ASP.NET Core Identity adapter.

If keeping the key inside a service is not a requirement, a local `HmacPepper` or the [Azure Key Vault](./azure-key-vault.md) provider has no per-request network dependency. [Peppers](./peppers.md) compares the options.

## How it works

1. **The hasher calls `ApplyAsync`** with the pepper key id and the input. For a new hash, the key id is `CurrentKeyId` and the input is the NFKC-normalized UTF-8 password. For an [onion-wrapped](./onion-wrapping.md) hash, the input is the legacy digest instead.
2. **The pepper sends one request** to `POST {VaultAddress}/v1/{MountPath}/hmac/{KeyName}/sha2-256` with the body `{"input":"<base64>","key_version":N}` and the headers `X-Vault-Token` and, when set, `X-Vault-Namespace`.
3. **Vault answers** `{"data":{"hmac":"vault:vN:<base64>"}}`. The pepper checks that `N` is the version it asked for and that the value decodes to exactly 32 bytes (`HashiCorpVaultPepper.HmacLength`).
4. **The hasher feeds the HMAC into Argon2id** (or the profile's KDF) and stores the key id in the hash: `$mh$p=2026a,k=v1$...`.

Key ids have the form `v{N}`: `v1` is Transit version 1, `v2` is version 2, and so on. Every request names its version explicitly, so a Transit rotation never changes the HMAC of an existing key id.

`IsKnownKey` only checks that the id is `v{N}` with N between `MinKeyVersion` and `MaxKeyVersion`. It makes no network call. A hash under a version outside that range fails with `UnknownPepperKey` before Vault is contacted.

## Set up Vault

**1. Enable Transit and create the key.**

```bash title="Vault CLI"
vault secrets enable transit

# Any Transit key type can compute HMACs; each key version has its own HMAC key.
# On Vault 1.12 and later you can create a dedicated HMAC key with type=hmac instead.
vault write -f transit/keys/password-pepper
```

Leave `exportable` and `allow_plaintext_backup` at their default `false`. If the key can be exported, it no longer "never leaves Vault".

**2. Write a least-privilege policy.** The application only needs `update` on the `sha2-256` HMAC path of this key:

```hcl title="app-pepper.hcl"
path "transit/hmac/password-pepper/sha2-256" {
  capabilities = ["update"]
}
```

```bash
vault policy write app-pepper app-pepper.hcl
```

If you mount Transit somewhere else, for example `team-a/transit`, use that path in the policy and set `MountPath` to match. With Vault Enterprise namespaces, the path is relative to the namespace you pass in `Namespace`.

Do not grant `read` on `transit/keys/password-pepper`, `update` on `.../rotate` or `.../config`, or any `encrypt`/`decrypt` path. Rotation is an operator task, not an application one.

**3. Give the application a token** with that policy. For a quick test, `vault token create -policy=app-pepper -period=24h`. In production, use an auth method (AppRole, Kubernetes, cloud IAM) and let Vault Agent keep the token fresh; see [Supplying the token](#supplying-the-token).

## Configure the pepper

```csharp title="Program.cs"
using System;
using System.Net.Http;
using Masterly.Hash;
using Masterly.Hash.Pepper.HashiCorpVault;

HttpClient vaultHttp = new HttpClient(new SocketsHttpHandler
{
    PooledConnectionLifetime = TimeSpan.FromMinutes(5),
});

HashiCorpVaultPepper pepper = new HashiCorpVaultPepper(vaultHttp, new HashiCorpVaultPepperOptions
{
    VaultAddress = new Uri("https://vault.example.com:8200"),
    KeyName = "password-pepper",
    Token = Environment.GetEnvironmentVariable("VAULT_TOKEN"),
    CurrentKeyVersion = 1,
});

PasswordHasher hasher = new PasswordHasher(new PasswordHasherOptions { Pepper = pepper });

// cancellationToken comes from your application, for example HttpContext.RequestAborted
string stored = await hasher.HashAsync("correct horse battery staple", cancellationToken);
// $mh$p=2026a,k=v1$...

PasswordVerificationResult result = await hasher.VerifyAsync("correct horse battery staple", stored, cancellationToken);
```

The constructor validates the options and copies them; changing the options object afterwards has no effect. It does not contact Vault, so a wrong token or key name shows up on the first hash or verify, not at startup. Add a [health check](#health-check) if you want to find out earlier.

The pepper does not dispose the `HttpClient`. It is thread-safe; create one per application and reuse it. Because it lives for the whole process, give it a long-lived `HttpClient` with `PooledConnectionLifetime` set, so DNS changes to the Vault address are picked up.

### Options

| Option | Default | Rules |
|--------|---------|-------|
| `VaultAddress` | none (required) | Absolute URI. Must be `https` unless `AllowInsecureHttp` is set. No user info, query or fragment. A path is kept, so `https://proxy.example.com/vault` works. |
| `MountPath` | `"transit"` | Leading and trailing `/` are trimmed. May contain `/` (`team-a/transit`). Each segment: 1 to 128 of `A-Z a-z 0-9 . _ -`, and not `.` or `..`. |
| `KeyName` | none (required) | 1 to 128 of `A-Z a-z 0-9 . _ -`, not `.` or `..`. |
| `Token` | `null` | Static token sent as `X-Vault-Token`. Printable ASCII, no spaces, 1 to 8192 characters. Set exactly one of `Token` and `TokenProvider`. |
| `TokenProvider` | `null` | `Func<CancellationToken, Task<string>>` called before every request. Set exactly one of `Token` and `TokenProvider`. |
| `Namespace` | `null` | Vault Enterprise namespace, sent as `X-Vault-Namespace`. 1 to 256 printable ASCII characters, no spaces. |
| `CurrentKeyVersion` | `0` (must be set) | Transit version used for new hashes; key id `v{N}`. At least 1. |
| `MinKeyVersion` | `1` | Oldest version accepted for verification. Between 1 and `CurrentKeyVersion`. |
| `MaxKeyVersion` | `null` (means `CurrentKeyVersion`) | Newest version accepted for verification. Not below `CurrentKeyVersion`. Raise it during a rolling deployment. |
| `Timeout` | 10 seconds | Limit for one request, including the token provider, any handler retries and reading the response. Greater than zero, at most 10 minutes. |
| `AllowInsecureHttp` | `false` | Allows an `http://` address. Local development only: the token and the pepper input would travel in clear text. |

Any violation throws `ArgumentException` with `ParamName` `"options"`. A null `httpClient` or `options` throws `ArgumentNullException`.

## Register with dependency injection

Register the pepper as a singleton and hand it to the hasher with `WithPepper`. The factory overload can run more than once while options are built, so resolve a singleton inside it instead of creating a new pepper.

```csharp title="Program.cs"
using System;
using System.Net.Http;
using Masterly.Hash.DependencyInjection;
using Masterly.Hash.Pepper.HashiCorpVault;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);

builder.Services.AddSingleton<HashiCorpVaultPepper>(_ =>
{
    HttpClient vaultHttp = new HttpClient(new SocketsHttpHandler
    {
        PooledConnectionLifetime = TimeSpan.FromMinutes(5),
    });

    HashiCorpVaultPepperOptions options = new HashiCorpVaultPepperOptions
    {
        VaultAddress = builder.Configuration.GetValue<Uri>("Vault:Address"),
        MountPath = builder.Configuration["Vault:MountPath"] ?? "transit",
        KeyName = builder.Configuration["Vault:PepperKey"],
        Token = builder.Configuration["Vault:Token"],
        CurrentKeyVersion = builder.Configuration.GetValue<int>("Vault:CurrentKeyVersion"),
        MinKeyVersion = builder.Configuration.GetValue<int>("Vault:MinKeyVersion", 1),
        MaxKeyVersion = builder.Configuration.GetValue<int?>("Vault:MaxKeyVersion"),
    };

    return new HashiCorpVaultPepper(vaultHttp, options);
});

builder.Services.AddMasterlyHash()
    .WithPepper(provider => provider.GetRequiredService<HashiCorpVaultPepper>());
```

Keeping `CurrentKeyVersion`, `MinKeyVersion` and `MaxKeyVersion` in configuration lets you rotate with a configuration change instead of a code change. Never put the token in `appsettings.json`; read it from the environment, a mounted file or a token provider. [Dependency Injection](./dependency-injection.md) covers the builder in full.

## Supplying the token

**Static token.** `Token` is sent unchanged with every request. Use it for short-lived processes and tests, or when a sidecar renews the token in place (a periodic token renewed by Vault Agent keeps its value).

**Token provider.** `TokenProvider` is called before **every** request, with a token that is cancelled when `Timeout` elapses or the caller cancels. Use it when the token is re-issued, for example by Vault Agent auto-auth writing to a file sink:

```csharp title="Program.cs"
using System;
using System.IO;
using System.Threading;
using Masterly.Hash.Pepper.HashiCorpVault;

HashiCorpVaultPepperOptions options = new HashiCorpVaultPepperOptions
{
    VaultAddress = new Uri("https://vault.example.com:8200"),
    KeyName = "password-pepper",
    CurrentKeyVersion = 1,
    TokenProvider = async (CancellationToken cancellationToken) =>
    {
        // Vault Agent rewrites this file whenever it renews or re-authenticates.
        string token = await File.ReadAllTextAsync("/vault/token", cancellationToken);
        return token.Trim();
    },
};
```

Rules for the provider:

- Return the token without surrounding whitespace. A null, empty, or non-printable value, or one with spaces, throws `PepperUnavailableException` ("The Vault token provider returned an empty or invalid token.").
- Any exception it throws, other than `OperationCanceledException`, becomes `PepperUnavailableException` ("The Vault token provider failed.") with the original as `InnerException`.
- Its time counts against `Timeout`. A slow provider times out like a slow Vault.
- It runs on every hash and verify. If fetching the token is expensive, cache it in your provider and refresh it in the background.

## Rotating the key

Rotation creates a new Transit version and makes it current. Existing hashes keep verifying under their old version and are upgraded the next time each user logs in.

**1. Rotate the Transit key.**

```bash
vault write -f transit/keys/password-pepper/rotate
vault read -field=latest_version transit/keys/password-pepper
```

Running instances are not affected: every request names its version explicitly.

**2. Let every instance accept the new version.** Deploy `MaxKeyVersion = N+1` while keeping `CurrentKeyVersion = N`. Wait until every instance runs this configuration.

Skip this step only if you stop all instances before starting new ones. Otherwise an old instance that sees a hash written by a new instance reports `UnknownPepperKey`, and that user's login fails.

**3. Make the new version current.** Deploy `CurrentKeyVersion = N+1`. New hashes now carry `k=vN+1`.

Do not raise `CurrentKeyVersion` above Vault's `latest_version`. Vault refuses the HMAC, and every hash and verify throws `PepperUnavailableException`.

**4. Upgrade on login.** A successful verification of a `vN` hash returns `SuccessRehashNeeded` with `RehashReason.OutdatedPepperKey` and a fresh hash in `Rehash`. Store it, as described in [Upgrade on Login](./upgrade-on-login.md).

During step 2 an instance still on `CurrentKeyVersion = N` also reports `OutdatedPepperKey` for a `vN+1` hash and offers a `vN` rehash. Storing it is harmless: the hash moves back to `vN` and is upgraded again after step 3.

**5. Retire the old version** once no stored hash uses it. Count what is left with [`masterly-hash audit`](./command-line-tool.md) and `--pepper-key-ids vN+1,vN`, or with a query. The key id is followed by `$`, or by `,` when the hash is wrapped:

```sql
SELECT COUNT(*) FROM Users
WHERE PasswordHash LIKE '$mh$%,k=v1$%' OR PasswordHash LIKE '$mh$%,k=v1,%';
```

Then deploy `MinKeyVersion = N+1`. Hashes still under older versions now fail with `UnknownPepperKey`, without a call to Vault. Those users need a password reset.

Only after every instance runs with the raised `MinKeyVersion`, tell Vault to refuse the old versions. Vault checks `min_encryption_version` when it computes an HMAC; raising `min_decryption_version` to the same value as well keeps the key consistent and is required before a trim:

```bash
# N+1, here 2
vault write transit/keys/password-pepper/config min_decryption_version=2 min_encryption_version=2
```

If you do this first, an instance that still accepts the old version sends it to Vault, Vault refuses, and the login fails with `PepperUnavailableException` instead of `UnknownPepperKey`.

:::danger

`vault write transit/keys/password-pepper/trim min_available_version=N` deletes the key versions below N permanently. Vault only accepts it when `min_decryption_version` and `min_encryption_version` are both at least N. Any hash still under a deleted version can never be verified again. Trim only after the audit shows zero such hashes, and only after you have decided that those accounts will reset their passwords.

:::

### Adopting the pepper on an existing table

Hashes made without a pepper (`$mh$p=2026a$...`) keep verifying after you add the Vault pepper; no pepper is applied to them. A successful login returns `OutdatedPepperKey` with a peppered rehash. To protect accounts that do not log in, there is no offline path: the pepper is applied to the password, which you do not have. Weak legacy hashes can still be wrapped offline; see [Onion Wrapping](./onion-wrapping.md).

A hasher has exactly one pepper. Hashes made with a different provider's key ids (for example `k1` from a local `HmacPepper`) fail with `UnknownPepperKey` after you switch to Vault.

## Failure handling

Every failure to obtain the HMAC throws `Masterly.Hash.Pepper.HashiCorpVault.PepperUnavailableException`. The hasher does not catch it, so an outage is never reported as a wrong password. Messages never contain the token, the input or the HMAC; the original exception, if any, is in `InnerException`.

| Cause | Message |
|-------|---------|
| `Timeout` elapsed (Vault, handler retries, or the token provider were too slow; also `HttpClient.Timeout` firing first) | HashiCorp Vault did not answer within the configured timeout. |
| `HttpRequestException` (DNS, TLS, connection refused) | HashiCorp Vault could not be reached. |
| `IOException` while sending or reading | The connection to HashiCorp Vault failed. |
| Any other exception from the `HttpClient` pipeline (resilience handler, open circuit, custom `DelegatingHandler`, disposed client) | HashiCorp Vault request failed. |
| Non-2xx status: 403 (bad token or policy), 400 (version does not exist or is below `min_encryption_version`), 429, 500, 503 (sealed) | HashiCorp Vault refused the Transit HMAC request with HTTP *code*. |
| Response body over 64 KiB, declared or actual | HashiCorp Vault returned an oversized response. |
| Not JSON, no `data.hmac`, escaped or malformed value, not exactly 32 bytes, trailing content | HashiCorp Vault returned an unexpected Transit HMAC response. |
| `vault:vN:` names a different version than requested | HashiCorp Vault answered with a different key version than requested. |
| Token provider threw / returned an invalid token | The Vault token provider failed. / The Vault token provider returned an empty or invalid token. |

Other exceptions from the pepper:

- `OperationCanceledException` when **your** cancellation token is cancelled. It is not converted, so cancelled requests do not look like outages. An already-cancelled token never reaches Vault.
- `KeyNotFoundException` from `Apply`/`ApplyAsync` for an id outside the configured range. The hasher checks `IsKnownKey` first, so you only see this when calling the pepper directly.
- `ArgumentNullException` for a null input.

The pepper does not retry. To retry transient errors, add a resilience handler to the `HttpClient`; `Timeout` still bounds the whole call.

**Map it to HTTP 503.** The `PasswordHasherBusyException` handler from `AddMasterlyHashExceptionHandler` does not cover this exception, so add one:

```csharp title="PepperUnavailableExceptionHandler.cs"
using System;
using System.Threading;
using System.Threading.Tasks;
using Masterly.Hash.Pepper.HashiCorpVault;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Http;

namespace MyApp.Web;

/// <summary>Answers an unavailable Vault pepper with 503, so an outage never looks like a wrong password.</summary>
public sealed class PepperUnavailableExceptionHandler : IExceptionHandler
{
    /// <inheritdoc />
    public async ValueTask<bool> TryHandleAsync(HttpContext httpContext, Exception exception, CancellationToken cancellationToken)
    {
        if (exception is not PepperUnavailableException)
        {
            return false;
        }

        httpContext.Response.Headers.RetryAfter = "5";
        await TypedResults.Problem(
            statusCode: StatusCodes.Status503ServiceUnavailable,
            title: "Sign-in is temporarily unavailable.").ExecuteAsync(httpContext);
        return true;
    }
}
```

```csharp title="Program.cs"
builder.Services.AddProblemDetails();
builder.Services.AddExceptionHandler<PepperUnavailableExceptionHandler>();
// ...
app.UseExceptionHandler();
```

The exception handler middleware already logs the exception, so the handler does not log it again.

:::note

Each pepper package has its own `PepperUnavailableException` type in its own namespace. They share no base type besides `Exception`. Catch the one from the package you use.

:::

## Load and latency

Each call below is one round trip to Vault:

| Operation | Vault calls |
|-----------|-------------|
| `HashAsync` | 1 |
| `VerifyAsync` on a current hash, right or wrong password | 1 |
| `VerifyAsync` on an older version, right password | 2 (verify, then the rehash). 1 if `ComputeRehashOnVerify` is `false`. |
| `VerifyAsync` on an unpeppered or legacy-format hash, right password | 1 (the rehash only) |
| `VerifyOrDummyAsync` with a null stored hash (unknown user) | 1, under the current version, so unknown users cost the same as real ones |
| Verify of a malformed hash, unknown profile or a version outside the range | 0 |
| `Inspect`, `NeedsRehash`, `IsKnownKey` | 0 |
| `TryWrap` | 1, through the synchronous `Apply` |

Size Vault for your peak login rate, including failed attempts and attacks. A credential-stuffing run hits Vault as hard as real users do. Rate-limit the login endpoint; see [User Enumeration](./user-enumeration.md) and [Limits and Concurrency](./limits-and-concurrency.md).

The Vault call happens before the hasher takes a slot under `MaxConcurrency`, so a slow Vault does not hold hashing slots. It does hold the request.

**Use the async API.** `ApplyAsync` is the real implementation and uses `ConfigureAwait(false)` throughout. `Apply`, used by `Hash`, `Verify`, `VerifyOrDummy` and `TryWrap`, runs `ApplyAsync` on the thread pool and blocks the calling thread until it finishes. The ASP.NET Core Identity adapter calls the sync API, because Identity's `IPasswordHasher<TUser>` is synchronous; under load that means one blocked thread per login waiting on Vault. Wrapping a large table with `TryWrap` makes one sync Vault call per row.

## Health check

The pepper has no health API of its own. A probe that computes one HMAC checks the address, the token, the policy and the key version in one call:

```csharp title="VaultPepperHealthCheck.cs"
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Masterly.Hash.Pepper.HashiCorpVault;
using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace MyApp.Web;

/// <summary>Checks that Vault computes the pepper HMAC with the current key version.</summary>
public sealed class VaultPepperHealthCheck : IHealthCheck
{
    private readonly HashiCorpVaultPepper _pepper;

    /// <summary>Creates the check.</summary>
    public VaultPepperHealthCheck(HashiCorpVaultPepper pepper)
    {
        _pepper = pepper;
    }

    /// <inheritdoc />
    public async Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        byte[] probe = Encoding.ASCII.GetBytes("masterly-hash-health-probe");
        try
        {
            await _pepper.ApplyAsync(_pepper.CurrentKeyId, probe, cancellationToken);
            return HealthCheckResult.Healthy();
        }
        catch (PepperUnavailableException exception)
        {
            return HealthCheckResult.Unhealthy("Vault cannot compute the password pepper.", exception);
        }
    }
}
```

```csharp title="Program.cs"
builder.Services.AddHealthChecks().AddCheck<VaultPepperHealthCheck>("vault-pepper");
```

Every probe is a Vault request, so keep the probe interval reasonable.

## Security notes

- **The key.** It stays in Vault, as long as the Transit key is not exportable. A database leak or an application memory dump does not reveal it.
- **The input.** The normalized password bytes (or, for a wrapped hash, the legacy digest) are sent to Vault on every request. Vault, and anything that can read that TLS traffic, sees them. `http` addresses are refused unless `AllowInsecureHttp` is set.
- **Audit devices.** Vault's audit devices HMAC request fields by default, so `input` is not logged in clear text. Do not enable `log_raw` on an audit device used by this mount.
- **The token.** It only needs `update` on one path. A stolen token lets an attacker compute peppers online, through Vault, which records every request in its audit devices and can throttle them with a rate limit quota. It does not reveal the key.
- **No secrets in errors.** Messages never contain the token, the input or the HMAC. The request body, the response body and intermediate buffers are zeroed after use, and the JSON is built and parsed as UTF-8 bytes, so no password-derived `string` is created. In .NET this is best effort; see the [Threat Model](./threat-model.md).
- **Strict responses.** The response must name the requested version and hold exactly 32 bytes, with JSON nesting limited to 16 levels and the body limited to 64 KiB. A misbehaving or hostile endpoint cannot make the pepper accept an HMAC under the wrong version or exhaust memory.

## API summary

| Member | Description |
|--------|-------------|
| `HashiCorpVaultPepper(HttpClient httpClient, HashiCorpVaultPepperOptions options)` | Validates and copies the options. Makes no network call. |
| `string CurrentKeyId` | `v{CurrentKeyVersion}`. |
| `Uri Endpoint` | The Transit HMAC URL the pepper calls, for logs and diagnostics. |
| `bool IsKnownKey(string keyId)` | `true` for `v{N}` with N in `[MinKeyVersion, MaxKeyVersion]`. No network call. |
| `ValueTask<byte[]> ApplyAsync(string keyId, byte[] input, CancellationToken cancellationToken = default)` | Computes the HMAC in Vault. |
| `byte[] Apply(string keyId, byte[] input)` | Blocks on `ApplyAsync`. Prefer the async hasher API. |
| `static string KeyIdFor(int version)` | `v3` for 3. Throws `ArgumentOutOfRangeException` below 1. |
| `static bool TryParseKeyId(string? keyId, out int version)` | Parses `v{N}` (no leading zeros, N up to `int.MaxValue`). |
| `const int HmacLength` | 32. |

## See also

- [Peppers](./peppers.md): what a pepper protects against and how key ids and rotation work.
- [AWS KMS](./aws-kms.md) and [Azure Key Vault](./azure-key-vault.md): the other key-management providers.
- [Upgrade on Login](./upgrade-on-login.md): storing the rehash after a rotation.
- [Auditing Hash Tables](./auditing-hash-tables.md): finding hashes that still use an old key.
- [Observability](./observability.md): metrics to watch during a rotation.
- [Package README](https://github.com/a7mdfre7at/Masterly.Hash/blob/master/src/Masterly.Hash.Pepper.HashiCorpVault/README.md)
