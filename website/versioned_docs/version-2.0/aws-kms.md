---
title: AWS KMS Pepper
sidebar_label: AWS KMS
description: Compute the password pepper with AWS KMS GenerateMac on an HMAC KMS key, so the key never leaves KMS, and rotate by adding a new key under a new key id.
---

`Masterly.Hash.Pepper.AwsKms` is an `IPasswordPepper` whose HMAC is computed by AWS KMS `GenerateMac` (`HMAC_SHA_256`) on an HMAC KMS key. For every hash and verify, the hasher sends the password-derived pepper input to KMS, and KMS answers with the MAC. The key never leaves KMS. Pepper key ids map to KMS keys through a key map, which is how you rotate.

```bash
dotnet add package Masterly.Hash.Pepper.AwsKms
```

The package targets .NET 8 and depends on `AWSSDK.KeyManagementService` 4.x.

## When to use it

Use the KMS pepper when:

- Your application runs in AWS, or can reach KMS with IAM credentials.
- You want a database leak **and** an application memory dump to be useless for offline cracking. The key is held by KMS, so neither exposes it.

Consider something else when:

- You cannot accept that AWS processes the normalized password bytes. `GenerateMac` computes the MAC on the message you send.
- A KMS outage, throttling or a revoked IAM permission must not stop logins. Every hash and every verification calls KMS; when it fails, logins fail with HTTP 503.
- Your peak login rate, including failed attempts and attacks, does not fit your KMS request quota.
- Your login path must be synchronous. The sync API blocks a thread-pool thread on every call, and the ASP.NET Core Identity adapter uses the sync API.

If keeping the key inside a service is not a requirement, a local `HmacPepper` or the [Azure Key Vault](./azure-key-vault.md) provider has no per-request network dependency. [Peppers](./peppers.md) compares the options.

## How it works

1. **The hasher calls `ApplyAsync`** with the pepper key id and the input. For a new hash, the key id is `CurrentKeyId` and the input is the NFKC-normalized UTF-8 password. For an [onion-wrapped](./onion-wrapping.md) hash, the input is the legacy digest instead.
2. **The pepper looks up the KMS key** for that id in `Keys` and calls `GenerateMac` with `MacAlgorithm = HMAC_SHA_256`, the input as `Message`, and any `GrantTokens`.
3. **KMS returns the MAC.** The pepper checks that it is exactly 32 bytes (`AwsKmsPepper.MacLength`) and, when KMS reports the algorithm, that it is `HMAC_SHA_256`. It copies the MAC and zeroes the SDK's buffer.
4. **The hasher feeds the MAC into Argon2id** (or the profile's KDF) and stores the key id in the hash: `$mh$p=2026a,k=2026-01$...`.

You choose the pepper key ids. Any id matching `^[A-Za-z0-9-]{1,32}$` works; a date such as `2026-01` makes rotations easy to read. `IsKnownKey` checks the key map only and never calls KMS, so a hash under an id that is not in the map fails with `UnknownPepperKey` before KMS is contacted.

## Set up AWS

**1. Create an HMAC key.** The key spec must be `HMAC_256` and the key usage `GENERATE_VERIFY_MAC`:

```bash title="AWS CLI"
aws kms create-key \
  --key-spec HMAC_256 \
  --key-usage GENERATE_VERIFY_MAC \
  --description "Masterly.Hash password pepper 2026-01" \
  --query KeyMetadata.Arn --output text
```

Keep the printed key ARN; it goes into `Keys`.

**2. Grant the application `kms:GenerateMac` on that key only.** Attach this policy to the application's IAM role:

```json title="app-pepper-policy.json"
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "PasswordPepper",
      "Effect": "Allow",
      "Action": "kms:GenerateMac",
      "Resource": [
        "arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
      ],
      "Condition": {
        "StringEquals": {
          "kms:MacAlgorithm": "HMAC_SHA_256"
        }
      }
    }
  ]
}
```

The pepper never calls `VerifyMac`, `DescribeKey` or any other KMS action, so do not grant them. During a rotation, list both key ARNs under `Resource`.

**3. Check the key policy.** The default key policy lets IAM policies in the account grant access, so step 2 is enough. If the key has a custom key policy, add a statement for the application role:

```json title="Key policy statement"
{
  "Sid": "AllowAppGenerateMac",
  "Effect": "Allow",
  "Principal": { "AWS": "arn:aws:iam::111122223333:role/app-role" },
  "Action": "kms:GenerateMac",
  "Resource": "*",
  "Condition": {
    "StringEquals": { "kms:MacAlgorithm": "HMAC_SHA_256" }
  }
}
```

Keep `kms:ScheduleKeyDeletion`, `kms:DisableKey` and `kms:PutKeyPolicy` away from the application role. Deleting the key destroys every hash made with it; see [Rotating the key](#rotating-the-key).

## Configure the pepper

```csharp title="Program.cs"
using Amazon;
using Amazon.KeyManagementService;
using Masterly.Hash;
using Masterly.Hash.Pepper.AwsKms;

IAmazonKeyManagementService kms = new AmazonKeyManagementServiceClient(RegionEndpoint.USEast1);

AwsKmsPepperOptions options = new AwsKmsPepperOptions { CurrentKeyId = "2026-01" };
options.Keys["2026-01"] = "arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab";

AwsKmsPepper pepper = new AwsKmsPepper(kms, options);
PasswordHasher hasher = new PasswordHasher(new PasswordHasherOptions { Pepper = pepper });

// cancellationToken comes from your application, for example HttpContext.RequestAborted
string stored = await hasher.HashAsync("correct horse battery staple", cancellationToken);
// $mh$p=2026a,k=2026-01$...

PasswordVerificationResult result = await hasher.VerifyAsync("correct horse battery staple", stored, cancellationToken);
```

The constructor validates the options and copies them; changing the options object afterwards has no effect. It does not call KMS, so missing permissions show up on the first hash or verify, not at startup. Add a [health check](#health-check) if you want to find out earlier.

The pepper does not dispose the KMS client. It is thread-safe; create one per application and reuse it. The client's Region must be the Region in the key ARNs.

### Options

| Option | Default | Rules |
|--------|---------|-------|
| `Keys` | empty | `IDictionary<string, string>` from pepper key id to KMS key. Ids must match `^[A-Za-z0-9-]{1,32}$`. Values: key ARN, key id, alias ARN or alias name (`alias/...`); 1 to 2048 printable ASCII characters, no whitespace. |
| `CurrentKeyId` | `null` (required) | Pepper key id used for new hashes. Must be a key in `Keys`. |
| `GrantTokens` | empty | Optional KMS grant tokens sent with every `GenerateMac` request. No null or empty entries. |
| `Timeout` | 10 seconds | Limit for one `GenerateMac` call, including SDK retries. Greater than zero, at most 10 minutes. |

Any violation throws `ArgumentException` with `ParamName` `"options"`. A null client or options throws `ArgumentNullException`.

:::warning

Prefer key ARNs to aliases. An alias can be repointed at a different KMS key, and every hash stored under that pepper key id then stops verifying (it reports `Mismatch`, not an error). For the same reason, never change the KMS key an existing pepper key id maps to. To rotate, add a new id.

:::

### Client settings

`AwsKmsPepperOptions.Timeout` bounds the whole call through a cancellation token. The SDK has its own per-attempt timeout and retry policy on the client config:

```csharp title="Program.cs"
using System;
using Amazon;
using Amazon.KeyManagementService;

AmazonKeyManagementServiceConfig kmsConfig = new AmazonKeyManagementServiceConfig
{
    RegionEndpoint = RegionEndpoint.USEast1,
    Timeout = TimeSpan.FromSeconds(3),
    MaxErrorRetry = 2,
};

IAmazonKeyManagementService kms = new AmazonKeyManagementServiceClient(kmsConfig);
```

Credentials come from the SDK's default chain (environment, shared profile, ECS task role, EC2 instance profile, EKS pod identity). Keep the per-attempt timeout well under the pepper's `Timeout` so retries fit inside it. If your instances have no internet path, add a KMS interface VPC endpoint.

## Register with dependency injection

```csharp title="Program.cs"
using System;
using Amazon;
using Amazon.KeyManagementService;
using Masterly.Hash.DependencyInjection;
using Masterly.Hash.Pepper.AwsKms;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);

builder.Services.AddSingleton<IAmazonKeyManagementService>(_ =>
    new AmazonKeyManagementServiceClient(new AmazonKeyManagementServiceConfig
    {
        RegionEndpoint = RegionEndpoint.USEast1,
        Timeout = TimeSpan.FromSeconds(3),
    }));

builder.Services.AddSingleton<AwsKmsPepper>(provider =>
{
    AwsKmsPepperOptions options = new AwsKmsPepperOptions
    {
        CurrentKeyId = builder.Configuration["Pepper:CurrentKeyId"],
    };
    foreach (IConfigurationSection key in builder.Configuration.GetSection("Pepper:Keys").GetChildren())
    {
        options.Keys[key.Key] = key.Value ?? string.Empty;
    }

    return new AwsKmsPepper(provider.GetRequiredService<IAmazonKeyManagementService>(), options);
});

builder.Services.AddMasterlyHash()
    .WithPepper(provider => provider.GetRequiredService<AwsKmsPepper>());
```

```json title="appsettings.json"
{
  "Pepper": {
    "CurrentKeyId": "2026-01",
    "Keys": {
      "2026-01": "arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
    }
  }
}
```

Key ARNs are not secrets, so they can live in `appsettings.json`. Register the pepper as a singleton and resolve it inside `WithPepper`: the factory overload can run more than once while options are built. An empty value fails the constructor's validation with a clear message. [Dependency Injection](./dependency-injection.md) covers the builder in full.

## Rotating the key

HMAC KMS keys do not support automatic or on-demand rotation in KMS. You rotate by creating a new key and adding it under a new pepper key id. Existing hashes keep verifying under their old id and are upgraded the next time each user logs in.

**1. Create a new HMAC key** with the same `create-key` command and add its ARN to the IAM policy's `Resource` list.

**2. Let every instance accept the new id.** Deploy `Keys["2027-01"] = "<new arn>"` while keeping `CurrentKeyId = "2026-01"`. Wait until every instance runs this configuration.

Skip this step only if you stop all instances before starting new ones. Otherwise an old instance that sees a hash written by a new instance reports `UnknownPepperKey`, and that user's login fails.

**3. Make the new id current.** Deploy `CurrentKeyId = "2027-01"`. New hashes now carry `k=2027-01`.

**4. Upgrade on login.** A successful verification of a `2026-01` hash returns `SuccessRehashNeeded` with `RehashReason.OutdatedPepperKey` and a fresh hash in `Rehash`. Store it, as described in [Upgrade on Login](./upgrade-on-login.md).

During step 2 an instance whose current id is still `2026-01` also reports `OutdatedPepperKey` for a `2027-01` hash and offers a `2026-01` rehash. Storing it is harmless: the hash moves back and is upgraded again after step 3.

**5. Retire the old id** once no stored hash uses it. Count what is left with [`masterly-hash audit`](./command-line-tool.md) and `--pepper-key-ids 2027-01,2026-01`, or with a query. The key id is followed by `$`, or by `,` when the hash is wrapped:

```sql
SELECT COUNT(*) FROM Users
WHERE PasswordHash LIKE '$mh$%,k=2026-01$%' OR PasswordHash LIKE '$mh$%,k=2026-01,%';
```

Then remove `2026-01` from `Keys` everywhere. Hashes still using it fail with `UnknownPepperKey`, without a call to KMS. Those users need a password reset.

**6. Disable the old KMS key**, and remove it from the IAM policy:

```bash
aws kms disable-key --key-id arn:aws:kms:us-east-1:111122223333:key/<old-key-id>
```

Disabling is reversible with `enable-key`. If an instance still maps an id to the disabled key, its calls fail with `PepperUnavailableException` (`DisabledException`) rather than verifying.

:::danger

`aws kms schedule-key-deletion` destroys the key after the waiting period (7 to 30 days). Every hash ever made with it becomes unverifiable, and nothing can recover it. Delete an old pepper key only after the audit shows zero hashes under its id, and only after deciding that those accounts reset their passwords. Disabling the key is usually enough.

:::

### Adopting the pepper on an existing table

Hashes made without a pepper (`$mh$p=2026a$...`) keep verifying after you add the KMS pepper; no pepper is applied to them. A successful login returns `OutdatedPepperKey` with a peppered rehash. Accounts that do not log in stay unpeppered, because the pepper is applied to the password. Weak legacy hashes can still be wrapped offline; see [Onion Wrapping](./onion-wrapping.md).

A hasher has exactly one pepper. Hashes made with another provider's key ids fail with `UnknownPepperKey` after you switch to KMS.

### Several Regions

The MAC depends on the key material, so each pepper key id must resolve to the same material wherever it is used. To run the same user table in several Regions, create the key with `--multi-region` and replicate it with `aws kms replicate-key`. Replicas share key material, so each Region's deployment can map the same pepper key id to its local replica ARN. Independent single-Region keys produce different MACs, and hashes made in one Region would report `Mismatch` in the other.

## Failure handling

Every failure to obtain the MAC throws `Masterly.Hash.Pepper.AwsKms.PepperUnavailableException`. The hasher does not catch it, so an outage is never reported as a wrong password. Messages carry at most the KMS error code and HTTP status, never the input; the original exception is in `InnerException`.

| Cause | Message |
|-------|---------|
| `Timeout` elapsed | AWS KMS did not answer within the configured timeout. |
| KMS returned an error (`AmazonServiceException`) | AWS KMS GenerateMac failed (*error code*, HTTP *status*). |
| SDK client-side error (`AmazonClientException`): credentials, configuration or network | AWS KMS GenerateMac failed on the client side (credentials, configuration or network). |
| `HttpRequestException` | AWS KMS could not be reached. |
| `IOException` | The connection to AWS KMS failed. |
| The SDK's own `ClientConfig.Timeout` fired (`TimeoutException`) | AWS KMS did not answer within the SDK client timeout. |
| Any other SDK failure, for example a disposed client | AWS KMS GenerateMac failed. |
| No MAC in the response | AWS KMS returned no MAC. |
| The response names an algorithm other than `HMAC_SHA_256` | AWS KMS answered with a different MAC algorithm than requested. |
| The MAC is not 32 bytes | AWS KMS returned a MAC of unexpected length. |

Common KMS error codes in the first row are `AccessDeniedException` (IAM or key policy), `DisabledException`, `KMSInvalidStateException` (for example pending deletion), `NotFoundException` (wrong ARN or Region), `InvalidKeyUsageException` (not an HMAC key), `ThrottlingException` and `KMSInternalException`. An error code that is empty or contains characters outside `A-Z a-z 0-9 . _ -` is reported as `unknown error`; longer codes are cut to 64 characters.

Other exceptions from the pepper:

- `OperationCanceledException` when **your** cancellation token is cancelled. It is not converted, so cancelled requests do not look like outages. An already-cancelled token never reaches KMS.
- `ArgumentException` from `Apply`/`ApplyAsync` for an empty input or one over 4096 bytes (`AwsKmsPepper.MaxInputBytes`), the largest message `GenerateMac` accepts.
- `KeyNotFoundException` for an id that is not in `Keys`. The hasher checks `IsKnownKey` first, so you only see this when calling the pepper directly.
- `ArgumentNullException` for a null input.

:::warning

Keep `PasswordHasherOptions.MaxPasswordBytes` at 4096 or less. The default is 1024. With a larger limit, a long password reaches the pepper and throws `ArgumentException` instead of being refused as `PasswordTooLong`.

:::

**Map it to HTTP 503.** The `PasswordHasherBusyException` handler from `AddMasterlyHashExceptionHandler` does not cover this exception, so add one:

```csharp title="PepperUnavailableExceptionHandler.cs"
using System;
using System.Threading;
using System.Threading.Tasks;
using Masterly.Hash.Pepper.AwsKms;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Http;

namespace MyApp.Web;

/// <summary>Answers an unavailable KMS pepper with 503, so an outage never looks like a wrong password.</summary>
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

:::note

Each pepper package has its own `PepperUnavailableException` type in its own namespace. They share no base type besides `Exception`. Catch the one from the package you use.

:::

## Load, quotas and latency

Each call below is one `GenerateMac` request:

| Operation | KMS calls |
|-----------|-----------|
| `HashAsync` | 1 |
| `VerifyAsync` on a current hash, right or wrong password | 1 |
| `VerifyAsync` on an older key id, right password | 2 (verify, then the rehash). 1 if `ComputeRehashOnVerify` is `false`. |
| `VerifyAsync` on an unpeppered or legacy-format hash, right password | 1 (the rehash only) |
| `VerifyOrDummyAsync` with a null stored hash (unknown user) | 1, under the current key, so unknown users cost the same as real ones |
| Verify of a malformed hash, unknown profile or an id that is not in `Keys` | 0 |
| `Inspect`, `NeedsRehash`, `IsKnownKey` | 0 |
| `TryWrap` | 1, through the synchronous `Apply` |

KMS applies a per-account, per-Region request quota to HMAC operations. Check the current value in Service Quotas and size it for your peak login rate, including failed attempts and attacks: a credential-stuffing run costs as many KMS calls as real users. Throttled calls fail with `ThrottlingException`, which the pepper turns into `PepperUnavailableException` and the handler above answers with HTTP 503. Rate-limit the login endpoint; see [User Enumeration](./user-enumeration.md) and [Limits and Concurrency](./limits-and-concurrency.md). Wrapping a large table offline with `TryWrap` makes one sync call per row, so throttle that job too.

The KMS call happens before the hasher takes a slot under `MaxConcurrency`, so slow KMS calls do not hold hashing slots.

**Use the async API.** `ApplyAsync` is the real implementation and uses `ConfigureAwait(false)` throughout. `Apply`, used by `Hash`, `Verify`, `VerifyOrDummy` and `TryWrap`, runs `ApplyAsync` on the thread pool and blocks the calling thread until it finishes. The ASP.NET Core Identity adapter calls the sync API, because Identity's `IPasswordHasher<TUser>` is synchronous.

## Health check

A probe that computes one MAC checks credentials, the Region, permissions and the key state in one call:

```csharp title="KmsPepperHealthCheck.cs"
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Masterly.Hash.Pepper.AwsKms;
using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace MyApp.Web;

/// <summary>Checks that KMS computes the pepper MAC with the current key.</summary>
public sealed class KmsPepperHealthCheck : IHealthCheck
{
    private readonly AwsKmsPepper _pepper;

    /// <summary>Creates the check.</summary>
    public KmsPepperHealthCheck(AwsKmsPepper pepper)
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
            return HealthCheckResult.Unhealthy("KMS cannot compute the password pepper.", exception);
        }
    }
}
```

```csharp title="Program.cs"
builder.Services.AddHealthChecks().AddCheck<KmsPepperHealthCheck>("kms-pepper");
```

Every probe counts against the KMS quota, so keep the probe interval reasonable.

## Security notes

- **The key** stays inside KMS (FIPS 140-validated HSMs). A database leak or an application memory dump does not reveal it.
- **The input.** Every `GenerateMac` request sends the normalized password bytes (or, for a wrapped hash, the legacy digest) to KMS over TLS. CloudTrail records each `GenerateMac` call, with the caller and the key, but not the message. AWS still processes the password.
- **The IAM role.** A stolen role lets an attacker compute peppers online, through KMS, which is rate-limited and logged in CloudTrail. It does not reveal the key. Monitor `GenerateMac` volume for unexpected callers.
- **No secrets in errors.** Messages carry only the KMS error code and HTTP status. The SDK's MAC buffer is zeroed after copying. In .NET this is best effort; see the [Threat Model](./threat-model.md).
- **Strict responses.** A MAC of the wrong length, or one labelled with a different algorithm, is refused.

## API summary

| Member | Description |
|--------|-------------|
| `AwsKmsPepper(IAmazonKeyManagementService kms, AwsKmsPepperOptions options)` | Validates and copies the options. Makes no network call. |
| `string CurrentKeyId` | The configured current pepper key id. |
| `bool IsKnownKey(string keyId)` | `true` if the id is in `Keys`. No network call. |
| `ValueTask<byte[]> ApplyAsync(string keyId, byte[] input, CancellationToken cancellationToken = default)` | Calls `GenerateMac`. |
| `byte[] Apply(string keyId, byte[] input)` | Blocks on `ApplyAsync`. Prefer the async hasher API. |
| `const int MacLength` | 32. |
| `const int MaxInputBytes` | 4096. |

## See also

- [Peppers](./peppers.md): what a pepper protects against and how key ids and rotation work.
- [HashiCorp Vault](./hashicorp-vault.md) and [Azure Key Vault](./azure-key-vault.md): the other key-management providers.
- [Upgrade on Login](./upgrade-on-login.md): storing the rehash after a rotation.
- [Auditing Hash Tables](./auditing-hash-tables.md): finding hashes that still use an old key.
- [Observability](./observability.md): metrics to watch during a rotation.
- [Package README](https://github.com/a7mdfre7at/Masterly.Hash/blob/master/src/Masterly.Hash.Pepper.AwsKms/README.md)
