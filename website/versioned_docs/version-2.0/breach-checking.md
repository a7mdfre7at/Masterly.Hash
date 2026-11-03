---
title: Breach Checking
sidebar_label: "Breach Checking"
description: Reject passwords that already appear in data breaches, using Have I Been Pwned's k-anonymity range API.
---

NIST SP 800-63B rev. 4 asks verifiers to compare new passwords against values obtained from previous breaches. `Masterly.Hash.Policy` defines the contract, `IBreachedPasswordChecker`, and `Masterly.Hash.Pwned` implements it with Have I Been Pwned's Pwned Passwords range API. The password never leaves your process: only the first 5 hex characters of its SHA-1 hash are sent.

```bash
dotnet add package Masterly.Hash.Pwned
```

The package targets `net8.0`, depends on `Masterly.Hash`, `Masterly.Hash.Policy`, `Microsoft.Extensions.DependencyInjection.Abstractions` and `Microsoft.Extensions.Http`, and is AOT-compatible.

## Quick start

**1. Register the client.** Name your application in the User-Agent; the API rejects requests without one.

```csharp title="Program.cs"
using Masterly.Hash.Policy;
using Masterly.Hash.Pwned;

builder.Services.AddPwnedPasswords(options =>
{
    options.UserAgent = "Contoso-SignUp/1.4";
    options.EnableCache = true;
});

builder.Services.AddSingleton<IPasswordPolicy>(serviceProvider => new PasswordPolicy(
    new PasswordPolicyOptions(),
    serviceProvider.GetRequiredService<IBreachedPasswordChecker>()));
```

**2. Evaluate with `EvaluateAsync`.** The synchronous `Evaluate` never calls the checker.

```csharp title="SignUpHandler.cs"
PasswordPolicyResult result = await _policy.EvaluateAsync(password, context, cancellationToken);

if (!result.IsAcceptable)
{
    return result.Violations;           // includes Breached when the password was found
}

if (result.BreachCheckUnavailable)
{
    _logger.LogWarning("Breach corpus unavailable; password accepted on local checks only");
}
```

**3. Decide what an outage means for you.** By default an outage does not block the user: the password is judged on the local rules and `BreachCheckUnavailable` is true. To require the check, see [Failing closed](#failing-closed).

## How the k-anonymity lookup works

1. **Hash locally.** The client computes SHA-1 over the password's UTF-8 bytes, exactly as given, with no normalization. This matches how the corpus was built. SHA-1 is used only because the API requires it; passwords are stored with Argon2id.
2. **Send a prefix.** It sends `GET {BaseAddress}range/{prefix}`, where `prefix` is the first 5 hex digits in upper case. For `password` (SHA-1 `5BAA61E4...`) the request is `https://api.pwnedpasswords.com/range/5BAA6`. The headers are your `User-Agent` and `Add-Padding: true`, so the response size does not hint at the prefix.
3. **Receive the range.** The service answers with every hash suffix that shares the prefix, one `SUFFIX:COUNT` line each, plus padding lines with a count of 0.
4. **Match locally.** The remaining 35 hex digits stay in memory as packed bytes, never as a string. The client compares them with every entry of the range using a fixed-time comparison and never stops early, so timing does not reveal where the hash sits. Hex is matched case-insensitively; duplicates resolve to the largest count.
5. **Clean up.** The UTF-8 bytes, the hash and the suffix buffers are zeroed after use.

Neither the password, its full hash nor the suffix leaves the process, is logged or appears in an exception message.

## What AddPwnedPasswords registers

`AddPwnedPasswords(this IServiceCollection services, Action<PwnedPasswordsOptions>? configure = null)` lives in the `Microsoft.Extensions.DependencyInjection` namespace and returns the `IHttpClientBuilder` of the client, so you can add handlers.

| Service | Lifetime | Notes |
|---|---|---|
| `IBreachedPasswordChecker` | Singleton | Only if none is registered yet. Safe to capture in singletons such as `PasswordPolicy`: it takes a fresh `HttpClient` from `IHttpClientFactory` for every lookup, so handler rotation and DNS changes still apply. |
| `PwnedPasswordsClient` | Transient typed client | On the named client `PwnedPasswordsClient` (`PwnedPasswordsServiceCollectionExtensions.HttpClientName`). Inject it into scoped or transient services; do not capture it in a singleton, which pins one handler and misses DNS changes. |
| Range cache | Singleton | Shared by both when `EnableCache` is set; built from the options as they are on first use. |
| `PwnedPasswordsOptions` | `IOptions<T>` | `configure` adds a configure step. Any other `Configure<PwnedPasswordsOptions>` call applies too. |

The factory's default request loggers are removed from this client (`RemoveAllLoggers`), because they log the request URI and the prefix in it is derived from the password.

Invalid options throw `ArgumentException` when the checker or the client is first resolved, not when you call `AddPwnedPasswords`. Resolve `IBreachedPasswordChecker` once in a startup test to catch configuration mistakes early.

If you registered your own `IBreachedPasswordChecker` before calling `AddPwnedPasswords`, yours is kept; `PwnedPasswordsClient` is still registered.

## Using the client without dependency injection

```csharp title="BreachCheck.cs"
using Masterly.Hash.Policy;
using Masterly.Hash.Pwned;

PwnedPasswordsOptions options = new PwnedPasswordsOptions { UserAgent = "Contoso-SignUp/1.4" };
PwnedPasswordsClient pwned = new PwnedPasswordsClient(httpClient, options);

BreachCheckResult result = await pwned.CheckAsync(password, cancellationToken);

if (result.IsBreached)
{
    Console.WriteLine($"This password has appeared in {result.Occurrences:N0} data breaches. Choose another.");
}
else if (result.Status == BreachCheckStatus.Unavailable)
{
    Console.WriteLine("Have I Been Pwned is unavailable; the password was checked locally only.");
}
```

- `PwnedPasswordsClient(HttpClient httpClient, PwnedPasswordsOptions? options = null)` uses the defaults when `options` is `null`. The options are copied, so later changes have no effect. It throws `ArgumentNullException` for a `null` client and `ArgumentException` for invalid options.
- The client is thread-safe; reuse one instance. It does not dispose the `HttpClient`.
- `CheckAsync(string password, CancellationToken cancellationToken = default)` and `CheckAsync(SensitiveString password, CancellationToken cancellationToken = default)` throw `ArgumentNullException` for `null` and `ArgumentException` for an empty password, synchronously and before any request.
- `ClearCache()` removes every cached range. It does nothing when the cache is off.

## Options

| Option | Default | Allowed values | Notes |
|---|---|---|---|
| `BaseAddress` | `https://api.pwnedpasswords.com/` (`PwnedPasswordsOptions.DefaultBaseAddress`) | Absolute `https` URI without user info, query or fragment | Requests go to `{BaseAddress}range/{prefix}`. A path is kept and a trailing slash added, so `https://mirror.example/pwned` sends `https://mirror.example/pwned/range/5BAA6`. |
| `AllowInsecureHttp` | `false` | | Permits an `http` base address, for example a local mirror. Without TLS a network attacker can rewrite answers so breached passwords look clean. |
| `Timeout` | 3 seconds | More than zero, at most 5 minutes (`MaxTimeout`) | Covers the whole lookup: connecting, headers and reading the body. |
| `UserAgent` | `Masterly.Hash.Pwned/2.0 (+https://github.com/a7mdfre7at/Masterly.Hash)` (`DefaultUserAgent`) | Non-blank, at most 512 printable ASCII characters, a valid `User-Agent` value | Sent trimmed. Name your application, for example `Contoso-SignUp/1.4`. |
| `FailureMode` | `FailOpen` | `FailOpen` or `Throw` | What happens when the service cannot answer. See below. |
| `MinimumOccurrences` | 1 | At least 1 | A password counts as breached only if it appears at least this many times. |
| `EnableCache` | `false` | | Keep parsed ranges in memory, keyed by prefix. |
| `CacheDuration` | 1 hour | More than zero, at most 7 days (`MaxCacheDuration`) | Checked only when the cache is on. |
| `CacheMaxEntries` | 256 | 1 to 100,000 (`MaxCacheEntriesLimit`) | Checked only when the cache is on. |

Validation errors are `ArgumentException`s with these messages: `BaseAddress must be an absolute URI.`, `BaseAddress must use https; set AllowInsecureHttp to permit http.`, `BaseAddress must use https.`, `BaseAddress must not contain user info, a query or a fragment.`, `Timeout must be greater than zero and at most 5 minutes.`, `UserAgent must be a non-empty, valid User-Agent header value.`, `FailureMode is not a defined value.`, `MinimumOccurrences must be at least 1.`, `CacheDuration must be greater than zero and at most 7 days.` and `CacheMaxEntries must be between 1 and 100000.`

## Failure and timeout behaviour

The client treats every answer it cannot trust as **unavailable**. It never turns a failure into "not breached", because that would let breached passwords through.

| Condition | `FailOpen` returns | `Throw` throws `PwnedPasswordsUnavailableException` with |
|---|---|---|
| No answer within `Timeout`, or `HttpClient.Timeout` or a resilience handler gave up | `BreachCheckResult.Unavailable` | `The Pwned Passwords service did not answer within the configured timeout.` |
| Non-success status, including 429 and 503 | `Unavailable` | `The Pwned Passwords service answered with HTTP {status}.` |
| Network error (`HttpRequestException`) | `Unavailable` | `The Pwned Passwords service could not be reached.` (inner exception attached) |
| Connection failure while reading (`IOException`) | `Unavailable` | `The connection to the Pwned Passwords service failed.` (inner exception attached) |
| Declared `Content-Length` or streamed body over 1 MiB (`PwnedPasswordsClient.MaxResponseBytes`, 1,048,576 bytes) | `Unavailable` | `The Pwned Passwords response exceeded 1048576 bytes.` |
| Malformed line, or a range with no real entries (empty body, 204, padding only) | `Unavailable` | `The Pwned Passwords service returned a malformed range.` |
| Any other exception from the `HttpClient` pipeline (custom handler, circuit breaker, disposed client) | `Unavailable` | `The Pwned Passwords request failed.` (inner exception attached) |
| Your `cancellationToken` is cancelled | throws `OperationCanceledException` | throws `OperationCanceledException` |

Exception messages never contain the password, its hash or the prefix. Unavailable answers are never cached.

A range is parsed strictly. Lines are separated by LF or CRLF; each is a 35-digit hex suffix in either case, a colon and a decimal count of at most 18 digits. Blank lines and surrounding spaces or tabs are tolerated, and entries with a count of 0 are dropped as padding. Any other line rejects the whole response. A real padded range is about 40 KiB and always holds hundreds of entries, so an empty one can only come from a proxy, a fallback handler or a broken mirror.

If a response stream ignores cancellation, as a custom handler's stream may, the client disposes it when the timeout fires to end a stalled read. A read torn down this way is reported as a timeout, never parsed as a truncated range.

## How PasswordPolicy uses the checker

`PasswordPolicy.EvaluateAsync` calls `IBreachedPasswordChecker.CheckAsync` after the local rules, with these rules:

- `Evaluate` (synchronous) never calls it; `BreachCheck` is `null`.
- A password already rejected as too short or too long is not sent; `BreachCheck` is `null`.
- The checker receives the NFKC-normalized password. For ASCII passwords this is the same as what the user typed.
- A `Breached` violation is added when the result is breached with at least `PasswordPolicyOptions.MinimumBreachOccurrences` occurrences. It is reported last, after the other violations.
- An `Unavailable` result, a `null` result, or any exception other than the caller's cancellation becomes `BreachCheckResult.Unavailable`. It is not a violation, and the exception is not surfaced, because it may have been built from a request that contains the password.
- The caller's cancellation propagates as `OperationCanceledException`.

`PasswordPolicyResult.BreachCheck` holds the outcome, and `BreachCheckUnavailable` is true when a lookup was attempted but failed.

:::note

There are two occurrence thresholds. `PwnedPasswordsOptions.MinimumOccurrences` makes the client return `NotBreached` below it. `PasswordPolicyOptions.MinimumBreachOccurrences` makes the policy skip the violation below it, while `BreachCheck` still shows the count. Set only one of them.

:::

### Failing closed

`FailureMode = Throw` does not make `PasswordPolicy` fail closed: the policy turns the exception back into `Unavailable`, as the `IBreachedPasswordChecker` contract asks. `Throw` is for code that calls `PwnedPasswordsClient` directly. To make the check mandatory through the policy, reject when `BreachCheckUnavailable` is true:

```csharp title="Program.cs"
using Masterly.Hash;
using Masterly.Hash.Policy;

app.MapPost("/api/v1/accounts", async (
    SignUpRequest request,
    IPasswordPolicy policy,
    CancellationToken cancellationToken) =>
{
    PasswordContext context = new PasswordContext { UserName = request.UserName, Email = request.Email };
    PasswordPolicyResult result = await policy.EvaluateAsync(request.Password, context, cancellationToken);

    if (!result.IsAcceptable)
    {
        Dictionary<string, string[]> errors = new Dictionary<string, string[]>
        {
            ["password"] = result.Violations.Select(violation => violation.Message).ToArray(),
        };
        return Results.ValidationProblem(errors);
    }

    if (result.BreachCheckUnavailable)
    {
        return Results.Problem(
            title: "Password check unavailable",
            detail: "Please try again shortly.",
            statusCode: StatusCodes.Status503ServiceUnavailable);
    }

    // hash and save the account
    return Results.Created($"/api/v1/accounts/{request.UserName}", null);
});

public sealed record SignUpRequest(string UserName, string Email, SensitiveString Password);
```

Fail-open is the default because a third-party outage should not usually block sign-ups. Choose fail-closed when accepting a breached password is worse than a short outage of sign-up.

## Configuring the HttpClient

`AddPwnedPasswords` returns the `IHttpClientBuilder`, so the usual `IHttpClientFactory` configuration applies to the lookup.

```csharp title="Program.cs"
using System.Net;

builder.Services
    .AddPwnedPasswords(options => options.UserAgent = "Contoso-SignUp/1.4")
    .ConfigurePrimaryHttpMessageHandler(() => new SocketsHttpHandler
    {
        Proxy = new WebProxy("http://proxy.contoso.local:8080"),
        UseProxy = true,
    });
```

- **Timeouts.** `PwnedPasswordsOptions.Timeout` (3 seconds) bounds the whole lookup, including everything the handler pipeline does. A resilience pipeline, such as `AddStandardResilienceHandler()` from `Microsoft.Extensions.Http.Resilience`, runs inside that budget: retries that do not fit are cut off and the lookup counts as unavailable. Raise `Timeout` if you add retries. `HttpClient.Timeout` (100 seconds by default) only matters if you set it below `Timeout`.
- **Circuit breakers.** An open circuit throws from the pipeline; the client reports it as unavailable or wraps it, according to `FailureMode`.
- **Loggers.** Do not add the factory's loggers back with `AddLogger`, and keep custom handlers, proxies and tracing instrumentation from recording the request URI path. See [Security notes](#security-notes).
- **Mirrors.** Point `BaseAddress` at a self-hosted mirror of the range API. Keep it on `https`; `AllowInsecureHttp` exists for local development.

Because the options come from `IOptions<PwnedPasswordsOptions>`, you can also bind them from configuration:

```csharp title="Program.cs"
using Masterly.Hash.Pwned;

builder.Services.Configure<PwnedPasswordsOptions>(builder.Configuration.GetSection("PwnedPasswords"));
builder.Services.AddPwnedPasswords();
```

The options are read once, when the checker or client is first built; later configuration reloads are not seen.

## The range cache

With `EnableCache = true` the client keeps parsed ranges in memory, keyed by the 5-character prefix, so lookups that share a prefix skip the network.

- It is a least-recently-used cache of at most `CacheMaxEntries` ranges, each valid for `CacheDuration`.
- Lifetimes use a monotonic clock, so changes to the wall clock do not extend or cut them.
- A range takes roughly 25 KiB, so the default of 256 entries is about 6 MiB. The maximum of 100,000 entries would be about 2.4 GiB; size the cache to your memory.
- With `AddPwnedPasswords` one cache is shared by the checker and every client instance. Each `new PwnedPasswordsClient(...)` has its own cache.
- Failures are never cached.

The cached ranges are public data, but the cache keys are the prefixes of recently checked passwords, 20 bits of each hash. Leave the cache off if that is a concern for memory dumps.

## Checking at sign-in

NIST asks verifiers to force a password change on evidence of compromise. After a successful sign-in you can look the password up and flag the account:

```csharp title="SignInHandler.cs"
using System.Threading;
using System.Threading.Tasks;
using Masterly.Hash;
using Masterly.Hash.Policy;

namespace Contoso.Accounts;

public sealed class SignInHandler
{
    private readonly IPasswordHasher _hasher;
    private readonly IBreachedPasswordChecker _breachChecker;

    public SignInHandler(IPasswordHasher hasher, IBreachedPasswordChecker breachChecker)
    {
        _hasher = hasher;
        _breachChecker = breachChecker;
    }

    public async Task<bool> MustChangePasswordAsync(string password, string storedHash, CancellationToken cancellationToken)
    {
        PasswordVerificationResult verification = await _hasher.VerifyAsync(password, storedHash, cancellationToken);
        if (!verification.IsMatch)
        {
            return false;
        }

        BreachCheckResult breach = await _breachChecker.CheckAsync(password, cancellationToken);
        return breach.IsBreached;
    }
}
```

- Look up only after the password verified. Otherwise every failed guess becomes a request to a third party.
- The lookup adds a network round trip to sign-in. Turn the cache on, and treat `Unavailable` as "unknown", not as a reason to refuse the sign-in.
- Do not block the sign-in itself. Let the user in and require a new password, as NIST describes.

## Writing your own checker

Implement `IBreachedPasswordChecker` to use another corpus, such as an offline copy of the Pwned Passwords list or passwords from your own incident history.

```csharp title="LocalBreachCorpus.cs"
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Masterly.Hash.Policy;

namespace Contoso.Security;

public sealed class LocalBreachCorpus : IBreachedPasswordChecker
{
    private readonly IReadOnlyDictionary<string, long> _countsBySha1;

    public LocalBreachCorpus(IReadOnlyDictionary<string, long> countsBySha1)
    {
        ArgumentNullException.ThrowIfNull(countsBySha1);
        _countsBySha1 = countsBySha1;
    }

    public ValueTask<BreachCheckResult> CheckAsync(string password, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(password);
        cancellationToken.ThrowIfCancellationRequested();

        string sha1 = Convert.ToHexString(SHA1.HashData(Encoding.UTF8.GetBytes(password)));
        BreachCheckResult result = _countsBySha1.TryGetValue(sha1, out long count) && count > 0
            ? BreachCheckResult.Breached(count)
            : BreachCheckResult.NotBreached;
        return ValueTask.FromResult(result);
    }
}
```

The contract:

| Rule | Why |
|---|---|
| `CheckAsync(string password, CancellationToken cancellationToken)` receives the NFKC-normalized candidate. | `PasswordPolicy` normalizes before it calls you. |
| Return `BreachCheckResult.Unavailable` when the corpus cannot be reached, rather than throwing. | `PasswordPolicy` treats exceptions other than cancellation the same way, but a result is clearer. |
| Never send the password itself to a remote service. Use a k-anonymity scheme such as a short hash prefix. | The corpus service must not learn the password. |
| Throw `OperationCanceledException` only for the caller's token. | Anything else is treated as unavailable. |

`BreachCheckResult` has three ways to be created: `BreachCheckResult.NotBreached`, `BreachCheckResult.Unavailable` and `BreachCheckResult.Breached(long occurrences)`, which throws `ArgumentOutOfRangeException` below 1. Its members are `Status` (`BreachCheckStatus.Ok` or `Unavailable`), `IsBreached` (always false when unavailable), `Occurrences` (0 when not breached or unknown) and `ToString()`, which returns `Not breached`, `Unavailable` or `Breached (42 occurrences)`.

## Testing

In unit tests, give the policy a fake checker instead of the network:

```csharp title="SignUpTests.cs"
using System.Threading;
using System.Threading.Tasks;
using Masterly.Hash.Policy;
using Xunit;

namespace Contoso.Accounts.Tests;

public sealed class SignUpTests
{
    [Fact]
    public async Task SignUp_WhenPasswordIsBreached_ReturnsBreachedViolation()
    {
        PasswordPolicy policy = new PasswordPolicy(new PasswordPolicyOptions(), new FixedBreachChecker(BreachCheckResult.Breached(3)));

        PasswordPolicyResult result = await policy.EvaluateAsync("violet-quartz-tundra-mosaic");

        Assert.True(result.HasViolation(PasswordViolationCode.Breached));
    }

    private sealed class FixedBreachChecker : IBreachedPasswordChecker
    {
        private readonly BreachCheckResult _result;

        public FixedBreachChecker(BreachCheckResult result)
        {
            _result = result;
        }

        public ValueTask<BreachCheckResult> CheckAsync(string password, CancellationToken cancellationToken) =>
            ValueTask.FromResult(_result);
    }
}
```

To test the real client offline, register it with `AddPwnedPasswords()` and replace the network with `.ConfigurePrimaryHttpMessageHandler(...)` and a handler that returns a canned range. See [Testing](./testing.md).

## Security notes

- **What leaves the process:** one `GET` to `/range/XXXXX` with `Add-Padding: true` and your User-Agent. Nothing else.
- **The prefix is sensitive.** The 5 characters are 20 bits of the password's SHA-1. Together with a stolen password hash they let an attacker discard about 999,999 of every million guesses with cheap SHA-1 before running Argon2id. That is why the default request loggers are removed. Keep the URI path out of logs, proxies and traces.
- **Integrity.** A malformed line or an empty range rejects the whole response, so a corrupted or substituted answer cannot make a breached password look clean. `http` is refused by default for the same reason.
- **Availability.** Fail-open is the default. `PasswordPolicy` never fails because of the checker, even with `FailureMode = Throw`; check `BreachCheckUnavailable` to fail closed.
- **Normalization.** The client hashes exactly what it is given. `PasswordPolicy` passes the NFKC form, which differs from what the user typed only for some non-ASCII passwords; such a password may be missed if the corpus holds its other form.
- **Terms.** The Pwned Passwords range API is free and needs no API key. Read its [acceptable use](https://haveibeenpwned.com/API/v3#AcceptableUse) and attribution terms.
- **Telemetry.** The packages write no logs or metrics of their own. Count `BreachCheckUnavailable` results yourself if you want to alert on outages.

## From the command line

`masterly-hash policy --pwned` adds the Have I Been Pwned lookup to the policy check. The command is online only with `--pwned`, and prints a notice to standard error before it queries. It exits with 0 for acceptable and 1 for rejected. When the password passes every other check but the lookup was unavailable, it exits with 2 so that a script never mistakes an unchecked password for a clean one; `--allow-unavailable` accepts the result without the lookup instead. See [Command-line tool](./command-line-tool.md).

## See also

- [Password policy](./password-policy.md): the rules the breach lookup is part of.
- [Strength estimation](./strength-estimation.md): the score that catches guessable passwords the corpus does not hold.
- [Dependency injection](./dependency-injection.md): registering Masterly.Hash services.
- [Threat model](./threat-model.md): what Masterly.Hash defends against.
- [PwnedPasswordsClient source](https://github.com/a7mdfre7at/Masterly.Hash/blob/master/src/Masterly.Hash.Pwned/PwnedPasswordsClient.cs) and [package README](https://github.com/a7mdfre7at/Masterly.Hash/blob/master/src/Masterly.Hash.Pwned/README.md).
