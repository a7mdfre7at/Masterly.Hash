# Masterly.Hash.Pwned

A [Have I Been Pwned](https://haveibeenpwned.com/Passwords) **Pwned Passwords** client for
[Masterly.Hash](https://github.com/a7mdfre7at/Masterly.Hash). It implements `IBreachedPasswordChecker` from
`Masterly.Hash.Policy`, so `PasswordPolicy` can reject passwords that already appear in breaches
(NIST SP 800-63B rev. 4, section 3.1.1.2).

It uses the k-anonymity range API. The password is hashed locally with SHA-1 and **only the first 5 hex characters**
of that hash are sent. The match is done locally against the returned range.

## Install

```
dotnet add package Masterly.Hash.Pwned
```

## Quickstart (dependency injection)

```csharp
using Masterly.Hash.Policy;
using Masterly.Hash.Pwned;

builder.Services.AddPwnedPasswords(o =>
{
    o.UserAgent = "Contoso-SignUp/1.4";   // the API requires a User-Agent; name your application
    o.EnableCache = true;                 // optional, bounded in-memory range cache
    // o.Timeout = TimeSpan.FromSeconds(3);
    // o.FailureMode = PwnedPasswordsFailureMode.FailOpen;   // or Throw
    // o.MinimumOccurrences = 1;
});
// AddPwnedPasswords returns the IHttpClientBuilder, so you can add handlers, e.g. .AddStandardResilienceHandler().

builder.Services.AddSingleton<IPasswordPolicy>(sp =>
    new PasswordPolicy(new PasswordPolicyOptions(), sp.GetRequiredService<IBreachedPasswordChecker>()));

// At sign-up / password change:
PasswordPolicyResult result = await policy.EvaluateAsync(password, context, cancellationToken);
if (!result.IsAcceptable)
    return BadRequest(result.Violations);
if (result.BreachCheckUnavailable && breachCheckIsMandatory)
    return StatusCode(503, "Please try again shortly.");   // fail closed; otherwise the password was checked locally only
```

`AddPwnedPasswords` registers:

- a singleton `IBreachedPasswordChecker` (unless one is already registered). It takes a fresh `HttpClient` from
  `IHttpClientFactory` for every lookup, so it is safe to capture in singletons such as `PasswordPolicy`;
- `PwnedPasswordsClient` as a transient typed client on the named client `PwnedPasswordsClient`. Inject it into
  scoped or transient services; do not capture it in a singleton (that pins one handler and misses DNS changes).

The range cache is a singleton shared by both. The `IHttpClientFactory` default request loggers are removed from
this client (see Security notes).

## Quickstart (without DI)

```csharp
var pwned = new PwnedPasswordsClient(httpClient, new PwnedPasswordsOptions { UserAgent = "Contoso-SignUp/1.4" });

BreachCheckResult r = await pwned.CheckAsync(password, cancellationToken);   // or a SensitiveString
if (r.IsBreached)
    return BadRequest($"This password has appeared in {r.Occurrences:N0} data breaches. Choose another.");
if (r.Status == BreachCheckStatus.Unavailable)
    logger.LogWarning("Pwned Passwords unavailable; password checked locally only.");
```

Reuse one `PwnedPasswordsClient` (it is thread-safe). It does not dispose the `HttpClient`.

## Options

| Option | Default | Notes |
|---|---|---|
| `BaseAddress` | `https://api.pwnedpasswords.com/` | Requests go to `{BaseAddress}range/{prefix}`. Must be https unless `AllowInsecureHttp` is set. |
| `Timeout` | 3 s | Covers the whole lookup, including reading the body. Maximum 5 minutes. |
| `UserAgent` | `Masterly.Hash.Pwned/2.0 (+repo url)` | Required by the API. |
| `FailureMode` | `FailOpen` | `FailOpen` returns `BreachCheckResult.Unavailable`. `Throw` throws `PwnedPasswordsUnavailableException`, but only for direct callers: `PasswordPolicy` turns it back into `Unavailable`. |
| `MinimumOccurrences` | 1 | Passwords seen fewer times count as not breached. |
| `EnableCache` / `CacheDuration` / `CacheMaxEntries` | off / 1 h / 256 | LRU cache keyed by prefix. About 25 KiB per range. |

The client counts these as **unavailable**: timeouts, network errors, non-2xx answers (including 429), bodies over 1 MiB,
malformed bodies, empty answers (no body, 204, or padding only: a real range always has entries), and failures in the
`HttpClient` pipeline. Unavailable answers are never cached. Caller cancellation always throws
`OperationCanceledException`.

## Security notes

- **What leaves the process**: a GET to `/range/XXXXX` with `Add-Padding: true` and your User-Agent. Nothing else.
  The password, its full SHA-1 hash and the 35-character suffix never leave the process. None of them is logged
  or put in an exception message. Padding means the response size does not narrow down the prefix. Padding entries
  (count 0) are discarded.
- **Hashing**: SHA-1 of the password's UTF-8 bytes, exactly as given. This matches how the corpus was built.
  `PasswordPolicy` passes the NFKC-normalized password. For ASCII passwords the two forms are the same.
  SHA-1 is used here only because the API requires it. Password storage uses Argon2id in `Masterly.Hash`.
- **Local matching** is case-insensitive on the hex suffix. It compares every entry with a fixed-time comparison,
  so timing does not reveal where the hash falls in the range. Hash buffers are zeroed after use.
- **The prefix is sensitive**: the 5 characters in `/range/XXXXX` are 20 bits of the password's SHA-1. Together
  with a stored hash they let an attacker discard about 999,999 of every million guesses with cheap SHA-1 before
  running Argon2id. `AddPwnedPasswords` therefore removes `IHttpClientFactory`'s default loggers (which log the
  request URI at Information level). Do not add them back with `AddLogger`, and keep custom handlers, proxies and
  tracing from recording the URI path.
- **Integrity**: a malformed line or an empty range rejects the whole response (unavailable), so a corrupted or
  substituted answer cannot make a breached password look clean. http is refused by default because a network
  attacker could rewrite the answer.
- **Availability**: fail-open is the default, so a third-party outage does not block sign-ups.
  `PasswordPolicyResult.BreachCheckUnavailable` reports it. `PasswordPolicy` never fails because of the checker, even
  with `FailureMode = Throw`; to make the check mandatory, reject when `BreachCheckUnavailable` is true (see the
  quickstart). `Throw` is for code that calls `PwnedPasswordsClient` directly.
- **Timeouts** cover connecting, headers and the body. If a response stream ignores cancellation (as a custom
  handler's stream may), the client disposes it to end a stalled read.
- **Cache**: cached ranges are public data. The cache keys are prefixes of recently checked passwords
  (20 bits of each hash). Leave the cache off if that is a concern in memory dumps.
- **Privacy**: the Pwned Passwords range API is free and needs no API key. Read its
  [acceptable use](https://haveibeenpwned.com/API/v3#AcceptableUse) and attribution terms.
