---
title: "Limits and Concurrency"
sidebar_label: "Limits and Concurrency"
description: "Cap password length and parallel hashing so a login flood cannot exhaust memory, and answer overload with 503."
---

Password hashing is expensive on purpose: one `2026a` hash takes about 125 ms of CPU and 64 MiB of memory. That cost protects stored hashes, but it also means a flood of login requests, or a few enormous passwords, can take a server down. Masterly.Hash has two guards against this: a cap on password length and a cap on how many hashes run at once. This page explains both, their defaults, and how to size them.

## Defaults

| Option | Default | Allowed values | What it limits |
|---|---|---|---|
| `MaxPasswordBytes` | 1024 | 64 to 1048576 | Longest password, in UTF-8 bytes after NFKC normalization |
| `MaxConcurrency` | `Environment.ProcessorCount` | 0 or more; 0 disables the limit | Hashes and verifications computed at the same time |
| `ConcurrencyTimeout` | 30 seconds | Positive, or `Timeout.InfiniteTimeSpan` | How long a call waits for a free slot |

All three are properties of `PasswordHasherOptions`. The hasher reads them once, in its constructor. Out-of-range values throw `ArgumentOutOfRangeException` from the constructor, or `OptionsValidationException` at startup when you use [dependency injection](./dependency-injection.md). The dependency injection validator also caps a finite `ConcurrencyTimeout` at `int.MaxValue` milliseconds (`24.20:31:23.647`), because larger values make the wait throw on .NET 8.

The same settings in configuration:

```json title="appsettings.json"
{
  "MasterlyHash": {
    "MaxPasswordBytes": 1024,
    "MaxConcurrency": 8,
    "ConcurrencyTimeout": "00:00:05"
  }
}
```

In configuration, an infinite timeout is written `-00:00:00.001`.

## The password length limit

Argon2 hashes its input once, so a long password costs little extra time. The risk is elsewhere: a multi-megabyte password has to be read, normalized and encoded before hashing, and normalization can expand it. `MaxPasswordBytes` bounds that work. The default of 1024 bytes is far longer than any real password or passphrase.

**How length is measured.** For new hashes and native verification, the password is normalized with NFKC (as NIST SP 800-63B recommends) and encoded as UTF-8; the limit applies to those bytes. One ASCII character is one byte. Most accented letters take two, most CJK characters three, and emoji four. NFKC can make a string longer: U+FDFA becomes 18 characters.

**What happens over the limit:**

| Call | Result |
|---|---|
| `Hash`, `HashAsync` | `ArgumentException` ("Password exceeds 1024 bytes.") |
| `Verify`, `VerifyAsync`, and `VerifyOrDummy` with a stored hash | `Failed` with `VerificationFailureReason.PasswordTooLong`. No KDF runs. |
| `VerifyOrDummy` with a `null` stored hash | `Failed` with `NoStoredHash`, as for any unknown user |

**Legacy and wrapped hashes count raw bytes.** Legacy formats and onion-wrapped hashes check the raw UTF-8 length of the password, without normalization, because the system that made them did not normalize. A password that fits raw but exceeds the limit after NFKC therefore still logs in against a legacy hash, but cannot be stored natively: the result is `SuccessRehashNeeded` with `Rehash == null`, and the legacy hash stays in place. See [Upgrade on login](./upgrade-on-login.md#when-rehash-is-null).

**Choosing a value.** Keep the default unless you have a reason to change it. Lower it (to no less than 64) if your password policy already rejects longer passwords. Raise it only if you are migrating hashes of longer passwords from another system. Never lower it below the longest password your users already have: those users would fail with `PasswordTooLong`.

### Rejecting long passwords at the edge

The hasher's check happens inside your login code, after the request has been read and bound. `Masterly.Hash.AspNetCore` checks earlier:

- **Minimal APIs.** `.WithPasswordLengthLimit()` adds `PasswordLengthEndpointFilter`, which answers `400 Bad Request` (problem details, title "Password too long") before the handler runs when a `SensitiveString` argument, or a public `SensitiveString` property of an argument one level deep, exceeds `MaxPasswordBytes`. It measures exactly as the hasher does, but rejects a value longer than 8 times the limit (in UTF-16 code units) from its length alone, before normalization can expand it. The response states the limit but never echoes the value.

  ```csharp title="Program.cs"
  // LoginService is the service from the Upgrade on login page
  app.MapPost("/login", async (LoginRequest request, LoginService logins, CancellationToken cancellationToken) =>
      await logins.SignInAsync(request.Email, request.Password.Reveal(), cancellationToken)
          ? Results.Ok()
          : Results.Unauthorized())
     .WithPasswordLengthLimit();

  public sealed record LoginRequest(string Email, SensitiveString Password);
  ```

- **ASP.NET Core Identity.** `AddMasterlyPasswordHasher()` registers `MasterlyPasswordLengthValidator<TUser>`. Identity's own validators have no maximum, so without it `UserManager.CreateAsync` and the password change and reset methods would throw from the hasher. With it they return a failed `IdentityResult` with the code `PasswordTooLong` (or `PasswordRequired` for an empty password). See [ASP.NET Core Identity](./aspnetcore-identity.md).

Also keep your web server's request body size limit in place. It bounds the request before any of this code runs.

### Other input rules

These are not limits but are checked at the same point:

| Input | `Hash` | `Verify` |
|---|---|---|
| `null` | `ArgumentNullException` | `ArgumentNullException` |
| Empty string | `ArgumentException` | `Failed`, `EmptyPassword` (never matches) |
| Unpaired UTF-16 surrogate, or U+FFFE | `ArgumentException` | `Failed`, `InvalidPassword` |
| A `$mh$` stored hash longer than 1024 characters | (not applicable) | `Failed`, `MalformedHash` |

Invalid UTF-16 is rejected rather than encoded lossily, because lossy encoding would make different passwords hash the same. See [Hashing and verifying](./hashing-and-verifying.md).

## The concurrency gate

Every Argon2 call allocates the profile's full memory cost for as long as it runs. A hundred simultaneous `2026a` logins would ask for 6.4 GiB at once. The gate prevents this: at most `MaxConcurrency` derivations run at the same time, and the rest wait.

**Peak memory is `MaxConcurrency` times the profile's memory:**

| `MaxConcurrency` | `2026a` (64 MiB) | `2026c` (19 MiB) |
|---:|---:|---:|
| 2 | 128 MiB | 38 MiB |
| 4 | 256 MiB | 76 MiB |
| 8 | 512 MiB | 152 MiB |
| 16 | 1 GiB | 304 MiB |

`2026f` (PBKDF2) uses less than 0.1 MiB per call, so for it the gate limits CPU rather than memory.

**What the gate covers.** A slot is held while the KDF runs: `Hash`, `HashAsync`, native verification, the dummy verification in `VerifyOrDummy`, the rehash after a successful verification, `TryWrap`, and legacy-format verification. Parsing, normalization and the pepper run outside the gate, so a slow remote pepper does not hold a slot.

**Why the default is the processor count.** The built-in profiles use one lane (`p=1`), so each derivation keeps one core busy. More concurrent derivations than cores would not finish sooner; they would only use more memory. In a container, .NET reports the container's CPU limit as `Environment.ProcessorCount`.

**Sizing it.** Start from the memory you can spare for hashing and divide by the profile's memory. On the reference machine (about 171 ms per `2026a` hash on one core), each slot handles roughly 5 to 6 logins per second, so 8 slots handle roughly 45. Measure on your own hardware with `masterly-hash bench` (see [Command-line tool](./command-line-tool.md)). If you need more throughput than your memory allows, use `2026c` (see [Profiles](./profiles.md)) or scale out.

Set it in code:

```csharp title="Program.cs"
builder.Services.AddMasterlyHash(options =>
{
    options.DefaultProfile = HashProfile.Constrained2026a;
    options.MaxConcurrency = 8;                          // at most 8 x 19 MiB in flight
    options.ConcurrencyTimeout = TimeSpan.FromSeconds(5);
});
```

:::note

The gate belongs to one `PasswordHasher` instance. Register the hasher as a singleton (`AddMasterlyHash` does), and do not create a new `PasswordHasher` per request: each instance has its own gate, so per-request instances have no limit at all. The static `Password` class uses the shared `PasswordHasher.Default`, which has the default options.

:::

### Waiting for a slot

A call that finds every slot busy waits, up to `ConcurrencyTimeout`, for one to become free.

- **Async calls** (`HashAsync`, `VerifyAsync`, `VerifyOrDummyAsync`) wait without blocking a thread. The `CancellationToken` is honoured while waiting: cancellation throws `OperationCanceledException`. Once the derivation has started it runs to completion; it cannot be cancelled.
- **Sync calls** (`Hash`, `Verify`, `VerifyOrDummy`) block the calling thread while they wait, and cannot be cancelled. On a busy web server, waiting threads can starve the thread pool. Prefer the async API on request paths.

The timeout counts only the wait for a slot, not the derivation itself.

### When the gate is full

If no slot becomes free within `ConcurrencyTimeout`, the call throws `PasswordHasherBusyException`. It derives from `TimeoutException`, and its message is "The password hasher is at its concurrency limit. Try again later."

Answer it with `503 Service Unavailable` so that clients back off instead of adding more load. `Masterly.Hash.AspNetCore` does this for you:

```csharp title="Program.cs"
builder.Services.AddMasterlyHash(builder.Configuration.GetSection("MasterlyHash"));
builder.Services.AddProblemDetails();
builder.Services.AddMasterlyHashExceptionHandler(options => options.RetryAfter = TimeSpan.FromSeconds(10));

WebApplication app = builder.Build();
app.UseExceptionHandler();
```

`PasswordHasherBusyExceptionHandler` responds with:

- status `503` and a problem details body (title "Service Unavailable", detail "The server is busy. Try again later.");
- a `Retry-After` header: `RetryAfter`, rounded up to whole seconds. The default is 5 seconds; values outside 1 second to 1 day throw `ArgumentOutOfRangeException`;
- `Cache-Control: no-store`.

It also recognizes the exception when it is wrapped, as an inner exception or inside an `AggregateException`. Exception handlers run in registration order, so register it before any catch-all handler. On .NET 8, `app.UseExceptionHandler()` needs `AddProblemDetails()` (or an error path) to start.

**Choosing the timeout.** The default of 30 seconds is longer than many clients wait for a response. On a login endpoint, a short timeout turns overload into fast `503` responses rather than a queue of requests that time out anyway. `AddMasterlyPasswordHasher()` for ASP.NET Core Identity lowers the timeout to 2 seconds (`MasterlyIdentityBuilderExtensions.IdentityConcurrencyTimeout`) if you have not changed it, because Identity calls the hasher synchronously and every waiting login blocks a thread.

### Disabling the limit

Set `MaxConcurrency = 0` to remove the gate. Do this only when something else already bounds concurrency, for example a queue worker that processes one job at a time, or a batch job that hashes with a fixed degree of parallelism. With the gate off, `ConcurrencyTimeout` has no effect and `PasswordHasherBusyException` is never thrown.

## Monitoring

The meter `Masterly.Hash` (`PasswordHasher.MeterName`) publishes two instruments that show saturation:

| Instrument | Type | Meaning |
|---|---|---|
| `masterly.hash.busy_rejections` | Counter, `{rejection}` | Calls rejected with `PasswordHasherBusyException`. Any non-zero rate means the gate is too small or the load too high. |
| `masterly.hash.duration` | Histogram, `ms`, tag `operation` (`hash` or `verify`), plus `profile` for hashes or `format` for verifications | Time spent per call, **including the wait for a slot**. A rising tail with a flat median means requests are queueing. |

`masterly.hash.verifications` counts `PasswordTooLong` failures under the `reason` tag. See [Observability](./observability.md).

## Security notes

- **The gate is not rate limiting.** It protects your memory, not your users. An attacker below the limit can still guess passwords at full speed. Add rate limiting and lockout in your web stack, and see [Attack detection](./attack-detection.md) for credential-stuffing detection.
- **Legacy hashes are cheap to verify.** A 1.x hash verifies in microseconds and still takes a slot only briefly. That speed is a timing signal; see [User enumeration](./user-enumeration.md).
- **Do not trade the limit for a weaker profile.** If logins are too slow under load, lower `MaxConcurrency` and return `503`, use `2026c`, or add capacity. A weaker profile makes every stored hash cheaper to crack.

## See also

- [Profiles](./profiles.md): memory and time per profile
- [Hashing and verifying](./hashing-and-verifying.md): input rules and failure reasons
- [ASP.NET Core Identity](./aspnetcore-identity.md): the length validator and the 2-second timeout
- [Observability](./observability.md): all metrics and their tags
- [Performance](./performance.md): how to benchmark on your hardware
