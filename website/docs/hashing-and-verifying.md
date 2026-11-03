---
title: "Hashing and Verifying"
sidebar_label: "Hashing and Verifying"
description: "Every overload of Hash and Verify, what the result tells you, which inputs are rejected and which exceptions can escape."
---

This page is the complete guide to the two core operations: turning a password into a stored hash, and checking a password against one. It covers the static `Password` class and the `IPasswordHasher` interface, every overload, the verification result, input rules, exceptions, the async API, `Inspect`, and `SensitiveString`.

All types on this page are in the `Masterly.Hash` package. Unless noted otherwise they live in the `Masterly.Hash` namespace; `IPasswordPepper` and `HmacPepper` are in `Masterly.Hash.Pepper`, `ILegacyHashFormat` and `V1LegacyFormat` in `Masterly.Hash.Legacy`, and `HashPrimitives` in `Masterly.Hash.Primitives`.

## Choose an entry point

| Entry point | Use it when | Configuration |
|-------------|-------------|---------------|
| `Password` (static) | Scripts, console tools, small apps, and anywhere the defaults are what you want. | None. It always uses `PasswordHasher.Default`: profile `2026a`, no pepper, the 1.x format accepted, default limits. |
| `IPasswordHasher`, implemented by `PasswordHasher` | Applications. Inject it, so you can configure a pepper, a profile or legacy formats, and replace it in tests. | `PasswordHasherOptions`, passed to the constructor or set through [Dependency Injection](./dependency-injection.md). |

Both expose the same operations. `PasswordHasher` is thread-safe and holds the concurrency gate for the whole process, so create one instance and reuse it. Creating a hasher per request defeats the concurrency limit.

```csharp title="Creating a hasher by hand"
using Masterly.Hash;

PasswordHasher hasher = new PasswordHasher(new PasswordHasherOptions
{
    DefaultProfile = HashProfile.Constrained2026a,
    MaxConcurrency = 8,
});
```

The constructor copies the options. Changing the `PasswordHasherOptions` object afterwards has no effect on the hasher.

| Option | Default | Details |
|--------|---------|---------|
| `DefaultProfile` | `HashProfile.Server2026a` (`2026a`) | Profile for new hashes. Must not be `null`. See [Profiles](./profiles.md). |
| `AdditionalProfiles` | Empty | Extra custom profiles to accept when verifying. The built-in profiles are always accepted. A get-only `IList<HashProfile>`: call `Add`, do not assign. |
| `Pepper` | `null` | An `IPasswordPepper`. See [Peppers](./peppers.md). |
| `LegacyFormats` | `V1LegacyFormat.Instance` | Read-only formats to verify and upgrade. A get-only `IList<ILegacyHashFormat>`: call `Add`, or `Clear` it to drop 1.x support. See [Legacy Formats](./legacy-formats.md). |
| `MaxPasswordBytes` | `1024` | Longest accepted password, in UTF-8 bytes after NFKC. Allowed range 64 to 1,048,576. |
| `MaxConcurrency` | `Environment.ProcessorCount` | KDF runs allowed at once. `0` disables the limit. See [Limits and Concurrency](./limits-and-concurrency.md). |
| `ConcurrencyTimeout` | 30 seconds | How long a call waits for a slot. Must be positive or `Timeout.InfiniteTimeSpan`. |
| `ComputeRehashOnVerify` | `true` | Whether a successful verify of an outdated hash also returns the replacement. |
| `AllowWeakProfiles` | `false` | Allows profiles below the OWASP minimums. Only for tests. |

The constructor validates everything and throws on the first problem: `ArgumentNullException` for `null` options; `ArgumentException` for a `null` default, additional profile or legacy format, a profile below the OWASP minimum without `AllowWeakProfiles`, a profile id registered twice with different parameters, an invalid or duplicate legacy format id, or a pepper whose `CurrentKeyId` does not match `^[A-Za-z0-9-]{1,32}$`; and `ArgumentOutOfRangeException` for `MaxPasswordBytes`, a negative `MaxConcurrency` or an invalid `ConcurrencyTimeout`. A misconfigured hasher therefore fails at startup, not on the first login.

A constructed hasher exposes `DefaultProfile`, `MaxPasswordBytes` and `Profiles` (every profile it accepts). `PasswordHasher.Default` is the shared default-options instance behind `Password`.

## Hashing

| Method | Notes |
|--------|-------|
| `string Hash(string password)` | Hashes with the default profile and the pepper's current key. |
| `string Hash(string password, HashProfile profile)` | Hashes with a specific registered profile. |
| `ValueTask<string> HashAsync(string password, CancellationToken cancellationToken = default)` | Async version of `Hash(string)`. Waits for a slot asynchronously and calls the pepper's `ApplyAsync`. |
| `Hash(SensitiveString)`, `HashAsync(SensitiveString, CancellationToken)` | Extension methods on `IPasswordHasher` (`PasswordHasherExtensions`). |
| `Password.Hash(string)`, `Password.Hash(string, HashProfile)`, `Password.Hash(SensitiveString)`, `Password.HashAsync(string, CancellationToken)` | The static equivalents, on `PasswordHasher.Default`. |

```csharp title="RegistrationService.cs"
using Masterly.Hash;

namespace MyApp.Accounts;

public sealed class RegistrationService
{
    private readonly IPasswordHasher _hasher;
    private readonly IAccountRepository _accounts;

    public RegistrationService(IPasswordHasher hasher, IAccountRepository accounts)
    {
        _hasher = hasher;
        _accounts = accounts;
    }

    public async Task RegisterAsync(string email, SensitiveString password, CancellationToken cancellationToken)
    {
        string passwordHash = await _hasher.HashAsync(password, cancellationToken);
        await _accounts.AddAsync(email, passwordHash, cancellationToken);
    }
}
```

Each call draws a new random salt, so the same password gives a different string every time. You cannot find a user by hashing their password and searching for the result, and you must never compare two hash strings. Always call `Verify`.

### Hashing with a specific profile

`Hash(password, profile)` accepts any profile the hasher has registered: the three built-in profiles are always registered, and custom profiles must be in `DefaultProfile` or `AdditionalProfiles`. Anything else throws `ArgumentException`, including a profile that reuses a registered id with different parameters. Profiles compare by value, so an equal profile built separately is accepted. The static `Password.Hash(password, profile)` uses `PasswordHasher.Default`, so it accepts only the three built-in profiles.

Hashing with a non-default profile does not change what the hasher considers current. When such a hash is later verified, the result reports `RehashReason.OutdatedProfile` and carries a replacement made with the default profile. To change the profile for everyone, change `DefaultProfile`. See [Profiles](./profiles.md).

There is no async overload that takes a profile.

### Input rules

| Input | `Hash` behaviour |
|-------|------------------|
| `null` password or profile | Throws `ArgumentNullException`. |
| Empty string | Throws `ArgumentException`: "Password cannot be empty." |
| Unpaired surrogate, or a code point NFKC normalization rejects (U+FFFE) | Throws `ArgumentException`: "Password contains invalid UTF-16 or a code point that cannot be normalized." |
| Longer than `MaxPasswordBytes` UTF-8 bytes after NFKC normalization (default 1024) | Throws `ArgumentException`: "Password exceeds 1024 bytes." (the configured limit). |
| A profile not registered with this hasher | Throws `ArgumentException`: "Profile '...' is not registered with this hasher." |
| Anything else, including spaces, emoji and any script | Hashed. The password is normalized to NFKC and encoded as UTF-8 first. |

These are programming or validation errors, not runtime conditions. Validate the password before you hash it, so users get a proper message instead of a 500. The [Password Policy](./password-policy.md) package checks length and quality, and in ASP.NET Core `WithPasswordLengthLimit()` rejects over-long passwords with a 400 before your handler runs; see [ASP.NET Core Identity](./aspnetcore-identity.md). The configured cap is available as `PasswordHasher.MaxPasswordBytes`.

### Unicode normalization

Before hashing, the password is normalized to NFKC (NIST SP 800-63B, section 5.1.1.2) and encoded as UTF-8. NFKC maps characters that look the same, or are compatibility forms of each other, to one form:

- `é` typed as one precomposed character (U+00E9) and as `e` plus a combining acute accent (U+0065 U+0301) hash the same.
- The ligature `ﬁ` (U+FB01) hashes the same as the two letters `fi`.
- A full-width `Ａ` (U+FF21) hashes the same as `A`.

So a user who signed up on one keyboard can log in from another. Case is not changed: `Password` and `password` are different passwords.

NFKC can make a password longer. The length cap applies to the normalized bytes, so a short input made of expanding characters can still exceed it.

:::note

For legacy formats, including the Masterly.Hash 1.x format, and for onion-wrapped hashes, the hasher passes the password exactly as given, without NFKC, because that is how the old system hashed it. Their length check uses the raw UTF-8 byte count.

:::

## Verifying

| Method | Notes |
|--------|-------|
| `PasswordVerificationResult Verify(string password, string storedHash)` | Verifies against any recognized format. |
| `PasswordVerificationResult VerifyOrDummy(string password, string? storedHash)` | Like `Verify`, but a `null` stored hash (unknown user) still costs one full verification. |
| `ValueTask<PasswordVerificationResult> VerifyAsync(string password, string storedHash, CancellationToken cancellationToken = default)` | Async `Verify`. |
| `ValueTask<PasswordVerificationResult> VerifyOrDummyAsync(string password, string? storedHash, CancellationToken cancellationToken = default)` | Async `VerifyOrDummy`. |
| `Verify`, `VerifyOrDummy`, `VerifyAsync`, `VerifyOrDummyAsync` with a `SensitiveString` password | Extension methods on `IPasswordHasher`. |
| `Password.Verify(string, string)`, `Password.Verify(SensitiveString, string)`, `Password.VerifyOrDummy(string, string?)`, `Password.VerifyAsync(...)`, `Password.VerifyOrDummyAsync(...)` | The static equivalents. |

```csharp title="LoginService.cs"
using Masterly.Hash;
using Microsoft.Extensions.Logging;

namespace MyApp.Accounts;

public sealed class LoginService
{
    private readonly IPasswordHasher _hasher;
    private readonly IAccountRepository _accounts;
    private readonly ILogger<LoginService> _logger;

    public LoginService(IPasswordHasher hasher, IAccountRepository accounts, ILogger<LoginService> logger)
    {
        _hasher = hasher;
        _accounts = accounts;
        _logger = logger;
    }

    public async Task<bool> LogInAsync(string email, SensitiveString password, CancellationToken cancellationToken)
    {
        // Account and IAccountRepository are your own types, as in the Quick Start.
        Account? account = await _accounts.FindByEmailAsync(email, cancellationToken);

        PasswordVerificationResult result =
            await _hasher.VerifyOrDummyAsync(password, account?.PasswordHash, cancellationToken);

        if (!result.IsMatch)
        {
            _logger.LogInformation("Login failed: {FailureReason}", result.FailureReason);
            return false;
        }

        if (result.Rehash is string fresh && account is not null)
        {
            await _accounts.UpdatePasswordHashAsync(account.Email, fresh, cancellationToken);
            _logger.LogInformation("Password hash upgraded: {RehashReason}", result.RehashReason);
        }

        return true;
    }
}
```

`Verify` never throws because of the stored hash. A `null`, empty, malformed, truncated, tampered or unknown string returns a failed result. The exceptions that can escape are listed in [Exceptions](#exceptions).

## Understanding the result

`PasswordVerificationResult` has these members:

| Member | Type | Meaning |
|--------|------|---------|
| `Status` | `VerificationStatus` | `Failed`, `Success` or `SuccessRehashNeeded`. |
| `IsMatch` | `bool` | `true` when the password is correct, whether or not a rehash is needed. This is the one property you must check. |
| `NeedsRehash` | `bool` | `true` when the password is correct and the stored hash should be replaced. |
| `FailureReason` | `VerificationFailureReason` | Why verification failed. `None` on success. |
| `RehashReason` | `RehashReason` | Why a rehash was requested. `None` when the hash is current or verification failed. |
| `Rehash` | `string?` | The replacement hash, made with the current default profile and pepper key. See [When Rehash is null](#when-rehash-is-null). |

`ToString()` returns `Success`, `SuccessRehashNeeded (<RehashReason>)` or `Failed (<FailureReason>)`. It never includes the replacement hash, so the result is safe to log.

### Failure reasons

The checks run in roughly this order, and the first one that applies decides the reason:

| `VerificationFailureReason` | When | Is the KDF run? |
|-----------------------------|------|-----------------|
| `NoStoredHash` | The stored hash is `null` or empty, or `VerifyOrDummy` was called for an unknown user. | No, except the dummy run in `VerifyOrDummy` |
| `EmptyPassword` | The password is the empty string. Empty passwords never match. | No |
| `InvalidPassword` | The password contains an unpaired surrogate or U+FFFE. | No |
| `MalformedHash` | A `$mh$` string that does not parse, or whose salt or tag length does not match its profile. Also a wrapped hash whose legacy parameters cannot be used. | No |
| `UnknownProfile` | A `$mh$` hash whose profile id is not registered with this hasher. | No |
| `UnknownPepperKey` | A peppered hash whose key id the configured pepper does not know, or a peppered hash checked by a hasher with no pepper. | No |
| `UnknownFormat` | A string no registered legacy format recognizes, or a wrapped hash whose legacy format is not registered. | No |
| `PasswordTooLong` | The password is longer than `MaxPasswordBytes`. Measured after NFKC for native hashes, raw UTF-8 for legacy and wrapped hashes. | No |
| `Mismatch` | The hash was usable and the password is wrong. | Yes |

Only `Mismatch` means "wrong password". Every other reason means the stored hash, the input or the configuration is the problem. Treat them differently in monitoring: a spike in `Mismatch` is password guessing, while `UnknownPepperKey` or `UnknownProfile` usually means a key or profile was removed from configuration too early.

:::warning

Failure reasons are for logs and metrics only. Show the user one generic message, such as "Email or password is incorrect", for every failure. Telling a user "no such account" or "password too long for this account" leaks information to attackers.

:::

### Rehash reasons

| `RehashReason` | When |
|----------------|------|
| `None` | The hash is current. |
| `LegacyFormat` | The hash is in a legacy format: Masterly.Hash 1.x or a format from `Masterly.Hash.Legacy`. |
| `Wrapped` | The hash is onion-wrapped. The replacement is a plain native hash. |
| `OutdatedProfile` | The hash uses a registered profile other than the current default. |
| `OutdatedPepperKey` | The hash was made with an older pepper key, or without a pepper and a pepper has since been added. |

When more than one applies to a native hash, the first in this order wins: `Wrapped`, `OutdatedProfile`, `OutdatedPepperKey`. See [Upgrade on Login](./upgrade-on-login.md).

### When Rehash is null

`Rehash` is non-null only when `NeedsRehash` is `true`. Even then it is `null` in two cases:

- **`ComputeRehashOnVerify` is `false`.** The hasher only flags the hash. Call `Hash(password)` yourself when you are ready to store the replacement. ASP.NET Core Identity integration turns this option off because `UserManager<TUser>` rehashes on its own.
- **The password cannot be stored natively.** A legacy or wrapped hash is checked against the raw UTF-8 length, but NFKC can expand a password past `MaxPasswordBytes`. One U+FDFA character, for example, becomes 18 characters. The login still succeeds; the hash just stays as it is.

Write the upgrade as `if (result.Rehash is string fresh)` and both cases are handled.

## Exceptions

`Verify` reports every problem with the stored hash through the result. These are the exceptions that can escape `Hash` and `Verify`:

| Exception | Thrown by | Cause | What to do |
|-----------|-----------|-------|------------|
| `ArgumentNullException` | Both | A `null` password, a `null` profile, or a `null` `SensitiveString` or hasher passed to an extension method. A `null` stored hash does not throw. The static `Password.Hash(SensitiveString)` and `Password.Verify(SensitiveString, string)` do not check their argument, so a `null` there throws `NullReferenceException`. | Fix the call. |
| `ArgumentException` | `Hash` | An empty, invalid or over-long password, or an unregistered profile. See [Input rules](#input-rules). | Validate input before hashing. |
| `PasswordHasherBusyException` | Both | No KDF slot freed up within `ConcurrencyTimeout`. It derives from `TimeoutException`. | Return HTTP 503 with `Retry-After`. See [Limits and Concurrency](./limits-and-concurrency.md). |
| `OperationCanceledException` | Async methods | The token was cancelled while the call waited for a slot or for a remote pepper. | Let it propagate. |
| Pepper exceptions, such as `PepperUnavailableException` from the key-store packages | Both | The pepper could not compute its HMAC, for example because Vault or KMS is unreachable. | Treat as an outage; do not report it as a wrong password. See [Peppers](./peppers.md). |

:::note

A successful verification of an outdated hash runs the KDF twice: once to verify, and once more to compute `Rehash`. The hasher releases its slot between the two, so a limit of one slot cannot deadlock. Under heavy load the second run can still time out, so `Verify` can throw `PasswordHasherBusyException` for a correct password. Turn `ComputeRehashOnVerify` off if you prefer to upgrade outside the login request.

:::

## Sync or async

| | Sync (`Hash`, `Verify`, `VerifyOrDummy`) | Async (`HashAsync`, `VerifyAsync`, `VerifyOrDummyAsync`) |
|--|------------------------------------------|----------------------------------------------------------|
| Waiting for a slot | Blocks the calling thread. | Waits without holding a thread. |
| Pepper | Calls `IPasswordPepper.Apply`, which may block on a network call for remote peppers. | Calls `IPasswordPepper.ApplyAsync`. |
| KDF | Runs on the calling thread. | Runs inline, on whichever thread resumes after the slot wait. Argon2 and PBKDF2 are CPU work; async does not offload them to a background thread. |
| Cancellation | Not supported. | Honoured while waiting for a slot and inside the pepper. Once the KDF starts, it runs to completion. |
| Synchronization context | Not applicable. | Continuations do not post back to the caller's context (`ConfigureAwait(false)`). |

In ASP.NET Core and other servers, use the async methods. Under a login flood, the sync methods park thread-pool threads on the concurrency gate, which starves the rest of the application. Use the sync methods in console tools, scripts and synchronous interfaces you cannot change.

The async methods return `ValueTask`. Await each one exactly once, and do not call `.Result` or `.GetAwaiter().GetResult()` on one.

## Unknown users

`VerifyOrDummy(password, storedHash)` behaves exactly like `Verify` when `storedHash` is not `null`. When it is `null`, it builds a random hash in the current format (default profile, current pepper key) and verifies against it, so a request for an account that does not exist takes as long as one for an account that does. The result is always a failure with `NoStoredHash`, and no rehash is ever computed for the dummy.

:::warning

Only `null` triggers the dummy work. An empty string returns `NoStoredHash` immediately, which makes that path measurably faster. Pass `null`, not `string.Empty`, when the user does not exist.

:::

An empty or invalid password returns at once on both paths, which reveals nothing, since it is equally fast for real and unknown users. The protection also does not cover accounts that still have a legacy hash, which verify faster than Argon2id. See [User Enumeration](./user-enumeration.md).

## Inspecting a stored hash

`Inspect(storedHash)` describes a hash without verifying it and without running the KDF. Use it for audits, dashboards and migration planning. `NeedsRehash(storedHash)` is shorthand for `Inspect(storedHash).NeedsRehash`.

```csharp title="Inspect a stored hash"
HashInfo info = hasher.Inspect(account.PasswordHash);

Console.WriteLine($"{info.Format} recognized={info.IsRecognized} profile={info.ProfileId} rehash={info.RehashReason}");
```

| `HashInfo` member | Meaning |
|-------------------|---------|
| `Format` | `mh` (`HashInfo.NativeFormat`) for a `$mh$` string, the id of the first legacy format that claims the string (such as `v1` or `bcrypt`), or `unknown` (`HashInfo.UnknownFormat`). |
| `IsRecognized` | `true` if this hasher could verify the hash: it parses, its profile is registered with matching lengths, its pepper key is known, and its wrapped format is registered. For a legacy string it means a registered format claims it. |
| `IsNative` | `true` when `Format` is `mh`. A malformed `$mh$` string is native but not recognized. |
| `ProfileId` | The profile id from a native hash, even when it is not registered. |
| `Profile` | The registered `HashProfile`, or `null` when the id is not in the allowlist. |
| `PepperKeyId` | The pepper key id, when the hash is peppered. |
| `WrappedFormat` | The legacy format id inside an onion-wrapped hash. |
| `RehashReason` | What a successful login would report. `None` for hashes that are current or not recognized. |
| `NeedsRehash` | `true` when `RehashReason` is not `None`. |

`Inspect` is cheap, but it does not prove the hash is valid: only `Verify` can tell whether a legacy string really verifies. To report on a whole table, use `HashAudit` from `Masterly.Hash.Legacy`; see [Auditing Hash Tables](./auditing-hash-tables.md).

## SensitiveString

`SensitiveString` wraps a secret so it cannot leak by accident. Use it for password properties in request models and commands.

| Member | Behaviour |
|--------|-----------|
| `new SensitiveString(string value)`, `(SensitiveString)value` | Wraps a value. `null` throws `ArgumentNullException`. |
| `Reveal()` | Returns the real value. Every call site is a place the secret can leak; keep them few. |
| `ToString()` | Always `***` (`SensitiveString.Redacted`). |
| Debugger display | `***`. |
| JSON | Reading takes the real value. Writing always writes `"***"`, so a `SensitiveString` never round-trips through JSON. A JSON `null` reads as `null`; any token other than a string throws `JsonException`. |
| `TryParse(string?, out SensitiveString?)` | Lets ASP.NET Core minimal APIs bind it from route, query or form values. Returns `false` only for `null`. |
| `Length`, `IsEmpty` | Length in UTF-16 code units, and whether the value is empty. |

The `IPasswordHasher` extension methods and the static `Password.Hash(SensitiveString)` and `Password.Verify(SensitiveString, string)` accept it directly, so the value is only revealed inside the hasher.

```csharp title="LoginRequest.cs"
using Masterly.Hash;

namespace MyApp.Api;

public sealed record LoginRequest(string Email, SensitiveString Password);

// Logging the request, or serializing it, prints Password = *** rather than the password.
```

`SensitiveString` does not encrypt or wipe anything; .NET strings are immutable and stay in memory until collected. It only stops the value from appearing in logs, exception messages, traces and debugger windows.

## Low-level primitives

`Masterly.Hash.Primitives.HashPrimitives` exposes the building blocks the companion packages share. Application code should use `Password` or `PasswordHasher` instead; use these only to build a custom scheme on the same foundations.

| Member | What it does |
|--------|--------------|
| `FixedTimeEquals(byte[], byte[])`, `FixedTimeEquals(ReadOnlySpan<byte>, ReadOnlySpan<byte>)` | Compares in time that depends only on the lengths. |
| `DeriveKey(HashProfile, byte[] input, byte[] salt)` | Runs a profile's KDF with an explicit salt. Bypasses the concurrency limit, the pepper and the format. Input must be non-empty; salt at least 8 bytes. |
| `Argon2(Argon2Variant, byte[] password, byte[] salt, int memoryKiB, int iterations, int parallelism, int tagLength)` | Argon2d, Argon2i or Argon2id (RFC 9106, version 0x13) with explicit parameters, for hashes made by other systems. Runs on the calling thread and bypasses the concurrency limit, the pepper and the format. Salt 8 to 1024 bytes, memory 8 × parallelism to 1,048,576 KiB, iterations 1 to 64, parallelism 1 to 16, tag 4 to 1024 bytes. |
| `EncodePassword(string)` | The exact bytes the hasher feeds the KDF: UTF-8 of the NFKC-normalized password. Throws `ArgumentException` for invalid input. |
| `IsWellFormedPassword(string)` | `true` if the hasher accepts the string: no unpaired surrogates and normalizable by NFKC. |
| `Pbkdf2(HashAlgorithmName, byte[], byte[], int, int)` | PBKDF2 with HMAC-SHA1, HMAC-SHA256 or HMAC-SHA512. Other PRFs throw `ArgumentOutOfRangeException`. |
| `RandomBytes(int)`, `Zero(byte[]?)` | Secure random bytes, and wiping a buffer. |
| `ToB64(byte[])`, `TryFromB64(string, out byte[])` | Unpadded standard base64, as used by the `$mh$` format. Decoding is strict and canonical. |
| `IsValidProfileId`, `IsValidKeyId`, `IsValidFormatId` | Check identifiers against the format's patterns. |

## The obsolete 1.x API

The 1.x types `Hash`, `IHash` and `SupportedHash` still compile, marked `[Obsolete]`, so upgrading the package does not break your build. They compute one salted SHA-2 pass, which is not suitable for passwords. `Hash.Verify` is now constant-time and no longer throws when given the wrong algorithm. Replace calls with `Password.Hash` and `Password.Verify`; 1.x hashes verify through the new API and are upgraded on the next login. The `MH0006` analyzer flags remaining uses. See [Upgrading from 1.x](./upgrading-from-1x.md).

## See also

- [Quick Start](./quick-start.md)
- [How It Works](./how-it-works.md)
- [Upgrade on Login](./upgrade-on-login.md)
- [User Enumeration](./user-enumeration.md)
- [Limits and Concurrency](./limits-and-concurrency.md)
- [API Reference](./api-reference.md)
