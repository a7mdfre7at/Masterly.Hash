---
title: "Preventing User Enumeration"
sidebar_label: "User Enumeration"
description: "Use VerifyOrDummy so that a login for an unknown account takes as long as one for a real account."
---

If your login endpoint answers faster for an unknown email address than for a real one, an attacker can find out which accounts exist by timing it. The usual cause is that the server skips the password hash when it finds no user, and a `2026a` hash takes about 170 ms. This page shows how `VerifyOrDummy` removes that difference, and which other differences remain for you to handle.

## Use VerifyOrDummy

Look the user up, then pass the stored hash, or `null` when there is no user, to `VerifyOrDummyAsync`:

```csharp title="LoginService.cs"
// users and LoginOutcome are your application's types; hasher is your IPasswordHasher
User? user = await users.FindByEmailAsync(email, cancellationToken);
string? stored = string.IsNullOrEmpty(user?.PasswordHash) ? null : user.PasswordHash;

PasswordVerificationResult result = await hasher.VerifyOrDummyAsync(password, stored, cancellationToken);
if (!result.IsMatch)
{
    return LoginOutcome.InvalidCredentials; // the same answer for "no such user" and "wrong password"
}
```

When `storedHash` is not `null`, `VerifyOrDummy` is exactly `Verify`. When it is `null`, the hasher:

1. builds a dummy hash in the current format: the default profile, the pepper's current key, a random salt and a random tag;
2. verifies the password against it, doing the same work as a real verification, including the pepper call and a slot in the [concurrency gate](./limits-and-concurrency.md#the-concurrency-gate);
3. returns `Failed` with `VerificationFailureReason.NoStoredHash`.

Nothing matches the dummy hash, and it is built fresh on each call, so it follows a pepper key rotation. A dummy under an old key would skip work and make unknown users measurably cheaper.

The `VerifyOrDummyBenchmarks` in [`perf/`](https://github.com/a7mdfre7at/Masterly.Hash/blob/master/perf/Masterly.Hash.Benchmarks/README.md) compare a known user with `null`; the ratio should be close to 1.00. See [Performance](./performance.md).

The same method is available as:

| API | Notes |
|---|---|
| `IPasswordHasher.VerifyOrDummy(password, storedHash)` | Sync. Blocks the thread while it waits for a slot. |
| `IPasswordHasher.VerifyOrDummyAsync(password, storedHash, cancellationToken)` | Async. Prefer it on request paths. |
| `Password.VerifyOrDummy`, `Password.VerifyOrDummyAsync` | Static, on `PasswordHasher.Default` |
| `VerifyOrDummy` / `VerifyOrDummyAsync` extensions taking a `SensitiveString` | In `PasswordHasherExtensions` |

`VerifyAndUpgradeAsync` from `Masterly.Hash.EntityFrameworkCore` calls `VerifyOrDummyAsync` with the entity's stored hash, so a `null` hash gets the dummy verification (an empty string does not; see the warning below). See [Entity Framework Core](./entity-framework-core.md).

:::warning

Pass `null`, not an empty string. `VerifyOrDummy(password, "")` returns `NoStoredHash` immediately, without the dummy work, so an account stored with an empty hash (for example one that signs in only with an external provider) answers fast. Convert empty values to `null`, as the example above does.

:::

## Give one answer

`VerifyOrDummy` equalizes the time spent hashing. The rest of the response must be equal too:

- **Return the same status code, body and headers** for an unknown user and a wrong password. `FailureReason` is `NoStoredHash` for one and `Mismatch` for the other: log it, but never send it to the client.
- **Run the verification before any check that only exists for real accounts**, such as "email not confirmed", "account locked" or "MFA required". If those return early for known users, the early return is itself the signal.
- **Do the same database and logging work** on both paths where you can. A second query or a slow audit write that only happens for real users is measurable.

## Differences that remain

The dummy costs what a verification with the **current** default profile and pepper costs. A real account's cost depends on its stored hash, so these accounts still answer at a different speed from an unknown one:

| Stored hash | Cost compared with the dummy |
|---|---|
| Current profile and pepper | The same |
| An older profile, such as `2026c` (verifies in about 33 ms) when the default is `2026a` (about 177 ms) | Faster |
| `2026f` (PBKDF2, verifies in about 82 ms) when the default is `2026a` | Faster |
| A legacy hash such as 1.x (about 5 µs) | Much faster |
| An onion-wrapped hash | Slower by the cost of recomputing the legacy digest before the Argon2id step: negligible for a salted SHA-2 digest, noticeable for bcrypt or PBKDF2 |
| Malformed, an unknown format, an unknown profile or an unknown pepper key | Much faster: it fails before any KDF runs |

Upgrade on login removes most of these over time, because each successful login moves the account to the current profile and pepper (see [Upgrade on login](./upgrade-on-login.md)). For legacy hashes, do not wait: wrap them offline with `TryWrap` so they cost at least as much as a native hash (see [Onion wrapping](./onion-wrapping.md)). To find the accounts that still differ, scan the table with `Inspect` or `masterly-hash audit` (see [Auditing hash tables](./auditing-hash-tables.md)).

These inputs fail quickly for **every** account, known or not, so they reveal nothing:

- an empty password (`EmptyPassword`, or `NoStoredHash` for an unknown user);
- a password with an unpaired surrogate or U+FFFE (`InvalidPassword`, or `NoStoredHash`);
- a password over `MaxPasswordBytes` (`PasswordTooLong`, or `NoStoredHash`).

`null` as the password throws `ArgumentNullException` in every case.

## ASP.NET Core Identity

Identity's sign-in flow looks the user up first and returns a failure without calling the password hasher when there is no such user. `VerifyOrDummy` cannot help there on its own. If you write your own login endpoint over `UserManager`, add the dummy verification on the unknown-user branch:

```csharp title="AccountController.cs"
// userManager is UserManager<AppUser> and hasher is Masterly.Hash.IPasswordHasher, both injected;
// model and cancellationToken are the action's parameters
AppUser? user = await userManager.FindByEmailAsync(model.Email);
if (user is null)
{
    await hasher.VerifyOrDummyAsync(model.Password, null, cancellationToken);
    return Unauthorized();
}
```

See [ASP.NET Core Identity](./aspnetcore-identity.md).

## Metrics

A dummy verification is not recorded in `masterly.hash.verifications` or `masterly.hash.duration`. Those instruments count only verifications against a stored hash, so unknown-user attempts do not appear in them. Count failed logins for unknown accounts in your own code if you need that number. See [Observability](./observability.md).

## What this does not cover

User enumeration has other channels that a hash library cannot close:

- **Registration** that says "this email is already registered".
- **Password reset** that answers differently for unknown addresses. Answer "if the account exists, we sent an email" in both cases.
- **Rate limiting and lockout** messages that only appear for real accounts.

Honey accounts and credential-stuffing detection in `Masterly.Hash.Detection` also rely on consistent timing: a honey account must still run a real or dummy verification before failing. See [Attack detection](./attack-detection.md).

## See also

- [Hashing and verifying](./hashing-and-verifying.md): `Verify` and the failure reasons
- [Onion wrapping](./onion-wrapping.md): removing the legacy timing signal
- [Limits and concurrency](./limits-and-concurrency.md): the dummy takes a slot like any verification
- [Threat model](./threat-model.md): online attackers at the login endpoint
