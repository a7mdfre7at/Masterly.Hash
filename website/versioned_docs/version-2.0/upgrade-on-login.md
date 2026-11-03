---
title: "Upgrade on Login"
sidebar_label: "Upgrade on Login"
description: "Replace outdated hashes with current ones as users log in, without a migration or a password reset."
---

A successful login is the only moment the server sees the user's password, so it is the moment to replace an outdated hash. Masterly.Hash does this for you: when a password matches a hash that is no longer current, the verification result carries a fresh hash. You store it, and the user is upgraded without noticing.

This page explains what counts as outdated, how to read the result, how to save the new hash safely, and what happens to accounts that never log in.

```csharp
// hasher is your IPasswordHasher; user comes from your users table
PasswordVerificationResult result = await hasher.VerifyAsync(password, user.PasswordHash, cancellationToken);

if (result.IsMatch && result.Rehash is { } fresh)
{
    user.PasswordHash = fresh; // then save the user
}
```

## What triggers a rehash

A matching password returns `VerificationStatus.SuccessRehashNeeded` instead of `VerificationStatus.Success` when the stored hash is one of these:

| `RehashReason` | The stored hash is | Typical cause |
|---|---|---|
| `LegacyFormat` | In a legacy format: Masterly.Hash 1.x, or a format from `Masterly.Hash.Legacy` such as bcrypt or ASP.NET Core Identity | Upgrading from 1.x, or migrating from another system |
| `Wrapped` | An onion-wrapped legacy hash (`w=` in the hash string) | You ran `TryWrap` or `masterly-hash wrap` |
| `OutdatedProfile` | A Masterly hash made with a registered profile other than the current `DefaultProfile` | You changed the default profile |
| `OutdatedPepperKey` | Made with an older pepper key, or made without a pepper when a pepper is now configured | You rotated or added a pepper key |

When several apply, the first in this order is reported: `Wrapped`, then `OutdatedProfile`, then `OutdatedPepperKey`. The replacement is always made with the current default profile and the current pepper key, so one rehash fixes everything at once.

A hash that is already current returns `Success` with `RehashReason.None`.

## Reading the result

`PasswordVerificationResult` has these members:

| Member | Meaning |
|---|---|
| `Status` | `Failed`, `Success` or `SuccessRehashNeeded` |
| `IsMatch` | True for `Success` and `SuccessRehashNeeded`. Use this to decide the login. |
| `NeedsRehash` | True for `SuccessRehashNeeded` |
| `RehashReason` | Why a rehash was requested, or `None` |
| `Rehash` | The replacement hash, or `null` (see below) |
| `FailureReason` | Why a failed verification failed, or `None`. For logs and metrics only. |

`ToString()` returns a short description for logs, such as `SuccessRehashNeeded (OutdatedProfile)` or `Failed (Mismatch)`. It never contains the password or the hash.

### When `Rehash` is null

`Rehash` is non-null only when `NeedsRehash` is true. Even then it is `null` in two cases:

- **`ComputeRehashOnVerify` is false.** The hasher reports that a rehash is needed but does not compute it. See [Computing the replacement yourself](#computing-the-replacement-yourself).
- **The password cannot be stored natively.** Legacy and wrapped formats check the raw UTF-8 length of the password against `MaxPasswordBytes`, but new hashes measure it after NFKC normalization, which can expand it (U+FDFA becomes 18 characters). If the normalized password exceeds the limit, the login still succeeds, `NeedsRehash` is true, and `Rehash` is `null`. The old hash stays as it is. See [Limits and concurrency](./limits-and-concurrency.md).

Always test `result.Rehash` for `null`, not only `result.NeedsRehash`.

## A complete login

This service verifies a password, protects against [user enumeration](./user-enumeration.md), and stores the upgraded hash only if the row has not changed in the meantime:

```csharp title="LoginService.cs"
using System.Threading;
using System.Threading.Tasks;
using Masterly.Hash;

namespace MyApp.Accounts;

// IUserRepository and User are your application's types.
public sealed class LoginService
{
    private readonly IPasswordHasher _hasher;
    private readonly IUserRepository _users;

    public LoginService(IPasswordHasher hasher, IUserRepository users)
    {
        _hasher = hasher;
        _users = users;
    }

    public async Task<bool> SignInAsync(string email, string password, CancellationToken cancellationToken)
    {
        User? user = await _users.FindByEmailAsync(email, cancellationToken);
        string? stored = string.IsNullOrEmpty(user?.PasswordHash) ? null : user.PasswordHash;

        PasswordVerificationResult result = await _hasher.VerifyOrDummyAsync(password, stored, cancellationToken);
        if (!result.IsMatch)
        {
            return false;
        }

        if (result.Rehash is { } fresh)
        {
            // A null stored hash never matches, so user and stored are non-null here.
            await _users.ReplacePasswordHashAsync(user!.Id, expectedHash: stored!, newHash: fresh, cancellationToken);
        }

        return true;
    }
}
```

`ReplacePasswordHashAsync` should update the row only when it still holds the hash that was verified:

```sql
UPDATE Users SET PasswordHash = @newHash WHERE Id = @id AND PasswordHash = @expectedHash;
```

Verification takes about 125 ms with the default profile. If the user resets their password in another request during that time, an unconditional update would overwrite the new password's hash with a hash of the old password. The `WHERE` clause makes the upgrade a no-op in that case. The upgrade is opportunistic: if it does not happen, the user is upgraded on a later login.

## With Entity Framework Core or Identity

You do not have to write the save logic yourself:

- **Entity Framework Core.** `context.VerifyAndUpgradeAsync(user, u => u.PasswordHash, password, cancellationToken)` from `Masterly.Hash.EntityFrameworkCore` verifies (with the dummy for a `null` hash), writes the replacement to the property (`Rehash`, or a hash it computes with `HashAsync` when `ComputeRehashOnVerify` is off) and saves. It re-reads the stored hash before saving so that a password reset that committed meanwhile is not overwritten, and a failed save of this entity alone still returns the successful result. See [Entity Framework Core](./entity-framework-core.md).
- **ASP.NET Core Identity.** `AddMasterlyPasswordHasher()` maps `SuccessRehashNeeded` to Identity's `PasswordVerificationResult.SuccessRehashNeeded`. `UserManager` then calls `HashPassword` and saves the user itself. For that reason `AddMasterlyPasswordHasher` sets `ComputeRehashOnVerify` to `false`, so the replacement is not computed twice. See [ASP.NET Core Identity](./aspnetcore-identity.md).

## Computing the replacement yourself

Set `ComputeRehashOnVerify = false` when something other than the verify call produces the new hash, as Identity does, or when you want to move the second hash computation off the login request:

```csharp title="Program.cs"
builder.Services.AddMasterlyHash(options => options.ComputeRehashOnVerify = false);
```

Verification then returns `SuccessRehashNeeded` with `Rehash == null`. Call `HashAsync` with the same password when you are ready to store a new hash:

```csharp
// hasher is your IPasswordHasher; result is the verification result from the login
if (result.NeedsRehash)
{
    string fresh = await hasher.HashAsync(password, cancellationToken);
    // store fresh, as in the login above
}
```

`HashAsync` throws `ArgumentException` for a password that exceeds `MaxPasswordBytes` after normalization, the case in which the hasher would have returned `Rehash == null`. With the default `ComputeRehashOnVerify = true`, the hasher computes the replacement inside the verify call: a successful login with an outdated hash costs one verification under the old profile plus one new hash under the default profile. A 1.x hash verifies in 6.3 µs, but in 128 ms including its rehash to `2026a` (measured on the hardware in [Profiles](./profiles.md#measured-cost)).

## Failures during the rehash

The replacement is computed after the password has matched, as a separate hash operation. It can fail for the same reasons any hash can:

| Failure | Cause |
|---|---|
| `PasswordHasherBusyException` | The rehash waits for its own slot in the concurrency gate, and no slot became free within `ConcurrencyTimeout`. |
| `OperationCanceledException` | The `CancellationToken` was cancelled while the rehash waited for a slot or for a remote pepper. |
| The pepper provider's exception | A remote pepper (Vault, KMS, Key Vault) could not be reached for the current key. |

In these cases the verify call throws, even though the password was correct. Treat it like any other failure of the login request: the busy exception maps to `503` with `Retry-After` (see [Limits and concurrency](./limits-and-concurrency.md#when-the-gate-is-full)), and the user retries. If you would rather never fail a correct login over the upgrade, set `ComputeRehashOnVerify = false` and compute the new hash in a separate `try` block that ignores failures.

The rehash does not deadlock at `MaxConcurrency = 1`: the verification releases its slot before the rehash asks for one.

## Checking without a password

Two methods describe a stored hash without verifying it and without running the KDF:

```csharp
// hasher is your IPasswordHasher; storedHash comes from your users table
bool outdated = hasher.NeedsRehash(storedHash);

HashInfo info = hasher.Inspect(storedHash);
Console.WriteLine($"{info.Format} {info.ProfileId} {info.PepperKeyId} {info.RehashReason}");
```

`NeedsRehash(storedHash)` is `Inspect(storedHash).NeedsRehash`: true if a successful login with this hash would produce a rehash. It is false for a hash the hasher cannot verify at all (an unknown format, an unregistered profile, an unknown pepper key), because no login with it can succeed. Use `Inspect(...).IsRecognized` to find those.

Use these to measure how far a migration has come. For whole tables, `HashAudit` and `masterly-hash audit` produce a report; see [Auditing hash tables](./auditing-hash-tables.md).

## Monitoring the upgrade

Every verification increments the `masterly.hash.verifications` counter with the tags `format`, `outcome` and `reason`. For a successful login with an outdated hash, `outcome` is `SuccessRehashNeeded` and `reason` is the `RehashReason`, for example `OutdatedPepperKey`. Watching that series fall to zero tells you that active users have been upgraded. See [Observability](./observability.md).

## Accounts that never log in

Upgrade on login only reaches users who log in. A dormant account keeps its old hash forever, and after a database leak a weak legacy hash is the easiest one to crack. Two tools close the gap:

- **Onion wrapping.** `TryWrap(legacyHash, out string wrappedHash)` wraps a legacy hash in Argon2id offline, without the password. The wrapped hash verifies with the original password and is upgraded to a plain hash (`RehashReason.Wrapped`) on the next login. See [Onion wrapping](./onion-wrapping.md).
- **A forced reset.** For hashes that cannot be wrapped, or that use a profile or pepper key you must retire, expire the password and send the user through your reset flow.

## See also

- [Profiles](./profiles.md): changing the default profile
- [Peppers](./peppers.md): adding and rotating pepper keys
- [Legacy formats](./legacy-formats.md): verifying hashes from other systems
- [User enumeration](./user-enumeration.md): `VerifyOrDummy` for unknown users
- [Upgrading from 1.x](./upgrading-from-1x.md)
