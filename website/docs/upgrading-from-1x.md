---
title: Upgrading from 1.x
sidebar_label: Upgrading from 1.x
description: Move from Masterly.Hash 1.x salted SHA-2 to Argon2id without a password reset, protect dormant accounts with onion wrapping, and review every behaviour change.
---

Masterly.Hash 1.x stored `base64(SHA-2(UTF-8(password) || salt) || salt)`. That is one fast hash, which a single GPU can attack at billions of guesses per second. Version 2 replaces it with Argon2id and migrates your users without forcing anyone to reset a password: 1.x hashes keep verifying, and each successful login hands you an Argon2id replacement. This page walks through the upgrade and lists every behaviour change.

## Step 1: upgrade the package

```bash
dotnet add package Masterly.Hash --version 2.*
```

Version 2 targets `net8.0` only (.NET 8 and later). The `netstandard2.0` target is gone, and with it .NET Framework support. Stay on 1.x for .NET Framework projects.

Old code still compiles. `Hash`, `IHash` and `SupportedHash` are marked `[Obsolete]`, so every use produces compiler warning CS0618. If your build treats warnings as errors, it fails at this point. Either finish Step 2 in the same change, or suppress CS0618 around the remaining calls until you do.

The `Masterly.Hash.Analyzers` package reports every remaining 1.x `ComputeHash` call as MH0006 and offers a code fix when the call passes only the plaintext. See [Analyzers](./analyzers.md).

## Step 2: verify with the new API

Replace the 1.x `Verify` call at login with `Verify` or `VerifyAsync`, and store `Rehash` when it is set:

```csharp title="Before (1.x)"
IHash hash = new Hash();
bool ok = hash.Verify(password, user.PasswordHash, SupportedHash.SHA512);
```

```csharp title="After (2.x)"
PasswordVerificationResult result = await Password.VerifyAsync(password, user.PasswordHash, cancellationToken);
if (result.IsMatch && result.Rehash is string fresh)
{
    user.PasswordHash = fresh; // now $mh$p=2026a$..., Argon2id
    await db.SaveChangesAsync(cancellationToken);
}

bool ok = result.IsMatch;
```

You do not need to know which SHA-2 variant produced a 1.x hash. The built-in v1 verifier tries SHA-512, SHA-384 and SHA-256, and compares in constant time. The result is `SuccessRehashNeeded` with `RehashReason.LegacyFormat`. After the first successful login the row holds an Argon2id hash and verifies as `Success`.

`Password` is a static facade over `PasswordHasher.Default`, which uses the default options. In an application with dependency injection, register the hasher once and inject `IPasswordHasher` instead of `IHash`:

```csharp title="Program.cs"
builder.Services.AddMasterlyHash(); // registers PasswordHasher and IPasswordHasher as one singleton
```

```csharp title="LoginService.cs"
using System.Threading;
using System.Threading.Tasks;
using Masterly.Hash;

namespace MyApp.Accounts;

public sealed class LoginService
{
    private readonly IPasswordHasher _hasher;
    private readonly AppDbContext _db; // your DbContext

    public LoginService(IPasswordHasher hasher, AppDbContext db)
    {
        _hasher = hasher;
        _db = db;
    }

    public async Task<bool> CheckPasswordAsync(User user, string password, CancellationToken cancellationToken)
    {
        PasswordVerificationResult result = await _hasher.VerifyAsync(password, user.PasswordHash, cancellationToken);
        if (result.IsMatch && result.Rehash is string fresh)
        {
            user.PasswordHash = fresh;
            await _db.SaveChangesAsync(cancellationToken);
        }

        return result.IsMatch;
    }
}
```

`AddMasterlyHash` comes from the `Masterly.Hash.DependencyInjection` package. In 1.x, `IHash` was an `IScopedDependency` picked up by Masterly.DependencyInjection; that dependency is removed. See [Dependency Injection](./dependency-injection.md). For a login endpoint that may receive unknown user names, use `VerifyOrDummyAsync`; see [User Enumeration](./user-enumeration.md).

## Step 3: hash new passwords with the new API

Registration and password changes call `Password.Hash(password)` or `HashAsync`, or the same methods on an injected `IPasswordHasher`. Replace every `ComputeHash` call:

```csharp title="Before (1.x)"
string stored = new Hash().ComputeHash(plainText);
```

```csharp title="After (2.x)"
string stored = await Password.HashAsync(plainText, cancellationToken);
```

The new API deliberately takes no algorithm and no salt. Unlike `ComputeHash`, `Hash` rejects some input with `ArgumentException`: an empty password, a password with an unpaired surrogate or U+FFFE, and a password longer than `MaxPasswordBytes` (1024 UTF-8 bytes after NFKC normalization, by default). Validate input before calling it; see [Limits and Concurrency](./limits-and-concurrency.md).

## Step 4: make room in the column

1.x and 2.x hashes can live in the same column, so no schema split is needed. Check its size:

| Value | Length |
|---|---|
| 1.x hash with the default random salt | 48 to 108 characters |
| 2.x hash, default profile `2026a` | 78 characters |
| 2.x hash, profile `2026f` | 121 characters |
| Peppered or wrapped 2.x hash | Longer; a wrapped hash grows with your 1.x salt |
| Upper bound of the `$mh$` format | 1024 characters |

Size the column for at least 256 characters, or use unbounded text.

## Step 5: wrap the users who never log in

Upgrade on login only reaches active users. Dormant accounts keep their fast SHA-2 hashes until the user returns, and a database leak exposes exactly those accounts. [Onion wrapping](./onion-wrapping.md) fixes that offline, without the passwords: it stores `Argon2id(SHA-2(password || salt))` in place of the SHA-2 digest.

Wrapping needs the algorithm explicitly, because 1.x did not record it and the digest length cannot be inferred from an arbitrary salt. The auto-detecting `V1LegacyFormat.Instance` therefore never wraps. 1.x defaulted to SHA-512:

```csharp title="WrapV1.cs"
using Masterly.Hash;
using Masterly.Hash.Legacy;

PasswordHasherOptions options = new PasswordHasherOptions();
options.LegacyFormats[0] = new V1LegacyFormat(V1Algorithm.SHA512); // replaces the auto-detecting default
PasswordHasher wrapper = new PasswordHasher(options);

foreach (User user in usersWithV1Hashes) // rows the login hasher's Inspect reports as "v1"
{
    if (wrapper.TryWrap(user.PasswordHash, out string wrapped))
    {
        user.PasswordHash = wrapped; // $mh$p=2026a,w=v1,wp=...$...$...
    }
}
```

`LegacyFormats[0]` is the v1 format only in fresh options. If you have added other legacy formats, replace the entry whose `Id` is `v1`.

This wrapper's only format is the explicit v1 format, which claims any long base64 string. Pass it only rows that the login hasher's `Inspect` reports as `v1`; an ASP.NET Identity hash in the same table would otherwise be wrapped as `w=v1` and never verify again.

Use a separate hasher for wrapping. The login hasher keeps `V1LegacyFormat.Instance`: it verifies `w=v1` wrapped hashes of every algorithm, because the algorithm is stored in the `wp` parameter. Give the wrapping hasher the same default profile and pepper as the login hasher. The [onion wrapping](./onion-wrapping.md#wrap-a-table-step-by-step) page shows a batch job that does not overwrite rows changed during the run.

:::danger

Wrapping with the wrong algorithm locks users out. The wrapped hash is built from a wrong split of digest and salt, so it never verifies and the original 1.x hash is gone. Wrap a copy first and check a few rows whose passwords you know.

:::

**If your code used more than one algorithm.** When every hash came from `ComputeHash` without a salt argument, the length of the stored string tells the algorithm. 1.x drew a random salt of 4 to 15 bytes, and the obsolete 2.x API draws 16, so the ranges do not overlap:

| Stored length (characters) | Algorithm |
|---|---|
| 48 to 64 | SHA-256 |
| 72 to 88 | SHA-384 |
| 92 to 108 | SHA-512 |

This does **not** hold for hashes made with your own salt (`ComputeHash(plainText, salt, hash)`), whose length is arbitrary. In that case, wrap only the rows whose algorithm you know. The rest still verify through auto-detection and upgrade on login.

```csharp title="WrapV1ByLength.cs"
using Masterly.Hash;
using Masterly.Hash.Legacy;

PasswordHasher sha256 = CreateWrapper(V1Algorithm.SHA256);
PasswordHasher sha384 = CreateWrapper(V1Algorithm.SHA384);
PasswordHasher sha512 = CreateWrapper(V1Algorithm.SHA512);

PasswordHasher? WrapperFor(string storedHash) => storedHash.Length switch
{
    >= 48 and <= 64 => sha256,
    >= 72 and <= 88 => sha384,
    >= 92 and <= 108 => sha512,
    _ => null,
};

foreach (User user in usersWithV1Hashes) // rows the login hasher's Inspect reports as "v1"
{
    PasswordHasher? wrapper = WrapperFor(user.PasswordHash);
    if (wrapper is not null && wrapper.TryWrap(user.PasswordHash, out string wrapped))
    {
        user.PasswordHash = wrapped;
    }
}

static PasswordHasher CreateWrapper(V1Algorithm algorithm)
{
    PasswordHasherOptions options = new PasswordHasherOptions(); // set DefaultProfile and Pepper as on the login hasher
    options.LegacyFormats.Clear();
    options.LegacyFormats.Add(new V1LegacyFormat(algorithm));
    return new PasswordHasher(options);
}
```

Each wrapper registers only one explicit v1 format, so the `Inspect` filter matters here too.

**From the command line.** The `masterly-hash wrap` command does the same for a CSV export, streaming and in parallel, with one algorithm for the whole file:

```bash
masterly-hash audit users.csv --column 2 --header
masterly-hash wrap users.csv users-wrapped.csv --column 2 --header --v1-algorithm SHA512
```

Without `--v1-algorithm`, v1 hashes are copied unchanged. See [Command-Line Tool](./command-line-tool.md).

Wrapped hashes verify through the normal `Verify`. They report `RehashReason.Wrapped`, so each one becomes a plain Argon2id hash the next time its user logs in.

## How 1.x hashes are recognized

`PasswordHasherOptions.LegacyFormats` contains `V1LegacyFormat.Instance` by default, so 1.x hashes work with no configuration. Its id is `v1`. It claims a stored value when the value is:

- canonical, padded standard base64, exactly as `Convert.ToBase64String` writes it,
- 44 to 1024 characters long, decoding to at least 32 bytes,
- not made of hex digits only (a hex digest is valid base64 too, and is left to the unsalted digest formats).

`V1LegacyFormat.Instance` verifies with SHA-512, SHA-384 and SHA-256, in that order, against the raw UTF-8 password with no normalization, as 1.x did. `new V1LegacyFormat(algorithm)` restricts verification to one algorithm and enables wrapping.

Because the rule is broad, the v1 format also matches ASP.NET Identity hashes. If you migrate Identity hashes in the same table, register the Identity formats with `AddLegacyFormats` or `AddAllLegacyFormats`, which insert them ahead of v1. See [Format order and overlaps](./legacy-formats.md#format-order-and-overlaps).

If the table holds no 1.x hashes, remove the format with `options.LegacyFormats.Clear()` (then add any formats you do need).

## Behaviour changes

| Area | 1.x | 2.x |
|---|---|---|
| Algorithm | Salted SHA-256/384/512 | Argon2id (`2026a`) by default |
| Normalization | Raw UTF-8 | NFKC, then UTF-8, for new hashes. 1.x hashes still verify against the raw password |
| Empty password | Hashed | `Hash` throws `ArgumentException`; `Verify` fails with `EmptyPassword` |
| Invalid UTF-16 (lone surrogate) | Silently became U+FFFD | `Hash` throws `ArgumentException`; `Verify` fails with `InvalidPassword` |
| Length | Unlimited | 1024 UTF-8 bytes by default (`MaxPasswordBytes`, 64 to 1,048,576). `Verify` fails with `PasswordTooLong` |
| Malformed or wrong-algorithm hash in `Verify` | Threw | `Hash.Verify` returns `false`; `PasswordHasher.Verify` fails with a `FailureReason` and never throws for a bad stored hash |
| Comparison | String equality | Constant-time |
| Concurrency | Unbounded | At most `MaxConcurrency` hashes at once (default: processor count). A call that waits longer than `ConcurrencyTimeout` (30 seconds) throws `PasswordHasherBusyException`; map it to HTTP 503 |
| DI | `IHash` was `IScopedDependency` (Masterly.DependencyInjection) | Register `PasswordHasher` as a singleton, or use `AddMasterlyHash` from `Masterly.Hash.DependencyInjection` |
| Target frameworks | `netstandard2.0` | `net8.0` (.NET 8 and later) |

Three of these affect existing users:

- **Users with an empty 1.x password** cannot log in after the upgrade. Ask them to reset it.
- **Users with a password over 1024 UTF-8 bytes** fail with `PasswordTooLong`. Raise `MaxPasswordBytes` during the migration if you allowed such passwords.
- **A password that fits the limit as raw UTF-8 but not after NFKC** still logs in, but `Rehash` is `null` and the 1.x hash stays in place.

## The 1.x API in 2.x

The obsolete types remain so existing code compiles. They still produce fast, single-pass hashes that are not suitable for passwords.

| Member | 2.x behaviour |
|---|---|
| `Hash.ComputeHash(plainText, hash)` | Same format as 1.x. The salt is now 16 bytes from a CSPRNG (1.x used 4 to 15 non-zero bytes). |
| `Hash.ComputeHash(plainText, string salt, hash)` | Same as 1.x: the salt is the UTF-8 of the string. Throws `ArgumentNullException` for a `null` salt. |
| `Hash.ComputeHash(plainText, byte[] saltBytes, hash)` | Same as 1.x. Throws `ArgumentNullException` for a `null` plaintext or salt. |
| `Hash.Verify(plainText, hashValue, hash)` | Constant-time. Checks only the given algorithm. Returns `false` for a `null`, malformed or wrong-algorithm `hashValue` instead of throwing. |

Do not write new 1.x hashes. Every one you create needs migrating again.

## Timing note

Verifying a 1.x hash takes microseconds (5.4 µs measured), while Argon2id takes about 170 ms. Response time therefore reveals which accounts still hold a 1.x hash. Wrapping (Step 5) removes that signal and the cracking exposure at the same time.

## Checklist

1. Upgrade to 2.x on .NET 8 or later and deal with the CS0618 warnings.
2. Switch login to `Verify` / `VerifyAsync` and store `Rehash`.
3. Switch registration and password changes to `Hash` / `HashAsync`.
4. Size the password column for at least 256 characters.
5. [Audit](./auditing-hash-tables.md) the table to count `v1` rows.
6. Wrap the `v1` rows whose algorithm you know.
7. Keep `V1LegacyFormat` registered until the audit shows no `v1` rows and no `w=v1` wrapped rows.

## See also

- [Upgrade on Login](./upgrade-on-login.md): how `Rehash` and `RehashReason` work.
- [Onion Wrapping](./onion-wrapping.md): protect dormant accounts offline.
- [Legacy Hash Formats](./legacy-formats.md): migrate hashes from other systems in the same table.
- [Analyzers](./analyzers.md): MH0006 flags the remaining 1.x calls.
- [Migration guide on GitHub](https://github.com/a7mdfre7at/Masterly.Hash/blob/master/docs/MIGRATION-1x.md)
- [CHANGELOG](https://github.com/a7mdfre7at/Masterly.Hash/blob/master/CHANGELOG.md)
