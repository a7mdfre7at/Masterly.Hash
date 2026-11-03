---
title: Legacy Hash Formats
sidebar_label: Legacy Formats
description: Verify bcrypt, ASP.NET Identity, Django, phpass, WordPress, external Argon2 and raw MD5/SHA hashes, and replace each with Argon2id on the next login.
---

This page explains how to point Masterly.Hash at a password table from another system. Users keep logging in with their existing passwords, and each successful login replaces the old hash with an Argon2id `$mh$` hash. The formats live in the `Masterly.Hash.Legacy` package. Masterly.Hash 1.x hashes are covered by the core package and are described in [Upgrading from 1.x](./upgrading-from-1x.md).

Legacy formats only ever **verify**. Nothing in `Masterly.Hash.Legacy` creates a new bcrypt, phpass, PBKDF2 or MD5 hash.

## Install

```bash
dotnet add package Masterly.Hash.Legacy
```

The package targets `net8.0` and depends on `Masterly.Hash`, BCrypt.Net-Next and Konscious.Security.Cryptography.Argon2.

## Register the formats

Legacy formats are registered on `PasswordHasherOptions.LegacyFormats`. Use the extension methods from `LegacyHashFormatOptionsExtensions` rather than editing the list by hand:

```csharp title="Program.cs"
using Masterly.Hash;
using Masterly.Hash.Legacy;

// Every format, with its default cost caps.
PasswordHasher hasher = new PasswordHasher(new PasswordHasherOptions().AddAllLegacyFormats());

// Only the formats you actually have.
PasswordHasher bcryptOnly = new PasswordHasher(
    new PasswordHasherOptions().AddLegacyFormats(BCryptFormat.Default, PhpassFormat.Default));

// Custom caps first, then the defaults for everything else.
PasswordHasher tuned = new PasswordHasher(
    new PasswordHasherOptions()
        .AddLegacyFormats(new BCryptFormat(12), new PhpassFormat(14))
        .AddAllLegacyFormats());
```

The two methods behave as follows:

| Method | Behaviour |
|---|---|
| `AddLegacyFormats(params ILegacyHashFormat[] formats)` | Adds the given formats. Adding an instance that is already registered does nothing. Adding a **different** instance with an id that is already registered, or the same id twice in one call, throws `ArgumentException` ("A different legacy format with id 'bcrypt' is already registered."). A `null` entry throws `ArgumentException` ("Formats cannot contain null."). The call is all-or-nothing: when it throws, the options are unchanged. |
| `AddAllLegacyFormats()` | Adds every format in `LegacyFormats.All` with default settings, skipping any id that is already registered. Formats registered earlier win, so custom caps can be combined with the defaults. |

Both methods insert the new formats **ahead of** the built-in 1.x format (`V1LegacyFormat`), which is in `LegacyFormats` by default. That order matters; see [Format order and overlaps](#format-order-and-overlaps).

`LegacyFormats.All` is a read-only list of the default instances, in this order: `bcrypt`, `wordpress-bcrypt`, `argon2-phc`, `phpass`, `django-pbkdf2`, `aspnet-identity-v3`, `aspnet-identity-v2`, `md5`, `sha1`, `sha256`, `sha512`.

The `PasswordHasher` constructor copies the list and validates it. It throws `ArgumentException` when the list contains `null`, when an id does not match `^[a-z0-9][a-z0-9-]{0,31}$`, or when two formats share an id.

## Supported formats

| Class | Id | Example stored value | Typical source | Wrappable |
|---|---|---|---|---|
| `BCryptFormat` | `bcrypt` | `$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW` (also `$2b$`, `$2y$`) | PHP `password_hash`, Spring Security, Devise, BCrypt.Net, node.bcrypt | Yes |
| `WordPressBcryptFormat` | `wordpress-bcrypt` | `$wp$2y$10$` + 22-char salt + 31-char hash | WordPress 6.8 and later | Yes |
| `ExternalArgon2Format` | `argon2-phc` | `$argon2id$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc` (also `$argon2i$`, `$argon2d$`) | libsodium, argon2-cffi, PHP, node-argon2, Spring Security | No (already strong) |
| `PhpassFormat` | `phpass` | `$P$9IQRaTwmfeRo7ud9Fh4E2PdI0S3r.L0`, `$H$9IQRaTwmfeRo7ud9Fh4E2PdI0S3r.L0` | WordPress before 6.8 (`$P$B`), phpBB3 (`$H$`), Drupal 7 imports | Yes |
| `DjangoPbkdf2Format` | `django-pbkdf2` | `pbkdf2_sha256$10000$seasalt$CWWFdHOWwPnki7HvkcqN9iA2T3KLW1cf2uZ5kvArtVY=`, `pbkdf2_sha1$10000$seasalt$oAfF6vgs95ncksAhGXOWf4Okq7o=` | Django | Yes |
| `AspNetIdentityV3Format` | `aspnet-identity-v3` | `AQAAAAIAAYagAAAAE...` (HMAC-SHA512, 100,000 iterations), `AQAAAAEAACcQAAAAE...` (HMAC-SHA256, 10,000 iterations) | ASP.NET Core Identity `PasswordHasher<TUser>` | Yes |
| `AspNetIdentityV2Format` | `aspnet-identity-v2` | 68 base64 characters starting with `A` | ASP.NET Identity 2.x, MVC 5, `System.Web.Helpers.Crypto.HashPassword`, `IdentityV2` compatibility mode | Yes |
| `UnsaltedDigestFormat.Md5` | `md5` | `5f4dcc3b5aa765d61d8327deb882cf99` | Hand-rolled `md5(password)` | Yes |
| `UnsaltedDigestFormat.Sha1` | `sha1` | `5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8` | Hand-rolled `sha1(password)` | Yes |
| `UnsaltedDigestFormat.Sha256` | `sha256` | `5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8` | Hand-rolled `sha256(password)` | Yes |
| `UnsaltedDigestFormat.Sha512` | `sha512` | 128 hex characters | Hand-rolled `sha512(password)` | Yes |
| `V1LegacyFormat` (core package) | `v1` | Canonical padded base64, 44 or more characters | Masterly.Hash 1.x | Only with an explicit algorithm |

"Wrappable" means the format supports [onion wrapping](./onion-wrapping.md): the hash can be protected with Argon2id offline, without the password.

The syntaxes of the formats in `LegacyFormats.All` do not overlap: every sample above is claimed by exactly one of them. Only the built-in `v1` format overlaps, with the two ASP.NET Identity formats.

### bcrypt

`BCryptFormat` verifies `$2a$`, `$2b$` and `$2y$` hashes: exactly 60 characters, a two-digit cost, a 22-character salt and a 31-character hash in bcrypt's alphabet. Verification uses BCrypt.Net-Next.

- **Cost cap.** The cost (log2 of the rounds) comes from the stored string, so it is capped by `MaxCost`. The default is `BCryptFormat.DefaultMaxCost` = 15. `new BCryptFormat(maxCost)` accepts 4 (`MinCost`) to 31 (`HardMaxCost`) and throws `ArgumentOutOfRangeException` outside that range. A hash above the cap is not handled at all: it reports as an unknown format and costs nothing to reject.
- **72-byte truncation.** bcrypt reads only the first 72 bytes of the UTF-8 password. Until the hash is upgraded, any password with the same first 72 bytes logs in. The upgrade happens on the first successful login.
- **Not supported:** `$2x$` (the crypt_blowfish sign-extension bug mode).

### WordPress bcrypt

`WordPressBcryptFormat` verifies the hashes WordPress 6.8 and later write: `$wp` followed by `password_hash(base64(HMAC-SHA384(key: "wp-sha384", password)), PASSWORD_BCRYPT)`. The stored value is 63 characters, for example `$wp$2y$10$...`.

- The SHA-384 pre-hash means the whole password counts, not just its first 72 bytes.
- Passwords longer than `WordPressBcryptFormat.MaxPasswordBytes` (4096 UTF-8 bytes) never match, as in WordPress's `wp_check_password`.
- The password is used as given. WordPress trims surrounding whitespace when it creates a hash, but not when it checks one, and neither does this format.
- The bcrypt cost is capped by `MaxCost`, default 15, configurable with `new WordPressBcryptFormat(maxCost)` in the same 4 to 31 range as `BCryptFormat`.

Older WordPress `$P$` hashes are handled by `PhpassFormat`. Plain `$2y$` hashes written by a `password_hash` plugin are handled by `BCryptFormat`.

### External Argon2 (PHC strings)

`ExternalArgon2Format` verifies Argon2 PHC strings from other libraries: `$argon2id$v=19$m=<KiB>,t=<iterations>,p=<lanes>$<salt>$<hash>`, and the same with `$argon2i$` or `$argon2d$`. Salt and hash are unpadded base64. Salts must decode to 8 to 64 bytes and hashes to 4 to 128 bytes.

The cost parameters come from the stored string, so all three are capped:

| Property | Default | Constructor range |
|---|---|---|
| `MaxMemoryKiB` | `DefaultMaxMemoryKiB` = 262,144 (256 MiB) | 8 to 1,048,576 (1 GiB) |
| `MaxIterations` | `DefaultMaxIterations` = 10 | 1 to 64 |
| `MaxParallelism` | `DefaultMaxParallelism` = 16 | 1 to 16 |

```csharp title="Program.cs"
// Accept at most 128 MiB, t = 4 and p = 4 from stored strings.
PasswordHasherOptions options = new PasswordHasherOptions()
    .AddLegacyFormats(new ExternalArgon2Format(maxMemoryKiB: 128 * 1024, maxIterations: 4, maxParallelism: 4))
    .AddAllLegacyFormats();
```

`m` must also be at least `8 * p`. Hashes over a cap are not handled.

Only version 19 (`v=19`) is supported. Strings without `v=` (version 16) and strings with a secret or associated-data parameter are not handled.

:::warning

Each concurrent Argon2 verify allocates `m` KiB, and up to `MaxConcurrency` verifies run at once. With the default 256 MiB cap and 16 cores, a burst of logins against tampered rows could ask for 4 GiB. Size `MaxMemoryKiB` times `MaxConcurrency` to the host. If the allocation fails anyway, `Verify` reports a non-match instead of throwing `OutOfMemoryException`.

:::

These hashes are already strong, so they are never onion-wrapped: `TryExtractWrapInput` returns `false` and `ComputeWrapInput` throws `FormatException`. A successful login still replaces them with a `$mh$` hash, which moves the cost parameters out of the database row.

### phpass

`PhpassFormat` verifies phpass portable hashes: `$P$` (WordPress before 6.8, Drupal 7 imports, many PHP applications) and `$H$` (phpBB3). The value is 34 characters: `$P$`, one count character, an 8-character salt and a 22-character hash. The hash is MD5 iterated 2^count times.

- **Cost cap.** phpass allows a log2 count of 7 to 30. The default cap `PhpassFormat.DefaultMaxCostLog2` is 18 (262,144 MD5 rounds). `new PhpassFormat(maxCostLog2)` accepts 7 (`MinCostLog2`) to 30 (`HardMaxCostLog2`). WordPress writes `$P$B` (2^13 rounds) and phpBB3 writes `$H$9` (2^11), both well under the cap.
- **Password length.** Every round hashes the whole password again, so the cost grows with the password length. Like upstream phpass and WordPress, passwords longer than `PhpassFormat.MaxPasswordBytes` (4096 UTF-8 bytes) never match and are refused before any hashing.
- Iterated MD5 is weak. Onion-wrap these hashes rather than waiting for logins.

### Django PBKDF2

`DjangoPbkdf2Format` verifies `pbkdf2_sha256$<iterations>$<salt>$<base64 hash>` (the Django default) and `pbkdf2_sha1$...`. The hash is PBKDF2-HMAC over the UTF-8 password and the UTF-8 salt, 32 bytes for SHA-256 and 20 bytes for SHA-1.

- **Iteration cap.** `MaxIterations` defaults to `DjangoPbkdf2Format.DefaultMaxIterations` = 10,000,000. `new DjangoPbkdf2Format(maxIterations)` accepts any positive value and throws `ArgumentOutOfRangeException` for 0 or less.
- **Salt.** 1 to 128 printable ASCII characters other than `$`. This covers every salt Django generates.
- The iteration count must be written without leading zeros, signs or whitespace, and with at most 10 digits.

Other Django hashers (`argon2`, `bcrypt_sha256`, `scrypt`) use different syntaxes and are not handled by this format.

### ASP.NET Core Identity v3

`AspNetIdentityV3Format` verifies the default format of `Microsoft.AspNetCore.Identity.PasswordHasher<TUser>`: `base64(0x01 || prf || iterations || saltLength || salt || subkey)`, with big-endian 32-bit header fields. PRF 0 is HMAC-SHA1, 1 is HMAC-SHA256 and 2 is HMAC-SHA512.

- **Work cap.** `MaxIterations` defaults to `AspNetIdentityV3Format.DefaultMaxIterations` = 10,000,000 and caps the total PBKDF2 work, not just the iteration count. PBKDF2 runs one full iteration chain per PRF output block, so a hash costs `iterations * ceil(subkeyLength / prfOutputLength)`. A 64-byte subkey over HMAC-SHA1 counts four times. Microsoft writes 32-byte subkeys, which is one block for HMAC-SHA256 and HMAC-SHA512.
- **Salt and subkey lengths.** Salts must be 8 to 256 bytes (Microsoft writes 16) and subkeys 16 to 64 bytes (Microsoft writes 32).
- `new AspNetIdentityV3Format(maxIterations)` accepts any positive value. If you never raised Identity's `IterationCount` far above its default of 100,000, a tighter cap such as `new AspNetIdentityV3Format(1_000_000)` limits the work a tampered row can force.

`AddMasterlyPasswordHasher` in the [ASP.NET Core Identity](./aspnetcore-identity.md) integration registers both Identity formats for you (through `AddAspNetIdentityFormats`, which also inserts ahead of `v1`).

### ASP.NET Identity v2

`AspNetIdentityV2Format.Instance` verifies `base64(0x00 || salt[16] || PBKDF2-HMAC-SHA1(password, salt, 1000 iterations)[32])`: exactly 68 base64 characters that decode to 49 bytes with a leading zero byte. It has no settings, so there is only the shared `Instance`.

1000 iterations of SHA-1 is weak by current standards. Onion-wrap these hashes so accounts that never log in are protected too.

### Unsalted digests

`UnsaltedDigestFormat` verifies `hex(H(UTF-8(password)))` in either case. The string length decides the algorithm:

| Instance | Id | Length (hex characters) | `DigestLength` (bytes) |
|---|---|---|---|
| `UnsaltedDigestFormat.Md5` | `md5` | 32 | 16 |
| `UnsaltedDigestFormat.Sha1` | `sha1` | 40 | 20 |
| `UnsaltedDigestFormat.Sha256` | `sha256` | 64 | 32 |
| `UnsaltedDigestFormat.Sha512` | `sha512` | 128 | 64 |

:::danger

Unsalted digests can be reversed with precomputed tables in seconds, and identical passwords have identical hashes. Onion-wrap them as soon as the format is registered. Do not wait for each user to log in.

:::

Salted digests (`md5(salt + password)` and similar) are not covered. Write a [custom format](#writing-your-own-format) for them.

## How verification works

`Verify` and `VerifyAsync` handle legacy hashes in the same call as native ones. For a stored value that does not start with `$mh$`:

1. **Pre-checks.** An empty stored value fails with `NoStoredHash`, an empty password with `EmptyPassword`, and an ill-formed password (an unpaired surrogate) with `InvalidPassword`. A `null` password throws `ArgumentNullException`.
2. **Candidate formats.** Every registered format whose `CanHandle` returns `true` is a candidate. `CanHandle` is a cheap syntactic check and does no hashing. If no format claims the value, verification fails with `UnknownFormat`.
3. **Length check.** If the password's raw UTF-8 length exceeds `MaxPasswordBytes` (default 1024), verification fails with `PasswordTooLong` before any hashing.
4. **Verify.** The hasher takes one concurrency slot and tries each candidate in order until one matches. An exception from a format's `Verify` counts as a non-match; only `OperationCanceledException` and `OutOfMemoryException` propagate.
5. **Result.** A mismatch fails with `Mismatch`. A match returns `SuccessRehashNeeded` with `RehashReason.LegacyFormat`, and `Rehash` holds a fresh `$mh$` hash with the default profile and current pepper key.

Store `Rehash` and the user is migrated:

```csharp title="LoginService.cs"
PasswordVerificationResult result = await hasher.VerifyAsync(password, user.PasswordHash, cancellationToken);
if (result.IsMatch && result.Rehash is string fresh)
{
    user.PasswordHash = fresh; // now $mh$p=2026a$...
    await db.SaveChangesAsync(cancellationToken);
}
```

`Rehash` is `null` when `ComputeRehashOnVerify` is `false`, or when the password fits `MaxPasswordBytes` as raw UTF-8 but not after NFKC normalization. In the second case the login succeeds and the legacy hash stays in place. See [Upgrade on Login](./upgrade-on-login.md).

`Inspect` reports a legacy hash with `Format` set to the format id, `IsRecognized` = `true`, `ProfileId` = `null` and `RehashReason.LegacyFormat`. `NeedsRehash` is `true` for every recognized legacy hash.

The verification metric `masterly.hash.verifications` carries a `format` tag with the legacy format id, or `unknown`, so you can watch each format drain to zero. See [Observability](./observability.md).

## Passwords are hashed as raw UTF-8

Legacy formats hash the password exactly as the original systems did: raw UTF-8 bytes, no Unicode normalization. An NFC "Å" and an NFD "Å" are different passwords to an Identity or Django hash, just as they were before. New `$mh$` hashes normalize with NFKC first, so after the upgrade both spellings match.

The same raw length is checked against `MaxPasswordBytes`. If your old system allowed passwords longer than 1024 UTF-8 bytes, raise `MaxPasswordBytes` (64 to 1,048,576) during the migration or those users cannot log in.

Empty passwords never verify, even if the old system accepted them.

## Format order and overlaps

The built-in `V1LegacyFormat` accepts any canonical padded base64 string of 44 or more characters that decodes to 32 or more bytes and is not all hex digits. Both ASP.NET Identity formats match that description. When a value is claimed by several formats:

- `Verify` tries all of them, so a correct password still matches.
- `Inspect` and `HashAudit` report the **first** format that claims the value.
- `TryWrap` wraps with the first format that claims the value **and** can extract a wrap input. The auto-detecting `V1LegacyFormat.Instance` never extracts one, so it is skipped; an explicit-algorithm `V1LegacyFormat` placed first wraps the value as `w=v1`.

`AddLegacyFormats` and `AddAllLegacyFormats` insert ahead of `v1` for exactly this reason. If you add formats to `options.LegacyFormats` directly with `Add`, they land after `v1`, and `Inspect` and `HashAudit` report Identity hashes as `v1`.

:::warning

The dependency injection builder's `AddLegacyFormat(format)` appends to `LegacyFormats`, after `v1`. For the Identity formats, register through the options instead, for example `.Configure(o => o.AddAllLegacyFormats())` or `.Configure(o => o.AddLegacyFormats(AspNetIdentityV3Format.Default))`. See [Dependency Injection](./dependency-injection.md).

:::

A value a format **refuses** can still be claimed by `v1`. An Identity v3 hash over the work cap, or with an odd salt or subkey length, is still canonical base64, so `Inspect` and `HashAudit` count it as a recognized, weak `v1` hash and `Verify` returns `Mismatch`. Raise the cap before relying on those reports. Do not run a bulk wrap with an explicit-algorithm `V1LegacyFormat` registered while such hashes exist: it would wrap them as `w=v1` and those users could never log in again.

If you have no 1.x hashes, you can remove `v1` with `options.LegacyFormats.Clear()` before adding the formats you need.

## Cost caps at a glance

Every format that reads a cost from the stored string refuses costs above a cap, without doing any hashing. Without the caps, an attacker who can write one row could plant a hash that takes hours to verify.

| Format | Cap property | Default | Allowed range |
|---|---|---|---|
| `bcrypt` | `MaxCost` | 15 | 4 to 31 |
| `wordpress-bcrypt` | `MaxCost` | 15 | 4 to 31 |
| `phpass` | `MaxCostLog2` | 18 | 7 to 30 |
| `django-pbkdf2` | `MaxIterations` | 10,000,000 | 1 and up |
| `aspnet-identity-v3` | `MaxIterations` (iterations times output blocks) | 10,000,000 | 1 and up |
| `argon2-phc` | `MaxMemoryKiB`, `MaxIterations`, `MaxParallelism` | 262,144 KiB, 10, 16 | 8 to 1,048,576 KiB, 1 to 64, 1 to 16 |

A refused hash reports `UnknownFormat` (or `Mismatch` if `v1` claims it). Any stored value longer than 1024 characters is rejected by every format before parsing.

## Writing your own format

Implement `ILegacyHashFormat` (namespace `Masterly.Hash.Legacy`, in the core package) for any scheme not listed above. The contract:

| Member | Contract |
|---|---|
| `string Id` | Stable id written into wrapped hashes. Must match `^[a-z0-9][a-z0-9-]{0,31}$`. Never change it once wrapped hashes exist. |
| `bool CanHandle(string storedHash)` | Cheap syntactic check. No hashing. Should not throw; an exception is treated as `false`. |
| `bool Verify(string password, string storedHash)` | Recomputes and compares with a constant-time comparison. Return `false` for a malformed value. |
| `bool TryExtractWrapInput(string storedHash, out byte[] digest, out byte[] parameter)` | For onion wrapping: split the hash into the secret digest and the public parameters (salt, cost) needed to recompute it. Return `false` if the format or this hash cannot be wrapped. |
| `byte[] ComputeWrapInput(string password, byte[] parameter)` | For onion wrapping: recompute the digest from the password and the parameter. For the right password the result must equal the extracted digest exactly. Throw `FormatException` for a bad parameter; it reaches you from the database, so validate it and cap any cost it carries. |

This example handles an in-house scheme stored as `ss256$<32 hex salt>$<64 hex digest>`, where the digest is `SHA-256(salt || UTF-8(password))`:

```csharp title="SaltedSha256Format.cs"
using System;
using System.Security.Cryptography;
using System.Text;
using Masterly.Hash.Legacy;
using Masterly.Hash.Primitives;

namespace MyApp.Security;

/// <summary>Verifies hashes from the old in-house scheme "ss256$hex(salt)$hex(SHA-256(salt || password))".</summary>
public sealed class SaltedSha256Format : ILegacyHashFormat
{
    private const string Prefix = "ss256$";
    private const int SaltLength = 16;
    private const int DigestLength = 32;
    private const int SaltHexStart = 6;
    private const int DigestHexStart = SaltHexStart + (SaltLength * 2) + 1;
    private const int StoredLength = DigestHexStart + (DigestLength * 2);

    public string Id => "salted-sha256";

    public bool CanHandle(string storedHash) => TryParse(storedHash, out _, out _);

    public bool Verify(string password, string storedHash)
    {
        ArgumentNullException.ThrowIfNull(password);
        if (!TryParse(storedHash, out byte[] salt, out byte[] expected))
        {
            return false;
        }

        byte[] actual = ComputeWrapInput(password, salt);
        bool match = HashPrimitives.FixedTimeEquals(expected, actual);
        HashPrimitives.Zero(actual);
        return match;
    }

    public bool TryExtractWrapInput(string storedHash, out byte[] digest, out byte[] parameter) =>
        TryParse(storedHash, out parameter, out digest);

    public byte[] ComputeWrapInput(string password, byte[] parameter)
    {
        ArgumentNullException.ThrowIfNull(password);
        if (parameter is null || parameter.Length != SaltLength)
        {
            throw new FormatException("Invalid salted-sha256 wrap parameter.");
        }

        byte[] plain = Encoding.UTF8.GetBytes(password);
        byte[] data = new byte[SaltLength + plain.Length];
        Buffer.BlockCopy(parameter, 0, data, 0, SaltLength);
        Buffer.BlockCopy(plain, 0, data, SaltLength, plain.Length);
        try
        {
            return SHA256.HashData(data);
        }
        finally
        {
            HashPrimitives.Zero(plain);
            HashPrimitives.Zero(data);
        }
    }

    private static bool TryParse(string storedHash, out byte[] salt, out byte[] digest)
    {
        salt = Array.Empty<byte>();
        digest = Array.Empty<byte>();
        if (storedHash is null
            || storedHash.Length != StoredLength
            || !storedHash.StartsWith(Prefix, StringComparison.Ordinal)
            || storedHash[DigestHexStart - 1] != '$'
            || !IsHex(storedHash.AsSpan(SaltHexStart, SaltLength * 2))
            || !IsHex(storedHash.AsSpan(DigestHexStart, DigestLength * 2)))
        {
            return false;
        }

        salt = Convert.FromHexString(storedHash.AsSpan(SaltHexStart, SaltLength * 2));
        digest = Convert.FromHexString(storedHash.AsSpan(DigestHexStart, DigestLength * 2));
        return true;
    }

    private static bool IsHex(ReadOnlySpan<char> value)
    {
        foreach (char c in value)
        {
            if (!char.IsAsciiHexDigit(c))
            {
                return false;
            }
        }

        return true;
    }
}
```

Register it like a built-in format: `options.AddLegacyFormats(new SaltedSha256Format())`. A format that cannot be wrapped returns `false` from `TryExtractWrapInput` and throws `FormatException` from `ComputeWrapInput`, as `ExternalArgon2Format` does.

## Security notes

- **Weak formats verify fast.** An MD5, phpass or 1.x hash verifies in microseconds, while Argon2id takes about 170 ms. Response time can reveal which accounts still hold a legacy hash. [Onion wrapping](./onion-wrapping.md) removes the signal.
- **Strict parsing.** Strings are parsed strictly: canonical base64, exact lengths, decimal numbers without leading zeros. Garbage and truncated values are rejected without throwing.
- **Constant-time comparisons.** Every format compares digests in constant time and zeroes the buffers that held password bytes or digests.
- **A writable users table is out of scope.** The cost caps limit the work a tampered row can force, but an attacker who can write rows can simply replace a hash with one for a password they know. See the [Threat Model](./threat-model.md).
- **Keep the formats registered** for as long as any row still holds a legacy or wrapped hash. A hash whose format is not registered fails with `UnknownFormat`.

## See also

- [Onion Wrapping](./onion-wrapping.md): protect weak hashes now, without waiting for logins.
- [Auditing Hash Tables](./auditing-hash-tables.md): find out which formats you have before you start.
- [Upgrade on Login](./upgrade-on-login.md): how `Rehash` and `RehashReason` work.
- [ASP.NET Core Identity](./aspnetcore-identity.md): migrate an Identity user store.
- [Masterly.Hash.Legacy README](https://github.com/a7mdfre7at/Masterly.Hash/blob/master/src/Masterly.Hash.Legacy/README.md)
