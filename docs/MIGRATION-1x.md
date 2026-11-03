# Migrating from Masterly.Hash 1.x

Masterly.Hash 1.x stored `base64(SHA-2(UTF-8(password) || salt) || salt)`. That is one fast hash, which a single GPU can attack at billions of guesses per second. Version 2 replaces it with Argon2id and migrates your users without forcing anyone to reset a password.

## Step 1: upgrade the package (no code changes needed)

```
dotnet add package Masterly.Hash --version 2.*
```

Old code still compiles. `Hash`, `IHash` and `SupportedHash` are marked `[Obsolete]`, with two fixes:

- `Verify` is now **constant-time**.
- `Verify` **no longer throws** when it is handed the wrong algorithm. It returns `false`.

`ComputeHash` without a salt now draws its 16-byte salt from a CSPRNG.

> The `Masterly.Hash.Analyzers` package flags every remaining 1.x call (MH0006) and offers a fix.

## Step 2: switch login to the new API

```csharp
// Before (1.x)
bool ok = hash.Verify(password, user.PasswordHash, SupportedHash.SHA512);

// After (2.x)
var result = Password.Verify(password, user.PasswordHash);
if (result.IsMatch && result.Rehash is { } fresh)
{
    user.PasswordHash = fresh;   // now $mh$p=2026a$…, Argon2id
    await db.SaveChangesAsync();
}
bool ok = result.IsMatch;
```

You don't need to know which SHA-2 variant produced a 1.x hash. The v1 verifier tries SHA-512, SHA-384 and SHA-256, all in constant time. Registration and password changes call `Password.Hash(password)`.

Only `Verify` changes. The 1.x and v2 hashes can live in the same column. A default v2 hash is 78 characters and a `2026f` hash 121; peppered and wrapped hashes are longer, and a wrapped one grows with your 1.x salt. Size the column for at least 256 characters, or use unbounded text. The format is capped at 1024.

## Step 3 (recommended): wrap the users who never log in

Upgrade-on-login only reaches active users. Dormant accounts keep their fast SHA-2 hashes until the user returns, and a database leak exposes exactly those accounts. **Onion wrapping** fixes that offline, without the passwords: it stores `Argon2id(SHA-2(password || salt))` in place of the SHA-2 digest.

Wrapping needs the algorithm explicitly. 1.x did not record it, and guessing wrong would lock users out. 1.x defaulted to SHA-512:

```csharp
var options = new PasswordHasherOptions();
options.LegacyFormats[0] = new V1LegacyFormat(V1Algorithm.SHA512); // replaces the auto-detecting default
var hasher = new PasswordHasher(options);

foreach (var user in db.Users.Where(u => !u.PasswordHash.StartsWith("$mh$")))
    if (hasher.TryWrap(user.PasswordHash, out string wrapped))
        user.PasswordHash = wrapped;   // $mh$p=2026a,w=v1,wp=…$…$…
```

The CLI can do the same for a CSV export, streaming and in parallel:

```
masterly-hash audit users.csv --column 2 --header            # what do we have?
masterly-hash wrap users.csv users-wrapped.csv --column 2 --header --v1-algorithm SHA512
```

Wrapped hashes verify through the normal `Verify`. They report `RehashReason.Wrapped`, so each one becomes a plain Argon2id hash the next time its user logs in.

If your 1.x code used more than one algorithm, wrap only the rows you know. The rest still verify through auto-detection.

## Behaviour changes to be aware of

| Area | 1.x | 2.x |
|---|---|---|
| Algorithm | Salted SHA-256/384/512 | Argon2id (`2026a`) by default |
| Normalization | Raw UTF-8 | NFKC, then UTF-8, for new hashes. v1 hashes still verify against the raw password |
| Empty password | Hashed | `Hash` throws; `Verify` fails with `EmptyPassword` |
| Invalid UTF-16 (lone surrogate) | Silently became U+FFFD | `Hash` throws; `Verify` fails with `InvalidPassword` |
| Length | Unlimited | 1024 UTF-8 bytes by default (`MaxPasswordBytes`) |
| Wrong algorithm in `Verify` | Threw | Returns `false` |
| DI | `IHash` was `IScopedDependency` (Masterly.DependencyInjection) | Register `PasswordHasher` as a singleton, or use `Masterly.Hash.DependencyInjection` |
| Target frameworks | netstandard2.0 | net8.0 (.NET 8 and later; .NET Framework is no longer supported) |

## Timing note

Verifying a 1.x hash takes microseconds, while Argon2id takes about 170 ms. Response time therefore reveals which accounts still hold a legacy hash. Wrapping (step 3) removes that signal and the cracking exposure at the same time.
