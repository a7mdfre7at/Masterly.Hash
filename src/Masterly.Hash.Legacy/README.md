# Masterly.Hash.Legacy

The universal hash migrator for [Masterly.Hash](https://www.nuget.org/packages/Masterly.Hash). Point it at
a password table from another system and your users keep logging in. Each successful login replaces the old hash
with an Argon2id Masterly hash. You can also onion-wrap weak hashes offline today, without waiting for anyone to
log in.

| Format | Id | Examples | Wrappable |
|---|---|---|---|
| `BCryptFormat` | `bcrypt` | `$2a$`/`$2b$`/`$2y$` from PHP, Spring, Devise, BCrypt.Net | yes |
| `WordPressBcryptFormat` | `wordpress-bcrypt` | `$wp$2y$…` from WordPress 6.8+ | yes |
| `ExternalArgon2Format` | `argon2-phc` | `$argon2id$v=19$m=…,t=…,p=…$…` from libsodium, argon2-cffi, PHP | no (already strong) |
| `PhpassFormat` | `phpass` | `$P$` WordPress before 6.8, `$H$` phpBB3 | yes |
| `DjangoPbkdf2Format` | `django-pbkdf2` | `pbkdf2_sha256$…`, `pbkdf2_sha1$…` | yes |
| `AspNetIdentityV3Format` | `aspnet-identity-v3` | ASP.NET Core Identity (`AQAAAA…`) | yes |
| `AspNetIdentityV2Format` | `aspnet-identity-v2` | ASP.NET Identity 2 / MVC 5 (`AA…`) | yes |
| `UnsaltedDigestFormat.Md5`/`.Sha1`/`.Sha256`/`.Sha512` | `md5`, `sha1`, `sha256`, `sha512` | hex of `H(password)` | yes |

It targets `net8.0` and depends on BCrypt.Net-Next and Konscious.Security.Cryptography.Argon2.

## Install

```
dotnet add package Masterly.Hash.Legacy
```

## Upgrade on login

```csharp
using Masterly.Hash;
using Masterly.Hash.Legacy;

var hasher = new PasswordHasher(new PasswordHasherOptions().AddAllLegacyFormats());
// or only what you have: .AddLegacyFormats(BCryptFormat.Default, PhpassFormat.Default)
// custom caps win over the defaults: .AddLegacyFormats(new BCryptFormat(12)).AddAllLegacyFormats()

PasswordVerificationResult result = hasher.Verify(password, user.PasswordHash);
if (result.IsMatch && result.Rehash is { } fresh)
    user.PasswordHash = fresh;          // now $mh$p=2026a$…
```

Verification never throws for a bad stored value. An unrecognized or malformed hash fails with
`FailureReason = UnknownFormat` (or `Mismatch` if the built-in 1.x format claims it; see the security notes).

## Onion-wrap weak hashes now

Unsalted MD5 or 1000-iteration PBKDF2 should not wait months for every user to log in. Wrapping computes
`Argon2id(legacyDigest)` offline, without the password. The wrapped hash still verifies with the original password
and is replaced with a plain hash on the next login.

```csharp
foreach (var user in db.Users)
    if (hasher.TryWrap(user.PasswordHash, out string wrapped))
        user.PasswordHash = wrapped;    // $mh$p=2026a,w=md5$…
```

Keep the format registered for as long as wrapped hashes exist.

## Audit a password table

```csharp
HashAuditReport report = HashAudit.Audit(hasher, db.Users.Select(u => u.PasswordHash));
Console.WriteLine(report.ToMarkdown());
```

The audit reads the input in a single streaming pass and never throws on garbage rows. It reports counts by
format and by profile, how many hashes are recognized, unknown or need a rehash, and how many are weak (unsalted
digests, 1.x, phpass, Identity v2, bcrypt below cost 10, PBKDF2 below 100k iterations). It also counts duplicate
values, which usually mean unsalted hashes.

## Security notes

- **Cost caps.** Legacy strings carry their own cost, so an attacker who can write a row could otherwise
  plant a hash that takes hours to verify. Each format refuses costs above a configurable cap without any
  hashing: bcrypt and WordPress bcrypt cost <= 15 (`new BCryptFormat(maxCost)`), phpass log2 <= 18, Django
  <= 10,000,000 iterations, Identity v3 <= 10,000,000 PBKDF2 block iterations (iterations times output blocks,
  so a 64-byte HMAC-SHA1 subkey counts four times), and Argon2 m <= 256 MiB (configurable up to 1 GiB),
  t <= 10, p <= 16. phpass and WordPress also refuse passwords over 4096 bytes, as upstream does, because
  phpass cost grows with the password length.
- **Argon2 memory.** Each concurrent Argon2 verify allocates `m` KiB, up to `MaxConcurrency` at once. Size
  `new ExternalArgon2Format(maxMemoryKiB, …)` to the host; a failed allocation is reported as a non-match.
- **Refused strings may still be claimed by the 1.x format.** The built-in `V1LegacyFormat` accepts any
  canonical base64 of 32+ bytes, so an Identity v3 hash this package refuses (over the cap, odd salt or subkey
  length) is reported as `v1`: `Inspect` and `HashAudit` count it as a recognized, weak `v1` hash and `Verify`
  returns `Mismatch`. Do not run a bulk `TryWrap` with an explicit-algorithm `V1LegacyFormat` registered while
  such hashes exist: it would wrap them as `w=v1` and those users could never log in again. Raise the cap first.
- **bcrypt truncates passwords at 72 bytes** (UTF-8). Until the hash is upgraded, any password with the same
  first 72 bytes logs in. The upgrade happens on the first successful login. WordPress `$wp$` hashes pre-hash
  with HMAC-SHA384 and are not truncated.
- **Passwords are hashed as raw UTF-8**, exactly as the original systems did, with no Unicode normalization.
  New Masterly hashes use NFKC.
- All comparisons are constant-time, and secret buffers are zeroed after use.
- Weak formats only ever verify. Nothing in this package creates a new MD5, phpass or bcrypt hash.
- Strings are parsed strictly: canonical base64, exact lengths and no leading zeros. `$2x$`, Argon2 version 16
  and Argon2 strings with secret or associated-data parameters are not handled.
