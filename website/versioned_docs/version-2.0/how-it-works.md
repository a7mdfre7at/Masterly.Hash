---
title: "How It Works"
sidebar_label: "How It Works"
description: "What happens to a password on the way to a stored hash and back, and how the packages fit together."
---

This page follows a password through `Hash` and `Verify`, explains what the stored string contains and why it contains nothing else, and shows how the 18 packages build on the core. Read it once before you configure anything; the rest of the documentation assumes this model.

## The pieces of the core

| Type | Role |
|------|------|
| `Password` | A static class with the two-method API. Every call goes to `PasswordHasher.Default`, a shared hasher built with the default options. |
| `PasswordHasher` | The implementation. Thread-safe; create one per application, or register it as a singleton, and reuse it. |
| `IPasswordHasher` | The interface `PasswordHasher` implements. Inject this, so tests can substitute a fast or recording hasher. |
| `PasswordHasherOptions` | Settings for a hasher: default profile, extra profiles, pepper, legacy formats and limits. The constructor copies them, so later changes have no effect. |
| `HashProfile` | A named, immutable set of KDF parameters, such as `HashProfile.Server2026a` (id `2026a`). |
| `IPasswordPepper` | A server-side secret mixed into every password before hashing. `HmacPepper` is the local implementation. Both are in the `Masterly.Hash.Pepper` namespace. |
| `ILegacyHashFormat` | A read-only format from another system. The hasher verifies it but never produces it. `V1LegacyFormat` (Masterly.Hash 1.x) is registered by default. Both are in the `Masterly.Hash.Legacy` namespace. |
| `PasswordVerificationResult` | What `Verify` returns: match or not, why it failed, whether to rehash, and the replacement hash. |
| `HashInfo` | What `Inspect` returns: a description of a stored hash, without verifying it. |

## What a stored hash contains

A hash produced by Masterly.Hash 2.x is a [PHC-format](https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md) string that starts with `$mh$`:

```text title="Anatomy of a $mh$ hash"
$mh$p=2026a,k=k1$ICEiIyQlJicoKSorLC0uLw$IM8bu1nJd/KqPgS7hpn0wJNlvaCKcJRwUAv3LjhXQUc
 |   |       |    |                      |
 |   |       |    salt (16 bytes)        tag (32 bytes for Argon2id, 64 for PBKDF2)
 |   |       pepper key id (only when a pepper is configured)
 |   profile id
 format marker
```

| Field | Meaning | Rules |
|-------|---------|-------|
| `p` | Profile id. Always present. | `^[a-z0-9][a-z0-9-]{0,31}$` |
| `k` | Pepper key id. Present only when the hash was made with a pepper. | `^[A-Za-z0-9-]{1,32}$` |
| `w` | Legacy format id, for an onion-wrapped hash. | `^[a-z0-9][a-z0-9-]{0,31}$` |
| `wp` | The legacy format's public parameters (salt, cost), for an onion-wrapped hash. Only allowed after `w`. | Unpadded, canonical standard base64 |
| salt | Random bytes, a new value for every hash. | Unpadded, canonical standard base64 |
| tag | The KDF output. | Unpadded, canonical standard base64 |

A native hash is 78 characters for the built-in Argon2id profiles and 121 for the built-in PBKDF2 profile, plus the length of `,k=<key id>` when it is peppered. The parser rejects any string longer than 1024 characters, which is also the most an onion-wrapped hash can use. A column of 1024 characters holds every form.

**The cost parameters are never stored.** The string names a profile, and the verifier looks the profile up in an allowlist compiled into your application. A row in your database therefore cannot make `Verify` allocate 4 GiB of memory, run with one pass, or use an algorithm you did not choose. An id the hasher does not know fails closed with `VerificationFailureReason.UnknownProfile`.

The parser is strict on purpose. `p` is required; each parameter may appear at most once, and only in the order `p`, `k`, `w`, `wp`; base64 must be unpadded and canonical; identifiers must match their pattern exactly. Each hash therefore has exactly one string form. The full grammar is in [Hash Format](./hash-format.md).

## Hashing a password

`Hash(password)` runs these steps:

1. **Validate the input.** A `null` password throws `ArgumentNullException`. An empty password, or one that is not well-formed UTF-16 (an unpaired surrogate) or contains a code point Unicode normalization rejects (U+FFFE), throws `ArgumentException`. Such passwords are rejected rather than silently mangled: lone surrogates would otherwise all encode to U+FFFD, so different passwords would hash the same.
2. **Normalize and encode.** The password is normalized to Unicode NFKC, as NIST SP 800-63B recommends, and encoded as UTF-8. A password typed with a precomposed `é` and one typed as `e` plus a combining accent produce the same bytes.
3. **Enforce the length cap.** If the UTF-8 bytes exceed `MaxPasswordBytes` (default 1024), `Hash` throws `ArgumentException` before any expensive work. This stops attackers from sending megabyte passwords to burn CPU.
4. **Apply the pepper.** If a pepper is configured, the bytes become `Pepper(currentKeyId, bytes)`. For `HmacPepper` that is HMAC-SHA256 under the current key. The key id is recorded in the hash as `k`.
5. **Draw a salt.** A fresh salt of the profile's `SaltLength` (16 bytes for every built-in profile) comes from the OS random number generator.
6. **Wait for a slot.** The hasher allows at most `MaxConcurrency` KDF runs at once (default: the processor count). A call that cannot get a slot within `ConcurrencyTimeout` (default 30 seconds) throws `PasswordHasherBusyException`.
7. **Derive the tag.** The profile's KDF runs: Argon2id (RFC 9106) or PBKDF2-HMAC-SHA512 (RFC 8018).
8. **Clean up and format.** The slot is released, the KDF input and the tag buffers are overwritten with zeros, and the `$mh$` string is returned.

```text title="Hash pipeline"
password ─► validate ─► NFKC ─► UTF-8 ─► length cap ─► pepper? ─► salt ─► wait for slot ─► KDF(profile, salt) ─► $mh$...
```

## Verifying a password

`Verify(password, storedHash)` first decides which format the stored string is in:

- **It starts with `$mh$`**: a native hash. The hasher parses it, looks up the profile in the allowlist, checks that the salt and tag lengths match the profile, checks that it holds the pepper key `k`, and then repeats steps 2, 3, 4, 6 and 7 of hashing with the stored salt instead of a new one. An over-long password fails with `PasswordTooLong` instead of throwing. The computed tag is compared with the stored tag in constant time.
- **Anything else**: the hasher asks each registered legacy format, in order, whether the string looks like its format (`CanHandle`). The formats that say yes try to verify the password, and the first match wins. With the default options only the 1.x format is registered.

A stored hash that is malformed, unknown or unusable never throws. `Verify` returns a failed result whose `FailureReason` says what was wrong: `MalformedHash`, `UnknownFormat`, `UnknownProfile`, `UnknownPepperKey` and so on. Most of these checks run before the KDF, so a garbage row costs almost nothing. Exceptions thrown by a legacy format, which may be third-party code, are treated as "does not match", except `OperationCanceledException` and `OutOfMemoryException`, which always propagate.

The full list of results and failure reasons is in [Hashing and Verifying](./hashing-and-verifying.md#understanding-the-result).

## Upgrade on login

A successful verification also checks whether the stored hash is current. In priority order, it is outdated when:

1. it is onion-wrapped (`RehashReason.Wrapped`);
2. its profile is not the hasher's default profile (`RehashReason.OutdatedProfile`);
3. the hasher has a pepper and the hash was made with a different key, or with no pepper at all (`RehashReason.OutdatedPepperKey`).

A legacy hash that verifies is always outdated (`RehashReason.LegacyFormat`).

When the hash is outdated, and `ComputeRehashOnVerify` is left at its default of `true`, the hasher immediately hashes the password again with the current default profile and pepper key and returns the new string in `PasswordVerificationResult.Rehash`. You store it, and the account is upgraded. This is the only moment the hasher has the plain password, which is why the upgrade happens at login. To upgrade accounts whose users never log in, wrap their hashes offline instead.

Profile ids are permanent. A stronger default ships as a new id in a new package version, for example `2027a`. The old id stays in the allowlist, so old hashes keep verifying and move to the new profile one login at a time. See [Upgrade on Login](./upgrade-on-login.md) and [Profiles](./profiles.md).

## Onion wrapping

A legacy hash, such as an unsalted MD5 or a 1.x SHA-512, can be upgraded without the password. `TryWrap` runs the default profile's KDF over the legacy digest itself and stores the legacy format id and parameters in `w` and `wp`:

```text title="Onion-wrapped hash"
$mh$p=2026c,w=v1,wp=AFNvbWVTYWx0IyQl$MDEyMzQ1Njc4OTo7PD0+Pw$I0rrq6cxTDjhQbHKyLdcoVmvfPnHMWf9y67vYizhp68
```

At login, the hasher recomputes the legacy digest from the password and `wp`, runs the KDF over it, and compares. A wrapped hash that verifies is flagged with `RehashReason.Wrapped`, so the next login replaces it with a plain native hash. See [Onion Wrapping](./onion-wrapping.md).

## Safe under load

Argon2id is deliberately expensive: the default profile allocates 64 MiB for every hash and every verification. Without a limit, a burst of login attempts could allocate gigabytes and take the process down. The hasher therefore holds a `SemaphoreSlim` with `MaxConcurrency` slots. Synchronous calls block their thread while they wait; asynchronous calls wait without holding a thread. When no slot frees up in time, the call throws `PasswordHasherBusyException`, a `TimeoutException`. Map it to HTTP 503 so clients back off. `Masterly.Hash.AspNetCore` does that for you. See [Limits and Concurrency](./limits-and-concurrency.md).

## Secrets in memory

- The encoded password, the peppered input and the computed tag are byte arrays the hasher owns. It overwrites them with zeros as soon as it is done. The KDF input is wiped in a `finally` block, so it is cleared even when the KDF or the concurrency gate throws.
- The password `string` itself cannot be wiped: .NET strings are immutable. To keep it out of logs, take it as a `SensitiveString` in your request models. Its `ToString()`, its debugger display and its JSON output are always `***`.
- Comparisons of secret values use `CryptographicOperations.FixedTimeEquals`, so the time taken does not reveal how many bytes matched.

## Telemetry

The hasher publishes metrics through `System.Diagnostics.Metrics` on the meter named `Masterly.Hash` (`PasswordHasher.MeterName`): a duration histogram, counters for hashes and verifications by profile, format and outcome, and a counter for calls rejected at the concurrency limit. No tag ever contains a password, a hash or a key. See [Observability](./observability.md).

## How the packages fit together

Every package builds on the core. Arrows point from a package to what it references:

```text title="Package references"
Masterly.Hash  (core: Argon2id, PBKDF2, profiles, pepper, v1 format, metrics)
├── Masterly.Hash.Legacy                  bcrypt, Identity, Django, phpass, digests, Argon2 PHC; HashAudit
├── Masterly.Hash.DependencyInjection     AddMasterlyHash(), IConfiguration binding, startup validation
│   └── Masterly.Hash.AspNetCore          Identity IPasswordHasher<TUser>, 503 handler, length filter
│                                         (also references Masterly.Hash.Legacy)
├── Masterly.Hash.BlindIndex              searchable HMAC indexes for encrypted columns
│   └── Masterly.Hash.EntityFrameworkCore hash-on-save interceptor, blind-index columns and queries
├── Masterly.Hash.Pepper.HashiCorpVault   IPasswordPepper backed by Vault Transit
├── Masterly.Hash.Pepper.AwsKms           IPasswordPepper backed by KMS GenerateMac
├── Masterly.Hash.Pepper.AzureKeyVault    IPasswordPepper with keys from Key Vault secrets
├── Masterly.Hash.Policy                  NIST SP 800-63B rules, strength estimation
│   └── Masterly.Hash.Pwned               Have I Been Pwned breach check
├── Masterly.Hash.Tokens                  API keys, signed tokens, secure random strings
├── Masterly.Hash.Integrity               content hashes, Merkle trees, hash chains, manifests
│   └── Masterly.Hash.Integrity.Blake3    BLAKE3 for the Integrity package
├── Masterly.Hash.Detection               honeywords, honey accounts, credential stuffing
├── Masterly.Hash.Testing                 FastPasswordHasher, fakes, assertions
└── Masterly.Hash.Tool                    the masterly-hash command (also uses Legacy, Policy, Pwned, Tokens)

Masterly.Hash.Analyzers                   compile-time checks, no run-time dependency
```

The extension points are small interfaces, so the companion packages plug in without the core knowing about them:

| Extension point | Implemented by |
|-----------------|----------------|
| `IPasswordPepper` | `HmacPepper` (core), `HashiCorpVaultPepper`, `AwsKmsPepper`, `AzureKeyVaultPepper`, `FakePepper` (Testing) |
| `ILegacyHashFormat` | `V1LegacyFormat` (core), the formats in `Masterly.Hash.Legacy` (which `Masterly.Hash.AspNetCore` registers for Identity), your own formats |
| `IPasswordHasher` | `PasswordHasher` (core), `FastPasswordHasher` and `RecordingPasswordHasher` (Testing), your own decorators |
| `HashProfile` | The built-in profiles, and custom profiles from `HashProfile.Argon2id(...)` or `HashProfile.Pbkdf2Sha512(...)` |

## What this design does not protect against

- **An attacker who can write to your users table.** The allowlist stops a row from weakening the KDF, but an attacker with write access can simply replace a hash with one of their own password.
- **Weak passwords.** Argon2id slows guessing down; it does not stop an attacker from trying `password1` first. Use [Password Policy](./password-policy.md) and [Breach Checking](./breach-checking.md) at sign-up.
- **Timing of legacy hashes.** Verifying a legacy hash is much faster than Argon2id, so response timing can show that an account still has one. Migrate quickly, or wrap legacy hashes offline.
- **A leaked pepper.** `HmacPepper` keeps its keys in process memory. Keep them out of the database, or use a key-store pepper so the key never leaves the service.

The full analysis is in the [Threat Model](./threat-model.md).

## See also

- [Hashing and Verifying](./hashing-and-verifying.md)
- [Profiles](./profiles.md)
- [Peppers](./peppers.md)
- [Hash Format](./hash-format.md)
- [Threat Model](./threat-model.md)
