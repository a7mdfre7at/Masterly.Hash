---
title: "The $mh$ Hash Format"
sidebar_label: "Hash Format"
description: "The specification of the $mh$ string that Masterly.Hash stores, with test vectors, for independent verifiers."
---

This page specifies the hash strings that Masterly.Hash 2.x stores, version 1 of the `$mh$` format. It is complete enough for an independent implementation, for example a Node, Python or Go verifier, to interoperate. The canonical copy lives in the repository at [docs/spec/FORMAT.md](https://github.com/a7mdfre7at/Masterly.Hash/blob/master/docs/spec/FORMAT.md), and the reference vectors at [docs/spec/test-vectors.json](https://github.com/a7mdfre7at/Masterly.Hash/blob/master/docs/spec/test-vectors.json).

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

## Anatomy of a hash

```text
$mh$p=2026a,k=k1$ICEiIyQlJicoKSorLC0uLw$IM8bu1nJd/KqPgS7hpn0wJNlvaCKcJRwUAv3LjhXQUc
 |   |       |    |                      |
 |   |       |    salt (16 bytes)        tag (32 bytes)
 |   |       pepper key id
 |   profile id
 format marker
```

| Part | Meaning |
|------|---------|
| `$mh$` | The format marker. Every native Masterly.Hash 2.x hash starts with it. |
| `p=` | The profile id. It names a fixed set of KDF parameters compiled into the verifier. |
| `k=` | Optional. The id of the pepper key the password was mixed with. |
| `w=` | Optional. The id of a legacy format, when the hash is an onion-wrapped legacy hash. |
| `wp=` | Optional, only with `w`. The legacy format's public parameters (salt, cost), in base64. |
| salt | The random salt, unpadded standard base64. |
| tag | The KDF output, unpadded standard base64. |

The string carries no cost parameters. That is the central design decision of the format; see [Profiles: parameters are never stored](#profiles-parameters-are-never-stored).

## Grammar

```text
hash        = "$mh$" params "$" salt "$" tag
params      = "p=" profile-id [ ",k=" key-id ] [ ",w=" format-id [ ",wp=" b64 ] ]
salt        = b64
tag         = b64
profile-id  = 1*32( %x61-7A / DIGIT / "-" )      ; ^[a-z0-9][a-z0-9-]{0,31}$
key-id      = 1*32( ALPHA / DIGIT / "-" )        ; ^[A-Za-z0-9-]{1,32}$
format-id   = 1*32( %x61-7A / DIGIT / "-" )      ; ^[a-z0-9][a-z0-9-]{0,31}$
b64         = standard base64 alphabet (A-Z a-z 0-9 + /), no padding, canonical
```

The string follows the [PHC string format](https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md). The whole string MUST NOT exceed 1024 characters.

### Rejection rules

A parser MUST reject the string as malformed if any of the following holds:

- It does not have exactly five `$`-separated fields.
- A parameter is unknown or appears twice.
- The parameters are out of order. The order is `p`, then `k`, then `w`, then `wp`, so each hash has exactly one string form.
- An identifier fails its pattern. The pattern must match the whole identifier: in .NET, Python and Perl regexes `$` also matches before a trailing newline, so anchor with `\z` (Python: `re.fullmatch`) or check each character.
- `wp` appears without `w`.
- A base64 field is padded or contains whitespace.
- A base64 field is non-canonical: its unused trailing bits are not zero, so re-encoding the decoded bytes would not give the same text.

:::note

`p` is required and must come first. The .NET writer omits `wp` when the legacy format's parameter is empty (for example the unsalted digest formats), so `w=md5` with no `wp` is a valid form.

:::

## Profiles: parameters are never stored

`p` names a **profile**, a permanent, immutable set of KDF parameters. Verifiers MUST look the profile up in an allowlist compiled into the verifier. They MUST NOT accept cost parameters from the stored string. A stored string therefore cannot make a verifier allocate unbounded memory or run with a weakened cost. A verifier MUST fail closed on an unknown profile id.

| id | KDF | Parameters | Salt | Tag | .NET field |
|----|-----|------------|------|-----|------------|
| `2026a` | Argon2id v1.3 (RFC 9106) | m = 65536 KiB, t = 3, p = 1; no secret or associated data | 16 bytes | 32 bytes | `HashProfile.Server2026a` (the default) |
| `2026c` | Argon2id v1.3 | m = 19456 KiB, t = 2, p = 1 | 16 bytes | 32 bytes | `HashProfile.Constrained2026a` |
| `2026f` | PBKDF2-HMAC-SHA512 (RFC 8018) | 210,000 iterations | 16 bytes | 64 bytes | `HashProfile.Fips2026a` |

A verifier MUST reject a hash whose decoded salt or tag length differs from the profile's lengths.

Applications MAY register their own profiles under ids that do not collide with built-in ids. A profile id, once used, MUST NOT be reused with different parameters. Stronger built-in parameters ship as a new id, for example `2027a`.

### Custom profiles in .NET

`HashProfile.Argon2id(id, memoryKiB, iterations, parallelism = 1, saltLength = 16, tagLength = 32)` and `HashProfile.Pbkdf2Sha512(id, iterations, saltLength = 16, tagLength = 64)` create custom profiles. They enforce these bounds and throw `ArgumentException` / `ArgumentOutOfRangeException` outside them:

| Parameter | Allowed range |
|-----------|---------------|
| Profile id | `^[a-z0-9][a-z0-9-]{0,31}$` |
| Argon2id memory | `8 × parallelism` to 1,048,576 KiB (`HashProfile.MaxMemoryKiB`, 1 GiB) |
| Argon2id iterations | 1 to 64 |
| Argon2id parallelism | 1 to 16 |
| PBKDF2 iterations | 1 to 10,000,000 |
| Salt length | 16 to 64 bytes |
| Tag length | 16 to 64 bytes |

`PasswordHasher` also refuses to register a profile below the OWASP minimum (`HashProfile.MeetsRecommendedMinimum`: Argon2id with m ≥ 19456 KiB and t ≥ 2, or PBKDF2 with at least 210,000 iterations) unless `PasswordHasherOptions.AllowWeakProfiles` is set, and refuses a second profile with an existing id but different parameters. See [Profiles](./profiles.md).

## KDF input

Let `pw` be the password as a UTF-16 string. Unless the hash is wrapped (see [Onion wrapping](#onion-wrapping-w-wp)):

1. `pw` MUST be well-formed UTF-16, with no unpaired surrogates. Otherwise hashing fails and verification returns "invalid password".
2. `pw` MUST be non-empty.
3. `n = UTF-8(NFKC(pw))`, per NIST SP 800-63B §5.1.1.2. If `n` exceeds the verifier's limit (1024 bytes by default), verification fails without running the KDF.
4. If `k` is present: `input = Pepper(k, n)`. Otherwise `input = n`.

Then `tag = KDF(profile, input, salt)`. The comparison MUST be constant-time.

Masterly.Hash's built-in pepper is `HMAC-SHA256(key[k], n)`. Remote peppers (HashiCorp Vault Transit, AWS KMS GenerateMac, Azure Key Vault) compute HMAC-SHA256 under a key that never leaves the service (Azure Key Vault cannot compute HMACs, so that provider loads the key and computes the HMAC locally). A verifier that does not hold key `k` MUST fail with "unknown pepper key" rather than "mismatch".

:::note

The .NET implementation also treats a password that .NET's NFKC normalization rejects (U+FFFE) as invalid. The 1024-byte limit is `PasswordHasherOptions.MaxPasswordBytes` (64 to 1,048,576). For legacy and wrapped hashes the limit is applied to the raw UTF-8 bytes, because those formats do not normalize.

:::

In .NET, `HashPrimitives.EncodePassword(password)` returns exactly the bytes `n` and `HashPrimitives.DeriveKey(profile, input, salt)` runs the profile's KDF, so you can reproduce each step independently.

## Verification outcomes

`PasswordHasher.Verify` never throws for a bad stored hash. It reports the reason in `PasswordVerificationResult.FailureReason`. An independent verifier should distinguish the same cases.

| Condition, checked in this order | `VerificationFailureReason` |
|----------------------------------|-----------------------------|
| Stored hash is null or empty | `NoStoredHash` |
| Password is empty | `EmptyPassword` |
| Password is not well-formed UTF-16, or cannot be normalized | `InvalidPassword` |
| String starts with `$mh$` but breaks a rule in [Grammar](#grammar) | `MalformedHash` |
| Profile id is not in the allowlist | `UnknownProfile` |
| Salt or tag length differs from the profile | `MalformedHash` |
| `k` names a key the verifier does not hold | `UnknownPepperKey` |
| `w` names a format the verifier does not implement | `UnknownFormat` |
| Password exceeds the byte limit | `PasswordTooLong` |
| Tag does not match | `Mismatch` |
| String does not start with `$mh$` and no legacy format claims it | `UnknownFormat` |

These reasons are for logs and metrics only. Show the user the same message for every failure.

## Rehash signals

A successful verification SHOULD report that the hash needs a rehash, and why, when any of these holds, in this priority order:

1. The hash is wrapped (`w` present). In .NET: `RehashReason.Wrapped`.
2. Its profile is not the verifier's current default: `RehashReason.OutdatedProfile`.
3. The verifier has a pepper and `k` differs from the pepper's current key id, or `k` is absent: `RehashReason.OutdatedPepperKey`.

Legacy, non-`$mh$` hashes that verify are always flagged for rehash (`RehashReason.LegacyFormat`). See [Upgrade on login](./upgrade-on-login.md).

## Onion wrapping (w, wp)

A legacy hash can be upgraded **without the password** by running the profile KDF over the legacy digest:

```text
input = Pepper?(k, LegacyDigest(format w, pw, wp))
```

`wp` carries whatever the legacy format needs to recompute its digest from a password, typically its salt and cost. A verifier MUST fail with "unknown format" for a `w` it does not implement.

For `w=v1` (Masterly.Hash 1.x), `wp = alg || salt`, where `alg` is 0 for SHA-256, 1 for SHA-384 and 2 for SHA-512, and `LegacyDigest = SHA-x(UTF-8(pw) || salt)`. The v1 digest uses the raw password, as 1.x did, with no NFKC step.

Formats from the `Masterly.Hash.Legacy` package define their own layouts:

| `w` | Legacy digest | `wp` |
|-----|---------------|------|
| `v1` | `SHA-x(UTF-8(pw) \|\| salt)` | algorithm byte (0, 1, 2), then the 1.x salt |
| `bcrypt` | the 31-character bcrypt hash part, ASCII | the 29-character `$2b$12$<salt>` prefix, ASCII |
| `wordpress-bcrypt` | the 31-character bcrypt hash part, ASCII | the 29-character `$2y$10$<salt>` prefix without `$wp`, ASCII |
| `phpass` | the 22-character hash part, ASCII | the 12-character setting (`$P$`, count and salt), ASCII |
| `django-pbkdf2` | the decoded PBKDF2 hash | algorithm byte (0 = SHA-1, 1 = SHA-256), iterations (4 bytes, big-endian), salt |
| `aspnet-identity-v3` | the PBKDF2 subkey | the stored header and salt, then one byte holding the subkey length |
| `aspnet-identity-v2` | the 32-byte PBKDF2-HMAC-SHA1 subkey | the 16-byte salt |
| `md5`, `sha1`, `sha256`, `sha512` | the decoded digest | empty (omitted) |
| `argon2-phc` | never wrapped | not applicable |

For a `v1` hash, wrapping requires a `V1LegacyFormat` constructed with an explicit `V1Algorithm`, because 1.x did not record the algorithm. See [Onion wrapping](./onion-wrapping.md).

## Test vectors

Each vector in [test-vectors.json](https://github.com/a7mdfre7at/Masterly.Hash/blob/master/docs/spec/test-vectors.json) was produced by Masterly.Hash 2.0.0 `HashPrimitives.DeriveKey` and verified with `PasswordHasher.Verify`, then checked independently against the reference C Argon2 (via argon2-cffi) and Python's `hashlib`. Every vector lists `kdfInputHex`, so you can test the KDF separately from normalization and peppering.

| Name | Profile | What it tests |
|------|---------|---------------|
| `argon2id-default` | `2026a` | The default Argon2id profile. |
| `argon2id-constrained` | `2026c` | The constrained Argon2id profile. |
| `pbkdf2-fips` | `2026f` | PBKDF2-HMAC-SHA512 with a 64-byte tag. |
| `nfkc-normalization` | `2026c` | Input is `UTF-8(NFKC(pw))`: `ﬁＡ² Café` (with a combining accent) becomes `fiA2 Café` with a precomposed `é`. |
| `pepper-hmac` | `2026a` | `input = HMAC-SHA256(pepperKey, n)` with key bytes `0x40..0x5f` (32 bytes) under id `k1`. |
| `onion-wrapped-v1` | `2026c` | A wrapped 1.x SHA-256 hash: `wp` = `0x00` then the salt `SomeSalt#$%`; input = `SHA-256(UTF-8(pw) \|\| salt)` with no NFKC. |

The first vector, in full. `passwordUtf16` lists the password's UTF-16 code units, so the input is unambiguous whatever your editor does to the text:

```json title="docs/spec/test-vectors.json (excerpt)"
{
  "name": "argon2id-default",
  "note": "Profile 2026a: Argon2id v1.3, m=65536 KiB, t=3, p=1, 32-byte tag. No secret/associated data.",
  "password": "correct horse battery staple",
  "passwordUtf16": "0063 006F 0072 0072 0065 0063 0074 0020 0068 006F 0072 0073 0065 0020 0062 0061 0074 0074 0065 0072 0079 0020 0073 0074 0061 0070 006C 0065",
  "kdfInputHex": "636f727265637420686f727365206261747465727920737461706c65",
  "profile": "2026a",
  "saltHex": "000102030405060708090a0b0c0d0e0f",
  "tagHex": "0d1a3c6523c8f06e4e0af9c515aa5b5448cfebd6838f2d52c3d8b6ef8ddc3c2e",
  "hash": "$mh$p=2026a$AAECAwQFBgcICQoLDA0ODw$DRo8ZSPI8G5OCvnFFapbVEjP69aDjy1Sw9i2743cPC4"
}
```

The wrapped vector shows the full parameter list:

```text
$mh$p=2026c,w=v1,wp=AFNvbWVTYWx0IyQl$MDEyMzQ1Njc4OTo7PD0+Pw$I0rrq6cxTDjhQbHKyLdcoVmvfPnHMWf9y67vYizhp68
```

:::tip

`Masterly.Hash.Testing.KnownHashes` exposes the same sample hashes as constants (`Server2026a`, `Constrained2026a`, `Fips2026a`) next to deliberately broken ones (`UnknownProfile`, `Malformed`, `UnknownFormat`), so a test suite can cover every outcome. See [Testing](./testing.md).

:::

## Interoperability checklist

- Reject every malformed form listed in [Rejection rules](#rejection-rules). The vectors include only valid hashes, so add your own negative tests.
- Use the profile table; never parse cost parameters.
- NFKC, then UTF-8. Reject unpaired surrogates. Reject empty passwords.
- Use constant-time tag comparison.
- Pass every vector in `test-vectors.json`.

## Related string formats

Other packages in the family store strings that are not `$mh$` hashes. None of them carries cost parameters a reader would trust.

| Package | Format |
|---------|--------|
| Masterly.Hash.Detection (honeywords) | `$mhw$p=<profileId>[,k=<pepperKeyId>]$<salt>$<tag1>,...,<tagk>`. Each tag is `KDF(profile, input, salt)` with `input = UTF-8(NFKC(sweetword))`, or `Pepper(k, UTF-8(NFKC(sweetword)))` when `k` is present; all sweetwords share one salt. |
| Masterly.Hash.BlindIndex | `<keyId>:<b64(Trunc(HMAC-SHA256(key, message), OutputBits))>`, with domain tags `masterly-blind-index/v1` and `masterly-blind-index-compound/v1`. |
| Masterly.Hash.Tokens (API key) | `<prefix>_<base62 random><base62 CRC-32, 6 chars>`. |
| Masterly.Hash.Tokens (lookup hash) | `<keyId>:<base64 HMAC-SHA256(lookupKey, UTF-8(apiKey))>`. |
| Masterly.Hash.Tokens (signed token) | base64url of `version(1) \| keyIdLength(1) \| keyId \| SHA-256(purpose)(32) \| issuedAt(8) \| expiresAt(8) \| nonce(16) \| subjectLength(2) \| subject \| HMAC-SHA256 tag(32)`. |
| Masterly.Hash.Integrity (content hash) | `sha256:<lowercase hex>`, or `hmac-sha256:<keyId>:<lowercase hex>` for keyed hashes. |

Details are on [Attack detection](./attack-detection.md), [Blind indexes](./blind-indexes.md), [API keys and tokens](./api-keys-and-tokens.md) and [Integrity](./integrity.md).

## See also

- [Profiles](./profiles.md)
- [Peppers](./peppers.md)
- [Onion wrapping](./onion-wrapping.md)
- [Legacy formats](./legacy-formats.md)
- [Threat model](./threat-model.md)
