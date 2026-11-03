# The `$mh$` hash format, version 1

This document specifies the hash strings that Masterly.Hash 2.x stores. It aims to be complete enough for an independent implementation, for example a Node, Python or Go verifier, to interoperate. [`test-vectors.json`](test-vectors.json) holds the reference vectors. Each was produced by Masterly.Hash, then checked independently against the reference C Argon2 (via argon2-cffi) and Python's `hashlib`.

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

## 1. Grammar

```
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

A parser MUST reject the string, as malformed, if any of the following holds:

- It does not have exactly five `$`-separated fields.
- A parameter is unknown or appears twice.
- The parameters are out of order. The order is `p`, then `k`, then `w`, then `wp`, so each hash has exactly one string form.
- An identifier fails its pattern. The pattern must match the whole identifier: in .NET, Python and Perl regexes `$` also matches before a trailing newline, so anchor with `\z` (Python: `re.fullmatch`) or check each character.
- `wp` appears without `w`.
- A base64 field is padded or contains whitespace.
- A base64 field is non-canonical: its unused trailing bits are not zero, so re-encoding the decoded bytes would not give the same text.

## 2. Profiles: parameters are never stored

`p` names a **profile**, a permanent, immutable set of KDF parameters. Verifiers MUST look the profile up in an allowlist compiled into the verifier. They MUST NOT accept cost parameters from the stored string. A stored string therefore cannot make a verifier allocate unbounded memory or run with a weakened cost. A verifier MUST fail closed on an unknown profile id.

| id | KDF | Parameters | Salt | Tag |
|---|---|---|---|---|
| `2026a` | Argon2id v1.3 (RFC 9106) | m = 65536 KiB, t = 3, p = 1; no secret or associated data | 16 bytes | 32 bytes |
| `2026c` | Argon2id v1.3 | m = 19456 KiB, t = 2, p = 1 | 16 bytes | 32 bytes |
| `2026f` | PBKDF2-HMAC-SHA512 (RFC 8018) | 210,000 iterations | 16 bytes | 64 bytes |

A verifier MUST reject a hash whose decoded salt or tag length differs from the profile's lengths.

Applications MAY register their own profiles under ids that do not collide with built-in ids. A profile id, once used, MUST NOT be reused with different parameters. Stronger built-in parameters ship as a new id, for example `2027a`.

## 3. KDF input

Let `pw` be the password as a UTF-16 string. Unless the hash is wrapped (§5):

1. `pw` MUST be well-formed UTF-16, with no unpaired surrogates. Otherwise hashing fails and verification returns "invalid password".
2. `pw` MUST be non-empty.
3. `n = UTF-8(NFKC(pw))`, per NIST SP 800-63B §5.1.1.2. If `n` exceeds the verifier's limit (1024 bytes by default), verification fails without running the KDF.
4. If `k` is present: `input = Pepper(k, n)`. Otherwise `input = n`.

Masterly.Hash's built-in pepper is `HMAC-SHA256(key[k], n)`. Remote peppers (HashiCorp Vault Transit, AWS KMS GenerateMac, Azure Key Vault) compute HMAC-SHA256 under a key that never leaves the service. A verifier that does not hold key `k` MUST fail with "unknown pepper key" rather than "mismatch".

Then `tag = KDF(profile, input, salt)`. The comparison MUST be constant-time.

## 4. Rehash signals

A successful verification SHOULD report that the hash needs a rehash, and why, when any of these holds, in this priority order:

1. The hash is wrapped (`w` present).
2. Its profile is not the verifier's current default.
3. The verifier has a pepper and `k` differs from the pepper's current key id, or `k` is absent.

Legacy, non-`$mh$` hashes that verify are always flagged for rehash.

## 5. Onion wrapping (`w`, `wp`)

A legacy hash can be upgraded **without the password** by running the profile KDF over the legacy digest:

```
input = Pepper?(k, LegacyDigest(format w, pw, wp))
```

`wp` carries whatever the legacy format needs to recompute its digest from a password, typically its salt and cost. For `w=v1` (Masterly.Hash 1.x), `wp = alg || salt`, where `alg` is 0 for SHA-256, 1 for SHA-384 and 2 for SHA-512, and `LegacyDigest = SHA-x(UTF-8(pw) || salt)`. The v1 digest uses the raw password, as 1.x did, with no NFKC step. Formats from the `Masterly.Hash.Legacy` package define their own `wp` layouts. A verifier MUST fail with "unknown format" for a `w` it does not implement.

## 6. Interoperability checklist

- [ ] Reject every malformed form listed in §1. The vectors include only valid hashes, so add your own negative tests.
- [ ] Use the profile table; never parse cost parameters.
- [ ] NFKC, then UTF-8. Reject unpaired surrogates. Reject empty passwords.
- [ ] Use constant-time tag comparison.
- [ ] Pass every vector in `test-vectors.json`. Each vector lists `kdfInputHex`, so you can test the KDF separately from normalization and peppering.
