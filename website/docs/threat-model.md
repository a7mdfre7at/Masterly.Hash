---
title: "Threat Model"
sidebar_label: "Threat Model"
description: "What Masterly.Hash defends against, how it does so, what is out of scope, and how to report a vulnerability."
---

This page lists what Masterly.Hash defends against, how it does so, and what is out of scope. Packages other than the core are named in brackets, for example [Detection]. The canonical copy is [docs/THREAT-MODEL.md](https://github.com/a7mdfre7at/Masterly.Hash/blob/master/docs/THREAT-MODEL.md) in the repository.

## Assets

| Asset | Why it matters |
|-------|----------------|
| User passwords | They are often reused on other sites. |
| Stored password hashes | The database column an attacker wants. |
| Pepper keys and token/index keys | With them, leaked hashes and indexes can be tested offline. |
| Availability of the login endpoint | Password hashing is deliberately expensive, which makes it a denial-of-service target. |

## Adversaries at a glance

| Adversary | Primary defenses | Residual risk or out of scope |
|-----------|------------------|-------------------------------|
| [A1](#a1-an-offline-attacker-with-a-copy-of-the-database) Offline attacker with a copy of the database | Argon2id, per-hash salt, pepper, onion wrapping, honeywords, breach and policy checks | Weak, unpeppered passwords still fall eventually |
| [A2](#a2-an-attacker-who-can-write-to-the-hash-column) Attacker who can write to the hash column | Profile allowlist, capped legacy costs, strict parsing | Replacing a hash outright |
| [A3](#a3-an-online-attacker-at-the-login-endpoint) Online attacker at the login endpoint | `VerifyOrDummy`, concurrency gate, length limits, stuffing detection, constant-time comparison | Rate limiting and lockout; legacy-hash timing leak |
| [A4](#a4-the-attacker-reads-process-memory-or-logs) Attacker who reads process memory or logs | Zeroing, `SensitiveString`, analyzers, remote peppers | Immutable .NET strings |
| [A5](#a5-developer-mistakes) Developer mistakes | Analyzers MH0001 to MH0006, safe defaults | None listed |

## A1: an offline attacker with a copy of the database

This is the primary threat. A backup leaks, SQL injection dumps the users table, or an insider copies it.

| Defense | Effect |
|---------|--------|
| Argon2id, m = 64 MiB, t = 3 (`2026a`) | Each guess costs about 125 ms of CPU time and 64 MiB of memory. Memory-hardness limits GPU and ASIC parallelism (RFC 9106). |
| 16-byte random salt per hash | No rainbow tables. Every user must be attacked separately. |
| Pepper (`HmacPepper`, or [Pepper.HashiCorpVault] / [Pepper.AwsKms], where the key never leaves the service) | Without the pepper key, the leaked hashes cannot be tested at all. |
| Onion wrapping (`TryWrap`, `masterly-hash wrap`) | Legacy fast hashes are protected **today**, not only after each user logs in again. |
| Honeywords [Detection] | A cracked hash usually yields a decoy. A login with a decoy alerts the separate honeychecker that the database leaked. |
| Breach and policy checks [Policy, Pwned] | They remove the passwords that are tried first. No hash function protects `123456`. |

**Residual risk.** A weak password, an unpeppered hash and a determined attacker together still mean the password gets cracked eventually. The [playground](https://a7mdfre7at.github.io/Masterly.Hash/playground/) shows roughly how long that takes.

What to do:

- Keep the default profile unless the host cannot afford 64 MiB per login; see [Profiles](./profiles.md) and [Performance](./performance.md).
- Add a pepper, and keep its key outside the database: [Peppers](./peppers.md), [HashiCorp Vault](./hashicorp-vault.md), [AWS KMS](./aws-kms.md), [Azure Key Vault](./azure-key-vault.md).
- Wrap legacy hashes now rather than waiting for logins: [Onion wrapping](./onion-wrapping.md), [Auditing hash tables](./auditing-hash-tables.md).
- Reject guessable and breached passwords at sign-up: [Password policy](./password-policy.md), [Breach checking](./breach-checking.md).

## A2: an attacker who can write to the hash column

Examples are SQL injection with UPDATE rights, a compromised admin tool, or a malicious migration.

- **The profile allowlist.** The stored string never carries cost parameters, so a forged `m=4194304` cannot make `Verify` allocate 4 GiB, and a forged `t=1` cannot downgrade anything. Unknown profiles fail closed with `VerificationFailureReason.UnknownProfile`. [Legacy] formats that do read costs from the string (bcrypt, PBKDF2, external Argon2) cap them, and refuse hashes over the cap without doing any work.
- **Strict parsing.** Canonical base64 and canonical parameter order are required, and the length is capped at 1024. Each hash has exactly one string form. See [The $mh$ hash format](./hash-format.md).
- **Out of scope.** Such an attacker can simply replace the hash with one for a password they know. Detecting that is the job of database auditing, not of a hash library.

The default caps on costs read from legacy strings:

| Format | Cap | Default |
|--------|-----|---------|
| `BCryptFormat`, `WordPressBcryptFormat` | `MaxCost` | 15 (`BCryptFormat.DefaultMaxCost`) |
| `PhpassFormat` | `MaxCostLog2` | 18 (262,144 MD5 rounds) |
| `DjangoPbkdf2Format` | `MaxIterations` | 10,000,000 |
| `AspNetIdentityV3Format` | `MaxIterations` (iterations times PRF blocks) | 10,000,000 |
| `ExternalArgon2Format` | `MaxMemoryKiB`, `MaxIterations`, `MaxParallelism` | 256 MiB, 10, 16 |

A hash above its cap is not handled by the format at all, so it reports as an unknown format and costs nothing to reject. See [Legacy formats](./legacy-formats.md).

## A3: an online attacker at the login endpoint

| Defense | Effect |
|---------|--------|
| `VerifyOrDummy(password, storedHashOrNull)` | An unknown user costs the same Argon2 work as a known one, so timing does not reveal which accounts exist. |
| Concurrency gate (`MaxConcurrency`, default `ProcessorCount`) and `PasswordHasherBusyException` → 503 [AspNetCore] | A login flood cannot run hundreds of 64 MiB derivations at once and exhaust memory. |
| `MaxPasswordBytes` (1024) and the password-length endpoint filter [AspNetCore] | Megabyte-sized passwords are rejected before any hashing. |
| Credential-stuffing detection [Detection] | Flags one password tried across many accounts. |
| Constant-time comparison | Leaves no timing oracle on the tag. |

**Out of scope.** Rate limiting and account lockout belong to your web stack, for example ASP.NET Core rate limiting or a WAF.

:::warning Known leak

A legacy hash (1.x, MD5 and similar) verifies in microseconds, and its response time reveals that the account has not migrated. Wrap legacy hashes to remove the signal.

:::

What to do:

- Call `VerifyOrDummy` (or `VerifyOrDummyAsync`) for every login, passing `null` when the user does not exist: [User enumeration](./user-enumeration.md).
- Map `PasswordHasherBusyException` to 503 with `AddMasterlyHashExceptionHandler()`, and put `.WithPasswordLengthLimit()` on login endpoints: [Limits and concurrency](./limits-and-concurrency.md).
- Feed failed logins to `CredentialStuffingDetector`: [Attack detection](./attack-detection.md).

## A4: the attacker reads process memory or logs

- Secrets are zeroed after use: encoded passwords, KDF input, tags, pepper outputs. In .NET this is **best effort**. `string` passwords are immutable and may be copied by the GC.
- `SensitiveString` returns `***` from `ToString()`, the debugger view and JSON output, which keeps passwords out of logs and serialized models.
- Analyzer MH0004 [Analyzers] flags passwords passed to loggers. MH0003 flags hard-coded peppers.
- `HmacPepper` and the [Pepper.AzureKeyVault] provider keep keys in process memory. The Vault Transit and KMS providers do not.

## A5: developer mistakes

[Analyzers] MH0001 to MH0006 catch these at build time:

| Id | Catches |
|----|---------|
| MH0001 | MD5 or SHA used on passwords |
| MH0002 | `==` comparison of secrets |
| MH0003 | Hard-coded keys |
| MH0004 | Logged passwords |
| MH0005 | Weak PBKDF2 parameters |
| MH0006 | The obsolete 1.x API |

The defaults (`Password.Hash` / `Password.Verify`) need no configuration to be safe. See [Analyzers](./analyzers.md).

## Explicitly out of scope

- Compromise of the running application host. An attacker on the host sees passwords as they arrive.
- Phishing, malware on the client, and transport security. Use TLS.
- PAKE or OPAQUE-style protocols in which the server never sees the password. These are not implemented: hand-rolled versions are unsafe, and there is no audited .NET implementation to build on.
- Formal certification (FIPS 140-3). The `2026f` profile uses only NIST-approved primitives, through the platform's crypto (`Rfc2898DeriveBytes` on .NET 8+). Certification depends on your OS crypto module, not on this library.
- An independent security audit. None has happened yet.

## Security policy

The full policy is [SECURITY.md](https://github.com/a7mdfre7at/Masterly.Hash/blob/master/SECURITY.md).

### Supported versions

| Version | Supported |
|---------|-----------|
| 2.x | Security fixes |
| 1.x | Not supported. Upgrade to 2.x. 1.x hashes keep verifying and migrate automatically ([Upgrading from 1.x](./upgrading-from-1x.md)). |

### Reporting a vulnerability

:::danger

Do not open a public issue. Report privately through GitHub's [private vulnerability reporting](https://github.com/a7mdfre7at/Masterly.Hash/security/advisories/new).

:::

Include:

- the affected package and version
- a minimal reproduction, such as a failing input, a stored hash, or a code snippet
- the impact as you understand it

You will get an acknowledgement within 7 days. The maintainers aim to release a fix within 90 days and coordinate disclosure with you. Credit is given in the advisory unless you prefer otherwise.

### Scope

In scope:

- Every package in this repository.
- The `$mh$` format ([specification](./hash-format.md)).
- Weaknesses in a built-in profile's parameters.

Especially welcome:

- ways to make `Verify` throw, hang or allocate excessively from a stored string
- timing differences that reveal tag bytes
- canonicalization bypasses, where two strings verify as one hash
- pepper or key material leaking into outputs, exceptions or logs

### What the project does

- The test suite includes known-answer vectors from RFC 9106, RFC 6070, RFC 7914 and NIST, plus differential tests against reference implementations and FsCheck property-based fuzzing of every parser.
- Releases are built in CI from the master commit that passed the Build workflow, published to NuGet through Trusted Publishing (no stored API key), and carry SourceLink, an SBOM and GitHub build-provenance attestations.
- Dependencies are kept current by Dependabot and checked by CodeQL and OpenSSF Scorecard.

No independent third-party audit has been done yet.

## See also

- [The $mh$ hash format](./hash-format.md)
- [How it works](./how-it-works.md)
- [User enumeration](./user-enumeration.md)
- [Limits and concurrency](./limits-and-concurrency.md)
- [Attack detection](./attack-detection.md)
