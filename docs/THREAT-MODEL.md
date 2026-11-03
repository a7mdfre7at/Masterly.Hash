# Threat model

This document lists what Masterly.Hash defends against, how it does so, and what is out of scope. The packages are noted in brackets where they are not the core.

## Assets

- **User passwords**, which are often reused on other sites.
- **Stored password hashes**: the database column.
- **Pepper keys and token/index keys**.
- **Availability** of the login endpoint.

## Adversaries and defenses

### A1: an offline attacker with a copy of the database

This is the primary threat. A backup leaks, SQL injection dumps the users table, or an insider copies it.

| Defense | Effect |
|---|---|
| Argon2id, m=64 MiB, t=3 (`2026a`) | Each guess costs about 170 ms of CPU time and 64 MiB of memory. Memory-hardness limits GPU and ASIC parallelism (RFC 9106). |
| 16-byte random salt per hash | No rainbow tables. Every user must be attacked separately. |
| Pepper (`HmacPepper`, or [Pepper.HashiCorpVault] / [Pepper.AwsKms], where the key never leaves the service) | Without the pepper key, the leaked hashes cannot be tested at all. |
| Onion wrapping (`TryWrap`, `masterly-hash wrap`) | Legacy fast hashes are protected **today**, not only after each user logs in again. |
| Honeywords [Detection] | A cracked hash usually yields a decoy. A login with a decoy alerts the separate honeychecker that the database leaked. |
| Breach and policy checks [Policy, Pwned] | They remove the passwords that are tried first. No hash function protects `123456`. |

**Residual risk.** A weak password, an unpeppered hash and a determined attacker together still mean the password gets cracked eventually. The [playground](playground/index.html) shows roughly how long that takes.

### A2: an attacker who can write to the hash column

Examples are SQL injection with UPDATE rights, a compromised admin tool, or a malicious migration.

- **The profile allowlist.** The stored string never carries cost parameters, so a forged `m=4194304` cannot make `Verify` allocate 4 GiB, and a forged `t=1` cannot downgrade anything. Unknown profiles fail closed. [Legacy] formats that do read costs from the string (bcrypt, PBKDF2, external Argon2) cap them, and refuse hashes over the cap without doing any work.
- **Strict parsing.** Canonical base64 and canonical parameter order are required, and the length is capped at 1024. Each hash has exactly one string form.
- **Out of scope.** Such an attacker can simply replace the hash with one for a password they know. Detecting that is the job of database auditing, not of a hash library.

### A3: an online attacker at the login endpoint

| Defense | Effect |
|---|---|
| `VerifyOrDummy(password, storedHashOrNull)` | An unknown user costs the same Argon2 work as a known one, so timing does not reveal which accounts exist. |
| Concurrency gate (`MaxConcurrency`, default `ProcessorCount`) and `PasswordHasherBusyException` → 503 [AspNetCore] | A login flood cannot run hundreds of 64 MiB derivations at once and exhaust memory. |
| `MaxPasswordBytes` (1024) and the password-length endpoint filter [AspNetCore] | Megabyte-sized passwords are rejected before any hashing. |
| Credential-stuffing detection [Detection] | Flags one password tried across many accounts. |
| Constant-time comparison | Leaves no timing oracle on the tag. |

**Out of scope.** Rate limiting and account lockout belong to your web stack, for example ASP.NET Core rate limiting or a WAF.

**Known leak.** A legacy hash (1.x, MD5 and similar) verifies in microseconds, and its response time reveals that the account has not migrated. Wrap legacy hashes to remove the signal.

### A4: the attacker reads process memory or logs

- Secrets are zeroed after use: encoded passwords, KDF input, tags, pepper outputs. In .NET this is **best effort**. `string` passwords are immutable and may be copied by the GC.
- `SensitiveString` returns `***` from `ToString()`, the debugger view and JSON output, which keeps passwords out of logs and serialized models.
- Analyzer MH0004 [Analyzers] flags passwords passed to loggers. MH0003 flags hard-coded peppers.
- `HmacPepper` and the [Pepper.AzureKeyVault] provider keep keys in process memory. The Vault Transit and KMS providers do not.

### A5: developer mistakes

[Analyzers] MH0001–MH0006 catch at build time:
- MD5 or SHA used on passwords
- `==` comparison of secrets
- hard-coded keys
- logged passwords
- weak PBKDF2 parameters
- the obsolete 1.x API

The defaults (`Password.Hash` / `Password.Verify`) need no configuration to be safe.

## Explicitly out of scope

- Compromise of the running application host. An attacker on the host sees passwords as they arrive.
- Phishing, malware on the client, and transport security. Use TLS.
- PAKE or OPAQUE-style protocols in which the server never sees the password. These are not implemented: hand-rolled versions are unsafe, and there is no audited .NET implementation to build on.
- Formal certification (FIPS 140-3). The `2026f` profile uses only NIST-approved primitives, through the platform's crypto (`Rfc2898DeriveBytes` on .NET 8+). Certification depends on your OS crypto module, not on this library.
- An independent security audit. None has happened yet. See [SECURITY.md](../SECURITY.md).
