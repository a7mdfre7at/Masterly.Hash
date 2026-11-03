# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses [Semantic Versioning](https://semver.org/).

## [2.0.0] - 2026-11-03

A ground-up rewrite. 1.x hashes keep verifying and are upgraded automatically; see the [migration guide](docs/MIGRATION-1x.md).

### Added: core (`Masterly.Hash`)

- `Password.Hash` / `Password.Verify`, and the thread-safe `PasswordHasher` with sync and async APIs.
- Argon2id (RFC 9106) by default. Dated, allowlisted profiles: `2026a` (m=64 MiB, t=3), `2026c` (m=19 MiB, t=2) and `2026f` (PBKDF2-HMAC-SHA512, 210k iterations). Cost parameters are never read from stored strings.
- The `$mh$` PHC-style format, with a [specification](docs/spec/FORMAT.md) and [test vectors](docs/spec/test-vectors.json).
- Upgrade on login: `PasswordVerificationResult.Rehash` is computed in the same call, and `RehashReason` reports why (legacy format, wrapped, outdated profile, outdated pepper key).
- `VerifyOrDummy`, for user-enumeration resistance.
- A concurrency gate with `PasswordHasherBusyException`.
- Input limits: `MaxPasswordBytes`, plus NFKC normalization.
- Peppers with key rotation (`IPasswordPepper`, `HmacPepper`).
- `ILegacyHashFormat`, onion wrapping (`TryWrap`), and `Inspect` / `NeedsRehash`.
- `SensitiveString` for request models, which redacts in `ToString`, the debugger and JSON.
- A `System.Diagnostics.Metrics` meter, `Masterly.Hash`.
- `HashPrimitives`, shared low-level building blocks.
- Targets `net8.0` and is AOT-compatible.

### Added: satellite packages

- `Masterly.Hash.Legacy`: bcrypt, ASP.NET Identity v2/v3, Django PBKDF2, phpass, unsalted MD5/SHA-x and Argon2 PHC formats, each with cost caps. Also `HashAudit` reports.
- `Masterly.Hash.DependencyInjection`: `AddMasterlyHash`, configuration binding and startup validation.
- `Masterly.Hash.AspNetCore`: the Identity `IPasswordHasher<TUser>` adapter, 503 mapping for a busy hasher, and password-length validation.
- `Masterly.Hash.EntityFrameworkCore`: hashed-password columns and blind-index columns.
- `Masterly.Hash.Policy`: a NIST SP 800-63B rev. 4 policy and a zxcvbn-style estimator.
- `Masterly.Hash.Pwned`: Have I Been Pwned k-anonymity breach checks.
- `Masterly.Hash.Pepper.HashiCorpVault`, `.AwsKms` and `.AzureKeyVault`: remote and managed peppers.
- `Masterly.Hash.Detection`: honeywords, honey accounts and credential-stuffing detection.
- `Masterly.Hash.Tokens`: checksummed API keys with lookup hashes, and signed, expiring tokens.
- `Masterly.Hash.BlindIndex`: searchable HMAC indexes for encrypted columns.
- `Masterly.Hash.Integrity` and `.Integrity.Blake3`: content hashes, RFC 9162 Merkle trees, hash chains and directory manifests.
- `Masterly.Hash.Analyzers`: rules MH0001–MH0006, with code fixes.
- `Masterly.Hash.Testing`: a fast hasher, a recording decorator, a fake pepper and assertions.
- `Masterly.Hash.Tool`: the `masterly-hash` CLI (`hash`, `verify`, `inspect`, `audit`, `wrap`, `bench`, `policy`, `pepper`, `apikey`).

### Added: documentation and branding

- A documentation site at [a7mdfre7at.github.io/Masterly.Hash](https://a7mdfre7at.github.io/Masterly.Hash/), built from `website/` and deployed to GitHub Pages by the `Docs` workflow. It covers every package, with guides, real-world examples, the API reference, the `$mh$` format and the threat model. The docs are versioned: `2.0` is the released line, and `website/docs` is the unreleased "Next" line.
- The password-cracking playground moved from `docs/playground/` to the site, at `/playground/`.
- A new logo: a hash sign whose top bar dips into an M. Light and dark README banners, a social preview and usage rules are in [assets/](assets/BRAND.md).
- Every package uses the new icon (`assets/icon.png`), which replaces `repo_image.png`.

### Changed

- **Breaking:** every package targets `net8.0` (.NET 8 and later). The `netstandard2.0` target, and with it support for .NET Framework, is removed; stay on 1.x there. (`Masterly.Hash.Analyzers` remains `netstandard2.0`, as Roslyn requires, and works in any project.)
- The 1.x `Hash`, `IHash` and `SupportedHash` types are `[Obsolete]`.
- `Hash.Verify` is now constant-time and returns `false` instead of throwing when given the wrong algorithm.
- `ComputeHash` without a salt now uses a 16-byte CSPRNG salt.
- `IHash` no longer implements `IScopedDependency`, and the `Masterly.DependencyInjection.Abstraction` dependency is removed.
- Empty passwords, and passwords with unpaired surrogates or U+FFFE (which Unicode normalization rejects), are rejected by `Hash`. `Verify` fails them with `EmptyPassword` / `InvalidPassword`.
- A legacy password that exceeds `MaxPasswordBytes` only after NFKC still logs in, but `Rehash` is null.

### Measured cost

AMD Ryzen 9 7950X, .NET 10, single thread, median of 15 runs:

| Profile | Hash | Verify | Allocated |
|---|---:|---:|---:|
| 2026a | 170.6 ms | 176.9 ms | 64.3 MiB |
| 2026c | 35.1 ms | 33.1 ms | 19.2 MiB |
| 2026f | 80.2 ms | 81.5 ms | <0.1 MiB |

A 1.x hash verifies in 5.4 µs, or 184 ms including its rehash to `2026a`. `HmacPepper` adds 0.7 µs.

## [1.0.0] - 2021

- Initial release: salted SHA-256/384/512 hashing.
