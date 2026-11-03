<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/banner-dark.svg">
  <img alt="Masterly.Hash: password hashing you can't get wrong." src="assets/banner-light.svg" width="100%">
</picture>

**Password hashing you can't get wrong.** It takes two methods, the defaults are safe, and every hash you already have upgrades itself the next time its user logs in.

[![Nuget](https://img.shields.io/nuget/v/Masterly.Hash?style=flat-square)](https://www.nuget.org/packages/Masterly.Hash) [![Documentation](https://img.shields.io/badge/docs-masterly.hash-8217D3?style=flat-square)](https://a7mdfre7at.github.io/Masterly.Hash/) ![Nuget](https://img.shields.io/nuget/dt/Masterly.Hash?style=flat-square) ![GitHub](https://img.shields.io/github/license/a7mdfre7at/Masterly.Hash?style=flat-square) [![Build](https://github.com/a7mdfre7at/Masterly.Hash/actions/workflows/build.yml/badge.svg?branch=master)](https://github.com/a7mdfre7at/Masterly.Hash/actions/workflows/build.yml) [![CodeQL](https://github.com/a7mdfre7at/Masterly.Hash/actions/workflows/codeql.yml/badge.svg?branch=master)](https://github.com/a7mdfre7at/Masterly.Hash/actions/workflows/codeql.yml) [![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/a7mdfre7at/Masterly.Hash/badge)](https://securityscorecards.dev/viewer/?uri=github.com/a7mdfre7at/Masterly.Hash)

```
dotnet add package Masterly.Hash
```

```csharp
using Masterly.Hash;

string stored = Password.Hash("hunter2");          // $mh$p=2026a$<salt>$<tag>

var result = Password.Verify("hunter2", stored);
if (result.IsMatch && result.Rehash is { } fresh)  // only when the stored hash is outdated
    user.PasswordHash = fresh;
```

That is the entire API most applications need.

## Why v2

Masterly.Hash 1.x computed a single salted SHA-2 hash. A modern GPU tests billions of those per second. Version 2 is a ground-up rewrite around the current consensus (RFC 9106, OWASP and NIST SP 800-63B):

- **Argon2id by default**, plus a PBKDF2-HMAC-SHA512 profile for NIST-only environments.
- **Dated profiles instead of knobs.** A stored hash names a profile (`2026a`) and never contains cost parameters. The verifier looks the profile up in a compiled-in allowlist, so a row in your database cannot make `Verify` allocate 4 GiB or run at `t=1`.
- **Upgrade on login.** Hashes from 1.x, from an older profile or under an older pepper key all verify, and the result carries a fresh `Rehash`. [Masterly.Hash.Legacy](src/Masterly.Hash.Legacy) adds the same treatment for bcrypt, ASP.NET Identity, Django, phpass, raw MD5/SHA and external Argon2 hashes.
- **Safe under load and attack:**
  - constant-time comparison
  - secrets zeroed after use
  - NFKC normalization
  - a 1024-byte input cap
  - a concurrency gate, so a login flood cannot exhaust memory
  - `VerifyOrDummy`, which defends against user enumeration
- **Onion wrapping.** `TryWrap` upgrades every weak hash in a table offline, today, without anyone's password.
- **Peppers with rotation:** local HMAC, HashiCorp Vault Transit, AWS KMS or Azure Key Vault.
- **An open format.** The [`$mh$` spec](docs/spec/FORMAT.md) comes with [test vectors](docs/spec/test-vectors.json) that were cross-checked against the reference Argon2 implementation.

## Packages

| Package | What it gives you | Targets |
|---|---|---|
| [**Masterly.Hash**](src/Masterly.Hash) | Core: `Password` / `PasswordHasher`, profiles, upgrade-on-login, pepper, v1 migration, metrics | net8.0 |
| [Masterly.Hash.Legacy](src/Masterly.Hash.Legacy) | Verifies and migrates bcrypt, ASP.NET Identity v2/v3, Django PBKDF2, phpass, MD5/SHA-x and Argon2 PHC hashes; `HashAudit` reports on a hash table | net8.0 |
| [Masterly.Hash.DependencyInjection](src/Masterly.Hash.DependencyInjection) | `services.AddMasterlyHash(...)`: singleton hasher, `IConfiguration` binding, validation at startup | net8.0 |
| [Masterly.Hash.AspNetCore](src/Masterly.Hash.AspNetCore) | Drop-in ASP.NET Core Identity `IPasswordHasher<TUser>` (existing Identity hashes keep working), 503 mapping for a busy hasher, password-length validator and endpoint filter | net8.0 |
| [Masterly.Hash.EntityFrameworkCore](src/Masterly.Hash.EntityFrameworkCore) | `IsHashedPassword()` hashes columns on `SaveChanges`; blind-index columns and `WhereBlindIndex` | net8.0 |
| [Masterly.Hash.Policy](src/Masterly.Hash.Policy) | NIST SP 800-63B rev. 4 password policy and a zxcvbn-style strength estimator | net8.0 |
| [Masterly.Hash.Pwned](src/Masterly.Hash.Pwned) | Have I Been Pwned k-anonymity breach check for the policy | net8.0 |
| [Masterly.Hash.Pepper.HashiCorpVault](src/Masterly.Hash.Pepper.HashiCorpVault) | Pepper computed by Vault Transit; the key never leaves Vault | net8.0 |
| [Masterly.Hash.Pepper.AwsKms](src/Masterly.Hash.Pepper.AwsKms) | Pepper computed by KMS `GenerateMac`; the key never leaves KMS | net8.0 |
| [Masterly.Hash.Pepper.AzureKeyVault](src/Masterly.Hash.Pepper.AzureKeyVault) | Pepper keys loaded from Key Vault secrets, with refresh | net8.0 |
| [Masterly.Hash.Detection](src/Masterly.Hash.Detection) | Honeywords (Juels and Rivest), honey accounts, credential-stuffing detection | net8.0 |
| [Masterly.Hash.Tokens](src/Masterly.Hash.Tokens) | API keys with a checksum and indexable lookup hash; signed, expiring, purpose-bound tokens | net8.0 |
| [Masterly.Hash.BlindIndex](src/Masterly.Hash.BlindIndex) | Searchable HMAC indexes for encrypted PII columns (the CipherSweet pattern) | net8.0 |
| [Masterly.Hash.Integrity](src/Masterly.Hash.Integrity) | Content hashes, RFC 9162 Merkle trees with proofs, tamper-evident hash chains, directory manifests | net8.0 |
| [Masterly.Hash.Integrity.Blake3](src/Masterly.Hash.Integrity.Blake3) | BLAKE3 (plain and keyed) for the Integrity package | net8.0 |
| [Masterly.Hash.Analyzers](src/Masterly.Hash.Analyzers) | Roslyn analyzers with code fixes: fast hash on a password (MH0001), non-constant-time comparison (MH0002), hard-coded pepper (MH0003), logged password (MH0004), weak PBKDF2 (MH0005), obsolete 1.x API (MH0006) | analyzer |
| [Masterly.Hash.Testing](src/Masterly.Hash.Testing) | A fast hasher for tests, a recording decorator, a fake pepper, `MasterlyHashAssert` | net8.0 |
| [Masterly.Hash.Tool](src/Masterly.Hash.Tool) | `masterly-hash` CLI with the commands `hash`, `verify`, `inspect`, `audit`, `wrap`, `bench`, `policy`, `pepper generate` and `apikey generate` | .NET tool |

## Profiles and cost

| Profile | Id | Algorithm | Parameters | Hash time¹ | Memory per hash |
|---|---|---|---|---:|---:|
| `HashProfile.Server2026a` (default) | `2026a` | Argon2id | m=64 MiB, t=3, p=1 | 171 ms | 64 MiB |
| `HashProfile.Constrained2026a` | `2026c` | Argon2id | m=19 MiB, t=2, p=1 | 35 ms | 19 MiB |
| `HashProfile.Fips2026a` | `2026f` | PBKDF2-HMAC-SHA512 | 210,000 iterations | 80 ms | <1 MiB |

¹ Median of 15 runs on an AMD Ryzen 9 7950X with .NET 10, single thread. Run `masterly-hash bench` on your own hardware for a recommendation, or see [perf/](perf/Masterly.Hash.Benchmarks).

Profile ids are permanent. Stronger parameters ship as a new id in a new package version. Old hashes keep verifying and are rehashed at the next login.

## Configuration

```csharp
builder.Services.AddMasterlyHash(o =>
{
    o.DefaultProfile = HashProfile.Constrained2026a;   // e.g. serverless
    o.MaxConcurrency = 8;                              // at most 8 × 19 MiB in flight
})
.WithPepper(HmacPepper.FromBase64("k2", new Dictionary<string, string>
{
    ["k1"] = config["Pepper:k1"],   // old key: still verifies, triggers rehash
    ["k2"] = config["Pepper:k2"],   // current key
}))
.Configure(o => o.AddAllLegacyFormats());   // Masterly.Hash.Legacy: bcrypt, Identity, Django, ...
```

To use ASP.NET Core Identity, call `services.AddIdentity<AppUser, IdentityRole>().AddMasterlyPasswordHasher();`.

## Upgrading from 1.x

1.x hashes keep working with no configuration. Each successful login hands you an Argon2id replacement. The old `Hash`/`IHash` API still compiles but is `[Obsolete]`; its `Verify` is now constant-time and no longer throws when given the wrong algorithm. See [docs/MIGRATION-1x.md](docs/MIGRATION-1x.md), which also explains how to wrap the whole table offline.

## Documentation

The full guide lives at **[a7mdfre7at.github.io/Masterly.Hash](https://a7mdfre7at.github.io/Masterly.Hash/)**: getting started, every package, migration, key management and the API reference.

- [Hash format specification](docs/spec/FORMAT.md) and [test vectors](docs/spec/test-vectors.json): for writing a verifier in another language
- [Threat model](docs/THREAT-MODEL.md): what each feature defends against, and what it doesn't
- [Migrating from 1.x](docs/MIGRATION-1x.md)
- [Analyzer rules](docs/analyzers)
- [Password-cracking playground](https://a7mdfre7at.github.io/Masterly.Hash/playground/): how long a stolen hash survives, per scheme
- [Security policy](SECURITY.md) · [Changelog](CHANGELOG.md)

## Building

```
dotnet build -c Release
dotnet test -c Release --collect "XPlat Code Coverage" --results-directory TestResults

python eng/coverage.py TestResults --min-line 98.5 --min-branch 97   # merged per-package coverage, as CI enforces
```

The repository contains 18 packages and about 4,900 tests, which cover over 99% of lines and 98% of branches. CI fails if coverage falls below that floor. The tests include RFC/NIST known-answer vectors, differential tests against Microsoft's Identity hasher and the reference implementations, and FsCheck property-based fuzzing. Stryker.NET mutation testing scores 95.8% across all packages (`dotnet tool restore`, then `dotnet stryker` in a test project folder); each remaining survivor was reviewed and judged unable to change observable behaviour (for example, zeroing a buffer that nothing reads afterwards).

## Give a star ⭐

If you use this project or like it, please give it a star. Thanks!

## License

MIT. See [LICENSE.txt](LICENSE.txt).
