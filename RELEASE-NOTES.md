# Masterly.Hash 2.0.0

Masterly.Hash 2.0.0 replaces salted SHA-2 with Argon2id. Existing hashes migrate on login, and you can also wrap them all offline today.

- `Password.Hash(pw)` and `Password.Verify(pw, stored)`, with safe defaults and no configuration.
- 1.x hashes keep verifying. A successful verification returns a fresh Argon2id `Rehash`.
- Requires .NET 8 or later: .NET Framework (netstandard2.0) is no longer supported.
- 17 optional packages: legacy-format migration (bcrypt, Identity, Django…), DI, ASP.NET Core Identity, EF Core, NIST password policy, HIBP checks, Vault/KMS/Key Vault peppers, honeywords, API keys, blind indexes, Merkle trees, Roslyn analyzers, test helpers and a CLI.

See [CHANGELOG.md](CHANGELOG.md) for details and [docs/MIGRATION-1x.md](docs/MIGRATION-1x.md) to upgrade.
