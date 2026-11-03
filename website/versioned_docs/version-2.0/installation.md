---
title: "Installation"
sidebar_label: "Installation"
description: "Install the core package and only the companion packages you need. Targets, dependencies and supported runtimes."
---

Install the core package, `Masterly.Hash`, first. It is all most applications need: hashing, verification, profiles, upgrade-on-login, peppers and 1.x migration. Then add only the companion packages that match what you build. All 18 packages ship together with the same version number, currently 2.0.0.

```bash
dotnet add package Masterly.Hash
```

Or add the reference to your project file:

```xml title="MyApp.csproj"
<ItemGroup>
  <PackageReference Include="Masterly.Hash" Version="2.0.0" />
</ItemGroup>
```

## Supported runtimes

| Package kind | Target | Runs on |
|--------------|--------|---------|
| Libraries (every package except the analyzers and the tool) | `net8.0` | .NET 8 and every later .NET version. Not .NET Framework, Mono or `netstandard` hosts. |
| `Masterly.Hash.Analyzers` | `netstandard2.0` analyzer | Any Roslyn host from Microsoft.CodeAnalysis 4.8: Visual Studio 2022 17.8 or later, the .NET 8 SDK or later, Rider, VS Code. |
| `Masterly.Hash.Tool` | `net8.0` .NET tool, `RollForward=Major` | Any machine with the .NET 8 runtime or later. |

The test suite runs on .NET 10, and CI builds with the .NET 8 and .NET 10 SDKs. Projects that consume the packages need nothing newer than the .NET 8 SDK.

:::note

The core package depends on `Konscious.Security.Cryptography.Argon2` 1.3.1, a fully managed Argon2 implementation. There is no native library to deploy, so the same package works on Windows, Linux, macOS, in containers and in serverless functions.

:::

## Packages

### Password hashing

| Package | What it is for | Extra dependencies |
|---------|----------------|--------------------|
| `Masterly.Hash` | The core: `Password` and `PasswordHasher`, dated profiles (Argon2id and PBKDF2-HMAC-SHA512), upgrade-on-login, constant-time verification, `VerifyOrDummy`, the local `HmacPepper`, the 1.x format, onion wrapping, `SensitiveString` and metrics. | `Konscious.Security.Cryptography.Argon2` 1.3.1 |
| `Masterly.Hash.Legacy` | Verifies hashes from other systems and upgrades them on login: bcrypt, ASP.NET Core Identity v2 and v3, Django PBKDF2, phpass (WordPress, phpBB), unsalted MD5 and SHA digests, and external Argon2 PHC strings. Wraps weak hashes offline and audits a password table (`HashAudit`). | `BCrypt.Net-Next` 4.2.1, `Konscious.Security.Cryptography.Argon2` 1.3.1 |

### Integrations

| Package | What it is for | Extra dependencies |
|---------|----------------|--------------------|
| `Masterly.Hash.DependencyInjection` | `services.AddMasterlyHash(...)`: one singleton `PasswordHasher`, also registered as `IPasswordHasher`, options bound from `IConfiguration`, validation at startup, and a builder for peppers, legacy formats and profiles. | `Microsoft.Extensions.DependencyInjection.Abstractions` 8.0.2, `Microsoft.Extensions.Options` 8.0.2, `Microsoft.Extensions.Options.ConfigurationExtensions` 8.0.0, `Microsoft.Extensions.Configuration.Abstractions` 8.0.0, `Microsoft.Extensions.Configuration.Binder` 8.0.2 |
| `Masterly.Hash.AspNetCore` | A drop-in ASP.NET Core Identity `IPasswordHasher<TUser>` that keeps verifying existing Identity hashes and upgrades them, an `IExceptionHandler` that maps `PasswordHasherBusyException` to HTTP 503 with `Retry-After`, a password-length validator, and a minimal API endpoint filter. | The `Microsoft.AspNetCore.App` shared framework. Also references `Masterly.Hash.Legacy` and `Masterly.Hash.DependencyInjection`. |
| `Masterly.Hash.EntityFrameworkCore` | A `SaveChanges` interceptor that hashes annotated password properties in place, blind-index columns, query helpers for blind-index lookups, and a verify-and-upgrade helper. | `Microsoft.EntityFrameworkCore` 8.0.33. Also references `Masterly.Hash.BlindIndex`. |

### Key management (peppers)

| Package | What it is for | Extra dependencies |
|---------|----------------|--------------------|
| `Masterly.Hash.Pepper.HashiCorpVault` | A pepper computed by the Vault Transit engine (HMAC-SHA256), so the key never leaves Vault. Key-version rotation, Vault namespaces and token providers. | None. It talks to Vault over the `HttpClient` you pass in. |
| `Masterly.Hash.Pepper.AwsKms` | A pepper computed by AWS KMS `GenerateMac` on an HMAC KMS key, so the key never leaves KMS. Rotation through a key-id map. | `AWSSDK.KeyManagementService` 4.0.101.1 |
| `Masterly.Hash.Pepper.AzureKeyVault` | Pepper keys loaded from Azure Key Vault secrets (each secret version is a key id), cached in memory with periodic refresh. HMAC-SHA256 runs locally. | `Azure.Security.KeyVault.Secrets` 4.12.0. Add `Azure.Identity` yourself if you authenticate with `DefaultAzureCredential`. |

### Password policy

| Package | What it is for | Extra dependencies |
|---------|----------------|--------------------|
| `Masterly.Hash.Policy` | Password rules aligned with NIST SP 800-63B rev. 4: length in code points, no composition rules, a blocklist of the 10,000 most common passwords, context-word and repetition checks, an optional breached-password lookup, and a zxcvbn-inspired strength estimator. | None |
| `Masterly.Hash.Pwned` | The Have I Been Pwned "Pwned Passwords" k-anonymity client. It implements `IBreachedPasswordChecker` from `Masterly.Hash.Policy` and sends only the first 5 hex characters of the password's SHA-1. Includes an optional bounded range cache (off by default) and `AddPwnedPasswords()` for a typed `HttpClient`. | `Microsoft.Extensions.DependencyInjection.Abstractions` 8.0.2, `Microsoft.Extensions.Http` 8.0.1. Also references `Masterly.Hash.Policy`. |

### Beyond passwords

| Package | What it is for | Extra dependencies |
|---------|----------------|--------------------|
| `Masterly.Hash.Tokens` | API keys with an offline CRC32 checksum and a keyed (HMAC-SHA256) lookup hash with key rotation; signed, expiring, purpose-bound tokens for password reset, email confirmation and magic links; unbiased secure random strings. | None |
| `Masterly.Hash.BlindIndex` | Searchable HMAC-SHA256 indexes for encrypted PII columns, with per-column domain separation, truncation, normalizers (email, phone, case-insensitive), compound indexes and key rotation. | None |
| `Masterly.Hash.Integrity` | Streaming content hashes (SHA-256/384/512, HMAC-SHA256), RFC 9162 Merkle trees with inclusion and consistency proofs, keyed hash-chain audit logs, and directory manifests. | None |
| `Masterly.Hash.Integrity.Blake3` | BLAKE3, plain and keyed, for the Integrity package. | `Blake3` 3.0.2. Also references `Masterly.Hash.Integrity`. |
| `Masterly.Hash.Detection` | Honeywords (Juels and Rivest) with a separate honeychecker, honey accounts, and privacy-preserving credential-stuffing detection. | None |

### Tooling

| Package | What it is for | Extra dependencies |
|---------|----------------|--------------------|
| `Masterly.Hash.Analyzers` | Roslyn analyzers with code fixes, MH0001 to MH0006: a fast hash used on a password, a non-constant-time comparison, a hard-coded pepper, a logged password, weak PBKDF2 parameters, and use of the obsolete 1.x API. | None at run time. It is a development dependency and never ends up in your build output. |
| `Masterly.Hash.Testing` | A real but very fast `IPasswordHasher` for tests (`FastPasswordHasher`), a call-recording decorator, a deterministic fake pepper, `MasterlyHashAssert` and known sample hashes. | None |
| `Masterly.Hash.Tool` | The `masterly-hash` command: `hash`, `verify`, `inspect`, `audit`, `wrap`, `bench`, `policy`, `pepper generate` and `apikey generate`. | `System.CommandLine` 2.0.14 (bundled with the tool) |

Every companion library depends on `Masterly.Hash`, directly or through another companion package, so NuGet brings the core package in for you. The analyzers have no run-time dependencies, and the tool bundles everything it needs. The versions shown are the minimum versions each package references.

## Install commands

```bash
# Core
dotnet add package Masterly.Hash

# Migration from other systems
dotnet add package Masterly.Hash.Legacy

# Integrations
dotnet add package Masterly.Hash.DependencyInjection
dotnet add package Masterly.Hash.AspNetCore
dotnet add package Masterly.Hash.EntityFrameworkCore

# Remote peppers: pick one
dotnet add package Masterly.Hash.Pepper.HashiCorpVault
dotnet add package Masterly.Hash.Pepper.AwsKms
dotnet add package Masterly.Hash.Pepper.AzureKeyVault

# Password policy
dotnet add package Masterly.Hash.Policy
dotnet add package Masterly.Hash.Pwned

# Beyond passwords
dotnet add package Masterly.Hash.Tokens
dotnet add package Masterly.Hash.BlindIndex
dotnet add package Masterly.Hash.Integrity
dotnet add package Masterly.Hash.Integrity.Blake3
dotnet add package Masterly.Hash.Detection
```

In the Visual Studio Package Manager Console, run `Install-Package Masterly.Hash`, and the same for each companion package.

### Analyzers

Add the analyzers to every project that handles passwords, hashes or tokens:

```bash
dotnet add package Masterly.Hash.Analyzers
```

The package is marked as a development dependency, so NuGet adds `PrivateAssets="all"` for you and the analyzers do not flow to projects that reference yours:

```xml title="MyApp.csproj"
<ItemGroup>
  <PackageReference Include="Masterly.Hash.Analyzers" Version="2.0.0">
    <PrivateAssets>all</PrivateAssets>
    <IncludeAssets>runtime; build; native; contentfiles; analyzers; buildtransitive</IncludeAssets>
  </PackageReference>
</ItemGroup>
```

### Test helpers

Reference `Masterly.Hash.Testing` from test projects only:

```bash
dotnet add tests/MyApp.Tests package Masterly.Hash.Testing
```

:::warning

`FastPasswordHasher` uses a deliberately weak profile (Argon2id, 64 KiB, one pass) so tests run in microseconds. Never reference `Masterly.Hash.Testing` from production code.

:::

### Command-line tool

Install the tool globally, or as a local tool pinned in the repository's tool manifest:

```bash
# Global
dotnet tool install --global Masterly.Hash.Tool
masterly-hash --help

# Local (pinned in .config/dotnet-tools.json)
dotnet new tool-manifest
dotnet tool install Masterly.Hash.Tool
dotnet tool run masterly-hash --help
```

## Native AOT and trimming

These packages are marked `IsAotCompatible`, so the build checks them with the trim and AOT analyzers: `Masterly.Hash`, `Masterly.Hash.BlindIndex`, `Masterly.Hash.Detection`, `Masterly.Hash.Integrity`, `Masterly.Hash.Integrity.Blake3`, `Masterly.Hash.Pepper.HashiCorpVault`, `Masterly.Hash.Policy`, `Masterly.Hash.Pwned` and `Masterly.Hash.Tokens`. The other packages are not marked. Several of them depend on frameworks with their own AOT limits, such as Entity Framework Core and the configuration binder.

## Which packages do I need?

| You are building | Install |
|------------------|---------|
| Any application that stores passwords | `Masterly.Hash` |
| An ASP.NET Core app with your own user table | `Masterly.Hash`, `Masterly.Hash.DependencyInjection`, `Masterly.Hash.AspNetCore` (for the 503 handler and length filter) |
| An ASP.NET Core Identity app | `Masterly.Hash.AspNetCore` (it brings the core, DI and Legacy packages) |
| A migration from bcrypt, Identity, Django, phpass or raw digests | `Masterly.Hash.Legacy` |
| An app whose pepper key must stay in a key store | One of the `Masterly.Hash.Pepper.*` packages |
| A sign-up flow that rejects weak or breached passwords | `Masterly.Hash.Policy`, and `Masterly.Hash.Pwned` for the breach check |
| Every project in the solution | `Masterly.Hash.Analyzers` |

## See also

- [Quick Start](./quick-start.md): hash and verify your first password.
- [How It Works](./how-it-works.md): what each package does and how they fit together.
- [Dependency Injection](./dependency-injection.md)
- [Upgrading from 1.x](./upgrading-from-1x.md)
