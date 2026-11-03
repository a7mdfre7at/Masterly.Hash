---
title: "API Reference"
sidebar_label: "API Reference"
description: "Every public type and its key members, package by package, with links to the guide for each area."
---

This reference lists the public types and members you use in application code, one package at a time. Each section names the namespaces the package uses and links to the guide page that explains the area. All packages target .NET 8 except Masterly.Hash.Analyzers, which targets netstandard2.0 as Roslyn requires.

Extension methods that register services live in `Microsoft.Extensions.DependencyInjection` (and `Microsoft.AspNetCore.Builder` for endpoint filters), so they appear without an extra `using`.

## Masterly.Hash

The core package: hashing, verification, profiles, peppers and the 1.x legacy format. Namespaces: `Masterly.Hash`, `Masterly.Hash.Pepper`, `Masterly.Hash.Legacy`, `Masterly.Hash.Primitives`. Guides: [Hashing and verifying](./hashing-and-verifying.md), [Profiles](./profiles.md), [Upgrade on login](./upgrade-on-login.md), [Peppers](./peppers.md), [Limits and concurrency](./limits-and-concurrency.md), [User enumeration](./user-enumeration.md).

**Hashing and verifying**

| Type or member | Purpose |
|----------------|---------|
| `Password` | Static entry point over `PasswordHasher.Default`: `Hash`, `Verify`, `VerifyOrDummy`, `HashAsync`, `VerifyAsync`, `VerifyOrDummyAsync`, `NeedsRehash`, `Inspect`. `Hash` and `Verify` also accept a `SensitiveString`; `Hash(password, profile)` takes a built-in profile. |
| `IPasswordHasher` | The hasher contract: `Hash(password)`, `Hash(password, profile)`, `Verify`, `VerifyOrDummy`, `HashAsync`, `VerifyAsync`, `VerifyOrDummyAsync` (each async method takes an optional `CancellationToken`), `NeedsRehash`, `Inspect`, `TryWrap(legacyHash, out wrappedHash)`. |
| `PasswordHasher` | The thread-safe implementation. Create one per application. Constructors `()` and `(PasswordHasherOptions)` (options are copied). Members: `Default` (shared instance), `DefaultProfile`, `MaxPasswordBytes`, `Profiles`, `MeterName` (`"Masterly.Hash"`). |
| `PasswordHasherOptions` | `DefaultProfile` (default `HashProfile.Server2026a`), `AdditionalProfiles`, `Pepper`, `LegacyFormats` (default contains `V1LegacyFormat.Instance`), `MaxPasswordBytes` (default 1024; 64 to 1,048,576), `MaxConcurrency` (default `Environment.ProcessorCount`; 0 disables the limit), `ConcurrencyTimeout` (default 30 seconds), `ComputeRehashOnVerify` (default `true`), `AllowWeakProfiles` (default `false`; tests only). |
| `PasswordHasherExtensions` | `SensitiveString` overloads on `IPasswordHasher`: `Hash`, `Verify`, `VerifyOrDummy`, `HashAsync`, `VerifyAsync`, `VerifyOrDummyAsync`. |
| `PasswordVerificationResult` | `Status`, `IsMatch`, `NeedsRehash`, `FailureReason`, `RehashReason`, `Rehash` (the replacement hash, when `NeedsRehash` and `ComputeRehashOnVerify` are true). Never thrown; returned for every stored hash, good or bad. |
| `VerificationStatus` | `Failed`, `Success`, `SuccessRehashNeeded`. |
| `VerificationFailureReason` | `None`, `Mismatch`, `NoStoredHash`, `UnknownFormat`, `MalformedHash`, `UnknownProfile`, `UnknownPepperKey`, `PasswordTooLong`, `EmptyPassword`, `InvalidPassword`. For logs and metrics, never for the end user. |
| `RehashReason` | `None`, `LegacyFormat`, `Wrapped`, `OutdatedProfile`, `OutdatedPepperKey`. |
| `HashInfo` | Result of `Inspect`, without verifying: `Format` (`mh`, a legacy id or `unknown`), `IsRecognized`, `ProfileId`, `Profile`, `PepperKeyId`, `WrappedFormat`, `RehashReason`, `IsNative`, `NeedsRehash`. Constants `NativeFormat` (`"mh"`) and `UnknownFormat` (`"unknown"`). |
| `PasswordHasherBusyException` | A `TimeoutException` thrown when no hashing slot frees up within `ConcurrencyTimeout`. Map it to HTTP 503. |
| `SensitiveString` | A password wrapper whose `ToString()`, debugger view and JSON output are `***` (`Redacted`). Constructor `(value)`, explicit conversion from `string`, `Reveal()`, `Length`, `IsEmpty`, `TryParse` for minimal API binding. |
| `SensitiveStringJsonConverter` | Reads the real value; always writes `"***"`. |

**Profiles**

| Type or member | Purpose |
|----------------|---------|
| `HashProfile` | A named, immutable KDF parameter set. `Id`, `Algorithm`, `MemoryKiB`, `Iterations`, `Parallelism`, `SaltLength`, `TagLength`, `MeetsRecommendedMinimum`. |
| `HashProfile.Server2026a` | `2026a`: Argon2id, m = 65536 KiB, t = 3, p = 1, 16-byte salt, 32-byte tag. The default. |
| `HashProfile.Constrained2026a` | `2026c`: Argon2id, m = 19456 KiB, t = 2, p = 1. |
| `HashProfile.Fips2026a` | `2026f`: PBKDF2-HMAC-SHA512, 210,000 iterations, 64-byte tag. |
| `HashProfile.BuiltIn` / `TryGetBuiltIn(id, out profile)` | The three built-in profiles. They are always accepted by every `PasswordHasher`. |
| `HashProfile.Argon2id(...)` / `HashProfile.Pbkdf2Sha512(...)` | Create a custom profile. Bounds are listed on [The $mh$ hash format](./hash-format.md). |
| `HashProfile.MaxMemoryKiB` | 1,048,576 KiB (1 GiB), the Argon2 memory ceiling. |
| `HashAlgorithmKind` | `Argon2id`, `Pbkdf2Sha512`. |

**Peppers** (`Masterly.Hash.Pepper`)

| Type or member | Purpose |
|----------------|---------|
| `IPasswordPepper` | `CurrentKeyId`, `IsKnownKey(keyId)`, `Apply(keyId, input)`, `ApplyAsync(keyId, input, cancellationToken)`. Key ids match `^[A-Za-z0-9-]{1,32}$`. |
| `HmacPepper` | Local HMAC-SHA256 key ring. Constructors `(currentKeyId, keys)` and `(keyId, key)`; `FromBase64(currentKeyId, base64Keys)`; `GenerateKey()`; `MinKeyLength` (32 bytes). |

**Legacy formats** (`Masterly.Hash.Legacy`)

| Type or member | Purpose |
|----------------|---------|
| `ILegacyHashFormat` | A read-only foreign format: `Id`, `CanHandle`, `Verify`, `TryExtractWrapInput`, `ComputeWrapInput`. Implement it to add your own format. |
| `V1LegacyFormat` | Masterly.Hash 1.x hashes, `base64(SHA-2(utf8(password) \|\| salt) \|\| salt)`, id `v1`. `Instance` verifies any 1.x hash but cannot wrap; `new V1LegacyFormat(V1Algorithm)` can wrap. |
| `V1Algorithm` | `SHA256`, `SHA384`, `SHA512`. |

**Primitives** (`Masterly.Hash.Primitives`)

| Type or member | Purpose |
|----------------|---------|
| `HashPrimitives` | Building blocks for custom schemes: `FixedTimeEquals`, `IsWellFormedPassword`, `IsValidProfileId`, `IsValidKeyId`, `IsValidFormatId`, `Zero`, `RandomBytes`, `Pbkdf2(prf, password, salt, iterations, length)`, `DeriveKey(profile, input, salt)`, `EncodePassword` (UTF-8 of NFKC), `ToB64`, `TryFromB64`. |

**Obsolete 1.x API**

| Type or member | Purpose |
|----------------|---------|
| `Hash`, `IHash`, `SupportedHash` | Marked `[Obsolete]`. `ComputeHash` and `Verify` keep 1.x code compiling; `Verify` is now constant-time. Replace with `Password.Hash` / `Password.Verify`. See [Upgrading from 1.x](./upgrading-from-1x.md). |

**Metrics** (meter `Masterly.Hash`; see [Observability](./observability.md))

| Instrument | Type | Measures | Tags |
|------------|------|----------|------|
| `masterly.hash.duration` (ms) | Histogram | Time spent computing a hash or verification | `operation` (`hash` or `verify`), plus `profile` or `format` |
| `masterly.hash.verifications` | Counter | Verifications by format and outcome | `format`, `outcome`, `reason` |
| `masterly.hash.hashes` | Counter | New hashes by profile | `profile` |
| `masterly.hash.busy_rejections` | Counter | Calls rejected at the concurrency limit | None |

No tag ever contains secret material.

## Masterly.Hash.DependencyInjection

Registers a singleton hasher in `IServiceCollection` and binds options from configuration. Namespace: `Masterly.Hash.DependencyInjection`; `AddMasterlyHash` lives in `Microsoft.Extensions.DependencyInjection`. Guide: [Dependency injection](./dependency-injection.md).

| Type or member | Purpose |
|----------------|---------|
| `services.AddMasterlyHash(configure)` | Registers `PasswordHasher` and `IPasswordHasher` as one singleton built from `IOptions<PasswordHasherOptions>`. Returns a `MasterlyHashBuilder`. Throws `InvalidOperationException` if a hasher was already registered by something else. |
| `services.AddMasterlyHash(configuration, configure)` | Also binds a configuration section to `MasterlyHashConfiguration`. Code configure steps always win over configuration. |
| `MasterlyHashBuilder` | `Services`, `Configure(...)`, `Configure<TDep>(...)`, `WithPepper(pepper)` / `WithPepper(factory)`, `AddLegacyFormat(format)` / `AddLegacyFormat(factory)`, `UseProfile(profile)`, `AddProfile(profile)`, `MeterName`. |
| `MasterlyHashConfiguration` | `DefaultProfile` (`2026a`, `2026c` or `2026f`), `MaxConcurrency`, `ConcurrencyTimeout`, `MaxPasswordBytes`, `ComputeRehashOnVerify`, `Pepper`. Unknown keys are startup errors. |
| `MasterlyHashPepperConfiguration` | `CurrentKeyId` and `Keys` (key id to base64 key of at least 32 bytes). Creates an `HmacPepper`. |
| `provider.ValidateMasterlyHash()` | In `MasterlyHashServiceProviderExtensions`. Builds the hasher now so configuration errors surface at startup, and returns the `PasswordHasher`. Throws `OptionsValidationException` for invalid options or configuration, `InvalidOperationException` when `AddMasterlyHash` was not called. |
| `PasswordHasherOptionsValidator` / `MasterlyHashConfigurationValidator` | `IValidateOptions` implementations registered for you; they report every problem at once. |

## Masterly.Hash.AspNetCore

ASP.NET Core Identity adapter, a 503 exception handler and a password-length endpoint filter. Namespace: `Masterly.Hash.AspNetCore`; registration methods in `Microsoft.Extensions.DependencyInjection` and `Microsoft.AspNetCore.Builder`. Guides: [ASP.NET Core Identity](./aspnetcore-identity.md), [Limits and concurrency](./limits-and-concurrency.md).

| Type or member | Purpose |
|----------------|---------|
| `identityBuilder.AddMasterlyPasswordHasher(configure)` | Registers Masterly.Hash, replaces Identity's `IPasswordHasher<TUser>`, sets `ComputeRehashOnVerify` to `false`, lowers a default `ConcurrencyTimeout` to `IdentityConcurrencyTimeout`, adds the Identity v3 and v2 formats and `MasterlyPasswordLengthValidator<TUser>`. |
| `MasterlyIdentityBuilderExtensions.IdentityConcurrencyTimeout` | 2 seconds. |
| `MasterlyIdentityPasswordHasher<TUser>` | Identity `IPasswordHasher<TUser>` over a Masterly hasher. Constructors `(hasher, IOptions<PasswordHasherOptions>)` and `(hasher, maxPasswordBytes)`; `HashPassword`, `VerifyHashedPassword`. Bad stored hashes return `Failed`; `PasswordHasherBusyException` propagates. |
| `MasterlyPasswordLengthValidator<TUser>` | Identity `IPasswordValidator<TUser>` that rejects empty and over-long passwords. Constructors `(IOptions<PasswordHasherOptions>)` and `(maxPasswordBytes)`. Error codes `PasswordRequiredCode` (`"PasswordRequired"`) and `PasswordTooLongCode` (`"PasswordTooLong"`); `MaxPasswordBytes`. |
| `options.AddAspNetIdentityFormats()` | Adds `AspNetIdentityV3Format.Default` and `AspNetIdentityV2Format.Instance` to `PasswordHasherOptions` unless their ids are already registered. |
| `services.AddMasterlyHashExceptionHandler(configure)` | Registers `PasswordHasherBusyExceptionHandler`. Also call `app.UseExceptionHandler()`. |
| `PasswordHasherBusyExceptionHandler` | `IExceptionHandler` that answers `PasswordHasherBusyException` with `503 Service Unavailable`, `Retry-After` and a problem details body. |
| `MasterlyHashExceptionHandlerOptions` | `RetryAfter` (default 5 seconds; 1 second to 1 day, rounded up to whole seconds). |
| `endpoint.WithPasswordLengthLimit()` | Adds `PasswordLengthEndpointFilter` to a minimal API endpoint or route group. |
| `PasswordLengthEndpointFilter` | Answers `400 Bad Request` when a `SensitiveString` argument, or a public `SensitiveString` property one level deep, exceeds `MaxPasswordBytes` (UTF-8 bytes after NFKC). Constructors `(IOptions<PasswordHasherOptions>)` and `(maxPasswordBytes)`; `MaxPasswordBytes`, `IsTooLong(password)`. |

## Masterly.Hash.EntityFrameworkCore

A `SaveChanges` interceptor that hashes password properties and maintains blind indexes, plus login and query helpers. Namespace: `Masterly.Hash.EntityFrameworkCore`. Guides: [Entity Framework Core](./entity-framework-core.md), [Blind indexes](./blind-indexes.md).

| Type or member | Purpose |
|----------------|---------|
| `optionsBuilder.UseMasterlyHash(hasher, indexer, configure)` | Adds a `MasterlyHashSaveChangesInterceptor`. `indexer` is needed only when the model uses `HasBlindIndex`. Generic and non-generic `DbContextOptionsBuilder` overloads. |
| `property.IsHashedPassword()` | Marks a string property as a password column. Plaintext is replaced by its hash, in the entity, on save. Deliberately not a value converter. |
| `property.HasBlindIndex(indexPropertyName, indexName, normalizer, outputBits)` | Maintains a blind index of the property in another string property. `outputBits` defaults to 64. |
| `MasterlyHashSaveChangesInterceptor` | The interceptor. Constructor `(hasher, indexer = null, options = null)`; `Hasher`, `Indexer`. Sync saves use `Hash`, async saves use `HashAsync`. |
| `MasterlyHashInterceptorOptions` | `AcceptLegacyHashes` (default `false`) and `Normalizers` (id to `IBlindIndexNormalizer`). |
| `context.VerifyAndUpgradeAsync(entity, passwordProperty, password, cancellationToken)` | Verifies and, when the hash is outdated, writes the rehash and saves. An overload takes an explicit `IPasswordHasher`. A null stored hash is verified against a dummy hash. |
| `query.WhereBlindIndex(indexProperty, indexer, indexName, value, options)` | Filters by a blind index under every key in the ring. |
| `dbSet.WhereBlindIndex(indexProperty, value)` | Same, using the `HasBlindIndex` settings and the context's indexer. |
| `context.GetBlindIndexCandidates<TEntity>(indexProperty, value)` | The index under every key, current first, for raw SQL. |
| `MasterlyHashAnnotationNames` | The model annotation names (`Prefix` `"Masterly:"`, `HashedPassword`, `BlindIndexProperty`, `BlindIndexName`, `BlindIndexNormalizer`, `BlindIndexOutputBits`). |

## Masterly.Hash.Legacy

Verifies hashes from other systems, upgrades them on login, wraps them offline and audits hash tables. Namespace: `Masterly.Hash.Legacy` (the options extensions are in `Masterly.Hash`). Guides: [Legacy formats](./legacy-formats.md), [Onion wrapping](./onion-wrapping.md), [Auditing hash tables](./auditing-hash-tables.md).

**Formats**

| Type or member | Id | Purpose and caps |
|----------------|----|------------------|
| `BCryptFormat` | `bcrypt` | `$2a$`, `$2b$`, `$2y$`. `Default`, `()`, `(maxCost)`, `MaxCost`; `DefaultMaxCost` 15, `MinCost` 4, `HardMaxCost` 31. |
| `WordPressBcryptFormat` | `wordpress-bcrypt` | WordPress 6.8+ `$wp$2y$...`. `Default`, `()`, `(maxCost)`, `MaxCost` (default 15); `MaxPasswordBytes` 4096. |
| `ExternalArgon2Format` | `argon2-phc` | `$argon2id$`, `$argon2i$`, `$argon2d$` (v=19). `Default`, `()`, `(maxMemoryKiB, maxIterations, maxParallelism)`, `MaxMemoryKiB`, `MaxIterations`, `MaxParallelism`; `DefaultMaxMemoryKiB` 262,144 (256 MiB), `DefaultMaxIterations` 10, `DefaultMaxParallelism` 16. Never wrapped. |
| `PhpassFormat` | `phpass` | `$P$` and `$H$`. `Default`, `()`, `(maxCostLog2)`, `MaxCostLog2`; `DefaultMaxCostLog2` 18, `MinCostLog2` 7, `HardMaxCostLog2` 30, `MaxPasswordBytes` 4096. |
| `DjangoPbkdf2Format` | `django-pbkdf2` | `pbkdf2_sha256$...` and `pbkdf2_sha1$...`. `Default`, `()`, `(maxIterations)`, `MaxIterations`; `DefaultMaxIterations` 10,000,000. |
| `AspNetIdentityV3Format` | `aspnet-identity-v3` | The ASP.NET Core Identity default. `Default`, `()`, `(maxIterations)`, `MaxIterations`; `DefaultMaxIterations` 10,000,000. |
| `AspNetIdentityV2Format` | `aspnet-identity-v2` | Identity v2 (PBKDF2-HMAC-SHA1, 1000 iterations). `Instance`; no settings. |
| `UnsaltedDigestFormat` | `md5`, `sha1`, `sha256`, `sha512` | Hex digests of the UTF-8 password. `Md5`, `Sha1`, `Sha256`, `Sha512`, `DigestLength`. |

**Registration and audit**

| Type or member | Purpose |
|----------------|---------|
| `LegacyFormats.All` | Every format above with default settings. |
| `options.AddLegacyFormats(params formats)` | Adds formats ahead of the built-in 1.x format. All-or-nothing; a different instance with a registered id throws. |
| `options.AddAllLegacyFormats()` | Adds `LegacyFormats.All`, skipping ids already registered. |
| `HashAudit.Audit(hasher, storedHashes)` | Classifies a column of hashes in one streaming pass with `Inspect`. Never throws for a bad entry. |
| `HashAudit.IsWeak(formatId, storedHash)` | The weakness rule. `WeakBCryptCostBelow` 10, `WeakPbkdf2IterationsBelow` 100,000. |
| `HashAuditReport` | `Total`, `Recognized`, `Unknown`, `NeedsRehash`, `Weak`, `Wrapped`, `Duplicates`, `ByFormat`, `ByProfile`, `WeakByFormat`, the matching `...Percent` properties, `Percent(count)`, `ToMarkdown()`. |

## Masterly.Hash.Pepper.HashiCorpVault

A pepper computed by the Vault Transit engine; the key never leaves Vault. Namespace: `Masterly.Hash.Pepper.HashiCorpVault`. Guide: [HashiCorp Vault](./hashicorp-vault.md).

| Type or member | Purpose |
|----------------|---------|
| `HashiCorpVaultPepper` | `IPasswordPepper` over `POST /v1/{mount}/hmac/{key}/sha2-256`. Constructor `(HttpClient, HashiCorpVaultPepperOptions)`. `Endpoint`, `HmacLength` (32). Key ids are `v{N}` for Transit version N: `KeyIdFor(version)`, `TryParseKeyId(keyId, out version)`. `Apply` blocks on `ApplyAsync`. |
| `HashiCorpVaultPepperOptions` | `VaultAddress` (https unless `AllowInsecureHttp`), `MountPath` (default `transit`), `KeyName`, `Token` or `TokenProvider` (exactly one), `Namespace`, `CurrentKeyVersion`, `MinKeyVersion` (default 1), `MaxKeyVersion` (default `CurrentKeyVersion`), `Timeout` (default 10 seconds), `AllowInsecureHttp`. |
| `PepperUnavailableException` | Vault could not compute the HMAC. The hasher does not catch it; treat it as HTTP 503. |

## Masterly.Hash.Pepper.AwsKms

A pepper computed by AWS KMS `GenerateMac` (`HMAC_SHA_256`); the key never leaves KMS. Namespace: `Masterly.Hash.Pepper.AwsKms`. Guide: [AWS KMS](./aws-kms.md).

| Type or member | Purpose |
|----------------|---------|
| `AwsKmsPepper` | `IPasswordPepper` over an HMAC KMS key. Constructor `(IAmazonKeyManagementService, AwsKmsPepperOptions)`. `MacLength` (32), `MaxInputBytes` (4096). `Apply` blocks on `ApplyAsync`. |
| `AwsKmsPepperOptions` | `CurrentKeyId`, `Keys` (pepper key id to key ARN, key id or alias; spec `HMAC_256`, usage `GENERATE_VERIFY_MAC`), `GrantTokens`, `Timeout` (default 10 seconds). |
| `PepperUnavailableException` | KMS could not compute the MAC. Treat it as HTTP 503. |

## Masterly.Hash.Pepper.AzureKeyVault

Pepper keys stored as Key Vault secrets, loaded into memory and used through `HmacPepper`. Namespace: `Masterly.Hash.Pepper.AzureKeyVault`. Guide: [Azure Key Vault](./azure-key-vault.md).

| Type or member | Purpose |
|----------------|---------|
| `AzureKeyVaultPepper` | Create with `CreateAsync(SecretClient, options, cancellationToken)` or `Create(...)`. `CurrentKeyId` (throws `PepperUnavailableException` when no usable key exists), `KeyIds`, `LastRefreshed`, `LastRefreshError`, `RefreshAsync`, `MinKeyLength` (32), `RemovedKeyGrace` (30 seconds). |
| `AzureKeyVaultPepperOptions` | Exactly one of `SecretName` (versions mode) and `Keys` (map mode). `CurrentKeyId`, `RefreshInterval` (default 5 minutes), `ActivationDelay` (default 15 minutes), `MaxVersions` (default 25), `Timeout` (default 30 seconds), `OnRefreshFailed`. |
| `AzureKeyVaultSecretReference` | `(name, version)` for map mode: `Name`, `Version`. |
| `PepperUnavailableException` | The keys could not be loaded. Thrown by `CreateAsync` and `RefreshAsync`, and by `CurrentKeyId` when no current key can be chosen. |

## Masterly.Hash.Policy

NIST SP 800-63B rev. 4 password rules and a zxcvbn-style strength estimator. Namespace: `Masterly.Hash.Policy`. Guides: [Password policy](./password-policy.md), [Strength estimation](./strength-estimation.md).

| Type or member | Purpose |
|----------------|---------|
| `IPasswordPolicy` / `PasswordPolicy` | `Evaluate(password, context)` (local rules only) and `EvaluateAsync(password, context, cancellationToken)` (adds the breach lookup), each for `string` and `SensitiveString`. Constructors `()`, `(options)`, `(options, breachedPasswordChecker)`. `PasswordPolicy.Default`. |
| `PasswordPolicyOptions` | `MinLength` (default 15; at least `MinimumAllowedMinLength`, 8), `MaxLength` (default 128; `MinimumAllowedMaxLength` 64 to `MaximumAllowedMaxLength` 4096), `BlockCommonPasswords` (default `true`), `BlockedPasswords`, `MinimumScore` (default 3), `CheckContextWords` (default `true`), `ContextWords`, `MinContextWordLength` (default 4), `RejectRepetitiveOrSequential` (default `true`), `MinimumBreachOccurrences` (default 1), `ReferenceYear`. |
| `PasswordContext` | Per-user words to reject: `UserName`, `Email`, `DisplayName`, `ApplicationName`, `AdditionalWords`. |
| `PasswordPolicyResult` | `IsAcceptable`, `Score`, `Length` (code points after NFKC), `Violations`, `Suggestions`, `StrengthEstimate`, `BreachCheck`, `BreachCheckUnavailable`, `HasViolation(code)`. |
| `PasswordViolation` / `PasswordViolationCode` | `Code` and `Message`. Codes: `TooShort`, `TooLong`, `CommonPassword`, `ContainsContextWord`, `RepetitiveOrSequential`, `TooWeak`, `Breached`. |
| `IBreachedPasswordChecker` | `CheckAsync(password, cancellationToken)` returning a `BreachCheckResult`. |
| `BreachCheckResult` / `BreachCheckStatus` | `Status` (`Ok`, `Unavailable`), `IsBreached`, `Occurrences`; `NotBreached`, `Unavailable`, `Breached(occurrences)`. |
| `PasswordStrengthEstimator.Estimate(...)` | Estimates strength from a `string` or `SensitiveString`, with optional user inputs and reference year. Analyzes at most `MaxAnalyzedLength` (100) UTF-16 units. |
| `StrengthEstimate` | `Guesses`, `GuessesLog10`, `Score` (0 to 4), `CrackTimes`, `Warning`, `Suggestions`, `Sequence`, `IsTruncated`. |
| `PatternMatch`, `PatternKind`, `DictionaryKind` | One pattern found: `Pattern`, `StartIndex`, `Length`, `Dictionary`, `IsL33t`, `IsReversed`. Kinds `Bruteforce`, `Dictionary`, `Spatial`, `Repeat`, `Sequence`, `Year`, `Date`; dictionaries `None`, `CommonPasswords`, `EnglishWords`, `ContextWords`. |
| `CrackTimeEstimates` / `CrackTimeEstimate` | `OnlineThrottled` (100 per hour), `OnlineUnthrottled` (10 per second), `OfflineSlowHash` (10^4 per second), `OfflineFastHash` (10^10 per second), with the rates as constants `OnlineThrottledRate`, `OnlineUnthrottledRate`, `OfflineSlowHashRate`, `OfflineFastHashRate`; each estimate has `GuessesPerSecond`, `Seconds`, `Display`. |

## Masterly.Hash.Pwned

Have I Been Pwned "Pwned Passwords" k-anonymity client. Namespace: `Masterly.Hash.Pwned`; `AddPwnedPasswords` in `Microsoft.Extensions.DependencyInjection`. Guide: [Breach checking](./breach-checking.md).

| Type or member | Purpose |
|----------------|---------|
| `PwnedPasswordsClient` | `IBreachedPasswordChecker` that sends only the first 5 hex characters of the SHA-1 hash, with padded responses. Constructor `(HttpClient, options = null)`. `CheckAsync` for `string` and `SensitiveString`, `ClearCache()`, `MaxResponseBytes` (1 MiB). |
| `PwnedPasswordsOptions` | `BaseAddress` (default `DefaultBaseAddress`, `https://api.pwnedpasswords.com/`), `AllowInsecureHttp`, `Timeout` (default 3 seconds; at most `MaxTimeout`, 5 minutes), `UserAgent` (default `DefaultUserAgent`), `FailureMode` (default `FailOpen`), `MinimumOccurrences` (default 1), `EnableCache` (default `false`), `CacheDuration` (default 1 hour; at most `MaxCacheDuration`, 7 days), `CacheMaxEntries` (default 256; at most `MaxCacheEntriesLimit`, 100,000). |
| `PwnedPasswordsFailureMode` | `FailOpen` (return `Unavailable`) or `Throw`. |
| `PwnedPasswordsUnavailableException` | Thrown only in `Throw` mode when the service cannot answer. |
| `services.AddPwnedPasswords(configure)` | Registers the named `HttpClient` (`HttpClientName`), the typed client and a singleton `IBreachedPasswordChecker`. Returns the `IHttpClientBuilder`. |

## Masterly.Hash.Tokens

API keys with keyed lookup hashes, and signed, expiring, purpose-bound tokens. Namespace: `Masterly.Hash.Tokens`. Guide: [API keys and tokens](./api-keys-and-tokens.md).

**API keys**

| Type or member | Purpose |
|----------------|---------|
| `ApiKey` | `Generate(prefix, entropyBytes)` and `Generate(hasher, prefix, entropyBytes)`, `HasValidChecksum`, `TryParse(apiKey, out parts)`, `IsValidPrefix`. `DefaultEntropyBytes` 32, `MinEntropyBytes` 16, `MaxEntropyBytes` 64, `ChecksumLength` 6, `MaxPrefixLength` 32, `MaxLength` (125). |
| `ApiKeyGenerator` | `(hasher, prefix, entropyBytes)`; `Prefix`, `EntropyBytes`, `Hasher`, `Generate()`. |
| `ApiKeyHasher` | Keyed HMAC-SHA256 lookup hashes over an `HmacKeyRing`. Constructor `(keyRing)`; `ComputeLookupHash`, `ComputeAllLookupHashes`, `Verify` (constant time, never throws), `NeedsRehash`, `TryGetKeyId`, `KeyRing`, `MaxApiKeyLength` (1024). |
| `GeneratedApiKey` | `PlainText`, `Prefix`, `LookupHash`, `Hint`. `ToString()` returns the hint, never the key. |
| `ApiKeyParts` | `Prefix`, `RandomPart`, `Checksum`, `EntropyBytes`. |
| `HmacKeyRing` | `(currentKeyId, keys)`, `(keyId, key)`, `FromBase64`, `GenerateKey()`, `IsValidKeyId`, `CurrentKeyId`, `KeyIds`, `Contains`. `MinKeyLength` 32, `MaxKeyIdLength` 32. |

**Signed tokens**

| Type or member | Purpose |
|----------------|---------|
| `SignedTokenService` | `(keyRing)` or `(keyRing, options)`. `Create(purpose, subject, lifetime)`, `Validate(token, expectedPurpose, out payload)`, `TryValidate`, `ConsumeAsync(token, expectedPurpose, store, cancellationToken)` for single use, `CurrentKeyId`. `CurrentVersion` 1, `MaxPurposeLength` 256, `NonceLength` 16. |
| `SignedTokenOptions` | `Clock` (default `DateTimeOffset.UtcNow`), `ClockSkew` (default 30 seconds; at most `MaxClockSkew`, 1 hour), `MaxTokenLength` (default 1024; 256 to 16384), `MaxSubjectBytes` (default 512; 1 to 4096), `MaxLifetime` (default 30 days). |
| `SignedTokenStatus` | `Valid`, `Expired`, `InvalidSignature`, `WrongPurpose`, `Malformed`, `UnknownKey`, `NotYetValid`, `AlreadyUsed`. |
| `SignedTokenPayload` | `Version`, `KeyId`, `Purpose`, `Subject`, `IssuedAt`, `ExpiresAt`, `Nonce`. Signed, not encrypted. |
| `SignedTokenResult` | Result of `ConsumeAsync`: `Status`, `IsValid`, `Payload`. |
| `IUsedTokenStore` | `TryMarkUsedAsync(nonce, retainUntil, cancellationToken)`; must be atomic across servers. |
| `InMemoryUsedTokenStore` | Single-process store. Constructor `(clock = null)`; `TryMarkUsed`, `TryMarkUsedAsync`, `Contains`, `Purge`, `Count`, `PurgeGrace` (5 minutes). |

**Helpers**

| Type or member | Purpose |
|----------------|---------|
| `SecureRandomString` | `Generate(length)` (base62) and `Generate(length, alphabet)`, `GetEntropyBits(length, alphabetLength)`. Alphabets `Base62`, `UrlSafe`, `Hex`, `Digits`, `LowercaseAlphanumeric`, `Crockford32`. `MaxLength` 1,048,576, `MaxAlphabetLength` 256. |
| `Base62` | `Alphabet`, `Encode`, `TryDecode`, `GetEncodedLength`, `IsBase62`, `MaxByteLength` (1024). |
| `Crc32` | `Compute` over bytes, a byte range `(data, offset, count)` or the UTF-8 of a string. |

## Masterly.Hash.BlindIndex

Keyed, truncated HMAC indexes for searching encrypted columns by equality. Namespaces: `Masterly.Hash.BlindIndex`, `Masterly.Hash.BlindIndex.Normalizers`. Guide: [Blind indexes](./blind-indexes.md).

| Type or member | Purpose |
|----------------|---------|
| `IBlindIndexer` / `BlindIndexer` | `CurrentKeyId`, `KeyIds`, `Compute`, `ComputeWithKey`, `ComputeAll`, `ComputeCompound`, `ComputeCompoundAll`, `Matches` (constant time, never throws), `NeedsReindex`. `BlindIndexer` adds constructors `(currentKeyId, keys)` and `(keyId, key)`, `FromBase64`, `GenerateKey()`, `TryGetKeyId`, `MinKeyLength` (32), `MaxIndexNameLength` (128). |
| `BlindIndexOptions` | `OutputBits` (default `DefaultOutputBits`, 64; a multiple of 8 from `MinOutputBits` 16 to `MaxOutputBits` 256) and `Normalizer` (default `Exact`). `IsValidOutputBits`. |
| `BlindIndexMath` | `ExpectedFalsePositivesPerQuery`, `ExpectedCollidingPairs`, `MinimumOutputBits(distinctValues, maxFalsePositivesPerQuery)`. |
| `IBlindIndexNormalizer` | `Normalize(value)`. Must be deterministic and culture-independent. |
| `BlindIndexNormalizers` | Built-in instances: `Exact`, `Trim`, `CaseInsensitive`, `Email`, `Phone`. |
| `ExactNormalizer`, `TrimNormalizer`, `CaseInsensitiveNormalizer` | No change; trim white space; NFKC plus invariant lower-casing. |
| `EmailNormalizer` | `(stripPlusTags = false, stripGmailDots = false)`; `StripPlusTags`, `StripGmailDots`. |
| `PhoneNormalizer` | `(defaultCountryCode = null)`; `DefaultCountryCode`. Digits only; not a full E.164 parser. |

## Masterly.Hash.Integrity

Streaming content hashes, RFC 9162 Merkle trees, keyed hash chains and directory manifests. Namespace: `Masterly.Hash.Integrity`. Guides: [Integrity](./integrity.md), [Merkle trees and hash chains](./merkle-trees-and-hash-chains.md).

**Content hashes**

| Type or member | Purpose |
|----------------|---------|
| `ContentHashAlgorithm` | `Sha256` (the default), `Sha384`, `Sha512`, `HmacSha256(keyId, key)`; `Name`, `DigestLength`, `KeyId`, `IsKeyed`, `Identifier`, `CreateDigest()`; `Register`, `RegisterKeyedFamily`, `TryGet`, `IsRegistered`. `MinHmacKeyLength` 32. |
| `ContentHash` | Canonical `sha256:<hex>` or `hmac-sha256:<keyId>:<hex>`. Constructor `(algorithm, digest)`; `Algorithm` (the name), `KeyId`, `IsKeyed`, `Digest`, `ToArray`, `ToHex`, `IsFrom`, `Parse`, `TryParse`. Equality is constant time. `MaxStringLength` (322). |
| `ContentHashJsonConverter` | Serializes a `ContentHash` as its canonical string. |
| `ContentHasher` | `Compute` (bytes or stream), `ComputeAsync`, `ComputeFileAsync`, `Verify`, `VerifyAsync`, `VerifyFileAsync`. `BufferSize` 64 KiB. |
| `ContentDigest` | Abstract incremental computation: `Append`, `GetHashAndReset`, `Dispose`. Subclass it for a custom algorithm by overriding `AppendCore` and `GetHashAndResetCore`. |

**Merkle trees and hash chains**

| Type or member | Purpose |
|----------------|---------|
| `MerkleTree` | `Build`, `FromLeafHashes`, `EmptyRoot`, `HashLeaf`, `HashChildren`, `Algorithm`, `Size`, `Root`, `RootHash`, `GetLeafHash`, `GetRoot(treeSize)`, `GetInclusionProof`, `GetConsistencyProof`, `VerifyInclusion`, `VerifyInclusionOfLeafHash`, `VerifyConsistency`. `MaxProofLength` 128. |
| `HashChain` | `GenesisHash`, `ComputeEntryHash`, `CreateNext(previous, payload, algorithm)`, `Verify(entries, ...)` with optional anchor and expected-head checkpoints. Never throws on bad entries. |
| `HashChainLog` | In-memory chain: `()`, `(algorithm)`, `(algorithm, existing)`; `Algorithm`, `Count`, `Entries`, `Head`, `Append`, `Verify`. |
| `HashChainEntry` | `Sequence`, `PreviousHash`, `Payload`, `Hash`, `ToCheckpoint()`. |
| `HashChainCheckpoint` | `(sequence, hash)`: `Sequence`, `Hash`. Store it out of the attacker's reach. |
| `HashChainVerificationResult` | `IsValid`, `EntriesVerified`, `FirstBrokenIndex`, `BrokenSequence`, `Failure`, `Reason`, `Head`. |
| `HashChainFailure` | `None`, `Gap`, `Reorder`, `Duplicate`, `PreviousHashMismatch`, `HashMismatch`, `InvalidEntry`, `Truncated`, `HeadMismatch`. |

**Directory manifests**

| Type or member | Purpose |
|----------------|---------|
| `DirectoryManifest` | `CreateAsync`, `VerifyAsync` (optionally against a trusted root), `Compare`, `FromEntries`, `IsIntact`, `ToMerkleTree`, `EncodeLeaf`, `ToJson`, `FromJson`, `TryFromJson`; `Algorithm`, `KeyId`, `Entries`, `Root`. `FormatId` `masterly-manifest/v1`. |
| `DirectoryManifestEntry` / `DirectoryManifestEntryKind` | `Path`, `Length`, `Hash`, `Kind` (`File`, `Link`); `IsCanonicalPath`; `MaxPathLength` 4096. |
| `DirectoryManifestOptions` | `Filter`, `FollowReparsePoints` (default `false`), `MaxDepth` (default 64), `MaxEntries` (default 1,000,000). |
| `DirectoryManifestDiff` | `ManifestIntact`, `Added`, `Removed`, `Modified`, `IsMatch`. |

## Masterly.Hash.Integrity.Blake3

BLAKE3 for the Integrity package, using the managed `Blake3` NuGet package. Namespace: `Masterly.Hash.Integrity.Blake3`. Guide: [Integrity](./integrity.md).

| Type or member | Purpose |
|----------------|---------|
| `Blake3Algorithms.Blake3` | Plain BLAKE3, `blake3:<hex>`, 32-byte output. |
| `Blake3Algorithms.Keyed(keyId, key)` | Keyed BLAKE3 (a MAC), `blake3-keyed:<keyId>:<hex>`. The key must be exactly `KeyLength` (32) bytes. |
| `Blake3Algorithms.Register()` | Makes `blake3` and `blake3-keyed` parseable before any BLAKE3 hash is computed. Idempotent and thread-safe. |
| `Name`, `KeyedName`, `DigestLength`, `KeyLength` | `"blake3"`, `"blake3-keyed"`, 32, 32. |

## Masterly.Hash.Detection

Honeywords, honey accounts and credential-stuffing detection. Namespace: `Masterly.Hash.Detection`. Guide: [Attack detection](./attack-detection.md).

**Honeywords**

| Type or member | Purpose |
|----------------|---------|
| `HoneywordService` | `(PasswordHasher hasher, options)` or `(defaultProfile, allowedProfiles, options)`. `Create`, `CreateAsync`, `Verify` (index or -1), `VerifyDetailed`, `VerifyDetailedAsync`, `VerifyOrDummy`, `VerifyOrDummyAsync`, `IsHoneywordHash`, `DefaultProfile`, `Profiles`, `Generator`. `DefaultSweetwordCount` 20, `MinSweetwordCount` 2, `MaxSweetwordLimit` 1000. |
| `HoneywordServiceOptions` | `Generator` (default `TweakingHoneywordGenerator.Default`), `Pepper`, `MaxSweetwordCount` (default 100), `MaxPasswordBytes` (default 1024), `MaxConcurrency` (default processor count), `ConcurrencyTimeout` (default 30 seconds), `AllowWeakProfiles`. |
| `HoneywordRecord` | `StoredHash` (`$mhw$...`), `RealIndex` (send only to the honeychecker), `SweetwordCount`. |
| `HoneywordVerification` / `HoneywordVerificationStatus` | `Status`, `Index`, `IsSweetwordMatch`. Statuses: `Mismatch`, `SweetwordMatch`, `NoStoredHash`, `MalformedHash`, `UnknownProfile`, `UnknownPepperKey`, `EmptyPassword`, `PasswordTooLong`, `InvalidPassword`. |
| `HoneywordLoginService` | Ties the service to a honeychecker. Constructors `(honeywords, honeychecker)` and `(honeywords, honeychecker, clock)`; `RegisterAsync(userId, password, sweetwordCount = 20, cancellationToken)`, `LoginAsync(userId, password, storedHash, cancellationToken)`, event `BreachDetected`. |
| `HoneywordLoginResult` / `HoneywordLoginOutcome` | `Outcome` (`Mismatch`, `Success`, `BreachDetected`), `IsSuccess`, `Verification`. |
| `HoneywordBreachDetectedEventArgs` | `UserId`, `SweetwordIndex`, `DetectedAt`. |
| `IHoneychecker` | `SetAsync(userId, index, cancellationToken)`, `IsRealAsync(userId, index, cancellationToken)`. Run it on a separate system. |
| `InMemoryHoneychecker` | For tests and single-process demos: `Count`, `Remove`. |
| `IHoneywordGenerator` | `GenerateDecoys(realPassword, count)`. |
| `PasswordModelHoneywordGenerator` | Recommended. `Default`, `()`, `(words)`, `WordCount`. |
| `TweakingHoneywordGenerator` | Tail-tweaking from the paper. `Default`, `(tailLength = 3, tweakCase = false)`, `DefaultTailLength` (3), `TailLength`, `TweakCase`. |

**Honey accounts and stuffing**

| Type or member | Purpose |
|----------------|---------|
| `HoneyAccountRegistry` | Decoy accounts. Constructors `()`, `(accounts)`, `(accounts, clock)`; `Add`, `Remove`, `IsHoneyAccount`, `CheckLogin(account, context)`, `Count`, event `HoneyAccountAccessed`. `MaxAccountLength` 1024. |
| `HoneyAccountAccessedEventArgs` | `Account`, `Context`, `Timestamp`. |
| `CredentialStuffingDetector` | Constructors `()` and `(options)` (copied). `RecordFailedLogin(account, password)` (also `SensitiveString`), `IsFlagged(password)`, `GetSnapshot()`, `Reset()`, `Dispose()`, event `StuffingDetected`; `DistinctAccountThreshold`, `Window`, `TrackedFingerprintCount`, `EvictedCount`, `WindowStart`. `FingerprintLength` 16. |
| `CredentialStuffingOptions` | `Window` (default 10 minutes), `DistinctAccountThreshold` (default 20), `MaxTrackedFingerprints` (default 100,000), `MaxPasswordLength` (default 4096), `MaxAccountLength` (default 1024), `Clock`. |
| `CredentialStuffingDetectedEventArgs` | `FingerprintId`, `DistinctAccountCount`, `WindowStart`, `WindowEnd`, `DetectedAt`. |
| `FingerprintStatistics` | `FingerprintId`, `DistinctAccountCount`, `IsFlagged`. |

## Masterly.Hash.Analyzers

Roslyn analyzers and code fixes. All diagnostics have category `Security` and link to `docs/analyzers/MH000x.md`. The ids are public constants on `Masterly.Hash.Analyzers.DiagnosticIds`: `FastHashOnPassword`, `NonConstantTimeComparison`, `HardCodedPepper`, `PasswordLogged`, `WeakPbkdf2`, `ObsoleteApi`. Guide: [Analyzers](./analyzers.md).

| Id | Title | Default severity | Code fix |
|----|-------|------------------|----------|
| MH0001 | Fast hash used on a password | Warning | Use Masterly.Hash.Password.Hash |
| MH0002 | Non-constant-time comparison of secrets | Warning | Use CryptographicOperations.FixedTimeEquals |
| MH0003 | Hard-coded pepper or key | Warning | None |
| MH0004 | Password may be logged | Warning | None |
| MH0005 | Weak PBKDF2 parameters | Warning | None |
| MH0006 | Obsolete Masterly.Hash 1.x API | Info | Use Masterly.Hash.Password.Hash |

## Masterly.Hash.Tool

The `masterly-hash` .NET global tool. Guide: [Command-line tool](./command-line-tool.md).

| Command | Purpose |
|---------|---------|
| `hash` | Hash a password from a no-echo prompt (asked twice) or `--stdin`. |
| `verify` | Verify a password against a stored hash. |
| `inspect` | Describe a stored hash: format, profile, pepper key, wrapping, rehash. |
| `audit` | Count formats, profiles, weak, needs-rehash and duplicate hashes. |
| `wrap` | Onion-wrap legacy hashes in one CSV column, streaming. |
| `bench` | Time each built-in profile on this machine (median of 5 runs). |
| `policy` | Check a password against the NIST SP 800-63B policy. |
| `pepper generate` | Print a new random 32-byte pepper key, base64-encoded. |
| `apikey generate` | Print a new API key and its lookup hash. |

Exit codes: 0 success, 1 a negative answer (mismatch, rejected, not recognized), 2 error, 130 cancelled.

## Masterly.Hash.Testing

Test helpers. Reference this package from test projects only. Namespace: `Masterly.Hash.Testing`. Guide: [Testing](./testing.md).

| Type or member | Purpose |
|----------------|---------|
| `FastPasswordHasher` | An `IPasswordHasher` that delegates to a real `PasswordHasher` (`Inner`) whose default is the `test-fast` profile (Argon2id, m = 64 KiB, t = 1, p = 1). Constructors `()` and `(configure)`; `Shared`, `Inner`, `DefaultProfile`, `Profiles`, `CreateOptions(configure)`, `ProfileId` (`"test-fast"`), `Profile`. Its hashes fail with `UnknownProfile` in production; it still accepts the built-in profiles. |
| `RecordingPasswordHasher` | A decorator that records calls. Constructors `()` (over a new `FastPasswordHasher`) and `(inner)`; `Inner`, `Calls`, `LastCall`, `RehashesIssued`, `UsedDummyVerification`, `CallsOf`, `Count`, `CallsWithPassword`, `Fingerprint`, `Clear`. |
| `PasswordHasherCall` / `PasswordHasherOperation` | One recorded call: `Sequence`, `Operation` (`Hash`, `Verify`, `VerifyOrDummy`, `NeedsRehash`, `Inspect`, `TryWrap`), `IsAsync`, `PasswordFingerprint`, `StoredHash`, `ProfileId`, `Result`, `Status`, `ProducedHash`, `BooleanResult`, `Info`, `Exception`, `IsUnknownUser`. |
| `FakePepper` | Deterministic `IPasswordPepper` with public keys: `()`, `(currentKeyId, otherKeyIds)`, `KeyFor`, `AddKey`, `RotateTo`, `RetireKey`, `ResetCounters`, `KeyIds`, `ApplyCount`, `ApplyAsyncCount`, `KeyIdsUsed`, `AsyncDelay`, `ForceAsynchronous`, `ThrowOnApply`. `DefaultKeyId` `"test-key"`. |
| `KnownHashes` | Sample hashes of `Password` (`"correct horse battery staple"`; `WrongPassword` differs in case only), with `PepperKeyId` (`"test-key"`), `MhSalt` and `V1Salt`: `V1Sha512`, `V1Sha384`, `V1Sha256`, `TestFast`, `TestFastPeppered`, `TestFastWrappedV1Sha512`, `Server2026a`, `Constrained2026a`, `Fips2026a`, plus `UnknownProfile`, `Malformed`, `UnknownFormat`. Builders `Create`, `CreateV1`, `CreateWrappedV1`. |
| `MasterlyHashAssert` | Framework-agnostic assertions: `IsMasterlyHash`, `UsesProfile`, `IsPeppered`, `IsNotPeppered`, `NeedsRehash`, `DoesNotNeedRehash`, `Verifies`, `DoesNotVerify`, `IsNotPlaintext`, `UsedVerifyOrDummyForUnknownUser`, `PersistedRehash`. |
| `MasterlyHashAssertionException` | Thrown when an assertion fails. |

## See also

- [Overview](./overview.mdx)
- [Installation](./installation.md)
- [The $mh$ hash format](./hash-format.md)
- [Threat model](./threat-model.md)
