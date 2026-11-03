---
title: "Roslyn Analyzers"
sidebar_label: "Analyzers"
description: "Six compile-time rules, MH0001 to MH0006, that catch fast password hashes, timing leaks, hard-coded keys, logged passwords, weak PBKDF2 and the 1.x API."
---

`Masterly.Hash.Analyzers` adds six Roslyn rules that flag password-hashing mistakes while you type and when you build. Three of them come with a code fix. This page covers installation, configuration, how the rules decide what a password or secret is, and each rule in detail.

## Installing

```bash
dotnet add package Masterly.Hash.Analyzers
```

- **Development dependency.** The package contains only an analyzer assembly (under `analyzers/dotnet/cs`). It adds nothing to your build output, and projects that reference yours do not inherit it.
- **Requirements.** The .NET 8 SDK, or Visual Studio 2022 17.8 or later (Roslyn 4.8 or later). The rules analyze C# only.
- **Works without the runtime package.** You can install it in a project that does not reference `Masterly.Hash`. A few behaviours depend on which types the compilation can see:

| Rule | Without `Masterly.Hash` | With `Masterly.Hash` |
|------|-------------------------|----------------------|
| MH0001 | Reports, no code fix | Reports, and offers the `Password.Hash` fix |
| MH0003 | Checks names (`pepper`, `signingKey`, ...) | Also checks `HmacPepper` constructor and `HmacPepper.FromBase64` arguments |
| MH0004 | Checks password-named values | Also flags `SensitiveString.Reveal()` results |
| MH0006 | Inactive (there is no 1.x API to call) | Reports calls to the 1.x `ComputeHash` |

- **Generated code is skipped.** Files the compiler treats as generated are not analyzed.
- **Read-only.** The analyzers read your syntax trees and symbols. They do not run code, read files or use the network.

## Rules at a glance

| Rule | Title | Default severity | Code fix |
|------|-------|------------------|----------|
| [MH0001](#mh0001-fast-hash-used-on-a-password) | Fast hash used on a password | Warning | Yes: `Password.Hash(x)` |
| [MH0002](#mh0002-non-constant-time-comparison-of-secrets) | Non-constant-time comparison of secrets | Warning | Yes: `CryptographicOperations.FixedTimeEquals` |
| [MH0003](#mh0003-hard-coded-pepper-or-key) | Hard-coded pepper or key | Warning | No |
| [MH0004](#mh0004-password-may-be-logged) | Password may be logged | Warning | No |
| [MH0005](#mh0005-weak-pbkdf2-parameters) | Weak PBKDF2 parameters | Warning | No |
| [MH0006](#mh0006-obsolete-masterlyhash-1x-api) | Obsolete Masterly.Hash 1.x API | Info | Yes: `Password.Hash(plainText)` |

Every rule is in the `Security` category and is enabled by default. Each diagnostic's help link opens the rule's page under [docs/analyzers](https://github.com/a7mdfre7at/Masterly.Hash/blob/master/docs/analyzers/MH0001.md) in the repository. The IDs are also available as constants on `Masterly.Hash.Analyzers.DiagnosticIds` (`FastHashOnPassword`, `NonConstantTimeComparison`, `HardCodedPepper`, `PasswordLogged`, `WeakPbkdf2`, `ObsoleteApi`).

## Configuring severity

Set severities in `.editorconfig`, like any Roslyn rule:

```ini title=".editorconfig"
[*.cs]
# Fail the build when a password reaches a log.
dotnet_diagnostic.MH0004.severity = error

# Surface 1.x API calls in build output, not only in the IDE.
dotnet_diagnostic.MH0006.severity = warning
```

The accepted values are `error`, `warning`, `suggestion`, `silent` and `none`. To fail CI on any of the rules without changing their severity, list them in the project file:

```xml title="MyApp.csproj"
<PropertyGroup>
  <WarningsAsErrors>$(WarningsAsErrors);MH0001;MH0002;MH0003;MH0004;MH0005</WarningsAsErrors>
</PropertyGroup>
```

:::tip

MH0006 is `Info` by default because the 1.x API still works and its hashes still verify. Info diagnostics never fail a build and are easy to miss. Raise MH0006 to `warning` while you migrate, so every remaining call shows up in CI.

:::

## Suppressing a diagnostic

The rules are heuristics, so they can report code that is fine. Prefer the first option that applies:

1. **Rename the symbol.** MH0001, MH0002, MH0003 and MH0004 match on names (see [How names are matched](#how-names-are-matched)). A variable called `password` that holds a password hash is better named `passwordHash` anyway.
2. **Suppress one occurrence** with a pragma and a comment that says why:

   ```csharp
   // 'pin' is a map pin, not a PIN; its title is public data.
   #pragma warning disable MH0001
   byte[] titleDigest = SHA256.HashData(Encoding.UTF8.GetBytes(pin.Title));
   #pragma warning restore MH0001
   ```

3. **Suppress for a member or type** with `SuppressMessage` (from `System.Diagnostics.CodeAnalysis`):

   ```csharp
   [SuppressMessage("Security", "MH0003:Hard-coded pepper or key", Justification = "Deterministic key for a snapshot test.")]
   private static readonly byte[] TestPepper = Convert.FromBase64String("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=");
   ```

4. **Turn a rule off for a folder** in `.editorconfig`, for example for test fixtures:

   ```ini title=".editorconfig"
   [tests/**.cs]
   dotnet_diagnostic.MH0003.severity = none
   ```

## How names are matched

A password is just a `string`, so MH0001, MH0002, MH0003 and MH0004 decide what is a password or a secret from the name of the local, parameter, field, property or method involved.

**Splitting names into words.** A name is split at camelCase and PascalCase humps, underscores and digits, then lower-cased: `userPassword` becomes user + password, `HTTPToken` becomes http + token, `pwd_2` becomes pwd. A pattern matches when one to three consecutive words spell it, so `apiKey`, `ApiKey` and `api_key` all spell `apikey`. Matching is on whole words: `spinner`, `pinned` and `opinion` never match `pin`.

**The three word lists.**

| Matcher | Used by | Patterns |
|---------|---------|----------|
| Password | MH0001, MH0004 | `password`, `passwd`, `pwd`, `passphrase`, `pin` |
| Secret | MH0002 | `hash`, `hashed`, `digest`, `mac`, `hmac`, `signature`, `token`, `apikey`, `secret` |
| Key | MH0003 | `pepper`, `hmackey`, `secretkey`, `signingkey` |

**Qualifier words.** A match that is followed, anywhere later in the name, by a qualifier word describes metadata about the secret, not the secret itself, and does not count. `passwordPolicy`, `maxPasswordLength`, `passwordSaltBytes`, `tokenType`, `hashAlgorithm`, `macAddress`, `pepperKeyId` and `GetHashCode` are all ignored. The qualifiers are:

- **Password:** policy, policies, length, len, rule, rules, hint, hints, strength, option, options, settings, config, configuration, requirement, requirements, validator, validation, regex, pattern, expiry, expiration, expires, expired, age, count, attempt, attempts, field, label, prompt, placeholder, token, reset, changed, date, time, timestamp, version, format, id, min, max, salt, iterations, enabled, required, history, error, errors, message, type, mode, provider, hasher, hash, hashed, hashes, manager, service, url, uri, path, file, name, visible, visibility, char, chars, encrypted, salted, digest, mac.
- **Secret:** algorithm, algorithms, alg, name, names, type, types, kind, length, len, size, count, id, code, set, table, map, provider, options, settings, address, expiry, expiration, expires, lifetime, header, prefix, format, version, mode, field, label, url, uri, endpoint, path, file, enabled, required, scheme, policy, handler, service, manager, factory, builder, generator, validator, parameters, params, status, state, source, location, claim, claims.
- **Key:** id, ids, name, names, length, len, size, path, file, options, provider, version, env, variable, config, configuration, setting, settings, location, uri, url, count, enabled, required, section, store, vault.

**Prefix qualifiers (passwords only).** A password word that comes after `hashed`, `encrypted`, `salted`, `masked` or `redacted` names a stored hash or ciphertext, so `hashedPassword` (the ASP.NET Core Identity name for the stored hash) and `encryptedPassword` do not match.

The lists are independent. `passwordResetToken` is not a password (`token` is a password qualifier), but it is a secret for MH0002, because `token` is the last word. `storedPasswordHash` is not a password, but it is a secret. That is usually what you want: you should not hash a reset token like a password, but you should compare it in constant time.

:::note

These rules find common mistakes. They do not prove code secure. A password that reaches a hash or a log through a differently named variable, a collection or another method is not followed.

:::

## MH0001: Fast hash used on a password

| Property | Value |
|----------|-------|
| Id | `MH0001` |
| Default severity | Warning |
| Code fix | Yes, in the cases described below |

**What it flags.** A general-purpose hash or MAC applied to a password-named value:

- the static `HashData`, `TryHashData` and `HashDataAsync` methods of `MD5`, `SHA1`, `SHA256`, `SHA384`, `SHA512`, `SHA3_256`, `SHA3_384`, `SHA3_512`, `HMACMD5`, `HMACSHA1`, `HMACSHA256`, `HMACSHA384`, `HMACSHA512`, `HMACSHA3_256`, `HMACSHA3_384` and `HMACSHA3_512`;
- `ComputeHash`, `TryComputeHash` and `ComputeHashAsync` on any `HashAlgorithm`, including one returned by a factory;
- `new HMACSHA256(...)` and every other HMAC constructor, when the key argument is password-named (the password used as an HMAC key).

The rule looks at every input argument, and at everything inside it, so `Encoding.UTF8.GetBytes(salt + password)` matches. It skips output arguments: `out` and `ref` parameters, the `destination` buffer of `HashData(source, destination)` and `cancellationToken`. It also follows one step through a local: `byte[] bytes = Encoding.UTF8.GetBytes(password);` followed by `SHA256.HashData(bytes)` is reported.

The message reads: `'SHA256' is a fast hash and must not be used on the password 'password'; use Masterly.Hash.Password.Hash`.

**Why it matters.** MD5, SHA-1, SHA-2, SHA-3 and HMAC are built to be fast. A single GPU computes billions of SHA-256 hashes per second, so a leaked table of salted SHA-256 password hashes falls to a dictionary attack in hours. Passwords need a deliberately slow, memory-hard function such as Argon2id.

**Bad:**

```csharp
string stored = Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(password)));
```

**Good:**

```csharp
using Masterly.Hash;

string stored = Password.Hash(password);                                    // Argon2id, random salt
PasswordVerificationResult result = Password.Verify(password, stored);      // constant-time
```

**The code fix.** "Use Masterly.Hash.Password.Hash" rewrites the hashing expression to `Password.Hash(x)`, where `x` is the string passed to `Encoding.X.GetBytes`, and adds `using Masterly.Hash;` when needed. It applies when all of these hold:

1. The project references `Masterly.Hash` (so `Password.Hash(string)` exists).
2. The hash call has exactly one argument, and that argument is `Encoding.X.GetBytes(x)` with one argument. `TryHashData` and `TryComputeHash` are never rewritten.
3. The result is consumed as a string or an implicitly typed local: wrapped in `Convert.ToBase64String`, `Convert.ToHexString`, `Convert.ToHexStringLower` or `BitConverter.ToString`, or assigned to a `var` local.
4. The hash is not keyed. Rewriting `HMACSHA256` or any other `KeyedHashAlgorithm` would silently drop the key.
5. The value only flows into storage: it is returned from a method or property, assigned to a field, property or local, or used to initialize one, and every later use of that local is also storage.
6. The rewritten document compiles with no new errors. For example, the fix is not offered when the `var` local is later used as a `byte[]`.

The fix is **not** offered when the value is compared (`stored == Convert.ToBase64String(...)`, `stored.Equals(...)`, `string.Compare(...)`), passed to another call (a pre-hash fed to another hasher, a database query), returned from a lambda or local function, or held in a local that is used in one of those ways. `Password.Hash` uses a fresh random salt, so on the verification side the rewrite would compile but never match again. Replace that code by hand with `Password.Verify(password, stored).IsMatch`.

:::warning

The fix changes the stored format. Hashes that the old code already wrote do not convert themselves. Keep verifying them with the old algorithm, or register them as a legacy format, and store the new hash after the next successful login. See [Legacy formats](./legacy-formats.md) and [Onion wrapping](./onion-wrapping.md). If a method that returns the hash is also used on the login path (`HashPassword(input) == user.PasswordHash`), change those callers to `Password.Verify` at the same time.

:::

**How to suppress.** If the value is not a password, rename it. Otherwise use `#pragma warning disable MH0001` with a comment that says why.

## MH0002: Non-constant-time comparison of secrets

| Property | Value |
|----------|-------|
| Id | `MH0002` |
| Default severity | Warning |
| Code fix | Yes, for byte `SequenceEqual` in the cases described below |

**What it flags.** A secret-named value (see the Secret patterns in [How names are matched](#how-names-are-matched)) compared with an early-exit comparison:

- `==` and `!=` between two strings;
- `string.Equals` (static and instance), `string.Compare` and `string.CompareOrdinal`;
- `Enumerable.SequenceEqual` and `MemoryExtensions.SequenceEqual` on `byte` or `char` sequences.

The rule looks through value-preserving calls, up to three levels deep: `ToBase64String`, `ToHexString`, `ToHexStringLower`, `GetString`, `GetBytes`, `ToString`, `AsSpan`, `AsMemory`, `ToArray`, `ToCharArray`, `Trim`, `TrimStart`, `TrimEnd`, `ToLower`, `ToLowerInvariant`, `ToUpper` and `ToUpperInvariant`. So `Convert.ToBase64String(mac) == header` and `token.Trim() == expected` are both reported. It also handles `mac?.SequenceEqual(other)`.

It does not report:

- comparisons with `null`, `default`, `""`, `string.Empty` or `Array.Empty<T>()` (`hash == null`, `token != ""`);
- numeric comparisons such as `hash.Length == 32`;
- names where the secret word is followed by a qualifier: `hashAlgorithm`, `tokenType`, `signatureScheme`, `macAddress`, `secretName`, `apiKeyHeader`;
- non-word matches such as `hashtag`, `machine` and `tokenizer`.

**Why it matters.** These comparisons return as soon as they find a difference, so the time they take reveals how many leading bytes of a guess are right. Over many requests an attacker can recover a valid MAC, API key or reset token byte by byte.

**Bad:**

```csharp
if (computedMac.SequenceEqual(expectedMac))
{
    // accept the request
}
```

**Good:**

```csharp
using System.Security.Cryptography;

if (CryptographicOperations.FixedTimeEquals(computedMac, expectedMac))
{
    // accept the request
}
```

**The code fix.** "Use CryptographicOperations.FixedTimeEquals" rewrites `a.SequenceEqual(b)` to `CryptographicOperations.FixedTimeEquals(a, b)` and adds `using System.Security.Cryptography;` when needed. It applies when all of these hold:

1. The target framework has `System.Security.Cryptography.CryptographicOperations.FixedTimeEquals` (.NET Core 2.1 or later, .NET Standard 2.1 or later).
2. The elements are `byte`, and both operands are `byte[]`, `Span<byte>` or `ReadOnlySpan<byte>`.
3. There are exactly two explicit arguments (no comparer overload).
4. It is not a conditional call such as `a?.SequenceEqual(b)`, which returns `bool?`.
5. For `Enumerable.SequenceEqual` on arrays, nullable flow analysis proves both operands non-null: the nullable context is enabled, there is no `!` suppression on the operand, and the flow state is not-null (non-nullable parameters, results of `HashData`, values after an `is null` check). `MemoryExtensions.SequenceEqual` already works on spans, so its fix has no such condition.
6. The rewritten document compiles with no new errors.

Condition 5 exists because `FixedTimeEquals` treats a `null` array as an empty span, while `Enumerable.SequenceEqual` throws on `null`. A blind rewrite could turn a failing comparison into a passing one, for example a missing cached MAC compared with an empty header, which is an authentication bypass. In nullable-oblivious code, or for `byte[]?` operands, add the null check yourself:

```csharp
if (expectedMac is null || providedMac is null)
{
    return false;
}

return CryptographicOperations.FixedTimeEquals(expectedMac, providedMac);
```

**Strings.** There is no fix for string comparisons. Compare bytes instead:

```csharp
bool tokensMatch = CryptographicOperations.FixedTimeEquals(
    Encoding.UTF8.GetBytes(providedToken),
    Encoding.UTF8.GetBytes(expectedToken));
```

`FixedTimeEquals` returns `false` at once when the lengths differ, so it reveals the length but not the content. That is fine for fixed-length MACs and hashes. For password hashes use `Password.Verify`, which already compares in constant time. For API keys and signed tokens, `Masterly.Hash.Tokens` does the comparison for you; see [API keys and tokens](./api-keys-and-tokens.md).

**How to suppress.** If the value is not a secret, rename it, for example `tokenCount` or `hashAlgorithmName`. Otherwise use `#pragma warning disable MH0002` with a comment.

## MH0003: Hard-coded pepper or key

| Property | Value |
|----------|-------|
| Id | `MH0003` |
| Default severity | Warning |
| Code fix | No |

**What it flags.** A compile-time constant used where a secret key belongs:

- as key material passed to a `Masterly.Hash.Pepper.HmacPepper` constructor or to `HmacPepper.FromBase64`, including values inside an inline dictionary initializer;
- assigned to, or used to initialize, a local, field or property named `pepper`, `hmacKey`, `secretKey` or `signingKey`;
- returned from a property or method with such a name (`static byte[] Pepper => Convert.FromBase64String("...");`, `string GetSigningKey() { return "..."; }`). A `return` inside a lambda or local function is not attributed to the containing member.

A value counts as hard-coded when it is one of these:

- a non-empty string literal or `const`;
- a `new byte[] { ... }` whose elements are all constants, or a collection expression of literals;
- a non-empty `"..."u8` literal;
- `Convert.FromBase64String`, `Convert.FromHexString` or `Encoding.X.GetBytes` applied to one of those, or `.ToArray()` on one of those;
- a fallback that is hard-coded: `Environment.GetEnvironmentVariable("PEPPER") ?? "dev-pepper"`, or either branch of `isDevelopment ? "dev-key" : fromConfig`.

A zero-filled `new byte[32]` passed directly to `HmacPepper` is also reported. It is an all-zero key that is long enough to pass the 32-byte `HmacPepper.MinKeyLength` check. A local named `pepper` created as `new byte[32]` is not reported, because it is normally filled with random bytes on the next line.

Key ids such as `"k1"` are identifiers, not secrets, and are ignored. So are empty strings, names ending in a qualifier (`pepperKeyId`, `signingKeyName`, `secretKeyPath`) and names that merely contain the pattern (`peppermint`).

**Why it matters.** A pepper only helps if it is stored somewhere other than the database. A key compiled into the binary is visible in source control, in build artifacts and to anyone who decompiles the application, and you cannot rotate it without a release.

**Bad:**

```csharp
HmacPepper pepper = new HmacPepper("k1", Convert.FromBase64String("c2VjcmV0LXBlcHBlci1rZXktZG8tbm90LXNoaXAtaXQ="));
```

**Good:**

```csharp title="Program.cs"
using Masterly.Hash.Pepper;

// The key comes from configuration: user secrets in development, the environment or a vault in production.
string currentKey = builder.Configuration["Pepper:k1"]
    ?? throw new InvalidOperationException("Pepper:k1 is not configured.");

HmacPepper pepper = HmacPepper.FromBase64("k1", new Dictionary<string, string> { ["k1"] = currentKey });
```

Generate a key with `HmacPepper.GenerateKey()` or `masterly-hash pepper generate` (see [Command-line tool](./command-line-tool.md#pepper-generate)). To keep the key out of the application entirely, use [HashiCorp Vault](./hashicorp-vault.md), [AWS KMS](./aws-kms.md) or [Azure Key Vault](./azure-key-vault.md). See [Peppers](./peppers.md) for rotation.

**How to suppress.** Tests are the usual exception. Instead of suppressing, use `FakePepper` from `Masterly.Hash.Testing` (see [Testing](./testing.md#fakepepper)), or generate a key inside the test with `HmacPepper.GenerateKey()`.

## MH0004: Password may be logged

| Property | Value |
|----------|-------|
| Id | `MH0004` |
| Default severity | Warning |
| Code fix | No |

**What it flags.** A password-named `string` or `char[]` value, or the result of `SensitiveString.Reveal()`, passed to a log sink:

| Sink type | Methods |
|-----------|---------|
| `Microsoft.Extensions.Logging.LoggerExtensions` | every `Log*` method, `BeginScope` |
| `Microsoft.Extensions.Logging.ILogger` | `Log`, `BeginScope` |
| `System.Console` | `Write`, `WriteLine` |
| `System.Diagnostics.Debug`, `System.Diagnostics.Trace` | every `Write*` and `Trace*` method, `Print`, `Fail` |

The rule follows the value through string concatenation (including long `"a" + b + "c" + ...` chains), interpolated strings, `string.Format`, `string.Concat`, `string.Join`, `params` arrays, `?:`, `??`, string methods that return text (`password.Trim()`, `password.ToCharArray()`), and methods named like a password that return text (`GetPassword()`). It reports each password it finds in a call, so one log statement can produce more than one diagnostic.

It ignores non-text values (`password.Length`, `bool isPasswordValid`), names with qualifiers (`passwordPolicy`, `passwordHash`) and a `SensitiveString` itself, which prints as `***`.

**Why it matters.** Logs are copied to aggregators, indexed, backed up and kept for months, and far more people can read them than can read the credential store. A password in a log is a leaked password.

**Bad:**

```csharp
_logger.LogInformation("Login {UserName} {Password}", request.UserName, request.Password);
```

**Good:**

```csharp
_logger.LogInformation("Login attempt for {UserName}", request.UserName);
```

Model request passwords as `SensitiveString`, so accidental logging, serialization and the debugger all show `***`. `Password.Hash` and `Password.Verify` accept a `SensitiveString` directly, so you rarely need `Reveal()`:

```csharp title="LoginRequest.cs"
using Masterly.Hash;

namespace MyApp.Accounts;

public sealed record LoginRequest(string UserName, SensitiveString Password);
```

```csharp
PasswordVerificationResult result = Password.Verify(request.Password, user.PasswordHash);
_logger.LogInformation("Login for {UserName}: {Request}", request.UserName, request);   // Password prints as ***
```

**How to suppress.** There is rarely a good reason. If a value is wrongly taken for a password (a `pin` that is a public map pin, say), rename it.

## MH0005: Weak PBKDF2 parameters

| Property | Value |
|----------|-------|
| Id | `MH0005` |
| Default severity | Warning |
| Code fix | No |

**What it flags.** `new Rfc2898DeriveBytes(...)` or `Rfc2898DeriveBytes.Pbkdf2(...)` called with:

- a **constant** iteration count below **100,000** (`WeakPbkdf2Analyzer.MinimumIterations`);
- `HashAlgorithmName.MD5` or `HashAlgorithmName.SHA1`, or `new HashAlgorithmName("MD5")` or `("SHA1")`, as the PRF;
- a constructor that omits the iteration count (it defaults to **1,000**) or the hash algorithm (it defaults to **HMAC-SHA1**), or both.

All problems are reported in one diagnostic, joined with `;`, for example: `Weak PBKDF2 parameters: this constructor defaults to 1,000 iterations; this constructor defaults to HMAC-SHA1`. Iteration counts that are not compile-time constants, such as values read from configuration, are not reported. On .NET 7 and later the compiler also reports `SYSLIB0041` for the `Rfc2898DeriveBytes` constructors that omit the iteration count or the hash algorithm.

**Why it matters.** The iteration count is PBKDF2's only defence against brute force. The [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2) recommends 600,000 iterations for PBKDF2-HMAC-SHA256, 210,000 for PBKDF2-HMAC-SHA512 and 1,300,000 for PBKDF2-HMAC-SHA1. The 100,000 threshold is a floor that catches clearly broken code, not a recommendation.

**Bad:**

```csharp
using Rfc2898DeriveBytes kdf = new Rfc2898DeriveBytes(password, salt);   // 1,000 iterations of HMAC-SHA1
byte[] key = kdf.GetBytes(32);
```

**Good:**

```csharp
byte[] key = Rfc2898DeriveBytes.Pbkdf2(password, salt, 600_000, HashAlgorithmName.SHA256, 32);
```

For password storage, use `Password.Hash` instead of calling PBKDF2 yourself. It uses Argon2id by default, or PBKDF2-HMAC-SHA512 with 210,000 iterations under the `2026f` profile, and the stored string records which profile was used. See [Profiles](./profiles.md).

**How to suppress.** Only for code that must reproduce an existing format, for example to verify hashes written by another system. Prefer the [legacy formats](./legacy-formats.md), which handle that for you.

## MH0006: Obsolete Masterly.Hash 1.x API

| Property | Value |
|----------|-------|
| Id | `MH0006` |
| Default severity | Info |
| Code fix | Yes, when the call passes only the plaintext |

**What it flags.** A call to the 1.x instance method `ComputeHash` on `Masterly.Hash.Hash`, on a subclass of `Hash`, or on `Masterly.Hash.IHash`.

The 1.x types are also marked `[Obsolete]`, so the compiler reports `CS0618` on the same line. MH0006 adds the reason and, where it is safe, a code fix.

**Why it matters.** The 1.x API hashes with a single salted SHA-256, SHA-384 or SHA-512 pass, which is fast to brute force (see [MH0001](#mh0001-fast-hash-used-on-a-password)). Masterly.Hash 2.0 keeps the 1.x types so existing code compiles, but new hashes should come from `Password.Hash`.

**Bad:**

```csharp
string stored = new Hash().ComputeHash(plainText);
```

**Good:**

```csharp
string stored = Password.Hash(plainText);
```

**The code fix.** "Use Masterly.Hash.Password.Hash" makes this change when the call passes only the plaintext, positionally or as `plainText:`, and returns a string. Calls that choose an algorithm (`SupportedHash.SHA384`) or a salt are reported without a fix, because the replacement deliberately ignores both.

Existing 1.x hashes keep working: `Password.Verify` accepts them, and `result.Rehash` holds an Argon2id replacement to store after a successful login. See [Upgrading from 1.x](./upgrading-from-1x.md).

**How to suppress.** Keep the old call only where you must reproduce a 1.x hash byte for byte, for example in a test fixture. Suppress both `MH0006` and `CS0618` there.

## See also

- [Upgrading from 1.x](./upgrading-from-1x.md)
- [Peppers](./peppers.md)
- [Command-line tool](./command-line-tool.md)
- [Testing](./testing.md)
- [Rule pages in the repository](https://github.com/a7mdfre7at/Masterly.Hash/blob/master/docs/analyzers/MH0001.md)
