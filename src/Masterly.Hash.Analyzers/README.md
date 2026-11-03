# Masterly.Hash.Analyzers

![Masterly.Hash: password hashing you can't get wrong.](https://raw.githubusercontent.com/a7mdfre7at/Masterly.Hash/master/assets/banner.png)

Roslyn analyzers and code fixes that catch password-hashing mistakes while you type and at build time. The package
is a development dependency: it adds nothing to your output, and it works with or without the `Masterly.Hash`
runtime package (rules that suggest `Password.Hash` offer their code fix only when `Masterly.Hash` is referenced).

## Install

```shell
dotnet add package Masterly.Hash.Analyzers
```

This requires the .NET 8 SDK or Visual Studio 2022 17.8 or later (Roslyn 4.8+). C# only.

## Rules

| ID | Severity | Rule | Code fix |
|----|----------|------|----------|
| [MH0001](https://github.com/a7mdfre7at/Masterly.Hash/blob/master/docs/analyzers/MH0001.md) | Warning | Fast hash (MD5, SHA-1/2/3, HMAC) used on a password | `Password.Hash(x)` |
| [MH0002](https://github.com/a7mdfre7at/Masterly.Hash/blob/master/docs/analyzers/MH0002.md) | Warning | Non-constant-time comparison of a hash, MAC, token or secret | `CryptographicOperations.FixedTimeEquals` |
| [MH0003](https://github.com/a7mdfre7at/Masterly.Hash/blob/master/docs/analyzers/MH0003.md) | Warning | Hard-coded pepper or key | |
| [MH0004](https://github.com/a7mdfre7at/Masterly.Hash/blob/master/docs/analyzers/MH0004.md) | Warning | Password may be logged | |
| [MH0005](https://github.com/a7mdfre7at/Masterly.Hash/blob/master/docs/analyzers/MH0005.md) | Warning | Weak PBKDF2 parameters (< 100,000 iterations, SHA-1/MD5, defaulting constructors) | |
| [MH0006](https://github.com/a7mdfre7at/Masterly.Hash/blob/master/docs/analyzers/MH0006.md) | Info | Obsolete Masterly.Hash 1.x `Hash.ComputeHash` | `Password.Hash(plainText)` |

## Quickstart

```csharp
// MH0001: fast hash on a password. The code fix rewrites this line to Password.Hash(password).
string stored = Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(password)));

// MH0002: early-exit comparison of a MAC. The code fix rewrites it to CryptographicOperations.FixedTimeEquals.
if (computedMac.SequenceEqual(expectedMac)) { }

// MH0004: password written to a log.
logger.LogInformation("Login {User} {Password}", user, password);
```

Configure severities in `.editorconfig`:

```ini
[*.cs]
dotnet_diagnostic.MH0004.severity = error
dotnet_diagnostic.MH0006.severity = warning
```

## How names are matched

MH0001, MH0002 and MH0004 decide what counts as a password or secret by symbol name, because the type of a password
is just `string`. Names are split into words (`userPassword` becomes user + password, `HTTPToken` becomes
http + token), so `spinner` never matches `pin`. A match followed by a metadata word, such as `passwordPolicy`,
`maxPasswordLength`, `passwordHash`, `passwordSaltBytes`, `tokenType` or `hashAlgorithm`, does not count, and
neither does `hashedPassword` or `encryptedPassword` (a stored hash, not a password). Comparisons
with `null`, `default`, `""` or a `Length` do not trigger MH0002.

## Security notes

- These are heuristics. They find common mistakes; they do not prove code secure, and they miss values that reach a
  sink through fields, collections or other methods.
- The MH0001 fix is offered only where the hash is stored (returned or assigned), never where it is compared:
  `Password.Hash` is randomly salted, so verification code must use `Password.Verify`. It is not offered for HMACs.
- The MH0002 fix is offered for `Enumerable.SequenceEqual` only when both arrays are provably non-null, because
  `FixedTimeEquals` treats `null` as empty where `SequenceEqual` throws.
- The MH0001 fix changes the stored format. Hashes written by the old code do not convert themselves, so plan a
  migration (verify with the old code, then store `Password.Hash` output).
- The analyzers only read your syntax trees and symbols. They do not execute code, read files or use the network.
