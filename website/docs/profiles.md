---
title: "Hash Profiles"
sidebar_label: "Profiles"
description: "Choose a built-in profile, define a custom one, and change profiles without breaking existing hashes."
---

A profile is a named, immutable set of hashing parameters: the algorithm, the memory and time cost, the salt length and the tag length. This page explains the built-in profiles, how to pick one, how to define your own, and how to move from one profile to another.

The stored hash records only the profile **id**, for example `2026a`. The parameters come from your code, never from the database row:

```text
$mh$p=2026a$<salt>$<tag>
```

When the hasher verifies this string it looks `2026a` up in its own list of registered profiles. A stored string cannot carry `m=4194304` to make the server allocate 4 GiB, or `t=1` to downgrade the cost, because there is nowhere in the format to put them. A hash that names an id the hasher does not know fails with `VerificationFailureReason.UnknownProfile`.

## Built-in profiles

| Property | Id | Algorithm | Parameters | Salt | Tag | For |
|---|---|---|---|---|---|---|
| `HashProfile.Server2026a` (default) | `2026a` | Argon2id | m=65536 KiB (64 MiB), t=3, p=1 | 16 bytes | 32 bytes | Web backends |
| `HashProfile.Constrained2026a` | `2026c` | Argon2id | m=19456 KiB (19 MiB), t=2, p=1 | 16 bytes | 32 bytes | Serverless, small containers |
| `HashProfile.Fips2026a` | `2026f` | PBKDF2-HMAC-SHA512 | 210,000 iterations | 16 bytes | 64 bytes | NIST-approved primitives only |

`2026a` is the second recommended option of RFC 9106. `2026c` is the OWASP Password Storage Cheat Sheet minimum for Argon2id. `2026f` follows the OWASP recommendation for PBKDF2-HMAC-SHA512.

Every `PasswordHasher` registers all three built-in profiles, whatever you configure. You can always verify a `2026a`, `2026c` or `2026f` hash, and switching the default between built-in profiles never breaks a login.

`HashProfile.BuiltIn` lists the three profiles, oldest first. `HashProfile.TryGetBuiltIn(id, out HashProfile profile)` looks one up by id:

```csharp
// id comes from your configuration, e.g. "2026c"
if (HashProfile.TryGetBuiltIn(id, out HashProfile profile))
{
    Console.WriteLine(profile); // 2026c (Argon2id m=19456KiB t=2 p=1)
}
```

### Measured cost

Median of 15 runs on an AMD Ryzen 9 7950X with .NET 10, single thread (from the [changelog](https://github.com/a7mdfre7at/Masterly.Hash/blob/master/CHANGELOG.md)):

| Profile | Hash | Verify | Allocated per call |
|---|---:|---:|---:|
| `2026a` | 125.6 ms | 130.1 ms | 64.0 MiB |
| `2026c` | 26.3 ms | 26.6 ms | 19.0 MiB |
| `2026f` | 81.3 ms | 83.6 ms | less than 0.1 MiB |

Your hardware will differ. Run `masterly-hash bench` to time the three profiles on the machine that will serve logins. It recommends `Server2026a` when `2026a` fits the target (250 ms by default, change it with `--target-ms`) and `Constrained2026a` otherwise. See [Command-line tool](./command-line-tool.md) and [Performance](./performance.md).

## Choosing a profile

**Use `2026a` unless you have a reason not to.** It is the default, so you do not need to configure anything. It costs an attacker about 125 ms of CPU time and 64 MiB of memory per guess, and memory-hardness limits how many guesses a GPU or ASIC can run in parallel.

**Use `2026c` when memory is tight.** Serverless functions and small containers often cannot spend 64 MiB per login, multiplied by the number of logins in flight. `2026c` still meets the OWASP minimum. Lower [`MaxConcurrency`](./limits-and-concurrency.md#the-concurrency-gate) is the other lever: it caps how many derivations run at once, so it caps peak memory without weakening each hash.

**Use `2026f` only when policy requires it.** PBKDF2 is not memory-hard, so the same attacker budget tests many more guesses per second than against Argon2id. Pick it only when your environment must use NIST-approved primitives. It runs through the platform's crypto (`Rfc2898DeriveBytes.Pbkdf2`), so FIPS 140-3 certification depends on your operating system's crypto module, not on this library.

**Do not use a weaker custom profile to make logins faster.** If `2026a` is too slow or too large on your hosts, use `2026c`.

Set the default in code:

```csharp title="Program.cs"
builder.Services.AddMasterlyHash(options => options.DefaultProfile = HashProfile.Constrained2026a);
```

or in configuration, which accepts the built-in ids only:

```json title="appsettings.json"
{
  "MasterlyHash": {
    "DefaultProfile": "2026c"
  }
}
```

An unknown id in `MasterlyHash:DefaultProfile` is a startup error (`OptionsValidationException`) that lists the known ids. An empty or whitespace value keeps the default. See [Dependency injection](./dependency-injection.md) for the full configuration section.

To hash one password with a profile other than the default, pass it explicitly. The profile must be registered with the hasher; otherwise `Hash` throws `ArgumentException`:

```csharp
// hasher is your IPasswordHasher
string stored = hasher.Hash(password, HashProfile.Constrained2026a);
```

There is no async overload that takes a profile: `HashAsync` always uses the default profile.

## Custom profiles

Create a custom profile with one of the two factory methods:

```csharp
HashProfile strong = HashProfile.Argon2id("app-2027a", memoryKiB: 131072, iterations: 3);
HashProfile fips = HashProfile.Pbkdf2Sha512("app-fips-2027a", iterations: 600_000);
```

| Factory | Parameters and defaults |
|---|---|
| `HashProfile.Argon2id(id, memoryKiB, iterations, parallelism = 1, saltLength = 16, tagLength = 32)` | Argon2id (RFC 9106) |
| `HashProfile.Pbkdf2Sha512(id, iterations, saltLength = 16, tagLength = 64)` | PBKDF2-HMAC-SHA512 (RFC 8018). `MemoryKiB` is 0 and `Parallelism` is 1. |

The factories validate every value and throw at once:

| Value | Allowed range | Exception |
|---|---|---|
| `id` | `^[a-z0-9][a-z0-9-]{0,31}$`: 1 to 32 characters, lowercase letters, digits and `-`, not starting with `-` | `ArgumentException` |
| `memoryKiB` (Argon2id) | `8 × parallelism` to `HashProfile.MaxMemoryKiB` (1048576 KiB, 1 GiB) | `ArgumentOutOfRangeException` |
| `iterations` (Argon2id) | 1 to 64 | `ArgumentOutOfRangeException` |
| `parallelism` (Argon2id) | 1 to 16 | `ArgumentOutOfRangeException` |
| `iterations` (PBKDF2) | 1 to 10,000,000 | `ArgumentOutOfRangeException` |
| `saltLength` | 16 to 64 bytes | `ArgumentOutOfRangeException` |
| `tagLength` | 16 to 64 bytes | `ArgumentOutOfRangeException` |

The 1 GiB memory cap means no profile, however it is configured, can exhaust a host with a single call.

:::tip

Give custom profiles an application prefix, such as `app-2027a`. Future package versions add new built-in profiles with dated ids. If your custom profile already uses that id with different parameters, the hasher refuses to start after the upgrade.

:::

### The OWASP minimum

`HashProfile.MeetsRecommendedMinimum` is true when the parameters meet the OWASP minimums:

- Argon2id: `MemoryKiB` at least 19456 and `Iterations` at least 2.
- PBKDF2-HMAC-SHA512: `Iterations` at least 210,000.

A profile below the minimum cannot be registered. The `PasswordHasher` constructor throws `ArgumentException` ("is below the OWASP minimum"), and the dependency injection validator reports the same message at startup. Only `PasswordHasherOptions.AllowWeakProfiles = true` lets it through, and that option exists for tests. In test projects, prefer the ready-made fast hasher from `Masterly.Hash.Testing`; see [Testing](./testing.md).

### Registering custom profiles

A hasher accepts the built-in profiles, the profiles in `PasswordHasherOptions.AdditionalProfiles`, and `PasswordHasherOptions.DefaultProfile`. Custom profiles are code-only; configuration cannot define them.

```csharp title="Program.cs"
HashProfile current = HashProfile.Argon2id("app-2027a", memoryKiB: 131072, iterations: 3);
HashProfile previous = HashProfile.Argon2id("app-2026b", memoryKiB: 98304, iterations: 3);

builder.Services.AddMasterlyHash()
    .UseProfile(current)     // new hashes
    .AddProfile(previous);   // existing hashes keep verifying
```

Without dependency injection:

```csharp
PasswordHasherOptions options = new PasswordHasherOptions { DefaultProfile = current };
options.AdditionalProfiles.Add(previous);
PasswordHasher hasher = new PasswordHasher(options);
```

Registration rules:

- **An id is permanent.** Registering an id that is already registered with different parameters throws `ArgumentException` ("Profile ids are permanent; pick a new id"). This includes reusing a built-in id such as `2026a`. Registering the same profile twice is fine.
- **Profiles compare by value.** Two `HashProfile` instances are equal when the id, algorithm, memory, iterations, parallelism, salt length and tag length all match.
- **`null` is rejected.** A `null` entry in `AdditionalProfiles` or a `null` `DefaultProfile` throws `ArgumentException`.
- **Options are copied.** The hasher reads the options once, in its constructor. Later changes to the options object have no effect.

`PasswordHasher.DefaultProfile` returns the profile used for new hashes, and `PasswordHasher.Profiles` returns every profile the hasher accepts.

## Changing the default profile

Changing `DefaultProfile` does not touch any stored hash. Hashes made with the previous profile keep verifying. On the next successful login the result has `Status == VerificationStatus.SuccessRehashNeeded`, `RehashReason == RehashReason.OutdatedProfile`, and a fresh hash under the new profile in `Rehash`. Store it and the user is upgraded. See [Upgrade on login](./upgrade-on-login.md).

**Between built-in profiles**, change the default and deploy. Every instance already knows every built-in profile.

**To a new custom profile**, roll it out in two deployments so that no instance meets a hash it cannot read:

1. **Register the new profile everywhere first.** Add it with `AddProfile` (or to `AdditionalProfiles`) and deploy to every instance, keeping the old default. Nothing changes for users yet.
2. **Make it the default.** Deploy `UseProfile(newProfile)` and keep the old profile registered with `AddProfile` if it is custom. Hashes are now upgraded as users log in.
3. **Watch the migration.** Count `masterly.hash.verifications` with `reason=OutdatedProfile` (see [Observability](./observability.md)), or scan the table offline with `Inspect` or `masterly-hash audit` (see [Auditing hash tables](./auditing-hash-tables.md)).
4. **Retire the old custom profile only when no hashes use it.** A hash whose profile is no longer registered fails with `UnknownProfile`, and that user can no longer log in with their password.

If you skip step 1 and roll out the new default directly, an instance still running the old configuration fails every hash written by an upgraded instance with `UnknownProfile` until it is updated.

During any rollout where instances disagree on the default, a user can be rehashed back and forth between the two profiles. This is harmless (every hash written is valid on both) and stops when the rollout completes.

:::warning

Never remove a custom profile from the hasher to "force" an upgrade. Users whose hashes still name it are locked out of password login. Use `Inspect` to find them first, and ask them to reset their password, or keep the profile registered.

:::

## Inspecting a stored hash

`Inspect(storedHash)` tells you which profile a hash uses without the password and without running the KDF:

```csharp
// hasher is your IPasswordHasher; storedHash comes from your users table
HashInfo info = hasher.Inspect(storedHash);

Console.WriteLine(info.ProfileId);    // "2026c"
Console.WriteLine(info.Profile);      // the registered HashProfile, or null if the id is unknown
Console.WriteLine(info.IsRecognized); // false for an unknown profile id
Console.WriteLine(info.RehashReason); // OutdatedProfile when 2026c is not the default
```

A native hash is recognized only when its profile is registered, its salt and tag lengths match the profile, and any pepper key id (`k=`) or wrapped legacy format (`w=`) it names is configured on the hasher. A hash whose salt or tag length does not match fails verification with `MalformedHash`.

## Profile properties

| Property | Meaning |
|---|---|
| `Id` | The identifier written into the hash string |
| `Algorithm` | `HashAlgorithmKind.Argon2id` or `HashAlgorithmKind.Pbkdf2Sha512` |
| `MemoryKiB` | Argon2 memory cost in KiB. 0 for PBKDF2. |
| `Iterations` | Argon2 passes, or PBKDF2 iterations |
| `Parallelism` | Argon2 lanes. Always 1 for PBKDF2. |
| `SaltLength` | Salt length in bytes |
| `TagLength` | Output tag length in bytes |
| `MeetsRecommendedMinimum` | True if the parameters meet the OWASP minimums |

`ToString()` describes the profile: `2026a (Argon2id m=65536KiB t=3 p=1)` or `2026f (PBKDF2-SHA512 i=210000)`.

## See also

- [Upgrade on login](./upgrade-on-login.md): how outdated hashes are replaced
- [Limits and concurrency](./limits-and-concurrency.md): peak memory is profile memory times `MaxConcurrency`
- [Hash format](./hash-format.md): the `$mh$` string and the profile id rules
- [Performance](./performance.md): benchmarks and how to run them
- [Threat model](./threat-model.md): why cost parameters are never stored
