---
title: Onion Wrapping
sidebar_label: Onion Wrapping
description: Protect weak legacy hashes with Argon2id today, offline and without the passwords, and let each one upgrade on the user's next login.
---

Upgrade on login only reaches users who log in. Dormant accounts keep their MD5, phpass or 1.x hashes until the user returns, and a database leak exposes exactly those accounts. Onion wrapping fixes that offline: `TryWrap` runs Argon2id over the legacy digest, so no password is needed. The wrapped hash still verifies with the original password and becomes a plain `$mh$` hash on the next successful login.

```csharp title="WrapOnce.cs"
using Masterly.Hash;
using Masterly.Hash.Legacy;

PasswordHasher hasher = new PasswordHasher(new PasswordHasherOptions().AddAllLegacyFormats());

if (hasher.TryWrap("5f4dcc3b5aa765d61d8327deb882cf99", out string wrapped))
{
    // wrapped is "$mh$p=2026a,w=md5$<salt>$<tag>" and verifies with "password".
}
```

## How it works

For a legacy hash in format `F`, the stored value is split into a secret **digest** and public **parameters** (salt, cost). Wrapping stores:

```
tag = KDF(profile, Pepper?(k, digest), randomSalt)
```

At login the hasher recomputes the digest from the typed password and the stored parameters, then runs the same KDF:

```
tag' = KDF(profile, Pepper?(k, F.ComputeWrapInput(password, wp)), salt)
```

The legacy hash itself is gone from the row. An attacker who steals the table now has to pay one Argon2id computation per guess per row, on top of the legacy cost. Identical MD5 values become different wrapped hashes, because every wrap draws a fresh random salt.

The `$mh$` string records the format and its parameters in the `w` and `wp` fields (see the [Hash Format](./hash-format.md) specification):

```
$mh$p=<profile>[,k=<pepperKeyId>],w=<formatId>[,wp=<base64 parameters>]$<salt>$<tag>
```

`wp` is omitted when the format has no parameters (unsalted digests).

## When to use it

Wrap when you have:

- unsalted `md5`, `sha1`, `sha256` or `sha512` digests (wrap these first),
- Masterly.Hash 1.x (`v1`), phpass or ASP.NET Identity v2 hashes,
- bcrypt below cost 10 or PBKDF2 below 100,000 iterations,
- many accounts that rarely log in, or a migration that will take months.

[Auditing Hash Tables](./auditing-hash-tables.md) counts exactly these as **weak**.

Do not wrap, or think twice, when:

- **The hash is already strong.** External Argon2 (`argon2-phc`) hashes are never wrapped: `TryWrap` returns `false`. Strong bcrypt or PBKDF2 gains little, and every wrapped login pays the legacy cost plus Argon2id.
- **The legacy hashes have already leaked.** Wrapping protects the current table, not old backups, replicas or exports. If those copies are exposed, force password resets instead.
- **You cannot keep the format registered.** A wrapped hash needs its format at every login until it is upgraded.
- **The column cannot grow.** See [Column size](#column-size).

## What can be wrapped

| Format id | Digest | `wp` parameter |
|---|---|---|
| `bcrypt` | The 31-character hash part (ASCII) | The 29-character `$2b$12$<salt>` prefix (ASCII) |
| `wordpress-bcrypt` | The 31-character bcrypt hash part | The 29-character `$2y$10$<salt>` prefix, without `$wp` |
| `phpass` | The 22-character hash part | The 12-character setting: `$P$`, count character and salt |
| `django-pbkdf2` | The decoded hash | One algorithm byte (0 = SHA-1, 1 = SHA-256), the iteration count (4 bytes, big-endian), the salt |
| `aspnet-identity-v3` | The subkey | The 13-byte header and salt, followed by one byte holding the subkey length |
| `aspnet-identity-v2` | The 32-byte subkey | The 16-byte salt |
| `md5`, `sha1`, `sha256`, `sha512` | The decoded digest | None |
| `v1` | The SHA-2 digest | One algorithm byte (0 = SHA-256, 1 = SHA-384, 2 = SHA-512), then the salt |
| `argon2-phc` | Not wrappable | |

`TryWrap` returns `false`, and leaves `wrappedHash` empty, when:

- the value is `null` or empty,
- the value already starts with `$mh$` (native and already-wrapped hashes are never wrapped twice),
- no registered format claims the value, or every format that claims it refuses to wrap it.

The built-in `V1LegacyFormat.Instance` cannot wrap, because 1.x did not record its algorithm. Register `new V1LegacyFormat(V1Algorithm.SHA512)` (or the algorithm you used) to wrap `v1` hashes. [Upgrading from 1.x](./upgrading-from-1x.md#step-5-wrap-the-users-who-never-log-in) explains how to choose it safely.

`TryWrap` tries the registered formats in order and wraps with the first one that both claims the value and can extract a digest. That is why the `AddLegacyFormats` extension methods insert ahead of `v1`; see [Format order and overlaps](./legacy-formats.md#format-order-and-overlaps).

## Wrap a table, step by step

**1. Build a wrapping hasher that matches the login hasher.** It needs the same default profile, the same pepper and the same legacy formats with the same caps. The wrapped hash records the profile and the pepper key id, and the login hasher must accept both.

```csharp title="WrapperFactory.cs"
using Masterly.Hash;
using Masterly.Hash.Legacy;
using Masterly.Hash.Pepper;

namespace MyApp.Maintenance;

public static class WrapperFactory
{
    /// <summary>A hasher for the wrap job, configured exactly like the one that verifies logins.</summary>
    public static PasswordHasher Create(IPasswordPepper? pepper)
    {
        PasswordHasherOptions options = new PasswordHasherOptions
        {
            DefaultProfile = HashProfile.Server2026a,
            Pepper = pepper,
        };
        options.AddAllLegacyFormats();
        return new PasswordHasher(options);
    }
}
```

If the application resolves `IPasswordHasher` from dependency injection with these settings, the job can use that instance.

**2. Audit first.** Run [`HashAudit`](./auditing-hash-tables.md) to see what you have, how many rows are weak and whether any are unknown. Unknown rows are not wrapped.

**3. Back up the column.** Wrapping cannot be undone without the passwords. Keep a copy until you have verified a sample of wrapped rows with known test passwords.

**4. Wrap in batches, and only replace the value you read.** A user may log in or change their password while the job runs. Write the wrapped value only if the row still holds the hash you wrapped; otherwise an old password could start working again.

```csharp title="WrapLegacyHashesJob.cs"
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Masterly.Hash;
using Microsoft.EntityFrameworkCore;

namespace MyApp.Maintenance;

/// <summary>Onion-wraps every legacy password hash, in batches, without touching rows that changed meanwhile.</summary>
public sealed class WrapLegacyHashesJob
{
    private const int BatchSize = 500;

    private readonly AppDbContext _db;        // your DbContext
    private readonly IPasswordHasher _wrapper; // from WrapperFactory.Create

    public WrapLegacyHashesJob(AppDbContext db, IPasswordHasher wrapper)
    {
        _db = db;
        _wrapper = wrapper;
    }

    public async Task<long> RunAsync(CancellationToken cancellationToken)
    {
        long wrappedCount = 0;
        int lastId = 0;
        while (true)
        {
            List<UserHashRow> batch = await _db.Users
                .AsNoTracking()
                .Where(u => u.Id > lastId && !u.PasswordHash.StartsWith("$mh$"))
                .OrderBy(u => u.Id)
                .Take(BatchSize)
                .Select(u => new UserHashRow(u.Id, u.PasswordHash))
                .ToListAsync(cancellationToken);
            if (batch.Count == 0)
            {
                return wrappedCount;
            }

            foreach (UserHashRow row in batch)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (!_wrapper.TryWrap(row.PasswordHash, out string wrapped))
                {
                    continue;
                }

                // A login or password change since the read wins: the update matches zero rows.
                wrappedCount += await _db.Users
                    .Where(u => u.Id == row.Id && u.PasswordHash == row.PasswordHash)
                    .ExecuteUpdateAsync(s => s.SetProperty(u => u.PasswordHash, wrapped), cancellationToken);
            }

            lastId = batch[^1].Id;
        }
    }

    private sealed record UserHashRow(int Id, string PasswordHash);
}
```

`ExecuteUpdateAsync` needs EF Core 7 or later with a relational provider (it lives in `Microsoft.EntityFrameworkCore.Relational`, which SQL Server, PostgreSQL and SQLite providers bring in). It bypasses `SaveChanges` interceptors, including the Masterly [Entity Framework Core](./entity-framework-core.md) interceptor. If you save wrapped values through `SaveChanges` instead, the interceptor's hasher must have the wrapped formats registered: a `$mh$` value it does not recognize fails the save with `InvalidOperationException` rather than being hashed again.

**5. Check a sample.** Verify a few rows whose passwords you know (test accounts), and inspect the rest: `hasher.Inspect(wrapped)` reports `Format` = `mh`, `WrappedFormat` = the legacy id and `RehashReason.Wrapped`.

**6. Keep the formats registered.** The login hasher needs every format id that appears in a `w=` field until the last wrapped hash is upgraded. The audit's `Wrapped` count tells you when that is.

For a CSV export, the `masterly-hash wrap` command does the same streaming and in parallel. See [Command-Line Tool](./command-line-tool.md).

## Verifying a wrapped hash

Wrapped hashes go through the normal `Verify` and `VerifyAsync`. There is nothing to configure beyond keeping the format registered. The possible outcomes:

| Condition | Result |
|---|---|
| The `$mh$` string does not parse, or salt and tag lengths do not match the profile | `Failed`, `MalformedHash` |
| The profile id is not registered | `Failed`, `UnknownProfile` |
| The hash names a pepper key the hasher does not know | `Failed`, `UnknownPepperKey` |
| The `w` format id is not registered | `Failed`, `UnknownFormat` |
| The raw UTF-8 password exceeds `MaxPasswordBytes` | `Failed`, `PasswordTooLong` |
| The format rejects the `wp` parameter (`ComputeWrapInput` throws), for example a cost above its cap | `Failed`, `MalformedHash` |
| Wrong password | `Failed`, `Mismatch` |
| Right password | `SuccessRehashNeeded`, `RehashReason.Wrapped`, with `Rehash` set |

`RehashReason.Wrapped` takes priority over an outdated profile or pepper key. `Inspect` reports a wrapped hash as recognized only when its format is registered.

As with plain legacy hashes, the legacy digest is computed from the raw UTF-8 password without normalization. The `v1` digest also uses the raw password.

## Costs and limits

**Time.** A wrapped login costs the legacy digest plus one KDF run with the profile, about 125 ms for `2026a`. A bcrypt or PBKDF2 digest adds its own cost on top. Wrapping a hash costs one KDF run.

**Memory and concurrency.** Each wrap allocates the profile's memory (64 MiB for `2026a`) and takes a slot of the hasher's concurrency gate. If no slot frees within `ConcurrencyTimeout` (default 30 seconds), `TryWrap` throws `PasswordHasherBusyException`. Run a large job in its own process, or give it its own hasher, so it does not compete with logins.

**No async, no cancellation.** `TryWrap` is synchronous and takes no `CancellationToken`. Check for cancellation between rows, as the job above does.

**Peppers.** With a pepper configured, `TryWrap` peppers the digest with `Pepper.CurrentKeyId`, using the synchronous `IPasswordPepper.Apply`. Remote peppers backed by HashiCorp Vault or AWS KMS block a thread on a network call for every row, and can throw their `PepperUnavailableException`. `TryWrap` does not catch exceptions from the pepper or the KDF.

**Metrics.** Each wrap counts as one hash in `masterly.hash.hashes` (tagged with the profile) and records a `masterly.hash.duration` sample with `operation` = `hash`. See [Observability](./observability.md).

### Column size

A wrapped hash is longer than a plain one. A default `$mh$` hash is 78 characters. The `,w=<formatId>,wp=<base64>` fields add 52 characters for bcrypt (130 in total, of which 39 are the `wp` value), 29 for phpass (107), 65 for a Microsoft-default Identity v3 hash (143) and 6 for an unsalted MD5 digest, which has no `wp` (84). Long salts add more (an Identity v3 salt can be up to 256 bytes, a Django salt up to 128 characters). The `$mh$` format is capped at 1024 characters. Size the column for at least 256 characters, or use unbounded text.

## Security notes

:::warning

Never lower a cost cap below the costs inside wrapped hashes. The cap is checked again at every login: a wrapped bcrypt cost-12 hash fails with `MalformedHash` under `new BCryptFormat(10)`, and its user can no longer log in. The same applies to the phpass, Django and Identity v3 caps.

:::

- **Forged parameters fail fast.** `wp` comes from the database, so every format validates it and applies its cap before any hashing. Someone who raises the bcrypt cost inside `wp` to 31 gets `MalformedHash` immediately, not a computation measured in days.
- **Legacy quirks survive until the rehash.** A wrapped bcrypt hash still only reads the first 72 bytes of the password, and a wrapped phpass hash still refuses passwords over 4096 bytes. Both go away when the login replaces the wrapped hash with a plain one.
- **Wrapping `v1` needs the right algorithm.** An explicit-algorithm `V1LegacyFormat` with the wrong algorithm produces wrapped hashes that never verify. The same happens to an Identity v3 hash that `aspnet-identity-v3` refuses (over its cap) and `v1` claims instead. See [Upgrading from 1.x](./upgrading-from-1x.md).
- **The timing signal disappears.** A legacy MD5 or 1.x hash verifies in microseconds, so response time reveals unmigrated accounts. A wrapped hash costs a full KDF run, like a native one.

## See also

- [Legacy Hash Formats](./legacy-formats.md): the formats and their caps.
- [Auditing Hash Tables](./auditing-hash-tables.md): count weak and wrapped hashes.
- [Upgrading from 1.x](./upgrading-from-1x.md): wrapping Masterly.Hash 1.x hashes.
- [Hash Format](./hash-format.md): the `w` and `wp` fields.
- [Command-Line Tool](./command-line-tool.md): `masterly-hash wrap` for CSV exports.
