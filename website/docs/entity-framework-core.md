---
title: Entity Framework Core
sidebar_label: Entity Framework Core
description: Hash password columns on SaveChanges, keep blind indexes up to date, query them during key rotation and upgrade outdated hashes at login.
---

`Masterly.Hash.EntityFrameworkCore` integrates Masterly.Hash with Entity Framework Core 8. It does three things:

- **Password columns.** Mark a property with `IsHashedPassword()`. On `SaveChanges`, a plaintext value is replaced by its hash, in the entity itself.
- **Blind indexes.** `HasBlindIndex(...)` keeps a searchable HMAC index of an (encrypted) column up to date, and `WhereBlindIndex(...)` queries it, still finding rows written under older keys during rotation.
- **Login upgrade.** `VerifyAndUpgradeAsync(...)` checks a password and, if the stored hash is outdated, stores the new hash.

```bash
dotnet add package Masterly.Hash.EntityFrameworkCore
```

The package targets `net8.0`, depends on `Microsoft.EntityFrameworkCore` 8.0.x, `Masterly.Hash` and `Masterly.Hash.BlindIndex`, and works with every provider.

## Set up the context

**1. Mark the properties in the model.**

```csharp title="AppDbContext.cs"
using Masterly.Hash.BlindIndex;
using Masterly.Hash.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace MyApp.Data;

public sealed class User
{
    public int Id { get; set; }

    public string? PasswordHash { get; set; }   // assign the plaintext; it holds the hash after SaveChanges

    public string? Email { get; set; }          // for example encrypted with your own value converter

    public string? EmailIndex { get; set; }     // maintained by the interceptor
}

public sealed class AppDbContext : DbContext
{
    public AppDbContext(DbContextOptions<AppDbContext> options)
        : base(options)
    {
    }

    public DbSet<User> Users => Set<User>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<User>(entity =>
        {
            entity.Property(u => u.PasswordHash).IsHashedPassword();
            entity.Property(u => u.Email).HasBlindIndex(nameof(User.EmailIndex), "users.email", BlindIndexNormalizers.Email);
            entity.HasIndex(u => u.EmailIndex);
        });
    }
}
```

**2. Register the interceptor.** Create one hasher and one indexer per application. The simplest form passes them to `UseMasterlyHash`:

```csharp title="Program.cs"
using Masterly.Hash;
using Masterly.Hash.BlindIndex;
using Masterly.Hash.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

builder.Services.AddMasterlyHash(builder.Configuration.GetSection("MasterlyHash"));

Dictionary<string, string> indexKeys = builder.Configuration.GetSection("BlindIndexKeys").Get<Dictionary<string, string>>()
    ?? throw new InvalidOperationException("BlindIndexKeys is not configured.");
builder.Services.AddSingleton<IBlindIndexer>(BlindIndexer.FromBase64("2026-01", indexKeys));

builder.Services.AddDbContext<AppDbContext>((services, options) => options
    .UseSqlServer(builder.Configuration.GetConnectionString("Default"))
    .UseMasterlyHash(services.GetRequiredService<IPasswordHasher>(), services.GetRequiredService<IBlindIndexer>()));
```

`UseMasterlyHash` creates a new `MasterlyHashSaveChangesInterceptor` each time it runs, and `AddDbContext` runs the options callback for every scope. The interceptor caches its per-entity plan, so to build that plan once, register the interceptor as a singleton and add it with `AddInterceptors`:

```csharp title="Program.cs"
builder.Services.AddSingleton<MasterlyHashSaveChangesInterceptor>(services =>
    new MasterlyHashSaveChangesInterceptor(
        services.GetRequiredService<IPasswordHasher>(),
        services.GetRequiredService<IBlindIndexer>()));

builder.Services.AddDbContext<AppDbContext>((services, options) => options
    .UseSqlServer(builder.Configuration.GetConnectionString("Default"))
    .AddInterceptors(services.GetRequiredService<MasterlyHashSaveChangesInterceptor>()));
```

The helpers in this package find the interceptor either way. The interceptor is thread-safe.

| `UseMasterlyHash` parameter | Required | Meaning |
|-----------------------------|----------|---------|
| `hasher` | Yes | The `IPasswordHasher`, typically the application singleton. |
| `indexer` | Only if the model uses `HasBlindIndex` | The `IBlindIndexer`. |
| `configure` | No | Sets `MasterlyHashInterceptorOptions` (below). |

Both `DbContextOptionsBuilder` and `DbContextOptionsBuilder<TContext>` have the overload.

## Password columns

### Sign-up and password change

Assign the plaintext and save. The interceptor writes the hash into the property before the database sees it.

```csharp title="SignUpService.cs"
User user = new User { PasswordHash = password, Email = email };
db.Users.Add(user);
await db.SaveChangesAsync(cancellationToken);
// user.PasswordHash now starts with "$mh$p=2026a$"
```

`SaveChangesAsync` uses `IPasswordHasher.HashAsync`, which supports remote peppers. The synchronous `SaveChanges` uses `Hash`.

### When the interceptor runs

A password property is processed when the entity is `Added`, or when it is `Modified` and that property is modified. Saving a user for another reason never touches the stored hash.

| Value assigned | Added entity | Modified entity |
|----------------|--------------|-----------------|
| `null` | Stays `null`. | Stays `null`. |
| Empty string | The save fails. | The save fails. |
| Plaintext | Hashed. | Hashed. |
| A native `$mh$` hash this hasher recognizes (any registered profile and pepper key) | Stored as-is. | Stored as-is. |
| A value starting with `$mh$` that this hasher does not recognize (malformed, or an unregistered profile, pepper key or wrapped legacy format) | The save fails; it is never hashed a second time. | Kept if the database already holds exactly this value, otherwise the save fails. |
| A legacy hash (for example 1.x base64) with `AcceptLegacyHashes` off | Hashed as plaintext. | Kept if the database already holds exactly this value, otherwise hashed as plaintext. |
| A legacy hash with `AcceptLegacyHashes` on | Stored as-is. | Stored as-is. |

The database comparison exists because EF cannot tell a re-saved value from a new one: `DbSet.Update` of a detached entity and `State = EntityState.Modified` mark every property modified. For values that look like hashes, the interceptor reads the row (`GetDatabaseValues`, once per entity) and keeps the value the database already holds. A not-yet-migrated legacy hash therefore survives a disconnected update instead of being hashed into a "password" that locks the user out. Plaintext and recognized Masterly hashes never cause this extra query.

### Why an interceptor and not a value converter

A `ValueConverter` changes only what is sent to the database. The entity would keep the plaintext after `SaveChanges`, and it would be tracked, cached and serialized with it. A converter would also run on query parameters, so `Where(u => u.PasswordHash == input)` would hash `input` with a new random salt and could never match. The interceptor writes the hash into the entity once, before the save, and does not affect queries.

### Interceptor options

| Option | Default | Effect |
|--------|---------|--------|
| `AcceptLegacyHashes` | `false` | Keep values that a registered legacy format recognizes instead of hashing them. Useful for bulk imports of legacy hashes through EF. |
| `Normalizers` | empty | Normalizers by id, overriding the ones recorded by `HasBlindIndex`. See [Normalizer ids](#normalizer-ids). |

```csharp title="Program.cs"
options.UseMasterlyHash(hasher, indexer, interceptor => interceptor.AcceptLegacyHashes = true);
```

The options are copied when the interceptor is created; later changes have no effect.

:::warning

Leave `AcceptLegacyHashes` off unless you are importing. The 1.x format is plain base64, so with it on, a long base64-looking password typed by a user would be recognized as a legacy hash and stored unhashed.

:::

## Verify and upgrade at login

`VerifyAndUpgradeAsync` verifies a password against the stored hash. If it matches and the hash is outdated (a legacy format, a wrapped hash, an older profile or pepper key), it writes the fresh hash to the property and saves.

```csharp title="LoginEndpoint.cs"
using Masterly.Hash;
using Masterly.Hash.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

User? user = await db.Users.WhereBlindIndex(u => u.EmailIndex, email).FirstOrDefaultAsync(cancellationToken);

PasswordVerificationResult result = user is null
    ? await hasher.VerifyOrDummyAsync(password, null, cancellationToken)   // same cost for unknown users
    : await db.VerifyAndUpgradeAsync(user, u => u.PasswordHash, password, cancellationToken);

if (!result.IsMatch)
{
    return Results.Unauthorized();
}
```

Two overloads exist:

| Overload | Hasher |
|----------|--------|
| `VerifyAndUpgradeAsync(entity, passwordProperty, password, cancellationToken)` | The one passed to `UseMasterlyHash`. Throws `InvalidOperationException` if the context has no `MasterlyHashSaveChangesInterceptor`. |
| `VerifyAndUpgradeAsync(hasher, entity, passwordProperty, password, cancellationToken)` | The one you pass. Works without the interceptor. |

How it behaves:

- A `null` stored hash is verified against a dummy hash (`VerifyOrDummyAsync`), so the response time does not reveal accounts without a password. It never throws for a bad stored hash.
- If the hasher did not precompute the replacement (`ComputeRehashOnVerify` is `false`, as under [ASP.NET Core Identity](./aspnetcore-identity.md)), it calls `HashAsync` itself.
- The entity can be tracked or detached (for example loaded with `AsNoTracking`). A detached entity is attached for the save and detached again.
- The upgrade calls `SaveChangesAsync`, which also saves any other pending changes of the context.

The upgrade is skipped, and the result returned unchanged, when:

- the entity is `Added` or `Deleted`;
- the password property already has an unsaved change;
- the row no longer holds the hash that was verified. The row is re-read just before the save, so a password reset that committed during the slow verification is not overwritten;
- the entity is detached and another instance with the same key is already tracked.

If the save fails with a `DbUpdateException` (including `DbUpdateConcurrencyException`) that concerns this entity alone, the property is restored and the successful result is returned: the login succeeds and the upgrade is retried next time. Any other failure (a connection error, a failing pending change of another entity, cancellation) is rethrown after the property is restored.

:::tip

The re-read leaves a small window between the read and the `UPDATE`. Make the password column, or a row version, a concurrency token to close it:

```csharp title="AppDbContext.cs"
entity.Property(u => u.PasswordHash).IsHashedPassword().IsConcurrencyToken();
```

:::

## Blind indexes

A blind index is a keyed, truncated HMAC of a normalized value, stored next to an encrypted column so you can search it by equality without decrypting. [Blind indexes](./blind-indexes.md) covers the indexer, keys and normalizers. This section covers the EF integration.

### Configure the index

```csharp title="AppDbContext.cs"
entity.Property(u => u.Email).HasBlindIndex(nameof(User.EmailIndex), "users.email", BlindIndexNormalizers.Email, outputBits: 64);
entity.HasIndex(u => u.EmailIndex);
```

| Parameter | Default | Rules |
|-----------|---------|-------|
| `indexPropertyName` | | A string property of the same entity, different from the source. Not the primary key. Give it a database index. |
| `indexName` | | Domain-separation name such as `users.email`. Must match `^[A-Za-z0-9._:/-]{1,128}$`. Never change it for existing data. |
| `normalizer` | `BlindIndexNormalizers.Exact` | Applied before hashing. |
| `outputBits` | `64` | A multiple of 8 from 16 to 256. |

The stored index has the form `<keyId>:<base64>` and is at most 76 characters (a 32-character key id at 256 bits).

On every save where the entity is `Added` or the source property is modified, the interceptor writes the current-key index of the source value into the index property. A `null` or empty value, or one that is empty after normalization, stores `null`. The index is also recomputed when only the index property is modified: the index is derived data, so a value written directly to it (mass assignment, a copied row) is replaced, and a row can never carry another row's index.

### Query the index

On a `DbSet`, `WhereBlindIndex` reads the index name, normalizer and length from the model and the indexer from the interceptor:

```csharp title="UserLookup.cs"
User? user = await db.Users.WhereBlindIndex(u => u.EmailIndex, email).FirstOrDefaultAsync(cancellationToken);
```

The value is indexed under every key in the ring, and the query becomes `WHERE EmailIndex = @p0 OR EmailIndex = @p1 ...`, so rows written under an older key are still found. Each candidate is a SQL parameter: no literals in the SQL text, a stable plan cache, and no dependency on JSON or array support in the provider.

| Method | Use |
|--------|-----|
| `DbSet<TEntity>.WhereBlindIndex(indexProperty, value)` | Uses the model configuration. Throws `InvalidOperationException` if the context has no `MasterlyHashSaveChangesInterceptor`, no `HasBlindIndex` writes to the property, or no indexer was passed to `UseMasterlyHash`. A value the normalizer rejects (not an email address) throws `ArgumentException`. |
| `IQueryable<TEntity>.WhereBlindIndex(indexProperty, indexer, indexName, value, options)` | For any queryable, without the interceptor. Pass the same `BlindIndexOptions` (normalizer, output bits) the index was written with; `options` defaults to `null` (the `Exact` normalizer and 64 bits). |
| `DbContext.GetBlindIndexCandidates<TEntity>(indexProperty, value)` | Returns the candidate index strings, current key first, for raw SQL. Throws `InvalidOperationException` if the entity type is not in the model, and for the same reasons as the `DbSet` overload. |

For the `DbSet` overload and `GetBlindIndexCandidates`, the `indexProperty` selector must be a direct property access (`u => u.EmailIndex`) or `EF.Property<string>(u, "EmailIndex")`; anything else throws `ArgumentException`.

An empty value, or one that is empty after normalization, matches nothing and yields no candidates.

:::note

A blind index can have false positives by design, especially with short output lengths. When it matters, decrypt each returned row and compare the value.

:::

### Rotate the index key

**1. Add the new key as current** and keep the old one in the ring. Lookups match either key.

**2. Re-index each row** by marking the source property modified and saving:

```csharp title="Reindexer.cs"
db.Entry(user).Property(u => u.Email).IsModified = true;
await db.SaveChangesAsync(cancellationToken);
```

Use `IBlindIndexer.NeedsReindex(user.EmailIndex)` to find rows that still carry an old key.

**3. Retire the old key** only after every row has been re-indexed.

### Normalizer ids

The model stores only the normalizer's id, so the annotations survive migration snapshots and `dotnet ef migrations add` works.

| Normalizer | Recorded id |
|------------|-------------|
| `BlindIndexNormalizers.Exact` | `exact` |
| `BlindIndexNormalizers.Trim` | `trim` |
| `BlindIndexNormalizers.CaseInsensitive` | `case-insensitive` |
| `BlindIndexNormalizers.Email`, or `EmailNormalizer` with no options | `email` |
| `EmailNormalizer` with plus-tag and/or Gmail-dot stripping | `email:strip-plus-tags`, `email:strip-gmail-dots` or `email:strip-plus-tags,strip-gmail-dots` |
| `BlindIndexNormalizers.Phone`, or `PhoneNormalizer` without a default country code | `phone` |
| `PhoneNormalizer` with a default country code | `phone:cc=44` (the code) |
| Any other normalizer | The type's full name |

Built-in normalizers resolve the same way in every process (web app, worker, design-time tools) without registration. A custom normalizer is resolved from a process-wide registry that `HasBlindIndex` fills. Because it is identified by type, one model cannot use two differently configured instances of the same custom type: reuse one instance, use a separate type per configuration, or override `Equals`. If two models in one process do so, map each id explicitly in `MasterlyHashInterceptorOptions.Normalizers`.

### Model annotations

`MasterlyHashAnnotationNames` lists the annotation names, all starting with `Masterly:`:

| Constant | Value | Placed on |
|----------|-------|-----------|
| `HashedPassword` | `Masterly:HashedPassword` | Password property, `true`. |
| `BlindIndexProperty` | `Masterly:BlindIndex:Property` | Source property, the index property's name. |
| `BlindIndexName` | `Masterly:BlindIndex:Name` | Source property, the index name. |
| `BlindIndexNormalizer` | `Masterly:BlindIndex:Normalizer` | Source property, the normalizer id. |
| `BlindIndexOutputBits` | `Masterly:BlindIndex:OutputBits` | Source property, the length in bits. |

Every value is a string, boolean or integer.

## Errors

Error messages name the entity and property, never the value being hashed or indexed.

| When | Exception |
|------|-----------|
| `IsHashedPassword` or `HasBlindIndex` on a non-string property | `ArgumentException` while building the model. |
| `HasBlindIndex` with an empty or identical index property name, an invalid index name | `ArgumentException`. Invalid `outputBits` throws `ArgumentOutOfRangeException`. |
| The same property as both a hashed password and a blind-index source (in either order) | `ArgumentException`: an index of a password would allow offline guessing. |
| A second, differently configured instance of a custom normalizer type in one model | `ArgumentException`. |
| First save: the index property does not exist, is not a string or is the primary key; two indexes write to one property; an index reads from or writes to a password property; the normalizer id is not registered | `InvalidOperationException`. |
| Saving a password that is empty, over `MaxPasswordBytes` or invalid UTF-16 | `InvalidOperationException` such as "Cannot hash the value of 'User.PasswordHash': Password cannot be empty. (Parameter 'password')", with the hasher's `ArgumentException` as inner exception. |
| Saving an unrecognized `$mh$` value | `InvalidOperationException`. Register the profile, pepper key or wrapped legacy format, or assign a plaintext password. |
| `VerifyAndUpgradeAsync(entity, ...)` on a context without the interceptor | `InvalidOperationException`. Use the overload that takes a hasher, or register the interceptor. |
| A blind index without an `IBlindIndexer` | `InvalidOperationException`. |
| A value the normalizer rejects on save | `InvalidOperationException` ("Cannot compute blind index ..."), with the `ArgumentException` as inner exception. |
| The hasher is at its concurrency limit | `PasswordHasherBusyException`, unwrapped. |

## Security notes

- **The plaintext sits in the entity** from the moment you assign it until `SaveChanges`, and .NET strings cannot be zeroed. Save promptly, and do not log or serialize entities before saving.
- **Paths that skip the interceptor write plaintext as-is:** `ExecuteUpdate`, `ExecuteDelete`, raw SQL and bulk-insert libraries. Hash explicitly with `IPasswordHasher.HashAsync` on those paths.
- **A password that is itself a valid hash string** is stored as that hash, so the typed password will not match. Applications that take passwords from untrusted input may reject values starting with `$mh$`.
- **Do not combine `IsHashedPassword` with ASP.NET Core Identity's `PasswordHash` column.** `UserManager` already hashes through the Identity adapter, and an added user carrying an Identity v3 hash would be hashed again as plaintext unless `AcceptLegacyHashes` is on.
- **Blind indexes leak equality**, and with short indexes some frequency information. Keep index keys out of the database and separate from pepper keys.

## See also

- [Upgrade on login](./upgrade-on-login.md)
- [Blind indexes](./blind-indexes.md)
- [User enumeration](./user-enumeration.md)
- [Dependency Injection](./dependency-injection.md)
- [Legacy formats](./legacy-formats.md)
