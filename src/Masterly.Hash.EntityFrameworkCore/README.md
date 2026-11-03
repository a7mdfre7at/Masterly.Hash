# Masterly.Hash.EntityFrameworkCore

![Masterly.Hash: password hashing you can't get wrong.](https://raw.githubusercontent.com/a7mdfre7at/Masterly.Hash/master/assets/banner.png)

Entity Framework Core 8+ integration for [Masterly.Hash](https://github.com/a7mdfre7at/Masterly.Hash):

- **Password columns**: mark a property with `IsHashedPassword()`. On `SaveChanges`, a plaintext value is replaced by its Argon2id hash in the entity itself.
- **Blind indexes**: `HasBlindIndex(...)` keeps a searchable HMAC index of an (encrypted) column up to date. `WhereBlindIndex(...)` queries it and still finds rows written under older keys during rotation.
- **Login upgrade**: `VerifyAndUpgradeAsync(...)` checks a password and, if the stored hash is outdated (a 1.x hash, an older profile or pepper key), stores the new hash.

## Install

```
dotnet add package Masterly.Hash.EntityFrameworkCore
```

Targets `net8.0`. Depends on `Microsoft.EntityFrameworkCore` 8.0.x, `Masterly.Hash` and `Masterly.Hash.BlindIndex`. It works with every provider.

## Quickstart

```csharp
public sealed class User
{
    public int Id { get; set; }
    public string? PasswordHash { get; set; }  // assign the plaintext; it holds the hash after SaveChanges
    public string? Email { get; set; }         // e.g. encrypted with your own value converter
    public string? EmailIndex { get; set; }    // maintained by the interceptor
}

protected override void OnModelCreating(ModelBuilder b)
{
    b.Entity<User>(e =>
    {
        e.Property(u => u.PasswordHash).IsHashedPassword();
        e.Property(u => u.Email).HasBlindIndex(nameof(User.EmailIndex), "users.email", BlindIndexNormalizers.Email);
        e.HasIndex(u => u.EmailIndex);
    });
}

// Registration: one hasher and one indexer per application.
var hasher = new PasswordHasher(new PasswordHasherOptions());
var indexer = BlindIndexer.FromBase64("2026-01", config.GetSection("BlindIndexKeys").Get<Dictionary<string, string>>()!);
services.AddDbContext<AppDbContext>(o => o.UseSqlServer(cs).UseMasterlyHash(hasher, indexer));
```

```csharp
// Sign-up: assign the plaintext and save.
db.Users.Add(new User { PasswordHash = password, Email = email });
await db.SaveChangesAsync();                 // user.PasswordHash is now "$mh$p=2026a$..."

// Login: look up by blind index, then verify (and upgrade the hash if it is outdated).
User? user = await db.Users.WhereBlindIndex(u => u.EmailIndex, email).FirstOrDefaultAsync();
var result = user is null
    ? hasher.VerifyOrDummy(password, null)   // same cost for unknown users
    : await db.VerifyAndUpgradeAsync(user, u => u.PasswordHash, password);
if (!result.IsMatch) return Unauthorized();
```

`WhereBlindIndex` on a `DbSet` reads the index name, normalizer and length from the model. For other queryables,
pass them yourself: `query.WhereBlindIndex(u => u.EmailIndex, indexer, "users.email", email, options)`.
`db.GetBlindIndexCandidates<User>(u => u.EmailIndex, email)` returns the candidate values for raw SQL.

## Why an interceptor and not a value converter

A `ValueConverter` changes only what is sent to the database. The entity would keep the plaintext after
`SaveChanges`, and it would be tracked, cached and serialized with it. A converter would also run on query
parameters, so `Where(u => u.PasswordHash == x)` would hash `x` with a new random salt, and that can never match. The
interceptor writes the hash into the entity once, before the save. Queries are not affected.

## Behaviour

- **When it runs.** Properties are processed when the entity is `Added`, or when it is `Modified` and that property is modified. Saving a user for another reason never touches the stored hash or index. A blind index is also recomputed when only the index property is modified: the index is derived data, so a value written to it directly (mass assignment, a copied row) is replaced by the one computed from the source, and a row can never carry another row's index.
- **Values that are already hashes.** A native Masterly hash this hasher recognizes is stored as-is. A value that starts with `$mh$` but is not recognized (unknown profile or pepper key, or malformed) makes the save fail. It is not hashed a second time, which would destroy it. Legacy hashes such as 1.x are treated as plaintext by default when assigned. Set `AcceptLegacyHashes` to keep them, for example when bulk-importing legacy hashes through EF.
- **Re-saving a stored hash.** `DbSet.Update(detached)` and `State = Modified` mark every property modified, so EF cannot tell a re-saved stored value from a new one. When such a value is a legacy hash or an unrecognized `$mh$` value, the interceptor reads the row first and keeps the value if the database already holds it. A not-yet-migrated 1.x hash therefore survives a disconnected update instead of being hashed into a password. Plaintext and recognized Masterly hashes never cause this extra query.
- **Null and empty.** A null password stays null. An empty password fails the save, because empty passwords cannot be hashed. A null or empty indexed value, or one that is empty after normalization, stores a null index. A value the normalizer rejects (not an email address, invalid UTF-16) fails the save.
- **Async.** `SaveChangesAsync` uses `HashAsync`, which supports remote peppers. `SaveChanges` uses the synchronous API.
- **Key rotation.** Add the new key as current and keep the old one in the ring. Lookups match either key. To re-index a row, mark the source property modified (`db.Entry(u).Property(x => x.Email).IsModified = true`) and save. Use `IBlindIndexer.NeedsReindex` to find rows that still need it. Retire the old key only after every row has been re-indexed.
- **Migrations.** Annotations store only strings, booleans and integers, so `dotnet ef migrations add` works. The built-in normalizers get ids that encode their settings (`email`, `email:strip-plus-tags`, `phone:cc=44`, ...), so they resolve the same way in every process. Any other normalizer is recorded under its type's full name. One model cannot use two differently configured instances of such a type (reuse one instance, or override `Equals`). If two models in one process do, map the id explicitly in `MasterlyHashInterceptorOptions.Normalizers`.

## Security notes

- The plaintext sits in the entity from the moment you assign it until `SaveChanges`. .NET strings cannot be zeroed. Save promptly, and do not log or serialize entities before saving.
- **Paths that skip the interceptor** write plaintext as-is: `ExecuteUpdate`/`ExecuteDelete`, raw SQL, and bulk-insert libraries. Hash explicitly (`hasher.Hash(password)`) on those paths.
- The interceptor cannot tell a plaintext that happens to be a valid hash string from a real hash. A user who submits a hash string as their password gets that string stored, so their typed password will not match. Applications that accept passwords from untrusted input may reject values starting with `$mh$`.
- `VerifyAndUpgradeAsync` calls `SaveChangesAsync`, which also saves any other pending changes. It skips the upgrade if the password property already has an unsaved change, or if the row no longer holds the verified hash (it re-reads the row just before saving, so a password reset committed during the slow verification is not overwritten). That leaves a small window between the read and the `UPDATE`. To close it, make the password column (or a row version) a concurrency token: the helper then sees the conflict, restores the property and returns the successful result, and the upgrade is retried on the next login. An upgrade that cannot be saved for this entity alone never turns a successful login into an exception. Other `SaveChangesAsync` failures are rethrown.
- Blind indexes leak equality, and with short indexes some frequency information. Keep index keys out of the database and separate from pepper keys. A blind index cannot be configured on a password property: an index of a password would allow offline guessing.
- Error messages name the entity and property, never the value.
