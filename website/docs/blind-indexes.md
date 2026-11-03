---
title: Blind Indexes
sidebar_label: Blind Indexes
description: Search encrypted PII columns by equality with keyed, truncated HMAC indexes, with normalizers, compound indexes, key rotation and Entity Framework Core support.
---

`Masterly.Hash.BlindIndex` lets you search an encrypted column without decrypting it. You encrypt the column (email, phone number, national ID) with randomized encryption, and store next to it a **blind index**: a keyed, truncated HMAC of the normalized plaintext. Equality queries go against the index, so the database never sees the plaintext and never needs the encryption key. The design follows the CipherSweet pattern from Paragon Initiative Enterprises.

```bash
dotnet add package Masterly.Hash.BlindIndex
```

The package targets `net8.0`, depends only on `Masterly.Hash` and uses the BCL's HMAC-SHA256. The main types are in `Masterly.Hash.BlindIndex`; the normalizer classes are in `Masterly.Hash.BlindIndex.Normalizers`.

## When to use a blind index

Use one when:

- A column holds personal data that you encrypt at rest, and you still need `WHERE email = @email` (login by email, duplicate checks, support lookups).
- You want a stolen database dump, without your keys, to reveal neither the values nor which rows share them across columns.

Do not use one when:

- You need range queries, sorting, `LIKE` or full-text search. Blind indexes support **equality only**.
- The value is a password. A fast HMAC of a password allows offline guessing by anyone who has the key; hash passwords with `PasswordHasher` instead.
- The column is not encrypted. An index next to plaintext adds nothing.

:::note

The package does not encrypt anything. Encrypt the source column with your own scheme (an EF Core value converter, Always Encrypted, application-level AES-GCM). The blind index is the searchable companion of that ciphertext.

:::

## Quick start

**1. Create the indexer.** Keys come from a secret store, never from the database. Generate one per environment with `BlindIndexer.GenerateKey()` and store it as base64.

```csharp title="Program.cs"
using System;
using System.Collections.Generic;
using Masterly.Hash.BlindIndex;

Dictionary<string, string> keys = builder.Configuration.GetSection("BlindIndex:Keys").Get<Dictionary<string, string>>()
    ?? throw new InvalidOperationException("BlindIndex:Keys is not configured.");

BlindIndexer indexer = BlindIndexer.FromBase64("2026", keys);
builder.Services.AddSingleton<IBlindIndexer>(indexer);
```

**2. Define the index options once** and use the same instance for writes and queries.

```csharp title="UserIndexes.cs"
using Masterly.Hash.BlindIndex;

namespace MyApp.Data;

public static class UserIndexes
{
    public const string EmailIndexName = "users.email";

    public static readonly BlindIndexOptions Email = new BlindIndexOptions
    {
        Normalizer = BlindIndexNormalizers.Email,
        OutputBits = 32,
    };
}
```

**3. Write the index** next to the ciphertext.

```csharp
user.EmailEncrypted = _encryption.Encrypt(email);
user.EmailIndex = _indexer.Compute(email, UserIndexes.EmailIndexName, UserIndexes.Email); // for example "2026:q4Zr1w"
```

**4. Query by the index, then confirm after decrypting.** An index match is only a candidate: different values can share an index (see [Choosing the length](#choosing-the-length)). The index matched normalized values, so normalize both sides of the comparison too.

```csharp
IReadOnlyList<string> candidates = _indexer.ComputeAll(input, UserIndexes.EmailIndexName, UserIndexes.Email);
List<User> rows = await _db.Users.Where(u => candidates.Contains(u.EmailIndex)).ToListAsync(cancellationToken);

string normalizedInput = UserIndexes.Email.Normalizer.Normalize(input);
User? user = rows.SingleOrDefault(
    u => UserIndexes.Email.Normalizer.Normalize(_encryption.Decrypt(u.EmailEncrypted)) == normalizedInput);
```

`ComputeAll` returns the index under every key in the ring, so rows written under an older key are still found during [key rotation](#rotating-keys). With a single key it returns one value.

## The indexer

`BlindIndexer` implements `IBlindIndexer`. It is thread-safe; create one per application and register it as a singleton.

| Constructor or factory | Use |
|------------------------|-----|
| `new BlindIndexer(keyId, key)` | A single key. |
| `new BlindIndexer(currentKeyId, keys)` | A key ring: `IReadOnlyDictionary<string, byte[]>`. |
| `BlindIndexer.FromBase64(currentKeyId, base64Keys)` | A key ring of base64 strings, for example bound from configuration. |
| `BlindIndexer.GenerateKey()` | Returns 32 random bytes from the OS CSPRNG. |

| Rule | Value |
|------|-------|
| Key id | `^[A-Za-z0-9-]{1,32}$` |
| Key length | At least 32 bytes (`BlindIndexer.MinKeyLength`) |
| Current key | Must be in the ring |

Construction errors throw `ArgumentException` (`ArgumentNullException` for a null dictionary, or a null key id passed to the single-key constructor): an invalid or null key id, a null or short key, a missing current key, or (for `FromBase64`) a value that is not valid base64. The message names the key id, never the key. The indexer copies the keys, and `FromBase64` zeroes its decoded copies.

`IBlindIndexer` members:

| Member | Returns |
|--------|---------|
| `CurrentKeyId` | The key id new indexes are written under. |
| `KeyIds` | Every key id, current first, then the others in ordinal order. |
| `Compute(value, indexName, options = null)` | The index under the current key. |
| `ComputeWithKey(keyId, value, indexName, options = null)` | The index under a specific key. Throws `ArgumentException` if the key is not in the ring. |
| `ComputeAll(value, indexName, options = null)` | The index under every key, current first. |
| `ComputeCompound(indexName, params parts)` | A compound index under the current key, with default options. |
| `ComputeCompound(indexName, options, params parts)` | A compound index under the current key. |
| `ComputeCompoundAll(indexName, params parts)` / `ComputeCompoundAll(indexName, options, params parts)` | A compound index under every key, current first. |
| `Matches(storedIndex, value, indexName, options = null)` | True if the stored index is the index of the value under the key it names. Constant-time. |
| `NeedsReindex(storedIndex)` | True if the stored index is malformed or was not computed under the current key. |

`BlindIndexer.TryGetKeyId(storedIndex, out keyId)` is a static helper that reads the key id of a stored index, for example to count rows per key during rotation. It returns false for a malformed index and never throws.

### Index names

Every call takes an index name such as `users.email`. It provides domain separation: the same email in `users.email` and `orders.contact_email` produces unrelated indexes, so an attacker with the database cannot join the two tables on them.

- The name must match `^[A-Za-z0-9._:/-]{1,128}$` (`BlindIndexer.MaxIndexNameLength` is 128).
- Use one name per column and never change it for existing data. A new name is a new index; every row must be re-indexed.

### Errors

The indexer throws for invalid arguments and never puts the value in an exception message, because it is personal data.

| Situation | Exception |
|-----------|-----------|
| `value`, `indexName`, `keyId` or `parts` is null | `ArgumentNullException` |
| Index name does not match the pattern | `ArgumentException` |
| Value is empty after normalization | `ArgumentException` |
| Every compound part is empty after normalization, or `parts` is empty | `ArgumentException` |
| Value contains invalid UTF-16 (a lone surrogate) | `ArgumentException` |
| The normalizer rejects the value (for example, not an email address) | `ArgumentException` from the normalizer |
| A custom normalizer returns null | `InvalidOperationException` |
| `ComputeWithKey` with a key id not in the ring | `ArgumentException` |

`Matches` returns false, without throwing, for a malformed stored index, an unknown key id or a stored index whose length differs from `OutputBits`. It still throws for an invalid `value` or `indexName`, because it has to compute the index to compare.

## Options

`BlindIndexOptions` sets the length and the normalizer of an index. Passing `null` uses the defaults: 64 bits and `Exact`.

| Option | Default | Range |
|--------|---------|-------|
| `OutputBits` | 64 (`BlindIndexOptions.DefaultOutputBits`) | A multiple of 8 from 16 (`MinOutputBits`) to 256 (`MaxOutputBits`). The setter throws `ArgumentOutOfRangeException` otherwise. |
| `Normalizer` | `BlindIndexNormalizers.Exact` | Any `IBlindIndexNormalizer`. The setter throws `ArgumentNullException` for null. |

`BlindIndexOptions.IsValidOutputBits(bits)` checks a length without throwing.

:::warning

Use the **same** options for writes and queries. Changing the normalizer, the length or the index name of an existing index is a re-index: every row must be recomputed, or lookups silently miss them.

:::

## Normalizers

A normalizer turns values that should match into the same string before hashing, so `Alice@Example.com` and `alice@example.com` produce the same index.

| Normalizer | Behaviour | Example |
|------------|-----------|---------|
| `BlindIndexNormalizers.Exact` (default) | The value as given. No trimming, no Unicode normalization. | `" Alice "` stays `" Alice "` |
| `BlindIndexNormalizers.Trim` | Removes leading and trailing white space. | `"  Alice \t\n"` becomes `"Alice"` |
| `BlindIndexNormalizers.CaseInsensitive` | Unicode NFKC, then invariant lower-casing. Does not trim. | `"Ｈｅｌｌｏ"` (full-width) becomes `"hello"` |
| `BlindIndexNormalizers.Email` | NFKC, trim, invariant lower-case, drop a trailing dot from the domain. | `"  Alice@Example.COM "` becomes `"alice@example.com"` |
| `BlindIndexNormalizers.Phone` | ASCII digits only, with the international-prefix rules below. | `"+962 79 123 4567"` becomes `"962791234567"` |

`BlindIndexNormalizers` holds shared instances. For other settings, create `EmailNormalizer` or `PhoneNormalizer` yourself.

### Email

`new EmailNormalizer(stripPlusTags: false, stripGmailDots: false)`:

- The last `@` separates the domain, so a quoted local part may contain `@`.
- `stripPlusTags`: removes a `+tag` sub-address from the local part for every domain. `john.doe+news@Example.com` becomes `john.doe@example.com`. A local part that is only a tag (`+leading@x.org`) is kept.
- `stripGmailDots`: for `gmail.com` and `googlemail.com` only, removes dots from the local part and maps `googlemail.com` to `gmail.com`. `J.O.H.N.Doe@gmail.com` becomes `johndoe@gmail.com`.
- A value with no `@`, an empty local part or an empty domain (`no-at-sign`, `@example.com`, `alice@`, `alice@.`) throws `ArgumentException`.

Both rewrites are off by default because they merge addresses that some providers treat as distinct. Turn them on only if your application already treats those addresses as one account.

### Phone

`new PhoneNormalizer(defaultCountryCode: null)`:

- Every Unicode decimal digit (Arabic-Indic, full-width, supplementary-plane digits) is mapped to its ASCII equivalent. Every other character (spaces, dashes, parentheses, dots, `+`, letters) is dropped. `"(079) 123.4567"` becomes `"0791234567"`.
- A leading `+` or `00` marks an international number. `00` is removed, so `+962...` and `00962...` match.
- In an international number, a parenthesised trunk zero after the country code is dropped: `+44 (0)20 7946 0958` matches `+44 20 7946 0958`.
- With a `defaultCountryCode` (1 to 3 ASCII digits, no leading zero, no `+`), a national number (neither prefix) has one leading `0` removed and the country code prepended. With country code `962`, `079 123 4567` matches `+962 79 123 4567`. An invalid code throws `ArgumentException`.
- A value with no digits normalizes to an empty string, which the indexer rejects.

:::warning

`PhoneNormalizer` is not an E.164 parser, and a mismatch is a silent false negative: the search misses the row. Known cases: with a `defaultCountryCode`, a number written with its country code but without `+` or `00` (`962 79 123 4567`) is read as national and gets the code prepended again; countries whose trunk prefix is not `0` are not rewritten; extensions are kept as digits. Always normalize the raw input, never an already-normalized value. If your input is that varied, canonicalize to E.164 in the application (for example with libphonenumber) and index the result with `Exact`.

:::

### Custom normalizers

Implement `IBlindIndexNormalizer`:

```csharp title="NationalIdNormalizer.cs"
using System;
using Masterly.Hash.BlindIndex;

namespace MyApp.Data;

public sealed class NationalIdNormalizer : IBlindIndexNormalizer
{
    public string Normalize(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        string compact = value.Replace(" ", string.Empty).Replace("-", string.Empty);
        if (compact.Length != 10)
        {
            throw new ArgumentException("Value is not a national ID.", nameof(value)); // never include the value
        }

        return compact.ToUpperInvariant();
    }
}
```

The contract:

- Deterministic. Do not depend on the current culture, the time or the machine.
- Throw `ArgumentNullException` for null and `ArgumentException` for a value that cannot be normalized. Never put the value in the message.
- Never return null; the indexer throws `InvalidOperationException` if you do.

NFKC and lower-casing use the runtime's Unicode tables, so rare characters may normalize differently after a major .NET upgrade. If you depend on exotic scripts, re-index after upgrading.

## Compound indexes

A compound index covers several values at once, for example last name and birth date. Each part is normalized separately and encoded with its length, so `("ab", "c")` and `("a", "bc")` never collide.

```csharp
BlindIndexOptions nameDob = new BlindIndexOptions { Normalizer = BlindIndexNormalizers.CaseInsensitive };

string index = _indexer.ComputeCompound("people.name_dob", nameDob, lastName, birthDate.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture));
```

- At least one part is required, and at least one part must be non-empty after normalization. Individual empty parts are allowed.
- Parts cannot be null.
- A compound index never equals a single-value index, even for one part: the two use different domain tags.
- Format dates and numbers with the invariant culture so the same value always produces the same string.

A compound index answers "last name **and** birth date equal X and Y", not either one alone. It is also useful to index a low-entropy value together with a higher-entropy one, so the index leaks less than an index of the low-entropy value would.

## Choosing the length

A truncated HMAC spreads values uniformly over `2^bits` buckets. For a column with `n` distinct values:

- false positives per query are about `(n - 1) / 2^bits`;
- colliding pairs in the column are about `n(n - 1) / 2^(bits + 1)` (the birthday bound).

**Shorter indexes mean more false positives, and more privacy.** With many values per bucket, a leaked index column does not pin rows to values, and an attacker who can guess candidates (low-entropy data such as phone numbers or birth dates) learns only a bucket. A long index is close to a deterministic encryption of the value: rows can be counted, grouped and confirmed against guesses.

| Distinct values `n` | 16 bits | 32 bits | 64 bits |
|---------------------|---------|---------|---------|
| 10,000 | 0.15 false positives per query | 2.3e-6 | 5.4e-16 |
| 1,000,000 | 15 | 2.3e-4 | 5.4e-14 |
| 100,000,000 | 1,526 | 0.023 | 5.4e-12 |

`BlindIndexMath` does the arithmetic:

| Method | Returns |
|--------|---------|
| `ExpectedFalsePositivesPerQuery(distinctValues, outputBits)` | `(n - 1) / 2^bits`; 0 when `n` is 0 or 1 |
| `ExpectedCollidingPairs(distinctValues, outputBits)` | `n(n - 1) / 2^(bits + 1)`; 0 when `n` is 0 or 1 |
| `MinimumOutputBits(distinctValues, maxFalsePositivesPerQuery)` | The smallest valid length (16, 24, ... 248) whose expected false positives are at or below the target, or 256 if none is |

They throw `ArgumentOutOfRangeException` for a negative `n`, an invalid length or a target that is not a positive finite number.

```csharp
int bits = BlindIndexMath.MinimumOutputBits(1_000_000, maxFalsePositivesPerQuery: 0.001); // 32
```

Guidance:

- Pick the **shortest** length your query cost tolerates. Every false positive costs one extra row to fetch and decrypt.
- For sensitive, guessable data, CipherSweet's guideline is to keep at least 2 expected rows per index value (`n / 2^bits >= 2`). For a million phone numbers that is 16 bits.
- Several indexes over the same column add up: their bits combine. Keep the **total** bits across all indexes of one column small.
- The default of 64 bits gives effectively unique indexes. Use it for high-entropy values, or when false positives would be expensive and the values are not guessable.

### Column size

A stored index is `<keyId>:<unpadded base64>`. The base64 part is 3 characters for 16 bits, 6 for 32, 11 for 64, 22 for 128 and 43 for 256. With a 32-character key id the longest possible index is 76 characters. Give the column a (non-unique) database index: distinct values can share a blind index by design.

## Rotating keys

1. **Add the new key and make it current.** New writes use it.
2. **Query with every key.** Use `ComputeAll` (or `ComputeCompoundAll`) and `WHERE idx IN (...)`, so rows not yet re-indexed are still found.
3. **Re-index in the background.** For each row where `NeedsReindex(row.EmailIndex)` is true, decrypt the source value and store `Compute(...)` again. `BlindIndexer.TryGetKeyId` lets you count rows per key to track progress.
4. **Remove the old key** from the ring once no row uses its key id.

:::danger

Removing a key before every row is re-indexed makes those rows unfindable. `ComputeAll` no longer produces the old index, and the search silently misses them.

:::

## Format

```
index    = keyId ":" base64-nopad( Trunc_bits( HMAC-SHA256(key, message) ) )
LP(x)    = uint32_be(len(x)) || x
single   = "masterly-blind-index/v1"          || LP(utf8(indexName)) || LP(utf8(normalize(value)))
compound = "masterly-blind-index-compound/v1" || LP(utf8(indexName)) || uint32_be(n) || LP(utf8(normalize(part1))) || ... || LP(utf8(normalize(partN)))
```

Truncation keeps the first `OutputBits / 8` bytes of the HMAC. Values are encoded as strict UTF-8; a lone surrogate is rejected rather than replaced, so two distinct invalid strings can never share an index. The test suite pins this format with vectors computed independently in Python ([KnownAnswerTests.cs](https://github.com/a7mdfre7at/Masterly.Hash/blob/master/test/Masterly.Hash.BlindIndex.Tests/KnownAnswerTests.cs)).

## With Entity Framework Core

`Masterly.Hash.EntityFrameworkCore` keeps blind-index columns up to date on `SaveChanges` and queries them during key rotation. Mark the source property in the model and pass the indexer to `UseMasterlyHash`:

```csharp title="AppDbContext.cs"
using Masterly.Hash.BlindIndex;
using Masterly.Hash.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

protected override void OnModelCreating(ModelBuilder modelBuilder)
{
    modelBuilder.Entity<User>(entity =>
    {
        entity.Property(u => u.Email)                 // encrypted by your value converter; the entity holds plaintext
            .HasBlindIndex(nameof(User.EmailIndex), "users.email", BlindIndexNormalizers.Email, outputBits: 32);
        entity.HasIndex(u => u.EmailIndex);
    });
}
```

```csharp title="Program.cs"
builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseSqlServer(connectionString).UseMasterlyHash(passwordHasher, indexer));
```

```csharp
User? user = await db.Users.WhereBlindIndex(u => u.EmailIndex, email).FirstOrDefaultAsync(cancellationToken);
```

`HasBlindIndex(indexPropertyName, indexName, normalizer = null, outputBits = 64)` throws `ArgumentNullException` for a null index property name or index name; `ArgumentException` when the source is not a string property, the index property name is empty or is the source itself, the index name is invalid, the source is already marked `IsHashedPassword`, or the model already uses a differently configured instance of the same custom normalizer type; and `ArgumentOutOfRangeException` for an invalid length. When the interceptor builds its plan, an index property that does not exist, is not a string or is the primary key, a normalizer id that cannot be resolved, or two indexes that write to the same property, fail with `InvalidOperationException`. A password property cannot be the source of a blind index, because an index of a password would allow offline guessing.

What the interceptor does:

- It recomputes the index when the entity is added, when the source property is modified, and when the index property itself is modified. The index is derived data, so a value written to it directly is replaced by the one computed from the source.
- A null or empty source value, or one that is empty after normalization, stores a null index.
- A value the normalizer rejects fails the save with `InvalidOperationException` naming the entity, property and index, never the value. The normalizer's `ArgumentException` is the inner exception.
- A model with `HasBlindIndex` but no indexer passed to `UseMasterlyHash` fails the save with `InvalidOperationException` as soon as a non-empty source value has to be indexed.
- To re-index a row after rotation, mark the source property modified (`db.Entry(user).Property(u => u.Email).IsModified = true`) and save.

Querying:

| Method | Behaviour |
|--------|-----------|
| `DbSet<TEntity>.WhereBlindIndex(indexProperty, value)` | Reads the index name, normalizer and length from the model and matches the value under every key in the ring. |
| `IQueryable<TEntity>.WhereBlindIndex(indexProperty, indexer, indexName, value, options = null)` | The same for any queryable, with the settings passed explicitly. |
| `DbContext.GetBlindIndexCandidates<TEntity>(indexProperty, value)` | The candidate index values, current key first, for raw SQL. |

Each candidate becomes a SQL parameter in an `OR` chain, so rows written under an older key are found and the provider needs no JSON or array support. An empty value, or one that is empty after normalization, matches nothing. The `DbSet` overload and `GetBlindIndexCandidates` throw `InvalidOperationException` if the context was not configured with `UseMasterlyHash`, no `HasBlindIndex` writes to the property, or no indexer was passed to `UseMasterlyHash`. A value the normalizer rejects (for example, not an email address) throws `ArgumentException` from all three.

The model stores only the normalizer's id, so migrations work. The built-in normalizers have the ids `exact`, `trim`, `case-insensitive`, `email` and `phone`, and configured instances get ids that encode their settings (`email:strip-plus-tags`, `email:strip-plus-tags,strip-gmail-dots`, `phone:cc=44`). A custom normalizer is recorded under its type's full name, so one model cannot use two differently configured instances of the same custom type; map ids explicitly with `MasterlyHashInterceptorOptions.Normalizers` when needed. Full details are in [Entity Framework Core](./entity-framework-core.md).

## Security notes

- **Keys live outside the database** (environment, Key Vault, KMS). A database leak plus the key lets an attacker brute-force low-entropy values offline.
- **Never reuse keys** between environments or between purposes, such as a password pepper or an API-key ring.
- **Blind indexes leak equality.** They reveal which rows share a bucket, and with long indexes, which rows share a value. They do not hide the number of rows.
- **Always re-check the decrypted value.** An index match is only a candidate.
- **Exceptions never contain the value** being indexed, from both the indexer and the built-in normalizers.

## See also

- [Entity Framework Core](./entity-framework-core.md): `HasBlindIndex`, `WhereBlindIndex` and the save interceptor.
- [API Keys and Tokens](./api-keys-and-tokens.md): keyed lookup hashes for secrets you issue.
- [HashiCorp Vault](./hashicorp-vault.md): keeping keys in a vault.
- [Threat Model](./threat-model.md)
- [BlindIndexer.cs on GitHub](https://github.com/a7mdfre7at/Masterly.Hash/blob/master/src/Masterly.Hash.BlindIndex/BlindIndexer.cs)
