# Masterly.Hash.BlindIndex

![Masterly.Hash: password hashing you can't get wrong.](https://raw.githubusercontent.com/a7mdfre7at/Masterly.Hash/master/assets/banner.png)

Blind indexes for searching encrypted PII columns, following the CipherSweet / Paragon Initiative Enterprises
pattern. You encrypt a column (email, phone, national ID) with randomized encryption, and store next to it a
**blind index**: a keyed, truncated HMAC of the normalized plaintext. Equality queries go against the index, so the
database never sees the plaintext and never needs the encryption key.

```
dotnet add package Masterly.Hash.BlindIndex
```

Targets `net8.0`. Uses only the BCL's HMAC-SHA256.

## Quickstart

```csharp
using Masterly.Hash.BlindIndex;
using Masterly.Hash.BlindIndex.Normalizers;

// Keys come from a secret store, never from the database. Generate with BlindIndexer.GenerateKey().
var indexer = BlindIndexer.FromBase64("2026", new Dictionary<string, string>
{
    ["2026"] = config["BlindIndex:Keys:2026"],
});

var emailIndex = new BlindIndexOptions
{
    Normalizer = BlindIndexNormalizers.Email, // or new EmailNormalizer(stripPlusTags: true, stripGmailDots: true)
    OutputBits = 32,
};

// Write: store the ciphertext and the index.
user.EmailEncrypted = Encrypt(email);
user.EmailIndex = indexer.Compute(email, "users.email", emailIndex);   // "2026:q4Zr1w"

// Query: compute the index of the search term, then filter false positives after decrypting.
// The index matched on normalized values, so the post-filter must normalize both sides too.
string idx = indexer.Compute(input, "users.email", emailIndex);
string normalizedInput = emailIndex.Normalizer.Normalize(input);
var hits = db.Users.Where(u => u.EmailIndex == idx).AsEnumerable()
                   .Where(u => emailIndex.Normalizer.Normalize(Decrypt(u.EmailEncrypted)) == normalizedInput);

// Compound index over several columns (each part normalized separately, unambiguously encoded).
string nameDob = indexer.ComputeCompound("users.name_dob", new BlindIndexOptions { Normalizer = BlindIndexNormalizers.CaseInsensitive },
                                         lastName, birthDate.ToString("yyyy-MM-dd"));
```

Normalizers (`IBlindIndexNormalizer`, pluggable):

| Normalizer | Behaviour |
|---|---|
| `Exact` (default) | value as given |
| `Trim` | strip leading/trailing white space |
| `CaseInsensitive` | NFKC, then invariant lower-case |
| `Email` / `EmailNormalizer` | NFKC, trim, lower-case, drop trailing domain dot; opt-in `stripPlusTags` (all domains) and `stripGmailDots` (gmail.com / googlemail.com) |
| `Phone` / `PhoneNormalizer` | ASCII digits only (Unicode digits mapped), `+`/`00` prefix = international (a `(0)` trunk group after the country code is dropped), optional `defaultCountryCode` that replaces a national trunk `0` |

`PhoneNormalizer` is not an E.164 parser. Known false negatives (a search that silently misses the row): with a
`defaultCountryCode`, a number typed with its country code but without `+`/`00` (`962 79 123 4567`) is read as
national and gets the code prepended again; trunk prefixes other than `0` are not rewritten. If your input is that
varied, canonicalize to E.164 in the application (e.g. libphonenumber) and index that with `Exact`.

## Format

```
index   = keyId ":" base64-nopad( Trunc_bits( HMAC-SHA256(key, message) ) )
LP(x)   = uint32_be(len(x)) || x
single  = "masterly-blind-index/v1"          || LP(utf8(indexName)) || LP(utf8(normalize(value)))
compound= "masterly-blind-index-compound/v1" || LP(utf8(indexName)) || uint32_be(n) || LP(part1) || ... || LP(partN)
```

The index name (`^[A-Za-z0-9._:/-]{1,128}$`, e.g. `users.email`) gives domain separation: the same email in two
columns produces unrelated indexes, so an attacker cannot join tables on them. Keys are at least 32 bytes.

## Choosing the length (truncation trade-off)

A truncated HMAC maps values uniformly onto `2^bits` buckets. For a column with `n` distinct values:

* false positives per query ≈ `(n - 1) / 2^bits`
* colliding pairs in the column ≈ `n(n - 1) / 2^(bits + 1)` (birthday bound)

**Shorter indexes mean more false positives, which means more privacy.** With many values per bucket, a leaked index
column does not pin rows to values, and an attacker who can guess candidates (low-entropy data such as phone numbers or
birth dates) learns only a bucket. Longer indexes are close to a deterministic encryption of the value: rows can be
counted, grouped and confirmed against guesses.

| distinct values `n` | 16 bits | 32 bits | 64 bits |
|---|---|---|---|
| 10,000 | 0.15 FP/query | 2.3e-6 | 5.4e-16 |
| 1,000,000 | 15 FP/query | 2.3e-4 | 5.4e-14 |
| 100,000,000 | 1,526 FP/query | 0.023 | 5.4e-12 |

Pick the shortest length your query cost tolerates; `BlindIndexMath.MinimumOutputBits(n, maxFalsePositives)` does the
arithmetic. CipherSweet's guideline is to keep at least 2 expected rows per index value (`n / 2^bits >= 2`) for
sensitive, guessable data. Multiple indexes over the same column add up: their bits combine, so keep the **total**
bits across indexes on one column small. Always re-check the decrypted value; an index match is only a candidate.

## Security notes

* **Keys live outside the database** (environment, Key Vault, KMS). A database leak plus the key lets an attacker
  brute-force low-entropy values offline.
* **Never reuse keys between environments** (dev/staging/prod) or between purposes (e.g. a password pepper). Use
  `BlindIndexer.GenerateKey()` per environment.
* **Rotate by re-indexing.** Add the new key to the ring and make it current; new writes use it. While a background job
  re-computes `Compute(...)` for rows where `NeedsReindex(row.Index)` is true, query with
  `WHERE idx IN (@i0, @i1, ...)` using `ComputeAll(...)`. When no row uses the old key id, remove it from the ring.
* **Changing a normalizer or `OutputBits` is a re-index**, as is changing the index name.
* Normalization (NFKC, lower-casing) uses the runtime's Unicode tables; rare characters may normalize differently after
  a major .NET upgrade. Re-index if you depend on exotic scripts.
* Blind indexes support equality only. They reveal which rows share a value bucket; they do not hide the number of rows.
* Exceptions never contain the value being indexed.
