---
title: API Keys and Signed Tokens
sidebar_label: API Keys and Tokens
description: Issue checksummed API keys stored as indexable HMAC lookup hashes, and create signed, expiring, purpose-bound tokens for password resets and magic links.
---

`Masterly.Hash.Tokens` handles the secrets that are not passwords: machine-generated, high-entropy values that your application issues itself. It has three parts:

- **API keys** in the GitHub-token style (`mh_live_<random><checksum>`), stored as a fast keyed lookup hash that fits in a unique index.
- **Signed tokens** for password resets, email confirmation and magic links. They are URL-safe, expiring, bound to a purpose and signed with HMAC-SHA256. Single use is optional.
- **Secure random strings** over any alphabet, without modulo bias, for one-time codes and recovery codes.

```bash
dotnet add package Masterly.Hash.Tokens
```

The package targets `net8.0` and depends only on `Masterly.Hash`. Every type is in the `Masterly.Hash.Tokens` namespace.

:::danger

Never use this package for passwords. API keys and tokens carry 128 bits or more of randomness, so a fast HMAC is safe for them. A password chosen by a person is guessable, and only a slow hash such as `PasswordHasher` protects it. See [Hashing and Verifying](./hashing-and-verifying.md).

:::

## Why API keys need a different hash

A password hash is slow on purpose and salted at random, so you cannot look a row up by it. You have to load the user by name first and then verify. An API key arrives with no user name. If you stored it with Argon2id, you would have to try every row.

`ApiKeyHasher` uses a deterministic, keyed hash instead:

- The same key always produces the same lookup hash, so you can store it in a **unique index** and find the row in one query.
- The hash is an HMAC under a secret key that lives **outside the database**. A stolen database alone does not let anyone confirm a guessed key.
- Brute force is not a concern: a key has at least 128 random bits.

## Key rings

Both `ApiKeyHasher` and `SignedTokenService` take an `HmacKeyRing`: a set of named HMAC keys with one current key. New values are made with the current key. Values made with any key still in the ring keep verifying, which is how you rotate keys.

```csharp title="KeyRings.cs"
using System.Collections.Generic;
using Masterly.Hash.Tokens;

// Generate a key once, store it in your secret store as base64, and load it at startup.
byte[] newKey = HmacKeyRing.GenerateKey(); // 32 random bytes

// From base64 strings, for example bound from configuration:
HmacKeyRing apiKeyRing = HmacKeyRing.FromBase64("k2", new Dictionary<string, string>
{
    ["k1"] = configuration["ApiKeys:Keys:k1"]!, // IConfiguration returns string?; both keys are required
    ["k2"] = configuration["ApiKeys:Keys:k2"]!,
});

// From raw bytes, with a single key:
HmacKeyRing tokenRing = new HmacKeyRing("t1", newKey);
```

| Rule | Value |
|------|-------|
| Key id | `^[A-Za-z0-9-]{1,32}$` (`HmacKeyRing.MaxKeyIdLength` is 32) |
| Key length | At least 32 bytes (`HmacKeyRing.MinKeyLength`) |
| Current key | Must be one of the keys in the ring |
| `GenerateKey()` | Returns 32 random bytes from the OS CSPRNG |

The constructors throw `ArgumentNullException` for a null key id or key dictionary, and `ArgumentException` for an invalid key id, a short or null key, or a current key that is not in the ring. `FromBase64` throws `ArgumentException` for a null value and `FormatException` when a value is not valid base64. The ring copies the keys it is given, and `FromBase64` zeroes its decoded copies afterwards.

Other members: `CurrentKeyId`, `KeyIds` (every id, in ordinal order), `Contains(keyId)` and the static `IsValidKeyId(keyId)`.

**Key separation.** A ring key is never used directly. `ApiKeyHasher` derives its own subkey, `HMAC-SHA256(ringKey, 0xFF || "Masterly.Hash.Tokens/ApiKeyLookup/v1")`, and `SignedTokenService` derives a different one with the label `Masterly.Hash.Tokens/SignedToken/v1`. A lookup hash therefore reveals nothing about the token-signing key, even when both use the same ring. Separate rings for API keys and tokens are still recommended.

:::warning

Do not reuse these keys anywhere else: not as a password pepper, not as a blind-index key, and not across environments. Give development, staging and production their own keys.

:::

## API keys

### Key format

```
<prefix>_<base62 random><base62 CRC-32, 6 chars>
mh_live_4FzQ...x1a2B3
```

- **Prefix.** Names the issuer and environment, so leaked keys can be recognised by secret scanners. 1 to 32 ASCII letters, digits and single underscores, starting with a letter and not ending with an underscore. `mh`, `mh_live` and `acme_test2` are valid; `_mh`, `mh_`, `mh__live` and `2mh` are not. `ApiKey.IsValidPrefix(prefix)` checks it.
- **Random part.** 16 to 64 random bytes from the OS CSPRNG, written in fixed-length base62 (alphabet `0-9A-Za-z`). The default is 32 bytes (256 bits), which is 43 characters.
- **Checksum.** The CRC-32 (IEEE) of the ASCII text `<prefix>_<random>`, written as 6 base62 digits.

| Constant | Value |
|----------|-------|
| `ApiKey.DefaultEntropyBytes` | 32 (43 base62 characters) |
| `ApiKey.MinEntropyBytes` | 16 (22 base62 characters) |
| `ApiKey.MaxEntropyBytes` | 64 (86 base62 characters) |
| `ApiKey.ChecksumLength` | 6 |
| `ApiKey.MaxPrefixLength` | 32 |
| `ApiKey.MaxLength` | 125, the longest key the format can produce; longer input is rejected unparsed |

With the default entropy, a key is the prefix plus 50 characters (`_`, 43 random, 6 checksum). Base62 needs no escaping in URLs, headers or file names, and a double-click selects the whole key.

:::note

The checksum is **not** a security control. Anyone can compute it. It lets you reject typos and garbage before touching the database, and it lets secret scanners tell a real key from a look-alike. A valid checksum says nothing about whether the key was ever issued.

:::

### Generating a key

Create one hasher and one generator per application and register them as singletons. Both are thread-safe.

```csharp title="Program.cs"
using Masterly.Hash.Tokens;

ApiKeyHasher apiKeyHasher = new ApiKeyHasher(apiKeyRing);
ApiKeyGenerator generator = new ApiKeyGenerator(apiKeyHasher, "mh_live"); // entropyBytes defaults to 32

builder.Services.AddSingleton(apiKeyHasher);
builder.Services.AddSingleton(generator);
```

```csharp title="ApiKeyEndpoints.cs"
GeneratedApiKey created = generator.Generate();

db.ApiKeys.Add(new ApiKeyRecord
{
    OwnerId = ownerId,
    LookupHash = created.LookupHash, // put a unique index on this column
    Hint = created.Hint,             // "mh_live_...a1B2", safe to show in a UI
});
await db.SaveChangesAsync(cancellationToken);

// Show created.PlainText to the owner exactly once. It cannot be recovered from the lookup hash.
return Results.Ok(new { apiKey = created.PlainText });
```

`ApiKeyGenerator` checks the prefix and entropy in its constructor (`ArgumentException` for a bad prefix, `ArgumentOutOfRangeException` for entropy outside 16 to 64) and exposes `Prefix`, `EntropyBytes` and `Hasher`. Without a generator, call the static methods directly:

| Method | Returns |
|--------|---------|
| `ApiKey.Generate(prefix, entropyBytes = 32)` | The key as a `string` |
| `ApiKey.Generate(hasher, prefix, entropyBytes = 32)` | A `GeneratedApiKey` with the lookup hash already computed |

`GeneratedApiKey` holds:

| Property | Meaning |
|----------|---------|
| `PlainText` | The key. Show it once; never store or log it. |
| `Prefix` | The prefix, for example `mh_live`. |
| `LookupHash` | The value to store: `<keyId>:<base64 HMAC-SHA256>`. |
| `Hint` | A non-secret label: the prefix, `_...` and the last four characters (part of the checksum). |

`ToString()` returns the hint, never the key, so a `GeneratedApiKey` that ends up in a log or the debugger does not leak.

### Storing the lookup hash

A lookup hash is `<keyId>:<43 base64 characters>`, unpadded standard base64 of a 32-byte HMAC-SHA256. With a 32-character key id it is at most 76 characters, so a `varchar(76)` (or `nvarchar(76)`) column fits every value. Give the column a **unique** index.

Keep the key id in the stored value. It is how `Verify` knows which ring key to use and how `NeedsRehash` spots values made with an old key.

### Authenticating a request

Check the request in this order:

1. **Reject malformed keys offline.** `ApiKey.HasValidChecksum` rejects typos, truncated keys and random garbage without a database query. It never throws.
2. **Look the key up.** Compute the lookup hash under every key in the ring and query with `IN`, so keys hashed under an older ring key are still found.
3. **Verify.** `Verify` recomputes the HMAC under the key id stored in the row and compares in constant time.
4. **Upgrade.** If the stored value was made with an old ring key, replace it.

```csharp title="ApiKeyAuthentication.cs"
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Masterly.Hash.Tokens;
using Microsoft.EntityFrameworkCore;

public async Task<ApiKeyRecord?> AuthenticateAsync(string? presented, CancellationToken cancellationToken)
{
    if (presented is null || !ApiKey.HasValidChecksum(presented))
    {
        return null;
    }

    IReadOnlyList<string> candidates = _hasher.ComputeAllLookupHashes(presented);
    ApiKeyRecord? record = await _db.ApiKeys
        .SingleOrDefaultAsync(k => candidates.Contains(k.LookupHash) && k.RevokedAt == null, cancellationToken);

    if (record is null || !_hasher.Verify(presented, record.LookupHash))
    {
        return null;
    }

    if (_hasher.NeedsRehash(record.LookupHash))
    {
        record.LookupHash = _hasher.ComputeLookupHash(presented); // move the row to the current ring key
        await _db.SaveChangesAsync(cancellationToken);
    }

    return record;
}
```

`HasValidChecksum` returns false for anything longer than `ApiKey.MaxLength` (125), so the hasher methods that follow never see over-long input.

`ApiKeyHasher` members:

| Member | Behaviour |
|--------|-----------|
| `ComputeLookupHash(apiKey)` | Lookup hash under the current key. Throws `ArgumentNullException` for null and `ArgumentException` for an empty key, one longer than 1024 characters (`ApiKeyHasher.MaxApiKeyLength`) or invalid UTF-16. |
| `ComputeAllLookupHashes(apiKey)` | One lookup hash per ring key, current key first, then the others in ordinal order. Same exceptions. |
| `Verify(apiKey, storedLookupHash)` | Constant-time check. Never throws: null, empty, oversized or malformed input, and a hash made with a key no longer in the ring, all return false. |
| `NeedsRehash(storedLookupHash)` | True if the value was not made with the current key, or is not a lookup hash at all. |
| `ApiKeyHasher.TryGetKeyId(storedLookupHash, out keyId)` | Static. Reads the key id, for example to count rows per key during rotation. Returns false for a malformed value. |
| `KeyRing` | The ring the hasher was built with. |

`ApiKeyHasher` accepts any string up to 1024 characters, not only keys made by `ApiKey`. You can use it for other high-entropy secrets you issue, such as webhook secrets or long random invitation codes.

### Parsing a key

`ApiKey.TryParse(apiKey, out ApiKeyParts? parts)` splits a well-formed key whose checksum matches. It never throws.

```csharp
if (ApiKey.TryParse(presented, out ApiKeyParts? parts))
{
    _logger.LogInformation("API key presented: {ApiKey}", parts); // logs "mh_live_***a1B2C3"
}
```

| Property | Meaning |
|----------|---------|
| `Prefix` | The prefix. Use it to reject a test key in production (`mh_test` versus `mh_live`). |
| `RandomPart` | The secret random part. Treat it like the whole key. |
| `Checksum` | The 6-character checksum. |
| `EntropyBytes` | Number of random bytes the key carries. |

`ApiKeyParts.ToString()` returns the prefix, `_***` and the checksum, never the random part.

### Rotating the lookup key

1. **Add a new key and make it current.** For example, a ring of `k1` and `k2` with `k2` current. New keys get lookup hashes under `k2`.
2. **Keep finding old rows.** `ComputeAllLookupHashes` returns one hash per ring key, so the `IN` query in the authentication code above still finds rows hashed under `k1`.
3. **Upgrade on use.** When `NeedsRehash` is true after a successful `Verify`, replace the stored value with `ComputeLookupHash`.
4. **Retire the old key.** Rows of keys that are never used keep their old lookup hash, because only the plaintext key can produce a new one. Count them with `ApiKeyHasher.TryGetKeyId`. When none remain, or after you have asked their owners to re-issue, remove `k1` from the ring.

:::warning

Removing a key from the ring permanently invalidates every API key still hashed under it. `Verify` returns false for them.

:::

### Issuing keys from the command line

The `masterly-hash` tool can print a new key and its lookup hash, for seeding a database or a CI secret: `masterly-hash apikey generate --prefix mh_live --key-env APIKEY_LOOKUP_KEY`. The HMAC lookup key is read from an environment variable (`--key-env`) or standard input (`--key-stdin`), never from an argument; with neither option, the tool generates a new lookup key and prints it once. See [Command-Line Tool](./command-line-tool.md).

## Signed tokens

`SignedTokenService` creates and validates tokens for password resets, email confirmation and magic links. A token carries a purpose, a subject (such as a user id), an issue time, an expiry and a random nonce, all covered by an HMAC-SHA256 tag. Tokens are stateless: nothing is stored when you create one.

```csharp title="Program.cs"
using System;
using Masterly.Hash.Tokens;

SignedTokenService tokens = new SignedTokenService(tokenRing, new SignedTokenOptions
{
    ClockSkew = TimeSpan.FromSeconds(30),
    MaxLifetime = TimeSpan.FromDays(7),
});
builder.Services.AddSingleton(tokens);
builder.Services.AddSingleton<IUsedTokenStore, InMemoryUsedTokenStore>(); // single process only, see below
```

The service is thread-safe. The options are copied when it is created, so later changes to the options object have no effect.

### Creating a token

```csharp title="PasswordResetService.cs"
string token = _tokens.Create("password-reset", user.Id, TimeSpan.FromMinutes(30));
string link = $"https://example.com/reset-password?token={token}";
await _email.SendPasswordResetAsync(user.Email, link, cancellationToken);
```

The token is base64url without padding, so it can go into a URL, a query string or a path segment unescaped.

| Argument | Rules |
|----------|-------|
| `purpose` | What the token is for, such as `"password-reset"` or `"confirm-email"`. 1 to 256 characters (`SignedTokenService.MaxPurposeLength`). Only its SHA-256 is stored in the token. |
| `subject` | Who or what it is for, usually a user id. Not empty, at most `MaxSubjectBytes` UTF-8 bytes (default 512). **Readable by anyone holding the token.** |
| `lifetime` | Positive and at most `MaxLifetime` (default 30 days). Rounded up to whole seconds. |

`Create` throws `ArgumentNullException` for null arguments, `ArgumentException` for an empty or over-long purpose or subject, invalid UTF-16, or a token that would be longer than `MaxTokenLength`, and `ArgumentOutOfRangeException` for a lifetime that is zero, negative or too long. It throws `InvalidOperationException` if the clock is outside the supported range (before 1970 or past the year 9999).

:::warning

Tokens are signed, not encrypted. Put an opaque user id in the subject, never a secret, and prefer an id over an email address.

:::

### Validating a token

`Validate` returns a `SignedTokenStatus` and never throws for a bad token: null, garbage, tampered, truncated or oversized input all return a failure status. It does throw `ArgumentNullException` or `ArgumentException` when `expectedPurpose` itself is null, empty, longer than 256 characters or not valid UTF-16, because that is a programming error.

```csharp
SignedTokenStatus status = _tokens.Validate(token, "confirm-email", out SignedTokenPayload? payload);
if (status == SignedTokenStatus.Valid)
{
    await _users.ConfirmEmailAsync(payload!.Subject, cancellationToken); // payload is set for Valid
}
```

`TryValidate(token, expectedPurpose, out payload)` returns true only for `Valid` and is annotated so the compiler knows `payload` is not null when it returns true.

| Status | Meaning | Payload |
|--------|---------|---------|
| `Valid` | Authentic, for the expected purpose, within its lifetime. The only status you may act on. | Set |
| `Expired` | Authentic and for the expected purpose, but at or past its expiry plus the clock skew. | Set |
| `InvalidSignature` | Well-formed, but the tag does not match: tampered with or forged. | Null |
| `WrongPurpose` | Authentic, but issued for another purpose, for example an email-confirmation token used for a password reset. | Null |
| `Malformed` | Null, empty, longer than `MaxTokenLength`, not base64url, an unknown version, or structurally invalid. | Null |
| `UnknownKey` | Signed with a key id that is not, or no longer, in the ring. | Null |
| `NotYetValid` | Authentic, but issued more than the clock skew in the future. | Null |
| `AlreadyUsed` | Valid, but its nonce was already recorded. Returned only by `ConsumeAsync`. | Set |

The checks run in a fixed order: structure, key id, signature, purpose, then time. A token is only reported as `Expired` or `WrongPurpose` after its signature has been verified, so those statuses never describe forged input. Use the payload of an `Expired` token only for messages such as "this link has expired, request a new one". Do not act on it.

:::tip

Show the user one generic message for every failure ("this link is invalid or has expired"). Log the precise status for yourself.

:::

`SignedTokenPayload` holds `Version`, `KeyId`, `Purpose`, `Subject`, `IssuedAt`, `ExpiresAt` (both to the second) and `Nonce` (the token's 16 random bytes as 22 base64url characters).

### Making a token single-use

A stateless token can be replayed until it expires. For password resets and magic links, redeem it with `ConsumeAsync` and an `IUsedTokenStore`. The first redemption records the token's nonce and returns `Valid`; every later one returns `AlreadyUsed`.

```csharp title="PasswordResetEndpoint.cs"
SignedTokenResult result = await _tokens.ConsumeAsync(request.Token, "password-reset", _usedTokens, cancellationToken);
if (!result.IsValid)
{
    _logger.LogInformation("Password reset token rejected: {Status}", result.Status);
    return Results.BadRequest("This link is invalid or has expired.");
}

await _users.SetPasswordAsync(result.Payload!.Subject, request.NewPassword, cancellationToken);
```

`SignedTokenResult` has `Status`, `IsValid` (true only for `Valid`) and `Payload` (set for `Valid`, `Expired` and `AlreadyUsed`).

How `ConsumeAsync` behaves:

- The token is validated first. The store is called only for a `Valid` token, so forged or expired tokens never reach it.
- The nonce is recorded **before** you act. If your action then fails, the user needs a new token.
- The store is asked to keep the nonce until `ExpiresAt + 2 x ClockSkew + 1 minute`. Another server whose clock lags by up to the skew still accepts the token until `ExpiresAt + ClockSkew` on its own clock, which is up to `ExpiresAt + 2 x ClockSkew` on this one.

**Binding a token to state.** Another way to make a token single-use is to put state that changes on use into the purpose, such as a security stamp that you rotate when the password changes: `Create($"password-reset:{user.SecurityStamp}", user.Id, lifetime)`. After the reset the stamp changes, and the old token validates as `WrongPurpose`. This needs no store, but the purpose (including the stamp) must stay within 256 characters.

### Used-token stores

`IUsedTokenStore` has one method:

```csharp
ValueTask<bool> TryMarkUsedAsync(string nonce, DateTimeOffset retainUntil, CancellationToken cancellationToken = default);
```

It must atomically record the nonce and return true if it was not recorded before, false if it was. The record may be deleted after `retainUntil`, never earlier. The operation must be atomic **across every server** that validates tokens. Two common implementations:

- Redis: `SET <nonce> 1 NX PXAT <retainUntil in Unix milliseconds>`. A reply of `OK` means first use.
- A database table with a unique key on the nonce: an `INSERT` that succeeds means first use; a unique-key violation means it was already used. Delete rows whose `retainUntil` has passed in a background job.

```csharp title="EfUsedTokenStore.cs"
using System;
using System.Threading;
using System.Threading.Tasks;
using Masterly.Hash.Tokens;
using Microsoft.EntityFrameworkCore;

namespace MyApp.Security;

public sealed class EfUsedTokenStore : IUsedTokenStore
{
    private readonly AppDbContext _db;

    public EfUsedTokenStore(AppDbContext db)
    {
        _db = db;
    }

    public async ValueTask<bool> TryMarkUsedAsync(string nonce, DateTimeOffset retainUntil, CancellationToken cancellationToken = default)
    {
        UsedToken row = new UsedToken { Nonce = nonce, RetainUntil = retainUntil }; // Nonce is the primary key
        _db.UsedTokens.Add(row);
        try
        {
            await _db.SaveChangesAsync(cancellationToken);
            return true;
        }
        catch (DbUpdateException)
        {
            // Duplicate key: the token was already redeemed. Any other failure also fails closed.
            _db.Entry(row).State = EntityState.Detached;
            return false;
        }
    }
}
```

`InMemoryUsedTokenStore` is a thread-safe, in-process store for single-instance applications and tests. A web farm needs a shared store.

| Member | Behaviour |
|--------|-----------|
| `InMemoryUsedTokenStore(clock = null)` | The clock defaults to `DateTimeOffset.UtcNow`. |
| `TryMarkUsed(nonce, retainUntil)` | Synchronous form of `TryMarkUsedAsync`. |
| `Contains(nonce)` | True if the nonce is recorded. |
| `Count` | Number of recorded nonces. |
| `Purge()` | Removes entries older than their `retainUntil` plus `PurgeGrace`. It also runs automatically every 256 calls. |
| `PurgeGrace` | 5 minutes. |

Only tokens with a valid signature reach the store, so its size is bounded by the number of tokens you issue within their lifetime.

### Options

| Option | Default | Range | Meaning |
|--------|---------|-------|---------|
| `Clock` | `() => DateTimeOffset.UtcNow` | Not null | Source of the current time. On .NET 8 you can pass `() => timeProvider.GetUtcNow()`. |
| `ClockSkew` | 30 seconds | 0 to 1 hour (`SignedTokenOptions.MaxClockSkew`) | A token is still accepted this long after expiry, and may be issued this far in the future. |
| `MaxTokenLength` | 1024 characters | 256 to 16384 | Longer tokens are `Malformed` before decoding, and `Create` refuses to produce one. |
| `MaxSubjectBytes` | 512 | 1 to 4096 | Maximum subject size in UTF-8 bytes. |
| `MaxLifetime` | 30 days | Positive, at most 3650 days | Longest lifetime `Create` accepts. |

The constructor throws `ArgumentException` for an option outside its range.

A token is 100 bytes plus the key id and the subject, base64url-encoded. With a 2-character key id and a 36-character GUID subject it is 184 characters. With the default 512-byte subject limit and a 32-character key id it is at most 859 characters, within the default `MaxTokenLength`.

### Token format

```
version(1) | keyIdLength(1) | keyId | SHA-256(purpose)(32) | issuedAt(8) | expiresAt(8) |
nonce(16) | subjectLength(2) | subject (UTF-8) | HMAC-SHA256 tag(32)
```

Integers are big-endian and times are Unix seconds. The tag covers every preceding byte and is computed with the derived token subkey. The version written is `SignedTokenService.CurrentVersion` (1); any other version is `Malformed`. Tags are compared in constant time.

### Rotating the signing key

Add a new key to the token ring and make it current. Tokens signed with the old key keep validating while it is in the ring. Remove it once the longest token lifetime plus the clock skew has passed since the switch; tokens still signed with it then return `UnknownKey`.

## Secure random strings

`SecureRandomString.Generate(length, alphabet)` draws each character by rejection sampling over the OS CSPRNG, so every character of the alphabet is exactly equally likely.

```csharp
string otp = SecureRandomString.Generate(6, SecureRandomString.Digits);              // about 19.9 bits
string recoveryCode = SecureRandomString.Generate(16, SecureRandomString.Crockford32); // 80 bits
string opaqueId = SecureRandomString.Generate(22);                                  // base62, about 131 bits
double bits = SecureRandomString.GetEntropyBits(16, SecureRandomString.Crockford32.Length); // 80
```

| Alphabet | Characters | Bits per character |
|----------|------------|--------------------|
| `Base62` (the default) | `0-9A-Za-z` | About 5.95 |
| `UrlSafe` | `A-Za-z0-9-_` (RFC 4648 base64url) | 6 |
| `Hex` | `0-9a-f` | 4 |
| `Digits` | `0-9` | About 3.32 |
| `LowercaseAlphanumeric` | `a-z0-9` | About 5.17 |
| `Crockford32` | `0-9A-Z` without `I`, `L`, `O`, `U` | 5 |

A custom alphabet needs 2 to 256 distinct characters (`MaxAlphabetLength`), none of them a UTF-16 surrogate; otherwise `Generate` throws `ArgumentException`. Duplicates are rejected because they would bias the output. The length can be 0 to 1,048,576 (`MaxLength`); outside that it throws `ArgumentOutOfRangeException`.

:::warning

A short code is guessable however good the randomness is. A 6-digit code has a million values: limit attempts per code and per account, and expire it within minutes.

:::

## Encoding helpers

Two building blocks of the key format are public:

- `Base62`: fixed-length base62 (`Alphabet` is `0-9A-Za-z`). `Encode(bytes)` reads the bytes as a big-endian number and writes exactly `GetEncodedLength(bytes.Length)` digits, left-padded with `0`. `TryDecode(text, out bytes)` never throws and rejects foreign characters, impossible lengths and values too large for the length. `IsBase62(text)` checks the characters. Input is limited to 1024 bytes (`MaxByteLength`); the conversion is quadratic, so it is meant for short values.
- `Crc32`: CRC-32 (IEEE 802.3, reflected polynomial `0xEDB88320`, as in zlib and PNG). `Compute(byte[])`, `Compute(byte[], offset, count)` and `Compute(string)` (UTF-8). It detects typos and truncation; it gives no protection against an adversary.

## Security checklist

- Keep ring keys in a secret store, never in the database or source control.
- Store only lookup hashes. Show a new API key once and never log it; log `Hint` or `ApiKeyParts` instead.
- Use different prefixes per environment (`mh_live`, `mh_test`) and register them with your secret-scanning provider.
- Keep token lifetimes short: minutes for password resets and magic links, hours or days for email confirmation.
- Use `ConsumeAsync` with a shared store for any token that grants access.
- Never put secrets in a token subject.

## See also

- [Hashing and Verifying](./hashing-and-verifying.md): for passwords, use `PasswordHasher`, not this package.
- [Blind Indexes](./blind-indexes.md): the same keyed-HMAC idea for searching encrypted columns.
- [Attack Detection](./attack-detection.md): honeywords, honey accounts and credential-stuffing detection.
- [Command-Line Tool](./command-line-tool.md): `apikey generate`.
- [Threat Model](./threat-model.md)
- [SignedTokenService.cs on GitHub](https://github.com/a7mdfre7at/Masterly.Hash/blob/master/src/Masterly.Hash.Tokens/SignedTokenService.cs)
