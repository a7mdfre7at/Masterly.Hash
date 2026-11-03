# Masterly.Hash.Tokens

High-entropy secrets done right, on top of [Masterly.Hash](https://www.nuget.org/packages/Masterly.Hash):

- **API keys** in the GitHub-token style: `<prefix>_<base62 random><6-char base62 CRC-32>`, stored as a fast,
  keyed, indexable lookup hash (HMAC-SHA256 under a derived subkey) with key rotation.
- **Signed tokens** for password resets, email confirmation and magic links: URL-safe, expiring, bound to a
  purpose, HMAC-SHA256 signed, with optional single-use enforcement.
- **Secure random strings** over any alphabet, without modulo bias.

Targets `net8.0`. No dependencies beyond Masterly.Hash.

## Install

```
dotnet add package Masterly.Hash.Tokens
```

## API keys

```csharp
using Masterly.Hash.Tokens;

// Keys live outside the database (environment, secret store). >= 32 bytes each.
var ring = HmacKeyRing.FromBase64("k2", new Dictionary<string, string>
{
    ["k1"] = config["ApiKeys:k1"],  // old key, still verifies
    ["k2"] = config["ApiKeys:k2"],  // current key, used for new hashes
});
var hasher = new ApiKeyHasher(ring);
var generator = new ApiKeyGenerator(hasher, "mh_live");

GeneratedApiKey created = generator.Generate();
// Show created.PlainText to the user ONCE. Store created.LookupHash (unique index) and created.Hint.

// On each request:
if (!ApiKey.HasValidChecksum(presented))     // offline: rejects typos and garbage without a DB hit
    return Unauthorized();
var row = db.ApiKeys.SingleOrDefault(k => hasher.ComputeAllLookupHashes(presented).Contains(k.LookupHash));
if (row == null || !hasher.Verify(presented, row.LookupHash))
    return Unauthorized();
if (hasher.NeedsRehash(row.LookupHash))
    row.LookupHash = hasher.ComputeLookupHash(presented);   // migrate to the current key
```

`ApiKey.TryParse` splits a key into prefix, random part and checksum. The checksum is CRC-32 (IEEE) over
`<prefix>_<random>`, so secret scanners can recognise your keys with a very low false-positive rate (about 1 in 2^32). The
checksum is public: a valid checksum does not prove a key was ever issued, so always look it up.

## Signed tokens

```csharp
// A separate ring for tokens (recommended; keys from your secret store).
var tokenRing = HmacKeyRing.FromBase64("t1", new Dictionary<string, string> { ["t1"] = config["Tokens:t1"] });
var tokens = new SignedTokenService(tokenRing);
string token = tokens.Create("password-reset", user.Id, TimeSpan.FromMinutes(30));
// email https://example.com/reset?token={token}

var store = new InMemoryUsedTokenStore();   // single process only; implement IUsedTokenStore for a farm
SignedTokenResult result = await tokens.ConsumeAsync(token, "password-reset", store);
if (result.IsValid)
    ResetPassword(result.Payload!.Subject);
```

`Validate` returns `Valid`, `Expired`, `InvalidSignature`, `WrongPurpose`, `Malformed`, `UnknownKey` or
`NotYetValid` and never throws for a bad token. `ConsumeAsync` adds `AlreadyUsed`. The clock is injectable
(`SignedTokenOptions.Clock`), with a configurable `ClockSkew` (default 30 s) and `MaxTokenLength` (default 1024).

## Random strings

```csharp
string code = SecureRandomString.Generate(8, SecureRandomString.Digits);
string recovery = SecureRandomString.Generate(16, SecureRandomString.Crockford32);
```

## Security notes

- API keys are high-entropy, so a fast keyed hash is the right choice; **never** use this for passwords
  (use `PasswordHasher` from Masterly.Hash).
- A stolen database alone is not enough to confirm a guessed key: the HMAC key is required. Keep it elsewhere.
- Comparisons of tags and lookup hashes are constant-time; random values come from the OS CSPRNG.
- The CRC-32 checksum detects typos and garbage; it is public, anyone can compute it, and it is not a
  security control.
- Signed tokens are **not encrypted**: do not put secrets in the subject.
- Without an `IUsedTokenStore`, a token can be replayed until it expires. Use `ConsumeAsync` for
  password resets and magic links, and keep lifetimes short.
- Ring keys are never used directly: API-key lookup hashes and token signatures each use their own subkey
  derived from the ring key, so a lookup hash of any input reveals nothing about the token-signing key. Separate
  rings for API keys and tokens are still recommended (the signed-token sample above does this).
- `ConsumeAsync` asks the store to keep a used nonce until expiry + 2 x `ClockSkew` + 1 minute, which covers
  servers whose clocks disagree by up to the skew. Custom stores must not drop records earlier.
