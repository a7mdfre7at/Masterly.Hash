# Masterly.Hash.Testing

![Masterly.Hash: password hashing you can't get wrong.](https://raw.githubusercontent.com/a7mdfre7at/Masterly.Hash/master/assets/banner.png)

Test helpers for applications that use [Masterly.Hash](https://github.com/a7mdfre7at/Masterly.Hash). Reference it from **test projects only**.

| Helper | What it does |
| --- | --- |
| `FastPasswordHasher` | A *real* `PasswordHasher` with a tiny Argon2id profile (`test-fast`: 64 KiB, t=1). Same behaviour as production (rehash on login, 1.x hashes, peppers, `VerifyOrDummy`, wrapping), microseconds per call. |
| `RecordingPasswordHasher` | Decorator that records every call (operation, sync/async, stored hash, result) so you can assert *how* your code uses the hasher. Never records passwords. |
| `FakePepper` | Deterministic, instrumented `IPasswordPepper` with key ids, rotation, retirement, async delay and fault injection. |
| `MasterlyHashAssert` | Framework-agnostic assertions; failures throw `MasterlyHashAssertionException`. |
| `KnownHashes` | Verified sample hashes (1.x, `test-fast`, peppered, wrapped, every built-in profile) and deterministic factories. |

## Install

```shell
dotnet add package Masterly.Hash.Testing
```

## Quickstart

```csharp
// Register the fast hasher in place of the production one.
services.AddSingleton<IPasswordHasher>(new FastPasswordHasher());

// Or wrap it to assert on usage.
var hasher = new RecordingPasswordHasher();          // wraps a FastPasswordHasher
var accounts = new AccountService(hasher, repository);

repository.Add("alice", KnownHashes.V1Sha512);        // a Masterly.Hash 1.x hash
await accounts.LoginAsync("alice", KnownHashes.Password);
MasterlyHashAssert.PersistedRehash(hasher, repository.HashOf("alice"));
MasterlyHashAssert.UsesProfile(repository.HashOf("alice"), FastPasswordHasher.ProfileId);

await accounts.LoginAsync("nobody", "whatever");
MasterlyHashAssert.UsedVerifyOrDummyForUnknownUser(hasher);

// Peppers and key rotation.
var pepper = new FakePepper("k1");
var peppered = new FastPasswordHasher(o => o.Pepper = pepper);
string stored = peppered.Hash("hunter2!");
MasterlyHashAssert.IsPeppered(stored, "k1");
pepper.RotateTo("k2");
MasterlyHashAssert.NeedsRehash(peppered, stored);

// Leak checks on whatever your code persisted.
MasterlyHashAssert.IsNotPlaintext(stored, "hunter2!");
```

## Security notes

- **Never use `FastPasswordHasher` or `FakePepper` in production.** The `test-fast` profile has no meaningful cost and the fake pepper's keys are public.
- Safety net: hashes from `FastPasswordHasher` carry profile id `test-fast`, which a production `PasswordHasher` rejects (`UnknownProfile`), so a test hash that leaks into a real database can never be accepted.
- `RecordingPasswordHasher` stores only an HMAC-SHA256 fingerprint of each password, keyed per recorder; compare with `recorder.Fingerprint(password)` or `recorder.CallsWithPassword(password)`.
- `MasterlyHashAssert` messages never include passwords or stored values.
- `IsMasterlyHash`/`UsesProfile`/`IsPeppered` also check salt and tag lengths, so a hash truncated by a too-short column fails.
- `UsedVerifyOrDummyForUnknownUser` fails if *any* unknown-user path called `Verify(password, null)`, even if another path used `VerifyOrDummy`.
- `IsNotPlaintext` tries UTF-8, UTF-16LE and NFKC forms of the password (plain, base64, hex and unsalted MD5/SHA-1/SHA-2 digests).
- Assertions that take a hasher unwrap a `RecordingPasswordHasher`, so they never add calls to the history you assert on.
- `KnownHashes` use fixed, public salts. Never seed a real database with them.
