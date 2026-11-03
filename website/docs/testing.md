---
title: "Testing Code That Uses Masterly.Hash"
sidebar_label: "Testing"
description: "A real but fast hasher, a call recorder, a deterministic fake pepper, framework-agnostic assertions and known sample hashes."
---

`Masterly.Hash.Testing` gives you what you need to unit-test code that hashes and verifies passwords, without paying the production cost on every call (about 125 ms per `2026a` hash on a fast desktop CPU) and without mocking the hasher. This page shows each helper and the tests it makes easy: upgrade-on-login, unknown users, pepper rotation, pepper outages and leaked plaintext.

| Helper | What it does |
|--------|--------------|
| [`FastPasswordHasher`](#fastpasswordhasher) | A real `PasswordHasher` with a tiny Argon2id profile, `test-fast`. Same behaviour as production, a fraction of a millisecond per call. |
| [`RecordingPasswordHasher`](#recordingpasswordhasher) | A decorator that records every call, so you can assert how your code uses the hasher. It never records passwords. |
| [`FakePepper`](#fakepepper) | A deterministic `IPasswordPepper` with key ids, rotation, retirement, async delay and fault injection. |
| [`MasterlyHashAssert`](#masterlyhashassert) | Assertions that work with any test framework. Failures throw `MasterlyHashAssertionException`. |
| [`KnownHashes`](#knownhashes) | Verified sample hashes (1.x, `test-fast`, peppered, wrapped, every built-in profile) and deterministic factories. |

## Installing

Reference the package from your **test projects only**:

```bash
dotnet add package Masterly.Hash.Testing
```

The package targets `net8.0`, so the test project must target .NET 8 or later. It depends only on `Masterly.Hash`. All types live in the `Masterly.Hash.Testing` namespace.

:::danger

Never reference this package from production code. The `test-fast` profile offers no real resistance to guessing, and `FakePepper` keys are public. Hashes made with `test-fast` are rejected by a production hasher (see [The test-fast safety net](#the-test-fast-safety-net)), but a fake pepper in production would silently weaken every hash.

:::

## The code under test

The examples on this page test this login service. It depends on `IPasswordHasher`, not on the static `Password` class, so a test can pass in a different hasher:

```csharp title="LoginService.cs"
using System;
using System.Threading;
using System.Threading.Tasks;
using Masterly.Hash;

namespace MyApp.Accounts;

public interface IUserStore
{
    Task<string?> FindPasswordHashAsync(string userName, CancellationToken cancellationToken);

    Task UpdatePasswordHashAsync(string userName, string passwordHash, CancellationToken cancellationToken);
}

public sealed class LoginService
{
    private readonly IPasswordHasher _hasher;
    private readonly IUserStore _users;

    public LoginService(IPasswordHasher hasher, IUserStore users)
    {
        ArgumentNullException.ThrowIfNull(hasher);
        ArgumentNullException.ThrowIfNull(users);
        _hasher = hasher;
        _users = users;
    }

    public async Task<bool> LoginAsync(string userName, string password, CancellationToken cancellationToken)
    {
        string? storedHash = await _users.FindPasswordHashAsync(userName, cancellationToken);
        PasswordVerificationResult result = await _hasher.VerifyOrDummyAsync(password, storedHash, cancellationToken);

        if (result.IsMatch && result.Rehash is not null)
        {
            await _users.UpdatePasswordHashAsync(userName, result.Rehash, cancellationToken);
        }

        return result.IsMatch;
    }
}
```

The tests use a small in-memory store:

```csharp title="InMemoryUserStore.cs"
using System;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;
using MyApp.Accounts;

namespace MyApp.Tests;

public sealed class InMemoryUserStore : IUserStore
{
    private readonly ConcurrentDictionary<string, string> _hashes = new ConcurrentDictionary<string, string>(StringComparer.Ordinal);

    public void Add(string userName, string passwordHash) => _hashes[userName] = passwordHash;

    public string? HashOf(string userName) => _hashes.TryGetValue(userName, out string? hash) ? hash : null;

    public Task<string?> FindPasswordHashAsync(string userName, CancellationToken cancellationToken) =>
        Task.FromResult(HashOf(userName));

    public Task UpdatePasswordHashAsync(string userName, string passwordHash, CancellationToken cancellationToken)
    {
        _hashes[userName] = passwordHash;
        return Task.CompletedTask;
    }
}
```

## A first test

**1. Seed a stored hash.** `KnownHashes.V1Sha512` is a Masterly.Hash 1.x hash of `KnownHashes.Password`.

**2. Run the code with a recording hasher.** `new RecordingPasswordHasher()` wraps a `FastPasswordHasher`.

**3. Assert on what was persisted.**

```csharp title="LoginServiceTests.cs"
using System.Threading;
using System.Threading.Tasks;
using Masterly.Hash.Testing;
using MyApp.Accounts;
using Xunit;

namespace MyApp.Tests;

public sealed class LoginServiceTests
{
    [Fact]
    public async Task Login_WithLegacyHash_PersistsRehash()
    {
        RecordingPasswordHasher hasher = new RecordingPasswordHasher();
        InMemoryUserStore users = new InMemoryUserStore();
        users.Add("alice", KnownHashes.V1Sha512);
        LoginService service = new LoginService(hasher, users);

        bool loggedIn = await service.LoginAsync("alice", KnownHashes.Password, CancellationToken.None);

        Assert.True(loggedIn);
        MasterlyHashAssert.PersistedRehash(hasher, users.HashOf("alice"));
        MasterlyHashAssert.UsesProfile(users.HashOf("alice"), FastPasswordHasher.ProfileId);
    }

    [Fact]
    public async Task Login_WithUnknownUser_UsesDummyVerification()
    {
        RecordingPasswordHasher hasher = new RecordingPasswordHasher();
        LoginService service = new LoginService(hasher, new InMemoryUserStore());

        bool loggedIn = await service.LoginAsync("nobody", "any-password", CancellationToken.None);

        Assert.False(loggedIn);
        MasterlyHashAssert.UsedVerifyOrDummyForUnknownUser(hasher);
    }

    [Fact]
    public async Task Login_WithWrongPassword_KeepsStoredHash()
    {
        RecordingPasswordHasher hasher = new RecordingPasswordHasher();
        InMemoryUserStore users = new InMemoryUserStore();
        users.Add("alice", KnownHashes.TestFast);
        LoginService service = new LoginService(hasher, users);

        bool loggedIn = await service.LoginAsync("alice", KnownHashes.WrongPassword, CancellationToken.None);

        Assert.False(loggedIn);
        Assert.Equal(KnownHashes.TestFast, users.HashOf("alice"));
        Assert.Empty(hasher.RehashesIssued);
    }
}
```

The assertions do not depend on xUnit. With NUnit or MSTest, keep the `MasterlyHashAssert` lines and change only the framework's own `Assert` calls.

## FastPasswordHasher

`FastPasswordHasher` implements `IPasswordHasher` by delegating to a real `PasswordHasher`. Only the default profile changes, so every behaviour your code relies on runs the production code path: upgrade-on-login, 1.x and other legacy hashes, peppers, `VerifyOrDummy`, onion wrapping, limits and failure reasons.

```csharp
using Masterly.Hash;
using Masterly.Hash.Testing;

FastPasswordHasher hasher = new FastPasswordHasher();

string stored = hasher.Hash("hunter2!");                     // $mh$p=test-fast$...
PasswordVerificationResult result = hasher.Verify("hunter2!", stored);
```

**The `test-fast` profile.** `FastPasswordHasher.Profile` is Argon2id with m=64 KiB, t=1, p=1, a 16-byte salt and a 32-byte tag. Its id is `FastPasswordHasher.ProfileId`, `"test-fast"`. Compare that with 64 MiB and t=3 for the production default `2026a`.

**Options.** The parameterless constructor uses `FastPasswordHasher.CreateOptions()`, which starts from `new PasswordHasherOptions()` and sets:

| Option | Value | Why |
|--------|-------|-----|
| `DefaultProfile` | `FastPasswordHasher.Profile` | New hashes use `test-fast`. |
| `AdditionalProfiles` | contains `FastPasswordHasher.Profile` | `test-fast` hashes keep verifying even if you change the default profile. |
| `AllowWeakProfiles` | `true` | `test-fast` is below the OWASP minimums, so it can only be registered with this switch. |
| `MaxConcurrency` | `0` | No concurrency limit, so parallel tests never wait or get `PasswordHasherBusyException`. |

Everything else keeps its production default: 1,024-byte `MaxPasswordBytes`, `ComputeRehashOnVerify` on, and the 1.x legacy format registered.

**Configuring it.** The constructor that takes an `Action<PasswordHasherOptions>` runs your callback after the test defaults, so it can add a pepper, legacy formats or profiles, or change any option:

```csharp
using Masterly.Hash.Legacy;
using Masterly.Hash.Testing;

// A pepper, as in production.
FastPasswordHasher peppered = new FastPasswordHasher(options => options.Pepper = new FakePepper("k1"));

// Every legacy format from Masterly.Hash.Legacy, to test a bcrypt or Django migration.
FastPasswordHasher migrating = new FastPasswordHasher(options => options.AddAllLegacyFormats());

// Exercise the length limit.
FastPasswordHasher strict = new FastPasswordHasher(options => options.MaxPasswordBytes = 64);
```

If the callback leaves the options invalid, for example by setting `AllowWeakProfiles` back to `false`, the constructor throws `ArgumentException`.

**Members.**

| Member | Description |
|--------|-------------|
| `FastPasswordHasher()`, `FastPasswordHasher(Action<PasswordHasherOptions>? configure)` | Create a hasher with the test defaults, optionally adjusted. |
| `FastPasswordHasher.Shared` | A shared, thread-safe instance with the default test options. |
| `FastPasswordHasher.CreateOptions(configure)` | The options the constructor uses, for building your own `PasswordHasher` or registering them in DI. |
| `Inner` | The underlying `PasswordHasher`. |
| `DefaultProfile` | The profile for new hashes (`test-fast` unless reconfigured). |
| `Profiles` | Every profile the hasher accepts: `test-fast`, the three built-in profiles and any you added. |
| `Hash`, `Verify`, `VerifyOrDummy`, `HashAsync`, `VerifyAsync`, `VerifyOrDummyAsync`, `NeedsRehash`, `Inspect`, `TryWrap` | The `IPasswordHasher` members, delegated to `Inner`. |

### The test-fast safety net

Hashes from `FastPasswordHasher` carry the profile id `test-fast`. A production `PasswordHasher` does not register that id, so if a test hash ever reaches a production database, verification fails with `VerificationFailureReason.UnknownProfile` instead of quietly accepting a weak hash.

The reverse works: `FastPasswordHasher` registers the built-in profiles, so production hashes such as `KnownHashes.Server2026a` verify with it. Because its default profile is `test-fast`, a successful verification of a production hash reports `SuccessRehashNeeded` with `RehashReason.OutdatedProfile`. Keep that in mind when a test asserts that no rehash was issued.

### Replacing the hasher in an integration test

`AddMasterlyHash` registers `PasswordHasher` and `IPasswordHasher` as one singleton. A later `IPasswordHasher` registration wins, so register the fast hasher after the application's own services, for example in `ConfigureTestServices`:

```csharp title="AppFactory.cs"
using Masterly.Hash;
using Masterly.Hash.Testing;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;

namespace MyApp.Tests;

public sealed class AppFactory : WebApplicationFactory<Program>
{
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.ConfigureTestServices(services =>
        {
            services.AddSingleton<IPasswordHasher>(FastPasswordHasher.Shared);
        });
    }
}
```

The ASP.NET Core Identity adapter (`AddMasterlyPasswordHasher`) depends on `IPasswordHasher`, so it picks up the replacement. Code that resolves the concrete `PasswordHasher` still gets the production one; depend on the interface in code you want to test. See [Dependency injection](./dependency-injection.md) and [ASP.NET Core Identity](./aspnetcore-identity.md).

:::warning

Register the replacement after `AddMasterlyHash`, never before. `AddMasterlyHash` throws `InvalidOperationException` when it finds an `IPasswordHasher` or `PasswordHasher` registered by something else, because that registration would silently ignore every option.

:::

## RecordingPasswordHasher

`RecordingPasswordHasher` wraps any `IPasswordHasher` and records each call it forwards. Use it to assert how your code uses the hasher: that it stores the rehash after login, uses `VerifyOrDummy` for unknown users, never hashes twice, or uses the async methods.

```csharp
RecordingPasswordHasher recorder = new RecordingPasswordHasher();                       // wraps a new FastPasswordHasher
RecordingPasswordHasher custom = new RecordingPasswordHasher(new FastPasswordHasher(options => options.Pepper = new FakePepper()));
```

| Member | Description |
|--------|-------------|
| `Inner` | The decorated hasher. |
| `Calls` | A snapshot of every recorded call, ordered by `Sequence`. |
| `LastCall` | The most recently started call that has completed, or `null`. |
| `CallsOf(operation)`, `Count(operation)` | Calls of one `PasswordHasherOperation`, sync and async together. |
| `CallsWithPassword(password)` | Calls that were given this password, matched by fingerprint. |
| `Fingerprint(password)` | The fingerprint this recorder stores for a password: 64 lowercase hex characters. |
| `RehashesIssued` | Every non-null `PasswordVerificationResult.Rehash` returned by a verify call, in call order. |
| `UsedDummyVerification` | `true` if any `VerifyOrDummy` call was made without a stored hash. |
| `Clear()` | Forgets all recorded calls. |

`PasswordHasherOperation` has the values `Hash`, `Verify`, `VerifyOrDummy`, `NeedsRehash`, `Inspect` and `TryWrap`. Each recorded call is a `PasswordHasherCall`:

| Property | Description |
|----------|-------------|
| `Sequence` | Order in which the call started, from 1 for each recorder. |
| `Operation` | Which member was called. |
| `IsAsync` | `true` for the `...Async` members. |
| `PasswordFingerprint` | The keyed fingerprint of the password, or `null` when the call took no password. |
| `StoredHash` | The stored hash passed to a verify, inspect or needs-rehash call, or the legacy hash passed to `TryWrap`. |
| `ProfileId` | The profile id passed to `Hash(password, profile)`, otherwise `null`. |
| `Result`, `Status` | The verification result and its status, for verify calls that returned. |
| `ProducedHash` | The hash returned by a hash call, or the wrapped hash returned by `TryWrap`. |
| `BooleanResult` | The return value of `NeedsRehash` or `TryWrap`. |
| `Info` | The `HashInfo` returned by `Inspect`. |
| `Exception` | The exception the inner hasher threw. It was rethrown to the caller. |
| `IsUnknownUser` | `true` for a verify call made without a stored hash. |

```csharp
[Fact]
public async Task Login_VerifiesOnce_Asynchronously()
{
    RecordingPasswordHasher hasher = new RecordingPasswordHasher();
    InMemoryUserStore users = new InMemoryUserStore();
    users.Add("alice", KnownHashes.TestFast);
    LoginService service = new LoginService(hasher, users);

    await service.LoginAsync("alice", KnownHashes.Password, CancellationToken.None);

    PasswordHasherCall call = Assert.Single(hasher.Calls);
    Assert.Equal(PasswordHasherOperation.VerifyOrDummy, call.Operation);
    Assert.True(call.IsAsync);
    Assert.Equal(VerificationStatus.Success, call.Status);
    Assert.Single(hasher.CallsWithPassword(KnownHashes.Password));
}
```

**Passwords are never recorded.** Each call stores an HMAC-SHA256 of the password bytes the hasher sees (after NFKC normalization, as UTF-8) under a random 32-byte key private to that recorder. A recorded call that ends up in test output cannot be reversed with a dictionary, and fingerprints from two recorders differ. Compare with `Fingerprint(password)` or `CallsWithPassword(password)`. The recorder is thread-safe.

## FakePepper

`FakePepper` is a deterministic `IPasswordPepper` for tests. It uses HMAC-SHA256, like `HmacPepper`, with a key derived from the key id: `FakePepper.KeyFor(keyId)` is the SHA-256 of a fixed domain string and the id. Two `FakePepper` instances with the same key ids are interchangeable, so a hash made with one verifies with the other.

```csharp
FakePepper pepper = new FakePepper("k1");                 // current key k1
FakePepper withOld = new FakePepper("k2", "k1");          // current key k2, k1 still verifies
FakePepper defaultPepper = new FakePepper();              // key id "test-key" (FakePepper.DefaultKeyId)
```

Key ids must match `^[A-Za-z0-9-]{1,32}$`; an invalid id throws `ArgumentException`.

| Member | Description |
|--------|-------------|
| `CurrentKeyId` | The key id for new hashes. |
| `KeyIds` | Every key id the pepper accepts. |
| `AddKey(keyId)` | Accept another key id from now on. |
| `RotateTo(keyId)` | Make `keyId` the current key, adding it if needed. Older keys keep verifying. |
| `RetireKey(keyId)` | Stop accepting `keyId`; hashes made with it then fail with `UnknownPepperKey`. Returns `true` if the key was known. Throws `InvalidOperationException` for the current key. |
| `ApplyCount`, `ApplyAsyncCount` | Number of synchronous and asynchronous apply calls. |
| `KeyIdsUsed` | The key id passed to each apply call, in call order. |
| `ResetCounters()` | Resets the counts and `KeyIdsUsed`. |
| `AsyncDelay` | If positive, `ApplyAsync` waits this long, honouring cancellation, before it returns. |
| `ForceAsynchronous` | If `true`, `ApplyAsync` always completes asynchronously, like a network call. |
| `ThrowOnApply` | If set, every apply call throws this exception, simulating an outage. |
| `FakePepper.KeyFor(keyId)` | The fixed 32-byte key for an id. Not secret. |

Applying an id the pepper does not know throws `KeyNotFoundException`. `FakePepper` is thread-safe.

**Testing key rotation.**

```csharp
[Fact]
public void PepperRotation_OldKeyVerifies_AndRehashUsesNewKey()
{
    FakePepper pepper = new FakePepper("k1");
    FastPasswordHasher hasher = new FastPasswordHasher(options => options.Pepper = pepper);
    string stored = hasher.Hash(KnownHashes.Password);

    pepper.RotateTo("k2");
    PasswordVerificationResult result = MasterlyHashAssert.Verifies(hasher, KnownHashes.Password, stored);

    Assert.Equal(RehashReason.OutdatedPepperKey, result.RehashReason);
    MasterlyHashAssert.IsPeppered(stored, "k1");
    MasterlyHashAssert.IsPeppered(result.Rehash, "k2");
}

[Fact]
public void RetiredPepperKey_FailsWithUnknownPepperKey()
{
    FakePepper pepper = new FakePepper("k1");
    FastPasswordHasher hasher = new FastPasswordHasher(options => options.Pepper = pepper);
    string stored = hasher.Hash(KnownHashes.Password);
    pepper.RotateTo("k2");

    pepper.RetireKey("k1");
    PasswordVerificationResult result = MasterlyHashAssert.DoesNotVerify(hasher, KnownHashes.Password, stored);

    Assert.Equal(VerificationFailureReason.UnknownPepperKey, result.FailureReason);
}
```

**Testing a remote key service.** Remote peppers such as [HashiCorp Vault](./hashicorp-vault.md) are slow, asynchronous and sometimes down. `FakePepper` reproduces all three:

```csharp
[Fact]
public async Task HashAsync_UsesTheAsyncPepperPath()
{
    FakePepper pepper = new FakePepper("k1") { ForceAsynchronous = true };
    FastPasswordHasher hasher = new FastPasswordHasher(options => options.Pepper = pepper);

    await hasher.HashAsync(KnownHashes.Password, CancellationToken.None);

    Assert.Equal(1, pepper.ApplyAsyncCount);
    Assert.Equal(0, pepper.ApplyCount);
}

[Fact]
public async Task HashAsync_WhenPepperIsSlow_HonoursCancellation()
{
    FakePepper pepper = new FakePepper("k1") { AsyncDelay = TimeSpan.FromSeconds(30) };
    FastPasswordHasher hasher = new FastPasswordHasher(options => options.Pepper = pepper);
    using CancellationTokenSource timeout = new CancellationTokenSource(TimeSpan.FromMilliseconds(50));

    Task hashing = hasher.HashAsync(KnownHashes.Password, timeout.Token).AsTask();

    await Assert.ThrowsAnyAsync<OperationCanceledException>(() => hashing);
}

[Fact]
public async Task HashAsync_WhenPepperIsDown_Throws()
{
    TimeoutException outage = new TimeoutException("vault down");
    FakePepper pepper = new FakePepper("k1") { ThrowOnApply = outage };
    FastPasswordHasher hasher = new FastPasswordHasher(options => options.Pepper = pepper);

    TimeoutException thrown = await Assert.ThrowsAsync<TimeoutException>(
        () => hasher.HashAsync(KnownHashes.Password, CancellationToken.None).AsTask());

    Assert.Same(outage, thrown);
}
```

The pepper's exception reaches the caller unchanged, so the last test is the place to check how your own code reacts to an outage, for example that a login endpoint returns 503.

## MasterlyHashAssert

`MasterlyHashAssert` is a static class of assertions about stored hashes. Each method returns normally on success and throws `MasterlyHashAssertionException` on failure. Every test framework reports an unhandled exception as a failed test, so the assertions work with xUnit, NUnit and MSTest alike.

**Format assertions.** These parse the stored string. They need no hasher.

| Method | Succeeds when |
|--------|---------------|
| `IsMasterlyHash(value)` | The value is a well-formed `$mh$p=...$salt$tag` string. |
| `UsesProfile(value, profileId)`, `UsesProfile(value, profile)` | It is a Masterly hash with that profile id, for example `"2026a"` or `FastPasswordHasher.ProfileId`. |
| `IsPeppered(value)`, `IsPeppered(value, keyId)` | It is a Masterly hash peppered with any key, or with that key id. |
| `IsNotPeppered(value)` | It is a Masterly hash without a pepper. |

All four also check the salt and tag lengths. For a built-in or `test-fast` profile they must match the profile exactly; for other profile ids they must be 16 to 64 bytes. A hash truncated by a database column that is too short therefore fails.

**Hasher assertions.** These ask a hasher configured like your application.

| Method | Succeeds when |
|--------|---------------|
| `NeedsRehash(hasher, storedHash)` | The hasher recognizes the hash and would replace it on the next successful login. |
| `DoesNotNeedRehash(hasher, storedHash)` | The hasher recognizes the hash and considers it current. |
| `Verifies(hasher, password, storedHash)` | The password verifies. Returns the `PasswordVerificationResult` for further checks. |
| `DoesNotVerify(hasher, password, storedHash)` | The password does not verify. Returns the result, so you can check `FailureReason`. |

If you pass a `RecordingPasswordHasher`, these methods unwrap it first, so the assertion's own call is not added to the history you assert on.

**Behaviour assertions.** These read a recorder.

| Method | Succeeds when |
|--------|---------------|
| `UsedVerifyOrDummyForUnknownUser(recorder)` | The code called `VerifyOrDummy` (or its async form) without a stored hash, and **never** called `Verify` without one. |
| `PersistedRehash(recorder, persistedHash)` | The most recent rehash the recorder saw equals the value your code stored. |

`UsedVerifyOrDummyForUnknownUser` fails if any unknown-user path called `Verify(password, null)`, even if another path used `VerifyOrDummy`, because `Verify` returns at once and reveals that the account does not exist. It also fails when `VerifyOrDummy` was given an empty string instead of `null`, which skips the dummy work. See [User enumeration](./user-enumeration.md).

**Leak check.** `IsNotPlaintext(stored, password)` fails when the value your code persisted exposes the password:

- the password itself or its NFKC-normalized form, in any case, as the whole value or embedded in it (embedded matches are checked for passwords of 6 characters or more);
- its bytes as base64 (standard, unpadded or URL-safe) or hex;
- an unsalted MD5, SHA-1, SHA-256, SHA-384 or SHA-512 digest of its bytes, in hex or base64.

The byte forms tried are UTF-8, UTF-16LE and UTF-8 of the NFKC-normalized password. For a well-formed Masterly hash only the salt, tag and wrap parameter are searched, so a password that happens to equal a profile id or pepper key id is not reported. A `null` stored value passes; an empty password throws `ArgumentException`.

```csharp
[Fact]
public async Task Register_NeverStoresAReversiblePassword()
{
    // registration is your own code under test; users is its store
    await registration.RegisterAsync("bob", "Tr0ub4dor&3-long", CancellationToken.None);

    MasterlyHashAssert.IsNotPlaintext(users.HashOf("bob"), "Tr0ub4dor&3-long");
    MasterlyHashAssert.IsMasterlyHash(users.HashOf("bob"));
}
```

:::note

`IsNotPlaintext` is a leak check, not a strength check. A salted SHA-256 hash passes it. Pair it with `IsMasterlyHash` or `UsesProfile` to require a proper password hash.

:::

Failure messages describe the problem (format, profile id, pepper key id, lengths) but never include the password or the stored value, which may itself be a leaked plaintext.

## KnownHashes

`KnownHashes` holds sample stored hashes for seeding fake repositories and snapshot tests. Every sample is a hash of `KnownHashes.Password`, `"correct horse battery staple"`, and is verified by the package's own tests against a real `PasswordHasher`.

| Member | Description |
|--------|-------------|
| `Password` | The password every sample was made from. |
| `WrongPassword` | `"Correct horse battery staple"`: differs only in case, and verifies against none of the samples. |
| `V1Sha512`, `V1Sha384`, `V1Sha256` | Masterly.Hash 1.x hashes, salted with `V1Salt`. Verify with any hasher and report `RehashReason.LegacyFormat`. |
| `TestFast` | A `test-fast` hash, no pepper. Verifies with `FastPasswordHasher`; production hashers reject it. |
| `TestFastPeppered` | A `test-fast` hash peppered with `new FakePepper()`, key id `KnownHashes.PepperKeyId` (`"test-key"`). |
| `TestFastWrappedV1Sha512` | `V1Sha512` onion-wrapped into `test-fast`. Verifies with any `FastPasswordHasher`, because the 1.x digest is stored in the wrap parameter. |
| `Server2026a`, `Constrained2026a`, `Fips2026a` | Hashes with the three built-in profiles. They verify with any `PasswordHasher` but are slow by design: tens to hundreds of milliseconds each. |
| `UnknownProfile` | A well-formed hash naming a profile no hasher registers. Fails with `UnknownProfile`. |
| `Malformed` | A `$mh$` string that is not valid. Fails with `MalformedHash`. |
| `UnknownFormat` | A value in no recognized format. Fails with `UnknownFormat`. |
| `MhSalt` | The fixed 16-byte salt of the Masterly samples: bytes 0x00 to 0x0F. Returns a new array on each call. |
| `V1Salt` | The fixed salt of the 1.x samples: the UTF-8 bytes of `SomeSalt#$%`. |

**Factories.** Build more samples deterministically, exactly as the hasher would with the same salt:

| Method | Returns |
|--------|---------|
| `Create(profile, password, salt, pepper, pepperKeyId)` | A Masterly hash. `salt` must be `profile.SaltLength` bytes. `pepper` and `pepperKeyId` are optional; the key id defaults to the pepper's current key. |
| `CreateV1(password, salt, algorithm)` | A 1.x hash, byte for byte what 1.x `Hash.ComputeHash` produced. `algorithm` defaults to `V1Algorithm.SHA512`; `salt` can be any length, including empty. |
| `CreateWrappedV1(profile, password, v1Salt, algorithm, salt)` | An onion-wrapped 1.x hash, exactly as `PasswordHasher.TryWrap` would produce. |

`V1Algorithm` is in the `Masterly.Hash.Legacy` namespace. `Create` throws `ArgumentException` for an empty password, a salt of the wrong length, a key id without a pepper, or a key id the pepper does not know.

```csharp
using Masterly.Hash.Legacy;
using Masterly.Hash.Testing;

// The same inputs give the same string on every run, so it is safe in a snapshot.
string stored = KnownHashes.Create(FastPasswordHasher.Profile, "pw-123456", KnownHashes.MhSalt);

// A 1.x hash with your own salt and digest.
string legacy = KnownHashes.CreateV1("pw-123456", KnownHashes.V1Salt, V1Algorithm.SHA256);

// The samples are what the factories return:
// KnownHashes.TestFast == KnownHashes.Create(FastPasswordHasher.Profile, KnownHashes.Password, KnownHashes.MhSalt)
```

:::warning

The samples and factories use fixed, public salts. Never seed a real database with them, and never use the factories to produce hashes for real users: production hashes need a random salt, which only `PasswordHasher` provides.

:::

## Choosing a helper

| You want to test that... | Use |
|--------------------------|-----|
| Your code hashes and verifies correctly | `FastPasswordHasher` |
| Your code stores the rehash after login | `RecordingPasswordHasher` + `PersistedRehash` |
| Unknown users cost as much as known ones | `RecordingPasswordHasher` + `UsedVerifyOrDummyForUnknownUser` |
| A legacy table migrates | `KnownHashes.V1*` or `CreateV1` + `NeedsRehash` / `PersistedRehash` |
| Pepper rotation and retirement work | `FakePepper` + `RotateTo` / `RetireKey` |
| A slow or failing key service is handled | `FakePepper` with `AsyncDelay`, `ForceAsynchronous` or `ThrowOnApply` |
| Nothing reversible is stored or logged | `IsNotPlaintext` |
| A database column is wide enough | `IsMasterlyHash` on the value read back |

Prefer these helpers to a mock of `IPasswordHasher`. A mock returns whatever you tell it to, so it cannot catch a missing rehash, a wrong failure reason or a truncated column.

## Security notes

- Never use `FastPasswordHasher` or `FakePepper` in production. The `test-fast` profile has no meaningful cost, and the fake pepper's keys are derived from public key ids.
- `test-fast` hashes are rejected by production hashers (`UnknownProfile`), so a leaked test hash can never be accepted.
- `RecordingPasswordHasher` stores only keyed fingerprints of passwords, never the passwords.
- `MasterlyHashAssert` messages never include passwords or stored values.
- `KnownHashes` use fixed, public salts.
- The production-profile samples (`Server2026a` and the others) and production hashers in tests are slow on purpose. Keep them to the few tests that need a real profile.

## See also

- [Hashing and verifying](./hashing-and-verifying.md)
- [Upgrade on login](./upgrade-on-login.md)
- [Peppers](./peppers.md)
- [User enumeration](./user-enumeration.md)
- [Analyzers](./analyzers.md)
- [Package README](https://github.com/a7mdfre7at/Masterly.Hash/blob/master/src/Masterly.Hash.Testing/README.md)
