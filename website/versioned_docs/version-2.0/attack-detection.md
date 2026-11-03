---
title: Attack Detection
sidebar_label: Attack Detection
description: Detect a cracked password database with honeywords, catch attackers with honey accounts, and spot credential stuffing and password spraying without storing passwords.
---

`Masterly.Hash.Detection` tells you when someone is attacking your logins, or has already stolen and cracked your password database. It has three independent detectors:

- **Honeywords.** Each user's hash covers the real password plus decoys. A login with a decoy means someone cracked the stolen hashes.
- **Honey accounts.** Decoy user names that no real person owns. Any login attempt against one is an attacker working from a stolen or scraped list.
- **Credential-stuffing and spraying detection.** Notices the same wrong password failing against many accounts in a short time, without keeping passwords or account names in readable form.

```bash
dotnet add package Masterly.Hash.Detection
```

The package targets `net8.0` and depends only on `Masterly.Hash`. Every public type is in the `Masterly.Hash.Detection` namespace. The detectors emit events; they do not log, meter or block anything themselves. You decide what an alert does.

| Detector | Detects | Needs | Cost per login |
|----------|---------|-------|----------------|
| Honeywords | A stolen **and cracked** password database being used | A separate honeychecker service; a new hash format | One key derivation, as today |
| Honey accounts | Logins driven by a stolen or scraped account list | Some decoy accounts | A dictionary lookup |
| Credential stuffing | One password tried against many accounts | Nothing extra | One HMAC per `IsFlagged` call, two per recorded failure |

## Honeywords

Honeywords come from Juels and Rivest, *Honeywords: Making Password-Cracking Detectable* (ACM CCS 2013). Each user has k "sweetwords": the real password and k - 1 decoys, all hashed under one per-user salt. An attacker who steals and cracks the database sees k equally plausible passwords per user and cannot tell which one is real. Logging in with a decoy reveals the breach.

Which sweetword is real is known only to a separate **honeychecker**. The user database never stores it.

**When to use them.** You want to learn that your hashes were cracked, not only that they were stolen, and you can run a small hardened service with separate storage and credentials.

**When not to.** You cannot keep the honeychecker apart from the application database. Without that separation the scheme protects nothing. Also consider the cost: creating a record costs k key derivations instead of one.

### Setting up

**1. Create the service and the login wrapper.** `HoneywordLoginService` ties `HoneywordService` (hashing) to an `IHoneychecker` (the separate system).

```csharp title="Program.cs"
using System;
using Masterly.Hash;
using Masterly.Hash.Detection;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

PasswordHasher hasher = new PasswordHasher(new PasswordHasherOptions { Pepper = pepper });

HoneywordService honeywords = new HoneywordService(hasher, new HoneywordServiceOptions
{
    Generator = PasswordModelHoneywordGenerator.Default, // recommended over the default tweaking generator
    Pepper = pepper,                                      // the same IPasswordPepper the hasher uses, if any
});

builder.Services.AddSingleton(honeywords);
builder.Services.AddHttpClient<IHoneychecker, HttpHoneychecker>(client =>
    client.BaseAddress = new Uri(builder.Configuration["Honeychecker:Url"]!)); // required setting

// Scoped, because the typed HttpClient behind IHoneychecker is transient.
builder.Services.AddScoped(services =>
{
    HoneywordLoginService login = new HoneywordLoginService(
        services.GetRequiredService<HoneywordService>(), services.GetRequiredService<IHoneychecker>());
    ILogger<HoneywordLoginService> logger = services.GetRequiredService<ILogger<HoneywordLoginService>>();
    login.BreachDetected += (_, e) =>
        logger.LogCritical("Honeyword used for user {UserId} at {DetectedAt}", e.UserId, e.DetectedAt);
    return login;
});
```

**2. Register users.** `RegisterAsync` generates the decoys, hashes all k sweetwords, sends the real index to the honeychecker and returns the string to store.

```csharp title="RegistrationService.cs"
user.PasswordHash = await _honeywordLogin.RegisterAsync(user.Id, password, cancellationToken: cancellationToken);
await _db.SaveChangesAsync(cancellationToken);
```

Persist the returned hash only after `RegisterAsync` completes. If saving then fails, call `RegisterAsync` again rather than keeping an older hash: the honeychecker now holds an index for a hash that was never stored, and the user's next correct login would be reported as a breach.

**3. Check logins.**

```csharp title="LoginService.cs"
HoneywordLoginResult result = await _honeywordLogin.LoginAsync(userName, password, user?.PasswordHash, cancellationToken);
if (!result.IsSuccess)
{
    _logger.LogInformation("Login failed: {Outcome} {Status}", result.Outcome, result.Verification.Status);
    return Results.Unauthorized(); // BreachDetected gets exactly the same response as Mismatch
}
```

`LoginAsync` performs one key derivation even when the stored hash is null (an unknown user), so timing does not reveal which accounts exist. Pass the submitted user name as `userId` for an unknown user; the honeychecker is never asked when there is no stored hash.

| Outcome | Meaning | What to do |
|---------|---------|------------|
| `Mismatch` (the default value) | The password matches no sweetword, or the stored hash is unusable. | An ordinary failed login. |
| `Success` | The password is the real one. | Sign the user in. |
| `BreachDetected` | The password is a decoy. Most likely someone who cracked the password file is logging in. | Deny exactly as for `Mismatch`, then investigate. |

:::danger

Never tell the client that a decoy was used. Respond to `BreachDetected` exactly as to a wrong password, including timing, then alert your security team. Consider forcing a password reset for every user once you confirm the breach.

:::

The built-in generators never place a decoy within one typo (one substitution, insertion, deletion or swap of neighbouring characters) of the real password, so an honest user's single typo cannot raise the alarm. Two or more typos, or a custom generator, can still land on a decoy. Treat one hit as a strong signal to investigate, and hits across many accounts as a confirmed breach.

`HoneywordLoginResult` exposes `Outcome`, `IsSuccess` (true only for `Success`) and `Verification`. After `Success`, `Verification.Index` is withheld and reads -1: the real index is the honeychecker's secret. `ToString()` returns the outcome only.

The `BreachDetected` event carries `HoneywordBreachDetectedEventArgs` with `UserId`, `SweetwordIndex` (the decoy that was entered, not the real index) and `DetectedAt`. Handlers run on the login path; exceptions they throw propagate to the caller of `LoginAsync`. If the honeychecker is unreachable, its exception also propagates: the login fails closed. Pass a clock to the three-argument constructor to control `DetectedAt` in tests.

### The honeychecker

`IHoneychecker` is the narrow interface to the separate system:

| Method | Contract |
|--------|----------|
| `Task SetAsync(string userId, int index, CancellationToken cancellationToken = default)` | Records the real index for the user, replacing any previous value. |
| `Task<bool> IsRealAsync(string userId, int index, CancellationToken cancellationToken = default)` | True if the index is the real one. Unknown users must return false (fail closed). |

Run the honeychecker as its own hardened service. It must not share storage, credentials or an administrator with the password database, so that one breach does not reveal both halves. Keep the wire interface as narrow as the C# one, "set" and "is this index real?", and have the honeychecker raise its own alarm when a wrong index is checked, independently of the application.

A client for such a service is a few lines; the endpoint shape is up to you:

```csharp title="HttpHoneychecker.cs"
using System;
using System.Net.Http;
using System.Net.Http.Json;
using System.Threading;
using System.Threading.Tasks;
using Masterly.Hash.Detection;

namespace MyApp.Security;

public sealed class HttpHoneychecker : IHoneychecker
{
    private readonly HttpClient _http;

    public HttpHoneychecker(HttpClient http)
    {
        _http = http;
    }

    public async Task SetAsync(string userId, int index, CancellationToken cancellationToken = default)
    {
        using HttpResponseMessage response = await _http.PutAsJsonAsync(
            $"users/{Uri.EscapeDataString(userId)}/index", new IndexRequest(index), cancellationToken);
        response.EnsureSuccessStatusCode();
    }

    public async Task<bool> IsRealAsync(string userId, int index, CancellationToken cancellationToken = default)
    {
        using HttpResponseMessage response = await _http.PostAsJsonAsync(
            $"users/{Uri.EscapeDataString(userId)}/check", new IndexRequest(index), cancellationToken);
        response.EnsureSuccessStatusCode(); // an unreachable or failing honeychecker throws: fail closed
        CheckResponse? body = await response.Content.ReadFromJsonAsync<CheckResponse>(cancellationToken);
        return body?.IsReal == true;
    }

    private sealed record IndexRequest(int Index);

    private sealed record CheckResponse(bool IsReal);
}
```

`InMemoryHoneychecker` keeps indexes in process memory. It has `Count` and `Remove(userId)` (for account deletion), and `SetAsync` rejects a negative index with `ArgumentOutOfRangeException`. Use it only in tests and demos.

:::danger

Do not use `InMemoryHoneychecker` in production. An in-process honeychecker falls to the same breach as the database and loses its state on restart.

:::

### HoneywordService directly

`HoneywordLoginService` covers the usual flow. `HoneywordService` gives you the pieces:

| Method | Returns |
|--------|---------|
| `Create(password, sweetwordCount = 20)` / `CreateAsync(password, sweetwordCount = 20, cancellationToken)` | A `HoneywordRecord`. |
| `Verify(password, storedHash)` | The zero-based index of the matching sweetword, or -1. |
| `VerifyDetailed(password, storedHash)` / `VerifyDetailedAsync(...)` | A `HoneywordVerification` with the reason for a failure. |
| `VerifyOrDummy(password, storedHash)` / `VerifyOrDummyAsync(...)` | Like `VerifyDetailed`, but performs one key derivation when `storedHash` is null, so unknown users cost the same. |
| `HoneywordService.IsHoneywordHash(storedHash)` | Static. True if the string starts with `$mhw$`. Does not validate it. |

It also exposes `DefaultProfile`, `Profiles` and `Generator`. The service is thread-safe; register it as a singleton. Prefer the async methods on the request path: they wait asynchronously for a derivation slot and use the pepper's async API.

`HoneywordRecord` has two halves that go to two different systems:

| Property | Goes to |
|----------|---------|
| `StoredHash` | The user database. It does not reveal which sweetword is real. |
| `RealIndex` | The honeychecker only. Never store it with the hash. |
| `SweetwordCount` | Informational. |

`HoneywordRecord.ToString()` returns only the count (`HoneywordRecord (k=20)`), so the index cannot end up in a log next to the hash.

`Create` throws `ArgumentNullException` for a null password; `ArgumentException` for an empty password, invalid UTF-16 or a password longer than `MaxPasswordBytes`; `ArgumentOutOfRangeException` for a sweetword count outside 2 to `MaxSweetwordCount`; `InvalidOperationException` when the generator returns an invalid decoy set; and `PasswordHasherBusyException` when no derivation slot becomes free in time.

The verify methods never throw for a bad stored hash. `HoneywordVerification` reports why:

| Status | Meaning |
|--------|---------|
| `Mismatch` (the default value) | The password equals none of the sweetwords. |
| `SweetwordMatch` | The password equals one of the sweetwords. Ask the honeychecker whether it is the real one. |
| `NoStoredHash` | No stored hash was supplied. |
| `MalformedHash` | Not a well-formed `$mhw$` hash, or a salt or tag length that does not fit its profile. |
| `UnknownProfile` | The stored profile id is not in the allowlist. |
| `UnknownPepperKey` | The hash was made with a pepper key that is not configured. |
| `EmptyPassword` | The password is empty. Empty passwords never match. |
| `PasswordTooLong` | The password exceeds `MaxPasswordBytes` after normalization. |
| `InvalidPassword` | The password is not valid UTF-16 (an unpaired surrogate) or cannot be normalized. |

`HoneywordVerification` is a struct with `Status`, `Index` (-1 when there is no match) and `IsSweetwordMatch`. `ToString()` returns the status only. Never log or store `Index`: for the real password it is the secret the honeychecker protects.

### Stored format

```
$mhw$p=<profileId>[,k=<pepperKeyId>]$<salt>$<tag1>,<tag2>,...,<tagk>
```

All values are unpadded base64. Each tag is the profile's key derivation of the NFKC-normalized UTF-8 sweetword (peppered when a pepper is configured) under the shared salt. As in the core `$mh$` format, cost parameters are never stored: the profile id is resolved against an allowlist and unknown ids are rejected.

Because all sweetwords share one salt, a login costs exactly **one** key derivation, compared against every tag in constant time. Creating a record costs **k** derivations.

With the default k of 20 and the `2026a` profile (16-byte salt, 32-byte tags), the stored string is about 915 characters, so size the column accordingly (for example `nvarchar(max)` or `varchar(1024)`). A parsed hash may be at most `256 + 87 x MaxSweetwordCount` characters; longer strings are rejected before parsing.

`PasswordHasher` does not understand `$mhw$` hashes. If some users have honeyword hashes and others `$mh$` hashes, route by `HoneywordService.IsHoneywordHash(storedHash)`. To move an existing user to honeywords, call `RegisterAsync` with the plaintext after a successful normal login and store the result. A database copy taken before the switch still contains that user's plain hash.

### Options

`HoneywordServiceOptions`:

| Option | Default | Range | Meaning |
|--------|---------|-------|---------|
| `Generator` | `TweakingHoneywordGenerator.Default` | Not null | The decoy generator. `PasswordModelHoneywordGenerator.Default` is recommended. |
| `Pepper` | null | Key id `^[A-Za-z0-9-]{1,32}$` | Optional `IPasswordPepper`. Its current key id is written into new hashes (`,k=`) so keys can rotate. `PasswordHasher` does not expose its pepper, so pass the same instance here. |
| `MaxSweetwordCount` | 100 | 2 to 1000 (`HoneywordService.MaxSweetwordLimit`) | Largest count accepted when creating and when parsing, which bounds the work an attacker-supplied string can cause. |
| `MaxPasswordBytes` | 1024 | 64 to 1,048,576 | Longest password in UTF-8 bytes after normalization. |
| `MaxConcurrency` | `Environment.ProcessorCount` | 0 or more; 0 disables the limit | Key derivations running at once, so a login flood cannot exhaust memory. |
| `ConcurrencyTimeout` | 30 seconds | Positive or `Timeout.InfiniteTimeSpan` | How long a call waits for a slot before throwing `PasswordHasherBusyException`. |
| `AllowWeakProfiles` | false | | Allows profiles below the OWASP minimums when profiles are passed explicitly. Only for tests. |

Two constructors:

- `HoneywordService(PasswordHasher hasher, HoneywordServiceOptions? options = null)` uses the hasher's default profile for new records and accepts every profile the hasher knows.
- `HoneywordService(HashProfile defaultProfile, IEnumerable<HashProfile> allowedProfiles, HoneywordServiceOptions? options = null)` takes an explicit allowlist. Profiles below the OWASP minimums throw `ArgumentException` unless `AllowWeakProfiles` is set.

The constructors also throw `ArgumentException` for a null generator, an invalid pepper key id or a profile id listed twice with different parameters, and `ArgumentOutOfRangeException` for an option outside its range. The concurrency limit is separate from the core hasher's; see [Limits and Concurrency](./limits-and-concurrency.md).

### Decoy generators

The security of honeywords rests entirely on decoys that look as human as the real password.

| Generator | How it works | Notes |
|-----------|--------------|-------|
| `TweakingHoneywordGenerator` (the default) | "Chaffing by tail-tweaking" (paper section 5.1). Replaces the last 3 characters with random characters of the same class: `BG+7y45` becomes `BG+7q03` or `BG+7m55`. | Easy to tell apart. Wang, Cheng, Wang, Yan and Huang (*A Security Analysis of Honeywords*, NDSS 2018) show the real password is usually the most "human" one in the set. |
| `PasswordModelHoneywordGenerator` (recommended) | "Chaffing with a password model" (section 5.2). Splits the password into letter, digit and symbol runs (`Summer2024!` is 6 letters, 4 digits, 1 symbol) and replaces each run with a plausible token of the same class and length: a dictionary word with the same capitalization, a year or digit pattern, common symbols. | Better, but still not perfect against a strong password-guessing model. Supply a word list that matches your users' language. |

**`TweakingHoneywordGenerator(tailLength = 3, tweakCase = false)`.** `tailLength` is 1 to 16 (`ArgumentOutOfRangeException` otherwise). With `tweakCase`, letters in the tail may also change case, which gives more variations but changes the password's shape and makes decoys easier to spot. If the tail does not offer enough variations it is widened towards the start of the password, and as a last resort random digits are appended. The properties are `TailLength` and `TweakCase`; `TweakingHoneywordGenerator.Default` uses a tail of 3 (`DefaultTailLength`).

**`PasswordModelHoneywordGenerator(words)`.** The parameterless constructor and `PasswordModelHoneywordGenerator.Default` use a built-in English word list. A custom list is lower-cased, and anything that is not 1 to 32 ASCII letters is ignored; a list with no usable word throws `ArgumentException`. `WordCount` is the number of distinct words. Digit runs of length 4 become a year between 1950 and 2030 about 40% of the time; other digit runs may become ascending sequences such as `6789` or repeated digits. Symbols are mostly drawn from the common set `!@#$%&*?._-+=`. If the structure leaves too little room for distinct decoys, the rest are filled by randomizing every replaceable character within its class.

Both generators:

- Replace letters and digits of other scripts (Cyrillic, Greek, Arabic, Hebrew, Devanagari, Thai, accented Latin, kana, Hangul, CJK and other Unicode letters and digits) with characters of the same script and case, so `пароль1` gets decoys such as `кшвтуя7`.
- Keep spaces, combining marks, non-ASCII symbols and emoji unchanged.
- Keep every decoy more than one typo away from the real password, distinct from each other and from the real password.

:::warning

A password with only one or two replaceable characters, such as `7` or a password made only of emoji, can only be padded with appended digits. That gives the real password away: it is the only sweetword without them. Reject such passwords with your [password policy](./password-policy.md). For passwords in other scripts, the built-in English word list means the real password may be the only sweetword made of real words.

:::

**Custom generators** implement `IHoneywordGenerator.GenerateDecoys(string realPassword, int count)`. The service passes the NFKC-normalized real password and `count` = k - 1, then checks the result and shuffles the real password in at a random position with a CSPRNG. Return exactly `count` non-empty decoys, distinct from each other and from the real password, and no longer than `MaxPasswordBytes`; otherwise `Create` throws `InvalidOperationException`. Use a cryptographically secure random source, and never log or retain the input.

### Honeyword caveats

- **Do not regenerate decoys for an unchanged password**, for example to move to a newer profile. An attacker holding two copies of the database can intersect the two sweetword sets and find the real password. Upgrade the profile when the user next changes their password.
- **Keep k modest.** The paper suggests 20 (`HoneywordService.DefaultSweetwordCount`). Creation costs k derivations; create records with `CreateAsync` or `RegisterAsync`, and keep the concurrency limit in place.
- **Store the two halves apart.** `StoredHash` in the user database, `RealIndex` in the honeychecker, and neither in logs.

## Honey accounts

A honey account is a decoy user name that no legitimate user owns. Seed a few into your user table (with honeyword or random hashes) and into places an attacker might harvest, such as an old public member list. Any login that targets one comes from an attacker working from a stolen list or a cracked database.

```csharp title="Program.cs"
HoneyAccountRegistry honeyAccounts = new HoneyAccountRegistry(new[] { "admin2", "backup-svc", "j.smith.old" });
honeyAccounts.HoneyAccountAccessed += (_, e) => // alerts is your own paging or SIEM client
    alerts.Page($"Honey account {e.Account} used from {e.Context} at {e.Timestamp:O}");
builder.Services.AddSingleton(honeyAccounts);
```

```csharp title="LoginService.cs"
if (_honeyAccounts.CheckLogin(request.UserName, context: clientIp))
{
    // Same response as a wrong password, including the time it takes.
    await _hasher.VerifyOrDummyAsync(request.Password, null, cancellationToken);
    return Results.Unauthorized();
}
```

`CheckLogin(account, context = null)` raises `HoneyAccountAccessed` and returns true for a honey account. Call it on every attempt.

:::warning

Keep the response identical to a wrong password, including its timing. Run the usual password verification, or a dummy one with `VerifyOrDummyAsync(password, null)`, before failing. A fast response marks the account as a honeypot.

:::

| Member | Behaviour |
|--------|-----------|
| `HoneyAccountRegistry()`, `(accounts)`, `(accounts, clock)` | Creates a registry. The clock sets event timestamps. |
| `Add(account)` | Returns false if already present. Throws `ArgumentException` for an empty name or one longer than 1024 characters. |
| `Remove(account)` | Returns false if not present. |
| `IsHoneyAccount(account)` | Checks without raising the event. |
| `CheckLogin(account, context)` | Checks and raises the event. |
| `Count` | Number of honey accounts. |
| `HoneyAccountRegistry.MaxAccountLength` | 1024 UTF-16 code units. |

- Matching is case-insensitive and NFKC-normalized, so `Admin`, `ADMIN` and the full-width `ａｄｍｉｎ` are the same account.
- Names longer than 1024 code units are never honey accounts and are not normalized, so an attacker-supplied multi-megabyte user name costs nothing.
- `HoneyAccountAccessedEventArgs` has `Account` (as supplied in the attempt), `Context` (what you passed, such as the client address or request id) and `Timestamp`. Never pass the password as context.
- Handlers run on the login path; exceptions they throw propagate to the caller of `CheckLogin`.
- The registry is thread-safe.

## Credential stuffing and password spraying

`CredentialStuffingDetector` notices the same wrong password failing against many distinct accounts in a short time. That pattern is credential stuffing (replaying leaked credentials) or password spraying (trying one common password everywhere).

```csharp title="Program.cs"
CredentialStuffingDetector stuffing = new CredentialStuffingDetector(new CredentialStuffingOptions
{
    Window = TimeSpan.FromMinutes(10),
    DistinctAccountThreshold = 20,
});
stuffing.StuffingDetected += (_, e) => logger.LogWarning( // logger is an ILogger from your host
    "Password {FingerprintId} failed for {AccountCount} accounts between {WindowStart} and {WindowEnd}",
    e.FingerprintId, e.DistinctAccountCount, e.WindowStart, e.WindowEnd);
builder.Services.AddSingleton(stuffing);
```

```csharp title="LoginService.cs"
if (_stuffing.IsFlagged(request.Password))
{
    // This password is being sprayed right now: require a CAPTCHA or slow the client down.
}

// ... verify the password ...

if (!verified)
{
    bool sprayed = _stuffing.RecordFailedLogin(request.UserName, request.Password);
}
```

| Member | Behaviour |
|--------|-----------|
| `RecordFailedLogin(account, password)` | Records a failed login. Returns true if the password is flagged in the current window, by this call or earlier. An overload takes a `SensitiveString` password. |
| `IsFlagged(password)` | True if the password is flagged in the current window. Does not record a failure, but keeps a flagged fingerprint from being evicted. |
| `GetSnapshot()` | The tracked fingerprints, most recently seen first, as `FingerprintStatistics` (`FingerprintId`, `DistinctAccountCount`, `IsFlagged`). Contains no secrets. |
| `Reset()` | Ends the current window now: discards all counts and zeroes the keys. |
| `Dispose()` | Zeroes the keys and discards all state. Afterwards `RecordFailedLogin`, `IsFlagged`, `GetSnapshot`, `Reset`, `TrackedFingerprintCount` and `WindowStart` throw `ObjectDisposedException`; calling `Dispose` again does nothing. |
| `DistinctAccountThreshold`, `Window` | The configured values. |
| `TrackedFingerprintCount`, `EvictedCount`, `WindowStart` | Current state, for dashboards. |

The `StuffingDetected` event fires **once per fingerprint per window**, when the threshold is reached. It is raised outside the detector's lock, on the thread that recorded the failure; exceptions thrown by handlers propagate to that caller. `CredentialStuffingDetectedEventArgs` carries `FingerprintId`, `DistinctAccountCount`, `WindowStart`, `WindowEnd` (exclusive) and `DetectedAt`. It contains no password and no account name.

### What is stored

- Each password is kept only as a fingerprint: `HMAC-SHA256(windowKey, password)` truncated to 128 bits (`CredentialStuffingDetector.FingerprintLength` is 16 bytes). `FingerprintId` is its 32-character hex form.
- Each account name is kept only as a 64-bit HMAC under a second key, after NFKC normalization and case folding, so `Alice` and `ALICE` count as one account.
- Both keys are random per window and are zeroed when the window ends. After that, recorded fingerprints cannot be reversed by dictionary attack or correlated with later ones. A fingerprint id is meaningful only within its window.

### Options

`CredentialStuffingOptions` are copied when the detector is created. An option outside its range throws `ArgumentOutOfRangeException`.

| Option | Default | Range | Meaning |
|--------|---------|-------|---------|
| `Window` | 10 minutes | 1 second to 1 day | Length of a detection window. |
| `DistinctAccountThreshold` | 20 | 2 to 10,000 | Distinct accounts one wrong password must fail against within a window. |
| `MaxTrackedFingerprints` | 100,000 | 1 to 10,000,000 | Fingerprints tracked at once; the least recently seen is evicted beyond that, in O(1). |
| `MaxPasswordLength` | 4096 | 1 to 1,048,576 | Longer passwords, in UTF-16 code units, are ignored before normalization. |
| `MaxAccountLength` | 1024 | 1 to 1,048,576 | Longer account names are ignored before normalization. |
| `Clock` | null (uses `DateTimeOffset.UtcNow`) | Any `Func<DateTimeOffset>` | Clock for windows and event timestamps; inject one in tests. |

Ignored input records nothing and returns false.

**Memory.** The worst case (every fingerprint one account short of the threshold, on a 64-bit runtime) is roughly `MaxTrackedFingerprints x (350 + 40 x DistinctAccountThreshold)` bytes, measured on .NET 10: about 115 MB with the defaults. Lower `MaxTrackedFingerprints` if that is too much.

### Limitations

- **Fixed windows can be gamed.** Windows are tumbling: a new one starts on the first call after the previous one ends. An attack that straddles a boundary is counted in two halves, so an attacker who knows the window can stay just under the threshold. Keep the window long and the threshold low enough for your traffic.
- **Eviction.** A flood of unique garbage passwords can evict a tracked fingerprint, and a fingerprint flagged, evicted and seen again is reported again. Both `RecordFailedLogin` and a positive `IsFlagged` mark a fingerprint as recently seen, so a password that keeps being sprayed stays flagged.
- **Memory dumps.** While a window is open its keys are in process memory, so a memory dump taken during the window allows guessing the passwords behind that window's fingerprints.
- **One process.** The detector keeps its state in memory. Each instance behind a load balancer counts only the failures it sees, so with several instances lower the threshold accordingly.
- **Common passwords.** A popular password can legitimately fail for many users who mistype their own. Use the flag to add friction, not to lock accounts.

## Putting it together

A login endpoint that uses all three detectors with honeyword hashes:

```csharp title="LoginEndpoint.cs"
public async Task<IResult> LoginAsync(LoginRequest request, string clientIp, CancellationToken cancellationToken)
{
    if (_stuffing.IsFlagged(request.Password))
    {
        _logger.LogWarning("Sprayed password attempted from {ClientIp}", clientIp); // add a CAPTCHA here
    }

    bool honeyAccount = _honeyAccounts.CheckLogin(request.UserName, context: clientIp);
    User? user = honeyAccount
        ? null
        : await _db.Users.AsNoTracking().SingleOrDefaultAsync(u => u.UserName == request.UserName, cancellationToken);

    // One key derivation whether or not the user exists, so timing reveals nothing.
    HoneywordLoginResult result = await _honeywordLogin.LoginAsync(request.UserName, request.Password, user?.PasswordHash, cancellationToken);
    if (result.IsSuccess)
    {
        return await SignInAsync(user!, cancellationToken); // Success implies a stored hash, so user is not null
    }

    _stuffing.RecordFailedLogin(request.UserName, request.Password);
    return Results.Unauthorized();
}
```

## Security notes

- Run the honeychecker as a separate, hardened service with its own storage, credentials and alerting.
- Respond to every detection exactly as to a wrong password. The detectors are only useful while the attacker does not know they fired.
- Event handlers run on the login path. Keep them fast and non-throwing; hand slow work such as paging to a queue.
- Never log a honeyword index, a password or a `HoneywordRecord.RealIndex`. The built-in `ToString()` methods leave them out.

## See also

- [User Enumeration](./user-enumeration.md): equal timing for unknown users.
- [Limits and Concurrency](./limits-and-concurrency.md): `PasswordHasherBusyException` and derivation slots.
- [Peppers](./peppers.md): the `IPasswordPepper` you pass to `HoneywordServiceOptions.Pepper`.
- [Password Policy](./password-policy.md): reject passwords too short for good decoys.
- [Threat Model](./threat-model.md)
- [HoneywordService.cs on GitHub](https://github.com/a7mdfre7at/Masterly.Hash/blob/master/src/Masterly.Hash.Detection/Honeywords/HoneywordService.cs)
