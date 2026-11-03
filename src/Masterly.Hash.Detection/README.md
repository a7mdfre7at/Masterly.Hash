# Masterly.Hash.Detection

![Masterly.Hash: password hashing you can't get wrong.](https://raw.githubusercontent.com/a7mdfre7at/Masterly.Hash/master/assets/banner.png)

Breach and attack detection for [Masterly.Hash](https://github.com/a7mdfre7at/Masterly.Hash):

- **Honeywords** (Juels and Rivest, *Honeywords: Making Password-Cracking Detectable*, ACM CCS 2013). Each user
  gets k "sweetwords": the real password plus k-1 decoys. A separate **honeychecker** is the only system that
  knows which one is real. If someone logs in with a decoy, your password database has been stolen and cracked.
- **Honey accounts**. These are decoy usernames that no real user owns. Any login attempt against one raises an
  alert.
- **Credential-stuffing and spraying detection**. It notices when the same wrong password fails against many
  accounts in a short time. Neither passwords nor account names are kept in readable form.

Targets `net8.0`. Its only dependency is `Masterly.Hash`.

## Install

```
dotnet add package Masterly.Hash.Detection
```

## Honeywords

```csharp
var hasher = new PasswordHasher();
var honeywords = new HoneywordService(hasher, new HoneywordServiceOptions
{
    Generator = PasswordModelHoneywordGenerator.Default, // recommended, see below
});

// Registration: k = 20 sweetwords, one salt, k key derivations.
HoneywordRecord record = honeywords.Create(password);
user.PasswordHash = record.StoredHash;          // "$mhw$p=2026a$<salt>$<tag1>,...,<tag20>"
await honeychecker.SetAsync(user.Id, record.RealIndex); // a SEPARATE system

// Login: exactly ONE key derivation, compared against every tag in constant time.
int index = honeywords.Verify(password, user.PasswordHash); // -1 if no sweetword matches
```

`HoneywordLoginService` combines both steps:

```csharp
var login = new HoneywordLoginService(honeywords, honeycheckerClient);
login.BreachDetected += (_, e) => alerts.Page($"Honeyword used for {e.UserId}");

user.PasswordHash = await login.RegisterAsync(user.Id, password);
HoneywordLoginResult result = await login.LoginAsync(user.Id, password, user?.PasswordHash);
// result.Outcome: Success | Mismatch | BreachDetected
```

When the outcome is `BreachDetected`, reject the login the same way as `Mismatch` so the attacker learns nothing,
then investigate. The built-in generators never put a decoy within one typo (one substitution, insertion, deletion
or swap of neighbouring characters) of the real password, so an honest user's single typo cannot raise the alarm.
Two or more typos still can, so treat a single hit as a strong signal and hits across many accounts as a confirmed
breach.

After `Success`, `result.Verification.Index` is withheld (-1), and `HoneywordVerification.ToString()` prints only
the status. The real index is the honeychecker's secret: never log it next to a user id.

The stored string never contains cost parameters. Profile ids are looked up in an allowlist (the hasher's
profiles, or a list you pass in), and unknown ids are rejected. `Verify` never throws for a malformed or unknown
stored hash. It returns -1, and `VerifyDetailed` tells you why.

### Decoy generators

| Generator | How it works | Notes |
|---|---|---|
| `TweakingHoneywordGenerator` (default) | "Chaffing by tweaking" from the paper. The last 3 characters are replaced by random characters of the same class. | Easy to tell apart. Wang, Cheng, Wang, Yan and Huang (*A Security Analysis of Honeywords*, NDSS 2018) show that the real password is usually the most "human" one in the set. |
| `PasswordModelHoneywordGenerator` (recommended) | "Chaffing with a password model". The password is split into letter, digit and symbol runs, and each run is replaced by a plausible token of the same class and length: dictionary words with the same capitalization, years, digit patterns, common symbols. | Better, but still not perfect against a strong password-guessing model. For best results, pass a word list that matches your users' language. |

Decoys are always distinct from each other and from the real password, and never within one typo of it.
Positions are shuffled with a CSPRNG.

Letters and digits in other scripts (Cyrillic, Greek, Arabic, Hebrew, Devanagari, Thai, accented Latin, kana,
Hangul, CJK and other Unicode letters and digits) are replaced by characters of the same script and case, so
`пароль1` gets decoys like `кшвтуя7`. The bundled word list is English, so for these passwords the real one may be
the only sweetword made of real words. Spaces, combining marks, non-ASCII symbols and emoji are kept unchanged.
A password with only one or two replaceable characters (`7`, or only emoji) can only be padded with appended
digits, which gives the real password away. Reject such passwords with your password policy.

## Honey accounts

```csharp
var honey = new HoneyAccountRegistry(new[] { "admin2", "backup-svc", "j.smith.old" });
honey.HoneyAccountAccessed += (_, e) => alerts.Page($"Honey account {e.Account} from {e.Context}");

if (honey.CheckLogin(username, context: clientIp))
{
    // Same response as a wrong password, including the time it takes: run a dummy verification first.
    hasher.VerifyOrDummy(password, null);
    return Unauthorized();
}
```

Matching ignores case and applies NFKC normalization, so `Admin`, `ADMIN` and `ａｄｍｉｎ` are treated as the same
account. Names longer than `HoneyAccountRegistry.MaxAccountLength` (1024) are never honey accounts and are not
normalized.

## Credential-stuffing detection

```csharp
var detector = new CredentialStuffingDetector(new CredentialStuffingOptions
{
    Window = TimeSpan.FromMinutes(10),
    DistinctAccountThreshold = 20,
    MaxTrackedFingerprints = 100_000,
});
detector.StuffingDetected += (_, e) =>
    log.LogWarning("Password {Fp} failed for {N} accounts", e.FingerprintId, e.DistinctAccountCount);

// On every failed login:
bool sprayed = detector.RecordFailedLogin(username, password);
```

- The detector stores only a fingerprint of each password: `HMAC-SHA256(windowKey, password)`, truncated to 128
  bits. Account names are stored the same way, as a 64-bit HMAC under a second key.
- Both keys are random for each window and are zeroed when the window rotates. After that, old fingerprints can't
  be brute-forced and can't be linked to new ones.
- The event fires once per fingerprint per window.
- Memory is bounded: the least recently seen fingerprint is evicted first, in O(1). The worst case is roughly
  `MaxTrackedFingerprints x (350 + 40 x DistinctAccountThreshold)` bytes (measured), about 115 MB with the defaults.
- `IsFlagged` refreshes a flagged fingerprint, so if you block flagged passwords without recording them, the flag
  stays in place while the spraying continues.
- Passwords longer than `MaxPasswordLength` and account names longer than `MaxAccountLength` are ignored before
  normalization.
- It is thread-safe, and the clock can be injected for tests.

## Security notes

- **Run the honeychecker as a separate, hardened service.** It needs its own storage, credentials and alerting,
  and should expose only "set" and "is this index real?". `InMemoryHoneychecker` is a reference implementation
  for tests and demos only. Do not use it in production.
- **Store `StoredHash` and `RealIndex` in different systems.** `HoneywordRecord.ToString()` deliberately leaves
  out the index.
- **Don't regenerate decoys for an unchanged password.** An attacker with two copies of the database could
  intersect the two sweetword sets and find the real password. Move to a new profile only when the user changes
  their password.
- **Creating a record costs k key derivations.** Use `CreateAsync`, keep k modest (the paper suggests 20), and
  remember that a login still costs one.
- **Peppering:** set `HoneywordServiceOptions.Pepper` to the same `IPasswordPepper` you give the core hasher.
- **Fixed windows can be gamed.** Stuffing windows are fixed (tumbling), so an attacker who knows the boundaries
  can stay just under the threshold. While a window is open, its keys are in process memory.
