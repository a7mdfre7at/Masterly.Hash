# Masterly.Hash.Policy

![Masterly.Hash: password hashing you can't get wrong.](https://raw.githubusercontent.com/a7mdfre7at/Masterly.Hash/master/assets/banner.png)

Password quality checks for sign-up and password-change forms, aligned with **NIST SP 800-63B rev. 4**, plus a
zxcvbn-inspired strength estimator. Companion to [Masterly.Hash](https://www.nuget.org/packages/Masterly.Hash).

```
dotnet add package Masterly.Hash.Policy
```

## Quickstart

```csharp
using Masterly.Hash;
using Masterly.Hash.Policy;

var policy = new PasswordPolicy(new PasswordPolicyOptions { ContextWords = { "Contoso" } });

PasswordPolicyResult result = policy.Evaluate(input, new PasswordContext
{
    UserName = user.UserName,
    Email = user.Email,
    DisplayName = user.FullName,
});

if (!result.IsAcceptable)
    return BadRequest(new { errors = result.Violations.Select(v => v.Message), result.Suggestions });

user.PasswordHash = Password.Hash(input);
```

With a breached-password corpus (you supply the implementation, e.g. a Pwned Passwords k-anonymity client):

```csharp
var policy = new PasswordPolicy(new PasswordPolicyOptions(), myBreachChecker);
var result = await policy.EvaluateAsync(input, context, cancellationToken);
if (result.BreachCheckUnavailable)
    logger.LogWarning("Breach corpus unavailable; password accepted on local checks only.");
```

Stand-alone strength meter:

```csharp
StrengthEstimate estimate = PasswordStrengthEstimator.Estimate(input, new[] { user.UserName });
// estimate.Score (0-4), estimate.GuessesLog10, estimate.CrackTimes.OfflineSlowHash.Display,
// estimate.Warning, estimate.Suggestions
```

## Rules

| Check | Default | Violation |
|---|---|---|
| Minimum length, in Unicode code points after NFKC | 15 (NIST, password as the only factor). 8 is allowed when the password is one factor of MFA; lower values are refused. | `TooShort` |
| Maximum length | 128 (must be 64-4096; NIST: permit at least 64) | `TooLong` |
| Blocklist: the 10,000 most common passwords, case- and l33t-insensitive, plus `BlockedPasswords` | on | `CommonPassword` |
| Context words: user name, email local part and domain, display name, service name, extra words; also reversed, and l33t-insensitive on both sides (`j0hnd03` blocks `johndoe` and vice versa) | on, words of 4+ code points | `ContainsContextWord` |
| Only repeats of short or patterned units, sequences and keyboard runs (`aaaaaa`, `aabaabaab`, `1234abcd`, `qwertyuiop`), checked over the whole password. A strong token typed twice is left to the score. | on | `RepetitiveOrSequential` |
| Strength score below `MinimumScore` | 3 (≥ 10^8 estimated guesses) | `TooWeak` |
| Breached-password lookup (`EvaluateAsync` with an `IBreachedPasswordChecker`) | off until you supply one | `Breached` |

There are **no composition rules** (upper case, digit, symbol) and **no expiry**: NIST SP 800-63B says verifiers
SHALL NOT impose them. Force a change only on evidence of compromise. All characters, including spaces and emoji,
are allowed.

## Strength estimator

`PasswordStrengthEstimator` is *inspired by* [zxcvbn](https://github.com/dropbox/zxcvbn) (Wheeler, USENIX Security
2016). It is an independent implementation of the same approach, not a port, and its numbers differ from zxcvbn's:

- matchers for dictionary words (embedded common-password list ranked by frequency, a small English word list and
  your context words), reversed words, l33t substitutions, QWERTY and keypad patterns, sequences, repeats, years and
  dates, with bruteforce for the rest;
- a dynamic-programming search for the decomposition needing the fewest guesses;
- `GuessesLog10`, a 0-4 `Score` with zxcvbn's thresholds (10^3, 10^6, 10^8, 10^10), crack-time estimates for
  online throttled (100/hour), online unthrottled (10/s), offline slow hash (10^4/s) and offline fast hash
  (10^10/s) attacks, and warning/suggestion text.

Only the first 100 characters are analyzed (`IsTruncated` tells you), which bounds the cost of a call; the estimate
of a longer password is that of its first 100 characters, an approximation rather than a bound. The policy's own
rules (length, blocklist, context words, repetitive/sequential) always look at the whole password.

## Security notes

- `PasswordPolicyResult.ToString()`, `IsAcceptable`, `Score`, `Violations`, `Suggestions` and
  `StrengthEstimate.Warning` never contain any part of the password and are safe to log.
- `StrengthEstimate` details are derived from the password: `Sequence` gives the position and length of each word,
  and the guess count of a weak password reflects the rank of the list entry it matched. Show them to the user who
  typed the password, but **do not log, serialize or store** `result.StrengthEstimate`. To limit leakage, guesses
  and crack times are rounded down to a tenth of a decade and individual patterns carry no guess counts.
- `IBreachedPasswordChecker` implementations must not send the password anywhere; use k-anonymity (send a short hash
  prefix only). A checker that throws or returns `Unavailable` does not block the user; the outcome is reported in
  `BreachCheck`.
- Strength estimates model a guessing attacker; they are heuristics, not guarantees. The real defence against offline
  attacks is the slow hash, so keep hashing with Masterly.Hash.
- `SensitiveString` overloads keep passwords out of logs in request models.

Third-party material: see `THIRD-PARTY-NOTICES.txt` (SecLists, MIT).
