---
title: Strength Estimation
sidebar_label: "Strength Estimation"
description: Estimate how many guesses a password needs, with a 0-4 score, crack times, a warning and suggestions.
---

`PasswordStrengthEstimator` estimates how many guesses an attacker who knows common password patterns would need to find a password. It returns a 0-4 score, crack-time estimates for four attack scenarios, a warning and suggestions. Use it to drive a strength meter, or let [the password policy](./password-policy.md) enforce a minimum score for you.

The estimator ships in `Masterly.Hash.Policy`:

```bash
dotnet add package Masterly.Hash.Policy
```

It is inspired by [zxcvbn](https://github.com/dropbox/zxcvbn) (Dropbox; Wheeler, USENIX Security 2016). It is an independent C# implementation of the same approach, not a port, and it does not embed zxcvbn's frequency lists, so its numbers differ from zxcvbn's.

## Quick start

```csharp title="StrengthMeter.cs"
using Masterly.Hash.Policy;

StrengthEstimate estimate = PasswordStrengthEstimator.Estimate(candidate, new[] { userName, email });

int score = estimate.Score;                                        // 0-4
string offline = estimate.CrackTimes.OfflineSlowHash.Display;      // e.g. "3 hours" or "centuries"
string warning = estimate.Warning;                                 // empty when the score is 3 or 4
IReadOnlyList<string> suggestions = estimate.Suggestions;
```

`PasswordStrengthEstimator` is a static class. It is thread-safe and deterministic: the same password, user inputs and reference year always give the same estimate. The embedded word lists are loaded once, on first use.

## Overloads

| Call | Notes |
|---|---|
| `Estimate(string password)` | No user inputs. Years and dates are scored against the current UTC year. |
| `Estimate(string password, IEnumerable<string>? userInputs)` | With user inputs; current UTC year. |
| `Estimate(SensitiveString password, IEnumerable<string>? userInputs = null)` | For a password kept in a `SensitiveString`; current UTC year. |
| `Estimate(string password, IEnumerable<string>? userInputs, int referenceYear)` | Scores years and dates against `referenceYear` instead of the current year. Use it for reproducible results in tests. |

They throw `ArgumentNullException` for a `null` password and `ArgumentOutOfRangeException` when `referenceYear` is outside 1000-9999.

**User inputs** are words an attacker targeting this user would try first: user name, email address, name, site name. Pass whatever you have; `null`, empty and blank entries are skipped. Each entry is trimmed and cut to 100 UTF-16 units. If an entry contains l33t characters, its plain readings are added too, so a user name `j0hnd03` also makes `johndoe` cheap to guess. User inputs form their own dictionary, ranked in the order you pass them, so the first entry is the cheapest.

:::note

The policy passes its context words (user name, email parts, display name, service name and `ContextWords`) to the estimator as user inputs. You do not need to call the estimator separately when you use the policy; read `PasswordPolicyResult.StrengthEstimate` instead.

:::

## What the estimator looks for

The password is normalized with NFKC first, so full-width `ｐａｓｓｗｏｒｄ` is estimated exactly like `password`. The estimator then finds every pattern it knows in the normalized text:

| `PatternKind` | Finds | Examples | Guesses estimated from |
|---|---|---|---|
| `Dictionary` | A word from a dictionary, case-insensitive, also written backwards or with l33t substitutions | `password`, `Sunshine`, `drowssap`, `p4ssw0rd` | The word's rank in its list, times the capitalization variants, times the l33t variants, times 2 if reversed |
| `Spatial` | A run of at least three adjacent keys on a US QWERTY keyboard or a numeric keypad | `qwerty`, `zxcvbnm,./`, `7896` | The number of keys, the average number of neighbours, the length, the number of turns and the shifted keys |
| `Repeat` | A repeated character or block, through a partial last copy | `aaa`, `abcabc`, `aabaabaab` | The guesses for one copy times the number of copies |
| `Sequence` | A run of at least three characters with a constant step of 1 to 5, or two adjacent characters with a step of 1 | `abc`, `6543`, `aceg` | 4 for obvious starts (`a`, `z`, `0`, `1`, `9`, in either case), 10 for other digits, 26 otherwise; doubled for descending runs; times the length |
| `Year` | A four-digit year from 1900 to 2099 | `1991`, `2019` | The distance from the reference year, at least 20 |
| `Date` | A date of 4 to 8 digits, or with separators (`/`, `\`, `_`, `.`, `-` or white space) | `19910101`, `1/1/91`, `11/20/1991` | 365 times the distance of its year from the reference year (at least 20), times 4 if it has separators |
| `Bruteforce` | Anything else | `kxqvbzrt` | 10 to the power of its length (10 guesses per character); 11 for a single character |

Dates are read with years from 1000 to 2050. A two-digit year above 50 is read as 19xx, otherwise as 20xx. When a date without separators has several readings, the one with the year closest to the reference year wins.

The dictionaries are:

| `DictionaryKind` | Content |
|---|---|
| `CommonPasswords` | The embedded SecLists list of the 10,000 most common passwords, ranked by position in the list. |
| `EnglishWords` | An embedded list of about 1,000 common English words, roughly by frequency. |
| `ContextWords` | The user inputs you passed. |
| `None` | Used on `PatternMatch` for every pattern that is not a dictionary word. |

### Choosing the cheapest decomposition

The matches can overlap. The estimator picks the sequence of non-overlapping patterns that covers the password, with gaps filled by bruteforce, that an attacker would need the fewest guesses for. For a sequence of `l` patterns it minimizes `l! * product(guesses) + 10000^(l-1)`. The factorial models an attacker who does not know the order of the patterns; the additive term penalizes long chains of tiny patterns. A pattern shorter than the whole password costs at least 10 guesses (one character) or 50 guesses (longer), so small patterns are never free.

### L33t substitutions

The estimator and the policy use the same substitution table as zxcvbn:

| Letter | Stand-ins |
|---|---|
| `a` | `4` `@` |
| `b` | `8` |
| `c` | `(` `{` `[` `<` |
| `e` | `3` |
| `g` | `6` `9` |
| `i` | `1` `!` `\|` |
| `l` | `1` `\|` `7` |
| `o` | `0` |
| `s` | `$` `5` |
| `t` | `+` `7` |
| `x` | `%` |
| `z` | `2` |

## The estimate

`StrengthEstimate` has these members:

| Member | Meaning |
|---|---|
| `Guesses` | Estimated guesses to find the password, rounded down to a power of 10^0.1 (steps of about 26%). |
| `GuessesLog10` | `log10(Guesses)`, rounded down to one decimal place. |
| `Score` | 0-4; see below. |
| `CrackTimes` | Time to find the password under four attack scenarios. |
| `Warning` | Why the password is weak, or empty. Only set when `Score` is 2 or lower. |
| `Suggestions` | Advice for a stronger password. Empty when `Score` is 3 or higher. |
| `Sequence` | The patterns the estimate is based on, left to right, covering the analyzed password. |
| `IsTruncated` | True when only the first 100 UTF-16 units were analyzed. |
| `ToString()` | A summary without any part of the password, such as `Score 3 (10^9.2 guesses)`. |

### Score

The score uses zxcvbn's thresholds, each with a margin of 5 guesses (score 0 is below 10^3 + 5, and so on):

| Score | Estimated guesses | Meaning |
|---|---|---|
| 0 | fewer than 10^3 | Too guessable: risky. |
| 1 | fewer than 10^6 | Very guessable: protects against throttled online attacks. |
| 2 | fewer than 10^8 | Somewhat guessable: protects against unthrottled online attacks. |
| 3 | fewer than 10^10 | Safely unguessable: moderate protection against offline attacks on a slow hash. |
| 4 | 10^10 or more | Very unguessable: strong protection against offline attacks on a slow hash. |

The score is computed from the exact estimate, before rounding. Some reference points from the test suite:

| Password | Score |
|---|---|
| `password`, `123456`, `qwerty` | 0 |
| `aaaaaaaaaaaaaaaaaaaa`, `abcabcabcabcabc` | 0 |
| `gx7#Lq2!vZ9pRm4w` | 4 |
| `violet-quartz-tundra-mosaic` | 4 |

### Crack times

`CrackTimes` is a `CrackTimeEstimates` with four `CrackTimeEstimate` values. Each one has `GuessesPerSecond`, `Seconds` (that is, `Guesses / GuessesPerSecond`) and `Display`; `ToString()` returns `Display`.

| Property | Scenario | Rate (constant) |
|---|---|---|
| `OnlineThrottled` | Online attack on a service that limits attempts | 100 per hour (`OnlineThrottledRate`) |
| `OnlineUnthrottled` | Online attack on a service that does not limit attempts | 10 per second (`OnlineUnthrottledRate`) |
| `OfflineSlowHash` | Offline attack on a stolen slow hash such as Argon2id, with many cores | 10^4 per second (`OfflineSlowHashRate`) |
| `OfflineFastHash` | Offline attack on a stolen fast unsalted hash such as SHA-1, with GPUs | 10^10 per second (`OfflineFastHashRate`) |

`Display` is one of `less than a second`, a whole number of seconds, minutes, hours, days, months (31 days) or years (12 such months), or `centuries` from 100 years up. Values are rounded to the nearest whole unit: 1.5 seconds is `2 seconds`, 150 seconds is `3 minutes`.

### Warning and suggestions

Feedback follows zxcvbn's rules with its own wording. It is based on the longest pattern in the sequence.

| Pattern | Warning |
|---|---|
| Common password, alone, not reversed or l33t | `This is a top-10 common password.`, `This is a top-100 common password.` or `This is a very common password.` |
| Common password inside a longer password, or reversed or l33t, needing at most 10^4 guesses | `This is similar to a commonly used password.` |
| English word on its own | `A word by itself is easy to guess.` |
| User input | `Words related to you or this service are easy to guess.` |
| Straight keyboard row | `Straight rows of keys are easy to guess.` |
| Keyboard pattern with turns | `Short keyboard patterns are easy to guess.` |
| Repeated character | `Repeated characters like "aaa" are easy to guess.` |
| Repeated block | `Repeats like "abcabcabc" are only slightly harder to guess than "abc".` |
| Sequence | `Sequences like "abc" or "6543" are easy to guess.` |
| Year | `Recent years are easy to guess.` |
| Date | `Dates are often easy to guess.` |

Weak passwords get `Add another word or two. Uncommon words are better.` as the first suggestion, followed by advice for the pattern, such as `Capitalization doesn't help very much.`, `All-uppercase is almost as easy to guess as all-lowercase.`, `Reversed words aren't much harder to guess.`, `Predictable substitutions like '@' instead of 'a' don't help very much.`, `Avoid sequences.` or `Avoid recent years.`. An empty password gets `Use a few unrelated words; avoid common phrases.` and `No need for symbols, digits or upper-case letters.`.

None of this text contains any part of the password.

### Patterns

Each item of `Sequence` is a `PatternMatch`:

| Member | Meaning |
|---|---|
| `Pattern` | The `PatternKind`. |
| `StartIndex` | Start of the pattern, in UTF-16 units of the NFKC-normalized password. |
| `Length` | Length in UTF-16 units. |
| `Dictionary` | For a dictionary word, the list it came from; otherwise `DictionaryKind.None`. |
| `IsReversed` | True for a dictionary word written backwards. |
| `IsL33t` | True for a dictionary word with l33t substitutions. |
| `ToString()` | The kind and range, such as `Dictionary [0..8)`. |

Patterns carry no guess counts of their own.

## Handling the estimate safely

No password text is stored in the estimate, but the estimate is derived from the password. `Sequence` gives the position and length of every word and pattern, and the guess count of a weak password reflects the rank of the list entry it matched. Together they can identify list entries.

- Show the estimate to the user who typed the password.
- Do not log it, serialize it to telemetry or store it.
- `ToString()`, `Score`, `Warning` and `Suggestions` are safe to log.

To limit what leaks, `Guesses`, `GuessesLog10` and `CrackTimes` are rounded down to a tenth of a decade, and the exact figures are never exposed.

## Long passwords

Only the first 100 UTF-16 units of the normalized password are analyzed (`PasswordStrengthEstimator.MaxAnalyzedLength`). This bounds the cost of a call. The cut never splits a surrogate pair. For a longer password `IsTruncated` is true, and the estimate is that of the first 100 units alone: the rest adds nothing. Treat it as approximate, not as a bound either way.

`PasswordPolicy`'s own rules (length, blocklist, context words, repetitive and sequential) look at the whole password. Only input longer than `4 * MaxLength` UTF-16 units is cut first, and it is rejected as too long anyway.

## Building a strength meter

A meter usually calls the server as the user types. Return only the parts meant for display:

```csharp title="Program.cs"
using Masterly.Hash;
using Masterly.Hash.Policy;

app.MapPost("/api/v1/password-strength", (StrengthRequest request) =>
{
    StrengthEstimate estimate = PasswordStrengthEstimator.Estimate(request.Password, new[] { request.UserName });

    StrengthResponse response = new StrengthResponse(
        estimate.Score,
        estimate.Warning,
        estimate.Suggestions,
        estimate.CrackTimes.OfflineSlowHash.Display);
    return Results.Ok(response);
})
.RequireRateLimiting("password-strength");

public sealed record StrengthRequest(string UserName, SensitiveString Password);

public sealed record StrengthResponse(int Score, string Warning, IReadOnlyList<string> Suggestions, string OfflineCrackTime);
```

- Serve it over HTTPS only, and keep request bodies out of access logs.
- Rate-limit it (the sample assumes a rate limiter policy named `password-strength`), because it answers questions about arbitrary passwords.
- The meter is guidance. Enforce the minimum with `PasswordPolicy` when the password is submitted, not with the meter.

## When to use it, and when not

Use the estimator for feedback while the user chooses a password, and through `PasswordPolicyOptions.MinimumScore` to reject guessable passwords that pass the other rules, such as `iloveyou12345678`.

Keep its limits in mind:

- It is a heuristic model of a guessing attacker, not a guarantee. A low score proves a password is weak; a high score does not prove it is strong.
- Its word lists are English, and its keyboard model is US QWERTY plus a numeric keypad. Words from other languages and other layouts count as bruteforce characters, which can overrate them.
- It knows nothing about passwords leaked in breaches beyond the embedded top 10,000. Combine it with [breach checking](./breach-checking.md).
- The real defence against offline attacks is the slow hash. Keep hashing with Masterly.Hash whatever the score.

## See also

- [Password policy](./password-policy.md): the rules that use the score.
- [Breach checking](./breach-checking.md): reject passwords known from breaches.
- [Command-line tool](./command-line-tool.md): `masterly-hash policy` prints the score and the four crack times.
- [Estimator source](https://github.com/a7mdfre7at/Masterly.Hash/blob/master/src/Masterly.Hash.Policy/Strength/PasswordStrengthEstimator.cs) and [third-party notices](https://github.com/a7mdfre7at/Masterly.Hash/blob/master/src/Masterly.Hash.Policy/THIRD-PARTY-NOTICES.txt).
