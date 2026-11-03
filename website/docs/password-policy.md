---
title: Password Policy
sidebar_label: "Password Policy"
description: Check new passwords against NIST SP 800-63B rev. 4 rules with PasswordPolicy before you hash them.
---

`Masterly.Hash.Policy` decides whether a new password is acceptable. Run it at sign-up, password change and password reset, before you hash the password. Its rules follow NIST SP 800-63B rev. 4: a minimum length in Unicode code points, a blocklist, context words, repetitive and sequential patterns, a strength score and an optional breached-password lookup. It has no composition rules and no expiry.

```bash
dotnet add package Masterly.Hash.Policy
```

The package targets `net8.0`, depends only on `Masterly.Hash` and is AOT-compatible.

## Quick start

**1. Create one policy and reuse it.** `PasswordPolicy` is thread-safe. The options are copied when it is created, so later changes to the options object have no effect.

```csharp title="Program.cs"
using Masterly.Hash.Policy;

PasswordPolicyOptions options = new PasswordPolicyOptions();
options.ContextWords.Add("Contoso");          // your service and company name

builder.Services.AddSingleton<IPasswordPolicy>(new PasswordPolicy(options));
```

**2. Evaluate the candidate with what you know about the account.**

```csharp title="SignUpHandler.cs"
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Masterly.Hash;
using Masterly.Hash.Policy;

namespace Contoso.Accounts;

public sealed class SignUpHandler
{
    private readonly IPasswordPolicy _policy;
    private readonly IPasswordHasher _hasher;

    public SignUpHandler(IPasswordPolicy policy, IPasswordHasher hasher)
    {
        _policy = policy;
        _hasher = hasher;
    }

    public async Task<IReadOnlyList<PasswordViolation>> HandleAsync(
        string userName, string email, SensitiveString password, CancellationToken cancellationToken)
    {
        PasswordContext context = new PasswordContext
        {
            UserName = userName,
            Email = email,
        };

        PasswordPolicyResult result = await _policy.EvaluateAsync(password, context, cancellationToken);
        if (!result.IsAcceptable)
        {
            return result.Violations;
        }

        string passwordHash = await _hasher.HashAsync(password, cancellationToken);
        // save the account with passwordHash
        return Array.Empty<PasswordViolation>();
    }
}
```

**3. Show the violations and suggestions to the user.** Every `PasswordViolation.Message` is an English sentence that never contains the password. `result.Suggestions` holds advice for a better password.

`PasswordPolicy.Default` is a ready-made instance with the default options and no breach lookup.

## How the rules map to NIST SP 800-63B rev. 4

| NIST requirement (section 3.1.1.2) | What `PasswordPolicy` does | Option |
|---|---|---|
| Minimum 15 characters when the password is the only factor, 8 when it is part of multi-factor authentication | Default minimum is 15 code points. You can lower it to 8, not further. | `MinLength` |
| Permit at least 64 characters | Default maximum is 128. A maximum below 64 is refused. | `MaxLength` |
| Accept all printing characters, including spaces and Unicode | Every character is allowed: spaces, emoji, any script. | none |
| Count each Unicode code point as one character, after normalization | Length is counted in code points after NFKC normalization. | none |
| Do not impose composition rules (mixtures of character types) | There are no "upper case, digit, symbol" rules. | none |
| Do not require periodic changes; force a change on evidence of compromise | There is no expiry. A breach lookup is available as evidence of compromise. | `IBreachedPasswordChecker` |
| Compare against a blocklist of commonly used, expected or compromised values | The 10,000 most common passwords, your own list, context words, repetitive and sequential patterns, and breached passwords. | `BlockCommonPasswords`, `BlockedPasswords`, `CheckContextWords`, `RejectRepetitiveOrSequential` |
| Offer guidance such as a strength meter | A 0-4 score, warning and suggestions from the strength estimator. | `MinimumScore` |

Some NIST requirements are outside a policy object: rate limiting failed sign-in attempts, never truncating the password and storing it with a slow salted hash. Masterly.Hash covers those elsewhere. See [Limits and concurrency](./limits-and-concurrency.md), [Attack detection](./attack-detection.md) and [Hashing and verifying](./hashing-and-verifying.md).

## The rules

Each rule adds a `PasswordViolation` when it fails. `IsAcceptable` is true only when there are none. Every rule runs, so a user sees all problems at once rather than one per attempt.

### Length

The password is normalized with NFKC, as the hasher does, and its length is counted in Unicode code points. This is the number `PasswordPolicyResult.Length` reports.

- 15 emoji are 30 UTF-16 units but 15 code points, so they meet the default minimum.
- `e` followed by a combining acute accent composes to one code point, `é`.
- The ligature `ﬀ` (U+FB00) decomposes to `ff`, two code points.
- The Arabic ligature U+FDFA expands to 18 code points, so one typed character can meet the minimum of 15.
- A lone surrogate counts as one code point. Text that cannot be normalized (invalid UTF-16) is measured as given.

`TooShort` covers the empty password. `TooLong` is raised above `MaxLength`.

To bound the work done on attacker-sized input, a password longer than `4 * MaxLength` UTF-16 units is cut to that length before normalization. Its reported length is the code point count of the whole original input, so it is still rejected as too long. A test evaluates a 1,000,000-character password in under 5 seconds.

:::warning

Keep `4 * MaxLength` within the hasher's `PasswordHasherOptions.MaxPasswordBytes` (default 1024). A code point takes up to 4 bytes in UTF-8. With the default `MaxLength` of 128 the worst case is 512 bytes. If you raise `MaxLength` above 256 without raising `MaxPasswordBytes`, a long non-Latin password can pass the policy and then be refused by the hasher.

:::

### Common passwords

The password is compared with the embedded list of the 10,000 most common passwords (SecLists `10k-most-common.txt`, MIT) and with your `BlockedPasswords`. The comparison is against the whole password:

- It is case-insensitive: `PASSWORD` and `PassWord` are blocked.
- It is l33t-insensitive: `p@ssw0rd` and `P4$$W0RD` are blocked. The substitutions are listed in [Strength estimation](./strength-estimation.md#l33t-substitutions).
- A password that merely contains a common password, such as `iloveyou12345678`, is not a `CommonPassword` violation. The strength score deals with it (see [Strength score](#strength-score)).

```csharp title="Program.cs"
using Masterly.Hash.Policy;

PasswordPolicyOptions options = new PasswordPolicyOptions();
options.BlockedPasswords.Add("ContosoSpring2026!");   // also blocks "C0NT0S0SPR1NG2026!"
```

Each entry of `BlockedPasswords` is cut to `2 * MaxLength` UTF-16 units. Empty entries are ignored. Setting `BlockCommonPasswords = false` turns off the embedded list but not `BlockedPasswords`.

### Context words

NIST asks verifiers to reject passwords built from "context-specific words, such as the name of the service, the username, and derivatives thereof". The policy collects words from `PasswordContext` and from `PasswordPolicyOptions.ContextWords`, and rejects a password that contains any of them.

| Source | Words checked |
|---|---|
| `PasswordContext.UserName` | The whole value, the parts joined together, and each part |
| `PasswordContext.DisplayName` | Same; each name part is checked |
| `PasswordContext.ApplicationName` | Same |
| `PasswordContext.AdditionalWords` | Same, for each entry |
| `PasswordContext.Email` | The local part like a user name. The domain labels one by one, without the last label and without the whole domain. A single-label domain such as `localhost` is kept. |
| `PasswordPolicyOptions.ContextWords` | Same as `UserName`, for each entry |

Values are trimmed, cut to 256 UTF-16 units, normalized with NFKC and lower-cased. They are split into parts on every character that is not a letter, digit or combining mark; characters outside the Basic Multilingual Plane, such as emoji, count as letters. For example:

- `UserName = "maggie_t"` gives `maggie_t`, `maggiet`, `maggie` and `t`.
- `Email = "mthatcher@fabrikam.co.uk"` gives `mthatcher`, `fabrikam` and `co` (the last label, `uk`, is dropped).
- `DisplayName = "Margaret Thatcher"` gives `margaret thatcher`, `margaretthatcher`, `margaret` and `thatcher`.
- An email value without `@` is treated as a plain word.

The match is a substring search that ignores case, reversal and l33t substitutions on both sides. With `UserName = "JohnSmith"`, all of `JOHNSMITH-likes-tea-a-lot`, `J0HN5M17H-likes-tea-a-lot` and `htimsnhoj-likes-tea-a-lot` are rejected. With `UserName = "j0hnd03"`, the plain `johndoe` is rejected too.

Words shorter than `MinContextWordLength` code points (default 4) are not violations by themselves, so a user called `Al` can still use `alpine`. The last label of a multi-label email domain (`uk`, `com`, `info`) is not checked at all. Short words still lower the strength estimate. `CheckContextWords = false` turns the violation off, but the words are still passed to the estimator and still lower the score.

:::tip

Put the service and company name in `PasswordPolicyOptions.ContextWords` once. Use `PasswordContext` for what is specific to the account.

:::

### Repetitive or sequential

A password is rejected when every character belongs to one of these patterns:

- a run of a weak repeated unit, including a partial last period: `aaaaaa`, `aabaabaab`, `abcabcabcabcabcabc`;
- a sequence of at least three characters with a constant step of 1 to 5, up or down: `abcdefghijklmnop`, `zyxwvutsrqponmlk`, `9876543210987654`;
- a keyboard run of at least three keys on a US QWERTY keyboard or a numeric keypad: `qwertyuiopasdfgh`, `1qaz2wsx3edc4rfv`.

Patterns can be mixed: `1234abcd1234abcd` and `aaaabbbbccccdddd` are rejected. A repeated unit counts as weak only if it is at most three characters long, or is itself made only of repeats, sequences and keyboard runs. So a strong token typed twice, such as `Xk9#mQ2$vL7!Xk9#mQ2$vL7!`, is not called repetitive; the strength score judges it instead. A password that mixes one of these patterns with other text, such as `abcdefg-orbit-cactus`, is not rejected by this rule.

The check covers the whole password at any length up to `MaxLength`. It is skipped for a password already rejected as too long. Turn it off with `RejectRepetitiveOrSequential = false`.

### Strength score

The policy runs [the strength estimator](./strength-estimation.md) on the normalized password, with every context word as a user input. When the score is below `MinimumScore` (default 3, at least 10^8 estimated guesses) it adds `TooWeak`. The message is "The password is too easy to guess." followed by the estimator's warning, if any. The estimator's suggestions are added to `result.Suggestions`.

Set `MinimumScore = 0` to report the score without enforcing it. The estimator analyzes only the first 100 UTF-16 units of the password; the other rules always look at the whole password.

### Breached passwords

When you pass an `IBreachedPasswordChecker` to the constructor, `EvaluateAsync` also looks the password up in a corpus of breached passwords and adds `Breached` when it is found at least `MinimumBreachOccurrences` times (default 1). `Evaluate` never calls the checker. An unavailable corpus is not a violation. [Breach checking](./breach-checking.md) covers the lookup, the Have I Been Pwned client and how to fail closed.

## Options

`PasswordPolicyOptions` holds every setting. The defaults follow NIST for a password used as the only authentication factor.

| Option | Default | Allowed values | Purpose |
|---|---|---|---|
| `MinLength` | 15 | 8 to `MaxLength` | Minimum length in code points after NFKC. Use 8 only when the password is one factor of MFA. |
| `MaxLength` | 128 | 64 to 4096 | Maximum length in code points. |
| `BlockCommonPasswords` | `true` | | Reject the 10,000 most common passwords. |
| `BlockedPasswords` | empty | | Extra passwords to reject outright, case- and l33t-insensitive. |
| `MinimumScore` | 3 | 0 to 4 | Minimum `StrengthEstimate.Score`. 0 reports without enforcing. |
| `CheckContextWords` | `true` | | Reject passwords containing a context word. |
| `ContextWords` | empty | | Words every password is checked against, typically the service and company name. |
| `MinContextWordLength` | 4 | 1 to 64 | Shorter context words are not violations by themselves. |
| `RejectRepetitiveOrSequential` | `true` | | Reject passwords made only of repeats, sequences and keyboard runs. |
| `MinimumBreachOccurrences` | 1 | at least 1 | A breached password is rejected when it appears at least this many times. |
| `ReferenceYear` | `null` | four digits, 1000 to 9999 | Year that years and dates are scored against. `null` is the current UTC year. Set it for reproducible tests. |

The limits are also public constants: `PasswordPolicyOptions.MinimumAllowedMinLength` (8), `MinimumAllowedMaxLength` (64) and `MaximumAllowedMaxLength` (4096).

The constructor validates the options and throws:

| Exception | When |
|---|---|
| `ArgumentNullException` | `options` is `null`. |
| `ArgumentOutOfRangeException` | `MaxLength` is outside 64-4096; `MinLength` is below 8 or above `MaxLength`; `MinimumScore` is outside 0-4; `MinContextWordLength` is outside 1-64; `MinimumBreachOccurrences` is below 1; `ReferenceYear` does not have four digits. |

The `Evaluate` and `EvaluateAsync` overloads throw `ArgumentNullException` for a `null` password.

## The API

`IPasswordPolicy` is the interface; `PasswordPolicy` is its only implementation. Inject the interface so you can replace it in tests.

| Member | Notes |
|---|---|
| `Evaluate(string password, PasswordContext? context = null)` | Every local rule. Never calls the breach checker. |
| `Evaluate(SensitiveString password, PasswordContext? context = null)` | Same, for a password kept in a `SensitiveString`. |
| `EvaluateAsync(string password, PasswordContext? context = null, CancellationToken cancellationToken = default)` | Every rule, plus the breach lookup if a checker is configured. Returns `ValueTask<PasswordPolicyResult>`. |
| `EvaluateAsync(SensitiveString password, PasswordContext? context = null, CancellationToken cancellationToken = default)` | Same, for a `SensitiveString`. |

Constructors: `PasswordPolicy()`, `PasswordPolicy(PasswordPolicyOptions options)` and `PasswordPolicy(PasswordPolicyOptions options, IBreachedPasswordChecker? breachedPasswordChecker)`.

`EvaluateAsync` throws `OperationCanceledException` when the token is already cancelled, or when it is cancelled during the breach lookup. Without a checker, or when the password is rejected as too short or too long, it completes synchronously and makes no lookup.

### PasswordContext

Every property is optional. Leave out what you do not have.

| Property | Type | Meaning |
|---|---|---|
| `UserName` | `string?` | The account's user name or login. |
| `Email` | `string?` | The account's email address. The local part and the domain labels are checked separately. |
| `DisplayName` | `string?` | The user's display or full name. Each name part is checked. |
| `ApplicationName` | `string?` | The application or site name. Usually better set once in `PasswordPolicyOptions.ContextWords`. |
| `AdditionalWords` | `IList<string>` | Other words specific to this user, such as a company name, city or pet's name. |

### PasswordPolicyResult

| Member | Meaning |
|---|---|
| `IsAcceptable` | True when `Violations` is empty. |
| `Violations` | Every rule the password breaks, sorted by `PasswordViolationCode`. Empty when acceptable. |
| `HasViolation(PasswordViolationCode code)` | True if a violation with this code is present. |
| `Suggestions` | Advice for a better password, without duplicates. May be non-empty for an acceptable password. |
| `Score` | The strength score 0-4. |
| `Length` | Length in code points after NFKC; the number the length rules use. |
| `StrengthEstimate` | The full [strength estimate](./strength-estimation.md). Do not log or serialize it. |
| `BreachCheck` | The `BreachCheckResult`, or `null` when no lookup was made. |
| `BreachCheckUnavailable` | True when a lookup was attempted but the corpus could not be consulted. |
| `ToString()` | A summary such as `Rejected (score 0, 4 violation(s))`. |

### Violation codes

`PasswordViolation` has a `Code` and a `Message`. Its constructor `PasswordViolation(PasswordViolationCode code, string message)` throws `ArgumentNullException` for a `null` message. `ToString()` returns `Code: Message`.

| Code | Message | Suggestion added |
|---|---|---|
| `TooShort` | The password must be at least {MinLength} characters long. | Use at least {MinLength} characters. A few unrelated words make a long password that is easy to remember. |
| `TooLong` | The password must be at most {MaxLength} characters long. | Use at most {MaxLength} characters. |
| `CommonPassword` | This is one of the most commonly used passwords. | Avoid common passwords and simple variations of them. |
| `ContainsContextWord` | The password contains your user name, email address, name or the name of this service. | Avoid your name, user name, email address and the name of this service. |
| `RepetitiveOrSequential` | The password consists only of repeated characters, sequences or keyboard patterns. | Avoid repeated characters, sequences like "abc" or "1234", and keyboard patterns like "qwerty". |
| `TooWeak` | The password is too easy to guess. (plus the estimator's warning) | The estimator's suggestions |
| `Breached` | This password has appeared in a data breach and must not be used. | Choose a password you have not used anywhere else. |

Violations are always reported in this order, whatever order the rules found them in. For example, `password` with `UserName = "password"` gives `TooShort`, `CommonPassword`, `ContainsContextWord` and `TooWeak`.

:::tip

The messages are English. To localize them, map `PasswordViolation.Code` to your own resource strings and ignore `Message`.

:::

## Returning violations from an API

Return the violations as an RFC 7807 validation problem. The password itself never appears in the response.

```csharp title="Program.cs"
using Masterly.Hash;
using Masterly.Hash.Policy;

app.MapPost("/api/v1/accounts", async (
    SignUpRequest request,
    IPasswordPolicy policy,
    IPasswordHasher hasher,
    CancellationToken cancellationToken) =>
{
    PasswordContext context = new PasswordContext { UserName = request.UserName, Email = request.Email };
    PasswordPolicyResult result = await policy.EvaluateAsync(request.Password, context, cancellationToken);

    if (!result.IsAcceptable)
    {
        Dictionary<string, string[]> errors = new Dictionary<string, string[]>
        {
            ["password"] = result.Violations.Select(violation => violation.Message).ToArray(),
        };
        return Results.ValidationProblem(errors);
    }

    string passwordHash = await hasher.HashAsync(request.Password, cancellationToken);
    // save the account with passwordHash
    return Results.Created($"/api/v1/accounts/{request.UserName}", null);
});

public sealed record SignUpRequest(string UserName, string Email, SensitiveString Password);
```

`SensitiveString` reads the real value from JSON but writes `***` and shows `***` in `ToString()` and the debugger, so the password cannot reach a log by accident. See [Hashing and verifying](./hashing-and-verifying.md).

## Using the policy with ASP.NET Core Identity

Identity calls every registered `IPasswordValidator<TUser>` from `CreateAsync`, `AddPasswordAsync`, `ChangePasswordAsync` and `ResetPasswordAsync`. A small adapter lets it use the policy:

```csharp title="PolicyPasswordValidator.cs"
using System;
using System.Linq;
using System.Threading.Tasks;
using Masterly.Hash.Policy;
using Microsoft.AspNetCore.Identity;

namespace Contoso.Accounts;

public sealed class PolicyPasswordValidator<TUser> : IPasswordValidator<TUser>
    where TUser : class
{
    private readonly IPasswordPolicy _policy;

    public PolicyPasswordValidator(IPasswordPolicy policy)
    {
        _policy = policy;
    }

    public async Task<IdentityResult> ValidateAsync(UserManager<TUser> manager, TUser user, string? password)
    {
        ArgumentNullException.ThrowIfNull(manager);
        ArgumentNullException.ThrowIfNull(password);

        PasswordContext context = new PasswordContext
        {
            UserName = await manager.GetUserNameAsync(user),
            Email = await manager.GetEmailAsync(user),
        };

        PasswordPolicyResult result = await _policy.EvaluateAsync(password, context);
        if (result.IsAcceptable)
        {
            return IdentityResult.Success;
        }

        IdentityError[] errors = result.Violations
            .Select(violation => new IdentityError { Code = $"Password{violation.Code}", Description = violation.Message })
            .ToArray();
        return IdentityResult.Failed(errors);
    }
}
```

Identity's built-in validator imposes composition rules by default. Turn them off, because NIST says verifiers must not impose them, and let the policy measure length:

```csharp title="Program.cs"
builder.Services
    .AddIdentityCore<ApplicationUser>(options =>
    {
        options.Password.RequireDigit = false;
        options.Password.RequireLowercase = false;
        options.Password.RequireUppercase = false;
        options.Password.RequireNonAlphanumeric = false;
        options.Password.RequiredUniqueChars = 1;
        options.Password.RequiredLength = 1;      // the policy counts code points after NFKC
    })
    .AddMasterlyPasswordHasher()
    .AddPasswordValidator<PolicyPasswordValidator<ApplicationUser>>();
```

`IPasswordValidator<TUser>` has no cancellation token, so the adapter cannot cancel a breach lookup; the lookup's own timeout bounds it. See [ASP.NET Core Identity](./aspnetcore-identity.md) for the hasher side.

## Logging and privacy

These members never contain any part of the password and are safe to log:

- `PasswordPolicyResult.ToString()`, `IsAcceptable`, `Score`, `Violations` and `Suggestions`;
- `StrengthEstimate.ToString()`, `Score`, `Warning` and `Suggestions`;
- `BreachCheckResult.ToString()`.

`PasswordPolicyResult.StrengthEstimate` as a whole is derived from the password. Its `Sequence` gives the position and length of every word found, and the guess count of a weak password reflects the rank of the list entry it matched. Show it to the user who typed the password, but do not log it, serialize it to telemetry or store it.

```csharp title="SignUpHandler.cs"
_logger.LogInformation("Password policy outcome {Outcome} for sign-up", result.ToString());
```

## When to use it, and when not

Use the policy wherever a user chooses a new password: sign-up, password change, password reset and administrator-set passwords.

Do not run it at sign-in to reject existing users. A user whose password was acceptable when chosen would be locked out by a stricter rule. At sign-in, the useful NIST check is evidence of compromise: you can look the password up with a breach checker and ask the user to change it. See [Breach checking](./breach-checking.md#checking-at-sign-in).

The policy is a heuristic defence against guessing. The real defence against offline attacks on a stolen database is the slow hash, so keep hashing with Masterly.Hash whatever the score.

## From the command line

The `masterly-hash policy` command runs the same checks on a password read from a no-echo prompt, or from standard input with `--stdin`. It accepts `--min-length` (8 to 128, default 15), `--user-name`, `--email`, `--pwned` and `--allow-unavailable`, and prints the score, the four crack times, the violations and the suggestions. It exits with 0 when the password is acceptable, 1 when it is rejected and 2 on an error, including a `--pwned` lookup that was unavailable for an otherwise acceptable password (unless `--allow-unavailable` is given). See [Command-line tool](./command-line-tool.md).

## See also

- [Strength estimation](./strength-estimation.md): how the score, crack times and feedback are computed.
- [Breach checking](./breach-checking.md): Have I Been Pwned and custom breached-password corpora.
- [Hashing and verifying](./hashing-and-verifying.md): what happens to the password after the policy accepts it.
- [ASP.NET Core Identity](./aspnetcore-identity.md): replacing Identity's hasher.
- [PasswordPolicy source](https://github.com/a7mdfre7at/Masterly.Hash/blob/master/src/Masterly.Hash.Policy/PasswordPolicy.cs) and [package README](https://github.com/a7mdfre7at/Masterly.Hash/blob/master/src/Masterly.Hash.Policy/README.md).
