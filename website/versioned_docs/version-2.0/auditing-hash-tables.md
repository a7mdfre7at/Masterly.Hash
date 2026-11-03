---
title: Auditing Hash Tables
sidebar_label: Auditing Hash Tables
description: Survey a password column with HashAudit to see which formats and profiles it holds, how many hashes are weak, wrapped or unknown, and how many rows share a hash.
---

Before you migrate a password table, and while you do, you need to know what is in it. `HashAudit.Audit` reads a column of stored hashes in one streaming pass and reports counts by format and profile, how many hashes are weak, how many a login would replace, how many are onion-wrapped and how many rows share a value. It never verifies anything and needs no passwords. It lives in the `Masterly.Hash.Legacy` package.

```csharp title="AuditPasswords.cs"
using System;
using System.IO;
using Masterly.Hash;
using Masterly.Hash.Legacy;

PasswordHasher hasher = new PasswordHasher(new PasswordHasherOptions().AddAllLegacyFormats());

HashAuditReport report = HashAudit.Audit(hasher, File.ReadLines("hashes.txt"));
Console.WriteLine(report.ToMarkdown());
```

## Running an audit

`HashAudit.Audit(IPasswordHasher hasher, IEnumerable<string?> storedHashes)` classifies each value with `hasher.Inspect`. The hasher decides what counts as recognized, so build it **exactly like the hasher that verifies logins**:

- the same legacy formats, with the same caps (see [Legacy Hash Formats](./legacy-formats.md)),
- the same default profile, plus every custom profile still present in the table in `AdditionalProfiles`,
- the same pepper, so peppered `$mh$` hashes are recognized. `Inspect` only asks the pepper whether a key id is known (`IsKnownKey`); it never applies the pepper.

If the application already builds its hasher through dependency injection, resolve `IPasswordHasher` and pass that. `Inspect` does no hashing and takes no concurrency slot, so auditing with the production hasher does not slow logins.

**From a database.** Any `IEnumerable<string?>` works, including an Entity Framework Core query. It is enumerated once, row by row:

```csharp title="AuditJob.cs"
// db is your DbContext; hasher is the application's IPasswordHasher
HashAuditReport report = HashAudit.Audit(hasher, db.Users.Select(u => u.PasswordHash));
logger.LogInformation(
    "Password audit: {Total} hashes, {Weak} weak, {Unknown} unknown, {NeedsRehash} need rehash",
    report.Total, report.Weak, report.Unknown, report.NeedsRehash);
```

`Audit` is synchronous and takes no `CancellationToken`. On a large table, run it from a background job or a maintenance script, not from a request.

**Behaviour you can rely on:**

- **Single pass.** The input is enumerated exactly once and not buffered.
- **Never throws on a bad row.** `null`, empty strings, garbage, and values that make a custom hasher's `Inspect` throw are all counted as unknown. Only a `null` hasher or a `null` sequence throws (`ArgumentNullException`).
- **Bounded memory.** Duplicates are detected from a 128-bit SHA-256 fingerprint of each non-empty value, so memory grows by about 40 bytes per distinct hash (about 400 MB for 10 million distinct rows). The stored strings themselves are not kept.
- **Nothing secret in the output.** The report never echoes stored hashes.

## The report

`HashAuditReport` is immutable.

| Property | Meaning |
|---|---|
| `Total` | Values audited, including `null` and empty ones. |
| `Recognized` | Values the hasher can verify. |
| `Unknown` | Values it cannot: unknown formats, malformed hashes, hashes over a format's cost cap, unregistered profiles or pepper keys, wrapped hashes whose format is not registered, `null` and empty values. `Recognized + Unknown = Total`. |
| `NeedsRehash` | Recognized values that a successful login would replace: legacy formats, wrapped hashes, outdated profiles and outdated pepper keys. |
| `Weak` | Recognized values in a weak format (rules below). Candidates for [onion wrapping](./onion-wrapping.md). Wrapped hashes are never weak. |
| `Wrapped` | Onion-wrapped `$mh$` hashes. Protected, but still upgraded on the next login. |
| `Duplicates` | Non-empty values identical to an earlier value (exact, case-sensitive match). |
| `ByFormat` | Counts by `HashInfo.Format`: `mh` for Masterly hashes (including malformed ones), a legacy format id, or `unknown`. The counts add up to `Total`. |
| `ByProfile` | `$mh$` hashes counted by profile id, including ids not registered with the hasher. |
| `WeakByFormat` | The `Weak` values counted by format id. |
| `RecognizedPercent`, `UnknownPercent`, `NeedsRehashPercent`, `WeakPercent`, `WrappedPercent`, `DuplicatePercent` | Each count as a percentage (0 to 100) of `Total`. |
| `Percent(long count)` | Any count as a percentage of `Total`; 0 for an empty audit. |

`ToMarkdown()` renders a totals table, then counts by format and, when there are `$mh$` hashes, by profile. Rows are sorted by count, then by name, and numbers use the invariant culture. For a table holding two copies of an MD5 digest, one cost-5 bcrypt hash and one garbage value:

```markdown title="Output of report.ToMarkdown()"
## Password hash audit

| Metric | Count | Share |
|---|---:|---:|
| Total | 4 | 100.0% |
| Recognized | 3 | 75.0% |
| Unknown | 1 | 25.0% |
| Needs rehash | 3 | 75.0% |
| Weak | 3 | 75.0% |
| Onion-wrapped | 0 | 0.0% |
| Duplicates | 1 | 25.0% |

### By format

| Format | Count | Share | Weak |
|---|---:|---:|---:|
| md5 | 2 | 50.0% | 2 |
| bcrypt | 1 | 25.0% | 1 |
| unknown | 1 | 25.0% | 0 |
```

`ToString()` gives a one-line summary for logs: `4 hashes: 3 recognized, 1 unknown, 3 need rehash, 3 weak, 1 duplicates`.

## What counts as weak

`HashAudit.IsWeak(string formatId, string storedHash)` applies these rules. It is public, so you can use the same rules row by row.

| Format id | Weak when |
|---|---|
| `md5`, `sha1`, `sha256`, `sha512` | Always (unsalted digests) |
| `v1` | Always (Masterly.Hash 1.x: one salted SHA-2 pass) |
| `phpass` | Always (iterated MD5) |
| `aspnet-identity-v2` | Always (PBKDF2-HMAC-SHA1, 1000 iterations) |
| `bcrypt`, `wordpress-bcrypt` | Cost below `HashAudit.WeakBCryptCostBelow` = 10 |
| `django-pbkdf2`, `aspnet-identity-v3` | Fewer than `HashAudit.WeakPbkdf2IterationsBelow` = 100,000 iterations |
| `argon2-phc`, `mh` and anything else | Never |

The cost and iteration checks read the value from the string and ignore the format's verification cap: `IsWeak("aspnet-identity-v3", hash)` is `false` for an Identity v3 hash with 50,000,000 iterations, which is not weak, merely unverifiable. In an audit, though, `aspnet-identity-v3` refuses that hash, so with the default `v1` format registered `Inspect` reports it as `v1` and it is counted as weak (see [Caveats](#caveats)). A value the rule cannot parse is not weak. `IsWeak` throws `ArgumentNullException` for a `null` argument.

To wrap only weak rows, combine `Inspect`, `IsWeak` and `TryWrap`:

```csharp title="WrapWeakOnly.cs"
HashInfo info = hasher.Inspect(storedHash);
bool weak = info.IsRecognized && !info.IsNative && HashAudit.IsWeak(info.Format, storedHash);
if (weak && hasher.TryWrap(storedHash, out string wrapped))
{
    // Store wrapped in place of storedHash.
}
```

## Reading the numbers

**`Unknown` is above zero.** Find out why before you migrate anything; these users cannot log in today. Common causes:

- a format you have not registered (check `ByFormat["unknown"]` against a sample of rows),
- a hash above a format's cost cap (raise the cap, see [Cost caps at a glance](./legacy-formats.md#cost-caps-at-a-glance)),
- an unregistered profile (listed in `ByProfile`) or a pepper key the hasher does not know,
- truncated values from a column that was once too short, or placeholder values such as `!` or `*` for disabled accounts.

**`Weak` is above zero.** Onion-wrap those rows now rather than waiting for logins. `WeakByFormat` tells you which formats to register on the wrapping hasher.

**`Duplicates` is above zero.** Salted hashes practically never repeat, so duplicates usually mean unsalted digests (same password, same hash) or copied rows. A high `DuplicatePercent` among MD5 or SHA-1 rows shows which passwords many users share, and those fall first to a precomputed table.

**`NeedsRehash` is your migration progress.** It shrinks as users log in. The part that stops shrinking is dormant accounts; wrap them.

**`Wrapped` is above zero.** Keep every wrapped format registered on the login hasher until this reaches zero.

Run the audit on a schedule and chart the counts. Together with the `format` tag on the `masterly.hash.verifications` metric (see [Observability](./observability.md)), it shows when a legacy format can be retired.

## Caveats

- **Recognition is syntactic.** `Inspect` checks shape and caps, not whether the hash is correct. A wrapped hash whose `wp` parameter the format rejects (for example a cost above its cap) counts as recognized but fails at login with `MalformedHash`.
- **Overlaps with 1.x.** The built-in `v1` format claims any long canonical base64 string. An ASP.NET Identity v3 hash that `aspnet-identity-v3` refuses (over its work cap, or an odd salt or subkey length) is counted as a recognized, weak `v1` hash. Identity hashes registered after `v1` are counted as `v1` too. See [Format order and overlaps](./legacy-formats.md#format-order-and-overlaps).
- **Peppered hashes need the pepper's key ids.** Without a pepper that knows the key, every peppered `$mh$` hash is unknown.
- **The hasher's configuration is the truth.** An audit with a different hasher from the one that verifies logins answers a different question.

## From the command line

The `masterly-hash audit` command streams a file (one hash per line) or one column of a CSV into `HashAudit`, with every legacy format registered, and prints the report as Markdown or JSON. The tool never holds a pepper key; pass `--pepper-key-ids` so peppered hashes are classified:

```bash
masterly-hash audit hashes.txt
masterly-hash audit users.csv --column 3 --header --format json --pepper-key-ids k2,k1
```

See [Command-Line Tool](./command-line-tool.md).

## See also

- [Legacy Hash Formats](./legacy-formats.md): the formats the audit can recognize.
- [Onion Wrapping](./onion-wrapping.md): protect the weak rows the audit finds.
- [Upgrade on Login](./upgrade-on-login.md): what `NeedsRehash` means for a user.
- [API Reference](./api-reference.md): `HashAudit`, `HashAuditReport` and `HashInfo`.
