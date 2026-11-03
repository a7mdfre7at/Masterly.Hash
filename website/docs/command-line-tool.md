---
title: "Command-Line Tool"
sidebar_label: "Command-Line Tool"
description: "The masterly-hash .NET tool: hash, verify, inspect, audit and wrap stored hashes, benchmark profiles, check policy and generate keys."
---

`masterly-hash` is a .NET tool for working with Masterly.Hash from a terminal or a script. This page covers installation, how the tool handles secrets, exit codes, and every command with its options.

| Command | What it does |
|---------|--------------|
| [`hash`](#hash) | Hashes a password and prints the stored string. |
| [`verify`](#verify) | Verifies a password against a stored hash in any supported format. |
| [`inspect`](#inspect) | Describes a stored hash without a password. |
| [`audit`](#audit) | Counts formats, profiles, weak hashes and duplicates in a hash export. |
| [`wrap`](#wrap) | Onion-wraps the legacy hashes in one column of a CSV export. |
| [`bench`](#bench) | Times the built-in profiles on this machine and recommends one. |
| [`policy`](#policy) | Checks a password against the NIST SP 800-63B policy, optionally against Have I Been Pwned. |
| [`pepper generate`](#pepper-generate) | Prints a new pepper key. |
| [`apikey generate`](#apikey-generate) | Prints a new API key and its lookup hash. |

## Installing

Install it as a global tool:

```bash
dotnet tool install --global Masterly.Hash.Tool
masterly-hash --help
```

Or pin it per repository with a tool manifest, so everyone on the team runs the same version:

```bash
dotnet new tool-manifest
dotnet tool install Masterly.Hash.Tool
dotnet tool run masterly-hash --help
```

The tool targets .NET 8 and rolls forward to newer major runtimes, so it runs on .NET 8 or later. `masterly-hash --version` prints the tool version, for example `2.0.0`. Every command accepts `--help`.

## How the tool handles secrets

**Passwords are never command-line arguments.** Arguments end up in shell history and process listings, so `hash`, `verify` and `policy` read the password from a no-echo prompt, or from the first line of standard input with `--stdin`. There is no option that takes a password.

- **The prompt** reads keys without echoing them. Backspace deletes a character, Ctrl+U clears the line and Escape cancels. `hash` asks twice and stops with `The passwords do not match.` if the entries differ.
- **`--stdin`** reads the first line of standard input, without its line break. It requires piped or redirected input. If standard input is a terminal the tool refuses, because the terminal would echo the password as you type it. If standard input is redirected and you did not pass `--stdin`, the tool also refuses, because there is no terminal to prompt on.
- **Encoding.** Piped input is decoded as strict UTF-8 whatever the console code page, so a non-ASCII password is hashed as itself. Invalid UTF-8 stops the command with `error: standard input is not valid UTF-8.` The invalid bytes are never printed.
- **Length.** Passwords longer than 4,096 characters are refused, at the prompt and on standard input. The hasher's own limit still applies after that (1,024 UTF-8 bytes after normalization, see [Limits and concurrency](./limits-and-concurrency.md)). Empty passwords are refused.
- **Stray arguments are not echoed.** If you type a password where a command or argument belongs, the error message does not repeat it. For the password commands, unexpected tokens get a generic message, and quoted values in parse errors are replaced with `'***'`. Response files (`@file`) are disabled for the same reason.
- **Clean standard output.** Prompts, progress, warnings and notes go to standard error. Standard output carries only results, so you can pipe it.

```bash
# Read the password from a variable without it appearing in the process list.
printf '%s\n' "$PASSWORD" | masterly-hash hash --stdin
```

:::tip

Put stored hashes in single quotes. They contain `$`, which most shells would otherwise expand: `masterly-hash inspect '$mh$p=2026a$...'`.

:::

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Success. For `verify`, the password matches. For `inspect`, the hash is recognized. For `policy`, the password is acceptable. |
| `1` | A negative answer. For `verify`, the password does not match. For `inspect`, the hash is not recognized. For `policy`, the password is rejected. |
| `2` | An error: bad arguments, unreadable input, a stored hash that cannot be used, or a requested breach check that could not run. |
| `130` | Cancelled with Ctrl+C. |

Errors are printed to standard error as `error: ...`. Argument errors are followed by a line such as `Run 'masterly-hash wrap --help' for usage.`

## hash

Hashes a password and prints the stored string.

```bash
masterly-hash hash                                       # prompts twice
printf '%s\n' "$PASSWORD" | masterly-hash hash --stdin --profile 2026c
```

| Option | Default | Description |
|--------|---------|-------------|
| `--profile 2026a\|2026c\|2026f` | `2026a` | The built-in profile for the new hash. See [Profiles](./profiles.md). |
| `--stdin` | off | Read the password from the first line of standard input instead of prompting. |

The output is one line, for example `$mh$p=2026a$<salt>$<tag>`. The tool never adds a pepper, so the hash is unpeppered. If the password cannot be hashed (for example it exceeds 1,024 UTF-8 bytes), the command fails with `The password cannot be hashed: ...` and exit code 2. The message names the limit, never the password.

## verify

Verifies a password against a stored hash.

```bash
masterly-hash verify '$mh$p=2026a$...'
printf '%s\n' "$PASSWORD" | masterly-hash verify --stdin '$2b$10$...'
```

| Argument or option | Description |
|--------------------|-------------|
| `storedHash` | The stored hash: a Masterly hash or any supported legacy format. Quote it. |
| `--stdin` | Read the password from standard input instead of prompting. |

The tool's hasher registers every legacy format from `Masterly.Hash.Legacy` (bcrypt, WordPress bcrypt, ASP.NET Core Identity v2 and v3, Django PBKDF2, phpass, unsalted digests, external Argon2 PHC strings and Masterly.Hash 1.x). The output looks like this:

```text
Status:         SuccessRehashNeeded
Match:          yes
Rehash reason:  LegacyFormat
Rehash:         $mh$p=2026a$...
```

- `Status` is `Success`, `SuccessRehashNeeded` or `Failed`.
- `Failure reason` appears when the status is `Failed`, for example `Mismatch`, `UnknownFormat`, `MalformedHash`, `UnknownProfile` or `UnknownPepperKey`.
- `Rehash reason` and `Rehash` appear when the hash is outdated. `Rehash` is the replacement hash with the `2026a` profile, ready to store.

The exit code is 0 for a match (with or without a rehash), 1 when the password is wrong (`Mismatch`) and 2 for every other failure: a hash in an unknown format, a malformed hash, an unregistered profile, an unknown pepper key, or an empty, too long or invalid password.

:::note

`verify` cannot check peppered hashes (`$mh$p=...,k=ID$...`), because the tool never holds a pepper key. They fail with `UnknownPepperKey` and exit code 2. Verify those with the library and your pepper configured.

:::

## inspect

Describes a stored hash without needing the password.

```bash
masterly-hash inspect '$mh$p=2026a$...'
masterly-hash inspect '$mh$p=2026a,k=k1$...' --pepper-key-ids k2,k1
```

| Argument or option | Description |
|--------------------|-------------|
| `storedHash` | The stored hash to describe. Quote it. |
| `--pepper-key-ids IDS` | Comma-separated pepper key ids your application knows, current key first, for example `k2,k1`. See [Peppered hashes](#peppered-hashes). |

```text
Format:       mh
Recognized:   yes
Profile:      2026a (Argon2id m=65536KiB t=3 p=1)
Pepper key:   none
Wrapped:      no
Needs rehash: no
Weak:         no
```

| Line | Meaning |
|------|---------|
| `Format` | `mh` for a Masterly hash, a legacy format id such as `bcrypt` or `v1`, or `unknown`. |
| `Recognized` | Whether the hasher could verify this hash. |
| `Profile` | The profile and its parameters. A profile id the tool does not register is shown as `<id> (not registered)`; legacy hashes show `-`. |
| `Pepper key` | `none`, the key id, or the key id followed by `(unknown; pass --pepper-key-ids <id> to classify it)`. |
| `Wrapped` | `yes (<format>)` for an onion-wrapped legacy hash. |
| `Needs rehash` | `yes (<reason>)` if a successful login would replace the hash, for example `LegacyFormat`, `Wrapped`, `OutdatedProfile` or `OutdatedPepperKey`. |
| `Weak` | For recognized legacy hashes, whether the format is weak by the audit rules (see [audit](#audit)). Always `no` for Masterly hashes. |

The exit code is 0 when the hash is recognized and 1 when it is not.

## audit

Surveys a whole table of stored hashes: which formats and profiles it holds, how many are weak, how many a login would upgrade and how many rows share a hash. It needs no passwords and verifies nothing. See [Auditing hash tables](./auditing-hash-tables.md) for the library API behind it.

```bash
masterly-hash audit hashes.txt                                   # one hash per line
masterly-hash audit users.csv --column 3 --header --format json  # one CSV column
psql -At -c 'select password_hash from users' | masterly-hash audit -
```

| Argument or option | Default | Description |
|--------------------|---------|-------------|
| `file` | | A file with one stored hash per line, or a CSV with `--column`. `-` reads standard input. |
| `--column N` | | Read the hash from this 1-based CSV column instead of whole lines. |
| `--delimiter C` | `,` | CSV field delimiter: one character, or `tab` (or `\t`). A quote or a line break is refused. |
| `--header` | off | Skip the first line or record. |
| `--format markdown\|json` | `markdown` | The report format. |
| `--pepper-key-ids IDS` | | Pepper key ids your application knows, current first. See [Peppered hashes](#peppered-hashes). |

**Input rules.**

- In line mode, each line is trimmed and blank lines are skipped. A line longer than 65,536 characters stops the audit with an error.
- With `--column`, the file is read as RFC 4180 CSV: quoted fields can contain the delimiter, doubled quotes and line breaks. Blank records are skipped. A record that has no such column is counted as unknown, and a warning on standard error says how many there were. A record longer than 1,048,576 characters (usually an unterminated quote) stops the audit.
- Masterly hashes peppered with a key id you did not pass in `--pepper-key-ids` are counted as unknown (they still appear under `mh` and their profile in the breakdowns), and a warning on standard error says how many.
- The file is streamed, never loaded whole. Duplicates are detected from a fingerprint of each value, so memory grows by about 40 bytes per distinct hash.

**What is weak.** Unsalted MD5, SHA-1, SHA-256 and SHA-512 digests, Masterly.Hash 1.x, phpass, ASP.NET Core Identity v2, bcrypt and WordPress bcrypt below cost 10, and Django PBKDF2 and Identity v3 below 100,000 iterations. Onion-wrapped hashes are not weak.

The markdown report looks like this:

```text
## Password hash audit

| Metric | Count | Share |
|---|---:|---:|
| Total | 1000 | 100.0% |
| Recognized | 990 | 99.0% |
| Unknown | 10 | 1.0% |
| Needs rehash | 900 | 90.0% |
| Weak | 300 | 30.0% |
| Onion-wrapped | 0 | 0.0% |
| Duplicates | 0 | 0.0% |

### By format

| Format | Count | Share | Weak |
|---|---:|---:|---:|
| bcrypt | 600 | 60.0% | 0 |
| v1 | 300 | 30.0% | 300 |
| mh | 90 | 9.0% | 0 |
| unknown | 10 | 1.0% | 0 |

### By profile

| Profile | Count | Share |
|---|---:|---:|
| 2026a | 90 | 9.0% |
```

With `--format json`, the same report is printed as indented JSON. Keys are format and profile ids, never stored hashes, and percentages are rounded to two decimals:

```json
{
  "total": 1000,
  "recognized": 990,
  "unknown": 10,
  "needsRehash": 900,
  "weak": 300,
  "wrapped": 0,
  "duplicates": 0,
  "percent": {
    "recognized": 99,
    "unknown": 1,
    "needsRehash": 90,
    "weak": 30,
    "wrapped": 0,
    "duplicates": 0
  },
  "byFormat": {
    "bcrypt": 600,
    "mh": 90,
    "unknown": 10,
    "v1": 300
  },
  "byProfile": {
    "2026a": 90
  },
  "weakByFormat": {
    "v1": 300
  }
}
```

Keys inside `byFormat`, `byProfile` and `weakByFormat` are sorted in ordinal order.

`audit` exits with 0 whenever it produced a report, whatever the report contains. To fail a CI job on weak hashes, read the JSON, for example `jq -e '.weak == 0'`.

## wrap

Onion-wraps the legacy hashes in one column of a CSV export: each legacy hash becomes `Argon2id(legacy digest)`, which still verifies with the user's original password and is upgraded to a plain hash on the next login. Every other column is copied unchanged. Read [Onion wrapping](./onion-wrapping.md) first for how this works and when to use it.

```bash
masterly-hash wrap users.csv users-wrapped.csv --column 3 --header --v1-algorithm SHA512
```

| Argument or option | Default | Description |
|--------------------|---------|-------------|
| `input.csv` | | The CSV export of the password table. |
| `output.csv` | | Where to write the result. It must differ from the input. |
| `--column N` | required | The 1-based column that holds the stored hash. |
| `--delimiter C` | `,` | CSV field delimiter: one character, or `tab`. |
| `--header` | off | The first record is a header row; copy it unchanged. |
| `--v1-algorithm SHA256\|SHA384\|SHA512` | | The digest of the Masterly.Hash 1.x hashes in this file. 1.x did not record it, so 1.x hashes are wrapped only when you give it. |
| `--profile 2026a\|2026c\|2026f` | `2026a` | The profile of the wrapping hash. |
| `--weak-only` | off | Wrap only weak hashes (see [audit](#audit)) and copy the rest unchanged. |
| `--parallelism N` | CPU count, at most 8 | Hashes computed at once, from 1 to 64. |
| `--force` | off | Overwrite the output file if it exists. |
| `--pepper-key-ids IDS` | | Pepper key ids your application knows, so peppered Masterly hashes count as already current instead of skipped. |

**What happens to each row.**

| Row | Result |
|-----|--------|
| A recognized Masterly hash | Copied unchanged, counted as already current. |
| A legacy hash the hasher can wrap | Replaced with the wrapped hash. |
| A blank line | Copied unchanged, not counted. |
| Anything else | Copied unchanged and counted as skipped, with a reason. |

The skip reasons are `missing column`, `empty`, `unknown format`, `<format> (not weak)` (with `--weak-only`), `<format> (cannot be wrapped)`, `v1 (pass --v1-algorithm to wrap 1.x hashes)`, `mh (unknown pepper key; pass --pepper-key-ids)` and `mh (malformed or unregistered profile)`.

At the end, the report goes to standard output:

```text
Rows:            1000
Wrapped:         900
Already current: 90
Skipped:         10
Wrapped by format:
  bcrypt: 600
  v1: 300
Skipped by reason:
  unknown format: 10
Output:          users-wrapped.csv
```

Every 10,000 rows, a progress line such as `wrap: 10000 rows processed` goes to standard error.

**How the file is handled.**

- **Streaming.** The file is read in batches of at most 16 × `--parallelism` records and at most about 4 Mi characters, so it is never loaded whole.
- **Byte-for-byte copy.** The input must be UTF-8, with or without a byte order mark. Every column you did not ask to change is copied exactly, including quoting, line endings and the BOM. A file with invalid UTF-8 (for example a Windows-1252 export) is refused rather than silently changed, and so is a UTF-16 or UTF-32 file. Convert it first, for example with `iconv -f WINDOWS-1252 -t UTF-8`.
- **Atomic output.** The result is written to a temporary file next to the output and renamed into place only when every row succeeded. On any error the temporary file is deleted and the output is untouched.
- **Private output.** On Linux and macOS the output file is created with mode `0600` (owner read and write only), even when `--force` replaces an existing file. On Windows it inherits the folder's permissions, so write it to a folder only you can read.
- **No pepper.** The wrapping hash is never peppered, because the tool never holds a pepper key. Hashes your application peppers are left alone. After import, the first successful login replaces each wrapped hash with a normal hash from your application, peppered if your application is.

:::warning

Know your 1.x digest before you pass `--v1-algorithm`. If you give the wrong one, the wrapped hashes never verify and those users cannot log in. Run `wrap` on a copy first and check a few rows with `verify` and known test passwords before you import the result.

:::

**Memory.** Each Argon2id hash allocates the profile's memory: 64 MiB for `2026a`, 19 MiB for `2026c`. With 8 hashes in flight (the default on a machine with 8 or more CPUs) that is about 512 MiB for `2026a`. If the process runs out of memory, the command stops with a message that suggests a lower `--parallelism` or `--profile 2026c`.

## bench

Times each built-in profile on this machine and recommends `Server2026a` or `Constrained2026a`.

```bash
masterly-hash bench
masterly-hash bench --target-ms 100
```

| Option | Default | Description |
|--------|---------|-------------|
| `--target-ms ms` | `250` | The longest acceptable time for one hash on this machine, from 1 to 60,000 milliseconds. |

For each profile the tool runs the key-derivation function once to warm up, then five more times, and reports the median. Each run hashes a random input with a random salt, on one thread. Progress lines (`bench: 2026a...`) go to standard error. The output has three parts:

```text
Median of 5 runs per profile; target 250 ms per hash.

| Profile | Parameters | Median (ms) |
|---|---|---:|
| 2026a | Argon2id m=65536 KiB, t=3, p=1 | <ms> |
| 2026c | Argon2id m=19456 KiB, t=2, p=1 | <ms> |
| 2026f | PBKDF2-SHA512 i=210000 | <ms> |

Recommendation: Server2026a (2026a takes <ms> ms, within the 250 ms target).

| OS | Arch | Cores | Runtime | 2026a (ms) | 2026c (ms) | 2026f (ms) | Recommended |
|---|---|---:|---|---:|---:|---:|---|
| <os> | X64 | 16 | .NET 8.0.x | <ms> | <ms> | <ms> | Server2026a |
```

The recommendation is `Server2026a` when `2026a` fits the target and `Constrained2026a` otherwise. When even `2026c` exceeds the target, the tool says so and advises adding capacity or lowering `PasswordHasherOptions.MaxConcurrency` instead, because `2026c` is the OWASP minimum and you should not go lower. `2026f` is measured for reference but never recommended; choose it only when you are restricted to NIST-approved primitives. The last table is a single Markdown row you can paste into an issue or a capacity plan. See [Performance](./performance.md) for how to read the numbers.

## policy

Checks a password against the NIST SP 800-63B policy from `Masterly.Hash.Policy` and prints a strength estimate. See [Password policy](./password-policy.md) and [Strength estimation](./strength-estimation.md) for the rules themselves.

```bash
masterly-hash policy
masterly-hash policy --min-length 12 --user-name alice --email alice@example.com
printf '%s\n' "$PASSWORD" | masterly-hash policy --stdin --pwned
```

| Option | Default | Description |
|--------|---------|-------------|
| `--stdin` | off | Read the password from standard input instead of prompting. |
| `--min-length N` | `15` | Minimum length in code points, from 8 (the NIST floor) to 128. 15 is the NIST minimum for a password used as the only factor. |
| `--user-name U` | | The account's user name. Passwords containing it are rejected. |
| `--email E` | | The account's email address. Passwords containing its parts are rejected. |
| `--pwned` | off | Also look the password up in Have I Been Pwned. This goes online. |
| `--allow-unavailable` | off | With `--pwned`: if the service cannot be reached, judge the password without it instead of failing. Only valid with `--pwned`. |

The output has these parts:

| Line | Content |
|------|---------|
| `Result` | `Acceptable` or `Rejected`. |
| `Score` | 0 to 4, with the estimated number of guesses as a power of ten. |
| `Length` | The length in code points. |
| `Crack time (estimates)` | Four estimates: online rate-limited (100 guesses per hour), online not rate-limited (10 per second), offline against a slow hash such as Argon2id (10^4 per second) and offline against a fast hash such as SHA-1 (10^10 per second). |
| `Warning` | A short explanation, when the estimator has one. |
| `Violations` | Each failed rule as `- <code>: <message>`. |
| `Suggestions` | Ways to make the password stronger. |
| `Breach check` | `skipped (offline)` without `--pwned`; otherwise found (with the number of times it was seen), not found, unavailable, or not performed because the password was already rejected on length. |

With `--pwned`, only the first 5 hex characters of the password's SHA-1 hash leave the machine (k-anonymity). A note on standard error says the tool is going online. See [Breach checking](./breach-checking.md).

The exit code is 0 for an acceptable password and 1 for a rejected one. A breach check you asked for must not look like a clean result when it did not run: if the password is otherwise acceptable but Have I Been Pwned could not be reached, the exit code is 2, unless you pass `--allow-unavailable`. A password rejected on other grounds still exits with 1.

## pepper generate

Prints a new random 32-byte pepper key, base64-encoded, for `HmacPepper`.

```bash
masterly-hash pepper generate
```

The key goes to standard output. A reminder goes to standard error: keep the key in a secret store (environment, Key Vault, Vault), never in the database, and give it a key id, for example `HmacPepper.FromBase64("k1", ...)`. The key is printed once and not stored anywhere. See [Peppers](./peppers.md).

```bash
# Generate a key straight into a secret store without it touching the terminal.
masterly-hash pepper generate | vault kv put secret/myapp/pepper k1=-
```

## apikey generate

Prints a new API key and its lookup hash (HMAC-SHA256). See [API keys and tokens](./api-keys-and-tokens.md) for the key format and how to look keys up.

```bash
masterly-hash apikey generate --prefix mh_live                          # generates a new lookup key too
API_LOOKUP_KEY="$(cat lookup.key)" masterly-hash apikey generate --prefix mh_live --key-env API_LOOKUP_KEY
masterly-hash apikey generate --prefix mh_live --key-stdin < lookup.key
```

| Option | Default | Description |
|--------|---------|-------------|
| `--prefix P` | required | The key prefix, for example `mh_live`: 1 to 32 ASCII letters, digits and single underscores, starting with a letter and not ending with `_`. |
| `--key-id ID` | `k1` | The id of the HMAC lookup key, stored in the lookup hash. Must match `^[A-Za-z0-9-]{1,32}$`. |
| `--key-env NAME` | | Read the base64 lookup key from this environment variable. |
| `--key-stdin` | off | Read the base64 lookup key from the first line of standard input. Requires piped input. |
| `--entropy-bytes N` | `32` | Random bytes in the key, from 16 to 64. |

`--key-env` and `--key-stdin` cannot be combined. The lookup key must decode to at least 32 bytes, and a key on standard input may be at most 1,024 characters. Without either option, the tool generates a new lookup key and prints it. The lookup key is never accepted as a command-line argument.

```text
API key:       mh_live_...
Lookup hash:   ...
Hint:          ...
Lookup key id: k1
Lookup key:    (provided from environment variable API_LOOKUP_KEY)
```

Give the API key to its owner once and store only the lookup hash, ideally in a unique index. When the tool generated the lookup key, the `Lookup key` line shows it in base64. Keep it in a secret store: every lookup hash depends on it.

## Peppered hashes

The tool never holds a pepper key, so on its own it cannot tell a well-formed peppered hash (`$mh$p=2026a,k=k2$...`) from one made with a key that no longer exists. `inspect`, `audit` and `wrap` therefore treat peppered hashes as unknown unless you pass `--pepper-key-ids`:

```bash
masterly-hash audit hashes.txt --pepper-key-ids k2,k1
```

- List the key ids your application knows, **current key first**. Each id must match `^[A-Za-z0-9-]{1,32}$`.
- Only the ids are needed, never the keys. With them, a hash made with `k2` is current and a hash made with `k1` needs a rehash (`OutdatedPepperKey`).
- `verify` cannot check peppered hashes at all. Use the library with your pepper configured.

## Scripting

The exit codes make the tool easy to use in scripts:

```bash
#!/usr/bin/env bash
set -u

printf '%s\n' "$CANDIDATE_PASSWORD" | masterly-hash policy --stdin --pwned > policy.txt
case $? in
  0) echo "password accepted" ;;
  1) echo "password rejected"; cat policy.txt ;;
  *) echo "policy check failed"; exit 2 ;;
esac
```

Because results go to standard output and everything else goes to standard error, `masterly-hash hash --stdin > hash.txt` captures only the hash.

## Security notes

- **No passwords or keys on the command line.** Use the prompt, `--stdin`, `--key-env` or `--key-stdin`.
- **Error messages never contain secrets.** They name limits and line numbers, never a password, a key or the bytes of an invalid input.
- **Only `--pwned` touches the network.** Every other command works offline.
- **Fixed profiles, no pepper.** The tool hashes only with the built-in profiles and never adds a pepper. An application with a pepper still verifies a hash from `hash`, but replaces it at the next successful login (`OutdatedPepperKey`).
- **Generated keys are printed once.** Store the output of `pepper generate` and `apikey generate` in a secret store straight away.
- **Wrap output is sensitive.** It holds the whole password table. Keep it private and delete it after import.

## See also

- [Onion wrapping](./onion-wrapping.md)
- [Auditing hash tables](./auditing-hash-tables.md)
- [Performance](./performance.md)
- [Password policy](./password-policy.md)
- [API keys and tokens](./api-keys-and-tokens.md)
- [Tool source and README](https://github.com/a7mdfre7at/Masterly.Hash/blob/master/src/Masterly.Hash.Tool/README.md)
