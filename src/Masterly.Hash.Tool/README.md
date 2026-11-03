# Masterly.Hash.Tool

![Masterly.Hash: password hashing you can't get wrong.](https://raw.githubusercontent.com/a7mdfre7at/Masterly.Hash/master/assets/banner.png)

`masterly-hash` is a .NET global tool for working with [Masterly.Hash](https://github.com/a7mdfre7at/Masterly.Hash) password hashes from a terminal or script. It can:

- hash and verify passwords
- inspect and audit stored hashes
- onion-wrap a legacy password table in a CSV export
- benchmark the built-in profiles on this machine
- check passwords against the NIST SP 800-63B policy
- generate pepper keys and API keys

## Install

```bash
dotnet tool install --global Masterly.Hash.Tool
masterly-hash --help
```

It needs .NET 8 or later (`RollForward=Major`, so newer runtimes work too).

## Quickstart

```bash
masterly-hash hash                                  # prompts twice, without echo; prints $mh$p=2026a$...
echo -n "$PASSWORD" | masterly-hash hash --stdin --profile 2026c
masterly-hash verify '$mh$p=2026a$...'              # exit 0 match, 1 mismatch, 2 error
masterly-hash inspect '$2b$10$...'                  # format, profile, pepper key, wrapped, needs-rehash, weak

masterly-hash audit hashes.txt                      # one hash per line ('-' = stdin)
masterly-hash audit users.csv --column 3 --header --format json

masterly-hash wrap users.csv users-wrapped.csv --column 3 --header --v1-algorithm SHA512
masterly-hash bench --target-ms 250                 # median of 5 runs per profile, recommends a profile
masterly-hash policy --min-length 12 --pwned        # score, crack times, violations, suggestions
masterly-hash pepper generate                       # base64 32-byte HmacPepper key
masterly-hash apikey generate --prefix mh_live      # API key + lookup hash (new lookup key printed)
API_LOOKUP_KEY=... masterly-hash apikey generate --prefix mh_live --key-env API_LOOKUP_KEY
```

Put stored hashes in single quotes. They contain `$`, which the shell would otherwise expand.

### Commands

| Command | What it does |
|---|---|
| `hash [--profile 2026a\|2026c\|2026f] [--stdin]` | Prints a new hash. When prompting, it asks for the password twice. |
| `verify <storedHash> [--stdin]` | Prints the status, the failure or rehash reason, and the replacement hash when one is due. Exit code 0 means match, 1 mismatch, 2 a hash or input that cannot be used. |
| `inspect <storedHash> [--pepper-key-ids IDS]` | Describes a stored hash without needing the password. Exit code 0 means recognized, 1 not recognized. |
| `audit <file\|-> [--column N] [--delimiter ,] [--header] [--format markdown\|json] [--pepper-key-ids IDS]` | Streams the file into `HashAudit` with every legacy format registered and prints the report. |
| `wrap <in.csv> <out.csv> --column N [--v1-algorithm SHA256\|SHA384\|SHA512] [--weak-only] [--profile ...] [--parallelism N] [--pepper-key-ids IDS] [--force]` | Onion-wraps the legacy hashes in one column. See [Wrapping a CSV](#wrapping-a-csv). |
| `bench [--target-ms 250]` | Times 2026a, 2026c and 2026f. It recommends `Server2026a` when 2026a fits the target and `Constrained2026a` otherwise, then prints a Markdown result row. |
| `policy [--min-length N] [--pwned [--allow-unavailable]] [--user-name U] [--email E]` | Prints the score, crack-time estimates, violations and suggestions. Exit code 0 means acceptable, 1 rejected. With `--pwned`, an otherwise acceptable password exits 2 if Have I Been Pwned cannot be reached, unless `--allow-unavailable` is given. |
| `pepper generate` | Prints a new base64 pepper key. |
| `apikey generate --prefix P [--key-env NAME \| --key-stdin] [--key-id k1] [--entropy-bytes 32]` | Prints a new API key and its lookup hash. |

`--column` numbers start at 1. Errors go to stderr as `error: ...` and exit with code 2.

**Peppered hashes.** The tool never holds a pepper key. A `$mh$p=...,k=ID$...` hash is therefore unknown to `inspect`, `audit` and `wrap` unless you pass `--pepper-key-ids` (comma-separated, current key first, e.g. `k2,k1`). Classifying a hash needs only the key ids, never the keys. `verify` cannot check peppered hashes; use the library with your pepper configured.

### Wrapping a CSV

- **Streaming:** the file is read in bounded batches and never loaded whole. The tool computes up to `--parallelism` hashes at once (default: the number of CPUs, at most 8).
- **Batches:** a batch holds at most `16 x --parallelism` records and at most about 4 Mi characters.
- **Columns:** the input must be UTF-8 (with or without a BOM). Every other column is then copied byte for byte, including the line endings and the BOM. A file with invalid UTF-8 bytes (for example a Windows-1252 export) is refused rather than silently changed, and so is a UTF-16 or UTF-32 file. Convert it first, for example with `iconv -f WINDOWS-1252 -t UTF-8`.
- **Atomic output:** the result goes to a temporary file and is renamed into place only on success.
- **Private output:** on Linux and macOS the output file is created with mode `0600` (owner read/write only), even when `--force` replaces an existing file. On Windows it inherits the folder's permissions, so write it to a folder only you can read.
- **Report:** at the end it prints how many rows were wrapped, how many were skipped and how many were already current.

## Security notes

- **No passwords on the command line.** The tool never takes a password as an argument, because arguments end up in shell history and process listings. Use the no-echo prompt or `--stdin`. If a password-reading command gets a stray argument or a bad option value, the tool refuses it without echoing it (response files, `@file`, are disabled for the same reason). For the same reason, the API lookup key is read only from `--key-env` or `--key-stdin`.
- **`--stdin` and `--key-stdin` need a pipe.** If standard input is a terminal, the tool refuses, because the terminal would echo the secret as you type it. Piped input is always decoded as UTF-8, whatever the console code page, so a non-ASCII password is hashed as itself. Invalid UTF-8 is an error.
- **Clean stdout.** Prompts, progress and notes go to stderr, so stdout carries only results.
- **`--pwned` goes online.** It queries the Have I Been Pwned range API, but only the first 5 hex characters of the password's SHA-1 hash leave the machine (k-anonymity). Nothing else touches the network. If the service cannot be reached, the check fails closed (exit code 2) unless you pass `--allow-unavailable`.
- **Know your 1.x digest before using `--v1-algorithm`.** Masterly.Hash 1.x did not record which digest it used. If you give the wrong one, the wrapped hashes will never verify. Run `wrap` on a copy first and check a few rows with `verify`.
- **Generated keys appear only once.** `pepper generate` and `apikey generate` print new keys exactly once. Store them in a secret store, never in the database.
- **Profiles are fixed.** The tool hashes only with the built-in profiles and uses no pepper. To verify peppered hashes, use the library with your pepper configured.
