# Security policy

## Supported versions

| Version | Supported |
|---|---|
| 2.x | ✅ Security fixes |
| 1.x | ❌ Upgrade to 2.x. 1.x hashes keep verifying and migrate automatically ([guide](docs/MIGRATION-1x.md)). |

## Reporting a vulnerability

**Do not open a public issue.** Report privately through GitHub's [private vulnerability reporting](https://github.com/a7mdfre7at/Masterly.Hash/security/advisories/new).

Please include:

- the affected package and version
- a minimal reproduction, such as a failing input, a stored hash, or a code snippet
- the impact as you understand it

You will get an acknowledgement within 7 days. We aim to release a fix within 90 days, and coordinate disclosure with you. Credit is given in the advisory unless you prefer otherwise.

## Scope

In scope:
- Every package in this repository.
- The `$mh$` format ([spec](docs/spec/FORMAT.md)).
- Weaknesses in a built-in profile's parameters.

Especially welcome:
- ways to make `Verify` throw, hang or allocate excessively from a stored string
- timing differences that reveal tag bytes
- canonicalization bypasses, where two strings verify as one hash
- pepper or key material leaking into outputs, exceptions or logs

## What we do

- The test suite includes known-answer vectors from RFC 9106, RFC 6070, RFC 7914 and NIST, plus differential tests against reference implementations and FsCheck property-based fuzzing of every parser.
- Releases are built in CI from the master commit that passed the Build workflow, published to NuGet through Trusted Publishing (no stored API key), and carry SourceLink, an SBOM and GitHub build-provenance attestations.
- Dependencies are kept current by Dependabot and checked by CodeQL and OpenSSF Scorecard.

No independent third-party audit has been done yet.
