---
title: "Integrity and Tamper Evidence"
sidebar_label: "Integrity"
description: "Content hashes, HMAC tags, directory manifests and BLAKE3 for detecting changed files and records."
---

`Masterly.Hash.Integrity` tells you whether bytes have changed since you last looked at them. This page covers content hashes such as `sha256:<hex>`, keyed HMAC tags, the algorithm registry, directory manifests that report added, removed and modified files, and the BLAKE3 add-on package. Merkle trees and hash-chain audit logs come from the same package and have their own page: [Merkle Trees and Hash Chains](./merkle-trees-and-hash-chains.md).

:::tip[What needs which package]

- Content hashes, HMAC-SHA256, directory manifests, Merkle trees and hash chains are in `Masterly.Hash.Integrity` (`net8.0`, AOT compatible).
- BLAKE3 needs `Masterly.Hash.Integrity.Blake3` as well.

:::

:::warning[This is not password hashing]

Everything on this page is fast by design. Never use `ContentHasher` or a manifest to store passwords. Use the password hasher described in [Hashing and Verifying](./hashing-and-verifying.md).

:::

## Install

```bash
dotnet add package Masterly.Hash.Integrity
dotnet add package Masterly.Hash.Integrity.Blake3   # optional
```

`Masterly.Hash.Integrity` depends on the core `Masterly.Hash` package and uses only the .NET cryptography APIs. The BLAKE3 package adds a dependency on the managed [`Blake3`](https://www.nuget.org/packages/Blake3) package (version 3.0.2).

## Content hashes

A `ContentHash` is a digest tagged with the algorithm that produced it. It has exactly one string form, so you can store it in a text column and compare strings or parse it back.

| Algorithm | String form | Digest length |
|-----------|-------------|---------------|
| SHA-256 (default) | `sha256:<64 hex>` | 32 bytes |
| SHA-384 | `sha384:<96 hex>` | 48 bytes |
| SHA-512 | `sha512:<128 hex>` | 64 bytes |
| HMAC-SHA256 | `hmac-sha256:<keyId>:<64 hex>` | 32 bytes |
| BLAKE3 | `blake3:<64 hex>` | 32 bytes |
| Keyed BLAKE3 | `blake3-keyed:<keyId>:<64 hex>` | 32 bytes |

**1. Compute a hash.** `ContentHasher` hashes byte arrays, streams and files. Overloads without an algorithm use SHA-256.

```csharp title="Program.cs"
using System.IO;
using System.Text;
using System.Threading;
using Masterly.Hash.Integrity;

CancellationToken cancellationToken = CancellationToken.None;

ContentHash fromBytes = ContentHasher.Compute(Encoding.UTF8.GetBytes("hello"));
// sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824

ContentHash fromFile = await ContentHasher.ComputeFileAsync("release.zip", cancellationToken);

await using FileStream stream = File.OpenRead("backup.tar");
ContentHash fromStream = await ContentHasher.ComputeAsync(stream, ContentHashAlgorithm.Sha512, cancellationToken);
```

**2. Store the string form.** `ToString()` returns the canonical string. `ToHex()` returns only the hex digest, without the algorithm prefix.

```csharp
string stored = fromFile.ToString();   // "sha256:9f86d0..."
```

**3. Verify later.** Parse the stored value and verify the content against it. The digests are compared in constant time.

```csharp
ContentHash expected = ContentHash.Parse(stored);
bool unchanged = await ContentHasher.VerifyFileAsync("release.zip", expected, cancellationToken);
```

### ContentHasher methods

| Method | Default algorithm | Notes |
|--------|-------------------|-------|
| `Compute(byte[] data)` | SHA-256 | |
| `Compute(byte[] data, ContentHashAlgorithm algorithm)` | | |
| `Compute(Stream stream, ContentHashAlgorithm algorithm)` | | Reads synchronously to the end of the stream. |
| `ComputeAsync(Stream stream, CancellationToken)` | SHA-256 | |
| `ComputeAsync(Stream stream, ContentHashAlgorithm algorithm, CancellationToken)` | | |
| `ComputeFileAsync(string path, CancellationToken)` | SHA-256 | Opens the file with `FileShare.Read`. |
| `ComputeFileAsync(string path, ContentHashAlgorithm algorithm, CancellationToken)` | | |
| `Verify(byte[] data, ContentHash expected)` | from `expected` | Unkeyed hashes only. |
| `Verify(byte[] data, ContentHash expected, ContentHashAlgorithm? algorithm)` | from `expected` when `null` | Required for keyed hashes. |
| `VerifyAsync(Stream stream, ContentHash expected, CancellationToken)` | from `expected` | Unkeyed hashes only. |
| `VerifyAsync(Stream stream, ContentHash expected, ContentHashAlgorithm? algorithm, CancellationToken)` | from `expected` when `null` | |
| `VerifyFileAsync(string path, ContentHash expected, CancellationToken)` | from `expected` | Unkeyed hashes only. |
| `VerifyFileAsync(string path, ContentHash expected, ContentHashAlgorithm? algorithm, CancellationToken)` | from `expected` when `null` | |

How the hasher behaves:

- Streams are read from their current position to the end and are never closed. A stream that cannot be read throws `ArgumentException`.
- Reads use one pooled buffer of `ContentHasher.BufferSize` (64 KiB, 65,536 bytes), so memory use does not depend on the content size. The buffer is cleared before it goes back to the pool, because the content may be what an HMAC protects.
- The verifiers treat `expected` as untrusted. If its algorithm name or key id differs from the algorithm you pass, or it is keyed and you pass no algorithm, or its algorithm is not registered, they return `false` instead of throwing. The stream and file overloads then return `false` without reading anything.
- Only `null` arguments, unreadable streams, I/O errors and cancellation (`OperationCanceledException`) throw, plus `InvalidOperationException` when a [custom algorithm](#adding-your-own-algorithm) returns a digest of the wrong length. A missing file throws `FileNotFoundException` from the file overloads, including `VerifyFileAsync` once the stored hash's algorithm has been resolved.

### Parsing rules

`ContentHash.Parse` throws `FormatException` on any deviation from the canonical form, and `ContentHash.TryParse` returns `false` instead. The rules make sure each hash has exactly one string:

- The algorithm name must be registered (see [Algorithms and the registry](#algorithms-and-the-registry)). An unknown name such as `md5:` is rejected.
- Hex must be lowercase and exactly twice the algorithm's digest length. Uppercase hex, whitespace, a trailing newline or an extra byte are rejected.
- A keyed algorithm needs exactly one key id, matching `^[A-Za-z0-9-]{1,32}$`. An unkeyed algorithm must not have one.
- Strings longer than `ContentHash.MaxStringLength` (322 characters) are rejected before any other work.

### ContentHash members

| Member | Description |
|--------|-------------|
| `Algorithm` | Algorithm name, for example `sha256`. |
| `KeyId` | Key id of a keyed hash; `null` otherwise. |
| `IsKeyed` | `true` when `KeyId` is set. |
| `Digest` | The raw digest as `ReadOnlyMemory<byte>`. |
| `ToArray()` | A copy of the digest. |
| `ToHex()` | Lowercase hex digest, without the prefix. |
| `IsFrom(algorithm)` | `true` when the name, key id and digest length match `algorithm`. |
| `Equals(other)` | Same algorithm and key id, and equal digests compared in constant time. |
| `new ContentHash(algorithm, digest)` | Wraps a digest you computed yourself. Throws `ArgumentException` when the length is wrong. The bytes are copied. |

`ContentHash` carries a `[JsonConverter]` attribute (`ContentHashJsonConverter`), so `System.Text.Json` writes it as its string form and reads it back with the same strict parser. An invalid string throws `JsonException`, and a JSON `null` reads as `null`.

```csharp
using System.Text.Json;
using Masterly.Hash.Integrity;

// fromFile is the ContentHash computed earlier
ArtifactDto artifact = new ArtifactDto("release.zip", fromFile);
string json = JsonSerializer.Serialize(artifact);
// {"Name":"release.zip","Hash":"sha256:9f86d0..."}

ArtifactDto? roundTripped = JsonSerializer.Deserialize<ArtifactDto>(json);

public sealed record ArtifactDto(string Name, ContentHash Hash);
```

## Keyed hashes with HMAC-SHA256

A plain hash only detects accidental changes, or changes made by someone who cannot also rewrite the stored hash. Anyone who can change the file and the hash next to it can recompute a matching SHA-256. When that attacker is in your threat model, use HMAC-SHA256 with a key kept outside the data store.

**1. Create a key once.** The key must be at least `ContentHashAlgorithm.MinHmacKeyLength` (32) bytes. Generate it randomly and keep it in your secret store.

```csharp
using Masterly.Hash.Primitives;

byte[] key = HashPrimitives.RandomBytes(32);
```

**2. Build the algorithm and hash.** The key id is written into every hash so you can rotate keys later. It must match `^[A-Za-z0-9-]{1,32}$`, the same rule as pepper key ids.

```csharp title="Program.cs"
using Masterly.Hash.Integrity;

// key comes from your secret store; data is the record you protect
ContentHashAlgorithm mac = ContentHashAlgorithm.HmacSha256("k2026", key);

ContentHash tag = ContentHasher.Compute(data, mac);
// hmac-sha256:k2026:5b1d...
```

**3. Verify with the key.** Keyed hashes can only be verified by passing the algorithm. Without it, every verifier returns `false`.

```csharp
bool valid = ContentHasher.Verify(data, ContentHash.Parse(stored), mac);
```

**Rotating keys.** Read `KeyId` from the stored hash and pick the matching key. A hash tagged with a key id you no longer hold, or one swapped from keyed to plain, simply fails verification.

```csharp
// keys is an IReadOnlyDictionary<string, byte[]> loaded from your secret store
ContentHash expected = ContentHash.Parse(stored);
bool valid = expected.KeyId != null
    && keys.TryGetValue(expected.KeyId, out byte[]? keyBytes)
    && ContentHasher.Verify(data, expected, ContentHashAlgorithm.HmacSha256(expected.KeyId, keyBytes));
```

After a successful verification under an old key, compute a new tag with the current key and store it.

Facts about the HMAC algorithm:

- `HmacSha256` copies the key, so changing your array afterwards has no effect.
- Algorithm equality, `GetHashCode` and `ToString()` use only the name and key id (`hmac-sha256:k2026`), never the key. Two instances with the same key id but different keys compare equal, and their hashes do not verify against each other.
- A key shorter than 32 bytes or an invalid key id throws `ArgumentException`.

## Algorithms and the registry

`ContentHashAlgorithm` describes a hash function. The same instances work for content hashes, manifests, Merkle trees and hash chains.

| Member | Description |
|--------|-------------|
| `Sha256`, `Sha384`, `Sha512` | Built-in unkeyed algorithms (FIPS 180-4). SHA-256 is the default everywhere. |
| `HmacSha256(keyId, key)` | Keyed HMAC-SHA256 (RFC 2104). |
| `Name` | Lowercase name, for example `sha256`. |
| `DigestLength` | Digest length in bytes. |
| `KeyId`, `IsKeyed` | Key id of a keyed algorithm; `null` and `false` for plain hashes. |
| `Identifier` | `name` or `name:keyId`. Also returned by `ToString()`. |
| `CreateDigest()` | Starts an incremental computation (a `ContentDigest`). |

The parsers only accept algorithm names that are registered. SHA-256, SHA-384, SHA-512 and the `hmac-sha256` family are registered when the type loads. The registry is process-wide and thread-safe.

| Registry method | What it does |
|-----------------|--------------|
| `Register(algorithm)` | Makes the name parseable. An unkeyed instance also becomes resolvable through `TryGet`, so verifiers can find it from a stored hash. For a keyed instance only the name family is registered. |
| `RegisterKeyedFamily(name, digestLength)` | Registers a keyed name so `name:keyId:hex` strings parse before any keyed instance exists. |
| `TryGet(name, out algorithm)` | Resolves a registered unkeyed algorithm. Keyed algorithms need their key and are never returned. |
| `IsRegistered(name)` | `true` for any registered name, keyed or not. |

Registering the same identity twice does nothing. Registering a different algorithm under a taken name throws `InvalidOperationException`.

### Incremental digests

`CreateDigest()` returns a `ContentDigest` for data that arrives in pieces. Feed it with `Append`, read the result with `GetHashAndReset()` (which also resets it for reuse), and dispose it. A digest is not thread-safe. Using it after `Dispose` throws `ObjectDisposedException`.

```csharp
using Masterly.Hash.Integrity;

// chunks is the data as it arrives
using ContentDigest digest = ContentHashAlgorithm.Sha256.CreateDigest();
foreach (byte[] chunk in chunks)
{
    digest.Append(chunk);
}

ContentHash hash = new ContentHash(ContentHashAlgorithm.Sha256, digest.GetHashAndReset());
```

### Adding your own algorithm

Derive from `ContentHashAlgorithm` and `ContentDigest`. The protected constructor takes the name (`^[a-z0-9][a-z0-9-]{0,31}$`), the digest length (16 to 128 bytes) and a key id (`null` for a plain hash). This example adds SHA3-256 from the .NET 8 cryptography APIs:

```csharp title="Sha3Algorithm.cs"
using System.Security.Cryptography;
using Masterly.Hash.Integrity;

namespace MyApp.Integrity;

public sealed class Sha3Algorithm : ContentHashAlgorithm
{
    public static readonly Sha3Algorithm Instance = new Sha3Algorithm();

    private Sha3Algorithm()
        : base("sha3-256", 32, null)
    {
    }

    public override ContentDigest CreateDigest() =>
        new Sha3Digest(IncrementalHash.CreateHash(HashAlgorithmName.SHA3_256));

    private sealed class Sha3Digest : ContentDigest
    {
        private readonly IncrementalHash _hash;

        public Sha3Digest(IncrementalHash hash)
        {
            _hash = hash;
        }

        protected override void AppendCore(byte[] buffer, int offset, int count) =>
            _hash.AppendData(buffer, offset, count);

        protected override byte[] GetHashAndResetCore() => _hash.GetHashAndReset();

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _hash.Dispose();
            }
        }
    }
}
```

```csharp title="Program.cs"
using System.Security.Cryptography;
using Masterly.Hash.Integrity;
using MyApp.Integrity;

if (SHA3_256.IsSupported)
{
    ContentHashAlgorithm.Register(Sha3Algorithm.Instance);   // "sha3-256:..." now parses and verifies
}
```

If `GetHashAndResetCore` returns a digest of the wrong length, `ContentHasher` throws `InvalidOperationException`.

## BLAKE3

`Masterly.Hash.Integrity.Blake3` adds BLAKE3 in two modes, both with 32-byte output. Use it for large files when you control both the writer and the verifier. Use SHA-256 when another system or a standard expects it.

| Member | Value |
|--------|-------|
| `Blake3Algorithms.Blake3` | Plain BLAKE3, `blake3:<hex>`. |
| `Blake3Algorithms.Keyed(keyId, key)` | Keyed BLAKE3 (a MAC), `blake3-keyed:<keyId>:<hex>`. |
| `Blake3Algorithms.Name` / `KeyedName` | `"blake3"` / `"blake3-keyed"` |
| `Blake3Algorithms.DigestLength` | 32 |
| `Blake3Algorithms.KeyLength` | 32. Keyed BLAKE3 needs **exactly** 32 bytes. |
| `Blake3Algorithms.Register()` | Registers both names. Idempotent and thread-safe. |

**1. Register at startup.** Call `Register()` once before you parse any stored BLAKE3 hash or manifest. Until something touches `Blake3Algorithms`, the names are unknown and `ContentHash.Parse("blake3:...")` and `DirectoryManifest.FromJson` reject them.

```csharp title="Program.cs"
using Masterly.Hash.Integrity;
using Masterly.Hash.Integrity.Blake3;

Blake3Algorithms.Register();
```

**2. Hash and verify.** Plain BLAKE3 resolves from the registry like SHA-256. Keyed BLAKE3 needs the algorithm when you verify.

```csharp
using Masterly.Hash.Integrity;
using Masterly.Hash.Integrity.Blake3;

// cancellationToken comes from your application; key is 32 bytes from your secret store
ContentHash hash = await ContentHasher.ComputeFileAsync("big.iso", Blake3Algorithms.Blake3, cancellationToken);
bool ok = await ContentHasher.VerifyFileAsync("big.iso", ContentHash.Parse(hash.ToString()), cancellationToken);

ContentHashAlgorithm mac = Blake3Algorithms.Keyed("k1", key);
DirectoryManifest manifest = await DirectoryManifest.CreateAsync("/srv/app", mac, null, cancellationToken);
```

A key that is not exactly 32 bytes, or an invalid key id, throws `ArgumentException`. The key is copied when the algorithm is created, and the hasher state is cleared when each digest is disposed.

:::note

Merkle trees built with BLAKE3 use the RFC 9162 structure, but they do not interoperate with Certificate Transparency, which requires SHA-256.

:::

## Directory manifests

A `DirectoryManifest` is a snapshot of a directory tree: the relative path, length and content hash of every file, sorted by ordinal path, plus a Merkle root over all entries. Verifying a directory against a manifest tells you which files were added, removed or modified. Typical uses are deployment folders, plugin directories and backups.

**1. Create the manifest** after you deploy.

```csharp title="Deploy.cs"
using System.IO;
using Masterly.Hash.Integrity;

// cancellationToken comes from your application
DirectoryManifest manifest = await DirectoryManifest.CreateAsync("/srv/app", cancellationToken);
await File.WriteAllTextAsync("/var/lib/app/manifest.json", manifest.ToJson(), cancellationToken);

// Keep the root where an attacker who can write /srv/app cannot, for example in a separate system.
string trustedRoot = manifest.Root.ToString();
```

**2. Verify** later, passing the root you kept.

```csharp title="IntegrityCheck.cs"
using System;
using System.IO;
using Masterly.Hash.Integrity;

string json = await File.ReadAllTextAsync("/var/lib/app/manifest.json", cancellationToken);
DirectoryManifest expected = DirectoryManifest.FromJson(json);
ContentHash trustedRoot = ContentHash.Parse(storedRoot);   // storedRoot comes from the trusted copy

DirectoryManifestDiff diff = await DirectoryManifest.VerifyAsync(
    "/srv/app", expected, trustedRoot, null, null, cancellationToken);

if (!diff.ManifestIntact)
{
    Console.WriteLine("The manifest itself was tampered with. Treat the whole directory as unverified.");
}
else if (!diff.IsMatch)
{
    Console.WriteLine(diff);   // "0 added, 0 removed, 1 modified"
    foreach (string path in diff.Modified)
    {
        Console.WriteLine($"modified: {path}");
    }
}
```

**3. Read the result.**

| `DirectoryManifestDiff` member | Meaning |
|--------------------------------|---------|
| `ManifestIntact` | The manifest's algorithm is the one verification used, its root matches its own entries, and the root equals the trusted root when you gave one. `false` means the manifest cannot be trusted. |
| `Added` | Files and links present now but not in the manifest, in ordinal order. |
| `Removed` | Files and links in the manifest that are gone, in ordinal order. |
| `Modified` | Entries whose content, length or kind changed (for links, the target), in ordinal order. |
| `IsMatch` | `ManifestIntact` and all three lists are empty. |
| `ToString()` | `Match`, or a summary such as `manifest tampered, 1 added, 0 removed, 2 modified`. |

When `ManifestIntact` is `false` the lists may be incomplete. They are empty when the manifest's algorithm could not be used at all, for example a keyed manifest verified without its key.

### Creating and verifying

| Method | Description |
|--------|-------------|
| `CreateAsync(rootPath, CancellationToken)` | SHA-256 manifest with default options. |
| `CreateAsync(rootPath, algorithm, options = null, CancellationToken)` | Manifest with any algorithm, keyed or not. |
| `VerifyAsync(rootPath, expected, CancellationToken)` | Walks with the manifest's own algorithm. Unkeyed manifests only. |
| `VerifyAsync(rootPath, expected, algorithm, options = null, CancellationToken)` | Walks with `algorithm`, or the manifest's unkeyed algorithm when `null`. |
| `VerifyAsync(rootPath, expected, trustedRoot, algorithm, options, CancellationToken)` | Also requires `expected.Root` to equal `trustedRoot`. |
| `Compare(expected, actual, algorithm = null)` | Compares two manifests you already have, without touching the disk. |
| `Compare(expected, actual, algorithm, trustedRoot)` | Same, with a trusted root. |
| `IsIntact()` / `IsIntact(algorithm)` | `true` when `Root` matches the entries. Keyed manifests need the algorithm. |
| `FromEntries(entries, algorithm)` | Builds a manifest from entries you made yourself. Sorts them and rejects duplicate paths and entries hashed with another algorithm (`ArgumentException`). |
| `ToMerkleTree(algorithm = null)` | The Merkle tree over the entries, for proving that one file is in the manifest. |
| `EncodeLeaf(entry)` | The Merkle leaf bytes of one entry. |

A manifest exposes `Algorithm` (the name, for example `sha256`), `KeyId` (`null` for unkeyed manifests), `Entries` (in ordinal path order) and `Root` (the recorded Merkle root, which `IsIntact` checks). `ToString()` returns a summary such as `2 files, root sha256:d469...`.

Pass the same `DirectoryManifestOptions` to `VerifyAsync` that you used for `CreateAsync`. A different filter or depth limit produces a different set of entries.

:::danger[A plain manifest root does not stop an attacker]

With SHA-256 or any unkeyed algorithm, anyone can rebuild a consistent manifest after changing files. `VerifyAsync` without a trusted root then reports a match. Either keep a copy of `Root` where the attacker cannot write and use the `trustedRoot` overload, or create the manifest with a keyed algorithm such as `ContentHashAlgorithm.HmacSha256`.

:::

### Options

`DirectoryManifestOptions` controls the walk.

| Option | Default | Description |
|--------|---------|-------------|
| `Filter` | `null` | `Func<string, bool>` on each file's or link's canonical relative path. Return `false` to leave it out. Directories are always walked. |
| `FollowReparsePoints` | `false` | When `false`, symbolic links, junctions and other reparse points are recorded as link entries and never followed. When `true`, links are followed and their targets hashed. |
| `MaxDepth` | `64` | Deepest directory nesting walked below the root. A non-empty directory deeper than this throws `IOException`. Must be 0 or more. |
| `MaxEntries` | `1,000,000` | Most file system entries (files, links and directories) visited before the walk throws `IOException`. Must be at least 1. |

An invalid `MaxDepth` or `MaxEntries` throws `ArgumentOutOfRangeException`.

```csharp
using System;
using Masterly.Hash.Integrity;

DirectoryManifestOptions options = new DirectoryManifestOptions
{
    Filter = path => !path.StartsWith("logs/", StringComparison.Ordinal),
    MaxDepth = 16,
};

DirectoryManifest manifest = await DirectoryManifest.CreateAsync("/srv/app", ContentHashAlgorithm.Sha256, options, cancellationToken);
```

:::warning

Anything the filter leaves out is outside tamper detection. A file planted under `logs/` in this example is never reported.

:::

### How the walk behaves

- **It fails closed.** Exceeding `MaxDepth` or `MaxEntries` throws `IOException` instead of silently leaving files out. Empty directories beyond `MaxDepth` hold nothing to verify and are skipped.
- **Links are recorded, not followed, by default.** Each link becomes an entry of kind `DirectoryManifestEntryKind.Link` holding the length and hash of its UTF-8 target text. Planting, removing or retargeting a link is reported, and the walk never reaches outside the root.
- **Following links stays bounded.** With `FollowReparsePoints = true`, a directory link that points back to one of its own ancestors, a broken link, and a link whose target kind differs (a file link to a directory or the reverse) are recorded as link entries instead of being followed. Other repeated targets are hashed once per path, bounded by `MaxDepth` and `MaxEntries`.
- **Zero-length files are not opened.** They are recorded as empty, so Unix FIFOs, sockets and device nodes, which report length 0, cannot block or flood the walk.
- **Verification never opens paths from the manifest.** It walks the directory, builds a fresh manifest and compares, so a hostile manifest cannot cause reads outside the root.
- **Paths must be representable.** A file name containing a backslash on Unix, or a path that is not canonical, throws `IOException`.
- **Cancellation** is checked for every entry and passed to every file read.

### Entries

`DirectoryManifestEntry` is one file or link.

| Member | Description |
|--------|-------------|
| `Path` | Canonical relative path with `/` separators. |
| `Length` | Length in bytes of the hashed content (the file, or the link target text). |
| `Hash` | `ContentHash` of the file, or of the link target text. |
| `Kind` | `DirectoryManifestEntryKind.File` or `DirectoryManifestEntryKind.Link`. |
| `IsCanonicalPath(path)` | `true` when a path is acceptable. |
| `MaxPathLength` | 4096 UTF-16 code units. |

A canonical path has `/` separators, no leading or trailing `/`, no empty, `.` or `..` segments, no backslashes, no control characters and no unpaired surrogates. The constructor throws `ArgumentException` for anything else, and `ArgumentOutOfRangeException` for a negative length or an unknown kind.

### JSON form

`ToJson(indented = true)` writes the manifest, and `FromJson` reads it back:

```json title="manifest.json"
{
  "format": "masterly-manifest/v1",
  "algorithm": "sha256",
  "root": "sha256:d46924f7f17b0aa70de3b07a20227c7bedf1bdc1a788ff7c2dabcdaa82d59b78",
  "files": [
    {
      "path": "bin/app.dll",
      "length": 6,
      "hash": "sha256:f6ae7280169c4d105385359fcdaeaed31f7f5b4b6a021a729736c1c40bfcccb3"
    },
    {
      "path": "readme.txt",
      "length": 5,
      "hash": "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    }
  ]
}
```

A link entry also carries `"kind": "link"`. For a keyed manifest, `algorithm` is `name:keyId`, for example `hmac-sha256:m1`. `DirectoryManifest.FormatId` is `masterly-manifest/v1`.

`FromJson` is strict and throws `FormatException` on anything unexpected. `TryFromJson` returns `false` instead and never throws. Both reject:

- unknown or repeated properties, a `kind` other than `"link"`, and a `format` other than `masterly-manifest/v1`;
- an `algorithm` that does not match the root's algorithm and key id, or an entry hashed with a different algorithm;
- non-canonical paths, and paths that are not in strictly ascending ordinal order (which also rules out duplicates);
- negative lengths, unregistered algorithm names, and JSON nested deeper than 8 levels.

Parsing does **not** check the root against the entries. Call `IsIntact()`, or use `VerifyAsync`, which does it for you.

### Keyed manifests

With a keyed algorithm, nobody without the key can produce a manifest that verifies.

```csharp
using Masterly.Hash.Integrity;

// key comes from your secret store
ContentHashAlgorithm mac = ContentHashAlgorithm.HmacSha256("m1", key);
DirectoryManifest manifest = await DirectoryManifest.CreateAsync("/srv/app", mac, null, cancellationToken);

DirectoryManifestDiff diff = await DirectoryManifest.VerifyAsync("/srv/app", manifest, mac, null, cancellationToken);
```

Without the key, or with a key for a different key id, `IsIntact` returns `false` and `VerifyAsync` returns `ManifestIntact = false`. No exception is thrown. `ToMerkleTree()` is the exception to this rule: called without the key on a keyed manifest, or with an algorithm whose name or key id differs from the manifest's, it throws `ArgumentException`.

### Leaf encoding

Each Merkle leaf is `field(tag) || field(utf8(path)) || u64(length) || field(digest)`, where `u64` is an 8-byte big-endian integer and `field(x)` is `u64(len(x)) || x`. The tag is `masterly-manifest/v1` for files and `masterly-manifest/v1:link` for links. Leaves are sorted by ordinal path and hashed into an RFC 9162 tree with the manifest's algorithm. An empty directory has the empty-tree root, which for SHA-256 is `sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

Because the root is a Merkle root, you can prove that one file is part of a manifest without shipping the whole list:

```csharp
using System.Collections.Generic;
using Masterly.Hash.Integrity;

// manifest is a SHA-256 DirectoryManifest; index is the position of the entry in manifest.Entries
MerkleTree tree = manifest.ToMerkleTree();
byte[] leaf = DirectoryManifest.EncodeLeaf(manifest.Entries[index]);
IReadOnlyList<byte[]> proof = tree.GetInclusionProof(index);

bool included = MerkleTree.VerifyInclusion(leaf, index, tree.Size, proof, manifest.Root.ToArray());
```

See [Merkle Trees and Hash Chains](./merkle-trees-and-hash-chains.md#inclusion-proofs) for how proofs work.

## Failure modes

| Situation | Result |
|-----------|--------|
| Content does not match | `false` |
| Stored hash for a different algorithm or key id | `false` (manifests: `ManifestIntact = false`) |
| Keyed stored hash, no algorithm passed | `false` (manifests: `ManifestIntact = false`, empty lists) |
| Malformed hash string | `Parse` throws `FormatException`; `TryParse` returns `false` |
| Malformed manifest JSON | `FromJson` throws `FormatException`; `TryFromJson` returns `false` |
| Invalid `ContentHash` in JSON | `JsonException` |
| HMAC key under 32 bytes, BLAKE3 key not 32 bytes, invalid key id or algorithm name | `ArgumentException` |
| Conflicting algorithm registration | `InvalidOperationException` |
| Manifest root directory missing | `DirectoryNotFoundException` |
| Walk exceeds `MaxDepth` or `MaxEntries`, or a path cannot be represented | `IOException` |
| File missing or unreadable | The file system exception, for example `FileNotFoundException`, `IOException` or `UnauthorizedAccessException` |
| Token cancelled | `OperationCanceledException` |

## When to use it

Use content hashes and manifests to:

- detect corruption in backups, caches, downloads and replicated files;
- detect unexpected changes to a deployed application or a plugin directory;
- give records a stable fingerprint you can index and compare.

Add a key (HMAC-SHA256 or keyed BLAKE3), or keep the root or hash out of the attacker's reach, when the person who might change the data could also change the stored hashes.

Do not use them to:

- hash passwords or other low-entropy secrets: these algorithms are fast, so guessing is cheap. Use the [password hasher](./hashing-and-verifying.md);
- look up records by a sensitive value: use a [blind index](./blind-indexes.md);
- issue API keys or signed tokens: see [API Keys and Tokens](./api-keys-and-tokens.md);
- prove who produced a file. An HMAC proves that someone holding the key produced it, and everyone who can verify can also create tags. If a third party must verify without being able to forge, you need a digital signature, which this package does not provide.

## Security notes

- Every verifier compares digests in constant time and treats the stored value as untrusted.
- `ToString()` on algorithms, hashes, entries and manifests never prints keys or file contents.
- Keep HMAC and BLAKE3 keys out of the store that holds the hashes. If both leak together, keyed hashes are no better than plain ones.
- A file that changes while it is being hashed produces a hash of whatever was read. Hash files that are no longer being written.

## See also

- [Merkle Trees and Hash Chains](./merkle-trees-and-hash-chains.md)
- [Blind Indexes](./blind-indexes.md)
- [Threat Model](./threat-model.md)
- [API Reference](./api-reference.md)
- [Masterly.Hash.Integrity README](https://github.com/a7mdfre7at/Masterly.Hash/blob/master/src/Masterly.Hash.Integrity/README.md)
- [Masterly.Hash.Integrity.Blake3 README](https://github.com/a7mdfre7at/Masterly.Hash/blob/master/src/Masterly.Hash.Integrity.Blake3/README.md)
