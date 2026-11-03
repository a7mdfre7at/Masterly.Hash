# Masterly.Hash.Integrity

Tamper evidence for files and records, built on [Masterly.Hash](https://www.nuget.org/packages/Masterly.Hash):

- **Content hashes**: `sha256:<hex>`, `sha384:`, `sha512:` and keyed `hmac-sha256:<keyId>:<hex>`, computed from streams in pooled buffers. Verification is constant-time.
- **Merkle trees** (RFC 9162 / Certificate Transparency v2) with inclusion and consistency proofs.
- **Hash-chain audit logs**: every entry covers the previous one. With an HMAC key, someone who can write the database still cannot forge the chain.
- **Directory manifests**: per-file hashes plus a Merkle root. Verification reports added, removed and modified files. Manifests serialize to JSON.

Targets `net8.0`. Uses only the .NET cryptography APIs (no custom primitives).

## Install

```
dotnet add package Masterly.Hash.Integrity
```

## Quickstart

```csharp
using Masterly.Hash.Integrity;

// Content hashes
ContentHash hash = await ContentHasher.ComputeFileAsync("release.zip");   // sha256:9f86d0...
string stored = hash.ToString();
bool ok = await ContentHasher.VerifyFileAsync("release.zip", ContentHash.Parse(stored));

// Keyed (HMAC) hashes: the key never leaves your secret store
var mac = ContentHashAlgorithm.HmacSha256("k2026", key32Bytes);
ContentHash tag = ContentHasher.Compute(data, mac);                     // hmac-sha256:k2026:...

// Merkle trees (RFC 9162)
MerkleTree tree = MerkleTree.Build(records);
IReadOnlyList<byte[]> proof = tree.GetInclusionProof(5);
bool included = MerkleTree.VerifyInclusion(records[5], 5, tree.Size, proof, tree.Root);
IReadOnlyList<byte[]> consistency = tree.GetConsistencyProof(oldSize);
bool appendOnly = MerkleTree.VerifyConsistency(oldSize, tree.Size, oldRoot, tree.Root, consistency);

// Hash-chain audit log
var log = new HashChainLog(ContentHashAlgorithm.HmacSha256("audit-1", auditKey));
log.Append(Encoding.UTF8.GetBytes("user 42 changed role to admin"));
HashChainCheckpoint head = log.Head!;          // save this somewhere else, refresh it periodically
// Later (the chain may have grown since): the entry at head.Sequence must still be there, unchanged.
HashChainVerificationResult result = log.Verify(loadedEntries, head);
if (!result.IsValid)
    Console.WriteLine($"{result.Failure} at index {result.FirstBrokenIndex}");   // Gap, Reorder, HashMismatch, ...

// Directory manifests
DirectoryManifest manifest = await DirectoryManifest.CreateAsync("/srv/app");
File.WriteAllText("manifest.json", manifest.ToJson());
ContentHash trustedRoot = manifest.Root;       // keep this out of the attacker's reach
DirectoryManifestDiff diff = await DirectoryManifest.VerifyAsync(
    "/srv/app", DirectoryManifest.FromJson(json), trustedRoot, algorithm: null, options: null);
// diff.Added, diff.Removed, diff.Modified, diff.ManifestIntact, diff.IsMatch
```

If you persist the chain in a database, use `HashChain.CreateNext(previousEntry, payload, algorithm)` and
`HashChain.Verify(entries, algorithm, anchor, expectedHead)`.

## Encodings

- Hash chain entry: `H(field("masterly-hash-chain/v1") || field(algorithmId) || u64(seq) || field(prevHash) || field(payload))`. Here `u64` is 8-byte big-endian and `field(x) = u64(len(x)) || x`. Genesis previous hash: all zeros.
- Manifest leaf: `field(tag) || field(utf8(path)) || u64(length) || field(digest)`, with tag `masterly-manifest/v1` for files and `masterly-manifest/v1:link` for links (whose digest covers the UTF-8 link target text). Leaves are sorted by ordinal path, and the tree is hashed as in RFC 9162.

## Security notes

- A plain hash only detects *accidental* or *outside* changes. An attacker who can rewrite the data can also rewrite plain hashes. Use an HMAC algorithm with a key kept outside the data store, and/or keep the root or chain head somewhere the attacker cannot write (another system, a signed receipt, a transparency log).
- `HashChain.Verify` detects gaps, reordering, duplicates, edited entries and broken links. Pass a trusted head checkpoint to also detect truncation and rewritten history up to that checkpoint; the chain may keep growing past it. Entries after the newest checkpoint are protected only by the links (and the key, when keyed).
- A manifest's root only detects accidental or inconsistent edits when the algorithm is unkeyed: anyone can recompute it. Pass a trusted copy of the root to `VerifyAsync`/`Compare`, or use an HMAC algorithm.
- Manifest verification walks the directory and never opens paths taken from the manifest. Symbolic links, junctions and other reparse points are not followed by default; each is recorded as a `link` entry holding the hash of its target text, so planting, removing or retargeting a link is reported. With `FollowReparsePoints = true`, loops back to an ancestor and broken links are recorded as links instead of being followed.
- The walk fails closed: a non-empty directory deeper than `MaxDepth` (64) or more than `MaxEntries` (1,000,000) entries raises `IOException` instead of silently leaving files out. Zero-length files are recorded as empty without being opened, so FIFOs, sockets and device nodes cannot block or flood the walk.
- Verifiers return `false` or a failure result, and do not throw, for malformed stored values and for a stored algorithm or key id that differs from the one supplied (treat that as tampering, or pick the key by `KeyId` during rotation). Manifest verification can still throw `IOException` for file system errors. Proof lengths are capped.
- The HMAC algorithm's identity covers its name and key id, never the key material. `ToString()` never prints keys or payloads.
