---
title: "Merkle Trees and Hash Chains"
sidebar_label: "Merkle Trees and Hash Chains"
description: "RFC 9162 Merkle trees with inclusion and consistency proofs, and keyed hash-chain audit logs."
---

`Masterly.Hash.Integrity` has two structures that make a list of records tamper-evident. A **Merkle tree** (RFC 9162, the hashing used by Certificate Transparency v2) lets you prove that one record is in a set, and that a later version of the set only appended to an earlier one. A **hash chain** links every record to the one before it, so editing, deleting, inserting or reordering any record breaks the chain. Content hashes, algorithms and directory manifests are covered in [Integrity and Tamper Evidence](./integrity.md).

```bash
dotnet add package Masterly.Hash.Integrity
```

## Which one to use

| You need to | Use |
|-------------|-----|
| Prove to someone else that one record is part of a published set, without sending the whole set | Merkle tree, inclusion proof |
| Prove that a new version of a log contains an old version unchanged, with only new records added | Merkle tree, consistency proof |
| Keep an append-only audit log in your own database and detect edits, deletions and reordering | Hash chain |
| Detect deleted newest records, or a history rewritten from the start | Hash chain plus a trusted checkpoint |

Both structures accept any `ContentHashAlgorithm`, including keyed ones such as `ContentHashAlgorithm.HmacSha256` and BLAKE3. SHA-256 is the default.

## Merkle trees

### How the tree is hashed

`MerkleTree` follows RFC 9162 section 2.1 exactly:

| Node | Hash |
|------|------|
| Empty tree | `HASH()` |
| Leaf | `HASH(0x00 \|\| data)` |
| Interior node | `HASH(0x01 \|\| left \|\| right)` |

A list of `n` leaves is split at the largest power of two strictly less than `n`. The `0x00` and `0x01` prefixes keep leaves and interior nodes apart, so a leaf can never be passed off as a subtree (the second-preimage attack the RFC prevents).

The implementation is tested against the Certificate Transparency reference tree. For SHA-256, the empty-tree root is `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

### Building a tree

**1. Collect the leaf data** in a fixed order. Each element is hashed as one leaf.

**2. Build the tree** and keep the root.

```csharp title="Program.cs"
using System.Collections.Generic;
using System.Text;
using Masterly.Hash.Integrity;

List<byte[]> records = new List<byte[]>
{
    Encoding.UTF8.GetBytes("release 1.0.0"),
    Encoding.UTF8.GetBytes("release 1.0.1"),
    Encoding.UTF8.GetBytes("release 1.1.0"),
};

MerkleTree tree = MerkleTree.Build(records);   // SHA-256

byte[] root = tree.Root;                // 32 bytes, a copy
ContentHash rootHash = tree.RootHash;   // "sha256:..."
int size = tree.Size;                   // 3
```

**3. Publish the tree head**: the size and the root together. A root means nothing without the size it was computed for.

```csharp
string published = $"{tree.Size} {tree.RootHash}";
```

To use another algorithm, pass it to `Build`:

```csharp
MerkleTree sha512Tree = MerkleTree.Build(records, ContentHashAlgorithm.Sha512);
```

### Inclusion proofs

An inclusion proof (an audit path, RFC 9162 section 2.1.3) shows that one leaf is part of a tree with a given root. It holds at most about log2(n) hashes, so a proof for a tree of a million leaves is about 20 hashes.

**On the server**, produce the proof:

```csharp
using System.Collections.Generic;
using Masterly.Hash.Integrity;

IReadOnlyList<byte[]> proof = tree.GetInclusionProof(1);
```

**On the verifier**, check it against the leaf data, its index, the tree size and a root you trust:

```csharp
// leafData, index, treeSize and proof come from the server; trustedRoot comes from the published tree head
bool included = MerkleTree.VerifyInclusion(leafData, index, treeSize, proof, trustedRoot);
```

`VerifyInclusion` returns `false`, and never throws, for any bad input: a malformed or overlong proof, an out-of-range index, hashes of the wrong length, or a root that does not match. It only throws `ArgumentNullException` when `algorithm` is `null`.

If the verifier already has the leaf hash rather than the leaf data, use `VerifyInclusionOfLeafHash(leafHash, index, treeSize, proof, root, algorithm)`.

You can also prove inclusion in an earlier version of the tree. `GetInclusionProof(index, treeSize)` builds the proof against the first `treeSize` leaves, and `GetRoot(treeSize)` returns that version's root.

```csharp
IReadOnlyList<byte[]> oldProof = tree.GetInclusionProof(0, 2);
bool inOldTree = MerkleTree.VerifyInclusion(records[0], 0, 2, oldProof, tree.GetRoot(2));
```

### Consistency proofs

A consistency proof (RFC 9162 section 2.1.4) shows that the tree of the first `oldSize` leaves is a prefix of a larger tree. In other words, nothing that was published before has been changed or removed: the log only grew. Clients that remember an old tree head use it to check every new one.

```csharp
using System.Collections.Generic;
using Masterly.Hash.Integrity;

// oldSize and oldRoot are a tree head published earlier
IReadOnlyList<byte[]> consistency = tree.GetConsistencyProof(oldSize);

bool appendOnly = MerkleTree.VerifyConsistency(oldSize, tree.Size, oldRoot, tree.Root, consistency);
```

The rules `VerifyConsistency` applies:

- Equal sizes need an empty proof and equal roots.
- An old size of 0 needs an empty proof and the empty-tree root (`MerkleTree.EmptyRoot(algorithm)`).
- Any other valid pair needs a non-empty proof.
- A negative old size, a new size smaller than the old one, hashes of the wrong length or a forked history all return `false`. Like the inclusion verifier, it never throws on bad input.

`GetConsistencyProof(oldSize, newSize)` builds a proof between two earlier sizes, where `0 <= oldSize <= newSize <= Size`. The proof is empty when `oldSize` is 0 or equals `newSize`.

### Sending proofs over the wire

Proofs are lists of byte arrays. Encode them in whatever format your API uses. Any `IReadOnlyList<byte[]>`, such as `List<byte[]>`, works on the verifying side.

```csharp
using System;
using System.Collections.Generic;
using System.Linq;

string[] encoded = proof.Select(Convert.ToBase64String).ToArray();

// on the verifier
List<byte[]> decoded = encoded.Select(Convert.FromBase64String).ToList();
```

The root travels well as its `ContentHash` string, `tree.RootHash.ToString()`. On the verifier, `ContentHash.Parse(value).ToArray()` gives the bytes back.

### MerkleTree reference

| Member | Description |
|--------|-------------|
| `Build(leaves)` | SHA-256 tree over raw leaf data. |
| `Build(leaves, algorithm)` | Tree with any algorithm. |
| `FromLeafHashes(leafHashes, algorithm)` | Tree from leaf hashes you already computed with `HashLeaf`. Each must be exactly `DigestLength` bytes. |
| `Algorithm` | The hash function. |
| `Size` | Number of leaves (`int`). |
| `Root` | Root hash bytes. A copy. |
| `RootHash` | Root as a `ContentHash`, for example `sha256:...`. |
| `GetLeafHash(index)` | One leaf hash. A copy. |
| `GetRoot(treeSize)` | Root of the first `treeSize` leaves, 0 to `Size`. |
| `GetInclusionProof(index)` / `GetInclusionProof(index, treeSize)` | Audit path in the full tree, or in the first `treeSize` leaves. |
| `GetConsistencyProof(oldSize)` / `GetConsistencyProof(oldSize, newSize)` | Consistency proof up to the full tree, or between two earlier sizes. |
| `VerifyInclusion(leafData, index, treeSize, proof, root)` | SHA-256 inclusion check. An overload takes an `algorithm`. |
| `VerifyInclusionOfLeafHash(leafHash, index, treeSize, proof, root, algorithm)` | Inclusion check from a leaf hash. |
| `VerifyConsistency(oldSize, newSize, oldRoot, newRoot, proof)` | SHA-256 consistency check. An overload takes an `algorithm`. |
| `EmptyRoot(algorithm)` | `HASH()` for that algorithm. |
| `HashLeaf(data, algorithm)` | `HASH(0x00 \|\| data)`. |
| `HashChildren(left, right, algorithm)` | `HASH(0x01 \|\| left \|\| right)`. |
| `MaxProofLength` | 128. Verifiers reject longer proofs. |

### Limits and errors

- **Memory.** The tree keeps every complete subtree hash, about `2n` digests for `n` leaves. Building costs O(n) hashes. A proof costs at most O(log² n) hashes to produce.
- **Size.** A tree holds up to `int.MaxValue` leaves. The verifiers take `long` indexes and sizes, so they can check proofs from larger trees built elsewhere, up to 128 proof hashes.
- **Immutability.** A tree never changes after it is built. To add records, build a new tree; then prove the new tree consistent with the old one.
- **Argument errors.** `Build` throws `ArgumentException` when a leaf is `null`. `FromLeafHashes` throws `ArgumentException` for a `null` hash or one of the wrong length. `GetLeafHash`, `GetRoot`, `GetInclusionProof` and `GetConsistencyProof` throw `ArgumentOutOfRangeException` for indexes and sizes outside the tree. `GetInclusionProof` needs a tree size of at least 1.

### Choosing the algorithm

- Use SHA-256 when anyone else must verify your proofs, and for Certificate Transparency style logs. Proofs only verify with the algorithm the tree was built with.
- `Build` hashes whatever bytes you pass as leaf data. To interoperate with an existing Certificate Transparency log you must pass its exact leaf encoding.
- A tree built with HMAC-SHA256 or keyed BLAKE3 can only be recomputed and verified by someone holding the key. That is useful for private trees, and useless for proofs to outsiders.

## Hash chains

### How an entry is hashed

Every entry has a sequence number (starting at 0), the hash of the previous entry, a payload and its own hash:

```text
hash = H( field("masterly-hash-chain/v1") || field(algorithmIdentifier) || u64(sequence)
          || field(previousHash) || field(payload) )
```

`u64` is an 8-byte big-endian integer and `field(x)` is `u64(len(x)) || x`, so no two different entries share an input. The first entry's previous hash is `DigestLength` zero bytes (`HashChain.GenesisHash(algorithm)`). The algorithm identifier, including any key id such as `hmac-sha256:audit-1`, is bound into every hash.

### An in-memory log

`HashChainLog` is a thread-safe, append-only log held in memory. Use it when the whole log fits in memory, or to build entries that you persist yourself.

**1. Create the log with a key.** With a plain hash, anyone who can write the stored entries can recompute a consistent chain after editing it. With HMAC-SHA256 and a key kept outside the store, they cannot.

```csharp title="AuditLog.cs"
using System;
using System.Text;
using Masterly.Hash.Integrity;

// auditKey is a 32-byte key from your secret store
ContentHashAlgorithm mac = ContentHashAlgorithm.HmacSha256("audit-1", auditKey);
HashChainLog log = new HashChainLog(mac);
```

**2. Append entries.** The payload is copied.

```csharp
HashChainEntry entry = log.Append(Encoding.UTF8.GetBytes("user 42 changed role to admin"));
```

**3. Save the head somewhere else**, and refresh it regularly. See [Checkpoints](#checkpoints).

```csharp
HashChainCheckpoint? head = log.Head;   // null while the log is empty
```

**4. Verify** the entries, for example after loading them back from storage.

```csharp
// loadedEntries come from your storage; trustedHead is a checkpoint you saved earlier
HashChainVerificationResult result = log.Verify(loadedEntries, trustedHead);
if (!result.IsValid)
{
    Console.WriteLine($"{result.Failure} at index {result.FirstBrokenIndex}: {result.Reason}");
}
```

| `HashChainLog` member | Description |
|-----------------------|-------------|
| `new HashChainLog()` | Empty SHA-256 log. |
| `new HashChainLog(algorithm)` | Empty log with any algorithm. |
| `new HashChainLog(algorithm, existing)` | Loads a persisted chain and verifies it from sequence 0 first. Throws `InvalidDataException` when it is not a valid chain, so appends always continue a valid one. |
| `Algorithm` | The hash function or MAC. |
| `Count` | Number of entries. |
| `Entries` | A snapshot array of the entries, oldest first. |
| `Head` | Checkpoint of the newest entry; `null` when empty. |
| `Append(payload)` | Appends and returns the new entry. |
| `Verify()` | Verifies the log's own entries. |
| `Verify(entries)` | Verifies other entries with the log's algorithm. |
| `Verify(entries, expectedHead)` | Also requires the chain to contain `expectedHead`. |

### Chains in a database

When the chain lives in a table, skip `HashChainLog` and call `HashChain.CreateNext` and `HashChain.Verify` directly. Entries do not record which algorithm or key made them, so store the key id alongside the rows if you rotate keys.

```csharp title="AuditRecord.cs"
using System;

namespace MyApp.Audit;

public sealed class AuditRecord
{
    public long Sequence { get; set; }

    public byte[] PreviousHash { get; set; } = Array.Empty<byte>();

    public byte[] Payload { get; set; } = Array.Empty<byte>();

    public byte[] Hash { get; set; } = Array.Empty<byte>();
}
```

**1. Append** by linking to the newest stored row.

```csharp title="AuditWriter.cs"
using System.Linq;
using Masterly.Hash.Integrity;
using Microsoft.EntityFrameworkCore;
using MyApp.Audit;

// db is your EF Core DbContext; mac is the chain's algorithm; payload is the event to record
AuditRecord? last = await db.AuditRecords
    .OrderByDescending(r => r.Sequence)
    .FirstOrDefaultAsync(cancellationToken);

HashChainEntry? previous = last == null
    ? null
    : new HashChainEntry(last.Sequence, last.PreviousHash, last.Payload, last.Hash);

HashChainEntry next = HashChain.CreateNext(previous, payload, mac);

db.AuditRecords.Add(new AuditRecord
{
    Sequence = next.Sequence,
    PreviousHash = next.PreviousHash.ToArray(),
    Payload = next.Payload.ToArray(),
    Hash = next.Hash.ToArray(),
});
await db.SaveChangesAsync(cancellationToken);
```

:::warning[Concurrent writers]

Two writers that read the same newest row both create the same next sequence number. Make `Sequence` the primary key or a unique index so the second insert fails, then retry it. Otherwise verification later reports a `Duplicate` or `PreviousHashMismatch` that is your own bug, not an attack.

:::

**2. Verify** by loading the rows in sequence order.

```csharp title="AuditVerifier.cs"
using System.Collections.Generic;
using System.Linq;
using Masterly.Hash.Integrity;
using Microsoft.EntityFrameworkCore;

// trustedHead is a HashChainCheckpoint saved out of the attacker's reach
List<HashChainEntry> entries = await db.AuditRecords
    .AsNoTracking()
    .OrderBy(r => r.Sequence)
    .Select(r => new HashChainEntry(r.Sequence, r.PreviousHash, r.Payload, r.Hash))
    .ToListAsync(cancellationToken);

HashChainVerificationResult result = HashChain.Verify(entries, mac, null, trustedHead);
```

`CreateNext` does not verify `previous`; it links to whatever hash the row holds. A tampered row is still caught by the next verification. `CreateNext` throws `ArgumentException` when `previous` has a hash of a different length than the algorithm's digest. `new HashChainEntry(...)` verifies nothing; it copies the arrays and throws `ArgumentOutOfRangeException` for a negative sequence.

### HashChain reference

| Member | Description |
|--------|-------------|
| `GenesisHash(algorithm)` | The previous hash of sequence 0: `DigestLength` zero bytes. |
| `ComputeEntryHash(previousHash, payload, sequence)` | SHA-256 entry hash. An overload takes an `algorithm`. Throws `ArgumentException` when `previousHash` has the wrong length and `ArgumentOutOfRangeException` for a negative sequence. |
| `CreateNext(previous, payload, algorithm)` | The entry after `previous`, or the first entry when `previous` is `null`. |
| `Verify(entries)` | SHA-256, whole chain from sequence 0. |
| `Verify(entries, algorithm)` | Whole chain from sequence 0. |
| `Verify(entries, algorithm, anchor, expectedHead)` | A chain or a segment, with optional checkpoints. |

`HashChainEntry` exposes `Sequence`, `PreviousHash`, `Payload` and `Hash` (as `ReadOnlyMemory<byte>`) and `ToCheckpoint()`. Its `ToString()` prints only the sequence and payload length, for example `#7 (42 bytes)`.

### Checkpoints

Links alone cannot catch two attacks: deleting the newest entries, and rewriting the whole chain from the start (possible for anyone with a plain hash, or anyone holding the key). A **checkpoint**, a trusted `(sequence, hash)` pair, catches both.

**1. Take a checkpoint** from `HashChainLog.Head` or `entry.ToCheckpoint()`.

**2. Store it out of the attacker's reach**: a different system, a signed receipt, a printed report. Persist `checkpoint.Sequence` and `checkpoint.Hash.ToArray()`.

**3. Pass it as `expectedHead`** when you verify. Rebuild it with `new HashChainCheckpoint(sequence, hash)`, which copies the hash and throws `ArgumentOutOfRangeException` for a negative sequence. Its `ToString()` prints only the sequence, for example `#41`.

With an expected head, the entry at `expectedHead.Sequence` must be present and have exactly that hash. The chain may legitimately continue past it.

| Situation | Result |
|-----------|--------|
| The chain ends before the checkpoint | `Truncated` |
| A different entry sits at the checkpoint's sequence | `HeadMismatch` |
| The chain contains the checkpoint and continues past it | Valid |

:::note

Entries appended after the newest checkpoint are protected only by the links, and by the key when the chain is keyed. Deleting them goes unnoticed until you take a new checkpoint, so refresh checkpoints on a schedule that matches how much history you can afford to lose silently.

:::

### Verifying in segments

An `anchor` is a trusted checkpoint a segment continues from: the segment's first entry must have sequence `anchor.Sequence + 1` and link to `anchor.Hash`. Without an anchor, the segment must start at sequence 0 with the genesis hash.

Anchors let you verify a long chain page by page, because `Verify` loads its input into a list. When a page is valid, `result.Head` is a checkpoint of its last entry and becomes the next page's anchor. Pass `expectedHead` only with the page that contains its sequence. A page that ends before it reports `Truncated`, and a page that starts after it reports `HeadMismatch` unless the anchor is that checkpoint.

```csharp title="AuditVerifier.cs"
using System;
using System.Collections.Generic;
using Masterly.Hash.Integrity;

// LoadPageAsync is your own query: up to pageSize entries with Sequence > afterSequence, in sequence order
HashChainCheckpoint? anchor = null;
bool headSeen = false;
while (true)
{
    long afterSequence = anchor?.Sequence ?? -1;
    List<HashChainEntry> page = await LoadPageAsync(afterSequence, 10_000, cancellationToken);
    if (page.Count == 0)
    {
        break;
    }

    bool coversHead = page[0].Sequence <= trustedHead.Sequence && trustedHead.Sequence <= page[page.Count - 1].Sequence;
    HashChainVerificationResult result = HashChain.Verify(page, mac, anchor, coversHead ? trustedHead : null);
    if (!result.IsValid)
    {
        Console.WriteLine(result);
        return;
    }

    headSeen |= coversHead;
    anchor = result.Head;
}

if (!headSeen)
{
    Console.WriteLine("The chain ends before the trusted checkpoint.");
}
```

### Verification results

`Verify` checks, for every entry in order: sequence continuity, the link to the previous hash, the entry's own hash and, at the checkpoint's sequence, the checkpoint. It stops at the first broken entry and never throws on bad entries. Only a `null` `entries` or `algorithm` throws `ArgumentNullException`.

| `HashChainFailure` | Meaning |
|--------------------|---------|
| `None` | The chain is intact. |
| `Gap` | One or more sequence numbers are missing (entries were deleted). |
| `Reorder` | Entries are out of order. |
| `Duplicate` | A sequence number appears more than once. |
| `PreviousHashMismatch` | An entry does not link to the hash of the entry before it (an entry was replaced or inserted). |
| `HashMismatch` | An entry's hash does not match its payload, sequence and link (the entry was edited, or it was made with another key or algorithm). |
| `InvalidEntry` | The input contained a `null` entry. |
| `Truncated` | The chain ends before the trusted head checkpoint. |
| `HeadMismatch` | The entry at the checkpoint's sequence differs from it, or the checkpoint is at or before the segment's anchor and is not the anchor itself. |

| `HashChainVerificationResult` member | Description |
|--------------------------------------|-------------|
| `IsValid` | Every entry verified and the chain contains any expected head. |
| `EntriesVerified` | Entries that verified before the first failure; all of them when valid. |
| `FirstBrokenIndex` | Position in the input of the first broken entry; `null` when valid. For `Truncated`, the input length. |
| `BrokenSequence` | Sequence number found, or expected, at the break; `null` when valid. |
| `Failure` | The `HashChainFailure`. |
| `Reason` | A human-readable explanation. Never contains payloads or hashes. |
| `Head` | Checkpoint of the last verified entry when valid; `null` for an empty segment or a failure. |
| `ToString()` | `Valid (n entries)` or `Failure at index i: reason`. |

An empty chain is valid unless you pass an expected head, in which case it is `Truncated` (an empty segment whose anchor is the expected head itself is still valid).

### Rotating the chain key

A single `Verify` call uses one algorithm, and the key id is part of every hash. To change keys, start a new segment:

**1. Link the first new-key entry** to the last old-key entry: `HashChain.CreateNext(lastOldEntry, payload, newMac)`. This works because both algorithms have the same digest length.

**2. Record the key id** for each row, since entries do not store it.

**3. Verify each key's segment separately**, anchoring each one at the end of the previous segment.

```csharp
using Masterly.Hash.Integrity;

// oldEntries were written with oldMac, newEntries with newMac
HashChainVerificationResult oldSegment = HashChain.Verify(oldEntries, oldMac, null, null);
HashChainVerificationResult newSegment = HashChain.Verify(newEntries, newMac, oldSegment.Head, trustedHead);
```

Check `oldSegment.IsValid` before you use its `Head`: it is `null` after a failure.

### Limits

- Sequence numbers run from 0 to `long.MaxValue`. `CreateNext` throws `OverflowException` past that, and nothing can follow `long.MaxValue` in a verified chain.
- `HashChainLog.Entries` copies the whole list on every call, and `HashChain.Verify` materializes its input. For long chains, verify in segments.
- `HashChainLog` keeps entries only in memory. Persist them yourself.

## Security notes

- **Plain hashes resist accidents, not attackers.** With SHA-256, an attacker who can write the store can recompute a consistent chain or tree. Use a keyed algorithm, keep checkpoints or published tree heads out of the attacker's reach, or both.
- **Keyed chains resist forgery, not deletion of the newest entries.** Without a fresh checkpoint, removing the tail leaves a shorter but valid chain.
- **Whoever holds the key can rewrite history.** A checkpoint stored outside that person's control is what stops them.
- **Payloads are stored as given.** A chain gives integrity, not confidentiality. Do not record secrets or unnecessary personal data in payloads.
- **Verifiers treat input as untrusted.** Proofs longer than `MaxProofLength` (128) are rejected, hashes of the wrong length return `false`, and malformed entries produce a failure result instead of an exception.

## See also

- [Integrity and Tamper Evidence](./integrity.md)
- [Attack Detection](./attack-detection.md)
- [Threat Model](./threat-model.md)
- [API Reference](./api-reference.md)
- [RFC 9162, Certificate Transparency Version 2.0](https://www.rfc-editor.org/rfc/rfc9162)
- [Masterly.Hash.Integrity README](https://github.com/a7mdfre7at/Masterly.Hash/blob/master/src/Masterly.Hash.Integrity/README.md)
