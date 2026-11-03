# Masterly.Hash.Integrity.Blake3

Adds [BLAKE3](https://github.com/BLAKE3-team/BLAKE3) to [Masterly.Hash.Integrity](https://www.nuget.org/packages/Masterly.Hash.Integrity) in two modes: plain (`blake3:<hex>`) and keyed (`blake3-keyed:<keyId>:<hex>`). You can use it anywhere that package accepts a `ContentHashAlgorithm`: content hashes, Merkle trees, hash chains and directory manifests.

The hashing comes from the fully managed, SIMD-accelerated [`Blake3`](https://www.nuget.org/packages/Blake3) package (BSD-2-Clause). Targets `net8.0`.

## Install

```
dotnet add package Masterly.Hash.Integrity.Blake3
```

## Quickstart

```csharp
using Masterly.Hash.Integrity;
using Masterly.Hash.Integrity.Blake3;

Blake3Algorithms.Register();   // once at startup, so "blake3:..." strings parse

ContentHash hash = await ContentHasher.ComputeFileAsync("big.iso", Blake3Algorithms.Blake3);
bool ok = await ContentHasher.VerifyFileAsync("big.iso", ContentHash.Parse(hash.ToString()));

var mac = Blake3Algorithms.Keyed("k1", key32Bytes);
DirectoryManifest manifest = await DirectoryManifest.CreateAsync("/srv/app", mac);
```

## Security notes

- Plain BLAKE3 detects changes but anyone can recompute it. If an attacker may also rewrite the stored hashes, use `Keyed` with a key kept outside the data store.
- Keys must be exactly 32 bytes and should be random (for example `HashPrimitives.RandomBytes(32)`). The key is copied when the algorithm is created. The hasher state is cleared when each digest is disposed.
- Merkle trees built with BLAKE3 use the RFC 9162 structure, but they are not interoperable with Certificate Transparency, which requires SHA-256.
