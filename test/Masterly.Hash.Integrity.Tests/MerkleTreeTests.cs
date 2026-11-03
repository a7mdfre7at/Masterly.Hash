using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using static Masterly.Hash.Integrity.Tests.TestUtil;

namespace Masterly.Hash.Integrity.Tests;

public class MerkleTreeTests
{
    // Reference test tree used by Certificate Transparency's RFC 6962 implementations
    // (identical hashing in RFC 9162 §2.1). Source: github.com/transparency-dev/merkle,
    // testonly/constants.go (LeafInputs, NodeHashes, RootHashes) and proof/verify_test.go at tag v0.0.1
    // (inclusionProofs, consistencyProofs); the same vectors appear in google/certificate-transparency
    // cpp/merkletree/merkle_tree_test.cc.
    private static readonly byte[][] CtLeaves =
    {
        Array.Empty<byte>(),
        Hex("00"),
        Hex("10"),
        Hex("2021"),
        Hex("3031"),
        Hex("40414243"),
        Hex("5051525354555657"),
        Hex("606162636465666768696a6b6c6d6e6f"),
    };

    private static readonly string[] CtRoots =
    {
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
        "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
        "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
        "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
        "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
        "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
        "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
        "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
    };

    private static readonly string[] CtLeafHashes =
    {
        "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
        "96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7",
        "0298d122906dcfc10892cb53a73992fc5b9f493ea4c9badb27b791b4127a7fe7",
        "07506a85fd9dd2f120eb694f86011e5bb4662e5c415a62917033d4a9624487e7",
        "bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b",
        "4271a26be0d8a84f0bd54c8c302e7cb3a3b5d1fa6780a40bcce2873477dab658",
        "b08693ec2e721597130641e8211e7eedccb4c26413963eee6c1e2ed16ffb1a5f",
        "46f6ffadd3d06a09ff3c5860d2755c8b9819db7df44251788c7d8e3180de8eb1",
    };

    // (leaf index, tree size, audit path). verify_test.go uses 1-based leaf numbers; converted to 0-based here.
    public static IEnumerable<object[]> CtInclusionProofs() => new[]
    {
        new object[] { 0, 8, new[] { "96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7", "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e", "6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4" } },
        new object[] { 5, 8, new[] { "bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b", "ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0", "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7" } },
        new object[] { 2, 3, new[] { "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125" } },
        new object[] { 1, 5, new[] { "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d", "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e", "bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b" } },
        new object[] { 0, 1, Array.Empty<string>() },
    };

    public static IEnumerable<object[]> CtConsistencyProofs() => new[]
    {
        new object[] { 1, 1, Array.Empty<string>() },
        new object[] { 1, 8, new[] { "96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7", "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e", "6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4" } },
        new object[] { 6, 8, new[] { "0ebc5d3437fbe2db158b9f126a1d118e308181031d0a949f8dededebc558ef6a", "ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0", "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7" } },
        new object[] { 2, 5, new[] { "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e", "bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b" } },
        new object[] { 6, 7, new[] { "0ebc5d3437fbe2db158b9f126a1d118e308181031d0a949f8dededebc558ef6a", "b08693ec2e721597130641e8211e7eedccb4c26413963eee6c1e2ed16ffb1a5f", "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7" } },
    };

    private static readonly MerkleTree CtTree = MerkleTree.Build(CtLeaves);

    [Fact]
    public void EmptyTree_RootIsSha256OfEmptyString()
    {
        MerkleTree tree = MerkleTree.Build(Array.Empty<byte[]>());
        Assert.Equal(0, tree.Size);
        Assert.Equal(CtRoots[0], ToHex(tree.Root));
        Assert.Equal(CtRoots[0], ToHex(MerkleTree.EmptyRoot(ContentHashAlgorithm.Sha256)));
        Assert.Equal("sha256:" + CtRoots[0], tree.RootHash.ToString());
        Assert.Empty(tree.GetConsistencyProof(0));
    }

    [Fact]
    public void CtReferenceTree_RootsForEverySize()
    {
        for (int n = 0; n <= 8; n++)
        {
            Assert.Equal(CtRoots[n], ToHex(MerkleTree.Build(CtLeaves.Take(n)).Root));
            Assert.Equal(CtRoots[n], ToHex(CtTree.GetRoot(n)));
        }
    }

    [Fact]
    public void CtReferenceTree_LeafHashes()
    {
        for (int i = 0; i < 8; i++)
        {
            Assert.Equal(CtLeafHashes[i], ToHex(CtTree.GetLeafHash(i)));
            Assert.Equal(CtLeafHashes[i], ToHex(MerkleTree.HashLeaf(CtLeaves[i], ContentHashAlgorithm.Sha256)));
        }
        Assert.Equal(CtRoots[2], ToHex(MerkleTree.HashChildren(Hex(CtLeafHashes[0]), Hex(CtLeafHashes[1]), ContentHashAlgorithm.Sha256)));
    }

    [Theory]
    [MemberData(nameof(CtInclusionProofs))]
    public void CtReferenceTree_InclusionProofs(int index, int size, string[] expected)
    {
        IReadOnlyList<byte[]> proof = CtTree.GetInclusionProof(index, size);
        Assert.Equal(expected, proof.Select(ToHex).ToArray());
        Assert.True(MerkleTree.VerifyInclusion(CtLeaves[index], index, size, expected.Select(Hex).ToList(), Hex(CtRoots[size])));
    }

    [Theory]
    [MemberData(nameof(CtConsistencyProofs))]
    public void CtReferenceTree_ConsistencyProofs(int oldSize, int newSize, string[] expected)
    {
        IReadOnlyList<byte[]> proof = CtTree.GetConsistencyProof(oldSize, newSize);
        Assert.Equal(expected, proof.Select(ToHex).ToArray());
        Assert.True(MerkleTree.VerifyConsistency(oldSize, newSize, Hex(CtRoots[oldSize]), Hex(CtRoots[newSize]), expected.Select(Hex).ToList()));
    }

    [Fact]
    public void Roots_MatchRfcDefinition_ForSizes0To70()
    {
        // Independent, literal transcription of RFC 9162 §2.1.1 MTH, using SHA256.HashData directly.
        byte[][] leaves = Enumerable.Range(0, 70).Select(i => new[] { (byte)i, (byte)(i * 7) }).ToArray();
        for (int n = 0; n <= leaves.Length; n++)
            Assert.Equal(ToHex(ReferenceMth(leaves, 0, n)), ToHex(MerkleTree.Build(leaves.Take(n)).Root));
    }

    [Fact]
    public void InclusionProofs_AllVerify_AndAllTamperingFails_Sizes1To64()
    {
        byte[][] leaves = Enumerable.Range(0, 64).Select(i => Utf8("leaf-" + i)).ToArray();
        MerkleTree tree = MerkleTree.Build(leaves);
        for (int n = 1; n <= 64; n++)
        {
            byte[] root = tree.GetRoot(n);
            for (int i = 0; i < n; i++)
            {
                IReadOnlyList<byte[]> proof = tree.GetInclusionProof(i, n);
                Assert.True(MerkleTree.VerifyInclusion(leaves[i], i, n, proof, root), $"leaf {i} of {n}");

                Assert.False(MerkleTree.VerifyInclusion(Flip(leaves[i]), i, n, proof, root));
                Assert.False(MerkleTree.VerifyInclusion(leaves[i], i, n, proof, Flip(root)));
                if (n > 1)
                {
                    Assert.False(MerkleTree.VerifyInclusion(leaves[i], (i + 1) % n, n, proof, root));
                    Assert.False(MerkleTree.VerifyInclusion(leaves[(i + 1) % n], i, n, proof, root));
                }
                Assert.False(MerkleTree.VerifyInclusion(leaves[i], i, i, proof, root));
                for (int p = 0; p < proof.Count; p++)
                {
                    var tampered = proof.ToList();
                    tampered[p] = Flip(tampered[p], p);
                    Assert.False(MerkleTree.VerifyInclusion(leaves[i], i, n, tampered, root));
                }
                if (proof.Count > 0)
                {
                    Assert.False(MerkleTree.VerifyInclusion(leaves[i], i, n, proof.Take(proof.Count - 1).ToList(), root));
                    if (proof.Count > 1)
                        Assert.False(MerkleTree.VerifyInclusion(leaves[i], i, n, proof.Reverse().ToList(), root));
                }
                Assert.False(MerkleTree.VerifyInclusion(leaves[i], i, n, proof.Concat(new[] { root }).ToList(), root));
            }
        }
    }

    [Fact]
    public void ConsistencyProofs_AllVerify_AndTamperingFails_AllPairsUpTo32()
    {
        byte[][] leaves = Enumerable.Range(0, 32).Select(i => Utf8("entry-" + i)).ToArray();
        MerkleTree tree = MerkleTree.Build(leaves);
        for (int n = 0; n <= 32; n++)
        {
            byte[] newRoot = tree.GetRoot(n);
            for (int m = 0; m <= n; m++)
            {
                byte[] oldRoot = tree.GetRoot(m);
                IReadOnlyList<byte[]> proof = tree.GetConsistencyProof(m, n);
                Assert.True(MerkleTree.VerifyConsistency(m, n, oldRoot, newRoot, proof), $"{m} -> {n}");

                // A separately built tree of the same leaves yields the same proof.
                if (m < n && n == 32)
                    Assert.Equal(proof.Select(ToHex), MerkleTree.Build(leaves).GetConsistencyProof(m).Select(ToHex));

                Assert.False(MerkleTree.VerifyConsistency(m, n, Flip(oldRoot), newRoot, proof));
                // The empty tree is a prefix of every tree, so any new root is consistent with size 0.
                Assert.Equal(m == 0 && n > 0, MerkleTree.VerifyConsistency(m, n, oldRoot, Flip(newRoot), proof));
                for (int p = 0; p < proof.Count; p++)
                {
                    var tampered = proof.ToList();
                    tampered[p] = Flip(tampered[p], p);
                    Assert.False(MerkleTree.VerifyConsistency(m, n, oldRoot, newRoot, tampered), $"{m} -> {n} tampered {p}");
                }
                if (proof.Count > 0)
                    Assert.False(MerkleTree.VerifyConsistency(m, n, oldRoot, newRoot, proof.Take(proof.Count - 1).ToList()));
                if (m > 0 && m < n)
                {
                    Assert.False(MerkleTree.VerifyConsistency(m, n, oldRoot, newRoot, proof.Concat(new[] { newRoot }).ToList()));
                    // Claiming the old tree is the new one (or swapping roots) must fail.
                    Assert.False(MerkleTree.VerifyConsistency(m, n, newRoot, oldRoot, proof));
                }
            }
        }
    }

    [Fact]
    public void Consistency_RejectsForkedHistory()
    {
        byte[][] honest = Enumerable.Range(0, 10).Select(i => Utf8("h" + i)).ToArray();
        byte[][] forked = honest.ToArray();
        forked[3] = Utf8("rewritten");
        MerkleTree old = MerkleTree.Build(honest.Take(6));
        MerkleTree fork = MerkleTree.Build(forked);
        Assert.False(MerkleTree.VerifyConsistency(6, 10, old.Root, fork.Root, fork.GetConsistencyProof(6)));
    }

    [Fact]
    public void Verifiers_NeverThrowOnMalformedInput()
    {
        byte[] root = CtTree.Root;
        var proof = CtTree.GetInclusionProof(3).ToList();
        Assert.False(MerkleTree.VerifyInclusion(null!, 3, 8, proof, root));
        Assert.False(MerkleTree.VerifyInclusion(CtLeaves[3], 3, 8, null!, root));
        Assert.False(MerkleTree.VerifyInclusion(CtLeaves[3], 3, 8, proof, null!));
        Assert.False(MerkleTree.VerifyInclusion(CtLeaves[3], 3, 8, new List<byte[]> { null!, proof[1], proof[2] }, root));
        Assert.False(MerkleTree.VerifyInclusion(CtLeaves[3], 3, 8, new List<byte[]> { new byte[31], proof[1], proof[2] }, root));
        Assert.False(MerkleTree.VerifyInclusion(CtLeaves[3], 3, 8, proof, new byte[33]));
        Assert.False(MerkleTree.VerifyInclusion(CtLeaves[3], -1, 8, proof, root));
        Assert.False(MerkleTree.VerifyInclusion(CtLeaves[3], 3, -8, proof, root));
        Assert.False(MerkleTree.VerifyInclusion(CtLeaves[3], 3, 0, proof, root));
        Assert.False(MerkleTree.VerifyInclusion(CtLeaves[3], long.MaxValue, long.MaxValue, proof, root));
        Assert.False(MerkleTree.VerifyInclusion(CtLeaves[3], 3, long.MaxValue, proof, root));
        Assert.False(MerkleTree.VerifyInclusion(CtLeaves[3], 3, 8, Enumerable.Repeat(proof[0], 10_000).ToList(), root));
        Assert.False(MerkleTree.VerifyInclusionOfLeafHash(new byte[5], 3, 8, proof, root, ContentHashAlgorithm.Sha256));

        var consistency = CtTree.GetConsistencyProof(6).ToList();
        byte[] old = CtTree.GetRoot(6);
        Assert.False(MerkleTree.VerifyConsistency(6, 8, old, root, null!));
        Assert.False(MerkleTree.VerifyConsistency(6, 8, null!, root, consistency));
        Assert.False(MerkleTree.VerifyConsistency(6, 8, old, null!, consistency));
        Assert.False(MerkleTree.VerifyConsistency(-1, 8, old, root, consistency));
        Assert.False(MerkleTree.VerifyConsistency(9, 8, old, root, consistency));
        Assert.False(MerkleTree.VerifyConsistency(6, 8, old, root, new List<byte[]>()));
        Assert.False(MerkleTree.VerifyConsistency(6, long.MaxValue, old, root, consistency));
        Assert.False(MerkleTree.VerifyConsistency(long.MaxValue - 1, long.MaxValue, old, root, consistency));
        Assert.False(MerkleTree.VerifyConsistency(6, 8, old, root, new List<byte[]> { null! }));
        Assert.False(MerkleTree.VerifyConsistency(6, 8, old, root, Enumerable.Repeat(consistency[0], 10_000).ToList()));
        // Degenerate sizes: equal sizes need equal roots and an empty proof; size 0 needs the empty root.
        Assert.True(MerkleTree.VerifyConsistency(8, 8, root, root, new List<byte[]>()));
        Assert.False(MerkleTree.VerifyConsistency(8, 8, root, root, consistency));
        Assert.False(MerkleTree.VerifyConsistency(8, 8, old, root, new List<byte[]>()));
        Assert.True(MerkleTree.VerifyConsistency(0, 8, Hex(CtRoots[0]), root, new List<byte[]>()));
        Assert.False(MerkleTree.VerifyConsistency(0, 8, old, root, new List<byte[]>()));
    }

    [Fact]
    public void Arguments_AreGuarded()
    {
        Assert.Throws<ArgumentNullException>(() => MerkleTree.Build(null!));
        Assert.Throws<ArgumentException>(() => MerkleTree.Build(new byte[][] { null! }));
        Assert.Throws<ArgumentOutOfRangeException>(() => CtTree.GetInclusionProof(8));
        Assert.Throws<ArgumentOutOfRangeException>(() => CtTree.GetInclusionProof(-1));
        Assert.Throws<ArgumentOutOfRangeException>(() => CtTree.GetInclusionProof(0, 9));
        Assert.Throws<ArgumentOutOfRangeException>(() => CtTree.GetConsistencyProof(9));
        Assert.Throws<ArgumentOutOfRangeException>(() => CtTree.GetConsistencyProof(5, 4));
        Assert.Throws<ArgumentOutOfRangeException>(() => CtTree.GetRoot(9));
        Assert.Throws<ArgumentOutOfRangeException>(() => CtTree.GetLeafHash(8));
        Assert.Throws<ArgumentException>(() => MerkleTree.FromLeafHashes(new[] { new byte[31] }, ContentHashAlgorithm.Sha256));
        Assert.Throws<ArgumentNullException>(() => MerkleTree.VerifyInclusion(CtLeaves[0], 0, 1, new List<byte[]>(), CtTree.Root, null!));
    }

    [Fact]
    public void FromLeafHashes_MatchesBuild_AndOutputsAreCopies()
    {
        MerkleTree fromHashes = MerkleTree.FromLeafHashes(CtLeafHashes.Select(Hex), ContentHashAlgorithm.Sha256);
        Assert.Equal(CtRoots[8], ToHex(fromHashes.Root));

        byte[] root = CtTree.Root;
        root[0] ^= 1;
        Assert.Equal(CtRoots[8], ToHex(CtTree.Root));
        CtTree.GetInclusionProof(0)[0][0] ^= 1;
        Assert.Equal(CtInclusionProofs().First()[2], CtTree.GetInclusionProof(0).Select(ToHex).ToArray());
    }

    [Fact]
    public void OtherAlgorithms_ProduceVerifiableProofs()
    {
        foreach (ContentHashAlgorithm algorithm in new[] { ContentHashAlgorithm.Sha512, Hmac("tree") })
        {
            byte[][] leaves = Enumerable.Range(0, 13).Select(i => Utf8("x" + i)).ToArray();
            MerkleTree tree = MerkleTree.Build(leaves, algorithm);
            Assert.Equal(algorithm.DigestLength, tree.Root.Length);
            Assert.True(MerkleTree.VerifyInclusion(leaves[7], 7, 13, tree.GetInclusionProof(7), tree.Root, algorithm));
            Assert.False(MerkleTree.VerifyInclusion(leaves[7], 7, 13, tree.GetInclusionProof(7), tree.Root));
            Assert.True(MerkleTree.VerifyConsistency(5, 13, tree.GetRoot(5), tree.Root, tree.GetConsistencyProof(5), algorithm));
        }

        // A keyed tree cannot be reproduced without the key.
        byte[][] data = { Utf8("a"), Utf8("b") };
        Assert.NotEqual(ToHex(MerkleTree.Build(data, Hmac("k", "1")).Root), ToHex(MerkleTree.Build(data, Hmac("k", "2")).Root));
    }

    [Fact]
    public void LeafAndNodeDomainsAreSeparated()
    {
        // A two-leaf tree's root must not equal a single leaf whose data is the concatenated child hashes
        // (the second-preimage attack RFC 9162's 0x00/0x01 prefixes prevent).
        MerkleTree two = MerkleTree.Build(new[] { Utf8("a"), Utf8("b") });
        byte[] forged = two.GetLeafHash(0).Concat(two.GetLeafHash(1)).ToArray();
        Assert.NotEqual(ToHex(two.Root), ToHex(MerkleTree.Build(new[] { forged }).Root));
    }

    private static byte[] ReferenceMth(byte[][] d, int start, int n)
    {
        if (n == 0)
            return SHA256.HashData(Array.Empty<byte>());
        if (n == 1)
            return SHA256.HashData(new byte[] { 0x00 }.Concat(d[start]).ToArray());
        int k = 1;
        while (k * 2 < n)
            k *= 2;
        return SHA256.HashData(new byte[] { 0x01 }.Concat(ReferenceMth(d, start, k)).Concat(ReferenceMth(d, start + k, n - k)).ToArray());
    }
}
