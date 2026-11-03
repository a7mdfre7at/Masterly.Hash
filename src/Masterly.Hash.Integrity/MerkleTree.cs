using System;
using System.Collections.Generic;
using Masterly.Hash.Primitives;

namespace Masterly.Hash.Integrity
{
    /// <summary>
    /// An immutable Merkle tree hashed as in RFC 9162 (Certificate Transparency v2), section 2.1:
    /// the empty tree is <c>HASH()</c>, a leaf is <c>HASH(0x00 || data)</c> and an interior node is
    /// <c>HASH(0x01 || left || right)</c>, where a list of n leaves is split at the largest power of two below n.
    /// Supports inclusion proofs (§2.1.3) and consistency proofs (§2.1.4) for the full tree and every earlier size.
    /// </summary>
    /// <remarks>
    /// RFC 9162 trees use SHA-256; other algorithms (including keyed ones) are accepted for private use, but proofs are
    /// then only verifiable with the same algorithm. Building is O(n); a proof costs O(log² n) hashes at most.
    /// </remarks>
    public sealed class MerkleTree
    {
        /// <summary>Upper bound on proof length accepted by the verifiers (a 2^63-leaf tree needs far fewer).</summary>
        public const int MaxProofLength = 128;

        private static readonly byte[] LeafPrefix = { 0x00 };
        private static readonly byte[] NodePrefix = { 0x01 };

        // _levels[j][i] is the hash of the complete subtree of 2^j leaves starting at leaf i * 2^j.
        private readonly List<byte[][]> _levels;
        private readonly byte[] _root;

        private MerkleTree(ContentHashAlgorithm algorithm, byte[][] leafHashes)
        {
            Algorithm = algorithm;
            _levels = new List<byte[][]> { leafHashes };
            using (ContentDigest digest = algorithm.CreateDigest())
            {
                byte[][] level = leafHashes;
                while (level.Length > 1)
                {
                    byte[][] next = new byte[level.Length / 2][];
                    for (int i = 0; i < next.Length; i++)
                        next[i] = HashChildren(digest, level[2 * i], level[2 * i + 1]);
                    _levels.Add(next);
                    level = next;
                }
                _root = SubtreeHash(digest, 0, leafHashes.Length);
            }
        }

        /// <summary>The hash function.</summary>
        public ContentHashAlgorithm Algorithm { get; }

        /// <summary>Number of leaves.</summary>
        public int Size => _levels[0].Length;

        /// <summary>The root hash (Merkle Tree Hash of all leaves). A copy.</summary>
        public byte[] Root => (byte[])_root.Clone();

        /// <summary>The root hash as a <see cref="ContentHash"/>.</summary>
        public ContentHash RootHash => ContentHash.FromOwned(Algorithm, (byte[])_root.Clone());

        /// <summary>Builds a SHA-256 tree over raw leaf data (each element is hashed as a leaf).</summary>
        public static MerkleTree Build(IEnumerable<byte[]> leaves) => Build(leaves, ContentHashAlgorithm.Sha256);

        /// <summary>Builds a tree over raw leaf data with <paramref name="algorithm"/>.</summary>
        public static MerkleTree Build(IEnumerable<byte[]> leaves, ContentHashAlgorithm algorithm)
        {
            if (leaves == null) throw new ArgumentNullException(nameof(leaves));
            if (algorithm == null) throw new ArgumentNullException(nameof(algorithm));
            var hashes = new List<byte[]>();
            using (ContentDigest digest = algorithm.CreateDigest())
            {
                foreach (byte[] leaf in leaves)
                {
                    if (leaf == null)
                        throw new ArgumentException("Leaves cannot contain null.", nameof(leaves));
                    hashes.Add(HashLeaf(digest, leaf));
                }
            }
            return new MerkleTree(algorithm, hashes.ToArray());
        }

        /// <summary>Builds a tree from leaf hashes that were already computed with <see cref="HashLeaf(byte[], ContentHashAlgorithm)"/>.</summary>
        public static MerkleTree FromLeafHashes(IEnumerable<byte[]> leafHashes, ContentHashAlgorithm algorithm)
        {
            if (leafHashes == null) throw new ArgumentNullException(nameof(leafHashes));
            if (algorithm == null) throw new ArgumentNullException(nameof(algorithm));
            var hashes = new List<byte[]>();
            foreach (byte[] hash in leafHashes)
            {
                if (hash == null || hash.Length != algorithm.DigestLength)
                    throw new ArgumentException($"Every leaf hash must be {algorithm.DigestLength} bytes.", nameof(leafHashes));
                hashes.Add((byte[])hash.Clone());
            }
            return new MerkleTree(algorithm, hashes.ToArray());
        }

        /// <summary>Root of the empty tree: <c>HASH()</c> (for SHA-256, e3b0c442...b855).</summary>
        public static byte[] EmptyRoot(ContentHashAlgorithm algorithm)
        {
            if (algorithm == null) throw new ArgumentNullException(nameof(algorithm));
            using (ContentDigest digest = algorithm.CreateDigest())
                return digest.GetHashAndReset();
        }

        /// <summary>Leaf hash <c>HASH(0x00 || data)</c>.</summary>
        public static byte[] HashLeaf(byte[] data, ContentHashAlgorithm algorithm)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));
            if (algorithm == null) throw new ArgumentNullException(nameof(algorithm));
            using (ContentDigest digest = algorithm.CreateDigest())
                return HashLeaf(digest, data);
        }

        /// <summary>Interior node hash <c>HASH(0x01 || left || right)</c>.</summary>
        public static byte[] HashChildren(byte[] left, byte[] right, ContentHashAlgorithm algorithm)
        {
            if (left == null) throw new ArgumentNullException(nameof(left));
            if (right == null) throw new ArgumentNullException(nameof(right));
            if (algorithm == null) throw new ArgumentNullException(nameof(algorithm));
            using (ContentDigest digest = algorithm.CreateDigest())
                return HashChildren(digest, left, right);
        }

        /// <summary>The leaf hash at <paramref name="index"/>. A copy.</summary>
        public byte[] GetLeafHash(int index)
        {
            if (index < 0 || index >= Size) throw new ArgumentOutOfRangeException(nameof(index));
            return (byte[])_levels[0][index].Clone();
        }

        /// <summary>Root of the tree formed by the first <paramref name="treeSize"/> leaves (0 to <see cref="Size"/>).</summary>
        public byte[] GetRoot(int treeSize)
        {
            if (treeSize < 0 || treeSize > Size) throw new ArgumentOutOfRangeException(nameof(treeSize));
            if (treeSize == Size)
                return Root;
            using (ContentDigest digest = Algorithm.CreateDigest())
                return Copy(SubtreeHash(digest, 0, treeSize));
        }

        /// <summary>Audit path for leaf <paramref name="index"/> in the full tree (RFC 9162 §2.1.3.1).</summary>
        public IReadOnlyList<byte[]> GetInclusionProof(int index) => GetInclusionProof(index, Size);

        /// <summary>Audit path for leaf <paramref name="index"/> in the tree of the first <paramref name="treeSize"/> leaves.</summary>
        public IReadOnlyList<byte[]> GetInclusionProof(int index, int treeSize)
        {
            if (treeSize < 1 || treeSize > Size) throw new ArgumentOutOfRangeException(nameof(treeSize));
            if (index < 0 || index >= treeSize) throw new ArgumentOutOfRangeException(nameof(index));
            var proof = new List<byte[]>();
            using (ContentDigest digest = Algorithm.CreateDigest())
                InclusionPath(digest, index, 0, treeSize, proof);
            return proof.AsReadOnly();
        }

        /// <summary>
        /// Proof that the tree of the first <paramref name="oldSize"/> leaves is a prefix of the full tree
        /// (RFC 9162 §2.1.4.1). Empty when <paramref name="oldSize"/> is 0 or equals <see cref="Size"/>.
        /// </summary>
        public IReadOnlyList<byte[]> GetConsistencyProof(int oldSize) => GetConsistencyProof(oldSize, Size);

        /// <summary>Consistency proof between two earlier sizes, <c>0 &lt;= oldSize &lt;= newSize &lt;= Size</c>.</summary>
        public IReadOnlyList<byte[]> GetConsistencyProof(int oldSize, int newSize)
        {
            if (newSize < 0 || newSize > Size) throw new ArgumentOutOfRangeException(nameof(newSize));
            if (oldSize < 0 || oldSize > newSize) throw new ArgumentOutOfRangeException(nameof(oldSize));
            var proof = new List<byte[]>();
            if (oldSize > 0 && oldSize < newSize)
            {
                using (ContentDigest digest = Algorithm.CreateDigest())
                    SubProof(digest, oldSize, 0, newSize, true, proof);
            }
            return proof.AsReadOnly();
        }

        /// <summary>Verifies that <paramref name="leafData"/> is leaf <paramref name="index"/> of a SHA-256 tree. Never throws on bad input.</summary>
        public static bool VerifyInclusion(byte[] leafData, long index, long treeSize, IReadOnlyList<byte[]> proof, byte[] root) =>
            VerifyInclusion(leafData, index, treeSize, proof, root, ContentHashAlgorithm.Sha256);

        /// <summary>Verifies that <paramref name="leafData"/> is leaf <paramref name="index"/> of the tree with <paramref name="root"/>. Never throws on bad input.</summary>
        public static bool VerifyInclusion(byte[] leafData, long index, long treeSize, IReadOnlyList<byte[]> proof, byte[] root, ContentHashAlgorithm algorithm)
        {
            if (algorithm == null) throw new ArgumentNullException(nameof(algorithm));
            if (leafData == null)
                return false;
            return VerifyInclusionOfLeafHash(HashLeaf(leafData, algorithm), index, treeSize, proof, root, algorithm);
        }

        /// <summary>
        /// RFC 9162 §2.1.3.2: verifies an audit path for a leaf hash. Returns false (never throws) for any malformed
        /// proof, out-of-range index, wrong hash lengths or mismatching root.
        /// </summary>
        public static bool VerifyInclusionOfLeafHash(byte[] leafHash, long index, long treeSize, IReadOnlyList<byte[]> proof, byte[] root, ContentHashAlgorithm algorithm)
        {
            if (algorithm == null) throw new ArgumentNullException(nameof(algorithm));
            int length = algorithm.DigestLength;
            if (leafHash == null || leafHash.Length != length || root == null || root.Length != length || !IsWellFormed(proof, length))
                return false;
            if (index < 0 || treeSize < 1 || index >= treeSize)
                return false;

            using (ContentDigest digest = algorithm.CreateDigest())
            {
                long fn = index;
                long sn = treeSize - 1;
                byte[] r = leafHash;
                foreach (byte[] p in proof)
                {
                    if (sn == 0)
                        return false;
                    if ((fn & 1) == 1 || fn == sn)
                    {
                        r = HashChildren(digest, p, r);
                        if ((fn & 1) == 0)
                        {
                            while ((fn & 1) == 0 && fn != 0)
                            {
                                fn >>= 1;
                                sn >>= 1;
                            }
                        }
                    }
                    else
                    {
                        r = HashChildren(digest, r, p);
                    }
                    fn >>= 1;
                    sn >>= 1;
                }
                return sn == 0 && HashPrimitives.FixedTimeEquals(r, root);
            }
        }

        /// <summary>Verifies a SHA-256 consistency proof. Never throws on bad input.</summary>
        public static bool VerifyConsistency(long oldSize, long newSize, byte[] oldRoot, byte[] newRoot, IReadOnlyList<byte[]> proof) =>
            VerifyConsistency(oldSize, newSize, oldRoot, newRoot, proof, ContentHashAlgorithm.Sha256);

        /// <summary>
        /// RFC 9162 §2.1.4.2: verifies that the tree with <paramref name="oldRoot"/> and <paramref name="oldSize"/> leaves
        /// is a prefix of the tree with <paramref name="newRoot"/>. Equal sizes need an empty proof and equal roots; an
        /// old size of zero needs an empty proof and the empty-tree root. Returns false (never throws) for bad input.
        /// </summary>
        public static bool VerifyConsistency(long oldSize, long newSize, byte[] oldRoot, byte[] newRoot, IReadOnlyList<byte[]> proof, ContentHashAlgorithm algorithm)
        {
            if (algorithm == null) throw new ArgumentNullException(nameof(algorithm));
            int length = algorithm.DigestLength;
            if (oldRoot == null || oldRoot.Length != length || newRoot == null || newRoot.Length != length || !IsWellFormed(proof, length))
                return false;
            if (oldSize < 0 || newSize < oldSize)
                return false;
            if (oldSize == newSize)
                return proof.Count == 0 && HashPrimitives.FixedTimeEquals(oldRoot, newRoot);
            if (oldSize == 0)
                return proof.Count == 0 && HashPrimitives.FixedTimeEquals(oldRoot, EmptyRoot(algorithm));
            if (proof.Count == 0)
                return false;

            var path = new List<byte[]>(proof.Count + 1);
            if ((oldSize & (oldSize - 1)) == 0)
                path.Add(oldRoot);
            path.AddRange(proof);

            long fn = oldSize - 1;
            long sn = newSize - 1;
            while ((fn & 1) == 1)
            {
                fn >>= 1;
                sn >>= 1;
            }

            using (ContentDigest digest = algorithm.CreateDigest())
            {
                byte[] fr = path[0];
                byte[] sr = path[0];
                for (int i = 1; i < path.Count; i++)
                {
                    byte[] c = path[i];
                    if (sn == 0)
                        return false;
                    if ((fn & 1) == 1 || fn == sn)
                    {
                        fr = HashChildren(digest, c, fr);
                        sr = HashChildren(digest, c, sr);
                        if ((fn & 1) == 0)
                        {
                            while ((fn & 1) == 0 && fn != 0)
                            {
                                fn >>= 1;
                                sn >>= 1;
                            }
                        }
                    }
                    else
                    {
                        sr = HashChildren(digest, sr, c);
                    }
                    fn >>= 1;
                    sn >>= 1;
                }

                bool oldMatches = HashPrimitives.FixedTimeEquals(fr, oldRoot);
                bool newMatches = HashPrimitives.FixedTimeEquals(sr, newRoot);
                return oldMatches & newMatches & (sn == 0);
            }
        }

        private static bool IsWellFormed(IReadOnlyList<byte[]>? proof, int length)
        {
            if (proof == null || proof.Count > MaxProofLength)
                return false;
            foreach (byte[] p in proof)
            {
                if (p == null || p.Length != length)
                    return false;
            }
            return true;
        }

        private static byte[] HashLeaf(ContentDigest digest, byte[] data)
        {
            digest.Append(LeafPrefix, 0, 1);
            digest.Append(data, 0, data.Length);
            return digest.GetHashAndReset();
        }

        private static byte[] HashChildren(ContentDigest digest, byte[] left, byte[] right)
        {
            digest.Append(NodePrefix, 0, 1);
            digest.Append(left, 0, left.Length);
            digest.Append(right, 0, right.Length);
            return digest.GetHashAndReset();
        }

        /// <summary>Largest power of two strictly less than <paramref name="n"/> (n &gt;= 2).</summary>
        private static int SplitPoint(int n)
        {
            int k = 1;
            while (k < n - k)
                k <<= 1;
            return k;
        }

        /// <summary>MTH(D[start : start + count]).</summary>
        private byte[] SubtreeHash(ContentDigest digest, int start, int count)
        {
            if (count == 0)
                return digest.GetHashAndReset();

            if ((count & (count - 1)) == 0 && start % count == 0)
            {
                int level = 0;
                while (1 << level < count)
                    level++;
                return _levels[level][start / count];
            }

            int k = SplitPoint(count);
            return HashChildren(digest, SubtreeHash(digest, start, k), SubtreeHash(digest, start + k, count - k));
        }

        /// <summary>PATH(m, D[start : start + count]).</summary>
        private void InclusionPath(ContentDigest digest, int m, int start, int count, List<byte[]> proof)
        {
            if (count <= 1)
                return;
            int k = SplitPoint(count);
            if (m < k)
            {
                InclusionPath(digest, m, start, k, proof);
                proof.Add(Copy(SubtreeHash(digest, start + k, count - k)));
            }
            else
            {
                InclusionPath(digest, m - k, start + k, count - k, proof);
                proof.Add(Copy(SubtreeHash(digest, start, k)));
            }
        }

        /// <summary>SUBPROOF(m, D[start : start + count], b).</summary>
        private void SubProof(ContentDigest digest, int m, int start, int count, bool complete, List<byte[]> proof)
        {
            if (m == count)
            {
                if (!complete)
                    proof.Add(Copy(SubtreeHash(digest, start, count)));
                return;
            }
            int k = SplitPoint(count);
            if (m <= k)
            {
                SubProof(digest, m, start, k, complete, proof);
                proof.Add(Copy(SubtreeHash(digest, start + k, count - k)));
            }
            else
            {
                SubProof(digest, m - k, start + k, count - k, false, proof);
                proof.Add(Copy(SubtreeHash(digest, start, k)));
            }
        }

        private static byte[] Copy(byte[] hash) => (byte[])hash.Clone();
    }
}
