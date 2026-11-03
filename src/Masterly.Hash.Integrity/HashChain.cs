using System;
using System.Collections.Generic;
using System.Text;
using Masterly.Hash.Integrity.Internal;
using Masterly.Hash.Primitives;

namespace Masterly.Hash.Integrity
{
    /// <summary>
    /// Tamper-evident hash chains: every entry's hash covers its sequence number, its payload and the previous entry's
    /// hash, so changing, removing, inserting or reordering any entry breaks every link after it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The entry hash is <c>H(field("masterly-hash-chain/v1") || field(algorithmIdentifier) || u64(sequence) ||
    /// field(previousHash) || field(payload))</c>, where <c>u64</c> is 8-byte big-endian and <c>field(x)</c> is
    /// <c>u64(len(x)) || x</c>. The encoding is unambiguous, so no two different entries share an input.
    /// </para>
    /// <para>
    /// With a plain hash anyone who can write the store can recompute the whole chain after editing it. Use a keyed
    /// algorithm (<see cref="ContentHashAlgorithm.HmacSha256"/>) with a key kept outside the store, and/or save the
    /// chain head (<see cref="HashChainEntry.ToCheckpoint"/>) somewhere the attacker cannot reach, so truncation and
    /// rewrites are caught.
    /// </para>
    /// </remarks>
    public static class HashChain
    {
        private static readonly byte[] DomainTag = Encoding.ASCII.GetBytes("masterly-hash-chain/v1");

        /// <summary>The previous hash of the first entry: <see cref="ContentHashAlgorithm.DigestLength"/> zero bytes.</summary>
        public static byte[] GenesisHash(ContentHashAlgorithm algorithm)
        {
            if (algorithm == null) throw new ArgumentNullException(nameof(algorithm));
            return new byte[algorithm.DigestLength];
        }

        /// <summary>SHA-256 entry hash. See <see cref="ComputeEntryHash(byte[], byte[], long, ContentHashAlgorithm)"/>.</summary>
        public static byte[] ComputeEntryHash(byte[] previousHash, byte[] payload, long sequence) =>
            ComputeEntryHash(previousHash, payload, sequence, ContentHashAlgorithm.Sha256);

        /// <summary>Computes the hash of an entry from its canonical, length-prefixed encoding.</summary>
        /// <param name="previousHash">Hash of the previous entry, or <see cref="GenesisHash"/> for sequence 0.</param>
        /// <param name="payload">The entry payload (may be empty).</param>
        /// <param name="sequence">Position in the chain, starting at 0.</param>
        /// <param name="algorithm">Hash or MAC; the algorithm identifier (including any key id) is bound into the hash.</param>
        public static byte[] ComputeEntryHash(byte[] previousHash, byte[] payload, long sequence, ContentHashAlgorithm algorithm)
        {
            if (previousHash == null) throw new ArgumentNullException(nameof(previousHash));
            if (payload == null) throw new ArgumentNullException(nameof(payload));
            if (algorithm == null) throw new ArgumentNullException(nameof(algorithm));
            if (sequence < 0) throw new ArgumentOutOfRangeException(nameof(sequence), sequence, "Sequence cannot be negative.");
            if (previousHash.Length != algorithm.DigestLength)
                throw new ArgumentException($"Previous hash must be {algorithm.DigestLength} bytes for {algorithm.Name}.", nameof(previousHash));

            using (ContentDigest digest = algorithm.CreateDigest())
                return ComputeCore(digest, algorithm, previousHash, payload, sequence);
        }

        /// <summary>
        /// Creates the entry that follows <paramref name="previous"/> (or the first entry when it is <see langword="null"/>).
        /// Use this when the chain lives in a database rather than in a <see cref="HashChainLog"/>.
        /// </summary>
        public static HashChainEntry CreateNext(HashChainEntry? previous, byte[] payload, ContentHashAlgorithm algorithm)
        {
            if (payload == null) throw new ArgumentNullException(nameof(payload));
            if (algorithm == null) throw new ArgumentNullException(nameof(algorithm));
            if (previous != null && previous.HashBytes.Length != algorithm.DigestLength)
                throw new ArgumentException("The previous entry was not produced by this algorithm.", nameof(previous));

            long sequence = previous == null ? 0 : checked(previous.Sequence + 1);
            byte[] previousHash = previous == null ? GenesisHash(algorithm) : (byte[])previous.HashBytes.Clone();
            byte[] copy = (byte[])payload.Clone();
            byte[] hash = ComputeEntryHash(previousHash, copy, sequence, algorithm);
            return HashChainEntry.FromOwned(sequence, previousHash, copy, hash);
        }

        /// <summary>SHA-256 verification of a complete chain starting at sequence 0. Never throws on bad entries.</summary>
        public static HashChainVerificationResult Verify(IEnumerable<HashChainEntry> entries) =>
            Verify(entries, ContentHashAlgorithm.Sha256, null, null);

        /// <summary>Verifies a complete chain starting at sequence 0. Never throws on bad entries.</summary>
        public static HashChainVerificationResult Verify(IEnumerable<HashChainEntry> entries, ContentHashAlgorithm algorithm) =>
            Verify(entries, algorithm, null, null);

        /// <summary>
        /// Verifies a chain, or a segment of one. Checks, in order for every entry: sequence continuity (reporting a
        /// <see cref="HashChainFailure.Gap"/>, <see cref="HashChainFailure.Reorder"/> or
        /// <see cref="HashChainFailure.Duplicate"/>), the link to the previous hash, and the entry's own hash. Stops at
        /// the first broken entry. Never throws on bad entries.
        /// </summary>
        /// <param name="entries">Entries in storage order.</param>
        /// <param name="algorithm">The algorithm the chain was built with.</param>
        /// <param name="anchor">
        /// A trusted checkpoint the segment continues from: the first entry must have sequence
        /// <c>anchor.Sequence + 1</c> and link to <c>anchor.Hash</c>. <see langword="null"/> means the segment starts
        /// at sequence 0 with the genesis hash.
        /// </param>
        /// <param name="expectedHead">
        /// A trusted checkpoint taken earlier (for example <see cref="HashChainLog.Head"/> saved out of the attacker's
        /// reach). When given, the entry at <c>expectedHead.Sequence</c> must be present and have exactly that hash;
        /// the chain may legitimately continue past it. A chain that ends before the checkpoint is
        /// <see cref="HashChainFailure.Truncated"/>; a different entry at that sequence (a rewritten history) is
        /// <see cref="HashChainFailure.HeadMismatch"/>. Entries appended after the checkpoint are covered only by the
        /// chain links (and the key, when keyed), so refresh the checkpoint regularly.
        /// </param>
        public static HashChainVerificationResult Verify(
            IEnumerable<HashChainEntry> entries,
            ContentHashAlgorithm algorithm,
            HashChainCheckpoint? anchor,
            HashChainCheckpoint? expectedHead)
        {
            if (entries == null) throw new ArgumentNullException(nameof(entries));
            if (algorithm == null) throw new ArgumentNullException(nameof(algorithm));

            var list = entries as IReadOnlyList<HashChainEntry> ?? new List<HashChainEntry>(entries);
            // pastEnd: the previous entry (or the anchor) is at long.MaxValue, so nothing can follow it. Tracked as a flag
            // because expectedSequence = previous + 1 would overflow.
            bool pastEnd = anchor != null && anchor.Sequence == long.MaxValue;
            // Held at long.MaxValue while pastEnd: the null-entry check below still reports it as the broken sequence.
            long expectedSequence = anchor == null ? 0 : pastEnd ? long.MaxValue : anchor.Sequence + 1;
            byte[] expectedPrevious = anchor == null ? GenesisHash(algorithm) : anchor.HashBytes;
            HashChainEntry? last = null;

            using (ContentDigest digest = algorithm.CreateDigest())
            {
                for (int i = 0; i < list.Count; i++)
                {
                    HashChainEntry entry = list[i];
                    if (entry == null)
                        return HashChainVerificationResult.Broken(i, i, expectedSequence, HashChainFailure.InvalidEntry, "Entry is null.");

                    if (pastEnd)
                        return entry.Sequence == long.MaxValue
                            ? HashChainVerificationResult.Broken(i, i, entry.Sequence, HashChainFailure.Duplicate, $"Sequence {entry.Sequence} appears twice.")
                            : HashChainVerificationResult.Broken(i, i, entry.Sequence, HashChainFailure.Reorder, $"No entry can follow sequence {long.MaxValue}, but found {entry.Sequence}.");

                    if (entry.Sequence != expectedSequence)
                        return SequenceFailure(list, i, expectedSequence);

                    if (!HashPrimitives.FixedTimeEquals(entry.PreviousHashBytes, expectedPrevious))
                        return HashChainVerificationResult.Broken(i, i, entry.Sequence, HashChainFailure.PreviousHashMismatch,
                            "Entry does not link to the hash of the entry before it.");

                    bool hashOk = entry.HashBytes.Length == algorithm.DigestLength;
                    if (hashOk)
                    {
                        byte[] actual = ComputeCore(digest, algorithm, entry.PreviousHashBytes, entry.PayloadBytes, entry.Sequence);
                        hashOk = HashPrimitives.FixedTimeEquals(actual, entry.HashBytes);
                    }
                    if (!hashOk)
                        return HashChainVerificationResult.Broken(i, i, entry.Sequence, HashChainFailure.HashMismatch,
                            "Entry hash does not match its contents.");

                    if (expectedHead != null && entry.Sequence == expectedHead.Sequence &&
                        !HashPrimitives.FixedTimeEquals(entry.HashBytes, expectedHead.HashBytes))
                        return HashChainVerificationResult.Broken(i, i, entry.Sequence, HashChainFailure.HeadMismatch,
                            "The entry at the trusted checkpoint's sequence does not match it.");

                    expectedPrevious = entry.HashBytes;
                    pastEnd = entry.Sequence == long.MaxValue;
                    expectedSequence = pastEnd ? long.MaxValue : entry.Sequence + 1;
                    last = entry;
                }
            }

            if (expectedHead != null)
            {
                long lastSequence = last?.Sequence ?? (anchor?.Sequence ?? -1);
                if (lastSequence < expectedHead.Sequence)
                    return HashChainVerificationResult.Broken(list.Count, list.Count, lastSequence + 1, HashChainFailure.Truncated,
                        "The chain ends before the trusted head checkpoint.");

                // Entries at the checkpoint's sequence were checked in the loop. A checkpoint at or before the anchor
                // can only be confirmed by the anchor itself.
                // (Compared as <= anchor.Sequence: anchor.Sequence + 1 would overflow at long.MaxValue.)
                bool beforeSegment = anchor == null ? expectedHead.Sequence < 0 : expectedHead.Sequence <= anchor.Sequence;
                if (beforeSegment)
                {
                    bool anchorMatches = anchor != null && anchor.Sequence == expectedHead.Sequence &&
                                         HashPrimitives.FixedTimeEquals(anchor.HashBytes, expectedHead.HashBytes);
                    if (!anchorMatches)
                        return HashChainVerificationResult.Broken(0, 0, expectedHead.Sequence, HashChainFailure.HeadMismatch,
                            "The trusted head checkpoint is not covered by this segment or its anchor.");
                }
            }

            return HashChainVerificationResult.Valid(list.Count, last?.ToCheckpoint());
        }

        private static HashChainVerificationResult SequenceFailure(IReadOnlyList<HashChainEntry> list, int index, long expected)
        {
            long actual = list[index].Sequence;
            if (actual < expected)
            {
                bool duplicate = index > 0 && list[index - 1] != null && list[index - 1].Sequence == actual;
                return duplicate
                    ? HashChainVerificationResult.Broken(index, index, actual, HashChainFailure.Duplicate, $"Sequence {actual} appears twice.")
                    : HashChainVerificationResult.Broken(index, index, actual, HashChainFailure.Reorder, $"Expected sequence {expected} but found {actual}.");
            }

            // A higher number is a reorder if the expected entry turns up later, otherwise entries are missing.
            for (int j = index + 1; j < list.Count; j++)
            {
                if (list[j] != null && list[j].Sequence == expected)
                    return HashChainVerificationResult.Broken(index, index, actual, HashChainFailure.Reorder, $"Expected sequence {expected} but found {actual}.");
            }
            return HashChainVerificationResult.Broken(index, index, actual, HashChainFailure.Gap, $"Sequence {expected} to {actual - 1} is missing.");
        }

        private static byte[] ComputeCore(ContentDigest digest, ContentHashAlgorithm algorithm, byte[] previousHash, byte[] payload, long sequence)
        {
            digest.AppendField(DomainTag);
            digest.AppendField(Encoding.ASCII.GetBytes(algorithm.Identifier));
            digest.AppendUInt64((ulong)sequence);
            digest.AppendField(previousHash);
            digest.AppendField(payload);
            return digest.GetHashAndReset();
        }
    }

    /// <summary>Why a hash chain failed verification.</summary>
    public enum HashChainFailure
    {
        /// <summary>The chain is intact.</summary>
        None = 0,

        /// <summary>One or more sequence numbers are missing (entries were deleted).</summary>
        Gap,

        /// <summary>Entries are out of order.</summary>
        Reorder,

        /// <summary>A sequence number appears more than once.</summary>
        Duplicate,

        /// <summary>An entry's previous-hash field does not equal the previous entry's hash (an entry was replaced or inserted).</summary>
        PreviousHashMismatch,

        /// <summary>An entry's hash does not match its payload, sequence and link (the entry was edited).</summary>
        HashMismatch,

        /// <summary>The input contained a null entry.</summary>
        InvalidEntry,

        /// <summary>The chain ends before the trusted head checkpoint (newest entries were deleted).</summary>
        Truncated,

        /// <summary>The entry at the trusted head checkpoint's sequence differs from it (history up to the checkpoint was rewritten).</summary>
        HeadMismatch,
    }

    /// <summary>Outcome of <see cref="HashChain.Verify(IEnumerable{HashChainEntry}, ContentHashAlgorithm, HashChainCheckpoint, HashChainCheckpoint)"/>.</summary>
    public sealed class HashChainVerificationResult
    {
        private HashChainVerificationResult(bool isValid, int entriesVerified, int? firstBrokenIndex, long? brokenSequence,
            HashChainFailure failure, string? reason, HashChainCheckpoint? head)
        {
            IsValid = isValid;
            EntriesVerified = entriesVerified;
            FirstBrokenIndex = firstBrokenIndex;
            BrokenSequence = brokenSequence;
            Failure = failure;
            Reason = reason;
            Head = head;
        }

        /// <summary>True if every entry verified and the chain contains any expected head checkpoint.</summary>
        public bool IsValid { get; }

        /// <summary>Number of entries that verified before the first failure (all of them when valid).</summary>
        public int EntriesVerified { get; }

        /// <summary>Position (in the input order) of the first broken entry; <see langword="null"/> when valid.</summary>
        public int? FirstBrokenIndex { get; }

        /// <summary>Sequence number found (or expected) at the break; <see langword="null"/> when valid.</summary>
        public long? BrokenSequence { get; }

        /// <summary>What went wrong; <see cref="HashChainFailure.None"/> when valid.</summary>
        public HashChainFailure Failure { get; }

        /// <summary>Human-readable explanation. Never contains payloads or hashes.</summary>
        public string? Reason { get; }

        /// <summary>Checkpoint of the last verified entry when valid; <see langword="null"/> for an empty segment or a failure.</summary>
        public HashChainCheckpoint? Head { get; }

        internal static HashChainVerificationResult Valid(int count, HashChainCheckpoint? head) =>
            new HashChainVerificationResult(true, count, null, null, HashChainFailure.None, null, head);

        internal static HashChainVerificationResult Broken(int index, int verified, long sequence, HashChainFailure failure, string reason) =>
            new HashChainVerificationResult(false, Math.Max(0, verified), Math.Max(0, index), sequence, failure, reason, null);

        /// <inheritdoc />
        public override string ToString() =>
            IsValid ? $"Valid ({EntriesVerified} entries)" : $"{Failure} at index {FirstBrokenIndex}: {Reason}";
    }
}
