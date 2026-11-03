using System;

namespace Masterly.Hash.Integrity
{
    /// <summary>
    /// One record of a tamper-evident hash chain: its sequence number, the hash of the previous entry, the payload and
    /// its own hash. Immutable; the byte arrays are copied on construction.
    /// </summary>
    public sealed class HashChainEntry
    {
        /// <summary>Creates an entry, e.g. when loading a chain from storage. Nothing is verified here.</summary>
        public HashChainEntry(long sequence, byte[] previousHash, byte[] payload, byte[] hash)
        {
            if (previousHash == null) throw new ArgumentNullException(nameof(previousHash));
            if (payload == null) throw new ArgumentNullException(nameof(payload));
            if (hash == null) throw new ArgumentNullException(nameof(hash));
            if (sequence < 0) throw new ArgumentOutOfRangeException(nameof(sequence), sequence, "Sequence cannot be negative.");
            Sequence = sequence;
            PreviousHashBytes = (byte[])previousHash.Clone();
            PayloadBytes = (byte[])payload.Clone();
            HashBytes = (byte[])hash.Clone();
        }

        private HashChainEntry(long sequence, byte[] previousHash, byte[] payload, byte[] hash, bool owned)
        {
            _ = owned;
            Sequence = sequence;
            PreviousHashBytes = previousHash;
            PayloadBytes = payload;
            HashBytes = hash;
        }

        /// <summary>Position in the chain, starting at 0.</summary>
        public long Sequence { get; }

        /// <summary>Hash of the previous entry, or the genesis hash (all zeros) for the first entry.</summary>
        public ReadOnlyMemory<byte> PreviousHash => PreviousHashBytes;

        /// <summary>The recorded payload.</summary>
        public ReadOnlyMemory<byte> Payload => PayloadBytes;

        /// <summary>This entry's hash, which the next entry links to.</summary>
        public ReadOnlyMemory<byte> Hash => HashBytes;

        internal byte[] PreviousHashBytes { get; }

        internal byte[] PayloadBytes { get; }

        internal byte[] HashBytes { get; }

        internal static HashChainEntry FromOwned(long sequence, byte[] previousHash, byte[] payload, byte[] hash) =>
            new HashChainEntry(sequence, previousHash, payload, hash, true);

        /// <summary>A checkpoint pointing at this entry, to anchor later verifications.</summary>
        public HashChainCheckpoint ToCheckpoint() => new HashChainCheckpoint(Sequence, HashBytes);

        /// <summary>Sequence number and payload length; the payload itself is never printed.</summary>
        public override string ToString() => $"#{Sequence} ({PayloadBytes.Length} bytes)";
    }

    /// <summary>
    /// A trusted (sequence, hash) pair, typically the chain head saved somewhere the attacker cannot write
    /// (a different system, a signed receipt, a printed report). Lets verification start mid-chain and detect truncation.
    /// </summary>
    public sealed class HashChainCheckpoint
    {
        private readonly byte[] _hash;

        /// <summary>Creates a checkpoint. The hash is copied.</summary>
        public HashChainCheckpoint(long sequence, byte[] hash)
        {
            if (hash == null) throw new ArgumentNullException(nameof(hash));
            if (sequence < 0) throw new ArgumentOutOfRangeException(nameof(sequence), sequence, "Sequence cannot be negative.");
            Sequence = sequence;
            _hash = (byte[])hash.Clone();
        }

        /// <summary>Sequence number of the entry.</summary>
        public long Sequence { get; }

        /// <summary>Hash of the entry.</summary>
        public ReadOnlyMemory<byte> Hash => _hash;

        internal byte[] HashBytes => _hash;

        /// <inheritdoc />
        public override string ToString() => $"#{Sequence}";
    }
}
