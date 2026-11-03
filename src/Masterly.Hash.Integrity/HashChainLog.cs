using System;
using System.Collections.Generic;
using System.IO;

namespace Masterly.Hash.Integrity
{
    /// <summary>
    /// An in-memory, append-only, tamper-evident log built on <see cref="HashChain"/>. Thread-safe.
    /// </summary>
    /// <remarks>
    /// Persist the <see cref="Entries"/> anywhere and re-check them later with <see cref="Verify(IEnumerable{HashChainEntry})"/>.
    /// Construct the log with <see cref="ContentHashAlgorithm.HmacSha256"/> so that someone with write access to the
    /// stored entries cannot recompute a forged chain.
    /// </remarks>
    public sealed class HashChainLog
    {
        private readonly object _lock = new object();
        private readonly List<HashChainEntry> _entries = new List<HashChainEntry>();

        /// <summary>Creates an empty SHA-256 log.</summary>
        public HashChainLog()
            : this(ContentHashAlgorithm.Sha256)
        {
        }

        /// <summary>Creates an empty log that hashes with <paramref name="algorithm"/>.</summary>
        public HashChainLog(ContentHashAlgorithm algorithm)
        {
            Algorithm = algorithm ?? throw new ArgumentNullException(nameof(algorithm));
        }

        /// <summary>
        /// Loads a previously persisted chain and verifies it first, so appends always continue a valid chain.
        /// </summary>
        /// <exception cref="InvalidDataException">The existing entries do not form a valid chain from sequence 0.</exception>
        public HashChainLog(ContentHashAlgorithm algorithm, IEnumerable<HashChainEntry> existing)
            : this(algorithm)
        {
            if (existing == null) throw new ArgumentNullException(nameof(existing));
            var list = new List<HashChainEntry>(existing);
            HashChainVerificationResult result = HashChain.Verify(list, algorithm);
            if (!result.IsValid)
                throw new InvalidDataException($"The existing chain is invalid: {result}");
            _entries.AddRange(list);
        }

        /// <summary>The hash function or MAC.</summary>
        public ContentHashAlgorithm Algorithm { get; }

        /// <summary>Number of entries.</summary>
        public int Count
        {
            get
            {
                lock (_lock)
                    return _entries.Count;
            }
        }

        /// <summary>A snapshot of the entries, oldest first.</summary>
        public IReadOnlyList<HashChainEntry> Entries
        {
            get
            {
                lock (_lock)
                    return _entries.ToArray();
            }
        }

        /// <summary>Checkpoint of the newest entry, or <see langword="null"/> when empty. Store it out of the attacker's reach.</summary>
        public HashChainCheckpoint? Head
        {
            get
            {
                lock (_lock)
                    return _entries.Count == 0 ? null : _entries[_entries.Count - 1].ToCheckpoint();
            }
        }

        /// <summary>Appends <paramref name="payload"/> (copied) and returns the new entry.</summary>
        public HashChainEntry Append(byte[] payload)
        {
            if (payload == null) throw new ArgumentNullException(nameof(payload));
            lock (_lock)
            {
                HashChainEntry? previous = _entries.Count == 0 ? null : _entries[_entries.Count - 1];
                HashChainEntry entry = HashChain.CreateNext(previous, payload, Algorithm);
                _entries.Add(entry);
                return entry;
            }
        }

        /// <summary>Verifies this log's own entries.</summary>
        public HashChainVerificationResult Verify() => HashChain.Verify(Entries, Algorithm);

        /// <summary>Verifies <paramref name="entries"/> (for example, loaded back from storage) with this log's algorithm.</summary>
        public HashChainVerificationResult Verify(IEnumerable<HashChainEntry> entries) => HashChain.Verify(entries, Algorithm);

        /// <summary>
        /// Verifies <paramref name="entries"/> and also requires the chain to contain <paramref name="expectedHead"/>
        /// (a checkpoint saved earlier): the entry at its sequence must exist and match. Entries appended since are allowed.
        /// </summary>
        public HashChainVerificationResult Verify(IEnumerable<HashChainEntry> entries, HashChainCheckpoint expectedHead)
        {
            if (expectedHead == null) throw new ArgumentNullException(nameof(expectedHead));
            return HashChain.Verify(entries, Algorithm, null, expectedHead);
        }
    }
}
