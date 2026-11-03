using System.Collections.Generic;

namespace Masterly.Hash.BlindIndex
{
    /// <summary>
    /// Computes blind indexes: keyed, truncated HMACs of normalized plaintext, stored next to an encrypted column so
    /// it can be searched by equality without decrypting. <see cref="BlindIndexer"/> is the implementation.
    /// </summary>
    /// <remarks>
    /// Index strings have the form <c>&lt;keyId&gt;:&lt;base64&gt;</c>. Invalid arguments (null or empty values, bad
    /// index names, unknown key ids) throw <see cref="System.ArgumentException"/> or a subclass.
    /// </remarks>
    public interface IBlindIndexer
    {
        /// <summary>The key id new indexes are written under.</summary>
        string CurrentKeyId { get; }

        /// <summary>Every key id in the ring, current first, then the others in ordinal order.</summary>
        IReadOnlyList<string> KeyIds { get; }

        /// <summary>Computes the index of <paramref name="value"/> for <paramref name="indexName"/> under the current key.</summary>
        string Compute(string value, string indexName, BlindIndexOptions? options = null);

        /// <summary>Computes the index under a specific key in the ring.</summary>
        string ComputeWithKey(string keyId, string value, string indexName, BlindIndexOptions? options = null);

        /// <summary>
        /// Computes the index under every key in the ring, current first. Use during key rotation:
        /// <c>WHERE email_idx IN (@i0, @i1, ...)</c> finds rows not yet re-indexed.
        /// </summary>
        IReadOnlyList<string> ComputeAll(string value, string indexName, BlindIndexOptions? options = null);

        /// <summary>Computes a compound index over several parts (e.g. last name and birth year) under the current key, with default options.</summary>
        string ComputeCompound(string indexName, params string[] parts);

        /// <summary>Computes a compound index under the current key. Each part is normalized separately.</summary>
        string ComputeCompound(string indexName, BlindIndexOptions? options, params string[] parts);

        /// <summary>Computes a compound index under every key in the ring, current first, with default options.</summary>
        IReadOnlyList<string> ComputeCompoundAll(string indexName, params string[] parts);

        /// <summary>Computes a compound index under every key in the ring, current first.</summary>
        IReadOnlyList<string> ComputeCompoundAll(string indexName, BlindIndexOptions? options, params string[] parts);

        /// <summary>
        /// True if <paramref name="storedIndex"/> is the index of <paramref name="value"/> under the key it names.
        /// Compares in constant time. Returns false (never throws) for a malformed stored index or unknown key.
        /// </summary>
        bool Matches(string? storedIndex, string value, string indexName, BlindIndexOptions? options = null);

        /// <summary>True if <paramref name="storedIndex"/> is malformed or was not computed under <see cref="CurrentKeyId"/>.</summary>
        bool NeedsReindex(string? storedIndex);
    }
}
