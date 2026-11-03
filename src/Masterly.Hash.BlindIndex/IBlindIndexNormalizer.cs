namespace Masterly.Hash.BlindIndex
{
    /// <summary>
    /// Canonicalizes a plaintext value before it is indexed, so that values that should match (e.g.
    /// <c>Alice@Example.com</c> and <c>alice@example.com</c>) produce the same blind index.
    /// </summary>
    /// <remarks>
    /// A normalizer must be deterministic and must not depend on the current culture, time or machine. Changing the
    /// normalizer of an existing index requires re-indexing every row. Implementations must not put the value in
    /// exception messages: it is personal data.
    /// </remarks>
    public interface IBlindIndexNormalizer
    {
        /// <summary>Returns the canonical form of <paramref name="value"/>.</summary>
        /// <exception cref="System.ArgumentNullException"><paramref name="value"/> is null.</exception>
        /// <exception cref="System.ArgumentException"><paramref name="value"/> cannot be normalized.</exception>
        string Normalize(string value);
    }
}
