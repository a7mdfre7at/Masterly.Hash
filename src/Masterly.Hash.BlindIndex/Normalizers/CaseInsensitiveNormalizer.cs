using System;

namespace Masterly.Hash.BlindIndex.Normalizers
{
    /// <summary>
    /// Unicode NFKC normalization followed by invariant lower-casing, so compatibility forms (full-width letters,
    /// ligatures) and case variants index identically. Does not trim.
    /// </summary>
    public sealed class CaseInsensitiveNormalizer : IBlindIndexNormalizer
    {
        /// <inheritdoc />
        public string Normalize(string value)
        {
            if (value == null) throw new ArgumentNullException(nameof(value));
            return UnicodeText.Nfkc(value, nameof(value)).ToLowerInvariant();
        }
    }
}
