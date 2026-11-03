using System;

namespace Masterly.Hash.BlindIndex.Normalizers
{
    /// <summary>Removes leading and trailing Unicode white space.</summary>
    public sealed class TrimNormalizer : IBlindIndexNormalizer
    {
        /// <inheritdoc />
        public string Normalize(string value)
        {
            if (value == null) throw new ArgumentNullException(nameof(value));
            return value.Trim();
        }
    }
}
