using System;

namespace Masterly.Hash.BlindIndex.Normalizers
{
    /// <summary>Returns the value unchanged.</summary>
    public sealed class ExactNormalizer : IBlindIndexNormalizer
    {
        /// <inheritdoc />
        public string Normalize(string value)
        {
            if (value == null) throw new ArgumentNullException(nameof(value));
            return value;
        }
    }
}
