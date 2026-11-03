using Masterly.Hash.BlindIndex.Normalizers;

namespace Masterly.Hash.BlindIndex
{
    /// <summary>The built-in <see cref="IBlindIndexNormalizer"/> implementations.</summary>
    public static class BlindIndexNormalizers
    {
        /// <summary>Indexes the value exactly as given (no trimming, no Unicode normalization).</summary>
        public static IBlindIndexNormalizer Exact { get; } = new ExactNormalizer();

        /// <summary>Removes leading and trailing white space.</summary>
        public static IBlindIndexNormalizer Trim { get; } = new TrimNormalizer();

        /// <summary>Unicode NFKC normalization followed by invariant lower-casing.</summary>
        public static IBlindIndexNormalizer CaseInsensitive { get; } = new CaseInsensitiveNormalizer();

        /// <summary>Email address: trimmed and lower-cased, no provider-specific rewriting. See <see cref="EmailNormalizer"/>.</summary>
        public static IBlindIndexNormalizer Email { get; } = new EmailNormalizer();

        /// <summary>Phone number: digits only, no default country code. See <see cref="PhoneNormalizer"/>.</summary>
        public static IBlindIndexNormalizer Phone { get; } = new PhoneNormalizer();
    }
}
