using System;
using System.Text;

namespace Masterly.Hash.AspNetCore
{
    /// <summary>
    /// Measures passwords the way <see cref="PasswordHasher"/> does when hashing (UTF-8 bytes after NFKC), but with
    /// cheap pre-checks so an attacker-sized input is rejected before NFKC can expand it (up to 18x, e.g. U+FDFA).
    /// </summary>
    internal static class PasswordLength
    {
        /// <summary>
        /// A password with more than <c>MaxRawExpansion * limit</c> UTF-16 code units cannot fit the limit on any path.
        /// NFKC never removes characters, and canonical composition merges at most 4 code points into one (the longest
        /// canonical decomposition, e.g. U+1FA2 = U+03C9 U+0313 U+0300 U+0345), so the normalized password has at
        /// least <c>codePoints / 4 &gt;= length / 8</c> code points of at least one UTF-8 byte each. Un-normalized
        /// paths (legacy formats) count raw UTF-8, which is never less than the UTF-16 length.
        /// </summary>
        public const int MaxRawExpansion = 8;

        /// <summary>
        /// True if <paramref name="value"/> is certainly too long for <paramref name="maxBytes"/> on every hasher path,
        /// decided from its length alone (no allocation, no normalization).
        /// </summary>
        public static bool ExceedsRawBound(string value, int maxBytes) =>
            value.Length > (long)maxBytes * MaxRawExpansion;

        /// <summary>
        /// True if <paramref name="value"/> is longer than <paramref name="maxBytes"/> UTF-8 bytes after NFKC, i.e. if
        /// <see cref="IPasswordHasher.Hash(string)"/> would reject it. Normalizes at most <c>8 * maxBytes</c> characters.
        /// </summary>
        public static bool IsTooLongToHash(string value, int maxBytes)
        {
            if (ExceedsRawBound(value, maxBytes))
                return true;

            // ASCII is unchanged by NFKC and one byte per character: decide without allocating.
            bool ascii = true;
            for (int i = 0; i < value.Length; i++)
            {
                if (value[i] > 0x7F)
                {
                    ascii = false;
                    break;
                }
            }
            if (ascii)
                return value.Length > maxBytes;

            string normalized;
            try
            {
                normalized = value.IsNormalized(NormalizationForm.FormKC) ? value : value.Normalize(NormalizationForm.FormKC);
            }
            catch (ArgumentException)
            {
                // Lone surrogates cannot be normalized; the hasher then encodes the password as given.
                normalized = value;
            }
            return Encoding.UTF8.GetByteCount(normalized) > maxBytes;
        }
    }
}
