using System;
using System.Diagnostics.CodeAnalysis;
using System.Text;
using Masterly.Hash.Primitives;

namespace Masterly.Hash.Tokens
{
    /// <summary>
    /// GitHub-style API keys: <c>&lt;prefix&gt;_&lt;base62 random&gt;&lt;base62 CRC-32, 6 chars&gt;</c>,
    /// e.g. <c>mh_live_4Fz…Qx1a2B3</c>.
    /// </summary>
    /// <remarks>
    /// <para>The prefix identifies the issuer and environment so leaked keys can be recognised by secret scanners.
    /// The checksum is the CRC-32 (IEEE) of the ASCII text <c>&lt;prefix&gt;_&lt;random&gt;</c>, written as six
    /// base62 digits. It lets <see cref="HasValidChecksum"/> reject typos and garbage without a database lookup and
    /// lets scanners tell real keys from look-alikes. It is <b>not</b> a security control: anyone can compute it.</para>
    /// <para>Store only the <see cref="ApiKeyHasher"/> lookup hash, never the plain-text key.</para>
    /// </remarks>
    public static class ApiKey
    {
        /// <summary>Default random part: 32 bytes (256 bits), 43 base62 characters.</summary>
        public const int DefaultEntropyBytes = 32;

        /// <summary>Smallest random part accepted: 16 bytes (128 bits).</summary>
        public const int MinEntropyBytes = 16;

        /// <summary>Largest random part accepted: 64 bytes (512 bits).</summary>
        public const int MaxEntropyBytes = 64;

        /// <summary>Length of the checksum suffix in characters.</summary>
        public const int ChecksumLength = 6;

        /// <summary>Maximum prefix length in characters.</summary>
        public const int MaxPrefixLength = 32;

        /// <summary>Upper bound on the length of any key this format can produce; longer input is rejected unparsed.</summary>
        public static readonly int MaxLength = MaxPrefixLength + 1 + Base62.GetEncodedLength(MaxEntropyBytes) + ChecksumLength;

        private static readonly int MinRandomLength = Base62.GetEncodedLength(MinEntropyBytes);

        /// <summary>
        /// Generates a new API key. Show the result to its owner once; store only its lookup hash.
        /// </summary>
        /// <param name="prefix">Issuer/environment prefix such as <c>mh_live</c>; see <see cref="IsValidPrefix"/>.</param>
        /// <param name="entropyBytes">Random bytes in the key, <see cref="MinEntropyBytes"/> to <see cref="MaxEntropyBytes"/>.</param>
        public static string Generate(string prefix, int entropyBytes = DefaultEntropyBytes)
        {
            if (prefix == null) throw new ArgumentNullException(nameof(prefix));
            ValidatePrefix(prefix, nameof(prefix));
            ValidateEntropy(entropyBytes, nameof(entropyBytes));

            byte[] random = HashPrimitives.RandomBytes(entropyBytes);
            try
            {
                string body = prefix + "_" + Base62.Encode(random);
                return body + ComputeChecksum(body);
            }
            finally
            {
                HashPrimitives.Zero(random);
            }
        }

        /// <summary>Generates a new API key together with the lookup hash to store for it.</summary>
        public static GeneratedApiKey Generate(ApiKeyHasher hasher, string prefix, int entropyBytes = DefaultEntropyBytes)
        {
            if (hasher == null) throw new ArgumentNullException(nameof(hasher));
            string key = Generate(prefix, entropyBytes);
            return new GeneratedApiKey(key, prefix, hasher.ComputeLookupHash(key));
        }

        /// <summary>
        /// Offline structural and checksum check. True only for a well-formed key whose checksum matches.
        /// Never throws. A true result says nothing about whether the key was ever issued.
        /// </summary>
        public static bool HasValidChecksum(string? apiKey) => TryParse(apiKey, out _);

        /// <summary>Splits a key into its parts if it is well-formed and its checksum matches. Never throws.</summary>
        public static bool TryParse(string? apiKey, [NotNullWhen(true)] out ApiKeyParts? parts)
        {
            parts = null;
            if (apiKey == null || apiKey.Length > MaxLength)
                return false;

            int separator = apiKey.LastIndexOf('_');
            if (separator <= 0)
                return false;

            string prefix = apiKey.Substring(0, separator);
            string tail = apiKey.Substring(separator + 1);
            if (!IsValidPrefix(prefix) || tail.Length < MinRandomLength + ChecksumLength || !Base62.IsBase62(tail))
                return false;

            string random = tail.Substring(0, tail.Length - ChecksumLength);
            string checksum = tail.Substring(tail.Length - ChecksumLength);

            if (!Base62.TryDecode(random, out byte[] randomBytes))
                return false;
            int entropy = randomBytes.Length;
            HashPrimitives.Zero(randomBytes);
            if (entropy < MinEntropyBytes || entropy > MaxEntropyBytes)
                return false;

            // The checksum is public information derived from the key; an ordinal comparison is fine here.
            string expected = ComputeChecksum(apiKey.Substring(0, apiKey.Length - ChecksumLength));
            if (!string.Equals(expected, checksum, StringComparison.Ordinal))
                return false;

            parts = new ApiKeyParts(prefix, random, checksum, entropy);
            return true;
        }

        /// <summary>
        /// True if <paramref name="prefix"/> is 1 to 32 ASCII letters, digits and single underscores, starting with a
        /// letter and not ending with an underscore (e.g. <c>mh</c>, <c>mh_live</c>, <c>acme_test2</c>).
        /// </summary>
        public static bool IsValidPrefix(string? prefix)
        {
            if (prefix == null || prefix.Length == 0 || prefix.Length > MaxPrefixLength)
                return false;
            if (!IsAsciiLetter(prefix[0]) || prefix[prefix.Length - 1] == '_')
                return false;

            for (int i = 1; i < prefix.Length; i++)
            {
                char c = prefix[i];
                if (c == '_')
                {
                    if (prefix[i - 1] == '_')
                        return false;
                }
                else if (!IsAsciiLetter(c) && !(c >= '0' && c <= '9'))
                {
                    return false;
                }
            }
            return true;
        }

        internal static void ValidatePrefix(string prefix, string paramName)
        {
            if (!IsValidPrefix(prefix))
                throw new ArgumentException(
                    "Prefix must be 1-" + MaxPrefixLength + " ASCII letters, digits and single underscores, start with a letter and not end with an underscore.",
                    paramName);
        }

        internal static void ValidateEntropy(int entropyBytes, string paramName)
        {
            if (entropyBytes < MinEntropyBytes || entropyBytes > MaxEntropyBytes)
                throw new ArgumentOutOfRangeException(paramName, entropyBytes,
                    "Entropy must be " + MinEntropyBytes + " to " + MaxEntropyBytes + " bytes.");
        }

        private static string ComputeChecksum(string prefixAndRandom) =>
            Base62.EncodeUInt32(Crc32.Compute(Encoding.ASCII.GetBytes(prefixAndRandom)));

        private static bool IsAsciiLetter(char c) => (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
    }
}
