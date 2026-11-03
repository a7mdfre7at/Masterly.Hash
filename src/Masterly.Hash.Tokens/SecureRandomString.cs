using System;
using System.Collections.Generic;
using Masterly.Hash.Primitives;

namespace Masterly.Hash.Tokens
{
    /// <summary>
    /// Cryptographically secure random strings over an arbitrary alphabet, without modulo bias.
    /// </summary>
    /// <remarks>
    /// Each character is drawn by rejection sampling: a random byte <c>b</c> is accepted only if
    /// <c>b &lt; 256 - (256 mod n)</c> for an alphabet of <c>n</c> characters, and then mapped with <c>b mod n</c>,
    /// so every character is exactly equally likely. The entropy of the result is
    /// <c>length * log2(n)</c> bits; see <see cref="GetEntropyBits"/>.
    /// </remarks>
    public static class SecureRandomString
    {
        /// <summary><c>0-9A-Za-z</c>: URL-, file- and double-click-safe. About 5.95 bits per character.</summary>
        public const string Base62 = Tokens.Base62.Alphabet;

        /// <summary>RFC 4648 base64url characters <c>A-Za-z0-9-_</c>. 6 bits per character.</summary>
        public const string UrlSafe = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

        /// <summary>Lowercase hexadecimal. 4 bits per character.</summary>
        public const string Hex = "0123456789abcdef";

        /// <summary>Decimal digits, e.g. for one-time codes. About 3.32 bits per character.</summary>
        public const string Digits = "0123456789";

        /// <summary>Lowercase letters and digits. About 5.17 bits per character.</summary>
        public const string LowercaseAlphanumeric = "abcdefghijklmnopqrstuvwxyz0123456789";

        /// <summary>
        /// Crockford base32 (no <c>I</c>, <c>L</c>, <c>O</c>, <c>U</c>): readable aloud and hard to mistype,
        /// for recovery codes. 5 bits per character.
        /// </summary>
        public const string Crockford32 = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

        /// <summary>Largest supported alphabet (one random byte per draw).</summary>
        public const int MaxAlphabetLength = 256;

        /// <summary>Largest supported output length.</summary>
        public const int MaxLength = 1 << 20;

        /// <summary>Generates a random string of <paramref name="length"/> characters from <see cref="Base62"/>.</summary>
        public static string Generate(int length) => Generate(length, Base62);

        /// <summary>Generates a random string of <paramref name="length"/> characters from <paramref name="alphabet"/>.</summary>
        /// <param name="length">Number of characters, 0 to <see cref="MaxLength"/>.</param>
        /// <param name="alphabet">2 to 256 distinct characters, none of them a UTF-16 surrogate.</param>
        /// <exception cref="ArgumentException">The alphabet is too short, too long, has duplicates or surrogates.</exception>
        public static string Generate(int length, string alphabet)
        {
            if (alphabet == null) throw new ArgumentNullException(nameof(alphabet));
            if (length < 0 || length > MaxLength) throw new ArgumentOutOfRangeException(nameof(length));
            ValidateAlphabet(alphabet);
            if (length == 0)
                return string.Empty;

            int n = alphabet.Length;
            int limit = 256 - (256 % n); // largest multiple of n that fits in a byte; bytes >= limit are rejected
            char[] output = new char[length];
            int filled = 0;

            // Expected draws per character is 256 / limit < 2; over-request a little to usually need one batch.
            int batch = Math.Min(length + (length >> 1) + 16, 4096);
            while (filled < length)
            {
                byte[] random = HashPrimitives.RandomBytes(batch);
                for (int i = 0; i < random.Length && filled < length; i++)
                {
                    int b = random[i];
                    if (b < limit)
                        output[filled++] = alphabet[b % n];
                }
                HashPrimitives.Zero(random);
            }

            string result = new string(output);
            Array.Clear(output, 0, output.Length);
            return result;
        }

        /// <summary>Entropy in bits of a string of <paramref name="length"/> characters from an alphabet of <paramref name="alphabetLength"/>.</summary>
        public static double GetEntropyBits(int length, int alphabetLength)
        {
            if (length < 0) throw new ArgumentOutOfRangeException(nameof(length));
            if (alphabetLength < 2) throw new ArgumentOutOfRangeException(nameof(alphabetLength));
            return length * (Math.Log(alphabetLength) / Math.Log(2));
        }

        private static void ValidateAlphabet(string alphabet)
        {
            if (alphabet.Length < 2 || alphabet.Length > MaxAlphabetLength)
                throw new ArgumentException($"Alphabet must have 2 to {MaxAlphabetLength} characters.", nameof(alphabet));

            var seen = new HashSet<char>();
            foreach (char c in alphabet)
            {
                if (char.IsSurrogate(c))
                    throw new ArgumentException("Alphabet cannot contain surrogate characters.", nameof(alphabet));
                if (!seen.Add(c))
                    throw new ArgumentException("Alphabet characters must be distinct; duplicates bias the output.", nameof(alphabet));
            }
        }
    }
}
