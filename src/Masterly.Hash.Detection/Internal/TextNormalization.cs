using System;
using System.Text;

namespace Masterly.Hash.Detection.Internal
{
    internal static class TextNormalization
    {
        /// <summary>NFKC, matching <see cref="Primitives.HashPrimitives.EncodePassword"/>. Invalid UTF-16 is returned as given.</summary>
        public static string Nfkc(string value)
        {
            try
            {
                return value.Normalize(NormalizationForm.FormKC);
            }
            catch (ArgumentException)
            {
                return value;
            }
        }

        /// <summary>
        /// Bytes that identify a password for fingerprinting. Well-formed text gives exactly
        /// <see cref="Primitives.HashPrimitives.EncodePassword"/>; invalid UTF-16 (which the hasher rejects) is encoded
        /// losslessly as 0xFF followed by its UTF-16LE code units. 0xFF never occurs in UTF-8, so the two never collide.
        /// </summary>
        public static byte[] FingerprintBytes(string value)
        {
            if (Primitives.HashPrimitives.IsWellFormedPassword(value))
                return Primitives.HashPrimitives.EncodePassword(value);
            // Copy code units directly: Encoding.Unicode would also replace lone surrogates with U+FFFD.
            var result = new byte[1 + 2 * value.Length];
            result[0] = 0xFF;
            for (int i = 0; i < value.Length; i++)
            {
                result[1 + 2 * i] = (byte)value[i];
                result[2 + 2 * i] = (byte)(value[i] >> 8);
            }
            return result;
        }

        /// <summary>Canonical form of an account name: NFKC, then upper-cased invariantly (case-insensitive matching).</summary>
        public static string Account(string account) => Nfkc(account).ToUpperInvariant();
    }
}
