using System;
using System.Text;

namespace Masterly.Hash.Internal
{
    internal static class PasswordEncoding
    {
        private static readonly UTF8Encoding StrictUtf8 = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

        /// <summary>
        /// True if the string is valid UTF-16 (no unpaired surrogates) and can be NFKC-normalized (.NET rejects U+FFFE).
        /// Lone surrogates would be encoded lossily (each becomes U+FFFD), so distinct passwords would hash the same;
        /// the hasher rejects such strings.
        /// </summary>
        public static bool IsWellFormed(string password)
        {
            if (!HasNoLoneSurrogates(password))
                return false;
            try
            {
                // .NET's NFKC rejects a few code points outright (U+FFFE); treat those passwords as invalid too.
                password.Normalize(NormalizationForm.FormKC);
                return true;
            }
            catch (ArgumentException)
            {
                return false;
            }
        }

        private static bool HasNoLoneSurrogates(string password)
        {
            for (int i = 0; i < password.Length; i++)
            {
                char c = password[i];
                if (char.IsHighSurrogate(c))
                {
                    if (i + 1 >= password.Length || !char.IsLowSurrogate(password[i + 1]))
                        return false;
                    i++;
                }
                else if (char.IsLowSurrogate(c))
                {
                    return false;
                }
            }
            return true;
        }

        /// <summary>NFKC-normalized password (NIST SP 800-63B §5.1.1.2). The input must be well-formed UTF-16.</summary>
        public static string Normalize(string password) => password.Normalize(NormalizationForm.FormKC);

        /// <summary>UTF-8 of the NFKC-normalized password. Throws <see cref="ArgumentException"/> on invalid UTF-16.</summary>
        public static byte[] Encode(string password)
        {
            if (!IsWellFormed(password))
                throw new ArgumentException("Password contains invalid UTF-16 or a code point that cannot be normalized.", nameof(password));
            return StrictUtf8.GetBytes(Normalize(password));
        }
    }
}
