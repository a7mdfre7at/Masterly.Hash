using System;
using System.Text;

namespace Masterly.Hash.Policy.Internal
{
    internal static class TextUtil
    {
        /// <summary>NFKC, as the hasher does (NIST SP 800-63B). Invalid UTF-16 is returned as given.</summary>
        public static string Normalize(string value)
        {
            try
            {
                return value.Normalize(NormalizationForm.FormKC);
            }
            catch (ArgumentException)
            {
                // Lone surrogates cannot be normalized.
                return value;
            }
        }

        /// <summary>Number of Unicode code points; a lone surrogate counts as one.</summary>
        public static int CountCodePoints(string value)
        {
            int count = 0;
            for (int i = 0; i < value.Length; i++)
            {
                if (char.IsHighSurrogate(value[i]) && i + 1 < value.Length && char.IsLowSurrogate(value[i + 1]))
                    i++;
                count++;
            }
            return count;
        }

        /// <summary>The first <paramref name="maxLength"/> UTF-16 units, never splitting a surrogate pair.</summary>
        public static string Truncate(string value, int maxLength)
        {
            if (value.Length <= maxLength)
                return value;
            int cut = maxLength;
            if (cut > 0 && char.IsHighSurrogate(value[cut - 1]))
                cut--;
            return value.Substring(0, cut);
        }

        /// <summary>Reverses a string, keeping surrogate pairs in order.</summary>
        public static string Reverse(string value)
        {
            char[] result = new char[value.Length];
            int w = value.Length;
            for (int i = 0; i < value.Length; i++)
            {
                if (char.IsHighSurrogate(value[i]) && i + 1 < value.Length && char.IsLowSurrogate(value[i + 1]))
                {
                    result[w - 2] = value[i];
                    result[w - 1] = value[i + 1];
                    w -= 2;
                    i++;
                }
                else
                {
                    result[--w] = value[i];
                }
            }
            return new string(result);
        }

        public static bool IsAsciiDigit(char c) => c >= '0' && c <= '9';

        public static bool IsAsciiLower(char c) => c >= 'a' && c <= 'z';

        public static bool IsAsciiUpper(char c) => c >= 'A' && c <= 'Z';
    }
}
