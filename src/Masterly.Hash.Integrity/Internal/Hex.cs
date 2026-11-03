using System;

namespace Masterly.Hash.Integrity.Internal
{
    /// <summary>Lowercase hexadecimal encoding with strict decoding.</summary>
    internal static class Hex
    {
        private const string Digits = "0123456789abcdef";

        public static string Encode(byte[] bytes)
        {
            char[] chars = new char[bytes.Length * 2];
            for (int i = 0; i < bytes.Length; i++)
            {
                chars[2 * i] = Digits[bytes[i] >> 4];
                chars[2 * i + 1] = Digits[bytes[i] & 0xF];
            }
            return new string(chars);
        }

        /// <summary>Decodes lowercase hex only; uppercase, whitespace and odd lengths are rejected.</summary>
        public static bool TryDecode(string value, int start, int length, out byte[] bytes)
        {
            bytes = Array.Empty<byte>();
            if (length <= 0 || length % 2 != 0)
                return false;

            byte[] result = new byte[length / 2];
            for (int i = 0; i < result.Length; i++)
            {
                int hi = Nibble(value[start + 2 * i]);
                int lo = Nibble(value[start + 2 * i + 1]);
                if (hi < 0 || lo < 0)
                    return false;
                result[i] = (byte)((hi << 4) | lo);
            }

            bytes = result;
            return true;
        }

        private static int Nibble(char c)
        {
            if (c >= '0' && c <= '9')
                return c - '0';
            if (c >= 'a' && c <= 'f')
                return c - 'a' + 10;
            return -1;
        }
    }
}
