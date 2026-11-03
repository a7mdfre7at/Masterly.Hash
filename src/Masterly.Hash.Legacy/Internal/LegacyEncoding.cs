using System;
using System.Text;

namespace Masterly.Hash.Legacy.Internal
{
    /// <summary>Strict parsing helpers shared by the legacy formats. Nothing here throws on bad input.</summary>
    internal static class LegacyEncoding
    {
        /// <summary>Longest stored hash any format looks at, so a huge column value costs nothing to reject.</summary>
        public const int MaxStoredLength = 1024;

        /// <summary>
        /// UTF-8 of the password exactly as given, without normalization: the legacy systems these formats come
        /// from (ASP.NET Identity, Django, PHP, BCrypt.Net) hash the raw UTF-8 bytes.
        /// </summary>
        public static byte[] Utf8(string password) => Encoding.UTF8.GetBytes(password);

        /// <summary>
        /// Parses <c>[1-9][0-9]*</c> (or a lone <c>0</c>) of at most 10 digits. Leading zeros, signs and whitespace
        /// are rejected so each value has one spelling.
        /// </summary>
        public static bool TryParseDecimal(string value, out long result)
        {
            result = 0;
            if (value == null || value.Length == 0 || value.Length > 10)
                return false;
            if (value.Length > 1 && value[0] == '0')
                return false;

            foreach (char c in value)
            {
                if (c < '0' || c > '9')
                    return false;
                result = result * 10 + (c - '0');
            }

            return true;
        }

        /// <summary>Strict, canonical, padded standard base64 as written by <c>Convert.ToBase64String</c>.</summary>
        public static bool TryFromBase64Padded(string value, out byte[] bytes)
        {
            bytes = Array.Empty<byte>();
            if (value == null || value.Length == 0 || value.Length % 4 != 0 || value.Length > MaxStoredLength)
                return false;

            foreach (char c in value)
            {
                bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=';
                if (!ok)
                    return false;
            }

            byte[] decoded;
            try
            {
                decoded = Convert.FromBase64String(value);
            }
            catch (FormatException)
            {
                return false;
            }

            if (!string.Equals(Convert.ToBase64String(decoded), value, StringComparison.Ordinal))
                return false;

            bytes = decoded;
            return true;
        }

        /// <summary>Decodes hex in either case. Rejects odd lengths and non-hex characters.</summary>
        public static bool TryFromHex(string value, out byte[] bytes)
        {
            bytes = Array.Empty<byte>();
            if (value == null || value.Length == 0 || value.Length % 2 != 0 || value.Length > MaxStoredLength)
                return false;

            byte[] result = new byte[value.Length / 2];
            for (int i = 0; i < result.Length; i++)
            {
                int hi = HexValue(value[2 * i]);
                int lo = HexValue(value[2 * i + 1]);
                if (hi < 0 || lo < 0)
                    return false;
                result[i] = (byte)((hi << 4) | lo);
            }

            bytes = result;
            return true;
        }

        /// <summary>True if every character is a hex digit (either case).</summary>
        public static bool IsHex(string value)
        {
            foreach (char c in value)
            {
                if (HexValue(c) < 0)
                    return false;
            }
            return true;
        }

        public static uint ReadUInt32BigEndian(byte[] buffer, int offset) =>
            ((uint)buffer[offset] << 24) | ((uint)buffer[offset + 1] << 16) | ((uint)buffer[offset + 2] << 8) | buffer[offset + 3];

        public static void WriteUInt32BigEndian(byte[] buffer, int offset, uint value)
        {
            buffer[offset] = (byte)(value >> 24);
            buffer[offset + 1] = (byte)(value >> 16);
            buffer[offset + 2] = (byte)(value >> 8);
            buffer[offset + 3] = (byte)value;
        }

        public static byte[] Slice(byte[] source, int offset, int count)
        {
            byte[] result = new byte[count];
            Buffer.BlockCopy(source, offset, result, 0, count);
            return result;
        }

        /// <summary>ASCII bytes of a string already validated to contain only ASCII.</summary>
        public static byte[] Ascii(string value, int start, int length)
        {
            byte[] result = new byte[length];
            for (int i = 0; i < length; i++)
                result[i] = (byte)value[start + i];
            return result;
        }

        /// <summary>Decodes ASCII bytes; returns null if any byte is outside 0x20..0x7E.</summary>
        public static string? FromPrintableAscii(byte[] bytes, int offset, int count)
        {
            var chars = new char[count];
            for (int i = 0; i < count; i++)
            {
                byte b = bytes[offset + i];
                if (b < 0x20 || b > 0x7E)
                    return null;
                chars[i] = (char)b;
            }
            return new string(chars);
        }

        private static int HexValue(char c)
        {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        }
    }
}
