using System;
using System.Security.Cryptography;
using System.Text;
using Masterly.Hash.Primitives;

namespace Masterly.Hash.Pwned.Internal
{
    /// <summary>
    /// SHA-1 split for the k-anonymity range API: a 5-hex-digit prefix that is sent, and a 35-hex-digit suffix that
    /// stays local. The suffix is kept packed as nibbles (<see cref="SuffixBytes"/> bytes), never as a string.
    /// </summary>
    internal static class PwnedHash
    {
        /// <summary>Hex digits sent to the service.</summary>
        public const int PrefixLength = 5;

        /// <summary>Hex digits of the SHA-1 hash kept locally.</summary>
        public const int SuffixLength = 35;

        /// <summary>Bytes of a packed suffix: 35 nibbles, high nibble first, last low nibble zero.</summary>
        public const int SuffixBytes = 18;

        private const string HexDigits = "0123456789ABCDEF";

        /// <summary>
        /// Hashes the UTF-8 bytes of <paramref name="password"/> (as Pwned Passwords does) and splits the hash.
        /// The caller zeroes <paramref name="packedSuffix"/>.
        /// </summary>
        public static void Compute(string password, out string prefix, out byte[] packedSuffix)
        {
            byte[] utf8 = Encoding.UTF8.GetBytes(password);
            byte[]? hash = null;
            try
            {
#pragma warning disable CA5350 // SHA-1 is mandated by the Pwned Passwords API; it is not used for security here.
                hash = SHA1.HashData(utf8);
#pragma warning restore CA5350
                prefix = Prefix(hash);
                packedSuffix = PackSuffix(hash);
            }
            finally
            {
                HashPrimitives.Zero(utf8);
                HashPrimitives.Zero(hash);
            }
        }

        /// <summary>The first five nibbles of a 20-byte hash as uppercase hex.</summary>
        internal static string Prefix(byte[] hash)
        {
            var chars = new char[PrefixLength];
            for (int i = 0; i < PrefixLength; i++)
                chars[i] = HexDigits[Nibble(hash, i)];
            return new string(chars);
        }

        /// <summary>Nibbles 5..39 of a 20-byte hash, packed.</summary>
        internal static byte[] PackSuffix(byte[] hash)
        {
            var packed = new byte[SuffixBytes];
            for (int i = 0; i < SuffixLength; i++)
                SetNibble(packed, i, Nibble(hash, PrefixLength + i));
            return packed;
        }

        /// <summary>
        /// Parses exactly <see cref="SuffixLength"/> hex digits (either case) from ASCII bytes into
        /// <paramref name="destination"/> at <paramref name="destinationOffset"/>.
        /// </summary>
        public static bool TryParseSuffix(byte[] source, int offset, int length, byte[] destination, int destinationOffset)
        {
            if (length != SuffixLength)
                return false;
            Array.Clear(destination, destinationOffset, SuffixBytes);
            for (int i = 0; i < SuffixLength; i++)
            {
                int value = HexValue(source[offset + i]);
                if (value < 0)
                    return false;
                int index = destinationOffset + (i >> 1);
                destination[index] = (byte)(destination[index] | ((i & 1) == 0 ? value << 4 : value));
            }
            return true;
        }

        private static int Nibble(byte[] data, int index) =>
            (index & 1) == 0 ? data[index >> 1] >> 4 : data[index >> 1] & 0x0F;

        private static void SetNibble(byte[] data, int index, int value) =>
            data[index >> 1] = (byte)(data[index >> 1] | ((index & 1) == 0 ? value << 4 : value));

        private static int HexValue(byte c)
        {
            if (c >= (byte)'0' && c <= (byte)'9') return c - '0';
            if (c >= (byte)'A' && c <= (byte)'F') return c - 'A' + 10;
            if (c >= (byte)'a' && c <= (byte)'f') return c - 'a' + 10;
            return -1;
        }
    }
}
