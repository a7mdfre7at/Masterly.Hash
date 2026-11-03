using System;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace Masterly.Hash.Internal
{
    internal static class CryptoUtil
    {

        /// <summary>Compares two byte arrays in time that depends only on their length.</summary>
        [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
        public static bool FixedTimeEquals(byte[] left, byte[] right)
        {
            return CryptographicOperations.FixedTimeEquals(left, right);
        }

        public static bool FixedTimeEquals(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) => CryptographicOperations.FixedTimeEquals(left, right);

        /// <summary>Overwrites a buffer that held secret material.</summary>
        [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
        public static void Zero(byte[]? buffer)
        {
            if (buffer == null)
                return;
            CryptographicOperations.ZeroMemory(buffer);
        }

        public static byte[] RandomBytes(int length)
        {
            byte[] bytes = new byte[length];
            RandomNumberGenerator.Fill(bytes);
            return bytes;
        }

        /// <summary>Standard base64 without padding, as used by the PHC string format.</summary>
        public static string ToB64(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=');

        /// <summary>Strictly decodes unpadded standard base64. Rejects padding, whitespace and non-canonical input.</summary>
        public static bool TryFromB64(string value, out byte[] bytes)
        {
            bytes = Array.Empty<byte>();
            if (value.Length == 0 || value.Length % 4 == 1)
                return false;

            foreach (char c in value)
            {
                bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/';
                if (!ok)
                    return false;
            }

            string padded = value.Length % 4 == 0 ? value : value + new string('=', 4 - value.Length % 4);
            try
            {
                bytes = Convert.FromBase64String(padded);
            }
            catch (FormatException)
            {
                return false;
            }

            // Reject non-canonical encodings (unused trailing bits set), so one hash has exactly one string form.
            if (ToB64(bytes) == value)
                return true;
            bytes = Array.Empty<byte>();
            return false;
        }
    }
}
