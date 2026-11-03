using System;

namespace Masterly.Hash.Tokens
{
    /// <summary>
    /// Fixed-length base62 encoding (alphabet <c>0-9A-Za-z</c>, the GMP digit order). A byte array is read as a
    /// big-endian unsigned integer and written with exactly <see cref="GetEncodedLength"/> digits, left-padded
    /// with <c>'0'</c>, so every byte length has one string length and every value has one string form.
    /// </summary>
    /// <remarks>
    /// Base62 needs no escaping in URLs, file names or identifiers, and a double-click selects the whole value.
    /// The conversion is quadratic in the input length; it is meant for short values such as keys and checksums.
    /// </remarks>
    public static class Base62
    {
        /// <summary>The 62 digits in ascending order of value.</summary>
        public const string Alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

        /// <summary>Largest input accepted by <see cref="Encode"/>, in bytes.</summary>
        public const int MaxByteLength = 1024;

        private static readonly double BitsPerDigit = Math.Log(62) / Math.Log(2);
        private static readonly int MaxEncodedLength;
        private static readonly int[] LengthToByteCount;

        static Base62()
        {
            MaxEncodedLength = GetEncodedLength(MaxByteLength);
            LengthToByteCount = new int[MaxEncodedLength + 1];
            for (int i = 0; i < LengthToByteCount.Length; i++)
                LengthToByteCount[i] = -1;
            for (int n = 0; n <= MaxByteLength; n++)
                LengthToByteCount[GetEncodedLength(n)] = n;
        }

        /// <summary>
        /// Number of base62 digits needed for any value of <paramref name="byteCount"/> bytes:
        /// the smallest <c>L</c> with <c>62^L &gt;= 256^byteCount</c>.
        /// </summary>
        public static int GetEncodedLength(int byteCount)
        {
            if (byteCount < 0 || byteCount > MaxByteLength) throw new ArgumentOutOfRangeException(nameof(byteCount));
            return (int)Math.Ceiling(byteCount * 8 / BitsPerDigit);
        }

        /// <summary>Encodes <paramref name="bytes"/> (big-endian) as exactly <see cref="GetEncodedLength"/> base62 digits.</summary>
        public static string Encode(byte[] bytes)
        {
            if (bytes == null) throw new ArgumentNullException(nameof(bytes));
            if (bytes.Length > MaxByteLength)
                throw new ArgumentException($"At most {MaxByteLength} bytes can be encoded.", nameof(bytes));

            int length = GetEncodedLength(bytes.Length);
            char[] output = new char[length];
            byte[] work = (byte[])bytes.Clone();
            try
            {
                // Repeated long division of the big-endian number by 62; remainders are the digits, least significant first.
                for (int pos = length - 1; pos >= 0; pos--)
                {
                    int remainder = 0;
                    for (int i = 0; i < work.Length; i++)
                    {
                        int acc = (remainder << 8) | work[i];
                        work[i] = (byte)(acc / 62);
                        remainder = acc % 62;
                    }
                    output[pos] = Alphabet[remainder];
                }
                return new string(output);
            }
            finally
            {
                Array.Clear(work, 0, work.Length);
            }
        }

        /// <summary>
        /// Decodes a string produced by <see cref="Encode"/>. Returns false, without throwing, for null, characters
        /// outside the alphabet, a length that no byte count encodes to, or a value too large for that byte count.
        /// </summary>
        public static bool TryDecode(string? text, out byte[] bytes)
        {
            bytes = Array.Empty<byte>();
            if (text == null || text.Length > MaxEncodedLength)
                return false;

            int byteCount = LengthToByteCount[text.Length];
            if (byteCount < 0)
                return false;

            byte[] result = new byte[byteCount];
            foreach (char c in text)
            {
                int digit = DigitValue(c);
                if (digit < 0)
                {
                    Array.Clear(result, 0, result.Length);
                    return false;
                }

                // result = result * 62 + digit
                int carry = digit;
                for (int i = result.Length - 1; i >= 0; i--)
                {
                    int acc = result[i] * 62 + carry;
                    result[i] = (byte)acc;
                    carry = acc >> 8;
                }

                if (carry != 0)
                {
                    Array.Clear(result, 0, result.Length);
                    return false; // value does not fit in byteCount bytes
                }
            }

            bytes = result;
            return true;
        }

        /// <summary>True if every character of <paramref name="text"/> is a base62 digit (and it is not empty).</summary>
        public static bool IsBase62(string? text)
        {
            if (string.IsNullOrEmpty(text))
                return false;
            foreach (char c in text!)
            {
                if (DigitValue(c) < 0)
                    return false;
            }
            return true;
        }

        internal static string EncodeUInt32(uint value) =>
            Encode(new[] { (byte)(value >> 24), (byte)(value >> 16), (byte)(value >> 8), (byte)value });

        internal static int DigitValue(char c)
        {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'A' && c <= 'Z') return c - 'A' + 10;
            if (c >= 'a' && c <= 'z') return c - 'a' + 36;
            return -1;
        }
    }
}
