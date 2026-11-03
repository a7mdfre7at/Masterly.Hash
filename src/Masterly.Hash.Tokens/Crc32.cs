using System;
using System.Text;

namespace Masterly.Hash.Tokens
{
    /// <summary>
    /// CRC-32 (IEEE 802.3, reflected polynomial <c>0xEDB88320</c>, as used by zlib, PNG and Ethernet).
    /// </summary>
    /// <remarks>
    /// A CRC is an error-detecting checksum, not a cryptographic hash: it detects typos and truncation and lets
    /// secret scanners recognise a key offline, but provides no integrity against an adversary.
    /// </remarks>
    public static class Crc32
    {
        private static readonly uint[] Table = BuildTable();

        /// <summary>Computes the CRC-32 of <paramref name="data"/>.</summary>
        public static uint Compute(byte[] data)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));
            return Compute(data, 0, data.Length);
        }

        /// <summary>Computes the CRC-32 of <paramref name="count"/> bytes of <paramref name="data"/> starting at <paramref name="offset"/>.</summary>
        public static uint Compute(byte[] data, int offset, int count)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));
            if (offset < 0 || offset > data.Length) throw new ArgumentOutOfRangeException(nameof(offset));
            if (count < 0 || count > data.Length - offset) throw new ArgumentOutOfRangeException(nameof(count));

            uint crc = 0xFFFFFFFFu;
            for (int i = offset; i < offset + count; i++)
                crc = Table[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
            return ~crc;
        }

        /// <summary>Computes the CRC-32 of the UTF-8 encoding of <paramref name="text"/>.</summary>
        public static uint Compute(string text)
        {
            if (text == null) throw new ArgumentNullException(nameof(text));
            return Compute(Encoding.UTF8.GetBytes(text));
        }

        private static uint[] BuildTable()
        {
            var table = new uint[256];
            for (uint n = 0; n < 256; n++)
            {
                uint c = n;
                for (int k = 0; k < 8; k++)
                    c = (c & 1) != 0 ? 0xEDB88320u ^ (c >> 1) : c >> 1;
                table[n] = c;
            }
            return table;
        }
    }
}
