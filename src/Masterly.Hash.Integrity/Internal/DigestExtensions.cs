namespace Masterly.Hash.Integrity.Internal
{
    /// <summary>Canonical, length-prefixed field encoding fed straight into a digest.</summary>
    internal static class DigestExtensions
    {
        /// <summary>Appends a 64-bit big-endian unsigned integer.</summary>
        public static void AppendUInt64(this ContentDigest digest, ulong value)
        {
            byte[] buffer = new byte[8];
            for (int i = 7; i >= 0; i--)
            {
                buffer[i] = (byte)value;
                value >>= 8;
            }
            digest.Append(buffer, 0, 8);
        }

        /// <summary>Appends an 8-byte big-endian length followed by the bytes.</summary>
        public static void AppendField(this ContentDigest digest, byte[] value)
        {
            digest.AppendUInt64((ulong)value.Length);
            digest.Append(value, 0, value.Length);
        }

        /// <summary>Appends a length-prefixed field from part of a buffer.</summary>
        public static void AppendField(this ContentDigest digest, byte[] value, int offset, int count)
        {
            digest.AppendUInt64((ulong)count);
            digest.Append(value, offset, count);
        }
    }
}
