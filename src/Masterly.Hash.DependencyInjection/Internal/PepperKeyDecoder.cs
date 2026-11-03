using System;
using Masterly.Hash.Primitives;

namespace Masterly.Hash.DependencyInjection.Internal
{
    /// <summary>Outcome of <see cref="PepperKeyDecoder.TryDecode"/>.</summary>
    internal enum PepperKeyDecodeResult
    {
        /// <summary>The key decoded and is at most <see cref="PepperKeyDecoder.MaxKeyLength"/> bytes.</summary>
        Ok,

        /// <summary>The value is missing, empty or not base64.</summary>
        NotBase64,

        /// <summary>The value encodes (or would encode) more than <see cref="PepperKeyDecoder.MaxKeyLength"/> bytes.</summary>
        TooLong,
    }

    /// <summary>Decodes configured pepper keys. Never echoes the key text.</summary>
    internal static class PepperKeyDecoder
    {
        /// <summary>Upper bound on a configured key, so a misconfigured value cannot allocate unbounded memory.</summary>
        public const int MaxKeyLength = 1024;

        /// <summary>Longest base64 text (padded) of a key of at most <see cref="MaxKeyLength"/> bytes.</summary>
        private const int MaxEncodedLength = (MaxKeyLength + 2) / 3 * 4;

        /// <summary>
        /// Decodes standard base64 (padded, or unpadded as written by <see cref="HashPrimitives.ToB64"/>).
        /// <paramref name="key"/> is set only when the result is <see cref="PepperKeyDecodeResult.Ok"/>;
        /// otherwise it is empty and any intermediate buffer has been zeroed.
        /// </summary>
        public static PepperKeyDecodeResult TryDecode(string? value, out byte[] key)
        {
            key = Array.Empty<byte>();
            if (value == null)
                return PepperKeyDecodeResult.NotBase64;

            string trimmed = value.Trim();
            if (trimmed.Length == 0)
                return PepperKeyDecodeResult.NotBase64;

            // Checked before decoding so an oversized value is never materialised.
            if (trimmed.Length > MaxEncodedLength)
                return PepperKeyDecodeResult.TooLong;

            byte[] decoded;
            if (trimmed.IndexOf('=') < 0 && trimmed.Length % 4 != 0)
            {
                if (!HashPrimitives.TryFromB64(trimmed, out decoded))
                    return PepperKeyDecodeResult.NotBase64;
            }
            else
            {
                try
                {
                    decoded = Convert.FromBase64String(trimmed);
                }
                catch (FormatException)
                {
                    return PepperKeyDecodeResult.NotBase64;
                }
            }

            if (decoded.Length > MaxKeyLength)
            {
                HashPrimitives.Zero(decoded);
                return PepperKeyDecodeResult.TooLong;
            }

            key = decoded;
            return PepperKeyDecodeResult.Ok;
        }
    }
}
