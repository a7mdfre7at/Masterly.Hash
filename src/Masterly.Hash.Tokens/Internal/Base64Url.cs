using System;
using Masterly.Hash.Primitives;

namespace Masterly.Hash.Tokens.Internal
{
    /// <summary>RFC 4648 section 5 base64url without padding, with strict canonical decoding.</summary>
    internal static class Base64Url
    {
        public static string Encode(byte[] bytes) =>
            HashPrimitives.ToB64(bytes).Replace('+', '-').Replace('/', '_');

        public static bool TryDecode(string? value, out byte[] bytes)
        {
            bytes = Array.Empty<byte>();
            if (string.IsNullOrEmpty(value))
                return false;

            char[] chars = new char[value!.Length];
            for (int i = 0; i < value.Length; i++)
            {
                char c = value[i];
                if (c == '+' || c == '/')
                    return false; // standard alphabet is not accepted
                chars[i] = c == '-' ? '+' : c == '_' ? '/' : c;
            }

            // HashPrimitives.TryFromB64 rejects padding, whitespace, foreign characters and non-canonical trailing bits.
            return HashPrimitives.TryFromB64(new string(chars), out bytes);
        }
    }
}
