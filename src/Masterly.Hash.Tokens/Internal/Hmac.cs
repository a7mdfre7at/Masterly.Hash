using System.Security.Cryptography;

namespace Masterly.Hash.Tokens.Internal
{
    internal static class Hmac
    {
        public const int TagLength = 32;

        public static byte[] Sha256(byte[] key, byte[] data)
        {
            return HMACSHA256.HashData(key, data);
        }

        public static byte[] Sha256Hash(byte[] data)
        {
            return SHA256.HashData(data);
        }
    }
}
