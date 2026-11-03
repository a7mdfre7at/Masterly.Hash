using System.Security.Cryptography;

namespace Masterly.Hash.Internal
{
    /// <summary>PBKDF2 (RFC 8018); callers restrict the PRF to HMAC-SHA1, HMAC-SHA256 or HMAC-SHA512.</summary>
    internal static class Pbkdf2
    {
        public static byte[] Derive(HashAlgorithmName algorithm, byte[] password, byte[] salt, int iterations, int length) =>
            Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, algorithm, length);
    }
}
