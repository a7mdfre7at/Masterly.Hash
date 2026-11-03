using System;
using System.Security.Cryptography;
using System.Text;
using Masterly.Hash.Internal;
using Masterly.Hash.Legacy;

namespace Masterly.Hash
{
    /// <summary>Hash functions supported by the 1.x API.</summary>
    [Obsolete("Use Password.Hash / Password.Verify. 1.x hashes keep verifying and are upgraded on login.")]
    public enum SupportedHash
    {
        /// <summary>SHA-256.</summary>
        SHA256,
        /// <summary>SHA-384.</summary>
        SHA384,
        /// <summary>SHA-512.</summary>
        SHA512,
    }

    /// <summary>The 1.x API.</summary>
    [Obsolete("Use IPasswordHasher. 1.x hashes keep verifying and are upgraded on login.")]
    public interface IHash
    {
        /// <summary>Single-pass salted SHA-2. Not suitable for passwords.</summary>
        string ComputeHash(string plainText, SupportedHash hash = SupportedHash.SHA512);

        /// <summary>Single-pass salted SHA-2. Not suitable for passwords.</summary>
        string ComputeHash(string plainText, byte[] saltBytes, SupportedHash hash = SupportedHash.SHA512);

        /// <summary>Single-pass salted SHA-2. Not suitable for passwords.</summary>
        string ComputeHash(string plainText, string salt, SupportedHash hash = SupportedHash.SHA512);

        /// <summary>Verifies a 1.x hash.</summary>
        bool Verify(string plainText, string hashValue, SupportedHash hash = SupportedHash.SHA512);
    }

    /// <summary>
    /// The 1.x API, kept so existing code compiles. It produces fast, single-pass hashes that are not suitable
    /// for passwords. <see cref="Verify"/> is now constant-time and no longer throws on a mismatched algorithm.
    /// </summary>
    [Obsolete("Use Password.Hash / Password.Verify. 1.x hashes keep verifying and are upgraded on login.")]
    public class Hash : IHash
    {
        /// <inheritdoc />
        public string ComputeHash(string plainText, SupportedHash hash = SupportedHash.SHA512) =>
            ComputeHash(plainText, CryptoUtil.RandomBytes(16), hash);

        /// <inheritdoc />
        public string ComputeHash(string plainText, string salt, SupportedHash hash = SupportedHash.SHA512)
        {
            if (salt == null) throw new ArgumentNullException(nameof(salt));
            return ComputeHash(plainText, Encoding.UTF8.GetBytes(salt), hash);
        }

        /// <inheritdoc />
        public string ComputeHash(string plainText, byte[] saltBytes, SupportedHash hash = SupportedHash.SHA512)
        {
            if (plainText == null) throw new ArgumentNullException(nameof(plainText));
            if (saltBytes == null) throw new ArgumentNullException(nameof(saltBytes));

            byte[] plain = Encoding.UTF8.GetBytes(plainText);
            byte[] data = new byte[plain.Length + saltBytes.Length];
            Buffer.BlockCopy(plain, 0, data, 0, plain.Length);
            Buffer.BlockCopy(saltBytes, 0, data, plain.Length, saltBytes.Length);

            byte[] digest;
            using (HashAlgorithm sha = hash == SupportedHash.SHA256 ? SHA256.Create()
                : hash == SupportedHash.SHA384 ? (HashAlgorithm)SHA384.Create() : SHA512.Create())
                digest = sha.ComputeHash(data);

            byte[] result = new byte[digest.Length + saltBytes.Length];
            Buffer.BlockCopy(digest, 0, result, 0, digest.Length);
            Buffer.BlockCopy(saltBytes, 0, result, digest.Length, saltBytes.Length);
            CryptoUtil.Zero(plain);
            CryptoUtil.Zero(data);
            return Convert.ToBase64String(result);
        }

        /// <inheritdoc />
        public bool Verify(string plainText, string hashValue, SupportedHash hash = SupportedHash.SHA512)
        {
            if (plainText == null) throw new ArgumentNullException(nameof(plainText));
            if (hashValue == null) return false;
            V1Algorithm algorithm = hash == SupportedHash.SHA256 ? V1Algorithm.SHA256
                : hash == SupportedHash.SHA384 ? V1Algorithm.SHA384 : V1Algorithm.SHA512;
            return new V1LegacyFormat(algorithm).Verify(plainText, hashValue);
        }
    }
}
