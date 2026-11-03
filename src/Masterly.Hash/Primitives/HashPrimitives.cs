using System;
using System.Security.Cryptography;
using Masterly.Hash.Internal;

namespace Masterly.Hash.Primitives
{
    /// <summary>
    /// Low-level building blocks shared by the Masterly.Hash packages. Application code should use
    /// <see cref="Password"/> or <see cref="PasswordHasher"/> instead.
    /// </summary>
    public static class HashPrimitives
    {
        /// <summary>Compares two byte arrays in time that depends only on their length.</summary>
        public static bool FixedTimeEquals(byte[] left, byte[] right)
        {
            if (left == null) throw new ArgumentNullException(nameof(left));
            if (right == null) throw new ArgumentNullException(nameof(right));
            return CryptoUtil.FixedTimeEquals(left, right);
        }

        /// <summary>Compares two spans in time that depends only on their length.</summary>
        public static bool FixedTimeEquals(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) => CryptoUtil.FixedTimeEquals(left, right);

        /// <summary>True if <paramref name="password"/> is valid UTF-16, i.e. the hasher accepts it.</summary>
        public static bool IsWellFormedPassword(string password)
        {
            if (password == null) throw new ArgumentNullException(nameof(password));
            return PasswordEncoding.IsWellFormed(password);
        }

        /// <summary>True if <paramref name="id"/> is a valid profile id (<c>^[a-z0-9][a-z0-9-]{0,31}$</c>).</summary>
        public static bool IsValidProfileId(string id) => HashProfile.IsValidId(id);

        /// <summary>True if <paramref name="keyId"/> is a valid pepper key id (<c>^[A-Za-z0-9-]{1,32}$</c>).</summary>
        public static bool IsValidKeyId(string keyId) => MhHash.IsValidKeyId(keyId);

        /// <summary>True if <paramref name="formatId"/> is a valid legacy format id (<c>^[a-z0-9][a-z0-9-]{0,31}$</c>).</summary>
        public static bool IsValidFormatId(string formatId) => MhHash.IsValidFormatId(formatId);

        /// <summary>Overwrites a buffer that held secret material.</summary>
        public static void Zero(byte[]? buffer) => CryptoUtil.Zero(buffer);

        /// <summary>Returns cryptographically secure random bytes.</summary>
        public static byte[] RandomBytes(int length)
        {
            if (length < 0) throw new ArgumentOutOfRangeException(nameof(length));
            return CryptoUtil.RandomBytes(length);
        }

        /// <summary>PBKDF2 (RFC 8018) with HMAC-SHA1, HMAC-SHA256 or HMAC-SHA512.</summary>
        public static byte[] Pbkdf2(HashAlgorithmName prf, byte[] password, byte[] salt, int iterations, int length)
        {
            if (password == null) throw new ArgumentNullException(nameof(password));
            if (salt == null) throw new ArgumentNullException(nameof(salt));
            if (iterations < 1) throw new ArgumentOutOfRangeException(nameof(iterations));
            if (length < 1) throw new ArgumentOutOfRangeException(nameof(length));
            if (prf != HashAlgorithmName.SHA1 && prf != HashAlgorithmName.SHA256 && prf != HashAlgorithmName.SHA512)
                throw new ArgumentOutOfRangeException(nameof(prf), prf.Name, "Supported PRFs are SHA1, SHA256 and SHA512.");
            return Internal.Pbkdf2.Derive(prf, password, salt, iterations, length);
        }

        /// <summary>
        /// Runs a profile's key-derivation function with an explicit salt. Bypasses the hasher's concurrency
        /// limit, pepper and format; for building custom schemes (e.g. honeywords) on the same KDF.
        /// </summary>
        public static byte[] DeriveKey(HashProfile profile, byte[] input, byte[] salt)
        {
            if (profile == null) throw new ArgumentNullException(nameof(profile));
            if (input == null) throw new ArgumentNullException(nameof(input));
            if (salt == null) throw new ArgumentNullException(nameof(salt));
            if (input.Length == 0) throw new ArgumentException("Input cannot be empty.", nameof(input));
            if (salt.Length < 8) throw new ArgumentException("Salt must be at least 8 bytes.", nameof(salt));
            return Kdf.Derive(profile, input, salt);
        }

        /// <summary>
        /// The exact bytes the hasher feeds to the KDF for a password: UTF-8 of the NFKC-normalized string
        /// (NIST SP 800-63B). Throws <see cref="ArgumentException"/> if the string contains an unpaired surrogate.
        /// </summary>
        public static byte[] EncodePassword(string password)
        {
            if (password == null) throw new ArgumentNullException(nameof(password));
            return PasswordEncoding.Encode(password);
        }

        /// <summary>Standard base64 without padding (PHC string encoding).</summary>
        public static string ToB64(byte[] bytes)
        {
            if (bytes == null) throw new ArgumentNullException(nameof(bytes));
            return CryptoUtil.ToB64(bytes);
        }

        /// <summary>Strict, canonical decoding of unpadded standard base64.</summary>
        public static bool TryFromB64(string value, out byte[] bytes)
        {
            if (value == null)
            {
                bytes = Array.Empty<byte>();
                return false;
            }
            return CryptoUtil.TryFromB64(value, out bytes);
        }
    }
}
