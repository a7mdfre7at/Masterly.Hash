using System;
using System.Security.Cryptography;
using System.Text;
using Masterly.Hash.Internal;

namespace Masterly.Hash.Legacy
{
    /// <summary>Digest used by a Masterly.Hash 1.x hash.</summary>
    public enum V1Algorithm
    {
        /// <summary>SHA-256 (32-byte digest).</summary>
        SHA256,
        /// <summary>SHA-384 (48-byte digest).</summary>
        SHA384,
        /// <summary>SHA-512 (64-byte digest), the 1.x default.</summary>
        SHA512,
    }

    /// <summary>
    /// Hashes produced by Masterly.Hash 1.x: <c>base64(SHA-2(utf8(password) || salt) || salt)</c>.
    /// Enabled by default so existing users migrate on their next login.
    /// </summary>
    /// <remarks>
    /// 1.x did not record the algorithm and allowed arbitrary user-supplied salts, so the digest length cannot be
    /// inferred from the string. <see cref="Instance"/> tries SHA-512, SHA-384 and SHA-256. Onion wrapping needs
    /// the exact split, so it is only available when the algorithm is given explicitly.
    /// </remarks>
    public sealed class V1LegacyFormat : ILegacyHashFormat
    {
        private const int MaxStoredLength = 1024;

        /// <summary>Verifies any 1.x hash; cannot wrap.</summary>
        public static readonly V1LegacyFormat Instance = new V1LegacyFormat(null);

        private readonly V1Algorithm? _algorithm;

        /// <summary>Creates a v1 format restricted to one algorithm. Required for onion wrapping.</summary>
        public V1LegacyFormat(V1Algorithm? algorithm)
        {
            _algorithm = algorithm;
        }

        /// <inheritdoc />
        public string Id => "v1";

        /// <inheritdoc />
        public bool CanHandle(string storedHash) => TryDecode(storedHash, out _);

        /// <inheritdoc />
        public bool Verify(string password, string storedHash)
        {
            if (password == null) throw new ArgumentNullException(nameof(password));
            if (!TryDecode(storedHash, out byte[] decoded))
                return false;

            bool match = false;
            foreach (V1Algorithm algorithm in Candidates())
            {
                int size = DigestSize(algorithm);
                if (decoded.Length < size)
                    continue;

                byte[] expected = Slice(decoded, 0, size);
                byte[] salt = Slice(decoded, size, decoded.Length - size);
                byte[] actual = Compute(algorithm, password, salt);
                match |= CryptoUtil.FixedTimeEquals(expected, actual);
                CryptoUtil.Zero(actual);
            }

            return match;
        }

        /// <inheritdoc />
        public bool TryExtractWrapInput(string storedHash, out byte[] digest, out byte[] parameter)
        {
            digest = Array.Empty<byte>();
            parameter = Array.Empty<byte>();
            if (_algorithm == null || !TryDecode(storedHash, out byte[] decoded))
                return false;

            V1Algorithm algorithm = _algorithm.Value;
            int size = DigestSize(algorithm);
            if (decoded.Length < size)
                return false;

            digest = Slice(decoded, 0, size);
            parameter = new byte[1 + decoded.Length - size];
            parameter[0] = (byte)algorithm;
            Buffer.BlockCopy(decoded, size, parameter, 1, decoded.Length - size);
            return true;
        }

        /// <inheritdoc />
        public byte[] ComputeWrapInput(string password, byte[] parameter)
        {
            if (password == null) throw new ArgumentNullException(nameof(password));
            if (parameter == null || parameter.Length < 1 || parameter[0] > (byte)V1Algorithm.SHA512)
                throw new FormatException("Invalid v1 wrap parameter.");
            return Compute((V1Algorithm)parameter[0], password, Slice(parameter, 1, parameter.Length - 1));
        }

        private V1Algorithm[] Candidates() =>
            _algorithm.HasValue
                ? new[] { _algorithm.Value }
                : new[] { V1Algorithm.SHA512, V1Algorithm.SHA384, V1Algorithm.SHA256 };

        private static int DigestSize(V1Algorithm algorithm) =>
            algorithm == V1Algorithm.SHA256 ? 32 : algorithm == V1Algorithm.SHA384 ? 48 : 64;

        private static byte[] Compute(V1Algorithm algorithm, string password, byte[] salt)
        {
            byte[] plain = Encoding.UTF8.GetBytes(password);
            byte[] data = new byte[plain.Length + salt.Length];
            Buffer.BlockCopy(plain, 0, data, 0, plain.Length);
            Buffer.BlockCopy(salt, 0, data, plain.Length, salt.Length);
            try
            {
                using (HashAlgorithm sha = algorithm == V1Algorithm.SHA256 ? SHA256.Create()
                    : algorithm == V1Algorithm.SHA384 ? (HashAlgorithm)SHA384.Create() : SHA512.Create())
                    return sha.ComputeHash(data);
            }
            finally
            {
                CryptoUtil.Zero(plain);
                CryptoUtil.Zero(data);
            }
        }

        /// <summary>Strict, padded standard base64 as written by <c>Convert.ToBase64String</c>, at least 32 bytes.</summary>
        private static bool TryDecode(string storedHash, out byte[] decoded)
        {
            decoded = Array.Empty<byte>();
            if (storedHash == null || storedHash.Length < 44 || storedHash.Length > MaxStoredLength || storedHash.Length % 4 != 0)
                return false;

            bool allHex = true;
            foreach (char c in storedHash)
            {
                bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=';
                if (!ok)
                    return false;
                allHex &= (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
            }

            // A hex digest (e.g. unsalted SHA-256) is also valid base64. A real 1.x hash of 44+ random-looking
            // base64 characters is all-hex with probability below 1e-20, so leave hex strings to other formats.
            if (allHex)
                return false;

            try
            {
                decoded = Convert.FromBase64String(storedHash);
            }
            catch (FormatException)
            {
                return false;
            }

            return decoded.Length >= 32 && Convert.ToBase64String(decoded) == storedHash;
        }

        private static byte[] Slice(byte[] source, int offset, int count)
        {
            byte[] result = new byte[count];
            Buffer.BlockCopy(source, offset, result, 0, count);
            return result;
        }
    }
}
