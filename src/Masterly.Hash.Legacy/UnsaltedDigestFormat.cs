using System;
using System.Security.Cryptography;
using Masterly.Hash.Legacy.Internal;
using Masterly.Hash.Primitives;

namespace Masterly.Hash.Legacy
{
    /// <summary>
    /// Unsalted hex digests of the UTF-8 password, <c>hex(H(password))</c> in either case: <see cref="Md5"/>
    /// (32 characters), <see cref="Sha1"/> (40), <see cref="Sha256"/> (64) and <see cref="Sha512"/> (128).
    /// The string length decides the algorithm.
    /// </summary>
    /// <remarks>
    /// These hashes can be reversed with precomputed tables in seconds and identical passwords have identical
    /// hashes. Onion-wrap them (<see cref="IPasswordHasher.TryWrap"/>) as soon as possible rather than waiting
    /// for each user to log in. The wrap digest is the decoded digest and the parameter is empty.
    /// </remarks>
    public sealed class UnsaltedDigestFormat : ILegacyHashFormat
    {
        /// <summary>Unsalted MD5, id <c>md5</c>.</summary>
        public static readonly UnsaltedDigestFormat Md5 = new UnsaltedDigestFormat("md5", HashAlgorithmName.MD5, 16);

        /// <summary>Unsalted SHA-1, id <c>sha1</c>.</summary>
        public static readonly UnsaltedDigestFormat Sha1 = new UnsaltedDigestFormat("sha1", HashAlgorithmName.SHA1, 20);

        /// <summary>Unsalted SHA-256, id <c>sha256</c>.</summary>
        public static readonly UnsaltedDigestFormat Sha256 = new UnsaltedDigestFormat("sha256", HashAlgorithmName.SHA256, 32);

        /// <summary>Unsalted SHA-512, id <c>sha512</c>.</summary>
        public static readonly UnsaltedDigestFormat Sha512 = new UnsaltedDigestFormat("sha512", HashAlgorithmName.SHA512, 64);

        private readonly HashAlgorithmName _algorithm;

        private UnsaltedDigestFormat(string id, HashAlgorithmName algorithm, int digestLength)
        {
            Id = id;
            _algorithm = algorithm;
            DigestLength = digestLength;
        }

        /// <inheritdoc />
        public string Id { get; }

        /// <summary>Digest length in bytes; the stored hash has twice as many hex characters.</summary>
        public int DigestLength { get; }

        /// <inheritdoc />
        public bool CanHandle(string storedHash) =>
            storedHash != null && storedHash.Length == 2 * DigestLength && LegacyEncoding.IsHex(storedHash);

        /// <inheritdoc />
        public bool Verify(string password, string storedHash)
        {
            if (password == null) throw new ArgumentNullException(nameof(password));
            if (!CanHandle(storedHash) || !LegacyEncoding.TryFromHex(storedHash, out byte[] expected))
                return false;

            byte[] actual = Compute(password);
            bool match = HashPrimitives.FixedTimeEquals(expected, actual);
            HashPrimitives.Zero(actual);
            HashPrimitives.Zero(expected);
            return match;
        }

        /// <inheritdoc />
        public bool TryExtractWrapInput(string storedHash, out byte[] digest, out byte[] parameter)
        {
            parameter = Array.Empty<byte>();
            if (!CanHandle(storedHash) || !LegacyEncoding.TryFromHex(storedHash, out digest))
            {
                digest = Array.Empty<byte>();
                return false;
            }
            return true;
        }

        /// <inheritdoc />
        public byte[] ComputeWrapInput(string password, byte[] parameter)
        {
            if (password == null) throw new ArgumentNullException(nameof(password));
            if (parameter == null || parameter.Length != 0)
                throw new FormatException($"Invalid {Id} wrap parameter.");
            return Compute(password);
        }

        private byte[] Compute(string password)
        {
            byte[] plain = LegacyEncoding.Utf8(password);
            try
            {
                using (HashAlgorithm hash = Create(_algorithm))
                    return hash.ComputeHash(plain);
            }
            finally
            {
                HashPrimitives.Zero(plain);
            }
        }

        private static HashAlgorithm Create(HashAlgorithmName algorithm)
        {
            if (algorithm == HashAlgorithmName.MD5) return MD5.Create();
            if (algorithm == HashAlgorithmName.SHA1) return SHA1.Create();
            if (algorithm == HashAlgorithmName.SHA256) return SHA256.Create();
            return SHA512.Create();
        }

        /// <inheritdoc />
        public override string ToString() => Id;
    }
}
