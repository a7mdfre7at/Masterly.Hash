using System;
using System.Security.Cryptography;
using System.Text;
using Masterly.Hash.Legacy.Internal;
using Masterly.Hash.Primitives;

namespace Masterly.Hash.Legacy
{
    /// <summary>
    /// Django's PBKDF2 hashers: <c>pbkdf2_sha256$&lt;iterations&gt;$&lt;salt&gt;$&lt;base64 hash&gt;</c> (the Django
    /// default) and <c>pbkdf2_sha1$...</c>. The hash is PBKDF2-HMAC over the UTF-8 password and UTF-8 salt with
    /// the digest's natural length (32 or 20 bytes).
    /// </summary>
    /// <remarks>
    /// <para>
    /// The iteration count is read from the stored hash, so it is capped by <see cref="MaxIterations"/>.
    /// Salts must be 1..128 printable ASCII characters other than <c>$</c>, which covers every salt Django generates.
    /// </para>
    /// <para>
    /// Onion wrapping: the digest is the decoded hash; the parameter is one algorithm byte (0 = SHA-1,
    /// 1 = SHA-256), the iteration count (4 bytes, big-endian) and the salt.
    /// </para>
    /// </remarks>
    public sealed class DjangoPbkdf2Format : ILegacyHashFormat
    {
        /// <summary>Default <see cref="MaxIterations"/>: 10,000,000.</summary>
        public const int DefaultMaxIterations = 10_000_000;

        private const int MaxSaltLength = 128;
        private const string Sha256Prefix = "pbkdf2_sha256";
        private const string Sha1Prefix = "pbkdf2_sha1";

        /// <summary>Django PBKDF2 with <see cref="DefaultMaxIterations"/>.</summary>
        public static readonly DjangoPbkdf2Format Default = new DjangoPbkdf2Format();

        /// <summary>Creates the format with <see cref="DefaultMaxIterations"/>.</summary>
        public DjangoPbkdf2Format()
            : this(DefaultMaxIterations)
        {
        }

        /// <summary>Creates the format, refusing hashes with more than <paramref name="maxIterations"/> iterations.</summary>
        public DjangoPbkdf2Format(int maxIterations)
        {
            if (maxIterations < 1)
                throw new ArgumentOutOfRangeException(nameof(maxIterations), maxIterations, "Max iterations must be positive.");
            MaxIterations = maxIterations;
        }

        /// <inheritdoc />
        public string Id => "django-pbkdf2";

        /// <summary>Highest accepted iteration count.</summary>
        public int MaxIterations { get; }

        /// <inheritdoc />
        public bool CanHandle(string storedHash) => TryParse(storedHash, MaxIterations, out _);

        /// <inheritdoc />
        public bool Verify(string password, string storedHash)
        {
            if (password == null) throw new ArgumentNullException(nameof(password));
            if (!TryParse(storedHash, MaxIterations, out Parsed parsed))
                return false;

            byte[] actual = Derive(password, parsed.Sha256, parsed.Salt, parsed.Iterations);
            bool match = HashPrimitives.FixedTimeEquals(parsed.Hash, actual);
            HashPrimitives.Zero(actual);
            HashPrimitives.Zero(parsed.Hash);
            return match;
        }

        /// <inheritdoc />
        public bool TryExtractWrapInput(string storedHash, out byte[] digest, out byte[] parameter)
        {
            digest = Array.Empty<byte>();
            parameter = Array.Empty<byte>();
            if (!TryParse(storedHash, MaxIterations, out Parsed parsed))
                return false;

            parameter = new byte[5 + parsed.Salt.Length];
            parameter[0] = parsed.Sha256 ? (byte)1 : (byte)0;
            LegacyEncoding.WriteUInt32BigEndian(parameter, 1, (uint)parsed.Iterations);
            Buffer.BlockCopy(parsed.Salt, 0, parameter, 5, parsed.Salt.Length);
            digest = parsed.Hash;
            return true;
        }

        /// <inheritdoc />
        public byte[] ComputeWrapInput(string password, byte[] parameter)
        {
            if (password == null) throw new ArgumentNullException(nameof(password));
            if (parameter == null || parameter.Length < 6 || parameter.Length > 5 + MaxSaltLength || parameter[0] > 1)
                throw new FormatException("Invalid Django PBKDF2 wrap parameter.");

            uint iterations = LegacyEncoding.ReadUInt32BigEndian(parameter, 1);
            string? salt = LegacyEncoding.FromPrintableAscii(parameter, 5, parameter.Length - 5);
            if (iterations < 1 || iterations > (uint)MaxIterations || salt == null || !IsValidSalt(salt))
                throw new FormatException("Invalid Django PBKDF2 wrap parameter.");

            return Derive(password, parameter[0] == 1, LegacyEncoding.Slice(parameter, 5, parameter.Length - 5), (int)iterations);
        }

        /// <summary>Reads the iteration count of a syntactically valid Django hash, ignoring <see cref="MaxIterations"/>.</summary>
        internal static bool TryReadIterations(string storedHash, out int iterations)
        {
            iterations = 0;
            if (!TryParse(storedHash, int.MaxValue, out Parsed parsed))
                return false;
            iterations = parsed.Iterations;
            return true;
        }

        private static bool TryParse(string storedHash, int maxIterations, out Parsed parsed)
        {
            parsed = default;
            if (storedHash == null || storedHash.Length > LegacyEncoding.MaxStoredLength)
                return false;

            string[] parts = storedHash.Split('$');
            if (parts.Length != 4)
                return false;

            bool sha256;
            if (string.Equals(parts[0], Sha256Prefix, StringComparison.Ordinal))
                sha256 = true;
            else if (string.Equals(parts[0], Sha1Prefix, StringComparison.Ordinal))
                sha256 = false;
            else
                return false;

            if (!LegacyEncoding.TryParseDecimal(parts[1], out long iterations) || iterations < 1 || iterations > maxIterations)
                return false;
            if (!IsValidSalt(parts[2]))
                return false;
            if (!LegacyEncoding.TryFromBase64Padded(parts[3], out byte[] hash) || hash.Length != (sha256 ? 32 : 20))
                return false;

            parsed = new Parsed(sha256, (int)iterations, Encoding.ASCII.GetBytes(parts[2]), hash);
            return true;
        }

        private static bool IsValidSalt(string salt)
        {
            if (salt.Length < 1 || salt.Length > MaxSaltLength)
                return false;
            foreach (char c in salt)
            {
                if (c < 0x21 || c > 0x7E || c == '$')
                    return false;
            }
            return true;
        }

        private static byte[] Derive(string password, bool sha256, byte[] salt, int iterations)
        {
            byte[] plain = LegacyEncoding.Utf8(password);
            try
            {
                return sha256
                    ? HashPrimitives.Pbkdf2(HashAlgorithmName.SHA256, plain, salt, iterations, 32)
                    : HashPrimitives.Pbkdf2(HashAlgorithmName.SHA1, plain, salt, iterations, 20);
            }
            finally
            {
                HashPrimitives.Zero(plain);
            }
        }

        private readonly struct Parsed
        {
            public Parsed(bool sha256, int iterations, byte[] salt, byte[] hash)
            {
                Sha256 = sha256;
                Iterations = iterations;
                Salt = salt;
                Hash = hash;
            }

            public bool Sha256 { get; }
            public int Iterations { get; }
            public byte[] Salt { get; }
            public byte[] Hash { get; }
        }
    }
}
