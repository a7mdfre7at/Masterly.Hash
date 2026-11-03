using System;
using System.Security.Cryptography;
using Masterly.Hash.Legacy.Internal;
using Masterly.Hash.Primitives;

namespace Masterly.Hash.Legacy
{
    /// <summary>
    /// ASP.NET Core Identity version 3 hashes (the default of <c>Microsoft.AspNetCore.Identity.PasswordHasher&lt;TUser&gt;</c>):
    /// <c>base64(0x01 || prf[4] || iterations[4] || saltLength[4] || salt || subkey)</c>, header fields big-endian,
    /// PRF 0 = HMAC-SHA1, 1 = HMAC-SHA256, 2 = HMAC-SHA512.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The iteration count is read from the stored hash, so the total PBKDF2 work is capped by
    /// <see cref="MaxIterations"/>. PBKDF2 runs one full iteration chain per PRF output block, so a hash costs
    /// <c>iterations * ceil(subkeyLength / prfOutputLength)</c>: a 64-byte subkey over HMAC-SHA1 is four chains.
    /// Microsoft writes 32-byte subkeys, which is one block for HMAC-SHA256 and HMAC-SHA512.
    /// Salts outside 8..256 bytes (Microsoft writes 16) and subkeys outside 16..64 bytes are rejected.
    /// </para>
    /// <para>
    /// A string this format refuses, for example one over the cap, is still canonical base64 and can be claimed by
    /// the built-in Masterly.Hash 1.x format (<see cref="V1LegacyFormat"/>), which then reports it as <c>v1</c>.
    /// Do not bulk-wrap with an explicit-algorithm <see cref="V1LegacyFormat"/> while such hashes exist.
    /// </para>
    /// <para>
    /// Onion wrapping: the digest is the subkey; the parameter is the stored header and salt followed by one
    /// byte holding the subkey length.
    /// </para>
    /// </remarks>
    public sealed class AspNetIdentityV3Format : ILegacyHashFormat
    {
        /// <summary>Default <see cref="MaxIterations"/>: 10,000,000.</summary>
        public const int DefaultMaxIterations = 10_000_000;

        private const int HeaderLength = 13;
        private const int MinSaltLength = 8;
        private const int MaxSaltLength = 256;
        private const int MinSubkeyLength = 16;
        private const int MaxSubkeyLength = 64;

        /// <summary>ASP.NET Core Identity v3 with <see cref="DefaultMaxIterations"/>.</summary>
        public static readonly AspNetIdentityV3Format Default = new AspNetIdentityV3Format();

        /// <summary>Creates the format with <see cref="DefaultMaxIterations"/>.</summary>
        public AspNetIdentityV3Format()
            : this(DefaultMaxIterations)
        {
        }

        /// <summary>
        /// Creates the format, refusing hashes whose PBKDF2 work (iterations times output blocks) exceeds
        /// <paramref name="maxIterations"/>.
        /// </summary>
        public AspNetIdentityV3Format(int maxIterations)
        {
            if (maxIterations < 1)
                throw new ArgumentOutOfRangeException(nameof(maxIterations), maxIterations, "Max iterations must be positive.");
            MaxIterations = maxIterations;
        }

        /// <inheritdoc />
        public string Id => "aspnet-identity-v3";

        /// <summary>
        /// Highest accepted PBKDF2 work: the iteration count multiplied by the number of PRF output blocks the
        /// subkey needs (1 for Microsoft's 32-byte subkeys over HMAC-SHA256 or HMAC-SHA512).
        /// </summary>
        public int MaxIterations { get; }

        /// <inheritdoc />
        public bool CanHandle(string storedHash) => TryParse(storedHash, out _);

        /// <inheritdoc />
        public bool Verify(string password, string storedHash)
        {
            if (password == null) throw new ArgumentNullException(nameof(password));
            if (!TryParse(storedHash, out Parsed parsed))
                return false;

            byte[] actual = Derive(password, parsed.Prf, parsed.Salt, parsed.Iterations, parsed.Subkey.Length);
            bool match = HashPrimitives.FixedTimeEquals(parsed.Subkey, actual);
            HashPrimitives.Zero(actual);
            HashPrimitives.Zero(parsed.Subkey);
            HashPrimitives.Zero(parsed.Decoded);
            return match;
        }

        /// <inheritdoc />
        public bool TryExtractWrapInput(string storedHash, out byte[] digest, out byte[] parameter)
        {
            digest = Array.Empty<byte>();
            parameter = Array.Empty<byte>();
            if (!TryParse(storedHash, out Parsed parsed))
                return false;

            int headerAndSalt = HeaderLength + parsed.Salt.Length;
            parameter = new byte[headerAndSalt + 1];
            Buffer.BlockCopy(parsed.Decoded, 0, parameter, 0, headerAndSalt);
            parameter[headerAndSalt] = (byte)parsed.Subkey.Length;
            digest = parsed.Subkey;
            HashPrimitives.Zero(parsed.Decoded);
            return true;
        }

        /// <inheritdoc />
        public byte[] ComputeWrapInput(string password, byte[] parameter)
        {
            if (password == null) throw new ArgumentNullException(nameof(password));
            if (parameter == null || parameter.Length < HeaderLength + MinSaltLength + 1 || parameter[0] != 0x01)
                throw new FormatException("Invalid ASP.NET Identity v3 wrap parameter.");

            int subkeyLength = parameter[parameter.Length - 1];
            if (!TryReadHeader(parameter, parameter.Length - 1, out HashAlgorithmName prf, out int iterations, out int saltLength) ||
                saltLength != parameter.Length - 1 - HeaderLength ||
                subkeyLength < MinSubkeyLength || subkeyLength > MaxSubkeyLength ||
                Work(prf, iterations, subkeyLength) > MaxIterations)
                throw new FormatException("Invalid ASP.NET Identity v3 wrap parameter.");

            byte[] salt = LegacyEncoding.Slice(parameter, HeaderLength, saltLength);
            return Derive(password, prf, salt, iterations, subkeyLength);
        }

        /// <summary>Reads the iteration count of a syntactically valid v3 hash, ignoring <see cref="MaxIterations"/>.</summary>
        internal static bool TryReadIterations(string storedHash, out int iterations)
        {
            iterations = 0;
            if (!TryParse(storedHash, long.MaxValue, out Parsed parsed))
                return false;
            HashPrimitives.Zero(parsed.Decoded);
            HashPrimitives.Zero(parsed.Subkey);
            iterations = parsed.Iterations;
            return true;
        }

        private bool TryParse(string storedHash, out Parsed parsed) => TryParse(storedHash, MaxIterations, out parsed);

        private static bool TryParse(string storedHash, long maxWork, out Parsed parsed)
        {
            parsed = default;
            if (storedHash == null || storedHash.Length > LegacyEncoding.MaxStoredLength)
                return false;
            if (!LegacyEncoding.TryFromBase64Padded(storedHash, out byte[] decoded))
                return false;
            if (decoded.Length < HeaderLength + MinSaltLength + MinSubkeyLength || decoded[0] != 0x01)
                return false;
            if (!TryReadHeader(decoded, decoded.Length, out HashAlgorithmName prf, out int iterations, out int saltLength))
                return false;

            int subkeyLength = decoded.Length - HeaderLength - saltLength;
            if (subkeyLength < MinSubkeyLength || subkeyLength > MaxSubkeyLength || Work(prf, iterations, subkeyLength) > maxWork)
                return false;

            parsed = new Parsed(decoded, prf, iterations,
                LegacyEncoding.Slice(decoded, HeaderLength, saltLength),
                LegacyEncoding.Slice(decoded, HeaderLength + saltLength, subkeyLength));
            return true;
        }

        /// <summary>Reads PRF, iteration count and salt length; the salt must fit in the first <paramref name="available"/> bytes.</summary>
        private static bool TryReadHeader(byte[] buffer, int available, out HashAlgorithmName prf, out int iterations, out int saltLength)
        {
            prf = default;
            iterations = 0;
            saltLength = 0;

            uint prfId = LegacyEncoding.ReadUInt32BigEndian(buffer, 1);
            uint iter = LegacyEncoding.ReadUInt32BigEndian(buffer, 5);
            uint salt = LegacyEncoding.ReadUInt32BigEndian(buffer, 9);

            switch (prfId)
            {
                case 0: prf = HashAlgorithmName.SHA1; break;
                case 1: prf = HashAlgorithmName.SHA256; break;
                case 2: prf = HashAlgorithmName.SHA512; break;
                default: return false;
            }

            if (iter < 1 || iter > int.MaxValue)
                return false;
            if (salt < MinSaltLength || salt > MaxSaltLength || salt > (uint)(available - HeaderLength))
                return false;

            iterations = (int)iter;
            saltLength = (int)salt;
            return true;
        }

        /// <summary>PBKDF2 work: one full iteration chain per PRF output block of the subkey.</summary>
        private static long Work(HashAlgorithmName prf, int iterations, int subkeyLength)
        {
            int blockLength = prf == HashAlgorithmName.SHA1 ? 20 : prf == HashAlgorithmName.SHA256 ? 32 : 64;
            long blocks = (subkeyLength + blockLength - 1) / blockLength;
            return iterations * blocks;
        }

        private static byte[] Derive(string password, HashAlgorithmName prf, byte[] salt, int iterations, int length)
        {
            byte[] plain = LegacyEncoding.Utf8(password);
            try
            {
                return HashPrimitives.Pbkdf2(prf, plain, salt, iterations, length);
            }
            finally
            {
                HashPrimitives.Zero(plain);
            }
        }

        private readonly struct Parsed
        {
            public Parsed(byte[] decoded, HashAlgorithmName prf, int iterations, byte[] salt, byte[] subkey)
            {
                Decoded = decoded;
                Prf = prf;
                Iterations = iterations;
                Salt = salt;
                Subkey = subkey;
            }

            public byte[] Decoded { get; }
            public HashAlgorithmName Prf { get; }
            public int Iterations { get; }
            public byte[] Salt { get; }
            public byte[] Subkey { get; }
        }
    }
}
