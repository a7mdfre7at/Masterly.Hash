using System;
using System.Security.Cryptography;
using Masterly.Hash.Legacy.Internal;
using Masterly.Hash.Primitives;

namespace Masterly.Hash.Legacy
{
    /// <summary>
    /// ASP.NET Identity version 2 hashes (<c>PasswordHasherCompatibilityMode.IdentityV2</c>, also ASP.NET MVC 5
    /// / Identity 2.x and <c>System.Web.Helpers.Crypto.HashPassword</c>):
    /// <c>base64(0x00 || salt[16] || PBKDF2-HMAC-SHA1(password, salt, 1000 iterations)[32])</c>.
    /// </summary>
    /// <remarks>
    /// 1000 iterations of SHA-1 is weak by current standards; enable onion wrapping
    /// (<see cref="IPasswordHasher.TryWrap"/>) to protect these hashes before their users next log in.
    /// The wrap digest is the 32-byte subkey and the parameter is the 16-byte salt.
    /// </remarks>
    public sealed class AspNetIdentityV2Format : ILegacyHashFormat
    {
        internal const int Iterations = 1000;
        private const int SaltLength = 16;
        private const int SubkeyLength = 32;
        private const int DecodedLength = 1 + SaltLength + SubkeyLength;
        private const int EncodedLength = 68;

        /// <summary>The ASP.NET Identity v2 format. It has no settings.</summary>
        public static readonly AspNetIdentityV2Format Instance = new AspNetIdentityV2Format();

        private AspNetIdentityV2Format()
        {
        }

        /// <inheritdoc />
        public string Id => "aspnet-identity-v2";

        /// <inheritdoc />
        public bool CanHandle(string storedHash) => TryDecode(storedHash, out _);

        /// <inheritdoc />
        public bool Verify(string password, string storedHash)
        {
            if (password == null) throw new ArgumentNullException(nameof(password));
            if (!TryDecode(storedHash, out byte[] decoded))
                return false;

            byte[] salt = LegacyEncoding.Slice(decoded, 1, SaltLength);
            byte[] expected = LegacyEncoding.Slice(decoded, 1 + SaltLength, SubkeyLength);
            byte[] actual = Derive(password, salt);
            bool match = HashPrimitives.FixedTimeEquals(expected, actual);
            HashPrimitives.Zero(actual);
            HashPrimitives.Zero(expected);
            HashPrimitives.Zero(decoded);
            return match;
        }

        /// <inheritdoc />
        public bool TryExtractWrapInput(string storedHash, out byte[] digest, out byte[] parameter)
        {
            digest = Array.Empty<byte>();
            parameter = Array.Empty<byte>();
            if (!TryDecode(storedHash, out byte[] decoded))
                return false;

            parameter = LegacyEncoding.Slice(decoded, 1, SaltLength);
            digest = LegacyEncoding.Slice(decoded, 1 + SaltLength, SubkeyLength);
            HashPrimitives.Zero(decoded);
            return true;
        }

        /// <inheritdoc />
        public byte[] ComputeWrapInput(string password, byte[] parameter)
        {
            if (password == null) throw new ArgumentNullException(nameof(password));
            if (parameter == null || parameter.Length != SaltLength)
                throw new FormatException("Invalid ASP.NET Identity v2 wrap parameter.");
            return Derive(password, parameter);
        }

        private static byte[] Derive(string password, byte[] salt)
        {
            byte[] plain = LegacyEncoding.Utf8(password);
            try
            {
                return HashPrimitives.Pbkdf2(HashAlgorithmName.SHA1, plain, salt, Iterations, SubkeyLength);
            }
            finally
            {
                HashPrimitives.Zero(plain);
            }
        }

        private static bool TryDecode(string storedHash, out byte[] decoded)
        {
            decoded = Array.Empty<byte>();
            if (storedHash == null || storedHash.Length != EncodedLength)
                return false;
            if (!LegacyEncoding.TryFromBase64Padded(storedHash, out byte[] bytes))
                return false;
            if (bytes.Length != DecodedLength || bytes[0] != 0x00)
            {
                HashPrimitives.Zero(bytes);
                return false;
            }

            decoded = bytes;
            return true;
        }
    }
}
