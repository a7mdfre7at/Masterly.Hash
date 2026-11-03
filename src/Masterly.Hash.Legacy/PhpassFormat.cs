using System;
using System.Security.Cryptography;
using System.Text;
using Masterly.Hash.Legacy.Internal;
using Masterly.Hash.Primitives;

namespace Masterly.Hash.Legacy
{
    /// <summary>
    /// phpass portable hashes: <c>$P$</c> (WordPress, Drupal 7 imports, many PHP apps) and <c>$H$</c> (phpBB3).
    /// <c>$P$&lt;count&gt;&lt;8-char salt&gt;&lt;22-char hash&gt;</c>, where the hash is MD5 iterated
    /// 2^count times: <c>h = md5(salt || password); repeat: h = md5(h || password)</c>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Iterated MD5 is weak; protect these hashes with onion wrapping (<see cref="IPasswordHasher.TryWrap"/>).
    /// The wrap digest is the 22-character hash part and the parameter is the 12-character setting
    /// (<c>$P$</c>, count and salt), both ASCII.
    /// </para>
    /// <para>
    /// phpass allows a log2 count of 7..30. The count comes from the stored hash, so it is capped by
    /// <see cref="MaxCostLog2"/> (default 18); hashes above the cap are not handled.
    /// </para>
    /// <para>
    /// Every round hashes the whole password again, so the cost also grows with the password length. Like upstream
    /// phpass and WordPress, passwords longer than <see cref="MaxPasswordBytes"/> (4096 UTF-8 bytes) never match
    /// and are refused before any hashing.
    /// </para>
    /// </remarks>
    public sealed class PhpassFormat : ILegacyHashFormat
    {
        /// <summary>Default <see cref="MaxCostLog2"/>: 18 (262,144 MD5 rounds).</summary>
        public const int DefaultMaxCostLog2 = 18;

        /// <summary>Smallest log2 count phpass accepts.</summary>
        public const int MinCostLog2 = 7;

        /// <summary>Largest log2 count phpass accepts.</summary>
        public const int HardMaxCostLog2 = 30;

        /// <summary>Longest password (UTF-8 bytes) phpass hashes; longer passwords never match, as in upstream phpass.</summary>
        public const int MaxPasswordBytes = 4096;

        private const int SettingLength = 12;
        private const int HashLength = 34;
        private const int DigestLength = HashLength - SettingLength;
        private const string Itoa64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

        /// <summary>phpass with <see cref="DefaultMaxCostLog2"/>.</summary>
        public static readonly PhpassFormat Default = new PhpassFormat();

        /// <summary>Creates the format with <see cref="DefaultMaxCostLog2"/>.</summary>
        public PhpassFormat()
            : this(DefaultMaxCostLog2)
        {
        }

        /// <summary>Creates the format, refusing hashes whose log2 count exceeds <paramref name="maxCostLog2"/>.</summary>
        /// <param name="maxCostLog2">Between <see cref="MinCostLog2"/> and <see cref="HardMaxCostLog2"/>.</param>
        public PhpassFormat(int maxCostLog2)
        {
            if (maxCostLog2 < MinCostLog2 || maxCostLog2 > HardMaxCostLog2)
                throw new ArgumentOutOfRangeException(nameof(maxCostLog2), maxCostLog2, $"Max cost must be between {MinCostLog2} and {HardMaxCostLog2}.");
            MaxCostLog2 = maxCostLog2;
        }

        /// <inheritdoc />
        public string Id => "phpass";

        /// <summary>Highest accepted log2 iteration count.</summary>
        public int MaxCostLog2 { get; }

        /// <inheritdoc />
        public bool CanHandle(string storedHash) => TryParse(storedHash, out _);

        /// <inheritdoc />
        public bool Verify(string password, string storedHash)
        {
            if (password == null) throw new ArgumentNullException(nameof(password));
            if (!TryParse(storedHash, out int costLog2) || IsTooLong(password))
                return false;

            byte[] actual = Compute(password, storedHash, costLog2);
            byte[] expected = LegacyEncoding.Ascii(storedHash, SettingLength, DigestLength);
            bool match = HashPrimitives.FixedTimeEquals(expected, actual);
            HashPrimitives.Zero(actual);
            HashPrimitives.Zero(expected);
            return match;
        }

        /// <inheritdoc />
        public bool TryExtractWrapInput(string storedHash, out byte[] digest, out byte[] parameter)
        {
            digest = Array.Empty<byte>();
            parameter = Array.Empty<byte>();
            if (!TryParse(storedHash, out _))
                return false;

            digest = LegacyEncoding.Ascii(storedHash, SettingLength, DigestLength);
            parameter = LegacyEncoding.Ascii(storedHash, 0, SettingLength);
            return true;
        }

        /// <inheritdoc />
        public byte[] ComputeWrapInput(string password, byte[] parameter)
        {
            if (password == null) throw new ArgumentNullException(nameof(password));
            if (parameter == null || parameter.Length != SettingLength)
                throw new FormatException("Invalid phpass wrap parameter.");
            if (IsTooLong(password))
                throw new FormatException("Password is too long for phpass.");

            string? setting = LegacyEncoding.FromPrintableAscii(parameter, 0, parameter.Length);
            if (setting == null || !TryParseSetting(setting, out int costLog2) || costLog2 > MaxCostLog2)
                throw new FormatException("Invalid phpass wrap parameter.");

            return Compute(password, setting, costLog2);
        }

        /// <summary>Checked before hashing: phpass cost is linear in the password length.</summary>
        internal static bool IsTooLong(string password) =>
            password.Length > MaxPasswordBytes || Encoding.UTF8.GetByteCount(password) > MaxPasswordBytes;

        private bool TryParse(string storedHash, out int costLog2)
        {
            costLog2 = 0;
            if (storedHash == null || storedHash.Length != HashLength)
                return false;
            if (!TryParseSetting(storedHash, out costLog2) || costLog2 > MaxCostLog2)
                return false;

            for (int i = SettingLength; i < HashLength; i++)
            {
                if (Itoa64.IndexOf(storedHash[i]) < 0)
                    return false;
            }

            // The 22nd character encodes only the top two bits of the last byte.
            return Itoa64.IndexOf(storedHash[HashLength - 1]) < 4;
        }

        /// <summary>Validates <c>$P$</c> or <c>$H$</c>, the count character and 8 salt characters.</summary>
        private static bool TryParseSetting(string value, out int costLog2)
        {
            costLog2 = 0;
            if (value.Length < SettingLength || value[0] != '$' || (value[1] != 'P' && value[1] != 'H') || value[2] != '$')
                return false;

            costLog2 = Itoa64.IndexOf(value[3]);
            if (costLog2 < MinCostLog2 || costLog2 > HardMaxCostLog2)
                return false;

            for (int i = 4; i < SettingLength; i++)
            {
                if (Itoa64.IndexOf(value[i]) < 0)
                    return false;
            }

            return true;
        }

        /// <summary>phpass <c>crypt_private</c>: returns the 22-character encoded hash as ASCII.</summary>
        private static byte[] Compute(string password, string setting, int costLog2)
        {
            byte[] plain = LegacyEncoding.Utf8(password);
            byte[] buffer = new byte[16 + plain.Length];
            byte[] hash = new byte[16];
            try
            {
                using (MD5 md5 = MD5.Create())
                {
                    // h = md5(salt || password); the salt is 8 ASCII characters.
                    byte[] first = new byte[8 + plain.Length];
                    for (int i = 0; i < 8; i++)
                        first[i] = (byte)setting[4 + i];
                    Buffer.BlockCopy(plain, 0, first, 8, plain.Length);
                    byte[] h = md5.ComputeHash(first);
                    HashPrimitives.Zero(first);

                    Buffer.BlockCopy(plain, 0, buffer, 16, plain.Length);
                    long count = 1L << costLog2;
                    do
                    {
                        Buffer.BlockCopy(h, 0, buffer, 0, 16);
                        HashPrimitives.Zero(h);
                        h = md5.ComputeHash(buffer);
                    }
                    while (--count > 0);

                    Buffer.BlockCopy(h, 0, hash, 0, 16);
                    HashPrimitives.Zero(h);
                }

                return Encode64(hash);
            }
            finally
            {
                HashPrimitives.Zero(plain);
                HashPrimitives.Zero(buffer);
                HashPrimitives.Zero(hash);
            }
        }

        /// <summary>phpass <c>encode64</c> of 16 bytes: 22 characters, little-endian 6-bit groups.</summary>
        private static byte[] Encode64(byte[] input)
        {
            var output = new byte[DigestLength];
            int o = 0;
            int i = 0;
            int count = input.Length;
            do
            {
                int value = input[i++];
                output[o++] = (byte)Itoa64[value & 0x3f];
                if (i < count)
                    value |= input[i] << 8;
                output[o++] = (byte)Itoa64[(value >> 6) & 0x3f];
                if (i++ >= count)
                    break;
                if (i < count)
                    value |= input[i] << 16;
                output[o++] = (byte)Itoa64[(value >> 12) & 0x3f];
                if (i++ >= count)
                    break;
                output[o++] = (byte)Itoa64[(value >> 18) & 0x3f];
            }
            while (i < count);

            return output;
        }
    }
}
