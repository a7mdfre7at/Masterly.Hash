using System;
using System.Security.Cryptography;
using System.Text;
using Masterly.Hash.Legacy.Internal;
using Masterly.Hash.Primitives;

namespace Masterly.Hash.Legacy
{
    /// <summary>
    /// WordPress 6.8+ bcrypt hashes: <c>$wp$2y$10$&lt;22-char salt&gt;&lt;31-char hash&gt;</c>, which is <c>$wp</c>
    /// followed by PHP's <c>password_hash(base64(HMAC-SHA384(key: "wp-sha384", password)), PASSWORD_BCRYPT)</c>.
    /// Older WordPress <c>$P$</c> hashes are handled by <see cref="PhpassFormat"/>, and plain bcrypt hashes (written
    /// by WordPress through a <c>password_hash</c> plugin) by <see cref="BCryptFormat"/>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The SHA-384 pre-hash means the whole password counts, not just its first 72 bytes. As in WordPress's
    /// <c>wp_check_password</c>, passwords longer than 4096 UTF-8 bytes never match, and the password is used as
    /// given (WordPress trims surrounding whitespace when it creates a hash, but not when it checks one).
    /// </para>
    /// <para>
    /// The bcrypt cost comes from the stored string and is capped by <see cref="MaxCost"/> (default 15); hashes
    /// above the cap are not handled.
    /// </para>
    /// <para>
    /// Onion wrapping: the digest is the 31-character bcrypt hash part, the parameter is the 29-character
    /// <c>$2y$10$&lt;salt&gt;</c> prefix without <c>$wp</c> (ASCII).
    /// </para>
    /// </remarks>
    public sealed class WordPressBcryptFormat : ILegacyHashFormat
    {
        /// <summary>Longest password (UTF-8 bytes) WordPress checks; longer passwords never match.</summary>
        public const int MaxPasswordBytes = 4096;

        private const string Marker = "$wp";
        private const int HashLength = 3 + BCryptFormat.HashLength;
        private const int PrefixEnd = 3 + BCryptFormat.PrefixLength;

        private static readonly byte[] HmacKey = Encoding.ASCII.GetBytes("wp-sha384");

        /// <summary>WordPress bcrypt with <see cref="BCryptFormat.DefaultMaxCost"/>.</summary>
        public static readonly WordPressBcryptFormat Default = new WordPressBcryptFormat();

        /// <summary>Creates the format with <see cref="BCryptFormat.DefaultMaxCost"/>.</summary>
        public WordPressBcryptFormat()
            : this(BCryptFormat.DefaultMaxCost)
        {
        }

        /// <summary>Creates the format, refusing hashes with a bcrypt cost above <paramref name="maxCost"/>.</summary>
        /// <param name="maxCost">Between <see cref="BCryptFormat.MinCost"/> and <see cref="BCryptFormat.HardMaxCost"/>.</param>
        public WordPressBcryptFormat(int maxCost)
        {
            if (maxCost < BCryptFormat.MinCost || maxCost > BCryptFormat.HardMaxCost)
                throw new ArgumentOutOfRangeException(nameof(maxCost), maxCost, $"Max cost must be between {BCryptFormat.MinCost} and {BCryptFormat.HardMaxCost}.");
            MaxCost = maxCost;
        }

        /// <inheritdoc />
        public string Id => "wordpress-bcrypt";

        /// <summary>Highest accepted bcrypt cost (log2 of the rounds).</summary>
        public int MaxCost { get; }

        /// <inheritdoc />
        public bool CanHandle(string storedHash) => TryParse(storedHash, out _);

        /// <inheritdoc />
        public bool Verify(string password, string storedHash)
        {
            if (password == null) throw new ArgumentNullException(nameof(password));
            if (!TryParse(storedHash, out _) || PhpassFormat.IsTooLong(password))
                return false;

            byte[]? actual = BCryptFormat.Compute(PreHash(password), storedHash.Substring(3, BCryptFormat.PrefixLength));
            if (actual == null)
                return false;

            byte[] expected = LegacyEncoding.Ascii(storedHash, PrefixEnd, BCryptFormat.DigestLength);
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

            digest = LegacyEncoding.Ascii(storedHash, PrefixEnd, BCryptFormat.DigestLength);
            parameter = LegacyEncoding.Ascii(storedHash, 3, BCryptFormat.PrefixLength);
            return true;
        }

        /// <inheritdoc />
        public byte[] ComputeWrapInput(string password, byte[] parameter)
        {
            if (password == null) throw new ArgumentNullException(nameof(password));
            if (parameter == null || parameter.Length != BCryptFormat.PrefixLength)
                throw new FormatException("Invalid WordPress bcrypt wrap parameter.");

            string? prefix = LegacyEncoding.FromPrintableAscii(parameter, 0, parameter.Length);
            if (prefix == null || !BCryptFormat.TryParsePrefix(prefix, out int cost) || cost > MaxCost)
                throw new FormatException("Invalid WordPress bcrypt wrap parameter.");
            if (PhpassFormat.IsTooLong(password))
                throw new FormatException("Password is too long for WordPress.");

            return BCryptFormat.Compute(PreHash(password), prefix) ?? throw new FormatException("Invalid WordPress bcrypt wrap parameter.");
        }

        /// <summary>Reads the bcrypt cost of a syntactically valid WordPress hash, ignoring <see cref="MaxCost"/>.</summary>
        internal static bool TryReadCost(string storedHash, out int cost)
        {
            cost = 0;
            return storedHash != null && storedHash.Length == HashLength &&
                storedHash.StartsWith(Marker + "$", StringComparison.Ordinal) &&
                BCryptFormat.TryReadCost(storedHash.Substring(3), out cost);
        }

        private bool TryParse(string storedHash, out int cost) =>
            TryReadCost(storedHash, out cost) && cost <= MaxCost;

        /// <summary><c>base64_encode(hash_hmac('sha384', $password, 'wp-sha384', true))</c>: 64 ASCII characters.</summary>
        private static string PreHash(string password)
        {
            byte[] plain = LegacyEncoding.Utf8(password);
            byte[]? mac = null;
            try
            {
                using (var hmac = new HMACSHA384(HmacKey))
                    mac = hmac.ComputeHash(plain);
                return Convert.ToBase64String(mac);
            }
            finally
            {
                HashPrimitives.Zero(plain);
                if (mac != null)
                    HashPrimitives.Zero(mac);
            }
        }
    }
}
