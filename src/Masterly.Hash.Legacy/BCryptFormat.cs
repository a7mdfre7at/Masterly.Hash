using System;
using Masterly.Hash.Legacy.Internal;
using Masterly.Hash.Primitives;

namespace Masterly.Hash.Legacy
{
    /// <summary>
    /// bcrypt hashes in the modular crypt format: <c>$2a$</c>, <c>$2b$</c> and <c>$2y$</c>, e.g.
    /// <c>$2b$12$&lt;22-char salt&gt;&lt;31-char hash&gt;</c> (PHP <c>password_hash</c>, Spring Security, Devise,
    /// BCrypt.Net, node.bcrypt and most others). Verification uses BCrypt.Net-Next.
    /// </summary>
    /// <remarks>
    /// <para>
    /// bcrypt only reads the first 72 bytes of the UTF-8 password; anything after that is ignored. A user whose
    /// password is longer than 72 bytes can log in with just its first 72 bytes until the hash is upgraded, which a
    /// successful verify does automatically.
    /// </para>
    /// <para>
    /// The cost (log2 rounds) is read from the stored string, so it is capped by <see cref="MaxCost"/>: a hash
    /// above the cap is not handled at all (it reports as an unknown format) and costs nothing to reject.
    /// <c>$2x$</c> (the crypt_blowfish sign-extension bug mode) is not supported.
    /// </para>
    /// <para>
    /// Onion wrapping: the digest is the 31-character hash part, the parameter is the 29-character
    /// <c>$2b$12$&lt;salt&gt;</c> prefix (ASCII).
    /// </para>
    /// </remarks>
    public sealed class BCryptFormat : ILegacyHashFormat
    {
        /// <summary>Default <see cref="MaxCost"/>: 15 (about 2-3 seconds per verify on a 2025 server core).</summary>
        public const int DefaultMaxCost = 15;

        /// <summary>Smallest cost bcrypt defines.</summary>
        public const int MinCost = 4;

        /// <summary>Largest cost bcrypt defines.</summary>
        public const int HardMaxCost = 31;

        internal const int HashLength = 60;
        internal const int PrefixLength = 29;
        internal const int DigestLength = HashLength - PrefixLength;
        private const string Alphabet = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

        /// <summary>bcrypt with <see cref="DefaultMaxCost"/>.</summary>
        public static readonly BCryptFormat Default = new BCryptFormat();

        /// <summary>Creates a bcrypt format with <see cref="DefaultMaxCost"/>.</summary>
        public BCryptFormat()
            : this(DefaultMaxCost)
        {
        }

        /// <summary>Creates a bcrypt format that refuses hashes with a cost above <paramref name="maxCost"/>.</summary>
        /// <param name="maxCost">Highest accepted cost, between <see cref="MinCost"/> and <see cref="HardMaxCost"/>.</param>
        public BCryptFormat(int maxCost)
        {
            if (maxCost < MinCost || maxCost > HardMaxCost)
                throw new ArgumentOutOfRangeException(nameof(maxCost), maxCost, $"Max cost must be between {MinCost} and {HardMaxCost}.");
            MaxCost = maxCost;
        }

        /// <inheritdoc />
        public string Id => "bcrypt";

        /// <summary>Highest accepted cost (log2 of the rounds).</summary>
        public int MaxCost { get; }

        /// <inheritdoc />
        public bool CanHandle(string storedHash) => TryParse(storedHash, out _);

        /// <inheritdoc />
        public bool Verify(string password, string storedHash)
        {
            if (password == null) throw new ArgumentNullException(nameof(password));
            if (!TryParse(storedHash, out _))
                return false;

            byte[]? actual = Compute(password, storedHash.Substring(0, PrefixLength));
            if (actual == null)
                return false;

            byte[] expected = LegacyEncoding.Ascii(storedHash, PrefixLength, DigestLength);
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

            digest = LegacyEncoding.Ascii(storedHash, PrefixLength, DigestLength);
            parameter = LegacyEncoding.Ascii(storedHash, 0, PrefixLength);
            return true;
        }

        /// <inheritdoc />
        public byte[] ComputeWrapInput(string password, byte[] parameter)
        {
            if (password == null) throw new ArgumentNullException(nameof(password));
            if (parameter == null || parameter.Length != PrefixLength)
                throw new FormatException("Invalid bcrypt wrap parameter.");

            string? prefix = LegacyEncoding.FromPrintableAscii(parameter, 0, parameter.Length);
            if (prefix == null || !TryParsePrefix(prefix, out int cost) || cost > MaxCost)
                throw new FormatException("Invalid bcrypt wrap parameter.");

            return Compute(password, prefix) ?? throw new FormatException("Invalid bcrypt wrap parameter.");
        }

        /// <summary>Reads the cost of a syntactically valid bcrypt hash, ignoring <see cref="MaxCost"/>.</summary>
        internal static bool TryReadCost(string storedHash, out int cost)
        {
            cost = 0;
            if (storedHash == null || storedHash.Length != HashLength || !TryParsePrefix(storedHash, out cost))
                return false;

            for (int i = PrefixLength; i < HashLength; i++)
            {
                if (Alphabet.IndexOf(storedHash[i]) < 0)
                    return false;
            }

            // 31 characters carry 186 bits for a 184-bit hash: the last character's two low bits are always zero.
            return Alphabet.IndexOf(storedHash[HashLength - 1]) % 4 == 0;
        }

        private bool TryParse(string storedHash, out int cost) =>
            TryReadCost(storedHash, out cost) && cost <= MaxCost;

        /// <summary>Validates <c>$2[aby]$NN$&lt;22 salt chars&gt;</c> at the start of <paramref name="value"/>.</summary>
        internal static bool TryParsePrefix(string value, out int cost)
        {
            cost = 0;
            if (value.Length < PrefixLength)
                return false;
            if (value[0] != '$' || value[1] != '2' || (value[2] != 'a' && value[2] != 'b' && value[2] != 'y') || value[3] != '$' || value[6] != '$')
                return false;
            if (value[4] < '0' || value[4] > '9' || value[5] < '0' || value[5] > '9')
                return false;

            cost = (value[4] - '0') * 10 + (value[5] - '0');
            if (cost < MinCost || cost > HardMaxCost)
                return false;

            for (int i = 7; i < PrefixLength; i++)
            {
                if (Alphabet.IndexOf(value[i]) < 0)
                    return false;
            }

            return true;
        }

        /// <summary>The 31-character hash part BCrypt.Net computes for <paramref name="prefix"/>, as ASCII; null on failure.</summary>
        internal static byte[]? Compute(string password, string prefix)
        {
            string full;
            try
            {
                full = BCrypt.Net.BCrypt.HashPassword(password, prefix);
            }
            catch (BCrypt.Net.SaltParseException)
            {
                return null;
            }
            catch (ArgumentException)
            {
                return null;
            }

            if (full == null || full.Length != HashLength)
                return null;
            return LegacyEncoding.Ascii(full, PrefixLength, DigestLength);
        }
    }
}
