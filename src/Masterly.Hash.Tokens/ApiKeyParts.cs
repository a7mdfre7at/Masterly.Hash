using System.Diagnostics;

namespace Masterly.Hash.Tokens
{
    /// <summary>The parts of a well-formed API key, from <see cref="ApiKey.TryParse"/>.</summary>
    [DebuggerDisplay("{ToString(),nq}")]
    public sealed class ApiKeyParts
    {
        internal ApiKeyParts(string prefix, string randomPart, string checksum, int entropyBytes)
        {
            Prefix = prefix;
            RandomPart = randomPart;
            Checksum = checksum;
            EntropyBytes = entropyBytes;
        }

        /// <summary>The prefix, e.g. <c>mh_live</c>.</summary>
        public string Prefix { get; }

        /// <summary>The secret base62 random part. Treat it like the whole key.</summary>
        public string RandomPart { get; }

        /// <summary>The six-character base62 CRC-32 checksum.</summary>
        public string Checksum { get; }

        /// <summary>Number of random bytes encoded in <see cref="RandomPart"/>.</summary>
        public int EntropyBytes { get; }

        /// <summary>The prefix and checksum only; the random part is never included.</summary>
        public override string ToString() => Prefix + "_***" + Checksum;
    }
}
