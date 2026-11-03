using System;

namespace Masterly.Hash.Tokens
{
    /// <summary>
    /// Generates API keys with a fixed prefix and entropy and hashes them with an <see cref="ApiKeyHasher"/>.
    /// Thread-safe; register it as a singleton.
    /// </summary>
    public sealed class ApiKeyGenerator
    {
        private readonly ApiKeyHasher _hasher;

        /// <summary>Creates a generator.</summary>
        /// <param name="hasher">Computes the lookup hash of each new key.</param>
        /// <param name="prefix">Prefix such as <c>mh_live</c>; see <see cref="ApiKey.IsValidPrefix"/>.</param>
        /// <param name="entropyBytes">Random bytes per key, <see cref="ApiKey.MinEntropyBytes"/> to <see cref="ApiKey.MaxEntropyBytes"/>.</param>
        public ApiKeyGenerator(ApiKeyHasher hasher, string prefix, int entropyBytes = ApiKey.DefaultEntropyBytes)
        {
            _hasher = hasher ?? throw new ArgumentNullException(nameof(hasher));
            if (prefix == null) throw new ArgumentNullException(nameof(prefix));
            ApiKey.ValidatePrefix(prefix, nameof(prefix));
            ApiKey.ValidateEntropy(entropyBytes, nameof(entropyBytes));
            Prefix = prefix;
            EntropyBytes = entropyBytes;
        }

        /// <summary>The prefix of generated keys.</summary>
        public string Prefix { get; }

        /// <summary>Random bytes per generated key.</summary>
        public int EntropyBytes { get; }

        /// <summary>The hasher that computes lookup hashes.</summary>
        public ApiKeyHasher Hasher => _hasher;

        /// <summary>Generates a new key and its lookup hash.</summary>
        public GeneratedApiKey Generate() => ApiKey.Generate(_hasher, Prefix, EntropyBytes);
    }
}
