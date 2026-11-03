using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Masterly.Hash.Internal;

namespace Masterly.Hash.Pepper
{
    /// <summary>
    /// Local HMAC-SHA256 pepper with a key ring. Keep the keys outside the database (environment, secret store),
    /// otherwise a database leak also leaks the pepper.
    /// </summary>
    public sealed class HmacPepper : IPasswordPepper
    {
        /// <summary>Minimum key length in bytes.</summary>
        public const int MinKeyLength = 32;

        private readonly Dictionary<string, byte[]> _keys;

        /// <summary>Creates a pepper from a key ring. <paramref name="currentKeyId"/> must be in <paramref name="keys"/>.</summary>
        public HmacPepper(string currentKeyId, IReadOnlyDictionary<string, byte[]> keys)
        {
            if (keys == null) throw new ArgumentNullException(nameof(keys));
            if (!MhHash.IsValidKeyId(currentKeyId))
                throw new ArgumentException("Key id must match ^[A-Za-z0-9-]{1,32}$.", nameof(currentKeyId));

            _keys = new Dictionary<string, byte[]>(StringComparer.Ordinal);
            foreach (KeyValuePair<string, byte[]> pair in keys)
            {
                if (!MhHash.IsValidKeyId(pair.Key))
                    throw new ArgumentException($"Key id '{pair.Key}' must match ^[A-Za-z0-9-]{{1,32}}$.", nameof(keys));
                if (pair.Value == null || pair.Value.Length < MinKeyLength)
                    throw new ArgumentException($"Pepper key '{pair.Key}' must be at least {MinKeyLength} bytes.", nameof(keys));
                _keys[pair.Key] = (byte[])pair.Value.Clone();
            }

            if (!_keys.ContainsKey(currentKeyId))
                throw new ArgumentException($"Current key '{currentKeyId}' is not in the key ring.", nameof(currentKeyId));
            CurrentKeyId = currentKeyId;
        }

        /// <summary>Creates a pepper with a single key.</summary>
        public HmacPepper(string keyId, byte[] key)
            : this(keyId, new Dictionary<string, byte[]> { [keyId] = key })
        {
        }

        /// <summary>Creates a pepper from base64-encoded keys, e.g. bound from configuration.</summary>
        public static HmacPepper FromBase64(string currentKeyId, IReadOnlyDictionary<string, string> base64Keys)
        {
            if (base64Keys == null) throw new ArgumentNullException(nameof(base64Keys));
            var keys = new Dictionary<string, byte[]>(StringComparer.Ordinal);
            foreach (KeyValuePair<string, string> pair in base64Keys)
                keys[pair.Key] = Convert.FromBase64String(pair.Value);
            return new HmacPepper(currentKeyId, keys);
        }

        /// <summary>Generates a new random key suitable for this pepper.</summary>
        public static byte[] GenerateKey() => CryptoUtil.RandomBytes(MinKeyLength);

        /// <inheritdoc />
        public string CurrentKeyId { get; }

        /// <inheritdoc />
        public bool IsKnownKey(string keyId) => keyId != null && _keys.ContainsKey(keyId);

        /// <inheritdoc />
        public byte[] Apply(string keyId, byte[] input)
        {
            if (input == null) throw new ArgumentNullException(nameof(input));
            if (keyId == null || !_keys.TryGetValue(keyId, out byte[]? key))
                throw new KeyNotFoundException($"Unknown pepper key '{keyId}'.");
            using (var hmac = new HMACSHA256(key))
                return hmac.ComputeHash(input);
        }

        /// <inheritdoc />
        public ValueTask<byte[]> ApplyAsync(string keyId, byte[] input, CancellationToken cancellationToken = default) =>
            new ValueTask<byte[]>(Apply(keyId, input));
    }
}
