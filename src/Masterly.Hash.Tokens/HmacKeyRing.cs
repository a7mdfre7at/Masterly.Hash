using System;
using System.Collections.Generic;
using System.Linq;
using Masterly.Hash.Primitives;

namespace Masterly.Hash.Tokens
{
    /// <summary>
    /// A set of named HMAC keys with one current key, used by <see cref="ApiKeyHasher"/> and
    /// <see cref="SignedTokenService"/>. New values are made with the current key; values made with any key in
    /// the ring keep verifying, which is how keys are rotated: add a new key, make it current, and remove the old
    /// one once nothing depends on it.
    /// </summary>
    /// <remarks>
    /// Keep the keys outside the database (environment, secret store). The ring copies the keys it is given.
    /// Ring keys are only ever used to derive per-use subkeys (one for API-key lookup hashes, one for token
    /// signatures), never directly; using separate rings for the two is still recommended.
    /// </remarks>
    public sealed class HmacKeyRing
    {
        /// <summary>Minimum key length in bytes (256 bits).</summary>
        public const int MinKeyLength = 32;

        /// <summary>Maximum key-id length in characters.</summary>
        public const int MaxKeyIdLength = 32;

        private readonly Dictionary<string, byte[]> _keys;

        /// <summary>Creates a key ring. <paramref name="currentKeyId"/> must be one of <paramref name="keys"/>.</summary>
        /// <exception cref="ArgumentException">A key id is not <c>^[A-Za-z0-9-]{1,32}$</c>, a key is shorter than
        /// <see cref="MinKeyLength"/>, or the current key is missing.</exception>
        public HmacKeyRing(string currentKeyId, IReadOnlyDictionary<string, byte[]> keys)
        {
            if (currentKeyId == null) throw new ArgumentNullException(nameof(currentKeyId));
            if (keys == null) throw new ArgumentNullException(nameof(keys));
            if (!IsValidKeyId(currentKeyId))
                throw new ArgumentException("Key id must match ^[A-Za-z0-9-]{1,32}$.", nameof(currentKeyId));

            _keys = new Dictionary<string, byte[]>(StringComparer.Ordinal);
            foreach (KeyValuePair<string, byte[]> pair in keys)
            {
                if (!IsValidKeyId(pair.Key))
                    throw new ArgumentException("Every key id must match ^[A-Za-z0-9-]{1,32}$.", nameof(keys));
                if (pair.Value == null || pair.Value.Length < MinKeyLength)
                    throw new ArgumentException($"Key '{pair.Key}' must be at least {MinKeyLength} bytes.", nameof(keys));
                _keys[pair.Key] = (byte[])pair.Value.Clone();
            }

            if (!_keys.ContainsKey(currentKeyId))
                throw new ArgumentException($"Current key '{currentKeyId}' is not in the key ring.", nameof(currentKeyId));

            CurrentKeyId = currentKeyId;
            KeyIds = _keys.Keys.OrderBy(id => id, StringComparer.Ordinal).ToArray();
        }

        /// <summary>Creates a key ring with a single key.</summary>
        public HmacKeyRing(string keyId, byte[] key)
            : this(keyId, new Dictionary<string, byte[]>(StringComparer.Ordinal) { [NotNull(keyId, nameof(keyId))] = NotNull(key, nameof(key)) })
        {
        }

        private static T NotNull<T>(T? value, string paramName) where T : class =>
            value ?? throw new ArgumentNullException(paramName);

        /// <summary>Creates a key ring from base64-encoded keys, e.g. bound from configuration.</summary>
        /// <exception cref="FormatException">A key is not valid base64.</exception>
        public static HmacKeyRing FromBase64(string currentKeyId, IReadOnlyDictionary<string, string> base64Keys)
        {
            if (base64Keys == null) throw new ArgumentNullException(nameof(base64Keys));
            var keys = new Dictionary<string, byte[]>(StringComparer.Ordinal);
            try
            {
                foreach (KeyValuePair<string, string> pair in base64Keys)
                {
                    if (pair.Value == null)
                        throw new ArgumentException($"Key '{pair.Key}' is null.", nameof(base64Keys));
                    keys[pair.Key] = Convert.FromBase64String(pair.Value);
                }
                return new HmacKeyRing(currentKeyId, keys);
            }
            finally
            {
                foreach (byte[] key in keys.Values)
                    HashPrimitives.Zero(key);
            }
        }

        /// <summary>Generates a new random key of <see cref="MinKeyLength"/> bytes.</summary>
        public static byte[] GenerateKey() => HashPrimitives.RandomBytes(MinKeyLength);

        /// <summary>True if <paramref name="keyId"/> matches <c>^[A-Za-z0-9-]{1,32}$</c>.</summary>
        public static bool IsValidKeyId(string? keyId) => keyId != null && HashPrimitives.IsValidKeyId(keyId);

        /// <summary>Id of the key used for new values.</summary>
        public string CurrentKeyId { get; }

        /// <summary>Ids of every key in the ring, in ordinal order.</summary>
        public IReadOnlyList<string> KeyIds { get; }

        /// <summary>True if <paramref name="keyId"/> is in the ring.</summary>
        public bool Contains(string? keyId) => keyId != null && _keys.ContainsKey(keyId);

        /// <summary>
        /// Derives one subkey per ring key for a single use: <c>HMAC-SHA256(ringKey, 0xFF || ASCII(label))</c>.
        /// Ring keys are never used to MAC anything else, so every consumer works under its own independent key.
        /// The leading 0xFF byte never occurs in UTF-8, so no strict-UTF-8 input any consumer MACs can equal a
        /// derivation input, even under the raw ring key.
        /// </summary>
        internal Dictionary<string, byte[]> DeriveSubkeys(string label)
        {
            byte[] labelBytes = System.Text.Encoding.ASCII.GetBytes(label);
            byte[] info = new byte[1 + labelBytes.Length];
            info[0] = 0xFF;
            Buffer.BlockCopy(labelBytes, 0, info, 1, labelBytes.Length);

            var subkeys = new Dictionary<string, byte[]>(StringComparer.Ordinal);
            foreach (KeyValuePair<string, byte[]> pair in _keys)
                subkeys[pair.Key] = Internal.Hmac.Sha256(pair.Value, info);
            return subkeys;
        }
    }
}
