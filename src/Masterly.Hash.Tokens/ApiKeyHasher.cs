using System;
using System.Collections.Generic;
using System.Text;
using Masterly.Hash.Primitives;
using Masterly.Hash.Tokens.Internal;

namespace Masterly.Hash.Tokens
{
    /// <summary>
    /// Keyed, deterministic lookup hashes for high-entropy secrets such as API keys:
    /// <c>&lt;keyId&gt;:&lt;base64 HMAC-SHA256(lookupKey, UTF-8(apiKey))&gt;</c>, where
    /// <c>lookupKey = HMAC-SHA256(ringKey, 0xFF || "Masterly.Hash.Tokens/ApiKeyLookup/v1")</c>.
    /// Thread-safe; register it as a singleton.
    /// </summary>
    /// <remarks>
    /// <para>A slow password hash (Argon2id) is the wrong tool here: an API key with 128+ random bits cannot be
    /// brute-forced, and a deterministic hash can be stored in a unique index so the key is found with one
    /// lookup instead of trying every row. The HMAC key (kept outside the database) means a database leak alone
    /// does not let anyone confirm guesses.</para>
    /// <para><b>Key separation:</b> the raw ring key is never used to MAC an API key; each ring key yields a
    /// lookup subkey that differs from the subkey <see cref="SignedTokenService"/> derives, so a lookup hash of any
    /// input (even one an attacker chose) reveals nothing about the token-signing key.</para>
    /// <para><b>Rotation:</b> make a new key current. New keys get lookup hashes under it; to find an existing key,
    /// query with <see cref="ComputeAllLookupHashes"/> (one hash per key in the ring) and, when
    /// <see cref="NeedsRehash"/> is true for the stored value, replace it with <see cref="ComputeLookupHash"/>.
    /// Remove the old key from the ring once no stored value uses it.</para>
    /// </remarks>
    public sealed class ApiKeyHasher
    {
        /// <summary>Longest API key that is hashed; longer input is rejected (and never matches).</summary>
        public const int MaxApiKeyLength = 1024;

        internal const string SubkeyLabel = "Masterly.Hash.Tokens/ApiKeyLookup/v1";

        private const char Separator = ':';
        private static readonly UTF8Encoding StrictUtf8 = new UTF8Encoding(false, true);

        private readonly HmacKeyRing _keyRing;
        private readonly Dictionary<string, byte[]> _lookupKeys;
        private readonly byte[] _currentLookupKey;

        /// <summary>Creates a hasher over a key ring.</summary>
        public ApiKeyHasher(HmacKeyRing keyRing)
        {
            _keyRing = keyRing ?? throw new ArgumentNullException(nameof(keyRing));
            _lookupKeys = keyRing.DeriveSubkeys(SubkeyLabel);
            _currentLookupKey = _lookupKeys[keyRing.CurrentKeyId];
        }

        /// <summary>The key ring.</summary>
        public HmacKeyRing KeyRing => _keyRing;

        /// <summary>Computes the lookup hash of <paramref name="apiKey"/> under the current key.</summary>
        /// <exception cref="ArgumentException"><paramref name="apiKey"/> is empty, longer than
        /// <see cref="MaxApiKeyLength"/> or not valid UTF-16.</exception>
        public string ComputeLookupHash(string apiKey)
        {
            if (apiKey == null) throw new ArgumentNullException(nameof(apiKey));
            byte[] input = EncodeOrThrow(apiKey);
            try
            {
                return Compute(_keyRing.CurrentKeyId, _currentLookupKey, input);
            }
            finally
            {
                HashPrimitives.Zero(input);
            }
        }

        /// <summary>
        /// Computes the lookup hash of <paramref name="apiKey"/> under every key in the ring, current key first,
        /// for a <c>WHERE lookup_hash IN (...)</c> query during key rotation.
        /// </summary>
        public IReadOnlyList<string> ComputeAllLookupHashes(string apiKey)
        {
            if (apiKey == null) throw new ArgumentNullException(nameof(apiKey));
            byte[] input = EncodeOrThrow(apiKey);
            try
            {
                var result = new List<string>(_keyRing.KeyIds.Count)
                {
                    Compute(_keyRing.CurrentKeyId, _currentLookupKey, input),
                };
                foreach (string keyId in _keyRing.KeyIds)
                {
                    if (keyId != _keyRing.CurrentKeyId && _lookupKeys.TryGetValue(keyId, out byte[]? key))
                        result.Add(Compute(keyId, key, input));
                }
                return result;
            }
            finally
            {
                HashPrimitives.Zero(input);
            }
        }

        /// <summary>
        /// Checks <paramref name="apiKey"/> against a stored lookup hash in constant time. Never throws: null,
        /// oversized or malformed input, and hashes made with a key no longer in the ring, all return false.
        /// </summary>
        public bool Verify(string? apiKey, string? storedLookupHash)
        {
            if (apiKey == null || apiKey.Length == 0 || apiKey.Length > MaxApiKeyLength)
                return false;
            if (!TryParseLookupHash(storedLookupHash, out string keyId, out byte[] storedTag))
                return false;
            if (!_lookupKeys.TryGetValue(keyId, out byte[]? key))
                return false;
            if (!TryEncode(apiKey, out byte[] input))
                return false;

            byte[] computed = Hmac.Sha256(key, input);
            try
            {
                return HashPrimitives.FixedTimeEquals(computed, storedTag);
            }
            finally
            {
                HashPrimitives.Zero(computed);
                HashPrimitives.Zero(input);
            }
        }

        /// <summary>
        /// True if <paramref name="storedLookupHash"/> was not made with the current key (or is not a lookup hash),
        /// so it should be replaced with <see cref="ComputeLookupHash"/> after a successful <see cref="Verify"/>.
        /// </summary>
        public bool NeedsRehash(string? storedLookupHash) =>
            !TryParseLookupHash(storedLookupHash, out string keyId, out _) ||
            !string.Equals(keyId, _keyRing.CurrentKeyId, StringComparison.Ordinal);

        /// <summary>
        /// Extracts the key id from a lookup hash. Returns false, without throwing, if it is not a well-formed lookup hash.
        /// </summary>
        public static bool TryGetKeyId(string? storedLookupHash, out string keyId)
        {
            bool ok = TryParseLookupHash(storedLookupHash, out keyId, out _);
            if (!ok)
                keyId = string.Empty;
            return ok;
        }

        private static string Compute(string keyId, byte[] key, byte[] input)
        {
            byte[] tag = Hmac.Sha256(key, input);
            try
            {
                return keyId + Separator + HashPrimitives.ToB64(tag);
            }
            finally
            {
                HashPrimitives.Zero(tag);
            }
        }

        private static bool TryParseLookupHash(string? value, out string keyId, out byte[] tag)
        {
            keyId = string.Empty;
            tag = Array.Empty<byte>();
            // keyId (<= 32) + ':' + 43 base64 characters.
            if (value == null || value.Length > HmacKeyRing.MaxKeyIdLength + 1 + 43)
                return false;

            int separator = value.IndexOf(Separator);
            if (separator <= 0)
                return false;

            string id = value.Substring(0, separator);
            if (!HmacKeyRing.IsValidKeyId(id))
                return false;
            if (!HashPrimitives.TryFromB64(value.Substring(separator + 1), out byte[] bytes) || bytes.Length != Hmac.TagLength)
                return false;

            keyId = id;
            tag = bytes;
            return true;
        }

        private static byte[] EncodeOrThrow(string apiKey)
        {
            if (apiKey.Length == 0)
                throw new ArgumentException("API key cannot be empty.", nameof(apiKey));
            if (apiKey.Length > MaxApiKeyLength)
                throw new ArgumentException("API key is longer than " + MaxApiKeyLength + " characters.", nameof(apiKey));
            if (!TryEncode(apiKey, out byte[] bytes))
                throw new ArgumentException("API key is not valid UTF-16.", nameof(apiKey));
            return bytes;
        }

        private static bool TryEncode(string apiKey, out byte[] bytes)
        {
            try
            {
                bytes = StrictUtf8.GetBytes(apiKey);
                return true;
            }
            catch (EncoderFallbackException)
            {
                bytes = Array.Empty<byte>();
                return false;
            }
        }
    }
}
