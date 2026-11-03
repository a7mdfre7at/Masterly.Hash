using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Security.Cryptography;
using System.Text;
using Masterly.Hash.Primitives;

namespace Masterly.Hash.BlindIndex
{
    /// <summary>
    /// Blind indexes with a key ring, after the CipherSweet / Paragon Initiative Enterprises pattern.
    /// </summary>
    /// <remarks>
    /// <para>
    /// An index is <c>&lt;keyId&gt;:&lt;b64(Trunc(HMAC-SHA256(key, message), OutputBits))&gt;</c> where, with
    /// <c>LP(x) = uint32_be(len(x)) || x</c>:
    /// </para>
    /// <list type="bullet">
    /// <item><description>single value: <c>message = "masterly-blind-index/v1" || LP(utf8(indexName)) || LP(utf8(normalize(value)))</c></description></item>
    /// <item><description>compound: <c>message = "masterly-blind-index-compound/v1" || LP(utf8(indexName)) || uint32_be(count) || LP(utf8(normalize(part1))) || ...</c></description></item>
    /// </list>
    /// <para>
    /// The index name provides domain separation: the same value in two columns has unrelated indexes. The two domain
    /// tags differ at byte 20, so a single-value index can never equal a compound one. Keep keys outside the database
    /// and never reuse them between environments or for other purposes (such as a password pepper). Thread-safe.
    /// </para>
    /// </remarks>
    public sealed class BlindIndexer : IBlindIndexer
    {
        /// <summary>Minimum key length in bytes.</summary>
        public const int MinKeyLength = 32;

        /// <summary>Maximum index name length in characters.</summary>
        public const int MaxIndexNameLength = 128;

        internal static readonly byte[] SingleDomain = Encoding.ASCII.GetBytes("masterly-blind-index/v1");
        internal static readonly byte[] CompoundDomain = Encoding.ASCII.GetBytes("masterly-blind-index-compound/v1");

        private static readonly BlindIndexOptions DefaultOptions = new BlindIndexOptions();
        private static readonly UTF8Encoding StrictUtf8 = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

        private readonly Dictionary<string, byte[]> _keys;
        private readonly string[] _keyIds;
        private readonly ReadOnlyCollection<string> _keyIdsView;

        // Longest well-formed index: 32-char key id, ':', unpadded base64 of a 256-bit tag (43 chars).
        private const int MaxStoredIndexLength = 32 + 1 + 43;

        /// <summary>Creates an indexer from a key ring. <paramref name="currentKeyId"/> must be in <paramref name="keys"/>.</summary>
        /// <exception cref="ArgumentException">A key id is invalid, a key is shorter than <see cref="MinKeyLength"/>, or the current key is missing.</exception>
        public BlindIndexer(string currentKeyId, IReadOnlyDictionary<string, byte[]> keys)
        {
            if (keys == null) throw new ArgumentNullException(nameof(keys));
            if (!IsValidKeyId(currentKeyId))
                throw new ArgumentException("Key id must match ^[A-Za-z0-9-]{1,32}$.", nameof(currentKeyId));

            _keys = new Dictionary<string, byte[]>(StringComparer.Ordinal);
            foreach (KeyValuePair<string, byte[]> pair in keys)
            {
                if (!IsValidKeyId(pair.Key))
                    throw new ArgumentException("Every key id must match ^[A-Za-z0-9-]{1,32}$.", nameof(keys));
                if (pair.Value == null || pair.Value.Length < MinKeyLength)
                    throw new ArgumentException($"Blind index key '{pair.Key}' must be at least {MinKeyLength} bytes.", nameof(keys));
                _keys[pair.Key] = (byte[])pair.Value.Clone();
            }

            if (!_keys.ContainsKey(currentKeyId))
                throw new ArgumentException($"Current key '{currentKeyId}' is not in the key ring.", nameof(currentKeyId));
            CurrentKeyId = currentKeyId;

            var others = new List<string>(_keys.Count);
            foreach (string id in _keys.Keys)
            {
                if (id != currentKeyId)
                    others.Add(id);
            }
            others.Sort(StringComparer.Ordinal);
            others.Insert(0, currentKeyId);
            _keyIds = others.ToArray();
            _keyIdsView = Array.AsReadOnly(_keyIds);
        }

        /// <summary>Creates an indexer with a single key.</summary>
        public BlindIndexer(string keyId, byte[] key)
            : this(keyId, SingleKey(keyId, key))
        {
        }

        /// <summary>Creates an indexer from base64-encoded keys, e.g. bound from configuration or a secret store.</summary>
        /// <exception cref="ArgumentException">A key is not valid base64, or see the key-ring constructor.</exception>
        public static BlindIndexer FromBase64(string currentKeyId, IReadOnlyDictionary<string, string> base64Keys)
        {
            if (base64Keys == null) throw new ArgumentNullException(nameof(base64Keys));
            var keys = new Dictionary<string, byte[]>(StringComparer.Ordinal);
            try
            {
                foreach (KeyValuePair<string, string> pair in base64Keys)
                {
                    // Validate the id before echoing it: with swapped key/value columns it would be the secret.
                    if (!IsValidKeyId(pair.Key))
                        throw new ArgumentException("Every key id must match ^[A-Za-z0-9-]{1,32}$.", nameof(base64Keys));
                    if (pair.Value == null)
                        throw new ArgumentException($"Blind index key '{pair.Key}' is null.", nameof(base64Keys));
                    byte[] key;
                    try
                    {
                        key = Convert.FromBase64String(pair.Value);
                    }
                    catch (FormatException)
                    {
                        throw new ArgumentException($"Blind index key '{pair.Key}' is not valid base64.", nameof(base64Keys));
                    }
                    keys[pair.Key] = key;
                }
                return new BlindIndexer(currentKeyId, keys);
            }
            finally
            {
                foreach (byte[] key in keys.Values)
                    HashPrimitives.Zero(key);
            }
        }

        /// <summary>Generates a new random 256-bit key.</summary>
        public static byte[] GenerateKey() => HashPrimitives.RandomBytes(MinKeyLength);

        /// <inheritdoc />
        public string CurrentKeyId { get; }

        /// <inheritdoc />
        public IReadOnlyList<string> KeyIds => _keyIdsView;

        /// <inheritdoc />
        public string Compute(string value, string indexName, BlindIndexOptions? options = null) =>
            ComputeWithKey(CurrentKeyId, value, indexName, options);

        /// <inheritdoc />
        /// <exception cref="ArgumentException"><paramref name="keyId"/> is not in the ring, or the value or name is invalid.</exception>
        public string ComputeWithKey(string keyId, string value, string indexName, BlindIndexOptions? options = null)
        {
            byte[] key = GetKey(keyId);
            BlindIndexOptions resolved = Resolve(options);
            byte[] message = SingleMessage(value, indexName, resolved);
            try
            {
                return Format(keyId, key, message, resolved.OutputBits);
            }
            finally
            {
                HashPrimitives.Zero(message);
            }
        }

        /// <inheritdoc />
        public IReadOnlyList<string> ComputeAll(string value, string indexName, BlindIndexOptions? options = null)
        {
            BlindIndexOptions resolved = Resolve(options);
            byte[] message = SingleMessage(value, indexName, resolved);
            try
            {
                return FormatAll(message, resolved.OutputBits);
            }
            finally
            {
                HashPrimitives.Zero(message);
            }
        }

        /// <inheritdoc />
        public string ComputeCompound(string indexName, params string[] parts) => ComputeCompound(indexName, null, parts);

        /// <inheritdoc />
        public string ComputeCompound(string indexName, BlindIndexOptions? options, params string[] parts)
        {
            BlindIndexOptions resolved = Resolve(options);
            byte[] message = CompoundMessage(indexName, parts, resolved);
            try
            {
                return Format(CurrentKeyId, _keys[CurrentKeyId], message, resolved.OutputBits);
            }
            finally
            {
                HashPrimitives.Zero(message);
            }
        }

        /// <inheritdoc />
        public IReadOnlyList<string> ComputeCompoundAll(string indexName, params string[] parts) => ComputeCompoundAll(indexName, null, parts);

        /// <inheritdoc />
        public IReadOnlyList<string> ComputeCompoundAll(string indexName, BlindIndexOptions? options, params string[] parts)
        {
            BlindIndexOptions resolved = Resolve(options);
            byte[] message = CompoundMessage(indexName, parts, resolved);
            try
            {
                return FormatAll(message, resolved.OutputBits);
            }
            finally
            {
                HashPrimitives.Zero(message);
            }
        }

        /// <inheritdoc />
        public bool Matches(string? storedIndex, string value, string indexName, BlindIndexOptions? options = null)
        {
            BlindIndexOptions resolved = Resolve(options);
            byte[] message = SingleMessage(value, indexName, resolved);
            byte[]? stored = null;
            byte[]? computed = null;
            try
            {
                if (!TryParse(storedIndex, out string keyId, out stored) || !_keys.TryGetValue(keyId, out byte[]? key))
                    return false;
                if (stored.Length != resolved.OutputBits / 8)
                    return false;
                computed = Tag(key, message, resolved.OutputBits);
                return HashPrimitives.FixedTimeEquals(stored, computed);
            }
            finally
            {
                HashPrimitives.Zero(message);
                HashPrimitives.Zero(computed);
            }
        }

        /// <inheritdoc />
        public bool NeedsReindex(string? storedIndex) =>
            !TryParse(storedIndex, out string keyId, out _) || !string.Equals(keyId, CurrentKeyId, StringComparison.Ordinal);

        /// <summary>
        /// Reads the key id of a stored index (e.g. to count rows per key during rotation). Returns false, never
        /// throws, for a malformed index.
        /// </summary>
        public static bool TryGetKeyId(string? storedIndex, out string keyId) => TryParse(storedIndex, out keyId, out _);

        private static Dictionary<string, byte[]> SingleKey(string keyId, byte[] key)
        {
            if (keyId == null) throw new ArgumentNullException(nameof(keyId));
            return new Dictionary<string, byte[]>(StringComparer.Ordinal) { [keyId] = key };
        }

        private byte[] GetKey(string keyId)
        {
            if (keyId == null) throw new ArgumentNullException(nameof(keyId));
            if (!_keys.TryGetValue(keyId, out byte[]? key))
                throw new ArgumentException($"Key '{(IsValidKeyId(keyId) ? keyId : "?")}' is not in the key ring.", nameof(keyId));
            return key;
        }

        private static BlindIndexOptions Resolve(BlindIndexOptions? options)
        {
            if (options == null)
                return DefaultOptions;
            if (!BlindIndexOptions.IsValidOutputBits(options.OutputBits))
                throw new ArgumentException("OutputBits must be a multiple of 8 from 16 to 256.", nameof(options));
            if (options.Normalizer == null)
                throw new ArgumentException("Normalizer cannot be null.", nameof(options));
            return options;
        }

        private string Format(string keyId, byte[] key, byte[] message, int outputBits)
        {
            byte[] tag = Tag(key, message, outputBits);
            try
            {
                return keyId + ":" + HashPrimitives.ToB64(tag);
            }
            finally
            {
                HashPrimitives.Zero(tag);
            }
        }

        private IReadOnlyList<string> FormatAll(byte[] message, int outputBits)
        {
            var result = new string[_keyIds.Length];
            for (int i = 0; i < _keyIds.Length; i++)
                result[i] = Format(_keyIds[i], _keys[_keyIds[i]], message, outputBits);
            return result;
        }

        private static byte[] Tag(byte[] key, byte[] message, int outputBits)
        {
            byte[] full = HMACSHA256.HashData(key, message);
            try
            {
                byte[] tag = new byte[outputBits / 8];
                Buffer.BlockCopy(full, 0, tag, 0, tag.Length);
                return tag;
            }
            finally
            {
                HashPrimitives.Zero(full);
            }
        }

        private static byte[] SingleMessage(string value, string indexName, BlindIndexOptions options)
        {
            if (value == null) throw new ArgumentNullException(nameof(value));
            byte[] name = EncodeIndexName(indexName);
            byte[] encoded = EncodeValue(NormalizeValue(value, options.Normalizer), nameof(value));
            try
            {
                if (encoded.Length == 0)
                    throw new ArgumentException("Value is empty after normalization.", nameof(value));

                byte[] message = new byte[SingleDomain.Length + 4 + name.Length + 4 + encoded.Length];
                int offset = Append(message, 0, SingleDomain);
                offset = AppendPrefixed(message, offset, name);
                AppendPrefixed(message, offset, encoded);
                return message;
            }
            finally
            {
                HashPrimitives.Zero(encoded);
            }
        }

        private static byte[] CompoundMessage(string indexName, string[] parts, BlindIndexOptions options)
        {
            if (parts == null) throw new ArgumentNullException(nameof(parts));
            if (parts.Length == 0)
                throw new ArgumentException("A compound index needs at least one part.", nameof(parts));

            byte[] name = EncodeIndexName(indexName);
            var encoded = new byte[parts.Length][];
            try
            {
                int length = CompoundDomain.Length + 4 + name.Length + 4;
                bool allEmpty = true;
                for (int i = 0; i < parts.Length; i++)
                {
                    if (parts[i] == null)
                        throw new ArgumentNullException(nameof(parts), "Compound index parts cannot be null.");
                    encoded[i] = EncodeValue(NormalizeValue(parts[i], options.Normalizer), nameof(parts));
                    allEmpty &= encoded[i].Length == 0;
                    length += 4 + encoded[i].Length;
                }
                if (allEmpty)
                    throw new ArgumentException("Every compound index part is empty after normalization.", nameof(parts));

                byte[] message = new byte[length];
                int offset = Append(message, 0, CompoundDomain);
                offset = AppendPrefixed(message, offset, name);
                offset = WriteUInt32(message, offset, (uint)parts.Length);
                foreach (byte[] part in encoded)
                    offset = AppendPrefixed(message, offset, part);
                return message;
            }
            finally
            {
                foreach (byte[] part in encoded)
                    HashPrimitives.Zero(part);
            }
        }

        private static string NormalizeValue(string value, IBlindIndexNormalizer normalizer)
        {
            string? normalized = normalizer.Normalize(value);
            if (normalized == null)
                throw new InvalidOperationException($"Normalizer {normalizer.GetType().Name} returned null.");
            return normalized;
        }

        private static byte[] EncodeValue(string value, string paramName)
        {
            try
            {
                return StrictUtf8.GetBytes(value);
            }
            catch (EncoderFallbackException)
            {
                // Lossy encoding would let distinct invalid strings share an index.
                throw new ArgumentException("Value contains invalid UTF-16 (a lone surrogate).", paramName);
            }
        }

        private static byte[] EncodeIndexName(string indexName)
        {
            if (indexName == null) throw new ArgumentNullException(nameof(indexName));
            if (!IsValidIndexName(indexName))
                throw new ArgumentException("Index name must match ^[A-Za-z0-9._:/-]{1,128}$.", nameof(indexName));
            return Encoding.ASCII.GetBytes(indexName);
        }

        internal static bool IsValidIndexName(string indexName)
        {
            if (indexName.Length < 1 || indexName.Length > MaxIndexNameLength)
                return false;
            foreach (char c in indexName)
            {
                bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
                    || c == '.' || c == '_' || c == ':' || c == '/' || c == '-';
                if (!ok)
                    return false;
            }
            return true;
        }

        internal static bool IsValidKeyId(string? keyId) => keyId != null && HashPrimitives.IsValidKeyId(keyId);

        private static bool TryParse(string? storedIndex, out string keyId, out byte[] tag)
        {
            keyId = string.Empty;
            tag = Array.Empty<byte>();
            if (storedIndex == null || storedIndex.Length > MaxStoredIndexLength)
                return false;

            int colon = storedIndex.IndexOf(':');
            if (colon <= 0 || colon > 32)
                return false;

            string id = storedIndex.Substring(0, colon);
            if (!IsValidKeyId(id))
                return false;
            if (!HashPrimitives.TryFromB64(storedIndex.Substring(colon + 1), out byte[] bytes))
                return false;
            if (bytes.Length < BlindIndexOptions.MinOutputBits / 8 || bytes.Length > BlindIndexOptions.MaxOutputBits / 8)
                return false;

            keyId = id;
            tag = bytes;
            return true;
        }

        private static int Append(byte[] buffer, int offset, byte[] data)
        {
            Buffer.BlockCopy(data, 0, buffer, offset, data.Length);
            return offset + data.Length;
        }

        private static int AppendPrefixed(byte[] buffer, int offset, byte[] data) =>
            Append(buffer, WriteUInt32(buffer, offset, (uint)data.Length), data);

        private static int WriteUInt32(byte[] buffer, int offset, uint value)
        {
            buffer[offset] = (byte)(value >> 24);
            buffer[offset + 1] = (byte)(value >> 16);
            buffer[offset + 2] = (byte)(value >> 8);
            buffer[offset + 3] = (byte)value;
            return offset + 4;
        }
    }
}
