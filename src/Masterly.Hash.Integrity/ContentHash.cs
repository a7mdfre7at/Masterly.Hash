using System;
using System.Text.Json;
using System.Text.Json.Serialization;
using Masterly.Hash.Integrity.Internal;
using Masterly.Hash.Primitives;

namespace Masterly.Hash.Integrity
{
    /// <summary>
    /// An algorithm-tagged digest with a canonical string form: <c>sha256:&lt;lowercase hex&gt;</c> for plain hashes and
    /// <c>hmac-sha256:&lt;keyId&gt;:&lt;lowercase hex&gt;</c> for keyed ones. Immutable.
    /// </summary>
    /// <remarks>
    /// Parsing is strict: the algorithm must be registered (see <see cref="ContentHashAlgorithm.Register"/>), the hex
    /// must be lowercase and exactly as long as the algorithm's digest, so each hash has exactly one string form.
    /// Equality compares digests in constant time.
    /// </remarks>
    [JsonConverter(typeof(ContentHashJsonConverter))]
    public sealed class ContentHash : IEquatable<ContentHash>
    {
        /// <summary>Longest string <see cref="Parse"/> accepts.</summary>
        public const int MaxStringLength = 32 + 1 + 32 + 1 + 2 * 128;

        private readonly byte[] _digest;

        /// <summary>Wraps a digest produced by <paramref name="algorithm"/>. The bytes are copied.</summary>
        public ContentHash(ContentHashAlgorithm algorithm, byte[] digest)
        {
            if (algorithm == null) throw new ArgumentNullException(nameof(algorithm));
            if (digest == null) throw new ArgumentNullException(nameof(digest));
            if (digest.Length != algorithm.DigestLength)
                throw new ArgumentException($"Digest must be {algorithm.DigestLength} bytes for {algorithm.Name}.", nameof(digest));
            Algorithm = algorithm.Name;
            KeyId = algorithm.KeyId;
            _digest = (byte[])digest.Clone();
        }

        private ContentHash(string algorithm, string? keyId, byte[] digest)
        {
            Algorithm = algorithm;
            KeyId = keyId;
            _digest = digest;
        }

        /// <summary>Algorithm name, e.g. <c>sha256</c>.</summary>
        public string Algorithm { get; }

        /// <summary>Key id for keyed algorithms; <see langword="null"/> otherwise.</summary>
        public string? KeyId { get; }

        /// <summary>True if the hash was made with a keyed algorithm.</summary>
        public bool IsKeyed => KeyId != null;

        /// <summary>The raw digest.</summary>
        public ReadOnlyMemory<byte> Digest => _digest;

        internal byte[] DigestBytes => _digest;

        /// <summary>Wraps a digest without copying it. The caller must not keep or change the array.</summary>
        internal static ContentHash FromOwned(ContentHashAlgorithm algorithm, byte[] digest) =>
            new ContentHash(algorithm.Name, algorithm.KeyId, digest);

        /// <summary>Returns a copy of the digest.</summary>
        public byte[] ToArray() => (byte[])_digest.Clone();

        /// <summary>The digest as lowercase hex, without the algorithm prefix.</summary>
        public string ToHex() => Hex.Encode(_digest);

        /// <summary>True if this hash was produced by <paramref name="algorithm"/> (same name, key id and length).</summary>
        public bool IsFrom(ContentHashAlgorithm algorithm)
        {
            if (algorithm == null) throw new ArgumentNullException(nameof(algorithm));
            return algorithm.Name == Algorithm && algorithm.KeyId == KeyId && algorithm.DigestLength == _digest.Length;
        }

        /// <summary>Parses the canonical string form. Throws <see cref="FormatException"/> on any deviation.</summary>
        public static ContentHash Parse(string value)
        {
            if (value == null) throw new ArgumentNullException(nameof(value));
            if (!TryParse(value, out ContentHash? result))
                throw new FormatException("Not a valid content hash string.");
            return result!;
        }

        /// <summary>Parses the canonical string form. Never throws.</summary>
        public static bool TryParse(string? value, out ContentHash? result)
        {
            result = null;
            if (value == null || value.Length == 0 || value.Length > MaxStringLength)
                return false;

            int first = value.IndexOf(':');
            if (first <= 0)
                return false;
            string name = value.Substring(0, first);
            if (!Identifiers.IsValidAlgorithmName(name) || !ContentHashAlgorithm.TryGetRegistration(name, out int digestLength, out bool isKeyed))
                return false;

            string? keyId = null;
            int hexStart = first + 1;
            if (isKeyed)
            {
                int second = value.IndexOf(':', hexStart);
                if (second < 0)
                    return false;
                keyId = value.Substring(hexStart, second - hexStart);
                if (!Identifiers.IsValidKeyId(keyId))
                    return false;
                hexStart = second + 1;
            }

            int hexLength = value.Length - hexStart;
            if (hexLength != 2 * digestLength || !Hex.TryDecode(value, hexStart, hexLength, out byte[] digest))
                return false;

            result = new ContentHash(name, keyId, digest);
            return true;
        }

        /// <summary>Compares the digests in constant time, after checking that the algorithm identities match.</summary>
        public bool Equals(ContentHash? other) =>
            other != null && Algorithm == other.Algorithm && KeyId == other.KeyId &&
            HashPrimitives.FixedTimeEquals(_digest, other._digest);

        /// <inheritdoc />
        public override bool Equals(object? obj) => Equals(obj as ContentHash);

        /// <inheritdoc />
        public override int GetHashCode()
        {
            int code = StringComparer.Ordinal.GetHashCode(Algorithm);
            for (int i = 0; i < 4 && i < _digest.Length; i++)
                code = (code * 31) ^ _digest[i];
            return code;
        }

        /// <summary>The canonical string form.</summary>
        public override string ToString() =>
            KeyId == null ? Algorithm + ":" + ToHex() : Algorithm + ":" + KeyId + ":" + ToHex();
    }

    /// <summary>Serializes a <see cref="ContentHash"/> as its canonical string.</summary>
    public sealed class ContentHashJsonConverter : JsonConverter<ContentHash>
    {
        /// <inheritdoc />
        public override ContentHash? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            if (reader.TokenType == JsonTokenType.Null)
                return null;
            if (reader.TokenType != JsonTokenType.String)
                throw new JsonException("Expected a content hash string.");
            if (!ContentHash.TryParse(reader.GetString(), out ContentHash? hash))
                throw new JsonException("Not a valid content hash string.");
            return hash;
        }

        /// <inheritdoc />
        public override void Write(Utf8JsonWriter writer, ContentHash value, JsonSerializerOptions options)
        {
            if (writer == null) throw new ArgumentNullException(nameof(writer));
            if (value == null) throw new ArgumentNullException(nameof(value));
            writer.WriteStringValue(value.ToString());
        }
    }
}
