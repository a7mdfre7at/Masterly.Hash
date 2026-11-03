using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Masterly.Hash.Primitives;
using Masterly.Hash.Tokens.Internal;

namespace Masterly.Hash.Tokens
{
    /// <summary>
    /// Creates and validates signed, expiring, purpose-bound tokens for password resets, email confirmation and
    /// magic links. Tokens are URL-safe (base64url) and stateless. Thread-safe; register it as a singleton.
    /// </summary>
    /// <remarks>
    /// <para>Binary layout (version 1), then base64url without padding:
    /// <c>version(1) | keyIdLength(1) | keyId | SHA-256(purpose)(32) | issuedAt(8) | expiresAt(8) | nonce(16) |
    /// subjectLength(2) | subject(UTF-8) | HMAC-SHA256 tag(32)</c>. Integers are big-endian; times are Unix seconds.
    /// The tag covers every preceding byte and is keyed with a subkey derived from the ring key
    /// (<c>HMAC-SHA256(ringKey, 0xFF || "Masterly.Hash.Tokens/SignedToken/v1")</c>). <see cref="ApiKeyHasher"/>
    /// uses its own derived subkey and never MACs with the raw ring key, and no UTF-8 input contains 0xFF, so a
    /// lookup hash can never reveal the token subkey. Separate rings for API keys and tokens are still recommended.
    /// Tags are compared in constant time.</para>
    /// <para>Tokens are signed, not encrypted: the subject is readable by whoever holds the token.</para>
    /// <para><b>Single use:</b> a stateless token can be replayed until it expires. For password resets and magic
    /// links, use <see cref="ConsumeAsync"/> with an <see cref="IUsedTokenStore"/>, which records
    /// <see cref="SignedTokenPayload.Nonce"/>. Binding the token to state that changes when it is used (e.g. putting
    /// a password-hash or security-stamp version in the purpose) also works.</para>
    /// </remarks>
    public sealed class SignedTokenService
    {
        /// <summary>The token format version this service writes.</summary>
        public const int CurrentVersion = 1;

        /// <summary>Maximum purpose length in characters.</summary>
        public const int MaxPurposeLength = 256;

        /// <summary>Nonce size in bytes.</summary>
        public const int NonceLength = 16;

        private const int PurposeHashLength = 32;
        private const int FixedLength = 1 + 1 + PurposeHashLength + 8 + 8 + NonceLength + 2 + Hmac.TagLength;
        private const long MaxUnixSeconds = 253402300799; // 9999-12-31T23:59:59Z

        internal const string SubkeyLabel = "Masterly.Hash.Tokens/SignedToken/v1";

        /// <summary>Extra time a used nonce is retained beyond its expiry plus twice the clock skew.</summary>
        internal static readonly TimeSpan RetainMargin = TimeSpan.FromMinutes(1);
        private static readonly UTF8Encoding StrictUtf8 = new UTF8Encoding(false, true);

        private readonly Dictionary<string, byte[]> _macKeys;
        private readonly string _currentKeyId;
        private readonly Func<DateTimeOffset> _clock;
        private readonly long _skewSeconds;
        private readonly int _maxTokenLength;
        private readonly int _maxSubjectBytes;
        private readonly TimeSpan _maxLifetime;

        /// <summary>Creates a service over a key ring with default options.</summary>
        public SignedTokenService(HmacKeyRing keyRing)
            : this(keyRing, new SignedTokenOptions())
        {
        }

        /// <summary>Creates a service. The options are copied; later changes to them have no effect.</summary>
        public SignedTokenService(HmacKeyRing keyRing, SignedTokenOptions options)
        {
            if (keyRing == null) throw new ArgumentNullException(nameof(keyRing));
            if (options == null) throw new ArgumentNullException(nameof(options));
            if (options.Clock == null) throw new ArgumentException("Clock is required.", nameof(options));
            if (options.ClockSkew < TimeSpan.Zero || options.ClockSkew > SignedTokenOptions.MaxClockSkew)
                throw new ArgumentException("ClockSkew must be between zero and one hour.", nameof(options));
            if (options.MaxTokenLength < 256 || options.MaxTokenLength > 16384)
                throw new ArgumentException("MaxTokenLength must be 256 to 16384.", nameof(options));
            if (options.MaxSubjectBytes < 1 || options.MaxSubjectBytes > 4096)
                throw new ArgumentException("MaxSubjectBytes must be 1 to 4096.", nameof(options));
            if (options.MaxLifetime <= TimeSpan.Zero || options.MaxLifetime > TimeSpan.FromDays(3650))
                throw new ArgumentException("MaxLifetime must be positive and at most 3650 days.", nameof(options));

            _macKeys = keyRing.DeriveSubkeys(SubkeyLabel);

            _currentKeyId = keyRing.CurrentKeyId;
            _clock = options.Clock;
            _skewSeconds = (long)Math.Ceiling(options.ClockSkew.TotalSeconds);
            _maxTokenLength = options.MaxTokenLength;
            _maxSubjectBytes = options.MaxSubjectBytes;
            _maxLifetime = options.MaxLifetime;
        }

        /// <summary>Id of the key that signs new tokens.</summary>
        public string CurrentKeyId => _currentKeyId;

        /// <summary>Creates a token.</summary>
        /// <param name="purpose">What the token is for, e.g. <c>"password-reset"</c>. Validation must name the same purpose.</param>
        /// <param name="subject">Who or what it is for, e.g. a user id. Readable by the token holder.</param>
        /// <param name="lifetime">How long it is valid; rounded up to whole seconds, at most <see cref="SignedTokenOptions.MaxLifetime"/>.</param>
        /// <exception cref="ArgumentException">The purpose or subject is empty or too long, or the token would exceed
        /// <see cref="SignedTokenOptions.MaxTokenLength"/>.</exception>
        public string Create(string purpose, string subject, TimeSpan lifetime)
        {
            if (purpose == null) throw new ArgumentNullException(nameof(purpose));
            if (subject == null) throw new ArgumentNullException(nameof(subject));
            byte[] purposeHash = HashPurpose(purpose, nameof(purpose));
            if (subject.Length == 0) throw new ArgumentException("Subject cannot be empty.", nameof(subject));
            byte[] subjectBytes = EncodeStrict(subject, nameof(subject));
            if (subjectBytes.Length > _maxSubjectBytes)
                throw new ArgumentException("Subject is longer than " + _maxSubjectBytes + " UTF-8 bytes.", nameof(subject));
            if (lifetime <= TimeSpan.Zero || lifetime > _maxLifetime)
                throw new ArgumentOutOfRangeException(nameof(lifetime), "Lifetime must be positive and at most MaxLifetime.");

            long issued = _clock().ToUnixTimeSeconds();
            long expires = issued + (long)Math.Ceiling(lifetime.TotalSeconds);
            if (issued < 0 || expires > MaxUnixSeconds)
                throw new InvalidOperationException("The clock is outside the supported range.");

            byte[] keyIdBytes = Encoding.ASCII.GetBytes(_currentKeyId);
            byte[] nonce = HashPrimitives.RandomBytes(NonceLength);
            byte[] token = new byte[FixedLength + keyIdBytes.Length + subjectBytes.Length];
            int pos = 0;
            token[pos++] = CurrentVersion;
            token[pos++] = (byte)keyIdBytes.Length;
            Copy(keyIdBytes, token, ref pos);
            Copy(purposeHash, token, ref pos);
            WriteInt64(token, ref pos, issued);
            WriteInt64(token, ref pos, expires);
            Copy(nonce, token, ref pos);
            token[pos++] = (byte)(subjectBytes.Length >> 8);
            token[pos++] = (byte)subjectBytes.Length;
            Copy(subjectBytes, token, ref pos);

            byte[] tag = ComputeTag(_macKeys[_currentKeyId], token, pos);
            Copy(tag, token, ref pos);

            string encoded = Base64Url.Encode(token);
            if (encoded.Length > _maxTokenLength)
                throw new ArgumentException("The token would be longer than MaxTokenLength; shorten the subject.", nameof(subject));
            return encoded;
        }

        /// <summary>
        /// Validates a token. Never throws for a bad token: null, garbage, tampered, truncated or oversized input
        /// returns a failure status. <paramref name="payload"/> is set for <see cref="SignedTokenStatus.Valid"/> and
        /// <see cref="SignedTokenStatus.Expired"/>, otherwise null; act on it only when the result is <c>Valid</c>.
        /// </summary>
        /// <param name="token">The token as received.</param>
        /// <param name="expectedPurpose">The purpose the caller is about to act on.</param>
        /// <param name="payload">The authenticated contents, or null.</param>
        public SignedTokenStatus Validate(string? token, string expectedPurpose, out SignedTokenPayload? payload)
        {
            if (expectedPurpose == null) throw new ArgumentNullException(nameof(expectedPurpose));
            byte[] expectedPurposeHash = HashPurpose(expectedPurpose, nameof(expectedPurpose));
            payload = null;

            if (token == null || token.Length == 0 || token.Length > _maxTokenLength)
                return SignedTokenStatus.Malformed;
            if (!Base64Url.TryDecode(token, out byte[] bytes) || bytes.Length < FixedLength + 1)
                return SignedTokenStatus.Malformed;
            if (bytes[0] != CurrentVersion)
                return SignedTokenStatus.Malformed;

            int keyIdLength = bytes[1];
            if (keyIdLength < 1 || keyIdLength > HmacKeyRing.MaxKeyIdLength || bytes.Length < FixedLength + keyIdLength)
                return SignedTokenStatus.Malformed;

            int pos = 2;
            string keyId = Encoding.ASCII.GetString(bytes, pos, keyIdLength);
            pos += keyIdLength;
            if (!HmacKeyRing.IsValidKeyId(keyId))
                return SignedTokenStatus.Malformed;

            byte[] purposeHash = Slice(bytes, ref pos, PurposeHashLength);
            long issued = ReadInt64(bytes, ref pos);
            long expires = ReadInt64(bytes, ref pos);
            byte[] nonce = Slice(bytes, ref pos, NonceLength);
            int subjectLength = (bytes[pos] << 8) | bytes[pos + 1];
            pos += 2;
            if (subjectLength < 1 || subjectLength > _maxSubjectBytes || pos + subjectLength + Hmac.TagLength != bytes.Length)
                return SignedTokenStatus.Malformed;
            int subjectOffset = pos;
            pos += subjectLength;
            int signedLength = pos;
            byte[] tag = Slice(bytes, ref pos, Hmac.TagLength);

            if (!_macKeys.TryGetValue(keyId, out byte[]? macKey))
                return SignedTokenStatus.UnknownKey;

            byte[] expectedTag = ComputeTag(macKey, bytes, signedLength);
            if (!HashPrimitives.FixedTimeEquals(expectedTag, tag))
                return SignedTokenStatus.InvalidSignature;

            // From here on the bytes were produced by this application.
            if (!HashPrimitives.FixedTimeEquals(expectedPurposeHash, purposeHash))
                return SignedTokenStatus.WrongPurpose;
            if (issued < 0 || expires <= issued || expires > MaxUnixSeconds)
                return SignedTokenStatus.Malformed;

            string subject;
            try
            {
                subject = StrictUtf8.GetString(bytes, subjectOffset, subjectLength);
            }
            catch (DecoderFallbackException)
            {
                return SignedTokenStatus.Malformed;
            }

            long now = _clock().ToUnixTimeSeconds();
            if (issued > now + _skewSeconds)
                return SignedTokenStatus.NotYetValid;

            payload = new SignedTokenPayload(CurrentVersion, keyId, expectedPurpose, subject,
                DateTimeOffset.FromUnixTimeSeconds(issued), DateTimeOffset.FromUnixTimeSeconds(expires),
                Base64Url.Encode(nonce));

            return now >= expires + _skewSeconds ? SignedTokenStatus.Expired : SignedTokenStatus.Valid;
        }

        /// <summary>
        /// Validates a token and returns true only if it is <see cref="SignedTokenStatus.Valid"/>. Never throws for a bad token.
        /// </summary>
        public bool TryValidate(string? token, string expectedPurpose, [NotNullWhen(true)] out SignedTokenPayload? payload)
        {
            SignedTokenStatus status = Validate(token, expectedPurpose, out payload);
            if (status == SignedTokenStatus.Valid && payload != null)
                return true;
            payload = null;
            return false;
        }

        /// <summary>
        /// Validates a token and, if valid, atomically records its nonce in <paramref name="store"/> so it cannot be
        /// used again. A second redemption returns <see cref="SignedTokenStatus.AlreadyUsed"/>.
        /// </summary>
        /// <remarks>
        /// <para>The nonce is recorded before the caller acts; if the action then fails, the user needs a new token.</para>
        /// <para>The store is asked to keep the nonce until <c>ExpiresAt + 2 * ClockSkew + 1 minute</c>: another
        /// server whose clock lags by up to the skew still accepts the token until <c>ExpiresAt + skew</c> on its
        /// own clock, i.e. up to <c>ExpiresAt + 2 * skew</c> on this one.</para>
        /// </remarks>
        public async ValueTask<SignedTokenResult> ConsumeAsync(string? token, string expectedPurpose, IUsedTokenStore store,
            CancellationToken cancellationToken = default)
        {
            if (store == null) throw new ArgumentNullException(nameof(store));
            SignedTokenStatus status = Validate(token, expectedPurpose, out SignedTokenPayload? payload);
            if (status != SignedTokenStatus.Valid || payload == null)
                return new SignedTokenResult(status, payload);

            DateTimeOffset retainUntil = RetainUntil(payload.ExpiresAt, _skewSeconds);
            bool first = await store.TryMarkUsedAsync(payload.Nonce, retainUntil, cancellationToken).ConfigureAwait(false);
            return new SignedTokenResult(first ? SignedTokenStatus.Valid : SignedTokenStatus.AlreadyUsed, payload);
        }

        private static DateTimeOffset RetainUntil(DateTimeOffset expiresAt, long skewSeconds)
        {
            TimeSpan extra = TimeSpan.FromSeconds(2 * skewSeconds) + RetainMargin;
            return DateTimeOffset.MaxValue - expiresAt <= extra ? DateTimeOffset.MaxValue : expiresAt + extra;
        }

        private static byte[] HashPurpose(string purpose, string paramName)
        {
            if (purpose.Length == 0) throw new ArgumentException("Purpose cannot be empty.", paramName);
            if (purpose.Length > MaxPurposeLength)
                throw new ArgumentException("Purpose is longer than " + MaxPurposeLength + " characters.", paramName);
            return Hmac.Sha256Hash(EncodeStrict(purpose, paramName));
        }

        private static byte[] EncodeStrict(string value, string paramName)
        {
            try
            {
                return StrictUtf8.GetBytes(value);
            }
            catch (EncoderFallbackException)
            {
                throw new ArgumentException("Value is not valid UTF-16.", paramName);
            }
        }

        private static byte[] ComputeTag(byte[] macKey, byte[] buffer, int length)
        {
            byte[] signed = new byte[length];
            Buffer.BlockCopy(buffer, 0, signed, 0, length);
            return Hmac.Sha256(macKey, signed);
        }

        private static void Copy(byte[] source, byte[] destination, ref int pos)
        {
            Buffer.BlockCopy(source, 0, destination, pos, source.Length);
            pos += source.Length;
        }

        private static byte[] Slice(byte[] source, ref int pos, int length)
        {
            byte[] result = new byte[length];
            Buffer.BlockCopy(source, pos, result, 0, length);
            pos += length;
            return result;
        }

        private static void WriteInt64(byte[] buffer, ref int pos, long value)
        {
            for (int shift = 56; shift >= 0; shift -= 8)
                buffer[pos++] = (byte)(value >> shift);
        }

        private static long ReadInt64(byte[] buffer, ref int pos)
        {
            long value = 0;
            for (int i = 0; i < 8; i++)
                value = (value << 8) | buffer[pos++];
            return value;
        }
    }
}
