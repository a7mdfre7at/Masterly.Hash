using System;

namespace Masterly.Hash.Tokens
{
    /// <summary>The authenticated contents of a signed token.</summary>
    /// <remarks>
    /// Tokens are signed, not encrypted: anyone holding one can read the subject, so do not put secrets in it.
    /// </remarks>
    public sealed class SignedTokenPayload
    {
        internal SignedTokenPayload(int version, string keyId, string purpose, string subject,
            DateTimeOffset issuedAt, DateTimeOffset expiresAt, string nonce)
        {
            Version = version;
            KeyId = keyId;
            Purpose = purpose;
            Subject = subject;
            IssuedAt = issuedAt;
            ExpiresAt = expiresAt;
            Nonce = nonce;
        }

        /// <summary>Token format version.</summary>
        public int Version { get; }

        /// <summary>Id of the key that signed the token.</summary>
        public string KeyId { get; }

        /// <summary>The purpose the token was validated against (and issued for).</summary>
        public string Purpose { get; }

        /// <summary>The subject, e.g. a user id or email address.</summary>
        public string Subject { get; }

        /// <summary>Issue time, to the second.</summary>
        public DateTimeOffset IssuedAt { get; }

        /// <summary>Expiry time, to the second.</summary>
        public DateTimeOffset ExpiresAt { get; }

        /// <summary>
        /// The token's 16-byte random nonce as 22 base64url characters; unique per token. To make a token
        /// single-use, record it in an <see cref="IUsedTokenStore"/> (see <see cref="SignedTokenService.ConsumeAsync"/>)
        /// until <see cref="ExpiresAt"/> plus the clock skew.
        /// </summary>
        public string Nonce { get; }
    }
}
