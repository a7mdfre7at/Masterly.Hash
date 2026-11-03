namespace Masterly.Hash.Tokens
{
    /// <summary>Outcome of validating a signed token. Only <see cref="Valid"/> means the token may be acted on.</summary>
    public enum SignedTokenStatus
    {
        /// <summary>Authentic, for the expected purpose, and within its lifetime.</summary>
        Valid = 0,

        /// <summary>Authentic and for the expected purpose, but past its expiry (plus clock skew).</summary>
        Expired = 1,

        /// <summary>Well-formed, but the tag does not match: tampered with, truncated or forged.</summary>
        InvalidSignature = 2,

        /// <summary>Authentic, but issued for a different purpose (e.g. an email-confirmation token used for a password reset).</summary>
        WrongPurpose = 3,

        /// <summary>Null, empty, too long, not base64url, an unknown version, or structurally invalid.</summary>
        Malformed = 4,

        /// <summary>Signed with a key id that is not (or no longer) in the key ring.</summary>
        UnknownKey = 5,

        /// <summary>Authentic, but its issue time is in the future by more than the allowed clock skew.</summary>
        NotYetValid = 6,

        /// <summary>
        /// Valid, but its nonce was already recorded by an <see cref="IUsedTokenStore"/>; returned only by
        /// <see cref="SignedTokenService.ConsumeAsync"/>.
        /// </summary>
        AlreadyUsed = 7,
    }
}
