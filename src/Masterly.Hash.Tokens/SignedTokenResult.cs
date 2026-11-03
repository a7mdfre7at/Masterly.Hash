namespace Masterly.Hash.Tokens
{
    /// <summary>Result of <see cref="SignedTokenService.ConsumeAsync"/>.</summary>
    public sealed class SignedTokenResult
    {
        internal SignedTokenResult(SignedTokenStatus status, SignedTokenPayload? payload)
        {
            Status = status;
            Payload = payload;
        }

        /// <summary>The outcome.</summary>
        public SignedTokenStatus Status { get; }

        /// <summary>True only for <see cref="SignedTokenStatus.Valid"/>: the token may be acted on, and it has now been used up.</summary>
        public bool IsValid => Status == SignedTokenStatus.Valid;

        /// <summary>
        /// The authenticated payload for <see cref="SignedTokenStatus.Valid"/>, <see cref="SignedTokenStatus.Expired"/>
        /// and <see cref="SignedTokenStatus.AlreadyUsed"/>; otherwise null. Only act on it when <see cref="IsValid"/>.
        /// </summary>
        public SignedTokenPayload? Payload { get; }
    }
}
