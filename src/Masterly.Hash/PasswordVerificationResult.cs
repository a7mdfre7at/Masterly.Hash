namespace Masterly.Hash
{
    /// <summary>Outcome of a password verification.</summary>
    public enum VerificationStatus
    {
        /// <summary>The password does not match, or the stored hash could not be used. See <see cref="PasswordVerificationResult.FailureReason"/>.</summary>
        Failed,

        /// <summary>The password matches and the stored hash is current.</summary>
        Success,

        /// <summary>The password matches but the stored hash is outdated; store <see cref="PasswordVerificationResult.Rehash"/>.</summary>
        SuccessRehashNeeded,
    }

    /// <summary>Why a verification failed. Intended for logs and metrics, never for the end user.</summary>
    public enum VerificationFailureReason
    {
        /// <summary>No failure.</summary>
        None,
        /// <summary>Wrong password.</summary>
        Mismatch,
        /// <summary>No stored hash was supplied (<see cref="IPasswordHasher.VerifyOrDummy"/> with an unknown user).</summary>
        NoStoredHash,
        /// <summary>The stored hash is not in any recognised format.</summary>
        UnknownFormat,
        /// <summary>The stored hash is syntactically invalid.</summary>
        MalformedHash,
        /// <summary>The stored hash names a profile that is not registered (not in the allowlist).</summary>
        UnknownProfile,
        /// <summary>The stored hash was made with a pepper key that is no longer (or not yet) configured.</summary>
        UnknownPepperKey,
        /// <summary>The password exceeds <see cref="PasswordHasherOptions.MaxPasswordBytes"/>.</summary>
        PasswordTooLong,
        /// <summary>The password is empty. Empty passwords never match.</summary>
        EmptyPassword,
        /// <summary>The password is not valid UTF-16 (an unpaired surrogate) or contains a code point Unicode normalization rejects (U+FFFE).</summary>
        InvalidPassword,
    }

    /// <summary>Why a successful verification asked for a rehash.</summary>
    public enum RehashReason
    {
        /// <summary>No rehash needed.</summary>
        None,
        /// <summary>A legacy (non-Masterly or 1.x) format.</summary>
        LegacyFormat,
        /// <summary>An onion-wrapped legacy hash.</summary>
        Wrapped,
        /// <summary>A registered profile other than the current default.</summary>
        OutdatedProfile,
        /// <summary>An older pepper key, or a pepper was added since the hash was made.</summary>
        OutdatedPepperKey,
    }

    /// <summary>Result of <see cref="IPasswordHasher.Verify"/>.</summary>
    public sealed class PasswordVerificationResult
    {
        internal static readonly PasswordVerificationResult Current = new PasswordVerificationResult(VerificationStatus.Success, VerificationFailureReason.None, RehashReason.None, null);

        internal PasswordVerificationResult(VerificationStatus status, VerificationFailureReason failureReason, RehashReason rehashReason, string? rehash)
        {
            Status = status;
            FailureReason = failureReason;
            RehashReason = rehashReason;
            Rehash = rehash;
        }

        /// <summary>Overall outcome.</summary>
        public VerificationStatus Status { get; }

        /// <summary>True if the password is correct.</summary>
        public bool IsMatch => Status != VerificationStatus.Failed;

        /// <summary>True if the password is correct and the stored hash should be replaced.</summary>
        public bool NeedsRehash => Status == VerificationStatus.SuccessRehashNeeded;

        /// <summary>Why verification failed, if it did.</summary>
        public VerificationFailureReason FailureReason { get; }

        /// <summary>Why a rehash was requested, if it was.</summary>
        public RehashReason RehashReason { get; }

        /// <summary>
        /// A fresh hash with the current profile and pepper key. Non-null only when <see cref="NeedsRehash"/> is true
        /// and <see cref="PasswordHasherOptions.ComputeRehashOnVerify"/> is enabled. Also null for a legacy or wrapped
        /// hash whose password exceeds <see cref="PasswordHasherOptions.MaxPasswordBytes"/> only after NFKC
        /// normalization: the login succeeds, but the password cannot be stored in the native format.
        /// </summary>
        public string? Rehash { get; }

        internal static PasswordVerificationResult Fail(VerificationFailureReason reason) =>
            new PasswordVerificationResult(VerificationStatus.Failed, reason, RehashReason.None, null);

        /// <inheritdoc />
        public override string ToString() =>
            Status == VerificationStatus.Failed ? $"Failed ({FailureReason})"
            : Status == VerificationStatus.SuccessRehashNeeded ? $"SuccessRehashNeeded ({RehashReason})"
            : "Success";
    }
}
