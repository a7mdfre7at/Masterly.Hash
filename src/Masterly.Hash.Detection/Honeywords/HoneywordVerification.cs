namespace Masterly.Hash.Detection
{
    /// <summary>Outcome of checking a password against a honeyword hash.</summary>
    /// <remarks>The zero (default) value is <see cref="Mismatch"/>, so an uninitialized result never reads as a match.</remarks>
    public enum HoneywordVerificationStatus
    {
        /// <summary>The password equals none of the sweetwords. Also the default value.</summary>
        Mismatch = 0,

        /// <summary>The password equals one of the sweetwords. Ask the honeychecker whether it is the real one.</summary>
        SweetwordMatch,

        /// <summary>No stored hash was supplied.</summary>
        NoStoredHash,

        /// <summary>The stored string is not a well-formed <c>$mhw$</c> hash.</summary>
        MalformedHash,

        /// <summary>The stored hash names a profile that is not in the allowlist.</summary>
        UnknownProfile,

        /// <summary>The stored hash was made with a pepper key that is not configured.</summary>
        UnknownPepperKey,

        /// <summary>The password is empty. Empty passwords never match.</summary>
        EmptyPassword,

        /// <summary>The password exceeds <see cref="HoneywordServiceOptions.MaxPasswordBytes"/>.</summary>
        PasswordTooLong,

        /// <summary>The password is not valid UTF-16 (an unpaired surrogate) or cannot be normalized (U+FFFE).</summary>
        InvalidPassword,
    }

    /// <summary>Result of <see cref="HoneywordService.VerifyDetailed"/>.</summary>
    /// <remarks>
    /// <c>default(HoneywordVerification)</c> is a <see cref="HoneywordVerificationStatus.Mismatch"/> with index -1.
    /// After a successful login the index is the user's real sweetword index, the secret only the honeychecker
    /// should hold: never log or store <see cref="Index"/>. <see cref="ToString"/> leaves it out.
    /// </remarks>
    public readonly struct HoneywordVerification
    {
        // Stored as index + 1 so that the default value means "no index".
        private readonly int _indexPlusOne;

        internal HoneywordVerification(HoneywordVerificationStatus status, int index)
        {
            Status = status;
            _indexPlusOne = status == HoneywordVerificationStatus.SweetwordMatch && index >= 0 ? index + 1 : 0;
        }

        /// <summary>What happened.</summary>
        public HoneywordVerificationStatus Status { get; }

        /// <summary>
        /// Zero-based index of the matching sweetword, or -1 (also -1 when <see cref="HoneywordLoginService"/> withholds
        /// the real index after a successful login). Never log or store it: for the real password it is the secret
        /// the honeychecker protects.
        /// </summary>
        public int Index => _indexPlusOne - 1;

        /// <summary>True if the password matched a sweetword (real or decoy).</summary>
        public bool IsSweetwordMatch => Status == HoneywordVerificationStatus.SweetwordMatch;

        internal static HoneywordVerification Fail(HoneywordVerificationStatus status) => new HoneywordVerification(status, -1);

        /// <summary>The status only. The index is left out so that it cannot end up in a log next to the user id.</summary>
        public override string ToString() => Status.ToString();
    }
}
