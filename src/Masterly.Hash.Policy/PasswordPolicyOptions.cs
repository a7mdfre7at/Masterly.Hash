using System.Collections.Generic;

namespace Masterly.Hash.Policy
{
    /// <summary>
    /// Settings for <see cref="PasswordPolicy"/>. The defaults follow NIST SP 800-63B rev. 4 for a password used as a
    /// single authentication factor. There are deliberately no composition rules (no "one upper-case letter, one
    /// digit, one symbol") and no expiry: NIST says verifiers SHALL NOT impose either, because they make passwords
    /// more predictable, not stronger. Change passwords only on evidence of compromise.
    /// </summary>
    public sealed class PasswordPolicyOptions
    {
        /// <summary>Smallest <see cref="MinLength"/> accepted: 8, the NIST floor for any password.</summary>
        public const int MinimumAllowedMinLength = 8;

        /// <summary>Smallest <see cref="MaxLength"/> accepted: NIST says verifiers SHOULD permit at least 64 characters.</summary>
        public const int MinimumAllowedMaxLength = 64;

        /// <summary>Largest <see cref="MaxLength"/> accepted.</summary>
        public const int MaximumAllowedMaxLength = 4096;

        /// <summary>
        /// Minimum length in Unicode code points after NFKC normalization. Default 15, the NIST minimum when the
        /// password is the only factor. NIST allows 8 when the password is used only as part of multi-factor
        /// authentication. Values below 8 are rejected.
        /// </summary>
        public int MinLength { get; set; } = 15;

        /// <summary>
        /// Maximum length in code points. Default 128; must be between 64 and 4096. A code point takes up to 4 bytes in
        /// UTF-8, so keep <c>4 * MaxLength</c> within the hasher's <c>PasswordHasherOptions.MaxPasswordBytes</c>
        /// (default 1024) or very long non-Latin passwords will pass the policy and then be refused by the hasher.
        /// </summary>
        public int MaxLength { get; set; } = 128;

        /// <summary>Reject the 10,000 most common passwords (case-insensitive, l33t-insensitive). Default true; NIST requires a blocklist.</summary>
        public bool BlockCommonPasswords { get; set; } = true;

        /// <summary>Additional passwords to reject outright (case-insensitive, l33t-insensitive), e.g. your product name followed by the year.</summary>
        public IList<string> BlockedPasswords { get; } = new List<string>();

        /// <summary>
        /// Minimum strength score 0-4 (<see cref="StrengthEstimate.Score"/>). Default 3: at least 10^8 estimated
        /// guesses. Set 0 to report the score without enforcing it.
        /// </summary>
        public int MinimumScore { get; set; } = 3;

        /// <summary>Reject passwords containing a context word (user name, email, name, service name). Default true.</summary>
        public bool CheckContextWords { get; set; } = true;

        /// <summary>Words every password is checked against, typically the service and company name.</summary>
        public IList<string> ContextWords { get; } = new List<string>();

        /// <summary>
        /// Context words shorter than this (in code points) are not violations by themselves, so a user called
        /// "Al" can still use the word "alpine". They still lower the strength estimate. Default 4.
        /// </summary>
        public int MinContextWordLength { get; set; } = 4;

        /// <summary>
        /// Reject passwords made only of repeats, sequences and keyboard runs, e.g. <c>aaaaaa</c>, <c>aabaabaab</c> or
        /// <c>1234abcd</c>, at any length up to <see cref="MaxLength"/>. A repeated unit counts only if it is weak itself
        /// (at most three characters, or itself only repeats, sequences and keyboard runs), so a strong token typed
        /// twice is left to the score. Default true.
        /// </summary>
        public bool RejectRepetitiveOrSequential { get; set; } = true;

        /// <summary>A breached password is rejected when it appears at least this many times. Default 1.</summary>
        public int MinimumBreachOccurrences { get; set; } = 1;

        /// <summary>Year that years and dates in passwords are scored against. Null (default) means the current UTC year.</summary>
        public int? ReferenceYear { get; set; }
    }
}
