using System;

namespace Masterly.Hash.Policy
{
    /// <summary>A reason a password is rejected.</summary>
    public enum PasswordViolationCode
    {
        /// <summary>Fewer code points than <see cref="PasswordPolicyOptions.MinLength"/> (includes the empty password).</summary>
        TooShort,

        /// <summary>More code points than <see cref="PasswordPolicyOptions.MaxLength"/>.</summary>
        TooLong,

        /// <summary>One of the most common passwords, or on <see cref="PasswordPolicyOptions.BlockedPasswords"/>.</summary>
        CommonPassword,

        /// <summary>Contains the user name, email, name, service name or another context word.</summary>
        ContainsContextWord,

        /// <summary>Made only of repeated characters, sequences or keyboard runs, e.g. <c>aaaaaa</c> or <c>1234abcd</c>.</summary>
        RepetitiveOrSequential,

        /// <summary>The strength score is below <see cref="PasswordPolicyOptions.MinimumScore"/>.</summary>
        TooWeak,

        /// <summary>Found in a corpus of breached passwords by the configured <see cref="IBreachedPasswordChecker"/>.</summary>
        Breached,
    }

    /// <summary>One rule a password breaks. <see cref="Message"/> never contains the password.</summary>
    public sealed class PasswordViolation
    {
        /// <summary>Creates a violation.</summary>
        public PasswordViolation(PasswordViolationCode code, string message)
        {
            Code = code;
            Message = message ?? throw new ArgumentNullException(nameof(message));
        }

        /// <summary>Machine-readable reason; map it to your own localized text if needed.</summary>
        public PasswordViolationCode Code { get; }

        /// <summary>English explanation suitable for showing to the user.</summary>
        public string Message { get; }

        /// <inheritdoc />
        public override string ToString() => Code + ": " + Message;
    }
}
