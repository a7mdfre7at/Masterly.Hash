using System.Collections.Generic;
using System.Globalization;

namespace Masterly.Hash.Policy
{
    /// <summary>
    /// Outcome of <see cref="PasswordPolicy.Evaluate(string, PasswordContext?)"/>. <see cref="ToString"/>,
    /// <see cref="IsAcceptable"/>, <see cref="Score"/>, <see cref="Violations"/> and <see cref="Suggestions"/> never
    /// contain any part of the password and are safe to log. <see cref="StrengthEstimate"/> is derived from the
    /// password (word positions and lengths, guess counts) and must not be logged or serialized; see
    /// <see cref="Policy.StrengthEstimate"/>.
    /// </summary>
    public sealed class PasswordPolicyResult
    {
        internal PasswordPolicyResult(
            int length,
            IReadOnlyList<PasswordViolation> violations,
            IReadOnlyList<string> suggestions,
            StrengthEstimate strengthEstimate,
            BreachCheckResult? breachCheck)
        {
            Length = length;
            Violations = violations;
            Suggestions = suggestions;
            StrengthEstimate = strengthEstimate;
            BreachCheck = breachCheck;
        }

        /// <summary>True if there are no <see cref="Violations"/>.</summary>
        public bool IsAcceptable => Violations.Count == 0;

        /// <summary>Strength score 0-4; see <see cref="Policy.StrengthEstimate.Score"/>.</summary>
        public int Score => StrengthEstimate.Score;

        /// <summary>Length in Unicode code points after NFKC normalization; the number the length rules use.</summary>
        public int Length { get; }

        /// <summary>Every rule the password breaks, in a stable order. Empty if acceptable.</summary>
        public IReadOnlyList<PasswordViolation> Violations { get; }

        /// <summary>Advice for choosing a better password; may be non-empty even for an acceptable password.</summary>
        public IReadOnlyList<string> Suggestions { get; }

        /// <summary>
        /// Details of the strength estimate: guesses, crack times, warning and patterns found. Show it to the user;
        /// do not log or serialize it, because it describes the password's structure.
        /// </summary>
        public StrengthEstimate StrengthEstimate { get; }

        /// <summary>
        /// The breach lookup, or null if none was made (synchronous evaluation, no checker configured, or the
        /// password was already rejected as too short or too long). <see cref="BreachCheckStatus.Unavailable"/> is
        /// reported here and is not a violation.
        /// </summary>
        public BreachCheckResult? BreachCheck { get; }

        /// <summary>True if a breach lookup was attempted but the corpus could not be consulted.</summary>
        public bool BreachCheckUnavailable => BreachCheck != null && BreachCheck.Status == BreachCheckStatus.Unavailable;

        /// <summary>True if a violation with this code is present.</summary>
        public bool HasViolation(PasswordViolationCode code)
        {
            foreach (PasswordViolation violation in Violations)
            {
                if (violation.Code == code)
                    return true;
            }
            return false;
        }

        /// <summary>A summary without any part of the password.</summary>
        public override string ToString() =>
            string.Format(CultureInfo.InvariantCulture, "{0} (score {1}, {2} violation(s))", IsAcceptable ? "Acceptable" : "Rejected", Score, Violations.Count);
    }
}
