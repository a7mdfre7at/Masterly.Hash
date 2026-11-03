using System;
using System.Globalization;
using System.Threading;
using System.Threading.Tasks;

namespace Masterly.Hash.Policy
{
    /// <summary>
    /// Looks a password up in a corpus of passwords from previous breaches (NIST SP 800-63B rev. 4, section 3.1.1.2).
    /// Implementations that call a remote service must not send the password itself; use a k-anonymity scheme
    /// such as the Pwned Passwords range API (send only the first 5 hex characters of the SHA-1 hash).
    /// </summary>
    public interface IBreachedPasswordChecker
    {
        /// <summary>
        /// Checks a password. Return <see cref="BreachCheckResult.Unavailable"/> when the corpus cannot be reached
        /// rather than throwing; <see cref="PasswordPolicy"/> treats exceptions other than cancellation the same way.
        /// </summary>
        /// <param name="password">The NFKC-normalized candidate password.</param>
        /// <param name="cancellationToken">Cancels the lookup.</param>
        ValueTask<BreachCheckResult> CheckAsync(string password, CancellationToken cancellationToken);
    }

    /// <summary>Whether a breach lookup produced an answer.</summary>
    public enum BreachCheckStatus
    {
        /// <summary>The lookup completed; <see cref="BreachCheckResult.IsBreached"/> is meaningful.</summary>
        Ok,

        /// <summary>The corpus could not be consulted (timeout, network error, service down). Nothing is known.</summary>
        Unavailable,
    }

    /// <summary>Outcome of <see cref="IBreachedPasswordChecker.CheckAsync"/>.</summary>
    public sealed class BreachCheckResult
    {
        /// <summary>The password was not found.</summary>
        public static readonly BreachCheckResult NotBreached = new BreachCheckResult(BreachCheckStatus.Ok, false, 0);

        /// <summary>The corpus could not be consulted.</summary>
        public static readonly BreachCheckResult Unavailable = new BreachCheckResult(BreachCheckStatus.Unavailable, false, 0);

        private BreachCheckResult(BreachCheckStatus status, bool isBreached, long occurrences)
        {
            Status = status;
            IsBreached = isBreached;
            Occurrences = occurrences;
        }

        /// <summary>The password was found <paramref name="occurrences"/> times (at least 1).</summary>
        public static BreachCheckResult Breached(long occurrences)
        {
            if (occurrences < 1)
                throw new ArgumentOutOfRangeException(nameof(occurrences), occurrences, "A breached password occurs at least once.");
            return new BreachCheckResult(BreachCheckStatus.Ok, true, occurrences);
        }

        /// <summary>Whether the lookup produced an answer.</summary>
        public BreachCheckStatus Status { get; }

        /// <summary>True if the password appears in the corpus. Always false when <see cref="Status"/> is <see cref="BreachCheckStatus.Unavailable"/>.</summary>
        public bool IsBreached { get; }

        /// <summary>How many times the password appears in the corpus; 0 if not breached or unknown.</summary>
        public long Occurrences { get; }

        /// <inheritdoc />
        public override string ToString() =>
            Status == BreachCheckStatus.Unavailable ? "Unavailable"
            : IsBreached ? string.Format(CultureInfo.InvariantCulture, "Breached ({0} occurrences)", Occurrences)
            : "Not breached";
    }
}
