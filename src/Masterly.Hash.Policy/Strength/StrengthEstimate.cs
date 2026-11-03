using System;
using System.Collections.Generic;
using System.Globalization;

namespace Masterly.Hash.Policy
{
    /// <summary>
    /// Output of <see cref="PasswordStrengthEstimator"/>: an estimate of how many guesses an attacker who knows common
    /// password patterns needs, a 0-4 score, crack-time estimates and feedback.
    /// </summary>
    /// <remarks>
    /// <para>
    /// No password text is stored, but the estimate is derived from the password and is not free of information
    /// about it. <see cref="Sequence"/> gives the position and length of every word and pattern, and the guess
    /// count of a weak password reflects the rank of the list entry it matched. Treat the whole estimate as
    /// sensitive: show it to the user who typed the password; do not log it, serialize it to telemetry or store it.
    /// <see cref="ToString"/>, <see cref="Score"/>, <see cref="Warning"/> and <see cref="Suggestions"/> are safe to log.
    /// </para>
    /// <para>
    /// To limit what leaks, <see cref="Guesses"/>, <see cref="GuessesLog10"/> and <see cref="CrackTimes"/> are
    /// rounded down to a tenth of a decade, and patterns carry no guess counts of their own; the exact figures,
    /// which together with the positions would identify list entries, are never exposed.
    /// </para>
    /// </remarks>
    public sealed class StrengthEstimate
    {
        internal StrengthEstimate(
            double exactGuesses,
            int score,
            string warning,
            IReadOnlyList<string> suggestions,
            IReadOnlyList<PatternMatch> sequence,
            bool isTruncated)
        {
            GuessesLog10 = Coarsen(exactGuesses);
            Guesses = Math.Pow(10, GuessesLog10);
            Score = score;
            CrackTimes = new CrackTimeEstimates(Guesses);
            Warning = warning;
            Suggestions = suggestions;
            Sequence = sequence;
            IsTruncated = isTruncated;
        }

        /// <summary>
        /// Estimated number of guesses needed to find the password, rounded down to a power of 10^0.1 (steps of
        /// about 26%) so that it cannot be used to look up the list entries the password contains.
        /// </summary>
        public double Guesses { get; }

        /// <summary><c>log10(</c><see cref="Guesses"/><c>)</c>: the order of magnitude, rounded down to one decimal place.</summary>
        public double GuessesLog10 { get; }

        /// <summary>
        /// 0 = too guessable (&lt; 10^3 guesses), 1 = very guessable (&lt; 10^6), 2 = somewhat guessable (&lt; 10^8),
        /// 3 = safely unguessable (&lt; 10^10), 4 = very unguessable (≥ 10^10). The same thresholds as zxcvbn.
        /// </summary>
        public int Score { get; }

        /// <summary>Time to find the password under four attack scenarios.</summary>
        public CrackTimeEstimates CrackTimes { get; }

        /// <summary>Why the password is weak, or empty. Only set when <see cref="Score"/> is 2 or lower.</summary>
        public string Warning { get; }

        /// <summary>Advice for a stronger password. Empty when <see cref="Score"/> is 3 or higher.</summary>
        public IReadOnlyList<string> Suggestions { get; }

        /// <summary>The patterns the estimate is based on, left to right, covering the analyzed password.</summary>
        public IReadOnlyList<PatternMatch> Sequence { get; }

        /// <summary>
        /// True if the password was longer than <see cref="PasswordStrengthEstimator.MaxAnalyzedLength"/> and only its
        /// beginning was analyzed. The estimate is then that of the first 100 UTF-16 units alone: approximate, not a
        /// bound either way.
        /// </summary>
        public bool IsTruncated { get; }

        /// <summary>A summary without any part of the password, e.g. <c>Score 3 (10^9.2 guesses)</c>.</summary>
        public override string ToString() =>
            string.Format(CultureInfo.InvariantCulture, "Score {0} (10^{1:0.0} guesses)", Score, GuessesLog10);

        /// <summary>log10 of the guesses, rounded down to one decimal place.</summary>
        private static double Coarsen(double guesses)
        {
            double log10 = Math.Log10(Math.Max(guesses, 1));
            // The small bias keeps exact powers of ten in their own bucket despite rounding error.
            return Math.Floor((log10 * 10) + 1e-9) / 10;
        }
    }

    /// <summary>
    /// One pattern in a <see cref="StrengthEstimate.Sequence"/>. Positions are in UTF-16 units of the NFKC-normalized
    /// password. They describe the password's structure, so do not log them (see <see cref="StrengthEstimate"/>).
    /// </summary>
    public sealed class PatternMatch
    {
        internal PatternMatch(PatternKind pattern, int startIndex, int length, DictionaryKind dictionary, bool isReversed, bool isL33t)
        {
            Pattern = pattern;
            StartIndex = startIndex;
            Length = length;
            Dictionary = dictionary;
            IsReversed = isReversed;
            IsL33t = isL33t;
        }

        /// <summary>Kind of pattern.</summary>
        public PatternKind Pattern { get; }

        /// <summary>Start of the pattern in the normalized password (UTF-16 index).</summary>
        public int StartIndex { get; }

        /// <summary>Length of the pattern in UTF-16 units.</summary>
        public int Length { get; }

        /// <summary>For <see cref="PatternKind.Dictionary"/>, the dictionary the word came from; otherwise <see cref="DictionaryKind.None"/>.</summary>
        public DictionaryKind Dictionary { get; }

        /// <summary>True for a dictionary word written backwards.</summary>
        public bool IsReversed { get; }

        /// <summary>True for a dictionary word with l33t substitutions such as <c>@</c> for <c>a</c>.</summary>
        public bool IsL33t { get; }

        /// <inheritdoc />
        public override string ToString() =>
            string.Format(CultureInfo.InvariantCulture, "{0} [{1}..{2})", Pattern, StartIndex, StartIndex + Length);
    }

    /// <summary>Crack-time estimates for the four attack scenarios zxcvbn reports.</summary>
    public sealed class CrackTimeEstimates
    {
        /// <summary>Guesses per second of a rate-limited online attack: 100 per hour.</summary>
        public const double OnlineThrottledRate = 100.0 / 3600.0;

        /// <summary>Guesses per second of an online attack without rate limiting: 10 per second.</summary>
        public const double OnlineUnthrottledRate = 10;

        /// <summary>Guesses per second of an offline attack on a slow hash (Argon2id, PBKDF2) with many cores: 10^4 per second.</summary>
        public const double OfflineSlowHashRate = 1e4;

        /// <summary>Guesses per second of an offline attack on a fast unsalted hash with GPUs: 10^10 per second.</summary>
        public const double OfflineFastHashRate = 1e10;

        internal CrackTimeEstimates(double guesses)
        {
            OnlineThrottled = new CrackTimeEstimate(guesses, OnlineThrottledRate);
            OnlineUnthrottled = new CrackTimeEstimate(guesses, OnlineUnthrottledRate);
            OfflineSlowHash = new CrackTimeEstimate(guesses, OfflineSlowHashRate);
            OfflineFastHash = new CrackTimeEstimate(guesses, OfflineFastHashRate);
        }

        /// <summary>Online attack against a service that limits attempts (100 per hour).</summary>
        public CrackTimeEstimate OnlineThrottled { get; }

        /// <summary>Online attack against a service that does not limit attempts (10 per second).</summary>
        public CrackTimeEstimate OnlineUnthrottled { get; }

        /// <summary>Offline attack on a stolen slow hash such as Masterly.Hash's Argon2id (10^4 per second).</summary>
        public CrackTimeEstimate OfflineSlowHash { get; }

        /// <summary>Offline attack on a stolen fast hash such as unsalted SHA-1 (10^10 per second).</summary>
        public CrackTimeEstimate OfflineFastHash { get; }
    }

    /// <summary>Time to find a password at a given guessing rate.</summary>
    public sealed class CrackTimeEstimate
    {
        internal CrackTimeEstimate(double guesses, double guessesPerSecond)
        {
            GuessesPerSecond = guessesPerSecond;
            Seconds = guesses / guessesPerSecond;
            Display = Internal.TimeDisplay.Format(Seconds);
        }

        /// <summary>Assumed attacker guessing rate.</summary>
        public double GuessesPerSecond { get; }

        /// <summary>Estimated seconds to find the password.</summary>
        public double Seconds { get; }

        /// <summary>Human-readable time, e.g. <c>"3 hours"</c>, <c>"less than a second"</c> or <c>"centuries"</c>.</summary>
        public string Display { get; }

        /// <inheritdoc />
        public override string ToString() => Display;
    }
}
