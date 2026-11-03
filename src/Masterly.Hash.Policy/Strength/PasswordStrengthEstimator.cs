using System;
using System.Collections.Generic;
using Masterly.Hash.Policy.Internal;

namespace Masterly.Hash.Policy
{
    /// <summary>
    /// A password strength estimator inspired by zxcvbn (Dropbox; Wheeler, USENIX Security 2016). It is an
    /// independent C# implementation of the same approach, not a port: it finds dictionary words (the 10,000 most
    /// common passwords, common English words and caller-supplied words, also reversed or with l33t substitutions),
    /// keyboard patterns (QWERTY and numeric keypad), sequences, repeats, years and dates, then picks the
    /// decomposition an attacker would need the fewest guesses for. Its numbers differ from zxcvbn's because the
    /// word lists differ.
    /// </summary>
    /// <remarks>Thread-safe. The embedded lists are loaded once, on first use.</remarks>
    public static class PasswordStrengthEstimator
    {
        /// <summary>
        /// Only the first 100 UTF-16 units of the normalized password are analyzed, which bounds the cost of a call.
        /// For longer passwords (<see cref="StrengthEstimate.IsTruncated"/>) the estimate is that of the first 100
        /// units alone: the rest adds nothing, so treat it as approximate, not as a bound either way.
        /// </summary>
        public const int MaxAnalyzedLength = 100;

        /// <summary>Estimates the strength of a password.</summary>
        public static StrengthEstimate Estimate(string password) => Estimate(password, null, DateTime.UtcNow.Year);

        /// <summary>
        /// Estimates the strength of a password. <paramref name="userInputs"/> are words an attacker targeting this
        /// user would try first (user name, email, name, site name); they rank above every dictionary word.
        /// </summary>
        public static StrengthEstimate Estimate(string password, IEnumerable<string>? userInputs) =>
            Estimate(password, userInputs, DateTime.UtcNow.Year);

        /// <summary>Estimates the strength of a password.</summary>
        public static StrengthEstimate Estimate(SensitiveString password, IEnumerable<string>? userInputs = null)
        {
            if (password == null) throw new ArgumentNullException(nameof(password));
            return Estimate(password.Reveal(), userInputs, DateTime.UtcNow.Year);
        }

        /// <summary>
        /// Estimates the strength of a password, scoring years and dates relative to <paramref name="referenceYear"/>
        /// instead of the current year (useful for reproducible results).
        /// </summary>
        public static StrengthEstimate Estimate(string password, IEnumerable<string>? userInputs, int referenceYear)
        {
            if (password == null) throw new ArgumentNullException(nameof(password));
            if (referenceYear < 1000 || referenceYear > 9999)
                throw new ArgumentOutOfRangeException(nameof(referenceYear), referenceYear, "Reference year must have four digits.");

            string normalized = TextUtil.Normalize(password);
            string analyzed = TextUtil.Truncate(normalized, MaxAnalyzedLength);

            var dictionaries = new List<RankedDictionary>(3)
            {
                EmbeddedDictionaries.CommonPasswords,
                EmbeddedDictionaries.EnglishWords,
            };
            RankedDictionary? context = BuildUserDictionary(userInputs);
            if (context != null)
                dictionaries.Add(context);

            var matching = new Matching(dictionaries, referenceYear);
            List<Match> matches = matching.Omnimatch(analyzed);
            GuessAnalysis analysis = Scoring.MostGuessableMatchSequence(analyzed, matches, referenceYear);
            int score = Scoring.GuessesToScore(analysis.Guesses);
            (string warning, List<string> suggestions) = Feedback.Get(score, analysis.Sequence);

            var sequence = new List<PatternMatch>(analysis.Sequence.Count);
            foreach (Match m in analysis.Sequence)
            {
                sequence.Add(new PatternMatch(
                    m.Pattern, m.I, m.J - m.I + 1,
                    m.Pattern == PatternKind.Dictionary ? m.Dictionary : DictionaryKind.None,
                    m.Reversed, m.L33t));
            }

            return new StrengthEstimate(
                analysis.Guesses,
                score,
                warning,
                suggestions.AsReadOnly(),
                sequence.AsReadOnly(),
                analyzed.Length < normalized.Length);
        }

        internal static RankedDictionary? BuildUserDictionary(IEnumerable<string>? userInputs)
        {
            if (userInputs == null)
                return null;
            var words = new List<string>();
            foreach (string? word in userInputs)
            {
                if (string.IsNullOrWhiteSpace(word))
                    continue;
                string trimmed = TextUtil.Truncate(word!.Trim(), MaxAnalyzedLength);
                words.Add(trimmed);
                // A l33t user name ("j0hnd03") also gives away its plain form ("johndoe").
                words.AddRange(L33t.PlainReadings(TextUtil.Normalize(trimmed).ToLowerInvariant()));
            }
            if (words.Count == 0)
                return null;
            return new RankedDictionary(DictionaryKind.ContextWords, words);
        }
    }
}
