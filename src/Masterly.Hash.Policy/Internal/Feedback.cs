using System;
using System.Collections.Generic;
using System.Globalization;

namespace Masterly.Hash.Policy.Internal
{
    /// <summary>Warning and suggestions for a weak password, following zxcvbn's feedback rules (own wording).</summary>
    internal static class Feedback
    {
        public const string UseFewWords = "Use a few unrelated words; avoid common phrases.";
        public const string NoNeedForSymbols = "No need for symbols, digits or upper-case letters.";
        public const string AddWord = "Add another word or two. Uncommon words are better.";

        public static (string Warning, List<string> Suggestions) Get(int score, IReadOnlyList<Match> sequence)
        {
            if (sequence.Count == 0)
                return (string.Empty, new List<string> { UseFewWords, NoNeedForSymbols });
            if (score > 2)
                return (string.Empty, new List<string>());

            Match longest = sequence[0];
            for (int k = 1; k < sequence.Count; k++)
            {
                if (sequence[k].Token.Length > longest.Token.Length)
                    longest = sequence[k];
            }

            (string Warning, List<string> Suggestions)? feedback = ForMatch(longest, sequence.Count == 1);
            if (feedback == null)
                return (string.Empty, new List<string> { AddWord });
            feedback.Value.Suggestions.Insert(0, AddWord);
            return feedback.Value;
        }

        private static (string, List<string>)? ForMatch(Match match, bool isSoleMatch)
        {
            switch (match.Pattern)
            {
                case PatternKind.Dictionary:
                    return ForDictionary(match, isSoleMatch);
                case PatternKind.Spatial:
                    return (match.Turns == 1 ? "Straight rows of keys are easy to guess." : "Short keyboard patterns are easy to guess.",
                        new List<string> { "Use a longer keyboard pattern with more turns, or better, a few words." });
                case PatternKind.Repeat:
                    return (match.BaseToken.Length == 1
                            ? "Repeated characters like \"aaa\" are easy to guess."
                            : "Repeats like \"abcabcabc\" are only slightly harder to guess than \"abc\".",
                        new List<string> { "Avoid repeated words and characters." });
                case PatternKind.Sequence:
                    return ("Sequences like \"abc\" or \"6543\" are easy to guess.", new List<string> { "Avoid sequences." });
                case PatternKind.Year:
                    return ("Recent years are easy to guess.",
                        new List<string> { "Avoid recent years.", "Avoid years that are associated with you." });
                case PatternKind.Date:
                    return ("Dates are often easy to guess.", new List<string> { "Avoid dates and years that are associated with you." });
                default:
                    return null;
            }
        }

        private static (string, List<string>) ForDictionary(Match match, bool isSoleMatch)
        {
            string warning = string.Empty;
            switch (match.Dictionary)
            {
                case DictionaryKind.CommonPasswords:
                    if (isSoleMatch && !match.L33t && !match.Reversed)
                    {
                        warning = match.Rank <= 10 ? "This is a top-10 common password."
                            : match.Rank <= 100 ? "This is a top-100 common password."
                            : "This is a very common password.";
                    }
                    else if (match.Guesses.HasValue && Math.Log10(match.Guesses.Value) <= 4)
                    {
                        warning = "This is similar to a commonly used password.";
                    }
                    break;
                case DictionaryKind.EnglishWords:
                    if (isSoleMatch)
                        warning = "A word by itself is easy to guess.";
                    break;
                case DictionaryKind.ContextWords:
                    warning = "Words related to you or this service are easy to guess.";
                    break;
            }

            var suggestions = new List<string>();
            string token = match.Token;
            int upper = 0, lower = 0;
            foreach (char c in token)
            {
                if (TextUtil.IsAsciiUpper(c)) upper++;
                else if (TextUtil.IsAsciiLower(c)) lower++;
            }
            if (upper == 1 && token.Length > 1 && TextUtil.IsAsciiUpper(token[0]))
                suggestions.Add("Capitalization doesn't help very much.");
            else if (upper > 0 && lower == 0)
                suggestions.Add("All-uppercase is almost as easy to guess as all-lowercase.");
            if (match.Reversed && token.Length >= 4)
                suggestions.Add("Reversed words aren't much harder to guess.");
            if (match.L33t)
                suggestions.Add("Predictable substitutions like '@' instead of 'a' don't help very much.");
            return (warning, suggestions);
        }
    }

    /// <summary>Human-readable durations, zxcvbn's <c>display_time</c> buckets.</summary>
    internal static class TimeDisplay
    {
        private const double Minute = 60;
        private const double Hour = Minute * 60;
        private const double Day = Hour * 24;
        private const double Month = Day * 31;
        private const double Year = Month * 12;
        private const double Century = Year * 100;

        public static string Format(double seconds)
        {
            if (double.IsNaN(seconds) || seconds < 1)
                return "less than a second";
            if (seconds < Minute)
                return Unit(seconds, 1, "second");
            if (seconds < Hour)
                return Unit(seconds, Minute, "minute");
            if (seconds < Day)
                return Unit(seconds, Hour, "hour");
            if (seconds < Month)
                return Unit(seconds, Day, "day");
            if (seconds < Year)
                return Unit(seconds, Month, "month");
            if (seconds < Century)
                return Unit(seconds, Year, "year");
            return "centuries";
        }

        private static string Unit(double seconds, double unit, string name)
        {
            double value = Math.Round(seconds / unit, MidpointRounding.AwayFromZero);
            string text = value.ToString("0", CultureInfo.InvariantCulture);
            return value == 1 ? text + " " + name : text + " " + name + "s";
        }
    }
}
