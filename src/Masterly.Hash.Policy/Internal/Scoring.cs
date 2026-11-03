using System;
using System.Collections.Generic;

namespace Masterly.Hash.Policy.Internal
{
    /// <summary>Result of <see cref="Scoring.MostGuessableMatchSequence"/>.</summary>
    internal sealed class GuessAnalysis
    {
        public GuessAnalysis(double guesses, List<Match> sequence)
        {
            Guesses = guesses;
            Sequence = sequence;
        }

        public double Guesses { get; }

        public List<Match> Sequence { get; }
    }

    /// <summary>
    /// Guess estimation for single matches and the minimum-guesses decomposition of a whole password.
    /// The formulas follow the published zxcvbn design (Wheeler, USENIX Security 2016); this is an
    /// independent C# implementation.
    /// </summary>
    internal static class Scoring
    {
        public const double BruteforceCardinality = 10;
        public const double MinGuessesBeforeGrowingSequence = 10000;
        public const double MinSubmatchGuessesSingleChar = 10;
        public const double MinSubmatchGuessesMultiChar = 50;
        public const int MinYearSpace = 20;

        /// <summary>
        /// Finds the sequence of non-overlapping matches covering the password (gaps filled with bruteforce) that
        /// minimises <c>l! * prod(guesses) + 10000^(l-1)</c>, where <c>l</c> is the number of matches.
        /// The factorial term models an attacker not knowing the order of the patterns; the additive term
        /// penalises long sequences of tiny matches.
        /// </summary>
        public static GuessAnalysis MostGuessableMatchSequence(string password, List<Match> matches, int referenceYear, bool excludeAdditive = false)
        {
            int n = password.Length;
            if (n == 0)
                return new GuessAnalysis(1, new List<Match>());

            var matchesByJ = new List<Match>[n];
            for (int k = 0; k < n; k++)
                matchesByJ[k] = new List<Match>();
            foreach (Match m in matches)
                matchesByJ[m.J].Add(m);
            foreach (List<Match> list in matchesByJ)
                StableSortByI(list);

            // optimalM[k][l]: best last match of a length-l sequence covering password[0..k].
            // optimalPi[k][l]: product of guesses of that sequence. optimalG[k][l]: its overall score.
            var optimalM = new SortedDictionary<int, Match>[n];
            var optimalPi = new SortedDictionary<int, double>[n];
            var optimalG = new SortedDictionary<int, double>[n];
            for (int k = 0; k < n; k++)
            {
                optimalM[k] = new SortedDictionary<int, Match>();
                optimalPi[k] = new SortedDictionary<int, double>();
                optimalG[k] = new SortedDictionary<int, double>();
            }

            void Update(Match m, int l)
            {
                int k = m.J;
                double pi = EstimateGuesses(m, password, referenceYear);
                if (l > 1)
                    pi *= optimalPi[m.I - 1][l - 1];
                double g = Factorial(l) * pi;
                if (!excludeAdditive)
                    g += Math.Pow(MinGuessesBeforeGrowingSequence, l - 1);
                g = Clamp(g);

                // Keep only if no sequence of length <= l ending at k does at least as well.
                foreach (KeyValuePair<int, double> competing in optimalG[k])
                {
                    if (competing.Key > l)
                        continue;
                    if (competing.Value <= g)
                        return;
                }
                optimalG[k][l] = g;
                optimalM[k][l] = m;
                optimalPi[k][l] = Clamp(pi);
            }

            void BruteforceUpdate(int k)
            {
                Update(MakeBruteforce(password, 0, k), 1);
                for (int i = 1; i <= k; i++)
                {
                    Match m = MakeBruteforce(password, i, k);
                    // Snapshot: Update(...) may add entries at index k, never at i - 1 < k.
                    foreach (KeyValuePair<int, Match> entry in optimalM[i - 1])
                    {
                        // Never put two bruteforce matches next to each other.
                        if (entry.Value.Pattern == PatternKind.Bruteforce)
                            continue;
                        Update(m, entry.Key + 1);
                    }
                }
            }

            for (int k = 0; k < n; k++)
            {
                foreach (Match m in matchesByJ[k])
                {
                    if (m.I > 0)
                    {
                        var lengths = new List<int>(optimalM[m.I - 1].Keys);
                        foreach (int l in lengths)
                            Update(m, l + 1);
                    }
                    else
                    {
                        Update(m, 1);
                    }
                }
                BruteforceUpdate(k);
            }

            // Unwind: pick the cheapest sequence ending at n - 1 (shortest wins ties).
            int bestL = 0;
            double bestG = double.PositiveInfinity;
            foreach (KeyValuePair<int, double> candidate in optimalG[n - 1])
            {
                if (candidate.Value < bestG)
                {
                    bestL = candidate.Key;
                    bestG = candidate.Value;
                }
            }

            var sequence = new List<Match>();
            int pos = n - 1;
            int length = bestL;
            while (pos >= 0)
            {
                Match m = optimalM[pos][length];
                sequence.Insert(0, m);
                pos = m.I - 1;
                length--;
            }
            return new GuessAnalysis(bestG, sequence);
        }

        private static void StableSortByI(List<Match> list)
        {
            if (list.Count < 2)
                return;
            var indexed = new List<(Match M, int Index)>(list.Count);
            for (int k = 0; k < list.Count; k++)
                indexed.Add((list[k], k));
            indexed.Sort((a, b) =>
            {
                int c = a.M.I.CompareTo(b.M.I);
                return c != 0 ? c : a.Index.CompareTo(b.Index);
            });
            for (int k = 0; k < list.Count; k++)
                list[k] = indexed[k].M;
        }

        private static Match MakeBruteforce(string password, int i, int j) =>
            new Match(PatternKind.Bruteforce, i, j, password.Substring(i, j - i + 1));

        /// <summary>Guesses for one match, cached on the match. Submatches get a floor so tiny patterns are not free.</summary>
        public static double EstimateGuesses(Match match, string password, int referenceYear)
        {
            if (match.Guesses.HasValue)
                return match.Guesses.Value;

            double minGuesses = 1;
            if (match.Token.Length < password.Length)
                minGuesses = match.Token.Length == 1 ? MinSubmatchGuessesSingleChar : MinSubmatchGuessesMultiChar;

            double guesses = match.Pattern switch
            {
                PatternKind.Bruteforce => BruteforceGuesses(match),
                PatternKind.Dictionary => DictionaryGuesses(match),
                PatternKind.Spatial => SpatialGuesses(match),
                PatternKind.Repeat => match.BaseGuesses * match.RepeatCount,
                PatternKind.Sequence => SequenceGuesses(match),
                PatternKind.Year => Math.Max(Math.Abs(match.Year - referenceYear), MinYearSpace),
                PatternKind.Date => DateGuesses(match, referenceYear),
                _ => BruteforceGuesses(match),
            };

            double result = Clamp(Math.Max(guesses, minGuesses));
            match.Guesses = result;
            return result;
        }

        private static double BruteforceGuesses(Match match)
        {
            double guesses = Clamp(Math.Pow(BruteforceCardinality, match.Token.Length));
            double minGuesses = match.Token.Length == 1 ? MinSubmatchGuessesSingleChar + 1 : MinSubmatchGuessesMultiChar + 1;
            return Math.Max(guesses, minGuesses);
        }

        private static double DictionaryGuesses(Match match)
        {
            double reversedVariations = match.Reversed ? 2 : 1;
            return (double)match.Rank * UppercaseVariations(match.Token) * L33tVariations(match) * reversedVariations;
        }

        /// <summary>How many capitalisation variants an attacker tries before this one.</summary>
        internal static double UppercaseVariations(string word)
        {
            int upper = 0, lower = 0;
            foreach (char c in word)
            {
                if (TextUtil.IsAsciiUpper(c)) upper++;
                else if (TextUtil.IsAsciiLower(c)) lower++;
            }
            if (upper == 0)
                return 1;

            // First letter only, last letter only, or every letter upper case: one extra bit.
            bool startUpper = upper == 1 && TextUtil.IsAsciiUpper(word[0]) && word.Length > 1;
            bool endUpper = upper == 1 && TextUtil.IsAsciiUpper(word[word.Length - 1]) && word.Length > 1;
            bool allUpper = lower == 0;
            if (startUpper || endUpper || allUpper)
                return 2;

            double variations = 0;
            for (int i = 1; i <= Math.Min(upper, lower); i++)
                variations += NCk(upper + lower, i);
            return Math.Max(variations, 1);
        }

        internal static double L33tVariations(Match match)
        {
            if (!match.L33t || match.Sub == null)
                return 1;
            double variations = 1;
            string lower = match.Token.ToLowerInvariant();
            foreach (KeyValuePair<char, char> entry in match.Sub)
            {
                int subbed = 0, unsubbed = 0;
                foreach (char c in lower)
                {
                    if (c == entry.Key) subbed++;
                    else if (c == entry.Value) unsubbed++;
                }
                if (subbed == 0 || unsubbed == 0)
                {
                    variations *= 2;
                }
                else
                {
                    double possibilities = 0;
                    for (int i = 1; i <= Math.Min(subbed, unsubbed); i++)
                        possibilities += NCk(subbed + unsubbed, i);
                    variations *= possibilities;
                }
            }
            return variations;
        }

        private static double SpatialGuesses(Match match)
        {
            AdjacencyGraph graph = match.Graph == AdjacencyGraph.Keypad.Name ? AdjacencyGraph.Keypad : AdjacencyGraph.Qwerty;
            double s = graph.StartingPositions;
            double d = graph.AverageDegree;
            double guesses = 0;
            int length = match.Token.Length;
            int turns = match.Turns;
            for (int i = 2; i <= length; i++)
            {
                int possibleTurns = Math.Min(turns, i - 1);
                for (int j = 1; j <= possibleTurns; j++)
                    guesses += NCk(i - 1, j - 1) * s * Math.Pow(d, j);
            }

            if (match.ShiftedCount > 0)
            {
                int shifted = match.ShiftedCount;
                int unshifted = length - shifted;
                if (unshifted <= 0)
                {
                    guesses *= 2;
                }
                else
                {
                    double variations = 0;
                    for (int i = 1; i <= Math.Min(shifted, unshifted); i++)
                        variations += NCk(shifted + unshifted, i);
                    guesses *= variations;
                }
            }
            return guesses;
        }

        private static double SequenceGuesses(Match match)
        {
            char first = match.Token[0];
            double baseGuesses;
            if (first == 'a' || first == 'A' || first == 'z' || first == 'Z' || first == '0' || first == '1' || first == '9')
                baseGuesses = 4; // obvious starting points
            else if (TextUtil.IsAsciiDigit(first))
                baseGuesses = 10;
            else
                baseGuesses = 26; // letters, and a rough figure for other alphabets
            if (!match.Ascending)
                baseGuesses *= 2;
            return baseGuesses * match.Token.Length;
        }

        private static double DateGuesses(Match match, int referenceYear)
        {
            double yearSpace = Math.Max(Math.Abs(match.Year - referenceYear), MinYearSpace);
            double guesses = yearSpace * 365;
            if (match.Separator.Length > 0)
                guesses *= 4;
            return guesses;
        }

        /// <summary>Binomial coefficient as a double (exact for the small values used here).</summary>
        internal static double NCk(int n, int k)
        {
            if (k > n || k < 0)
                return 0;
            if (k == 0)
                return 1;
            double r = 1;
            for (int d = 1; d <= k; d++)
            {
                r *= n;
                r /= d;
                n--;
            }
            return Math.Round(r);
        }

        internal static double Factorial(int n)
        {
            double f = 1;
            for (int i = 2; i <= n; i++)
            {
                f *= i;
                if (double.IsInfinity(f))
                    return double.MaxValue;
            }
            return f;
        }

        private static double Clamp(double value) =>
            double.IsInfinity(value) || double.IsNaN(value) || value > double.MaxValue ? double.MaxValue : value;

        /// <summary>zxcvbn's score thresholds, each with a small margin.</summary>
        public static int GuessesToScore(double guesses)
        {
            const double delta = 5;
            if (guesses < 1e3 + delta) return 0; // risky: guessable within ~1000 attempts
            if (guesses < 1e6 + delta) return 1; // protects against throttled online attacks
            if (guesses < 1e8 + delta) return 2; // protects against unthrottled online attacks
            if (guesses < 1e10 + delta) return 3; // moderate protection against offline slow-hash attacks
            return 4; // strong protection against offline slow-hash attacks
        }
    }
}
