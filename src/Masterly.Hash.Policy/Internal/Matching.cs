using System;
using System.Collections.Generic;

namespace Masterly.Hash.Policy.Internal
{
    /// <summary>
    /// Finds every candidate pattern in a password. Follows the matcher design of zxcvbn
    /// (Wheeler, "zxcvbn: Low-Budget Password Strength Estimation", USENIX Security 2016).
    /// </summary>
    internal sealed class Matching
    {
        private const int DateMinYear = 1000;
        private const int DateMaxYear = 2050;
        private const int SequenceMaxDelta = 5;

        private const string ShiftedCharacters = "~!@#$%^&*()_+QWERTYUIOP{}|ASDFGHJKL:\"ZXCVBNM<>?";

        // For length-n digit strings, the ways to split into day/month/year parts.
        private static readonly Dictionary<int, (int K, int L)[]> s_dateSplits = new Dictionary<int, (int K, int L)[]>
        {
            [4] = new[] { (1, 2), (2, 3) },
            [5] = new[] { (1, 3), (2, 3) },
            [6] = new[] { (1, 2), (2, 4), (4, 5) },
            [7] = new[] { (1, 3), (2, 3), (4, 5), (4, 6) },
            [8] = new[] { (2, 4), (4, 6) },
        };

        private readonly IReadOnlyList<RankedDictionary> _dictionaries;

        public Matching(IReadOnlyList<RankedDictionary> dictionaries, int referenceYear)
        {
            _dictionaries = dictionaries;
            ReferenceYear = referenceYear;
        }

        public int ReferenceYear { get; }

        /// <summary>All matches, sorted by (I, J).</summary>
        public List<Match> Omnimatch(string password)
        {
            var matches = new List<Match>();
            matches.AddRange(DictionaryMatch(password));
            matches.AddRange(ReverseDictionaryMatch(password));
            matches.AddRange(L33tMatch(password));
            matches.AddRange(SpatialMatch(password));
            matches.AddRange(RepeatMatch(password));
            matches.AddRange(SequenceMatch(password));
            matches.AddRange(YearMatch(password));
            matches.AddRange(DateMatch(password));
            Sort(matches);
            return matches;
        }

        internal static void Sort(List<Match> matches)
        {
            // Stable sort by (I, J) so results are deterministic.
            var indexed = new List<(Match M, int Index)>(matches.Count);
            for (int k = 0; k < matches.Count; k++)
                indexed.Add((matches[k], k));
            indexed.Sort((a, b) =>
            {
                int c = a.M.I.CompareTo(b.M.I);
                if (c != 0) return c;
                c = a.M.J.CompareTo(b.M.J);
                return c != 0 ? c : a.Index.CompareTo(b.Index);
            });
            for (int k = 0; k < matches.Count; k++)
                matches[k] = indexed[k].M;
        }

        // ---------------------------------------------------------------- dictionary

        public List<Match> DictionaryMatch(string password)
        {
            var matches = new List<Match>();
            string lower = password.ToLowerInvariant();
            int n = password.Length;
            foreach (RankedDictionary dictionary in _dictionaries)
            {
                int maxLength = dictionary.MaxWordLength;
                for (int i = 0; i < n; i++)
                {
                    for (int j = i; j < n && j - i < maxLength; j++)
                    {
                        string word = lower.Substring(i, j - i + 1);
                        if (dictionary.TryGetRank(word, out int rank))
                        {
                            matches.Add(new Match(PatternKind.Dictionary, i, j, password.Substring(i, j - i + 1))
                            {
                                MatchedWord = word,
                                Rank = rank,
                                Dictionary = dictionary.Kind,
                            });
                        }
                    }
                }
            }
            Sort(matches);
            return matches;
        }

        public List<Match> ReverseDictionaryMatch(string password)
        {
            // Reverse by UTF-16 unit, as zxcvbn does, so indices map back one-to-one.
            char[] chars = password.ToCharArray();
            Array.Reverse(chars);
            string reversed = new string(chars);
            int n = password.Length;
            List<Match> matches = DictionaryMatch(reversed);
            foreach (Match match in matches)
            {
                char[] token = match.Token.ToCharArray();
                Array.Reverse(token);
                match.Token = new string(token);
                match.Reversed = true;
                int i = n - 1 - match.J;
                int j = n - 1 - match.I;
                match.I = i;
                match.J = j;
            }
            Sort(matches);
            return matches;
        }

        public List<Match> L33tMatch(string password)
        {
            var matches = new List<Match>();
            foreach (Dictionary<char, char> sub in L33t.EnumerateSubstitutions(password))
            {
                string subbed = L33t.Translate(password, sub);
                foreach (Match match in DictionaryMatch(subbed))
                {
                    string token = password.Substring(match.I, match.J - match.I + 1);
                    // Only keep matches that actually use a substitution.
                    if (string.Equals(token.ToLowerInvariant(), match.MatchedWord, StringComparison.Ordinal))
                        continue;
                    // Single-character l33t matches are noise.
                    if (token.Length <= 1)
                        continue;
                    var used = new Dictionary<char, char>();
                    foreach (KeyValuePair<char, char> entry in sub)
                    {
                        if (token.IndexOf(entry.Key) >= 0)
                            used[entry.Key] = entry.Value;
                    }
                    match.Token = token;
                    match.L33t = true;
                    match.Sub = used;
                    if (!ContainsEquivalent(matches, match))
                        matches.Add(match);
                }
            }
            Sort(matches);
            return matches;
        }

        private static bool ContainsEquivalent(List<Match> matches, Match candidate)
        {
            // Different substitution tables can yield the same match; keep one.
            foreach (Match m in matches)
            {
                if (m.I == candidate.I && m.J == candidate.J && m.Dictionary == candidate.Dictionary &&
                    string.Equals(m.MatchedWord, candidate.MatchedWord, StringComparison.Ordinal))
                    return true;
            }
            return false;
        }

        // ---------------------------------------------------------------- spatial

        public List<Match> SpatialMatch(string password)
        {
            var matches = new List<Match>();
            matches.AddRange(SpatialMatchHelper(password, AdjacencyGraph.Qwerty));
            matches.AddRange(SpatialMatchHelper(password, AdjacencyGraph.Keypad));
            Sort(matches);
            return matches;
        }

        private static List<Match> SpatialMatchHelper(string password, AdjacencyGraph graph)
        {
            var matches = new List<Match>();
            bool isKeyboard = graph == AdjacencyGraph.Qwerty;
            int i = 0;
            while (i < password.Length - 1)
            {
                int j = i + 1;
                int lastDirection = -1;
                int turns = 0;
                int shiftedCount = isKeyboard && ShiftedCharacters.IndexOf(password[i]) >= 0 ? 1 : 0;
                while (true)
                {
                    char previous = password[j - 1];
                    bool found = false;
                    if (j < password.Length && graph.TryGetAdjacent(previous, out string?[] adjacent))
                    {
                        char current = password[j];
                        for (int direction = 0; direction < adjacent.Length; direction++)
                        {
                            string? key = adjacent[direction];
                            if (key == null)
                                continue;
                            int index = key.IndexOf(current);
                            if (index < 0)
                                continue;
                            found = true;
                            // Index 1 in the key is its shifted character.
                            if (index == 1)
                                shiftedCount++;
                            if (lastDirection != direction)
                            {
                                turns++;
                                lastDirection = direction;
                            }
                            break;
                        }
                    }

                    if (found)
                    {
                        j++;
                    }
                    else
                    {
                        // Ignore chains of one or two characters.
                        if (j - i > 2)
                        {
                            matches.Add(new Match(PatternKind.Spatial, i, j - 1, password.Substring(i, j - i))
                            {
                                Graph = graph.Name,
                                Turns = turns,
                                ShiftedCount = shiftedCount,
                            });
                        }
                        i = j;
                        break;
                    }
                }
            }
            return matches;
        }

        // ---------------------------------------------------------------- repeat

        /// <summary>
        /// Equivalent of zxcvbn's greedy <c>/(.+)\1+/</c> versus lazy <c>/(.+?)\1+/</c> regex scan, implemented
        /// without regular expressions (no backtracking blow-up, no regex timeouts).
        /// </summary>
        public List<Match> RepeatMatch(string password)
        {
            var matches = new List<Match>();
            int n = password.Length;
            int lastIndex = 0;
            while (lastIndex < n)
            {
                if (!FindRepeat(password, lastIndex, out int start, out int greedyLength, out int lazyLength, out int lazyUnit))
                    break;

                int length;
                string baseToken;
                if (greedyLength > lazyLength)
                {
                    length = greedyLength;
                    baseToken = password.Substring(start, SmallestPeriod(password, start, greedyLength));
                }
                else
                {
                    length = lazyLength;
                    baseToken = password.Substring(start, lazyUnit);
                }

                // Unlike zxcvbn, run on through a trailing partial period ("aab" x 5 is one repeat, not a repeat of
                // "aabaab" plus "aab"), so an odd number of periods or a cut-off copy adds no spurious guesses.
                int unit = baseToken.Length;
                while (start + length < n && password[start + length] == password[start + length - unit])
                    length++;

                string token = password.Substring(start, length);
                var baseMatches = Omnimatch(baseToken);
                double baseGuesses = Scoring.MostGuessableMatchSequence(baseToken, baseMatches, ReferenceYear).Guesses;
                matches.Add(new Match(PatternKind.Repeat, start, start + length - 1, token)
                {
                    BaseToken = baseToken,
                    BaseGuesses = baseGuesses,
                    RepeatCount = length / unit,
                });
                lastIndex = start + length;
            }
            return matches;
        }

        /// <summary>
        /// Leftmost position at or after <paramref name="from"/> that starts a repetition; the total length when the
        /// unit is as long as possible (greedy) and as short as possible (lazy).
        /// </summary>
        private static bool FindRepeat(string s, int from, out int start, out int greedyLength, out int lazyLength, out int lazyUnit)
        {
            int n = s.Length;
            for (int p = from; p < n - 1; p++)
            {
                int smallest = -1;
                int largest = -1;
                for (int unit = 1; p + 2 * unit <= n; unit++)
                {
                    if (string.CompareOrdinal(s, p, s, p + unit, unit) == 0)
                    {
                        if (smallest < 0)
                            smallest = unit;
                        largest = unit;
                    }
                }
                if (smallest < 0)
                    continue;
                start = p;
                lazyUnit = smallest;
                lazyLength = smallest * CountRepeats(s, p, smallest);
                greedyLength = largest * CountRepeats(s, p, largest);
                return true;
            }
            start = greedyLength = lazyLength = lazyUnit = 0;
            return false;
        }

        private static int CountRepeats(string s, int start, int unit)
        {
            int count = 1;
            while (start + (count + 1) * unit <= s.Length && string.CompareOrdinal(s, start, s, start + count * unit, unit) == 0)
                count++;
            return count;
        }

        /// <summary>Shortest unit u such that the span is u repeated at least twice (zxcvbn's <c>/^(.+?)\1+$/</c>).</summary>
        private static int SmallestPeriod(string s, int start, int length)
        {
            for (int unit = 1; unit <= length / 2; unit++)
            {
                if (length % unit != 0)
                    continue;
                bool ok = true;
                for (int k = unit; k < length && ok; k += unit)
                    ok = string.CompareOrdinal(s, start, s, start + k, unit) == 0;
                if (ok)
                    return unit;
            }
            return length;
        }

        // ---------------------------------------------------------------- sequence

        public static List<Match> SequenceMatch(string password)
        {
            var result = new List<Match>();
            if (password.Length <= 1)
                return result;

            int i = 0;
            int? lastDelta = null;
            for (int k = 1; k < password.Length; k++)
            {
                int delta = password[k] - password[k - 1];
                if (lastDelta == null)
                    lastDelta = delta;
                if (delta == lastDelta)
                    continue;
                int j = k - 1;
                AddSequence(password, i, j, lastDelta.Value, result);
                i = j;
                lastDelta = delta;
            }
            AddSequence(password, i, password.Length - 1, lastDelta!.Value, result);
            return result;
        }

        private static void AddSequence(string password, int i, int j, int delta, List<Match> result)
        {
            if (j - i > 1 || Math.Abs(delta) == 1)
            {
                int absDelta = Math.Abs(delta);
                if (absDelta > 0 && absDelta <= SequenceMaxDelta)
                {
                    result.Add(new Match(PatternKind.Sequence, i, j, password.Substring(i, j - i + 1))
                    {
                        Ascending = delta > 0,
                    });
                }
            }
        }

        // ---------------------------------------------------------------- year

        /// <summary>Non-overlapping years 1900-2099 (zxcvbn's <c>recent_year</c> regex, widened to the 2000s).</summary>
        public static List<Match> YearMatch(string password)
        {
            var result = new List<Match>();
            int i = 0;
            while (i + 4 <= password.Length)
            {
                char a = password[i], b = password[i + 1], c = password[i + 2], d = password[i + 3];
                bool isYear = TextUtil.IsAsciiDigit(c) && TextUtil.IsAsciiDigit(d) &&
                    ((a == '1' && b == '9') || (a == '2' && b == '0'));
                if (isYear)
                {
                    string token = password.Substring(i, 4);
                    result.Add(new Match(PatternKind.Year, i, i + 3, token) { Year = int.Parse(token, System.Globalization.CultureInfo.InvariantCulture) });
                    i += 4;
                }
                else
                {
                    i++;
                }
            }
            return result;
        }

        // ---------------------------------------------------------------- date

        public List<Match> DateMatch(string password)
        {
            var matches = new List<Match>();
            int n = password.Length;

            // Without separators: 4 ('1191') to 8 ('11111991') digits.
            for (int i = 0; i + 4 <= n; i++)
            {
                for (int j = i + 3; j <= i + 7 && j < n; j++)
                {
                    if (!AllDigits(password, i, j))
                        break;
                    string token = password.Substring(i, j - i + 1);
                    (int Year, int Month, int Day)? best = null;
                    int bestDistance = int.MaxValue;
                    foreach ((int k, int l) in s_dateSplits[token.Length])
                    {
                        var dmy = MapIntsToDmy(
                            ParseDigits(token, 0, k),
                            ParseDigits(token, k, l - k),
                            ParseDigits(token, l, token.Length - l));
                        if (dmy == null)
                            continue;
                        // Prefer the reading with the year closest to the reference year.
                        int distance = Math.Abs(dmy.Value.Year - ReferenceYear);
                        if (best == null || distance < bestDistance)
                        {
                            best = dmy;
                            bestDistance = distance;
                        }
                    }
                    if (best == null)
                        continue;
                    matches.Add(new Match(PatternKind.Date, i, j, token)
                    {
                        Year = best.Value.Year,
                        Month = best.Value.Month,
                        Day = best.Value.Day,
                    });
                }
            }

            // With separators: 6 ('1/1/91') to 10 ('11/11/1991') characters.
            for (int i = 0; i + 6 <= n; i++)
            {
                for (int j = i + 5; j <= i + 9 && j < n; j++)
                {
                    string token = password.Substring(i, j - i + 1);
                    if (!TryParseSeparatedDate(token, out int first, out string separator, out int second, out int third))
                        continue;
                    var dmy = MapIntsToDmy(first, second, third);
                    if (dmy == null)
                        continue;
                    matches.Add(new Match(PatternKind.Date, i, j, token)
                    {
                        Separator = separator,
                        Year = dmy.Value.Year,
                        Month = dmy.Value.Month,
                        Day = dmy.Value.Day,
                    });
                }
            }

            // Drop date matches that are strict sub-spans of other date matches.
            var filtered = new List<Match>();
            foreach (Match match in matches)
            {
                bool isSubmatch = false;
                foreach (Match other in matches)
                {
                    if (ReferenceEquals(match, other))
                        continue;
                    if (other.I <= match.I && other.J >= match.J)
                    {
                        isSubmatch = true;
                        break;
                    }
                }
                if (!isSubmatch)
                    filtered.Add(match);
            }
            Sort(filtered);
            return filtered;
        }

        private static bool AllDigits(string s, int i, int j)
        {
            for (int k = i; k <= j; k++)
            {
                if (!TextUtil.IsAsciiDigit(s[k]))
                    return false;
            }
            return true;
        }

        private static int ParseDigits(string s, int start, int length)
        {
            int value = 0;
            for (int k = start; k < start + length; k++)
                value = value * 10 + (s[k] - '0');
            return value;
        }

        /// <summary>Matches <c>^(\d{1,4})([\s/\\_.-])(\d{1,2})\2(\d{1,4})$</c>.</summary>
        private static bool TryParseSeparatedDate(string token, out int first, out string separator, out int second, out int third)
        {
            first = second = third = 0;
            separator = string.Empty;
            int p = 0;
            int a = ReadDigits(token, ref p, 4);
            if (a == 0 || p >= token.Length)
                return false;
            char sep = token[p];
            if (!(char.IsWhiteSpace(sep) || sep == '/' || sep == '\\' || sep == '_' || sep == '.' || sep == '-'))
                return false;
            first = ParseDigits(token, 0, a);
            p++;
            int startB = p;
            int b = ReadDigits(token, ref p, 2);
            if (b == 0 || p >= token.Length || token[p] != sep)
                return false;
            second = ParseDigits(token, startB, b);
            p++;
            int startC = p;
            int c = ReadDigits(token, ref p, 4);
            if (c == 0 || p != token.Length)
                return false;
            third = ParseDigits(token, startC, c);
            separator = sep.ToString();
            return true;
        }

        private static int ReadDigits(string s, ref int p, int max)
        {
            int count = 0;
            while (p < s.Length && count < max && TextUtil.IsAsciiDigit(s[p]))
            {
                p++;
                count++;
            }
            return count;
        }

        /// <summary>zxcvbn's <c>map_ints_to_dmy</c>: interprets three integers as a plausible date, or null.</summary>
        internal static (int Year, int Month, int Day)? MapIntsToDmy(int a, int b, int c)
        {
            // The middle value is never a year, and is never zero.
            if (b > 31 || b <= 0)
                return null;
            int over12 = 0, over31 = 0, under1 = 0;
            foreach (int value in new[] { a, b, c })
            {
                if ((value > 99 && value < DateMinYear) || value > DateMaxYear)
                    return null;
                if (value > 31) over31++;
                if (value > 12) over12++;
                if (value <= 0) under1++;
            }
            if (over31 >= 2 || over12 == 3 || under1 >= 2)
                return null;

            // A four-digit year first or last; the rest must be a day and month.
            var splits = new[] { (Y: c, R0: a, R1: b), (Y: a, R0: b, R1: c) };
            foreach (var split in splits)
            {
                if (split.Y >= DateMinYear && split.Y <= DateMaxYear)
                {
                    var dm = MapIntsToDm(split.R0, split.R1);
                    if (dm == null)
                        return null;
                    return (split.Y, dm.Value.Month, dm.Value.Day);
                }
            }

            // Otherwise a two-digit year.
            foreach (var split in splits)
            {
                var dm = MapIntsToDm(split.R0, split.R1);
                if (dm != null)
                    return (TwoToFourDigitYear(split.Y), dm.Value.Month, dm.Value.Day);
            }
            return null;
        }

        private static (int Day, int Month)? MapIntsToDm(int a, int b)
        {
            if (a >= 1 && a <= 31 && b >= 1 && b <= 12)
                return (a, b);
            if (b >= 1 && b <= 31 && a >= 1 && a <= 12)
                return (b, a);
            return null;
        }

        private static int TwoToFourDigitYear(int year)
        {
            if (year > 99)
                return year;
            if (year > 50)
                return year + 1900;
            return year + 2000;
        }
    }
}
