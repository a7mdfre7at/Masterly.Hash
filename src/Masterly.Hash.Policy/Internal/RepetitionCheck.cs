using System;
using System.Collections.Generic;

namespace Masterly.Hash.Policy.Internal
{
    /// <summary>
    /// The NIST SP 800-63B "repetitive or sequential characters" rule: true if every character of the password
    /// belongs to a run of a weak unit (<c>aaaa</c>, <c>abcabc</c>, <c>aabaabaab</c>, partial last period
    /// included), a sequence of at least three characters (<c>abcd</c>, <c>9753</c>) or a keyboard run
    /// (<c>qwerty</c>, <c>1qaz2wsx</c>). A strong token typed twice is not repetitive in this sense; the strength score
    /// deals with it. Runs in roughly O(n * MaxUnit^2) on any length, so the whole password is always checked.
    /// </summary>
    internal static class RepetitionCheck
    {
        /// <summary>Longest unit the local repeat scan tries; longer periods are found by the whole-string check.</summary>
        internal const int MaxUnit = 32;

        /// <summary>Units this short are weak whatever they contain (at most 10^3 brute-force guesses).</summary>
        private const int AlwaysWeakUnitLength = 3;

        private static readonly Matching s_spatialMatcher = new Matching(Array.Empty<RankedDictionary>(), 2000);

        public static bool IsRepetitiveOrSequential(string s) => IsCovered(s, new Dictionary<string, bool>(StringComparer.Ordinal));

        private static bool IsCovered(string s, Dictionary<string, bool> weakCache)
        {
            int n = s.Length;
            if (n < 2)
                return false;

            // The whole string is a weak unit repeated (any period length, last period possibly partial).
            int period = SmallestPeriod(s);
            if (period <= n / 2 && IsWeakUnit(s.Substring(0, period), weakCache))
                return true;

            var covered = new bool[n];
            foreach (Match m in Matching.SequenceMatch(s))
            {
                if (m.J - m.I >= 2)
                    Cover(covered, m.I, m.J + 1);
            }
            foreach (Match m in s_spatialMatcher.SpatialMatch(s))
                Cover(covered, m.I, m.J + 1);
            CoverRepeats(s, covered, weakCache);

            foreach (bool c in covered)
            {
                if (!c)
                    return false;
            }
            return true;
        }

        /// <summary>
        /// Marks every span that is a weak unit of length 1..<see cref="MaxUnit"/> repeated at least twice, extended
        /// through any partial last period. At each start the farthest-reaching weak unit wins.
        /// </summary>
        private static void CoverRepeats(string s, bool[] covered, Dictionary<string, bool> weakCache)
        {
            int n = s.Length;
            // For each unit, the span [spanStart, spanEnd) last found to have that period: a double inside it
            // extends to exactly spanEnd, so it need not be rescanned.
            var spanStart = new int[MaxUnit + 1];
            var spanEnd = new int[MaxUnit + 1];
            int coveredEnd = 0;
            var candidates = new List<(int End, int Unit)>();

            for (int i = 0; i < n - 1; i++)
            {
                candidates.Clear();
                int maxUnit = Math.Min(MaxUnit, (n - i) / 2);
                for (int u = 1; u <= maxUnit; u++)
                {
                    int end;
                    if (i >= spanStart[u] && i + 2 * u <= spanEnd[u])
                    {
                        end = spanEnd[u];
                    }
                    else
                    {
                        if (string.CompareOrdinal(s, i, s, i + u, u) != 0)
                            continue;
                        end = i + 2 * u;
                        while (end < n && s[end] == s[end - u])
                            end++;
                        spanStart[u] = i;
                        spanEnd[u] = end;
                    }
                    // A span ending inside one already covered from an earlier start adds nothing.
                    if (end > coveredEnd)
                        candidates.Add((end, u));
                }
                if (candidates.Count == 0)
                    continue;

                candidates.Sort((a, b) => a.End != b.End ? b.End.CompareTo(a.End) : a.Unit.CompareTo(b.Unit));
                foreach ((int end, int unit) in candidates)
                {
                    if (IsWeakUnit(s.Substring(i, unit), weakCache))
                    {
                        Cover(covered, i, end);
                        coveredEnd = end;
                        break;
                    }
                }
            }
        }

        /// <summary>A unit whose repetition is "repetitive": very short, or itself only repeats, sequences and keyboard runs.</summary>
        private static bool IsWeakUnit(string unit, Dictionary<string, bool> weakCache)
        {
            if (unit.Length <= AlwaysWeakUnitLength)
                return true;
            if (weakCache.TryGetValue(unit, out bool weak))
                return weak;
            weak = IsCovered(unit, weakCache);
            weakCache[unit] = weak;
            return weak;
        }

        /// <summary>Smallest p such that s[k] == s[k - p] for every k >= p (KMP prefix function), O(n).</summary>
        internal static int SmallestPeriod(string s)
        {
            int n = s.Length;
            if (n == 0)
                return 0;
            var prefix = new int[n];
            for (int k = 1; k < n; k++)
            {
                int j = prefix[k - 1];
                while (j > 0 && s[k] != s[j])
                    j = prefix[j - 1];
                if (s[k] == s[j])
                    j++;
                prefix[k] = j;
            }
            return n - prefix[n - 1];
        }

        private static void Cover(bool[] covered, int from, int to)
        {
            for (int k = from; k < to; k++)
                covered[k] = true;
        }
    }
}
