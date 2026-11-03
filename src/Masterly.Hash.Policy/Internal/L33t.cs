using System.Collections.Generic;
using System.Text;

namespace Masterly.Hash.Policy.Internal
{
    /// <summary>Common character substitutions ("l33t speak"); the same table zxcvbn uses.</summary>
    internal static class L33t
    {
        /// <summary>Letter to the characters that commonly stand in for it.</summary>
        public static readonly IReadOnlyDictionary<char, string> Table = new Dictionary<char, string>
        {
            ['a'] = "4@",
            ['b'] = "8",
            ['c'] = "({[<",
            ['e'] = "3",
            ['g'] = "69",
            ['i'] = "1!|",
            ['l'] = "1|7",
            ['o'] = "0",
            ['s'] = "$5",
            ['t'] = "+7",
            ['x'] = "%",
            ['z'] = "2",
        };

        /// <summary>Substitute character to the letters it can stand for, e.g. '1' to "il".</summary>
        public static readonly IReadOnlyDictionary<char, string> Reverse = BuildReverse();

        /// <summary>True if <paramref name="candidate"/> equals <paramref name="letter"/> or is a l33t substitute for it.</summary>
        public static bool CharMatches(char candidate, char letter)
        {
            if (candidate == letter)
                return true;
            return Reverse.TryGetValue(candidate, out string? letters) && letters.IndexOf(letter) >= 0;
        }

        /// <summary>True if <paramref name="text"/> equals <paramref name="word"/>, allowing l33t substitutions in <paramref name="text"/>.</summary>
        public static bool EqualsWithSubstitutions(string text, string word)
        {
            if (text.Length != word.Length)
                return false;
            for (int i = 0; i < text.Length; i++)
            {
                if (!CharMatches(text[i], word[i]))
                    return false;
            }
            return true;
        }

        /// <summary>
        /// True if <paramref name="a"/> and <paramref name="b"/> can stand for the same letter: they are equal, one is a
        /// l33t substitute for the other, or both are substitutes for a common letter (e.g. '1' and '|' for 'l').
        /// Symmetric, so l33t in either string is ignored.
        /// </summary>
        public static bool CharsEquivalent(char a, char b)
        {
            if (a == b)
                return true;
            bool aIsSubstitute = Reverse.TryGetValue(a, out string? aLetters);
            bool bIsSubstitute = Reverse.TryGetValue(b, out string? bLetters);
            if (aIsSubstitute && aLetters!.IndexOf(b) >= 0)
                return true;
            if (bIsSubstitute && bLetters!.IndexOf(a) >= 0)
                return true;
            if (aIsSubstitute && bIsSubstitute)
            {
                foreach (char letter in aLetters!)
                {
                    if (bLetters!.IndexOf(letter) >= 0)
                        return true;
                }
            }
            return false;
        }

        /// <summary>
        /// True if <paramref name="text"/> contains <paramref name="word"/>, ignoring l33t substitutions on both
        /// sides (<see cref="CharsEquivalent"/>): a user name "j0hnd03" is found in "johndoe" and vice versa.
        /// </summary>
        public static bool ContainsEquivalent(string text, string word)
        {
            if (word.Length == 0 || word.Length > text.Length)
                return false;
            for (int start = 0; start + word.Length <= text.Length; start++)
            {
                int k = 0;
                while (k < word.Length && CharsEquivalent(text[start + k], word[k]))
                    k++;
                if (k == word.Length)
                    return true;
            }
            return false;
        }

        /// <summary>Every plain-letter reading of <paramref name="word"/>'s l33t characters; empty if it has none.</summary>
        public static List<string> PlainReadings(string word)
        {
            var readings = new List<string>();
            foreach (Dictionary<char, char> sub in EnumerateSubstitutions(word))
            {
                string reading = Translate(word, sub);
                if (!readings.Contains(reading))
                    readings.Add(reading);
            }
            return readings;
        }

        /// <summary>Replaces each character found in <paramref name="map"/>.</summary>
        public static string Translate(string value, Dictionary<char, char> map)
        {
            var sb = new StringBuilder(value.Length);
            foreach (char c in value)
                sb.Append(map.TryGetValue(c, out char replacement) ? replacement : c);
            return sb.ToString();
        }

        /// <summary>
        /// Every way to read the l33t characters present in <paramref name="password"/> as letters
        /// (each substitute character maps to exactly one letter). Empty if there are none.
        /// At most 2^3 entries: only '1', '|' and '7' are ambiguous.
        /// </summary>
        public static List<Dictionary<char, char>> EnumerateSubstitutions(string password)
        {
            var present = new List<char>();
            foreach (KeyValuePair<char, string> entry in Reverse)
            {
                if (password.IndexOf(entry.Key) >= 0)
                    present.Add(entry.Key);
            }
            present.Sort();

            var subs = new List<Dictionary<char, char>>();
            if (present.Count == 0)
                return subs;

            subs.Add(new Dictionary<char, char>());
            foreach (char substitute in present)
            {
                string letters = Reverse[substitute];
                var next = new List<Dictionary<char, char>>(subs.Count * letters.Length);
                foreach (Dictionary<char, char> sub in subs)
                {
                    foreach (char letter in letters)
                        next.Add(new Dictionary<char, char>(sub) { [substitute] = letter });
                }
                subs = next;
            }
            return subs;
        }

        private static IReadOnlyDictionary<char, string> BuildReverse()
        {
            var reverse = new SortedDictionary<char, string>();
            foreach (KeyValuePair<char, string> entry in Table)
            {
                foreach (char substitute in entry.Value)
                {
                    reverse.TryGetValue(substitute, out string? letters);
                    reverse[substitute] = (letters ?? string.Empty) + entry.Key;
                }
            }
            return new Dictionary<char, string>(reverse);
        }
    }
}
