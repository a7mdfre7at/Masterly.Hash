using System;

namespace Masterly.Hash.Detection.Internal
{
    /// <summary>
    /// Typo-safety (Juels and Rivest 2013, section 4): a decoy must not be one typo away from the real password,
    /// otherwise an honest user's mistyped login lands on a decoy and raises a false breach alarm.
    /// </summary>
    internal static class TypoSafety
    {
        /// <summary>
        /// True if <paramref name="a"/> and <paramref name="b"/> differ by at most one substitution, insertion,
        /// deletion or adjacent transposition (Damerau-Levenshtein distance 0 or 1). O(n), no allocation.
        /// </summary>
        public static bool WithinOneEdit(string a, string b)
        {
            if (a == null) throw new ArgumentNullException(nameof(a));
            if (b == null) throw new ArgumentNullException(nameof(b));

            int lengthDiff = a.Length - b.Length;
            if (lengthDiff > 1 || lengthDiff < -1)
                return false;

            int prefix = 0;
            int shorter = Math.Min(a.Length, b.Length);
            while (prefix < shorter && a[prefix] == b[prefix])
                prefix++;
            if (prefix == a.Length && prefix == b.Length)
                return true;

            if (lengthDiff == 0)
            {
                // One substitution at prefix, or a transposition of prefix and prefix + 1.
                if (Tail(a, prefix + 1, b, prefix + 1))
                    return true;
                return prefix + 1 < a.Length
                    && a[prefix] == b[prefix + 1] && a[prefix + 1] == b[prefix]
                    && Tail(a, prefix + 2, b, prefix + 2);
            }

            // One insertion: skip the extra character of the longer string.
            return lengthDiff > 0
                ? Tail(a, prefix + 1, b, prefix)
                : Tail(a, prefix, b, prefix + 1);
        }

        private static bool Tail(string a, int i, string b, int j)
        {
            if (a.Length - i != b.Length - j)
                return false;
            for (; i < a.Length; i++, j++)
            {
                if (a[i] != b[j])
                    return false;
            }
            return true;
        }
    }
}
