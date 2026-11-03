using System;
using System.Collections.Concurrent;
using System.Globalization;
using System.Text;

namespace Masterly.Hash.Detection.Internal
{
    /// <summary>
    /// Replacement alphabets for non-ASCII letters and digits, so passwords written in other scripts get decoys of
    /// the same shape instead of falling back to appended digits. Common scripts use curated ranges (the everyday
    /// letters of the alphabet, split by case); anything else uses the characters of the same Unicode category in
    /// the same 128-code-point block. Every character in an alphabet is NFKC-stable on its own.
    /// </summary>
    internal static class ScriptAlphabets
    {
        private static readonly Script[] Curated =
        {
            new Script(0x0430, 0x044F, Range(0x0430, 0x044F)), // Cyrillic small а-я
            new Script(0x0410, 0x042F, Range(0x0410, 0x042F)), // Cyrillic capital А-Я
            new Script(0x03B1, 0x03C9, Range(0x03B1, 0x03C9)), // Greek small α-ω
            new Script(0x0391, 0x03A9, Range(0x0391, 0x03A9)), // Greek capital Α-Ω
            new Script(0x05D0, 0x05EA, Range(0x05D0, 0x05EA)), // Hebrew letters
            new Script(0x0621, 0x064A, Range(0x0621, 0x063A) + Range(0x0641, 0x064A)), // Arabic letters
            new Script(0x0660, 0x0669, Range(0x0660, 0x0669)), // Arabic-Indic digits
            new Script(0x06F0, 0x06F9, Range(0x06F0, 0x06F9)), // Extended Arabic-Indic digits
            new Script(0x0905, 0x0939, Range(0x0905, 0x0939)), // Devanagari vowels and consonants
            new Script(0x0966, 0x096F, Range(0x0966, 0x096F)), // Devanagari digits
            new Script(0x0E01, 0x0E2E, Range(0x0E01, 0x0E2E)), // Thai consonants
            new Script(0x00DF, 0x00FF, Range(0x00DF, 0x00FF)), // Latin-1 small letters (ß à ... ÿ)
            new Script(0x00C0, 0x00DE, Range(0x00C0, 0x00DE)), // Latin-1 capital letters (À ... Þ)
            new Script(0x3041, 0x3093, Range(0x3041, 0x3093)), // Hiragana
            new Script(0x30A1, 0x30F3, Range(0x30A1, 0x30F3)), // Katakana
            new Script(0xAC00, 0xD7A3, Range(0xAC00, 0xD7A3)), // Hangul syllables
            new Script(0x4E00, 0x9FFF, Range(0x4E00, 0x9FFF)), // CJK unified ideographs
        };

        private static readonly ConcurrentDictionary<int, string> Generic = new ConcurrentDictionary<int, string>();

        /// <summary>
        /// Alphabet that <paramref name="c"/> can be replaced from, or null if it is kept verbatim (ASCII, which
        /// <see cref="CharClasses"/> handles; spaces, marks, symbols, surrogates; scripts with fewer than two candidates).
        /// </summary>
        public static string? For(char c)
        {
            if (c < 0x80 || char.IsSurrogate(c))
                return null;

            foreach (Script script in Curated)
            {
                if (script.Contains(c))
                    return script.Alphabet;
            }

            UnicodeCategory category = CharUnicodeInfo.GetUnicodeCategory(c);
            if (category != UnicodeCategory.LowercaseLetter && category != UnicodeCategory.UppercaseLetter &&
                category != UnicodeCategory.OtherLetter && category != UnicodeCategory.DecimalDigitNumber)
            {
                return null;
            }

            int block = c & 0xFF80;
            string generic = Generic.GetOrAdd((block << 5) | (int)category, _ => Build(block, block + 0x7F, category));
            return generic.Length >= 2 ? generic : null;
        }

        private static string Range(int first, int last) =>
            Build(first, last, null);

        private static string Build(int first, int last, UnicodeCategory? category)
        {
            var sb = new StringBuilder(last - first + 1);
            for (int code = first; code <= last; code++)
            {
                char c = (char)code;
                if (char.IsSurrogate(c))
                    continue;
                UnicodeCategory cat = CharUnicodeInfo.GetUnicodeCategory(c);
                bool usable = category.HasValue
                    ? cat == category.Value
                    : char.IsLetterOrDigit(c);
                if (usable && IsStable(c))
                    sb.Append(c);
            }
            return sb.ToString();
        }

        private sealed class Script
        {
            private readonly int _first;
            private readonly int _last;
            private readonly bool _complete;

            public Script(int first, int last, string alphabet)
            {
                _first = first;
                _last = last;
                Alphabet = alphabet;
                _complete = alphabet.Length == last - first + 1;
            }

            public string Alphabet { get; }

            public bool Contains(char c) =>
                c >= _first && c <= _last && (_complete || Alphabet.IndexOf(c) >= 0);
        }

        private static bool IsStable(char c)
        {
            string s = c.ToString();
            try
            {
                return s.Normalize(NormalizationForm.FormKC) == s;
            }
            catch (ArgumentException)
            {
                return false;
            }
        }
    }
}
