using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using Masterly.Hash.Detection.Internal;

namespace Masterly.Hash.Detection
{
    /// <summary>
    /// "Chaffing with a password model" (Juels and Rivest 2013, section 5.2): every decoy is drawn from a simple
    /// generative model of human passwords, shaped like the real one. The password is split into runs of letters,
    /// digits and symbols (its structure, e.g. <c>Summer2024!</c> is L6 D4 S1) and each run is replaced by a
    /// plausible token of the same class and length: a dictionary word with the same capitalization pattern, a year
    /// or digit pattern, common symbols. Letters and digits of other scripts (Cyrillic, Greek, Arabic, CJK and so on)
    /// are replaced character by character with characters of the same script and case. Spaces, combining marks,
    /// non-ASCII symbols and emoji are kept as they are.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is the recommended generator. Because the replaceable parts of the real password are not reused, an
    /// attacker cannot find the real one by looking for the "untweaked" sweetword. It is still not perfect: Wang,
    /// Cheng, Wang, Yan and Huang (<i>A Security Analysis of Honeywords</i>, NDSS 2018) show that real passwords
    /// remain more probable than decoys under a good password-guessing model (a real name next to random dictionary
    /// words, a meaningful date). Non-ASCII letters are replaced by random characters of their script rather than by
    /// words, so for such passwords the real one is the only sweetword made of real words; supply a word list that
    /// matches your users' language and culture through
    /// <see cref="PasswordModelHoneywordGenerator(IEnumerable{string})"/> where you can (the list is ASCII-only).
    /// </para>
    /// <para>
    /// Decoys are never within one typo of the real password (see <see cref="TweakingHoneywordGenerator"/>), so an
    /// honest user's single mistyped character does not raise a false breach alarm.
    /// </para>
    /// <para>
    /// If the structure leaves too little room for distinct decoys (a short word list, or a password such as
    /// <c>7</c>) the remainder is filled by randomizing every replaceable character within its class, which keeps
    /// the shape but not the "human" look. Passwords with only one or two replaceable characters can only be padded
    /// with appended digits, which makes the real password recognisable; reject them with your password policy.
    /// </para>
    /// </remarks>
    public sealed class PasswordModelHoneywordGenerator : IHoneywordGenerator
    {
        private readonly Dictionary<int, string[]> _wordsByLength;
        private readonly int[] _lengths;

        /// <summary>A generator using the built-in English word list.</summary>
        public static PasswordModelHoneywordGenerator Default { get; } = new PasswordModelHoneywordGenerator();

        /// <summary>Creates a generator using the built-in English word list.</summary>
        public PasswordModelHoneywordGenerator()
            : this(DefaultWordList.Words.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries))
        {
        }

        /// <summary>
        /// Creates a generator using <paramref name="words"/> for letter runs. Words are lower-cased; anything that is
        /// not 1 to 32 ASCII letters is ignored. At least one usable word is required.
        /// </summary>
        public PasswordModelHoneywordGenerator(IEnumerable<string> words)
        {
            if (words == null) throw new ArgumentNullException(nameof(words));

            var unique = new HashSet<string>(StringComparer.Ordinal);
            foreach (string? word in words)
            {
                if (word == null || word.Length == 0 || word.Length > 32)
                    continue;
                string lower = word.ToLowerInvariant();
                if (lower.All(c => c >= 'a' && c <= 'z'))
                    unique.Add(lower);
            }

            if (unique.Count == 0)
                throw new ArgumentException("The word list contains no usable words (1 to 32 ASCII letters).", nameof(words));

            _wordsByLength = unique
                .GroupBy(w => w.Length)
                .ToDictionary(g => g.Key, g => g.OrderBy(w => w, StringComparer.Ordinal).ToArray());
            _lengths = _wordsByLength.Keys.OrderBy(l => l).ToArray();
            WordCount = unique.Count;
        }

        /// <summary>Number of distinct words in the vocabulary.</summary>
        public int WordCount { get; }

        /// <inheritdoc />
        public IReadOnlyList<string> GenerateDecoys(string realPassword, int count)
        {
            if (realPassword == null) throw new ArgumentNullException(nameof(realPassword));
            if (realPassword.Length == 0) throw new ArgumentException("Password cannot be empty.", nameof(realPassword));
            if (count < 0) throw new ArgumentOutOfRangeException(nameof(count));

            string real = TextNormalization.Nfkc(realPassword);
            List<Run> runs = Tokenize(real);
            var result = new List<string>(count);
            var seen = new HashSet<string>(StringComparer.Ordinal) { realPassword, real };

            int attempts = count * 50 + 50;
            var builder = new StringBuilder(realPassword.Length + 8);
            while (result.Count < count && attempts-- > 0)
            {
                builder.Clear();
                foreach (Run run in runs)
                    AppendToken(builder, run);
                string decoy = TextNormalization.Nfkc(builder.ToString());
                if (!TypoSafety.WithinOneEdit(decoy, real) && seen.Add(decoy))
                    result.Add(decoy);
            }
            builder.Clear();

            // Not enough room in the model: randomize every replaceable character (tail = whole password), so the
            // fallback decoys share no replaceable character with the real password and it is not their centre.
            if (result.Count < count)
                TweakingHoneywordGenerator.Default.AddDecoys(real, count - result.Count, seen, result, real.Length);

            return result;
        }

        private void AppendToken(StringBuilder builder, Run run)
        {
            switch (run.Kind)
            {
                case RunKind.Letters:
                    AppendLetters(builder, run.Text);
                    break;
                case RunKind.Digits:
                    AppendDigits(builder, run.Text.Length);
                    break;
                case RunKind.Symbols:
                    for (int i = 0; i < run.Text.Length; i++)
                    {
                        builder.Append(SecureRandom.Chance(4, 5)
                            ? SecureRandom.Pick(CharClasses.CommonSymbols)
                            : SecureRandom.Pick(CharClasses.Symbols));
                    }
                    break;
                case RunKind.Script:
                    foreach (char c in run.Text)
                        builder.Append(SecureRandom.Pick(ScriptAlphabets.For(c)!));
                    break;
                default:
                    builder.Append(run.Text);
                    break;
            }
        }

        private void AppendLetters(StringBuilder builder, string original)
        {
            string letters = FillLetters(original.Length);
            bool allLower = original.All(IsLower);
            bool allUpper = original.All(IsUpper);
            bool capitalized = original.Length > 1 && IsUpper(original[0]) && original.Skip(1).All(IsLower);
            bool mixed = !allLower && !allUpper && !capitalized;

            for (int i = 0; i < letters.Length; i++)
            {
                bool upper = allUpper || (capitalized && i == 0) || (mixed && IsUpper(original[i]));
                builder.Append(upper ? char.ToUpperInvariant(letters[i]) : letters[i]);
            }
        }

        /// <summary>Exactly <paramref name="length"/> lower-case letters, made of whole words where possible.</summary>
        private string FillLetters(int length)
        {
            var sb = new StringBuilder(length);
            while (sb.Length < length)
            {
                int remaining = length - sb.Length;
                bool exact = _wordsByLength.TryGetValue(remaining, out string[]? exactWords);
                if (exact && (sb.Length > 0 || remaining <= 2 || SecureRandom.Chance(3, 4)))
                {
                    sb.Append(exactWords![SecureRandom.Next(exactWords.Length)]);
                    continue;
                }

                // Compose: a shorter word, leaving room for at least one more character.
                int shorterCount = 0;
                while (shorterCount < _lengths.Length && _lengths[shorterCount] < remaining)
                    shorterCount++;
                if (shorterCount > 0 && remaining > 2)
                {
                    string[] pool = _wordsByLength[_lengths[SecureRandom.Next(shorterCount)]];
                    sb.Append(pool[SecureRandom.Next(pool.Length)]);
                    continue;
                }

                if (exact)
                {
                    sb.Append(exactWords![SecureRandom.Next(exactWords.Length)]);
                    continue;
                }

                for (int i = 0; i < remaining; i++)
                    sb.Append(SecureRandom.Pick(CharClasses.Lower));
            }
            return sb.ToString();
        }

        private static void AppendDigits(StringBuilder builder, int length)
        {
            if (length == 4 && SecureRandom.Chance(2, 5))
            {
                builder.Append(SecureRandom.Next(1950, 2031).ToString("D4", CultureInfo.InvariantCulture));
                return;
            }

            if (length >= 2 && SecureRandom.Chance(1, 5))
            {
                // Ascending sequence such as 123 or 6789.
                int first = SecureRandom.Next(10);
                for (int i = 0; i < length; i++)
                    builder.Append((char)('0' + ((first + i) % 10)));
                return;
            }

            if (length >= 2 && SecureRandom.Chance(1, 8))
            {
                builder.Append(SecureRandom.Pick(CharClasses.Digits), length);
                return;
            }

            for (int i = 0; i < length; i++)
                builder.Append(SecureRandom.Pick(CharClasses.Digits));
        }

        private static bool IsLower(char c) => c >= 'a' && c <= 'z';

        private static bool IsUpper(char c) => c >= 'A' && c <= 'Z';

        private static List<Run> Tokenize(string password)
        {
            var runs = new List<Run>();
            int i = 0;
            while (i < password.Length)
            {
                RunKind kind = KindOf(password[i]);
                int start = i;
                while (i < password.Length && KindOf(password[i]) == kind)
                    i++;
                runs.Add(new Run(kind, password.Substring(start, i - start)));
            }
            return runs;
        }

        private static RunKind KindOf(char c)
        {
            CharClass cls = CharClasses.Of(c);
            if (CharClasses.IsLetter(cls)) return RunKind.Letters;
            if (cls == CharClass.Digit) return RunKind.Digits;
            if (cls == CharClass.Symbol) return RunKind.Symbols;
            return ScriptAlphabets.For(c) != null ? RunKind.Script : RunKind.Other;
        }

        private enum RunKind
        {
            Letters,
            Digits,
            Symbols,
            Script,
            Other,
        }

        private readonly struct Run
        {
            public Run(RunKind kind, string text)
            {
                Kind = kind;
                Text = text;
            }

            public RunKind Kind { get; }

            public string Text { get; }
        }
    }
}
