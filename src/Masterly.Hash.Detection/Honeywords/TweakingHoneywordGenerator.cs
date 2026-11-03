using System;
using System.Collections.Generic;
using Masterly.Hash.Detection.Internal;

namespace Masterly.Hash.Detection
{
    /// <summary>
    /// "Chaffing by tail-tweaking" from Juels and Rivest, <i>Honeywords: Making Password-Cracking Detectable</i>
    /// (ACM CCS 2013), section 5.1: each decoy is the real password with its last <see cref="TailLength"/> characters
    /// replaced by random characters of the same class (digit by digit, lower-case letter by lower-case letter,
    /// upper-case by upper-case, symbol by symbol). <c>BG+7y45</c> becomes e.g. <c>BG+7q03</c>, <c>BG+7m55</c>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Known weakness.</b> Wang, Cheng, Wang, Yan and Huang (<i>A Security Analysis of Honeywords</i>, NDSS 2018)
    /// show that tweaked decoys are easy to tell apart: the real password is usually the most "human" of the set (a
    /// real year, a real word, <c>123</c> rather than <c>8q1</c>), and the untouched prefix is shared by every
    /// sweetword, so an attacker who cracks the file and logs in with the most plausible sweetword trips the alarm
    /// far less often than the ideal 1-in-k. Prefer <see cref="PasswordModelHoneywordGenerator"/>.
    /// </para>
    /// <para>
    /// <b>Typo safety.</b> Decoys are never within one typo (one substitution, insertion, deletion or adjacent
    /// transposition) of the real password, so an honest user who mistypes one character does not land on a decoy
    /// and raise a false breach alarm. Two or more typos can still hit a decoy, so treat a single decoy hit as a
    /// strong signal that warrants investigation rather than as proof.
    /// </para>
    /// <para>
    /// Letters and digits of other scripts (Cyrillic, Greek, Arabic, Hebrew, Devanagari, Thai, Latin-1 accented
    /// letters, kana, Hangul, CJK ideographs, and other Unicode letters and digits) are replaced by characters of the
    /// same script and case. Spaces, combining marks, non-ASCII symbols and characters outside the Basic
    /// Multilingual Plane (such as emoji) are never tweaked. If the tail does not offer enough variations it is
    /// widened towards the start of the password, and as a last resort random digits are appended. Appended
    /// digits make the real password recognisable (it is the only sweetword without them), which happens only for
    /// passwords with one or two replaceable characters, such as <c>7</c> or a password made only of emoji or spaces.
    /// Reject such passwords with your password policy.
    /// </para>
    /// </remarks>
    public sealed class TweakingHoneywordGenerator : IHoneywordGenerator
    {
        /// <summary>Tail length used by <see cref="Default"/>, as in the paper's examples.</summary>
        public const int DefaultTailLength = 3;

        /// <summary>A generator that tweaks the last <see cref="DefaultTailLength"/> characters.</summary>
        public static TweakingHoneywordGenerator Default { get; } = new TweakingHoneywordGenerator(DefaultTailLength);

        /// <summary>Creates a generator that tweaks the last <paramref name="tailLength"/> characters (1 to 16).</summary>
        /// <param name="tailLength">How many trailing characters to tweak.</param>
        /// <param name="tweakCase">
        /// If true, letters in the tail may also change case (a lower-case letter becomes any letter), as in the
        /// paper's case-flipping variant. This gives more variations but also changes the password's shape, which
        /// makes decoys easier to spot. Default false.
        /// </param>
        public TweakingHoneywordGenerator(int tailLength = DefaultTailLength, bool tweakCase = false)
        {
            if (tailLength < 1 || tailLength > 16)
                throw new ArgumentOutOfRangeException(nameof(tailLength), tailLength, "Tail length must be between 1 and 16.");
            TailLength = tailLength;
            TweakCase = tweakCase;
        }

        /// <summary>How many trailing characters are tweaked.</summary>
        public int TailLength { get; }

        /// <summary>True if letters in the tail may change case as well as value.</summary>
        public bool TweakCase { get; }

        /// <inheritdoc />
        public IReadOnlyList<string> GenerateDecoys(string realPassword, int count)
        {
            if (realPassword == null) throw new ArgumentNullException(nameof(realPassword));
            if (realPassword.Length == 0) throw new ArgumentException("Password cannot be empty.", nameof(realPassword));
            if (count < 0) throw new ArgumentOutOfRangeException(nameof(count));

            string real = TextNormalization.Nfkc(realPassword);
            var result = new List<string>(count);
            var seen = new HashSet<string>(StringComparer.Ordinal) { realPassword, real };
            AddDecoys(real, count, seen, result, TailLength);
            return result;
        }

        /// <summary>
        /// Adds <paramref name="needed"/> tweaks of the last <paramref name="tailLength"/> characters of
        /// <paramref name="real"/> (NFKC-normalized) that are not yet in <paramref name="seen"/> and are not within
        /// one typo of <paramref name="real"/>. Decoys are added NFKC-normalized.
        /// </summary>
        internal void AddDecoys(string real, int needed, HashSet<string> seen, List<string> result, int tailLength)
        {
            if (needed <= 0)
                return;

            char[] basis = real.ToCharArray();
            int tail = Math.Min(tailLength, basis.Length);

            // Make the variation space at least twice what must be avoided (earlier sweetwords and every candidate
            // one typo from the real password) plus what is needed, so rejection sampling below terminates quickly.
            // Doubles avoid overflow on long tails.
            while (Space(basis, tail) < 2.0 * (seen.Count + needed + Neighbourhood(basis, tail)))
            {
                if (tail < basis.Length)
                {
                    tail++;
                }
                else
                {
                    Array.Resize(ref basis, basis.Length + 1);
                    basis[basis.Length - 1] = '0';
                    tail++;
                }
            }

            int start = basis.Length - tail;
            int target2 = result.Count + needed;
            int attempts = needed * 100 + 100;
            char[] candidate = new char[basis.Length];
            while (result.Count < target2)
            {
                if (attempts-- <= 0)
                    throw new InvalidOperationException("Could not generate enough distinct decoys.");

                Array.Copy(basis, candidate, basis.Length);
                for (int i = start; i < candidate.Length; i++)
                {
                    string? alphabet = AlphabetFor(candidate[i]);
                    if (alphabet != null)
                        candidate[i] = SecureRandom.Pick(alphabet);
                }

                string decoy = TextNormalization.Nfkc(new string(candidate));
                if (!TypoSafety.WithinOneEdit(decoy, real) && seen.Add(decoy))
                    result.Add(decoy);
            }

            Array.Clear(candidate, 0, candidate.Length);
            Array.Clear(basis, 0, basis.Length);
        }

        private double Space(char[] chars, int tail)
        {
            double space = 1;
            for (int i = chars.Length - tail; i < chars.Length; i++)
                space *= AlphabetFor(chars[i])?.Length ?? 1;
            return space;
        }

        /// <summary>Upper bound on the candidates within one typo of the basis (substitutions and transpositions in the tail).</summary>
        private double Neighbourhood(char[] chars, int tail)
        {
            double count = tail;
            for (int i = chars.Length - tail; i < chars.Length; i++)
                count += (AlphabetFor(chars[i])?.Length ?? 1) - 1;
            return count;
        }

        private string? AlphabetFor(char c)
        {
            CharClass cls = CharClasses.Of(c);
            if (cls == CharClass.Other)
                return ScriptAlphabets.For(c);
            return TweakCase && CharClasses.IsLetter(cls) ? CharClasses.Letters : CharClasses.Alphabet(cls);
        }
    }
}
