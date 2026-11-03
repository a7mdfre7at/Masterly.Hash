using System;
using System.Globalization;
using System.Text;

namespace Masterly.Hash.BlindIndex.Normalizers
{
    /// <summary>
    /// Normalizes a phone number to ASCII digits only. Any Unicode decimal digit (e.g. Arabic-Indic, or a
    /// supplementary-plane digit such as Adlam) is mapped to its ASCII equivalent; every other character (spaces,
    /// dashes, parentheses, dots, <c>+</c>, letters) is dropped.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A leading <c>+</c> or <c>00</c> marks an international number; <c>00</c> is removed so <c>+962...</c> and
    /// <c>00962...</c> match. In an international number, a parenthesised trunk zero after the country code is
    /// dropped, so <c>+44 (0)20 7946 0958</c> matches <c>+44 20 7946 0958</c>. With a <see cref="DefaultCountryCode"/>,
    /// a national number (neither prefix) has one leading trunk <c>0</c> removed and the country code prepended, so
    /// <c>079 123 4567</c> with country code <c>962</c> matches <c>+962 79 123 4567</c>.
    /// </para>
    /// <para>
    /// This is not a full E.164 parser, and a mismatch is a silent false negative (the search misses the row). Known
    /// cases: with a <see cref="DefaultCountryCode"/>, a number written with its country code but without <c>+</c> or
    /// <c>00</c> (<c>962 79 123 4567</c>) reads as national and gets the code prepended again; countries whose trunk
    /// prefix is not <c>0</c> are not rewritten; extensions are kept as digits. Where that matters, canonicalize to
    /// E.164 in the application (e.g. with libphonenumber) before indexing. Always normalize the raw input, never an
    /// already-normalized value: with a country code, digits-only output fed back in reads as a national number.
    /// </para>
    /// </remarks>
    public sealed class PhoneNormalizer : IBlindIndexNormalizer
    {
        /// <summary>Creates a phone normalizer.</summary>
        /// <param name="defaultCountryCode">
        /// Optional E.164 country calling code (1 to 3 ASCII digits, no leading zero, no <c>+</c>) applied to national
        /// numbers.
        /// </param>
        /// <exception cref="ArgumentException"><paramref name="defaultCountryCode"/> is not 1 to 3 digits.</exception>
        public PhoneNormalizer(string? defaultCountryCode = null)
        {
            if (defaultCountryCode != null && !IsCountryCode(defaultCountryCode))
                throw new ArgumentException("Country code must be 1 to 3 ASCII digits without a leading zero.", nameof(defaultCountryCode));
            DefaultCountryCode = defaultCountryCode;
        }

        /// <summary>The country calling code prepended to national numbers, or null.</summary>
        public string? DefaultCountryCode { get; }

        /// <inheritdoc />
        /// <remarks>Returns an empty string when the value contains no digits.</remarks>
        public string Normalize(string value)
        {
            if (value == null) throw new ArgumentNullException(nameof(value));

            string text = UnicodeText.Nfkc(value, nameof(value)).Trim();
            bool plus = text.Length > 0 && text[0] == '+';

            // Walk by code point so supplementary-plane digits are not split into (dropped) surrogates.
            var digits = new StringBuilder(text.Length);
            int trunkGroupAt = -1;
            int i = 0;
            while (i < text.Length)
            {
                if (text[i] == '(' && TryMatchZeroGroup(text, i, out int end))
                {
                    if (trunkGroupAt < 0 && digits.Length > 0)
                        trunkGroupAt = digits.Length;
                    digits.Append('0');
                    i = end;
                    continue;
                }

                int d = DigitAt(text, i);
                if (d >= 0)
                    digits.Append((char)('0' + d));
                i += char.IsSurrogatePair(text, i) ? 2 : 1;
            }

            string result = digits.ToString();
            bool doubleZero = !plus && result.StartsWith("00", StringComparison.Ordinal);
            if (plus || doubleZero)
            {
                // A "(0)" group after the country code is the national trunk prefix, not part of the number.
                int prefixLength = doubleZero ? 2 : 0;
                if (trunkGroupAt > prefixLength)
                    result = result.Remove(trunkGroupAt, 1);
                return doubleZero ? result.Substring(2) : result;
            }

            if (DefaultCountryCode == null || result.Length == 0)
                return result;

            if (result[0] == '0')
                result = result.Substring(1);
            return result.Length == 0 ? result : DefaultCountryCode + result;
        }

        /// <summary>Matches <c>(0)</c>, allowing white space inside the parentheses, at <paramref name="start"/>.</summary>
        private static bool TryMatchZeroGroup(string text, int start, out int end)
        {
            end = start;
            int j = SkipWhiteSpace(text, start + 1);
            if (j >= text.Length || DigitAt(text, j) != 0)
                return false;
            j = SkipWhiteSpace(text, j + (char.IsSurrogatePair(text, j) ? 2 : 1));
            if (j >= text.Length || text[j] != ')')
                return false;
            end = j + 1;
            return true;
        }

        private static int SkipWhiteSpace(string text, int index)
        {
            while (index < text.Length && char.IsWhiteSpace(text[index]))
                index++;
            return index;
        }

        /// <summary>The value 0-9 of the decimal digit code point at <paramref name="index"/>, or -1.</summary>
        private static int DigitAt(string text, int index)
        {
            if (CharUnicodeInfo.GetUnicodeCategory(text, index) != UnicodeCategory.DecimalDigitNumber)
                return -1;
            int d = CharUnicodeInfo.GetDecimalDigitValue(text, index);
            return d >= 0 && d <= 9 ? d : -1;
        }

        private static bool IsCountryCode(string code)
        {
            if (code.Length < 1 || code.Length > 3 || code[0] == '0')
                return false;
            foreach (char c in code)
            {
                if (c < '0' || c > '9')
                    return false;
            }
            return true;
        }
    }
}
