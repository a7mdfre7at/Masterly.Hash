namespace Masterly.Hash.Detection.Internal
{
    /// <summary>Character classes used to shape decoys like the real password.</summary>
    internal enum CharClass
    {
        Lower,
        Upper,
        Digit,
        Symbol,

        /// <summary>Space, control and non-ASCII characters. Non-ASCII letters and digits are replaced via <see cref="ScriptAlphabets"/>; the rest is kept verbatim.</summary>
        Other,
    }

    internal static class CharClasses
    {
        public const string Lower = "abcdefghijklmnopqrstuvwxyz";
        public const string Upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        public const string Digits = "0123456789";

        /// <summary>Lower- and upper-case ASCII letters.</summary>
        public const string Letters = Lower + Upper;

        /// <summary>The 32 printable ASCII punctuation characters.</summary>
        public const string Symbols = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";

        /// <summary>Symbols people actually put in passwords, most common first.</summary>
        public const string CommonSymbols = "!@#$%&*?._-+=";

        public static CharClass Of(char c)
        {
            if (c >= 'a' && c <= 'z') return CharClass.Lower;
            if (c >= 'A' && c <= 'Z') return CharClass.Upper;
            if (c >= '0' && c <= '9') return CharClass.Digit;
            if (c > ' ' && c < (char)127) return CharClass.Symbol;
            return CharClass.Other;
        }

        public static string? Alphabet(CharClass cls)
        {
            switch (cls)
            {
                case CharClass.Lower: return Lower;
                case CharClass.Upper: return Upper;
                case CharClass.Digit: return Digits;
                case CharClass.Symbol: return Symbols;
                default: return null;
            }
        }

        public static bool IsLetter(CharClass cls) => cls == CharClass.Lower || cls == CharClass.Upper;
    }
}
