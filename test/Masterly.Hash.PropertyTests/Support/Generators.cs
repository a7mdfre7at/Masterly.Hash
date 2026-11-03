using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using FsCheck;
using FsCheck.Fluent;
using Masterly.Hash.Primitives;

namespace Masterly.Hash.PropertyTests.Support;

// Wrapper types give each property a precise input distribution and a readable rendering on failure.

/// <summary>Any string a database column could hold: random UTF-16 (lone surrogates included), PHC-shaped junk, huge values.</summary>
public sealed record AnyString(string Value)
{
    public override string ToString() => Fixtures.Show(Value);
}

/// <summary>
/// Any non-null password, including empty, huge and invalid UTF-16 (lone surrogates). Hash must reject the ill-formed
/// ones and Verify must report <see cref="VerificationFailureReason.InvalidPassword"/> for them.
/// </summary>
public sealed record AnyPassword(string Value)
{
    public override string ToString() => Fixtures.Show(Value);
}

/// <summary>
/// A non-empty, well-formed UTF-16 password whose NFKC UTF-8 encoding fits <see cref="PasswordHasherOptions.MaxPasswordBytes"/>.
/// </summary>
public sealed record ValidPassword(string Value)
{
    public override string ToString() => Fixtures.Show(Value);
}

/// <summary>
/// A well-formed password and a well-formed second candidate: an edit of it, an equivalent form, itself, or an
/// unrelated password.
/// </summary>
public sealed record PasswordPair(string Password, string Candidate)
{
    public override string ToString() => $"{Fixtures.Show(Password)} vs {Fixtures.Show(Candidate)}";
}

/// <summary>A password built from a repeated unit, sized to straddle the 1024-byte cap after NFKC.</summary>
public sealed record CapPassword(string Value)
{
    public override string ToString() =>
        $"{Fixtures.Show(Value.Substring(0, Math.Min(4, Value.Length)))}... {Value.Length} chars, {HashPrimitives.EncodePassword(Value).Length} NFKC bytes";
}

/// <summary>Well-formed Unicode text and a canonically/compatibly equivalent rewrite of it.</summary>
public sealed record EquivalentText(string Text, string Variant)
{
    public override string ToString() => $"{Fixtures.Show(Text)} ~ {Fixtures.Show(Variant)}";
}

/// <summary>One edit applied to a hash string. Positions are reduced modulo the string length when applied.</summary>
public sealed record MutationOp(int Kind, int Position, char Char, int Variant)
{
    public override string ToString() => $"{Kind}@{Position}:{Fixtures.Show(Char.ToString())}/{Variant}";
}

/// <summary>A valid <c>$mh$</c> hash recipe and the edits to apply to it.</summary>
public sealed record MhMutation(int BaseKind, string Password, byte[] LegacySalt, MutationOp[] Ops)
{
    public override string ToString() =>
        $"kind={BaseKind} pw={Fixtures.Show(Password)} salt={Convert.ToHexString(LegacySalt)} ops=[{string.Join(", ", Ops.Select(o => o.ToString()))}]";
}

/// <summary>A legacy hash kind (see <see cref="Fixtures.BuildLegacyHash"/>), a password and a salt.</summary>
public sealed record LegacyCase(int Kind, string Password, byte[] Salt)
{
    public override string ToString() =>
        $"{Fixtures.LegacyKindName(Kind)} pw={Fixtures.Show(Password)} ({Encoding.UTF8.GetByteCount(Password)} raw bytes) salt={Convert.ToHexString(Salt)}";
}

/// <summary>Well-formed equivalent text with the same lone surrogate inserted at the same place in both strings.</summary>
public sealed record IllFormedEquivalent(string Text, string Variant)
{
    public override string ToString() => $"{Fixtures.Show(Text)} ~ {Fixtures.Show(Variant)}";
}

/// <summary>
/// An ill-formed UTF-16 password (<see cref="Value"/>) derived from a short well-formed one (<see cref="Origin"/>) by
/// inserting a lone surrogate, dropping one half of a surrogate pair, or swapping the halves of a pair.
/// </summary>
public sealed record IllFormedPassword(string Value, string Origin)
{
    /// <summary>
    /// What a lossy UTF-8 encoder makes of <see cref="Value"/> (every lone surrogate becomes U+FFFD): the
    /// well-formed password a legacy system that hashed <see cref="Value"/> effectively stored.
    /// </summary>
    public string Lossy => Encoding.UTF8.GetString(Encoding.UTF8.GetBytes(Value));

    public override string ToString() => $"{Fixtures.Show(Value)} (from {Fixtures.Show(Origin)})";
}

/// <summary>A legacy seed (by index into <see cref="Fixtures.LegacySeeds"/>) and the edits to apply to it.</summary>
public sealed record LegacyMutation(int SeedIndex, MutationOp[] Ops)
{
    public override string ToString() =>
        $"seed={SeedIndex} ({Fixtures.LegacySeeds[SeedIndex].Format.Id}) ops=[{string.Join(", ", Ops.Select(o => o.ToString()))}]";
}

/// <summary>A candidate unpadded-base64 string, biased towards near-valid encodings.</summary>
public sealed record B64Candidate(string Value)
{
    public override string ToString() => Fixtures.Show(Value);
}

/// <summary>A non-empty byte array.</summary>
public sealed record NonEmptyBytes(byte[] Value)
{
    public override string ToString() => Convert.ToHexString(Value);
}

/// <summary>Random PBKDF2 inputs with small iteration counts.</summary>
public sealed record Pbkdf2Case(HashAlgorithmName Prf, byte[] Password, byte[] Salt, int Iterations, int Length)
{
    public override string ToString() =>
        $"{Prf.Name} pw={Convert.ToHexString(Password)} salt={Convert.ToHexString(Salt)} c={Iterations} dkLen={Length}";
}

/// <summary>A pepper key set K with its current key (null: no pepper), and a superset K' with its current key.</summary>
public sealed record KeyRotation(string[] Original, string? OriginalCurrent, string[] Superset, string SupersetCurrent, string Password)
{
    public override string ToString() =>
        $"K={{{string.Join(",", Original)}}} cur={OriginalCurrent ?? "none"} K'={{{string.Join(",", Superset)}}} cur'={SupersetCurrent} pw={Fixtures.Show(Password)}";
}

/// <summary>FsCheck arbitraries for every wrapper type above.</summary>
public static class Arbitraries
{
    /// <summary>The hasher default for <see cref="PasswordHasherOptions.MaxPasswordBytes"/>.</summary>
    public const int MaxPasswordBytes = 1024;

    /// <summary>Upper bound on generated huge strings (well past every length cap in the library).</summary>
    public const int HugeCap = 70_000;

    private const string B64Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    private const string Structural = "$mh,p=kw.+/=_-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz \t\n\0";

    // Lone surrogates, replacement char, BOM, zero-width, combining marks, ligatures, fullwidth, superscript,
    // Angstrom/Ohm, dotted/dotless i, sharp s, an 18-char NFKC expansion (U+FDFA), Hangul jamo and a syllable.
    // Used one UTF-16 unit at a time, so the astral U+10FC00 also contributes its two halves as lone surrogates.
    // Only for AnyString/AnyPassword: passwords meant to be hashed use WellFormedSpecials instead.
    private const string Specials = "\uD800􏰀\uDFFF�﻿​́̊ﬁＡ²ÅΩİıßﷺ가가";

    /// <summary>
    /// The well-formed counterpart of <see cref="Specials"/>, as whole strings so that astral characters stay paired:
    /// surrogate pairs (U+10000, U+10FC00, U+10FFFD, a musical symbol, an emoji, a ZWJ sequence, a mathematical
    /// letter that NFKC maps to ASCII), U+FFFD, BOM, ZWSP, NUL, combining marks, a decomposed e-acute, ligatures,
    /// fullwidth, superscript, Angstrom/Ohm, dotted/dotless i, sharp s, U+FDFA, Hangul jamo and a syllable.
    /// </summary>
    private static readonly string[] WellFormedSpecials =
    {
        "\U00010000", "\U0010FC00", "\U0010FFFD", "\U0001D11E", "\U0001F600", "\U0001F469\u200D\U0001F4BB", "\U0001D400",
        "\uFFFD", "\uFEFF", "\u200B", "\0", "\u0301", "\u030A", "e\u0301", "\uFB01", "\uFB03", "\uFF21", "\u00B2",
        "\u212B", "\u2126", "\u0130", "\u0131", "\u00DF", "\uFDFA", "\u1100", "\u1161", "\uAC00",
    };

    private static readonly string[] Prefixes =
    {
        "$mh$", "$mh$p=test$", "$mh$p=test,k=key1$", "$mh$p=test,w=v1,wp=", "$2a$", "$2b$04$", "$2y$05$", "$wp$2y$04$",
        "$P$", "$H$9", "pbkdf2_sha256$", "pbkdf2_sha1$1000$", "$argon2id$v=19$m=64,t=1,p=1$", "$argon2i$", "AQAAAA", "AAAA",
        "5f4dcc3b5aa765d61d8327deb882cf99",
    };

    private static readonly string[] Params =
    {
        "p=test", "p=test2", "p=2026f", "p=nope", "p=", "p=TEST", "p=-x", "k=key1", "k=key2", "k=nokey", "k=", "k=key 1",
        "w=v1", "w=md5", "w=nope", "w=", "wp=AA", "wp=AAAA", "wp=A", "wp=", "x=1", "=", "p", "p==test", "k=key1,k=key1",
    };

    private static readonly int[] InterestingLengths = { 0, 1, 2, 15, 16, 17, 31, 32, 33, 48, 64, 65 };

    /// <summary>
    /// U+FFFE is well-formed UTF-16, but string.Normalize throws on it and core lets that escape Hash and Verify
    /// (pinned in <c>NormalizationEdgeCases</c>). Every generator maps it to U+FFFF until core handles it.
    /// </summary>
    private const char NormalizeThrows = '\uFFFE';

    private static char AvoidFFFE(int i) => i == NormalizeThrows ? '\uFFFF' : (char)i;

    private static readonly Gen<char> AnyChar = Gen.Choose(0, 0xFFFF).Select(AvoidFFFE);
    private static readonly Gen<char> StructuralChar = Gen.Elements(Structural.ToCharArray());
    private static readonly Gen<char> SpecialChar = Gen.Elements(Specials.ToCharArray());
    private static readonly Gen<char> B64Char = Gen.Elements(B64Alphabet.ToCharArray());
    private static readonly Gen<char> PrintableAscii = Gen.Choose(0x20, 0x7E).Select(i => (char)i);

    /// <summary>Any BMP code point except the surrogate range D800-DFFF (so always well-formed on its own) and U+FFFE.</summary>
    private static readonly Gen<char> BmpScalar = Gen.Choose(0, 0xFFFF - 0x800).Select(i => AvoidFFFE(i < 0xD800 ? i : i + 0x800));
    private static readonly Gen<string> Astral = Gen.Choose(0x10000, 0x10FFFF).Select(char.ConvertFromUtf32);

    private static readonly Gen<char> NastyChar = Gen.Frequency(
        (6, StructuralChar),
        (2, AnyChar),
        (2, SpecialChar));

    private static Gen<byte[]> BytesOf(int length) => Gen.ArrayOf(Gen.Choose(0, 255).Select(b => (byte)b), length);

    private static Gen<byte[]> BytesUpTo(int max) => Gen.Choose(0, max).SelectMany(BytesOf);

    private static Gen<string> StringOf(Gen<char> chars) => Gen.ArrayOf(chars).Select(a => new string(a));

    private static Gen<string> Concat(Gen<string> pieces) => Gen.ListOf(pieces).Select(l => string.Concat(l));

    private static readonly Gen<string> Piece = Gen.Frequency(
        (12, NastyChar.Select(c => c.ToString())),
        (1, Astral),
        (1, Gen.Elements(Prefixes)),
        (2, StringOf(B64Char)));

    private static readonly Gen<string> B64Field = Gen.Frequency(
        (4, Gen.Elements(InterestingLengths).SelectMany(BytesOf).Select(HashPrimitives.ToB64)),
        (1, StringOf(B64Char)),
        (1, StringOf(NastyChar)));

    /// <summary>Strings shaped like a <c>$mh$</c> hash with random parts, to reach every parser rejection branch.</summary>
    private static readonly Gen<string> MhWild =
        from parameters in Gen.NonEmptyListOf(Gen.Frequency((6, Gen.Elements(Params)), (1, StringOf(StructuralChar)))).Resize(4)
        from salt in B64Field
        from tag in B64Field
        from extra in Gen.Frequency((6, Gen.Constant("")), (1, Gen.Elements("$", "$$", "=", "$AAAA", " ")))
        select "$mh$" + string.Join(",", parameters) + "$" + salt + "$" + tag + extra;

    /// <summary>
    /// Mostly well-formed <c>$mh$</c> strings (valid ids, correct salt/tag lengths), so that the profile allowlist,
    /// the pepper key lookup, the wrap lookup and the KDF itself are reached with random data.
    /// </summary>
    private static readonly Gen<string> MhStructured =
        from profile in Gen.Elements("test", "test2", "nope", "2025a", "TEST", "")
        from key in Gen.Frequency((2, Gen.Constant("")), (1, Gen.Elements(",k=key1", ",k=key2", ",k=nokey", ",k=bad key")))
        from wrap in Gen.Frequency((3, Gen.Constant("")), (1, Gen.Elements(",w=v1,wp=AA", ",w=v1", ",w=md5", ",w=nope,wp=AAAA", ",w=v1,wp=AgAA")))
        from salt in Gen.Frequency((4, BytesOf(16).Select(HashPrimitives.ToB64)), (1, B64Field))
        from tag in Gen.Frequency((4, BytesOf(32).Select(HashPrimitives.ToB64)), (1, B64Field))
        select "$mh$p=" + profile + key + wrap + "$" + salt + "$" + tag;

    private static readonly Gen<string> MhShaped = Gen.Frequency((1, MhWild), (2, MhStructured));

    /// <summary>Long strings, built from a seed so generation stays cheap.</summary>
    private static readonly Gen<string> Huge =
        from length in Gen.Choose(1025, HugeCap)
        from seed in Gen.Choose(0, int.MaxValue)
        from kind in Gen.Choose(0, 5)
        select BuildHuge(kind, length, seed);

    private static string BuildHuge(int kind, int length, int seed)
    {
        var random = new Random(seed);
        switch (kind)
        {
            case 0: return new string('a', length);
            case 1: return new string('$', length);
            case 2: return "$mh$p=test$" + new string('A', length) + "$" + new string('A', 43);
            case 3: return new string('A', length - length % 4);
            case 4:
            {
                var chars = new char[length];
                for (int i = 0; i < length; i++)
                    chars[i] = Structural[random.Next(Structural.Length)];
                return new string(chars);
            }
            default:
            {
                var chars = new char[length];
                for (int i = 0; i < length; i++)
                    chars[i] = AvoidFFFE(random.Next(0x10000));
                return new string(chars);
            }
        }
    }

    private static readonly Gen<string> AnyStringGen = Gen.Frequency(
        (8, Concat(Piece)),
        (4, MhShaped),
        (1, Huge),
        (1, Gen.Constant("")));

    public static Arbitrary<AnyString> AnyStrings() => AnyStringGen.Select(s => new AnyString(s)).ToArbitrary();

    public static Arbitrary<AnyPassword> AnyPasswords() =>
        Gen.Frequency(
                (8, Concat(Piece)),
                (2, StringOf(PrintableAscii)),
                (1, Huge),
                (1, Gen.Constant("")))
            .Select(s => new AnyPassword(s))
            .ToArbitrary();

    // ---- Passwords -------------------------------------------------------------------------------------------

    /// <summary>
    /// One well-formed piece of a password. Every piece is a complete sequence of code points, so any
    /// concatenation of pieces is well-formed UTF-16 too.
    /// </summary>
    private static readonly Gen<string> PasswordPiece = Gen.Frequency(
        (10, PrintableAscii.Select(c => c.ToString())),
        (2, Gen.Elements(WellFormedSpecials)),
        (2, BmpScalar.Select(c => c.ToString())),
        (1, Astral));

    private static bool FitsCap(string password) =>
        password.Length > 0 && Fixtures.IsWellFormedUtf16(password) && HashPrimitives.EncodePassword(password).Length <= MaxPasswordBytes;

    // ASCII, 2/3/4-byte UTF-8, a 3-byte ligature that expands to 3 ASCII bytes, the 18-char U+FDFA expansion,
    // a parenthesized digit, and a decomposed é that NFKC shortens from 3 bytes to 2.
    private static readonly string[] CapUnits = { "a", "é", "€", "𝄞", "ﬃ", "ﷺ", "⑴", "é" };

    private static readonly Gen<string> NearCap =
        from unit in Gen.Elements(CapUnits)
        from slack in Gen.Choose(0, 3)
        let max = MaxPasswordBytes / HashPrimitives.EncodePassword(unit).Length
        select Repeat(unit, Math.Max(1, max - slack));

    private static readonly Gen<string> ValidPasswordGen = Gen.Frequency(
            (4, Gen.NonEmptyListOf(PrintableAscii).Select(l => new string(l.ToArray()))),
            (4, Gen.NonEmptyListOf(PasswordPiece).Select(l => string.Concat(l))),
            (1, NearCap))
        .Where(FitsCap);

    public static Arbitrary<ValidPassword> ValidPasswords() => ValidPasswordGen.Select(s => new ValidPassword(s)).ToArbitrary();

    /// <summary>Repeats of one unit, sized around the cap measured on the raw UTF-8 or on the NFKC form.</summary>
    public static Arbitrary<CapPassword> CapPasswords() =>
        (from unit in Gen.Elements(CapUnits)
         from delta in Gen.Choose(-3, 3)
         from aroundRaw in Gen.Elements(true, false)
         let rawMax = MaxPasswordBytes / Encoding.UTF8.GetByteCount(unit)
         let nfkcMax = MaxPasswordBytes / HashPrimitives.EncodePassword(unit).Length
         select Repeat(unit, Math.Max(1, (aroundRaw ? rawMax : nfkcMax) + delta)))
        .Select(s => new CapPassword(s))
        .ToArbitrary();

    private static string Repeat(string unit, int count)
    {
        var sb = new StringBuilder(unit.Length * count);
        for (int i = 0; i < count; i++)
            sb.Append(unit);
        return sb.ToString();
    }

    /// <summary>
    /// Snippets that differ as strings but are canonically or compatibility equivalent. Well-formed text only: core
    /// rejects lone surrogates outright (see <c>FixedCoreIssues</c>).
    /// </summary>
    private static readonly (string, string)[] EquivalentSnippets =
    {
        ("Å", "Å"), ("Å", "Å"), ("ﬁ", "fi"), ("가", "가"), ("Ａ", "A"),
        ("²", "2"), ("Ω", "Ω"), ("é", "é"), ("\uFDFA", "\uFDFA".Normalize(NormalizationForm.FormKC)),
    };

    /// <summary>The same password with two equivalent snippets inserted at the same place: near-equal pairs.</summary>
    private static readonly Gen<PasswordPair> EquivalentInsertions =
        (from password in ValidPasswordGen
         from snippet in Gen.Elements(EquivalentSnippets)
         from rawPosition in Gen.Choose(0, password.Length)
         from flip in Gen.Elements(true, false)
         let position = Boundary(password, rawPosition)
         select new PasswordPair(
             password.Insert(position, flip ? snippet.Item1 : snippet.Item2),
             password.Insert(position, flip ? snippet.Item2 : snippet.Item1)))
        .Where(p => FitsCap(p.Password));

    public static Arbitrary<PasswordPair> PasswordPairs() =>
        Gen.Frequency(
                (4, from password in ValidPasswordGen
                    from candidate in Gen.Frequency(
                        (4, EditOf(password)),
                        (2, NormalizedFormOf(password)),
                        (1, Gen.Constant(password)),
                        (2, ValidPasswordGen))
                    select new PasswordPair(password, candidate)),
                (1, EquivalentInsertions))
            .ToArbitrary();

    /// <summary>
    /// A single-code-point edit: replace, insert, delete, case toggle or whitespace padding. Positions are snapped to
    /// code-point boundaries, so an edit never splits a surrogate pair and the candidate stays well-formed.
    /// </summary>
    private static Gen<string> EditOf(string password) =>
        from kind in Gen.Choose(0, 5)
        from position in Gen.Choose(0, password.Length)
        from piece in PasswordPiece
        select ApplyEdit(password, kind, position, piece);

    /// <summary>The largest code-point boundary of <paramref name="s"/> that is not after <paramref name="position"/>.</summary>
    private static int Boundary(string s, int position)
    {
        position = Math.Clamp(position, 0, s.Length);
        if (position > 0 && position < s.Length && char.IsLowSurrogate(s[position]) && char.IsHighSurrogate(s[position - 1]))
            position--;
        return position;
    }

    /// <summary>Number of UTF-16 units of the code point that starts at <paramref name="at"/>.</summary>
    private static int CodePointLength(string s, int at) =>
        at + 1 < s.Length && char.IsHighSurrogate(s[at]) && char.IsLowSurrogate(s[at + 1]) ? 2 : 1;

    private static string ApplyEdit(string s, int kind, int position, string piece)
    {
        int at = Boundary(s, Math.Min(position, s.Length - 1));
        int length = CodePointLength(s, at);
        switch (kind)
        {
            case 0: return s.Remove(at, length).Insert(at, piece);
            case 1: return s.Insert(Boundary(s, position), piece);
            case 2: return s.Remove(at, length);
            case 3:
            {
                if (length == 2)
                    return s; // astral: nothing simple to toggle
                char c = s[at];
                char toggled = char.IsUpper(c) ? char.ToLowerInvariant(c) : char.ToUpperInvariant(c);
                return s.Remove(at, 1).Insert(at, toggled.ToString());
            }
            case 4: return s + " ";
            default: return " " + s;
        }
    }

    private static Gen<string> NormalizedFormOf(string password) =>
        Gen.Elements(NormalizationForm.FormC, NormalizationForm.FormD, NormalizationForm.FormKC, NormalizationForm.FormKD)
            .Select(form => TryNormalize(password, form) ?? password);

    private static string? TryNormalize(string value, NormalizationForm form)
    {
        try
        {
            return value.Normalize(form);
        }
        catch (ArgumentException)
        {
            return null;
        }
    }

    // ---- Legacy hashes of arbitrary passwords ----------------------------------------------------------------

    /// <summary>
    /// The region where core's legacy/wrap paths check the raw UTF-8 length but the rehash checks the NFKC length,
    /// so <c>Verify</c> throws (reported in coreChangeRequests; pinned in <c>NormalizationEdgeCases</c>).
    /// </summary>
    public static bool InLegacyRehashLengthGap(string password) =>
        Encoding.UTF8.GetByteCount(password) <= MaxPasswordBytes && HashPrimitives.EncodePassword(password).Length > MaxPasswordBytes;

    /// <summary>
    /// Passwords for legacy round trips: random well-formed text, and repeats sized around the raw and the NFKC cap.
    /// (Ill-formed passwords are rejected before any legacy format runs; see <c>FixedCoreIssues</c>.)
    /// </summary>
    private static readonly Gen<string> LegacyPasswordGen = Gen.Frequency(
        (6, Gen.NonEmptyListOf(PasswordPiece).Select(l => string.Concat(l))),
        (2, Gen.NonEmptyListOf(PrintableAscii).Select(l => new string(l.ToArray()))),
        (2, from unit in Gen.Elements(CapUnits)
            from delta in Gen.Choose(-3, 3)
            from aroundRaw in Gen.Elements(true, false)
            let rawMax = MaxPasswordBytes / Encoding.UTF8.GetByteCount(unit)
            let nfkcMax = MaxPasswordBytes / HashPrimitives.EncodePassword(unit).Length
            select Repeat(unit, Math.Max(1, (aroundRaw ? rawMax : nfkcMax) + delta))));

    private static Gen<LegacyCase> LegacyCaseGen(Gen<string> passwords) =>
        from kind in Gen.Choose(0, Fixtures.LegacyKinds - 1)
        from password in passwords
        from salt in Gen.Frequency((3, BytesOf(16)), (1, BytesUpTo(48)))
        select new LegacyCase(kind, password, salt);

    /// <summary>Legacy cases outside the known core length gap (<see cref="InLegacyRehashLengthGap"/>).</summary>
    public static Arbitrary<LegacyCase> LegacyCases() =>
        LegacyCaseGen(LegacyPasswordGen.Where(p => p.Length > 0 && !InLegacyRehashLengthGap(p))).ToArbitrary();

    /// <summary>Legacy cases inside the known core length gap: a short prefix plus repeated U+FDFA.</summary>
    public static Gen<LegacyCase> LegacyGapCases() =>
        LegacyCaseGen(
            from prefix in Gen.Elements("", "a", "pw-", "\u00E9")
            from count in Gen.Choose(32, 300)
            select prefix + Repeat("\uFDFA", count)).Where(c => InLegacyRehashLengthGap(c.Password));

    // ---- NFKC equivalence ------------------------------------------------------------------------------------

    private static Gen<string> Range(int from, int to) => Gen.Choose(from, to).Select(char.ConvertFromUtf32);

    /// <summary>Code points rich in canonical and compatibility decompositions.</summary>
    private static readonly Gen<string> EquivalencePiece = Gen.Frequency(
        (4, Gen.Elements("a", "e", "i", "o", "u", "A", "E", "n", "c", "K", "s", "1", " ")),
        (3, Range(0x0300, 0x036F)),   // combining diacritical marks
        (3, Range(0x00C0, 0x017F)),   // precomposed Latin
        (1, Range(0x0390, 0x03CE)),   // Greek incl. tonos
        (1, Range(0x1E00, 0x1EFF)),   // Latin Extended Additional
        (2, Range(0xFB00, 0xFB06)),   // Latin ligatures
        (2, Range(0xFF01, 0xFF5E)),   // fullwidth ASCII
        (1, Range(0xFF65, 0xFF9F)),   // halfwidth katakana
        (1, Range(0x2460, 0x2473)),   // circled numbers
        (1, Range(0x2160, 0x217F)),   // roman numerals
        (1, Gen.Elements("²", "³", "¹", "⁰", "ⁱ", "ⁿ", "Å", "Ω", "K", "µ", "ſ", "ﷺ")),
        (2, Range(0xAC00, 0xD7A3)),   // Hangul syllables
        (2, Gen.OneOf(Range(0x1100, 0x1112), Range(0x1161, 0x1175), Range(0x11A8, 0x11C2))), // conjoining jamo
        (1, Range(0xF900, 0xFA2D)),   // CJK compatibility ideographs
        (1, Range(0x1D400, 0x1D6A3)), // mathematical alphanumerics (astral, compatibility to ASCII)
        (1, Range(0x1F600, 0x1F64F)), // emoji (astral, no decomposition)
        (1, Range(0x0E00, 0x0E7F)));  // Thai

    private static bool IsNormalizable(string value) =>
        TryNormalize(value, NormalizationForm.FormC) != null && TryNormalize(value, NormalizationForm.FormKD) != null;

    public static Arbitrary<EquivalentText> EquivalentTexts() =>
        (from text in Gen.NonEmptyListOf(EquivalencePiece).Select(l => string.Concat(l)).Where(t => IsNormalizable(t) && FitsCap(t))
         from variant in Gen.OneOf(WholeForm(text), ChunkedForms(text))
         select new EquivalentText(text, variant))
        .ToArbitrary();

    /// <summary>An <see cref="EquivalentText"/> pair with the same lone surrogate inserted at the same index.</summary>
    public static Arbitrary<IllFormedEquivalent> IllFormedEquivalents() =>
        (from pair in EquivalentTexts().Generator
         from surrogate in Gen.Elements("\uD800", "\uDBFF", "\uDC00", "\uDFFF")
         from atEnd in Gen.Elements(true, false)
         select new IllFormedEquivalent(
             atEnd ? pair.Text + surrogate : surrogate + pair.Text,
             atEnd ? pair.Variant + surrogate : surrogate + pair.Variant))
        .ToArbitrary();

    /// <summary>Short well-formed passwords, so that the ill-formed derivatives stay well under every length cap.</summary>
    private static readonly Gen<string> ShortPassword =
        Gen.NonEmptyListOf(PasswordPiece).Resize(16).Select(l => string.Concat(l)).Where(FitsCap);

    private static readonly Gen<string> LoneSurrogate =
        Gen.Frequency(
                (2, Gen.Elements(0xD800, 0xDBFF, 0xDC00, 0xDFFF)),
                (1, Gen.Choose(0xD800, 0xDFFF)))
            .Select(i => ((char)i).ToString());

    /// <summary>
    /// Ill-formed passwords: a lone surrogate inserted anywhere (between the halves of a pair included), one half of
    /// a pair dropped, or the two halves of a pair swapped.
    /// </summary>
    public static Arbitrary<IllFormedPassword> IllFormedPasswords() =>
        (from origin in ShortPassword
         from kind in Gen.Choose(0, 2)
         from position in Gen.Choose(0, origin.Length)
         from surrogate in LoneSurrogate
         from keepHigh in Gen.Elements(true, false)
         let value = BreakUtf16(origin, kind, position, surrogate, keepHigh)
         where !Fixtures.IsWellFormedUtf16(value)
         select new IllFormedPassword(value, origin))
        .ToArbitrary();

    private static string BreakUtf16(string origin, int kind, int position, string surrogate, bool keepHigh)
    {
        int pair = origin.IndexOf(origin.FirstOrDefault(char.IsHighSurrogate));
        if (kind == 0 || !origin.Any(char.IsHighSurrogate))
            return origin.Insert(position, surrogate);
        if (kind == 1)
            return origin.Remove(keepHigh ? pair + 1 : pair, 1);
        return origin.Substring(0, pair) + origin[pair + 1] + origin[pair] + origin.Substring(pair + 2);
    }

    private static Gen<string> WholeForm(string text) =>
        Gen.Elements(NormalizationForm.FormC, NormalizationForm.FormD, NormalizationForm.FormKC, NormalizationForm.FormKD)
            .Select(form => text.Normalize(form));

    /// <summary>
    /// Splits the text at random code-point boundaries and normalizes each chunk with a random form. Canonical and
    /// compatibility equivalence are preserved by concatenation (UAX #15), so the result is equivalent to the input.
    /// </summary>
    private static Gen<string> ChunkedForms(string text) =>
        from cuts in Gen.ListOf(Gen.Choose(0, text.Length))
        from forms in Gen.ArrayOf(Gen.Elements(NormalizationForm.FormC, NormalizationForm.FormD, NormalizationForm.FormKC, NormalizationForm.FormKD), cuts.Count + 1)
        select Chunk(text, cuts, forms);

    private static string Chunk(string text, IEnumerable<int> cuts, NormalizationForm[] forms)
    {
        var boundaries = cuts
            .Where(c => c > 0 && c < text.Length && !char.IsLowSurrogate(text[c]))
            .Distinct()
            .OrderBy(c => c)
            .ToList();
        boundaries.Add(text.Length);

        var sb = new StringBuilder();
        int start = 0;
        for (int i = 0; i < boundaries.Count; i++)
        {
            string chunk = text.Substring(start, boundaries[i] - start);
            sb.Append(chunk.Normalize(forms[i % forms.Length]));
            start = boundaries[i];
        }
        return sb.ToString();
    }

    // ---- Mutations -------------------------------------------------------------------------------------------

    private const string MutationChars = "$,=.+/_-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz \0é";

    private static readonly Gen<MutationOp> MhOp =
        from kind in Gen.Choose(0, 11)
        from position in Gen.Choose(0, 4096)
        from c in Gen.Elements(MutationChars.ToCharArray())
        from variant in Gen.Choose(0, 31)
        select new MutationOp(kind, position, c, variant);

    private static readonly Gen<MutationOp> GenericOp =
        from kind in Gen.Elements(0, 1, 2, 3, 4, 8, 9)
        from position in Gen.Choose(0, 4096)
        from c in Gen.Elements(MutationChars.ToCharArray())
        from variant in Gen.Choose(0, 31)
        select new MutationOp(kind, position, c, variant);

    public static Arbitrary<MhMutation> MhMutations() =>
        (from baseKind in Gen.Choose(0, 4)
         from password in Gen.NonEmptyListOf(PasswordPiece).Resize(12).Select(l => string.Concat(l)).Where(FitsCap)
         from salt in Gen.Choose(1, 16).SelectMany(BytesOf)
         from count in Gen.Choose(1, 3)
         from ops in Gen.ArrayOf(MhOp, count)
         select new MhMutation(baseKind, password, salt, ops))
        .ToArbitrary();

    public static Arbitrary<LegacyMutation> LegacyMutations() =>
        (from seed in Gen.Choose(0, Fixtures.LegacySeeds.Length - 1)
         from count in Gen.Choose(1, 3)
         from ops in Gen.ArrayOf(GenericOp, count)
         select new LegacyMutation(seed, ops))
        .ToArbitrary();

    // ---- Base64 ----------------------------------------------------------------------------------------------

    public static Arbitrary<NonEmptyBytes> NonEmptyByteArrays() =>
        Gen.Choose(1, 100).SelectMany(BytesOf).Select(b => new NonEmptyBytes(b)).ToArbitrary();

    private static readonly Gen<char> NearB64Char = Gen.Frequency(
        (20, B64Char),
        (1, Gen.Elements('=', ' ', '\n', '\r', '\t', '-', '_', '\0', '.', 'é', 'Ａ', '٠', '\uD800')));

    public static Arbitrary<B64Candidate> B64Candidates() =>
        Gen.Frequency(
                (4, StringOf(B64Char)),
                (3, from bytes in Gen.Choose(1, 40).SelectMany(BytesOf)
                    from last in B64Char
                    let valid = HashPrimitives.ToB64(bytes)
                    select valid.Substring(0, valid.Length - 1) + last),   // flips the unused trailing bits
                (2, StringOf(NearB64Char)),
                (1, from bytes in Gen.Choose(1, 40).SelectMany(BytesOf)
                    from padding in Gen.Elements("=", "==", "===", " ", "\n")
                    select HashPrimitives.ToB64(bytes) + padding),
                (1, Gen.Choose(1, 40).SelectMany(BytesOf).Select(Convert.ToBase64String)), // padded standard base64
                (1, Gen.Constant("")))
            .Select(s => new B64Candidate(s))
            .ToArbitrary();

    // ---- PBKDF2 ----------------------------------------------------------------------------------------------

    public static Arbitrary<Pbkdf2Case> Pbkdf2Cases() =>
        (from prf in Gen.Elements(HashAlgorithmName.SHA1, HashAlgorithmName.SHA256, HashAlgorithmName.SHA512)
         from password in BytesUpTo(200)   // crosses the 64- and 128-byte HMAC block sizes (long keys are hashed first)
         from salt in BytesUpTo(80)
         from iterations in Gen.Choose(1, 40)
         from length in Gen.Choose(1, 200) // crosses output block boundaries for every PRF
         select new Pbkdf2Case(prf, password, salt, iterations, length))
        .ToArbitrary();

    // ---- Pepper rotation -------------------------------------------------------------------------------------

    public static Arbitrary<KeyRotation> KeyRotations() =>
        (from original in Gen.SubListOf(Fixtures.KeyIdPool)
         from extra in Gen.SubListOf(Fixtures.KeyIdPool)
         let superset = original.Union(extra).DefaultIfEmpty("k0").Distinct().ToArray()
         from originalCurrent in original.Count == 0
             ? Gen.Constant<string?>(null)
             : Gen.Elements(original.ToArray()).Select(s => (string?)s)
         from supersetCurrent in Gen.Elements(superset)
         from password in Gen.NonEmptyListOf(PasswordPiece).Resize(16).Select(l => string.Concat(l)).Where(FitsCap)
         select new KeyRotation(original.ToArray(), originalCurrent, superset, supersetCurrent, password))
        .ToArbitrary();
}
