using System;
using System.Text;
using FsCheck.Xunit;
using Masterly.Hash.Primitives;
using Masterly.Hash.PropertyTests.Support;

namespace Masterly.Hash.PropertyTests;

/// <summary>
/// Hash/Verify round trips: a password always verifies against its own hash, and another password verifies
/// exactly when it is the same password after NFKC normalization (NIST SP 800-63B §5.1.1.2). The oracle is
/// .NET's normalizer plus ordinal comparison, never the core encoder under test.
/// </summary>
[Properties(Arbitrary = new[] { typeof(Arbitraries) }, QuietOnSuccess = true)]
public class RoundTripProperties
{
    private static readonly PasswordHasher Hasher = Fixtures.Plain;

    [Property(MaxTest = 1000)]
    public void A_password_verifies_against_its_own_hash(ValidPassword password)
    {
        string hash = Hasher.Hash(password.Value);
        Assert.StartsWith("$mh$p=test$", hash, StringComparison.Ordinal);

        PasswordVerificationResult result = Hasher.Verify(password.Value, hash);
        Assert.Equal(VerificationStatus.Success, result.Status);
        Assert.Null(result.Rehash);

        HashInfo info = Hasher.Inspect(hash);
        Assert.True(info.IsRecognized);
        Assert.False(info.NeedsRehash);
        Assert.Equal("test", info.ProfileId);

        // Fresh random salt every time: the same password never produces the same string.
        Assert.NotEqual(hash, Hasher.Hash(password.Value));
    }

    [Property(MaxTest = 1500)]
    public void Another_password_verifies_iff_it_is_the_same_password_after_NFKC(PasswordPair pair)
    {
        string context = pair.ToString();
        string hash = Hasher.Hash(pair.Password);
        PasswordVerificationResult result = Hasher.Verify(pair.Candidate, hash);
        Assertions.Consistent(result, context);

        if (pair.Candidate.Length == 0)
        {
            Assert.Equal(VerificationFailureReason.EmptyPassword, result.FailureReason);
            return;
        }

        // The generator only produces well-formed pairs; ill-formed passwords are rejected outright (FixedCoreIssues).
        Assert.True(Fixtures.IsWellFormedUtf16(pair.Password) && Fixtures.IsWellFormedUtf16(pair.Candidate), context);

        // Independent oracle: string.Normalize(FormKC) + ordinal equality, and the NFKC UTF-8 length rule.
        if (Fixtures.NfkcByteCount(pair.Candidate) > Arbitraries.MaxPasswordBytes)
            Assert.Equal(VerificationFailureReason.PasswordTooLong, result.FailureReason);
        else if (Fixtures.NfkcEqual(pair.Password, pair.Candidate))
            Assert.True(result.IsMatch, context);
        else
            Assert.Equal(VerificationFailureReason.Mismatch, result.FailureReason);

        // Secondary check only: the hasher agrees with its own public encoding primitive.
        bool encodable = HashPrimitives.EncodePassword(pair.Candidate).Length <= Arbitraries.MaxPasswordBytes;
        Assert.Equal(encodable && Fixtures.SameEncoding(pair.Password, pair.Candidate), result.IsMatch);
    }

    /// <summary>
    /// No truncation anywhere (bcrypt-style 72-byte cut-offs, prefix hashing): passwords that differ only in their
    /// last character never verify, at every length up to the cap and for 1- to 4-byte UTF-8 characters.
    /// </summary>
    [Theory]
    [InlineData("a", 1)]
    [InlineData("a", 72)]
    [InlineData("a", 73)]
    [InlineData("a", 80)]
    [InlineData("a", 128)]
    [InlineData("a", 129)]
    [InlineData("a", 512)]
    [InlineData("a", 1023)]
    [InlineData("é", 511)]
    [InlineData("€", 340)]
    [InlineData("𝄞", 255)]
    public void Long_passwords_differing_only_in_the_last_character_do_not_verify(string unit, int count)
    {
        var sb = new StringBuilder();
        for (int i = 0; i < count; i++)
            sb.Append(unit);
        string password = sb.ToString() + "x";
        string other = sb.ToString() + "y";
        Assert.True(Encoding.UTF8.GetByteCount(password) <= Arbitraries.MaxPasswordBytes);

        string hash = Hasher.Hash(password);
        Assert.True(Hasher.Verify(password, hash).IsMatch);
        Assert.Equal(VerificationFailureReason.Mismatch, Hasher.Verify(other, hash).FailureReason);
        Assert.Equal(VerificationFailureReason.Mismatch, Hasher.Verify(sb.ToString(), hash).FailureReason);
    }

    [Property(MaxTest = 300)]
    public void The_length_cap_applies_to_the_NFKC_encoding(CapPassword password)
    {
        int bytes = HashPrimitives.EncodePassword(password.Value).Length;
        string reference = Hasher.Hash("reference");
        if (bytes <= Arbitraries.MaxPasswordBytes)
        {
            string hash = Hasher.Hash(password.Value);
            Assert.True(Hasher.Verify(password.Value, hash).IsMatch);
            Assert.Equal(VerificationFailureReason.Mismatch, Hasher.Verify(password.Value, reference).FailureReason);
        }
        else
        {
            Assert.Throws<ArgumentException>(() => Hasher.Hash(password.Value));
            Assert.Equal(VerificationFailureReason.PasswordTooLong, Hasher.Verify(password.Value, reference).FailureReason);
        }
    }

    [Property(MaxTest = 1000)]
    public void Canonically_and_compatibly_equivalent_text_verifies_both_ways(EquivalentText text)
    {
        // First the oracle: .NET's normalizer agrees the two are equivalent...
        Assert.True(Fixtures.NfkcEqual(text.Text, text.Variant), text.ToString());

        // ...then the hasher honours it in both directions.
        Assert.True(Hasher.Verify(text.Variant, Hasher.Hash(text.Text)).IsMatch, text.ToString());
        Assert.True(Hasher.Verify(text.Text, Hasher.Hash(text.Variant)).IsMatch, text.ToString());
    }

    /// <summary>Equivalences from Unicode Standard Annex #15 (Unicode Normalization Forms), Figures 1-6 and §1.2.</summary>
    [Theory]
    [InlineData("Å", "Å")]           // Å precomposed vs A + combining ring (canonical)
    [InlineData("Å", "Å")]            // ANGSTROM SIGN vs Å (canonical singleton)
    [InlineData("Ω", "Ω")]            // OHM SIGN vs GREEK CAPITAL OMEGA (canonical singleton)
    [InlineData("ô", "ô")]           // ô vs o + combining circumflex
    [InlineData("ṩ", "ṩ")]     // ṩ vs s + dot below + dot above (reordering)
    [InlineData("ḍ̇", "ḍ̇")]// ḍ̇ vs ḍ̇ (canonical reordering)
    [InlineData("가", "가")]      // Hangul syllable GA vs conjoining jamo
    [InlineData("ﬁ", "fi")]                // ﬁ ligature (compatibility)
    [InlineData("2⁵", "25")]               // superscript five (compatibility)
    [InlineData("ẛ̣", "ṩ")]      // ẛ̣ → NFKC ṩ (UAX #15 Figure 6)
    [InlineData("ℌ", "H")]                 // BLACK-LETTER CAPITAL H (font variant)
    [InlineData("ﾀ", "タ")]            // halfwidth katakana TA vs TA
    [InlineData("Ａｂｃ", "Abc")]   // fullwidth Latin
    [InlineData("①", "1")]                 // CIRCLED DIGIT ONE
    public void Known_equivalent_pairs_verify(string a, string b)
    {
        Assert.True(Hasher.Verify(b, Hasher.Hash(a)).IsMatch);
        Assert.True(Hasher.Verify(a, Hasher.Hash(b)).IsMatch);
    }

    /// <summary>NFKC does not case-fold or strip: these stay distinct.</summary>
    [Theory]
    [InlineData("a", "A")]
    [InlineData("ß", "ss")]      // ß is not compatibility-equivalent to ss (that is case folding)
    [InlineData("i", "ı")]       // dotless i
    [InlineData("İ", "I")]       // dotted capital I
    [InlineData("ﬁ", "f")]
    [InlineData("pass", "pass ")]
    [InlineData("pass", "pass​")] // zero-width space is not removed by NFKC
    [InlineData("é", "e")]
    public void Known_distinct_pairs_do_not_verify(string a, string b)
    {
        Assert.False(Hasher.Verify(b, Hasher.Hash(a)).IsMatch);
        Assert.False(Hasher.Verify(a, Hasher.Hash(b)).IsMatch);
    }

    [Fact]
    public void Empty_passwords_cannot_be_hashed_and_never_match()
    {
        Assert.Throws<ArgumentException>(() => Hasher.Hash(""));
        Assert.Equal(VerificationFailureReason.EmptyPassword, Hasher.Verify("", Hasher.Hash("x")).FailureReason);
    }
}
