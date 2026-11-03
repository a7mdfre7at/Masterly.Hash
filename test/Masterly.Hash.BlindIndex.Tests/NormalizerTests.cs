using System;
using Masterly.Hash.BlindIndex.Normalizers;

namespace Masterly.Hash.BlindIndex.Tests;

public class NormalizerTests
{
    [Theory]
    [InlineData(" Alice ", " Alice ")]
    [InlineData("Å", "Å")] // Angstrom sign stays as given: Exact does no Unicode normalization
    public void Exact_returns_value_unchanged(string input, string expected)
    {
        Assert.Equal(expected, BlindIndexNormalizers.Exact.Normalize(input));
    }

    [Theory]
    [InlineData("  Alice \t\n", "Alice")]
    [InlineData(" Bob ", "Bob")]
    [InlineData("in side", "in side")]
    public void Trim_strips_unicode_whitespace(string input, string expected)
    {
        Assert.Equal(expected, BlindIndexNormalizers.Trim.Normalize(input));
    }

    [Theory]
    [InlineData("HeLLo", "hello")]
    [InlineData("Ｈｅｌｌｏ", "hello")] // full-width "Hello" (NFKC)
    [InlineData("ﬁle", "file")] // "fi" ligature (NFKC)
    [InlineData("Café", "café")] // combining acute composes (NFKC)
    [InlineData("ÉCOLE", "école")]
    [InlineData(" Spaced ", " spaced ")] // does not trim
    public void CaseInsensitive_applies_nfkc_and_invariant_lower(string input, string expected)
    {
        Assert.Equal(expected, BlindIndexNormalizers.CaseInsensitive.Normalize(input));
    }

    [Fact]
    public void CaseInsensitive_is_culture_independent()
    {
        var previous = System.Globalization.CultureInfo.CurrentCulture;
        try
        {
            System.Globalization.CultureInfo.CurrentCulture = new System.Globalization.CultureInfo("tr-TR");
            Assert.Equal("i", BlindIndexNormalizers.CaseInsensitive.Normalize("I"));
        }
        finally
        {
            System.Globalization.CultureInfo.CurrentCulture = previous;
        }
    }

    [Theory]
    [InlineData("  Alice@Example.COM ", "alice@example.com")]
    [InlineData("alice@example.com.", "alice@example.com")]
    [InlineData("a.b+tag@gmail.com", "a.b+tag@gmail.com")] // provider rewriting is off by default
    [InlineData("a.b@googlemail.com", "a.b@googlemail.com")]
    [InlineData("\"a@b\"@example.com", "\"a@b\"@example.com")] // last '@' splits
    [InlineData("ａ@example.com", "a@example.com")] // full-width 'a'
    public void Email_default(string input, string expected)
    {
        Assert.Equal(expected, BlindIndexNormalizers.Email.Normalize(input));
    }

    [Theory]
    [InlineData("john.doe+news@Example.com", "john.doe@example.com")]
    [InlineData("john.doe+a+b@x.org", "john.doe@x.org")]
    [InlineData("+leading@x.org", "+leading@x.org")] // a local part that is only a tag is kept
    [InlineData("J.Doe+x@gmail.com", "j.doe@gmail.com")] // gmail dots untouched without stripGmailDots
    public void Email_strip_plus_tags(string input, string expected)
    {
        Assert.Equal(expected, new EmailNormalizer(stripPlusTags: true).Normalize(input));
    }

    [Theory]
    [InlineData("J.O.H.N.Doe@gmail.com", "johndoe@gmail.com")]
    [InlineData("john.doe@GoogleMail.com", "johndoe@gmail.com")]
    [InlineData("john.doe@example.com", "john.doe@example.com")] // other domains untouched
    [InlineData("john.doe+tag@gmail.com", "johndoe+tag@gmail.com")] // plus tags untouched without stripPlusTags
    public void Email_strip_gmail_dots(string input, string expected)
    {
        Assert.Equal(expected, new EmailNormalizer(stripGmailDots: true).Normalize(input));
    }

    [Fact]
    public void Email_both_options()
    {
        var normalizer = new EmailNormalizer(stripPlusTags: true, stripGmailDots: true);
        Assert.True(normalizer.StripPlusTags);
        Assert.True(normalizer.StripGmailDots);
        Assert.Equal("johndoe@gmail.com", normalizer.Normalize(" John.Doe+Shopping@GoogleMail.com "));
    }

    [Theory]
    [InlineData("no-at-sign")]
    [InlineData("@example.com")]
    [InlineData("alice@")]
    [InlineData("alice@.")]
    [InlineData("   ")]
    public void Email_invalid_throws_argument_exception(string input)
    {
        Assert.Throws<ArgumentException>(() => BlindIndexNormalizers.Email.Normalize(input));
    }

    [Fact]
    public void Email_gmail_local_of_only_dots_throws()
    {
        Assert.Throws<ArgumentException>(() => new EmailNormalizer(stripGmailDots: true).Normalize("...@gmail.com"));
    }

    [Theory]
    [InlineData("+962 79 123 4567", "962791234567")]
    [InlineData("00962-79-123-4567", "962791234567")]
    [InlineData("(079) 123.4567", "0791234567")]
    [InlineData("٠٧٩١٢٣٤٥٦٧", "0791234567")] // Arabic-Indic digits
    [InlineData("＋９６２ 79", "96279")] // full-width plus and digits (NFKC)
    [InlineData("555-1234 ext. 99", "555123499")]
    [InlineData("no digits", "")]
    public void Phone_digits_only(string input, string expected)
    {
        Assert.Equal(expected, BlindIndexNormalizers.Phone.Normalize(input));
    }

    [Theory]
    [InlineData("079 123 4567", "962791234567")]
    [InlineData("79 123 4567", "962791234567")]
    [InlineData("+962 79 123 4567", "962791234567")]
    [InlineData("00962 79 123 4567", "962791234567")]
    [InlineData("+1 202 555 0100", "12025550100")] // other countries keep their own code
    [InlineData("0", "")]
    public void Phone_with_default_country_code(string input, string expected)
    {
        var normalizer = new PhoneNormalizer("962");
        Assert.Equal("962", normalizer.DefaultCountryCode);
        Assert.Equal(expected, normalizer.Normalize(input));
    }

    [Fact]
    public void Phone_formats_of_same_number_share_an_index()
    {
        BlindIndexer indexer = TestKeys.Single();
        var options = TestKeys.Bits(32, new PhoneNormalizer("962"));
        string a = indexer.Compute("079-123-4567", "users.phone", options);
        Assert.Equal(a, indexer.Compute("+962 (79) 123 4567", "users.phone", options));
        Assert.Equal(a, indexer.Compute("00962791234567", "users.phone", options));
    }

    [Theory]
    [InlineData("+44 (0)20 7946 0958", "442079460958")]
    [InlineData("+44 ( 0 ) 20 7946 0958", "442079460958")]
    [InlineData("+44(0)2079460958", "442079460958")]
    [InlineData("0044 (0)20 7946 0958", "442079460958")]
    [InlineData("+44 20 7946 0958", "442079460958")]
    [InlineData("(0)20 7946 0958", "02079460958")] // national: "(0)" is just the leading digit
    [InlineData("+44 (020) 7946 0958", "4402079460958")] // only a lone zero in parentheses is a trunk group
    [InlineData("+44 (0)20 (0)7946", "442007946")] // only the first group counts
    public void Phone_parenthesised_trunk_zero_is_dropped_from_international_numbers(string input, string expected)
    {
        Assert.Equal(expected, BlindIndexNormalizers.Phone.Normalize(input));
    }

    [Fact]
    public void Phone_parenthesised_trunk_zero_shares_index_with_plain_form()
    {
        BlindIndexer indexer = TestKeys.Single();
        var options = TestKeys.Bits(32, new PhoneNormalizer("44"));
        string a = indexer.Compute("+44 20 7946 0958", "users.phone", options);
        Assert.Equal(a, indexer.Compute("+44 (0)20 7946 0958", "users.phone", options));
        Assert.Equal(a, indexer.Compute("020 7946 0958", "users.phone", options));
        Assert.Equal(a, indexer.Compute("(0)20 7946 0958", "users.phone", options));
    }

    [Fact]
    public void Phone_maps_supplementary_plane_digits()
    {
        // Adlam digits U+1E950..U+1E959 (category Nd, no NFKC decomposition) are surrogate pairs in UTF-16.
        Assert.Equal("12", BlindIndexNormalizers.Phone.Normalize("\U0001E951\U0001E952"));
        Assert.Equal("11", BlindIndexNormalizers.Phone.Normalize("1\U0001E951"));
        Assert.NotEqual(BlindIndexNormalizers.Phone.Normalize("1\U0001E951"), BlindIndexNormalizers.Phone.Normalize("1\U0001E952"));
        Assert.Equal("442079", BlindIndexNormalizers.Phone.Normalize("+44 (\U0001E950)20 79")); // Adlam zero as trunk group
        // Mathematical digits have NFKC mappings to ASCII and keep working.
        Assert.Equal("12", BlindIndexNormalizers.Phone.Normalize("\U0001D7CF\U0001D7D0"));
    }

    [Fact]
    public void Phone_documented_false_negative_country_code_without_plus()
    {
        // Documented limitation: with a default country code, "962 ..." without '+'/'00' reads as national.
        var normalizer = new PhoneNormalizer("962");
        Assert.Equal("962791234567", normalizer.Normalize("+962 79 123 4567"));
        Assert.Equal("962962791234567", normalizer.Normalize("962 79 123 4567"));
    }

    [Theory]
    [InlineData("")]
    [InlineData("0")]
    [InlineData("044")]
    [InlineData("1234")]
    [InlineData("+1")]
    [InlineData("1a")]
    [InlineData("١")] // non-ASCII digit
    public void Phone_invalid_country_code_throws(string code)
    {
        Assert.Throws<ArgumentException>(() => new PhoneNormalizer(code));
    }

    [Fact]
    public void Normalizers_reject_null()
    {
        IBlindIndexNormalizer[] all =
        {
            BlindIndexNormalizers.Exact, BlindIndexNormalizers.Trim, BlindIndexNormalizers.CaseInsensitive,
            BlindIndexNormalizers.Email, BlindIndexNormalizers.Phone,
        };
        foreach (IBlindIndexNormalizer n in all)
            Assert.Throws<ArgumentNullException>(() => n.Normalize(null!));
    }

    [Fact]
    public void Nfkc_normalizers_report_lone_surrogates_as_argument_exception()
    {
        Assert.Throws<ArgumentException>(() => BlindIndexNormalizers.CaseInsensitive.Normalize("x\uD800"));
        Assert.Throws<ArgumentException>(() => BlindIndexNormalizers.Email.Normalize("x\uD800@example.com"));
        Assert.Throws<ArgumentException>(() => BlindIndexNormalizers.Phone.Normalize("1\uD800"));
    }

    [Fact]
    public void Normalizers_are_idempotent()
    {
        var cases = new (IBlindIndexNormalizer Normalizer, string Input)[]
        {
            (BlindIndexNormalizers.CaseInsensitive, "ＨÉllo"),
            (BlindIndexNormalizers.Trim, "  x  "),
            (new EmailNormalizer(true, true), " J.Doe+x@GoogleMail.com. "),
            (BlindIndexNormalizers.Phone, "+962 79 123 4567"),
        };
        foreach (var (normalizer, input) in cases)
        {
            string once = normalizer.Normalize(input);
            Assert.Equal(once, normalizer.Normalize(once));
        }
    }

    [Fact]
    public void Phone_with_country_code_is_meant_for_raw_input_only()
    {
        // Documented: digits-only output has lost the '+', so re-normalizing it treats it as national.
        var normalizer = new PhoneNormalizer("962");
        string once = normalizer.Normalize("079 123 4567");
        Assert.Equal("962791234567", once);
        Assert.Equal(once, normalizer.Normalize("+" + once));
        Assert.NotEqual(once, normalizer.Normalize(once));
    }
}
