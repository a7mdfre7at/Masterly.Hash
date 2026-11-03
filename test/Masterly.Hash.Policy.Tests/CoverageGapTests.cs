using System.Collections.Generic;
using Masterly.Hash.Policy.Internal;

namespace Masterly.Hash.Policy.Tests;

/// <summary>Edge paths not reached by the scenario tests.</summary>
public class CoverageGapTests
{
    // ---------- context words through the public policy ----------

    [Fact]
    public void Reversed_context_word_containing_an_astral_character_is_found()
    {
        // The emoji is a surrogate pair; reversing must keep the pair in order or the reversed word never matches.
        var context = new PasswordContext { UserName = "moon\uD83C\uDF19light" };

        PasswordPolicyResult reversed = Policies.Create().Evaluate("Zz9-thgil\uD83C\uDF19noom-Qq", context);
        Assert.True(reversed.HasViolation(PasswordViolationCode.ContainsContextWord), string.Join("; ", reversed.Violations));

        PasswordPolicyResult unrelated = Policies.Create().Evaluate("Zz9-violet-quartz-tundra-Qq", context);
        Assert.False(unrelated.HasViolation(PasswordViolationCode.ContainsContextWord));
    }

    [Fact]
    public void Email_without_an_at_sign_is_used_as_a_context_word()
    {
        var context = new PasswordContext { Email = "jsmithers" };

        PasswordPolicyResult result = Policies.Create().Evaluate("Tr0ub4dor-jsmithers-9!", context);

        Assert.True(result.HasViolation(PasswordViolationCode.ContainsContextWord));
    }

    [Fact]
    public void Context_word_longer_than_the_password_does_not_match()
    {
        var context = new PasswordContext { UserName = "averyveryverylongusername" };

        PasswordPolicyResult result = Policies.Create().Evaluate("averyvery", context);

        Assert.False(result.HasViolation(PasswordViolationCode.ContainsContextWord));
    }

    // Split on the marks, each word would leave only pieces shorter than MinContextWordLength, so the part is found
    // only if the marks count as word characters. NFKC leaves both words unchanged.
    [Theory]
    [InlineData("\u0915\u093E\u092E\u0928\u093E")]       // U+093E is a spacing combining mark (Mc)
    [InlineData("\u0928\u092E\u0938\u094D\u0924\u0947")] // U+094D and U+0947 are non-spacing marks (Mn)
    public void Combining_marks_are_part_of_a_context_word(string word)
    {
        Assert.Equal(word, word.Normalize(System.Text.NormalizationForm.FormKC));
        var context = new PasswordContext { DisplayName = "Raj " + word };

        PasswordPolicyResult result = Policies.Create().Evaluate("Blue-" + word + "-Horse-42", context);

        Assert.True(result.HasViolation(PasswordViolationCode.ContainsContextWord));
    }

    // ---------- internals ----------

    // Lone surrogates cannot go through [InlineData]: attribute strings are stored as UTF-8 and would be mangled.
    [Fact]
    public void TextUtil_Reverse_keeps_surrogate_pairs()
    {
        Assert.Equal("b\uD83D\uDE00a", TextUtil.Reverse("a\uD83D\uDE00b")); // pair kept in order
        Assert.Equal("\uD83Dba", TextUtil.Reverse("ab\uD83D"));             // lone high surrogate at the end
        Assert.Equal("x\uD83D", TextUtil.Reverse("\uD83Dx"));               // high surrogate not followed by a low one
        Assert.Equal("\uD83D\uDE00", TextUtil.Reverse("\uDE00\uD83D"));     // low then high: two lone surrogates
        Assert.Equal("", TextUtil.Reverse(""));
    }

    [Fact]
    public void Unknown_pattern_kind_is_estimated_as_bruteforce()
    {
        double unknown = Scoring.EstimateGuesses(new Match((PatternKind)999, 0, 3, "kx7q"), "kx7q", Policies.ReferenceYear);
        double bruteforce = Scoring.EstimateGuesses(new Match(PatternKind.Bruteforce, 0, 3, "kx7q"), "kx7q", Policies.ReferenceYear);

        Assert.Equal(bruteforce, unknown);
        Assert.Equal(10_000, unknown); // 10^4 for a four-character token
    }

    [Fact]
    public void Factorial_saturates_at_double_max_value()
    {
        Assert.Equal(1, Scoring.Factorial(0));
        Assert.Equal(120, Scoring.Factorial(5));
        Assert.True(double.IsFinite(Scoring.Factorial(170)));
        Assert.Equal(double.MaxValue, Scoring.Factorial(171));
        Assert.Equal(double.MaxValue, Scoring.Factorial(1000));
    }

    [Theory]
    [InlineData(1, "Straight rows of keys are easy to guess.")]
    [InlineData(3, "Short keyboard patterns are easy to guess.")]
    public void Feedback_uses_the_longest_match_even_when_it_is_not_first(int turns, string warning)
    {
        var sequence = new List<Match>
        {
            new(PatternKind.Bruteforce, 0, 1, "k9"),
            new(PatternKind.Spatial, 2, 7, "qwerty") { Turns = turns, Graph = "qwerty" },
            new(PatternKind.Bruteforce, 8, 8, "x"),
        };

        (string actualWarning, List<string> suggestions) = Feedback.Get(0, sequence);

        Assert.Equal(warning, actualWarning);
        Assert.Contains("Use a longer keyboard pattern with more turns, or better, a few words.", suggestions);
    }
}
