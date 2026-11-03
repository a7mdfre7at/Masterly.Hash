using System;
using System.Linq;
using System.Reflection;
using System.Text.Json;
using Masterly.Hash.Policy.Internal;

namespace Masterly.Hash.Policy.Tests;

/// <summary>What a result reveals about the password beyond its text.</summary>
public class EstimatePrivacyTests
{
    private const int Year = Policies.ReferenceYear;

    [Fact]
    public void Patterns_expose_no_guess_counts()
    {
        Assert.Null(typeof(PatternMatch).GetProperty("Guesses", BindingFlags.Public | BindingFlags.Instance));
        Assert.All(typeof(PatternMatch).GetProperties(BindingFlags.Public | BindingFlags.Instance),
            p => Assert.NotEqual(typeof(double), p.PropertyType));
    }

    [Theory]
    [InlineData("dragonfly-violet-quartz")]
    [InlineData("michael2025-orbit-cactus")]
    [InlineData("password")]
    [InlineData("violet")]
    [InlineData("gx7#Lq2!vZ9pRm4w")]
    public void Guesses_and_crack_times_are_rounded_to_a_tenth_of_a_decade(string password)
    {
        StrengthEstimate e = PasswordStrengthEstimator.Estimate(password, null, Year);

        double tenths = e.GuessesLog10 * 10;
        Assert.Equal(Math.Round(tenths), tenths, 9);
        Assert.Equal(Math.Pow(10, e.GuessesLog10), e.Guesses, 6);
        Assert.Equal(e.Guesses / CrackTimeEstimates.OfflineSlowHashRate, e.CrackTimes.OfflineSlowHash.Seconds, 6);
    }

    [Fact]
    public void Neighbouring_list_entries_give_identical_serialized_results()
    {
        // "violet" and "hobbit" are entries 1653 and 1652 of the SecLists list. With exact per-pattern guesses the
        // serialized result named the entry; now the two passwords must be indistinguishable from the result.
        PasswordPolicy policy = Policies.Create();
        PasswordPolicyResult a = policy.Evaluate("dragonfly-violet-quartz");
        PasswordPolicyResult b = policy.Evaluate("dragonfly-hobbit-quartz");

        string jsonA = JsonSerializer.Serialize(a);
        Assert.Equal(jsonA, JsonSerializer.Serialize(b));
        Assert.DoesNotContain("1653", jsonA);
        Assert.DoesNotContain("5286", jsonA); // rank of "quartz"
    }

    [Fact]
    public void A_single_list_entry_is_not_given_away_exactly()
    {
        // Entries 1652 and 1653: the guess count of the bare word must not tell them apart.
        Assert.Equal(
            JsonSerializer.Serialize(PasswordStrengthEstimator.Estimate("hobbit", null, Year)),
            JsonSerializer.Serialize(PasswordStrengthEstimator.Estimate("violet", null, Year)));
    }

    [Fact]
    public void Scores_still_use_the_exact_estimate()
    {
        // Rounding is for display only; the 0-4 thresholds are applied before it.
        foreach (string password in new[] { "password", "violet-quartz", "violet-quartz-tundra-mosaic" })
        {
            StrengthEstimate e = PasswordStrengthEstimator.Estimate(password, null, Year);
            Assert.True(e.Score >= Scoring.GuessesToScore(e.Guesses), password);
        }
    }
}

/// <summary>l33t in the context words themselves.</summary>
public class ContextWordL33tTests
{
    [Theory]
    [InlineData("johndoe-violet-quartz-tundra", "j0hnd03")]
    [InlineData("johnsmith-likes-tea-a-lot", "j0hnsm1th")]
    [InlineData("htimsnhoj-likes-tea-a-lot", "j0hnsm1th")]   // reversed
    [InlineData("j0hnsm1th-likes-tea-a-lot", "j0hnsm1th")]
    [InlineData("johnsm!th-likes-tea-a-lot", "j0hnsm1th")]   // '!' and '1' both stand for 'i'
    [InlineData("orbit-xxsniperxx-cactus-lamp", "xXsn1p3rXx")]
    public void A_l33t_context_word_blocks_its_plain_form(string password, string userName)
    {
        PasswordPolicyResult result = Policies.Create().Evaluate(password, new PasswordContext { UserName = userName });

        Assert.True(result.HasViolation(PasswordViolationCode.ContainsContextWord), result.ToString());
        Assert.False(result.IsAcceptable);
    }

    [Fact]
    public void A_l33t_context_word_lowers_the_estimate_of_its_plain_form()
    {
        StrengthEstimate without = PasswordStrengthEstimator.Estimate("kxqvbzrt", null, Policies.ReferenceYear);
        StrengthEstimate with = PasswordStrengthEstimator.Estimate("kxqvbzrt", new[] { "kxqvb2rt" }, Policies.ReferenceYear);

        Assert.True(with.Guesses < without.Guesses);
        Assert.Equal(DictionaryKind.ContextWords, Assert.Single(with.Sequence).Dictionary);
    }

    [Fact]
    public void Unrelated_words_are_still_fine()
    {
        PasswordPolicyResult result = Policies.Create().Evaluate("violet-quartz-tundra-mosaic", new PasswordContext { UserName = "j0hnd03" });
        Assert.True(result.IsAcceptable, string.Join("; ", result.Violations));
    }

    [Theory]
    [InlineData('1', 'l', true)]
    [InlineData('1', '|', true)]   // both can be 'i' or 'l'
    [InlineData('1', '!', true)]   // both can be 'i'
    [InlineData('0', 'o', true)]
    [InlineData('o', '0', true)]
    [InlineData('4', '@', true)]
    [InlineData('7', '+', true)]   // both can be 't'
    [InlineData('0', '1', false)]
    [InlineData('a', 'b', false)]
    public void Character_equivalence_is_symmetric(char a, char b, bool expected)
    {
        Assert.Equal(expected, L33t.CharsEquivalent(a, b));
        Assert.Equal(expected, L33t.CharsEquivalent(b, a));
    }
}

/// <summary>The repetitive/sequential rule at every length and period count.</summary>
public class RepetitionRuleTests
{
    private static string Repeat(string unit, int count) => string.Concat(Enumerable.Repeat(unit, count));

    public static TheoryData<string> OddAndPartialPeriods => new()
    {
        "zzkzzkzzkzzkzzk",       // 5 periods
        Repeat("aab", 7),
        Repeat("aab", 11),
        "aabaabaabaabaab",
        Repeat("aab", 6) + "aa",  // partial last period
        Repeat("abcd", 4) + "ab",
        Repeat("xxyxxy", 3) + "xx",
    };

    [Theory]
    [MemberData(nameof(OddAndPartialPeriods))]
    public void Odd_and_partial_period_counts_are_repetitive(string password)
    {
        PasswordPolicyResult result = Policies.Create(o => o.MinimumScore = 0).Evaluate(password);

        Assert.True(result.HasViolation(PasswordViolationCode.RepetitiveOrSequential), result.ToString());
        Assert.False(result.IsAcceptable);
    }

    [Theory]
    [InlineData(101)]
    [InlineData(102)]
    [InlineData(110)]
    [InlineData(120)]
    [InlineData(128)]
    public void Long_repetitive_passwords_are_rejected(int length)
    {
        foreach (string unit in new[] { "abcdefghij", "aab", "a", "qwerty", "Xk9" })
        {
            string password = Repeat(unit, length / unit.Length + 1).Substring(0, length);
            PasswordPolicyResult reportOnly = Policies.Create(o => o.MinimumScore = 0).Evaluate(password);
            PasswordPolicyResult strict = Policies.Create().Evaluate(password);

            Assert.True(reportOnly.HasViolation(PasswordViolationCode.RepetitiveOrSequential), $"{unit} x {length}");
            Assert.False(strict.IsAcceptable, $"{unit} x {length}");
        }
    }

    [Fact]
    public void A_long_repeat_cut_mid_period_is_still_too_weak()
    {
        // "aab" x 34 is 102 characters; the estimator sees 100 of them, cut inside a period.
        PasswordPolicyResult result = Policies.Create().Evaluate(Repeat("aab", 34));

        Assert.False(result.IsAcceptable);
        Assert.True(result.HasViolation(PasswordViolationCode.TooWeak), result.ToString());
        Assert.True(result.StrengthEstimate.IsTruncated);
        Assert.True(result.Score <= 2);
    }

    [Fact]
    public void Truncating_a_periodic_password_mid_period_adds_no_guesses()
    {
        StrengthEstimate full = PasswordStrengthEstimator.Estimate(Repeat("aab", 33), null, Policies.ReferenceYear);
        StrengthEstimate cut = PasswordStrengthEstimator.Estimate(Repeat("aab", 34), null, Policies.ReferenceYear);

        Assert.True(cut.IsTruncated);
        Assert.Equal(full.Guesses, cut.Guesses);
        Assert.Equal(PatternKind.Repeat, Assert.Single(cut.Sequence).Pattern);
    }

    [Theory]
    [InlineData("Xk9#mQ2$vL7!Xk9#mQ2$vL7!")]
    [InlineData("gx7#Lq2!vZ9pgx7#Lq2!vZ9p")]
    public void A_strong_token_typed_twice_is_not_called_repetitive(string password)
    {
        PasswordPolicyResult result = Policies.Create().Evaluate(password);

        Assert.False(result.HasViolation(PasswordViolationCode.RepetitiveOrSequential), result.ToString());
    }

    [Theory]
    [InlineData("abcdabcdabcdabcd")]   // weak unit: a sequence
    [InlineData("qwerqwerqwerqwer")]   // weak unit: a keyboard run
    [InlineData("1234abcd1234abcd")]
    [InlineData("aaaabbbbccccdddd")]
    public void Repeats_of_patterned_units_are_repetitive(string password)
    {
        Assert.True(Policies.Create().Evaluate(password).HasViolation(PasswordViolationCode.RepetitiveOrSequential));
    }

    [Fact]
    public void Smallest_period_allows_a_partial_last_period()
    {
        Assert.Equal(3, RepetitionCheck.SmallestPeriod("zzkzzkzzkzzkzzk"));
        Assert.Equal(3, RepetitionCheck.SmallestPeriod("aabaabaa"));
        Assert.Equal(1, RepetitionCheck.SmallestPeriod("aaaa"));
        Assert.Equal(5, RepetitionCheck.SmallestPeriod("abcde"));
        Assert.Equal(0, RepetitionCheck.SmallestPeriod(string.Empty));
    }

    [Fact]
    public void Degenerate_inputs_do_not_throw()
    {
        Assert.False(RepetitionCheck.IsRepetitiveOrSequential(string.Empty));
        Assert.False(RepetitionCheck.IsRepetitiveOrSequential("a"));
        Assert.True(RepetitionCheck.IsRepetitiveOrSequential("aa"));
        Assert.True(RepetitionCheck.IsRepetitiveOrSequential("🦊🦊🦊🦊"));
        Assert.False(RepetitionCheck.IsRepetitiveOrSequential("\uD800x\uDC00y"));
    }

    [Fact]
    public void Long_adversarial_input_is_checked_quickly()
    {
        // MaxLength 4096 lets the rule run on 4096 characters; a small alphabet makes repeats appear everywhere.
        var random = new Random(4096);
        PasswordPolicy policy = Policies.Create(o => o.MaxLength = PasswordPolicyOptions.MaximumAllowedMaxLength);
        var sw = System.Diagnostics.Stopwatch.StartNew();
        foreach (string alphabet in new[] { "ab", "abc", "aab", "0123456789" })
        {
            char[] chars = new char[4096];
            for (int k = 0; k < chars.Length; k++)
                chars[k] = alphabet[random.Next(alphabet.Length)];
            policy.Evaluate(new string(chars));
        }
        policy.Evaluate(Repeat("Xk9#mQ2$vL7!wE5^", 256));
        policy.Evaluate(new string('a', 4096));
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(5), sw.Elapsed.ToString());
    }
}

public class RepeatMatchExtensionTests
{
    private static readonly Matching Matcher = new(Array.Empty<RankedDictionary>(), Policies.ReferenceYear);

    [Theory]
    [InlineData("zzkzzkzzkzzkzzk", "zzk", 5)]
    [InlineData("aabaabaabaabaab", "aab", 5)]
    [InlineData("abcabcab", "abc", 2)]   // partial last period joins the repeat
    [InlineData("aaaaaaa", "a", 7)]
    public void Repeats_run_through_odd_and_partial_periods(string password, string baseToken, int repeatCount)
    {
        Match m = Assert.Single(Matcher.RepeatMatch(password));
        Assert.Equal((0, password.Length - 1), (m.I, m.J));
        Assert.Equal(baseToken, m.BaseToken);
        Assert.Equal(repeatCount, m.RepeatCount);
    }
}
