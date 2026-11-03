using System;
using System.Linq;
using System.Text;
using Masterly.Hash.Policy.Internal;

namespace Masterly.Hash.Policy.Tests;

public class StrengthEstimatorTests
{
    private const int Year = Policies.ReferenceYear;

    private static StrengthEstimate Estimate(string password, params string[] userInputs) =>
        PasswordStrengthEstimator.Estimate(password, userInputs, Year);

    [Theory]
    [InlineData("password", 0)]
    [InlineData("123456", 0)]
    [InlineData("qwerty", 0)]
    [InlineData("aaaaaaaaaaaaaaaaaaaa", 0)]
    [InlineData("abcabcabcabcabc", 0)]
    [InlineData("gx7#Lq2!vZ9pRm4w", 4)]
    [InlineData("violet-quartz-tundra-mosaic", 4)]
    public void Clear_cut_scores(string password, int expected) => Assert.Equal(expected, Estimate(password).Score);

    [Fact]
    public void Random_strings_get_more_guesses_as_they_get_longer()
    {
        var random = new Random(20261102);
        const string alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#%&*+-=?@^_~";
        var sb = new StringBuilder();
        double previous = 0;
        for (int length = 1; length <= 40; length++)
        {
            sb.Append(alphabet[random.Next(alphabet.Length)]);
            double guesses = Estimate(sb.ToString()).Guesses;
            // Appending can reveal a pattern, so allow a small dip, but the trend must be up.
            Assert.True(guesses >= previous / 100, $"length {length}: {guesses} < {previous}");
            previous = Math.Max(previous, guesses);
        }
        Assert.True(Estimate(sb.ToString()).GuessesLog10 > 30);
    }

    [Fact]
    public void More_words_mean_more_guesses()
    {
        string[] words = { "violet", "quartz", "tundra", "mosaic", "lantern", "orbit" };
        double previous = 0;
        for (int n = 1; n <= words.Length; n++)
        {
            double guesses = Estimate(string.Join("-", words.Take(n))).Guesses;
            Assert.True(guesses > previous, $"{n} words");
            previous = guesses;
        }
    }

    [Fact]
    public void More_repeats_mean_more_guesses_but_not_many_more()
    {
        double three = Estimate("aaa").Guesses;
        double six = Estimate("aaaaaa").Guesses;
        double twelve = Estimate("aaaaaaaaaaaa").Guesses;
        Assert.True(three < six && six < twelve);
        Assert.True(twelve < 1000);
    }

    [Fact]
    public void Patterns_are_weaker_than_random_text_of_the_same_length()
    {
        foreach (string pattern in new[] { "abcdefgh", "qwertyui", "11111111", "19911991", "password", "drowssap", "p4ssw0rd" })
            Assert.True(Estimate(pattern).Guesses < Estimate("k9#vR2pq").Guesses, pattern);
    }

    [Fact]
    public void Variations_cost_a_little_more_than_the_plain_word()
    {
        double plain = Estimate("sunshine").Guesses;
        Assert.True(Estimate("Sunshine").Guesses > plain);
        Assert.True(Estimate("SUNSHINE").Guesses > plain);
        Assert.True(Estimate("sUnShInE").Guesses > Estimate("Sunshine").Guesses);
        Assert.True(Estimate("5unsh1ne").Guesses > plain);
        Assert.True(Estimate("enihsnus").Guesses > plain);
    }

    [Fact]
    public void User_inputs_make_their_words_cheap()
    {
        double without = Estimate("kxqvbzrt").Guesses;
        double with = Estimate("kxqvbzrt", "kxqvbzrt").Guesses;
        Assert.True(with < without);
        Assert.True(with <= 2);

        StrengthEstimate e = Estimate("kxqvbzrt", "KXQVBZRT", "", null!, "   ");
        Assert.Equal(DictionaryKind.ContextWords, Assert.Single(e.Sequence).Dictionary);
        Assert.Equal("Words related to you or this service are easy to guess.", e.Warning);
    }

    [Fact]
    public void Years_are_scored_relative_to_the_reference_year()
    {
        double near = PasswordStrengthEstimator.Estimate("1990", null, 1995).Guesses;
        double far = PasswordStrengthEstimator.Estimate("1990", null, 2090).Guesses;
        Assert.True(near < far);
    }

    [Fact]
    public void Sequence_covers_the_password_left_to_right()
    {
        foreach (string password in new[] { "violet-quartz-tundra-mosaic", "p4ssw0rd1991qwerty", "aaaabcdxyz", "a", "🦊🦊🦊" })
        {
            StrengthEstimate e = Estimate(password);
            int next = 0;
            foreach (PatternMatch m in e.Sequence)
            {
                Assert.Equal(next, m.StartIndex);
                Assert.True(m.Length > 0);
                next += m.Length;
            }
            Assert.Equal(password.Normalize(NormalizationForm.FormKC).Length, next);
        }
    }

    [Fact]
    public void Pattern_details_are_exposed()
    {
        PatternMatch reversed = Assert.Single(Estimate("drowssap").Sequence);
        Assert.Equal(PatternKind.Dictionary, reversed.Pattern);
        Assert.Equal(DictionaryKind.CommonPasswords, reversed.Dictionary);
        Assert.True(reversed.IsReversed);
        Assert.False(reversed.IsL33t);

        PatternMatch l33t = Assert.Single(Estimate("p4ssw0rd").Sequence);
        Assert.True(l33t.IsL33t);

        Assert.Equal(PatternKind.Spatial, Assert.Single(Estimate("zxcvbnm,./").Sequence).Pattern);
        Assert.Equal(PatternKind.Date, Assert.Single(Estimate("11/20/1991").Sequence).Pattern);
        PatternMatch bruteforce = Assert.Single(Estimate("kxqvbzrt").Sequence);
        Assert.Equal(PatternKind.Bruteforce, bruteforce.Pattern);
        Assert.Equal(DictionaryKind.None, bruteforce.Dictionary);
    }

    [Fact]
    public void Crack_times_follow_the_four_scenarios()
    {
        StrengthEstimate e = Estimate("violet-quartz");
        double g = e.Guesses;

        Assert.Equal(g / (100.0 / 3600.0), e.CrackTimes.OnlineThrottled.Seconds, 6);
        Assert.Equal(g / 10, e.CrackTimes.OnlineUnthrottled.Seconds, 6);
        Assert.Equal(g / 1e4, e.CrackTimes.OfflineSlowHash.Seconds, 6);
        Assert.Equal(g / 1e10, e.CrackTimes.OfflineFastHash.Seconds, 6);
        Assert.Equal(1e4, e.CrackTimes.OfflineSlowHash.GuessesPerSecond);
        Assert.True(e.CrackTimes.OnlineThrottled.Seconds > e.CrackTimes.OnlineUnthrottled.Seconds);
        Assert.True(e.CrackTimes.OfflineSlowHash.Seconds > e.CrackTimes.OfflineFastHash.Seconds);

        StrengthEstimate weak = Estimate("password");
        Assert.Equal("less than a second", weak.CrackTimes.OfflineFastHash.Display);
        Assert.Equal("less than a second", weak.CrackTimes.OfflineFastHash.ToString());
        Assert.Equal("centuries", Estimate("gx7#Lq2!vZ9pRm4wT8kq").CrackTimes.OfflineSlowHash.Display);
    }

    [Theory]
    [InlineData(0, "less than a second")]
    [InlineData(0.999, "less than a second")]
    [InlineData(1, "1 second")]
    [InlineData(1.5, "2 seconds")]
    [InlineData(59, "59 seconds")]
    [InlineData(60, "1 minute")]
    [InlineData(150, "3 minutes")]
    [InlineData(3600, "1 hour")]
    [InlineData(5 * 3600, "5 hours")]
    [InlineData(86400, "1 day")]
    [InlineData(2 * 86400, "2 days")]
    [InlineData(31 * 86400, "1 month")]
    [InlineData(3 * 31 * 86400, "3 months")]
    [InlineData(12 * 31 * 86400.0, "1 year")]
    [InlineData(50 * 12 * 31 * 86400.0, "50 years")]
    [InlineData(100 * 12 * 31 * 86400.0, "centuries")]
    [InlineData(double.MaxValue, "centuries")]
    [InlineData(double.NaN, "less than a second")]
    public void Time_display_buckets(double seconds, string expected) => Assert.Equal(expected, TimeDisplay.Format(seconds));

    [Fact]
    public void Feedback_for_weak_passwords()
    {
        Assert.Equal("This is a top-10 common password.", Estimate("password").Warning);
        Assert.Equal("This is a top-100 common password.", Estimate("sunshine").Warning); // rank 47
        Assert.Equal("This is a very common password.", Estimate("qwerty123").Warning); // rank ~6,300
        Assert.Equal("Repeated characters like \"aaa\" are easy to guess.", Estimate("aaaaaaaaaaaa").Warning);
        Assert.Equal("Repeats like \"abcabcabc\" are only slightly harder to guess than \"abc\".", Estimate("kxqkxqkxqkxq").Warning);
        Assert.Equal("Dates are often easy to guess.", Estimate("11/20/1991").Warning);
        Assert.Equal("Recent years are easy to guess.", Estimate("2019").Warning);
        Assert.Equal("Straight rows of keys are easy to guess.", Estimate("zxcvbnm,./").Warning);

        StrengthEstimate l33t = Estimate("p4ssw0rd");
        Assert.Contains("Predictable substitutions like '@' instead of 'a' don't help very much.", l33t.Suggestions);
        Assert.Equal(Feedback.AddWord, l33t.Suggestions[0]);
        Assert.Contains("Capitalization doesn't help very much.", Estimate("Sunshine").Suggestions);
        Assert.Contains("All-uppercase is almost as easy to guess as all-lowercase.", Estimate("SUNSHINE").Suggestions);
        Assert.Contains("Reversed words aren't much harder to guess.", Estimate("enihsnus").Suggestions);
    }

    [Fact]
    public void Strong_passwords_get_no_feedback()
    {
        StrengthEstimate e = Estimate("violet-quartz-tundra-mosaic");
        Assert.Equal(string.Empty, e.Warning);
        Assert.Empty(e.Suggestions);
    }

    [Fact]
    public void Empty_password()
    {
        StrengthEstimate e = Estimate(string.Empty);
        Assert.Equal(1, e.Guesses);
        Assert.Equal(0, e.GuessesLog10);
        Assert.Equal(0, e.Score);
        Assert.Empty(e.Sequence);
        Assert.Equal(new[] { Feedback.UseFewWords, Feedback.NoNeedForSymbols }, e.Suggestions);
    }

    [Fact]
    public void Only_the_first_100_characters_are_analyzed()
    {
        string hundred = new string('k', 100);
        Assert.False(Estimate(hundred).IsTruncated);

        StrengthEstimate truncated = Estimate(hundred + "gx7#Lq2!vZ9pRm4w");
        Assert.True(truncated.IsTruncated);
        Assert.Equal(Estimate(hundred).Guesses, truncated.Guesses);
        Assert.Equal(100, truncated.Sequence.Sum(m => m.Length));
    }

    [Fact]
    public void Truncation_never_splits_a_surrogate_pair()
    {
        string password = new string('k', 99) + "🦊🦊";
        StrengthEstimate e = Estimate(password);
        Assert.True(e.IsTruncated);
        Assert.Equal(99, e.Sequence.Sum(m => m.Length));
    }

    [Fact]
    public void Estimates_are_deterministic_and_thread_safe()
    {
        const string password = "p4ssw0rd1991qwerty-violet";
        double expected = Estimate(password).Guesses;
        var results = new double[64];
        System.Threading.Tasks.Parallel.For(0, results.Length, i => results[i] = Estimate(password).Guesses);
        Assert.All(results, r => Assert.Equal(expected, r));
    }

    [Fact]
    public void Arguments_are_validated()
    {
        Assert.Throws<ArgumentNullException>(() => PasswordStrengthEstimator.Estimate((string)null!));
        Assert.Throws<ArgumentNullException>(() => PasswordStrengthEstimator.Estimate((SensitiveString)null!));
        Assert.Throws<ArgumentOutOfRangeException>(() => PasswordStrengthEstimator.Estimate("x", null, 999));
        Assert.Throws<ArgumentOutOfRangeException>(() => PasswordStrengthEstimator.Estimate("x", null, 10000));
    }

    [Fact]
    public void Public_overloads_agree()
    {
        const string password = "violet-quartz";
        double a = PasswordStrengthEstimator.Estimate(password).Guesses;
        double b = PasswordStrengthEstimator.Estimate(password, null).Guesses;
        double c = PasswordStrengthEstimator.Estimate(new SensitiveString(password)).Guesses;
        Assert.Equal(a, b);
        Assert.Equal(a, c);
    }

    [Fact]
    public void ToString_does_not_reveal_the_password()
    {
        StrengthEstimate e = Estimate("violet-quartz-tundra-mosaic");
        Assert.StartsWith("Score 4 (10^", e.ToString());
        Assert.DoesNotContain("violet", e.ToString());
        Assert.All(e.Sequence, m => Assert.DoesNotContain("violet", m.ToString()));
    }

    [Fact]
    public void Nfkc_equivalent_inputs_get_the_same_estimate()
    {
        Assert.Equal(Estimate("café-orbit").Guesses, Estimate("café-orbit").Guesses);
        Assert.Equal(Estimate("ｐａｓｓｗｏｒｄ").Guesses, Estimate("password").Guesses); // full-width
    }
}
