using System.Collections.Generic;
using Masterly.Hash.Policy.Internal;

namespace Masterly.Hash.Policy.Tests;

/// <summary>
/// Known-answer vectors from zxcvbn's own test suite, test/test-scoring.coffee
/// (https://github.com/dropbox/zxcvbn/blob/master/test/test-scoring.coffee, MIT). The estimator re-implements
/// zxcvbn's published formulas, so these values must match exactly (with REFERENCE_YEAR replaced by ours).
/// </summary>
public class ScoringKnownAnswerTests
{
    private const int Year = Policies.ReferenceYear;

    [Theory]
    [InlineData(0, 0, 1)]
    [InlineData(1, 0, 1)]
    [InlineData(5, 0, 1)]
    [InlineData(0, 1, 0)]
    [InlineData(0, 5, 0)]
    [InlineData(2, 1, 2)]
    [InlineData(4, 2, 6)]
    [InlineData(33, 7, 4272048)]
    public void NCk(int n, int k, double expected) => Assert.Equal(expected, Scoring.NCk(n, k));

    [Fact]
    public void NCk_mirror_identity()
    {
        for (int n = 0; n < 50; n++)
            for (int k = 0; k <= n; k++)
                Assert.Equal(Scoring.NCk(n, k), Scoring.NCk(n, n - k));
    }

    public static IEnumerable<object[]> UppercaseVectors() => new[]
    {
        new object[] { "", 1d },
        new object[] { "a", 1d },
        new object[] { "A", 2d },
        new object[] { "abcdef", 1d },
        new object[] { "Abcdef", 2d },
        new object[] { "abcdeF", 2d },
        new object[] { "ABCDEF", 2d },
        new object[] { "aBcdef", Scoring.NCk(6, 1) },
        new object[] { "aBcDef", Scoring.NCk(6, 1) + Scoring.NCk(6, 2) },
        new object[] { "ABCDEf", Scoring.NCk(6, 1) },
        new object[] { "aBCDEf", Scoring.NCk(6, 1) + Scoring.NCk(6, 2) },
        new object[] { "ABCdef", Scoring.NCk(6, 1) + Scoring.NCk(6, 2) + Scoring.NCk(6, 3) },
    };

    [Theory]
    [MemberData(nameof(UppercaseVectors))]
    public void Uppercase_variations(string word, double expected) => Assert.Equal(expected, Scoring.UppercaseVariations(word));

    public static IEnumerable<object[]> L33tVectors() => new[]
    {
        new object[] { "", 1d, new Dictionary<char, char>() },
        new object[] { "a", 1d, new Dictionary<char, char>() },
        new object[] { "4", 2d, new Dictionary<char, char> { ['4'] = 'a' } },
        new object[] { "4pple", 2d, new Dictionary<char, char> { ['4'] = 'a' } },
        new object[] { "abcet", 1d, new Dictionary<char, char>() },
        new object[] { "4bcet", 2d, new Dictionary<char, char> { ['4'] = 'a' } },
        new object[] { "a8cet", 2d, new Dictionary<char, char> { ['8'] = 'b' } },
        new object[] { "abce+", 2d, new Dictionary<char, char> { ['+'] = 't' } },
        new object[] { "48cet", 4d, new Dictionary<char, char> { ['4'] = 'a', ['8'] = 'b' } },
        new object[] { "a4a4aa", Scoring.NCk(6, 2) + Scoring.NCk(6, 1), new Dictionary<char, char> { ['4'] = 'a' } },
        new object[] { "4a4a44", Scoring.NCk(6, 2) + Scoring.NCk(6, 1), new Dictionary<char, char> { ['4'] = 'a' } },
        new object[] { "a44att+", (Scoring.NCk(4, 2) + Scoring.NCk(4, 1)) * Scoring.NCk(3, 1), new Dictionary<char, char> { ['4'] = 'a', ['+'] = 't' } },
        // Capitalization does not affect l33t variations.
        new object[] { "Aa44aA", Scoring.NCk(6, 2) + Scoring.NCk(6, 1), new Dictionary<char, char> { ['4'] = 'a' } },
    };

    [Theory]
    [MemberData(nameof(L33tVectors))]
    public void L33t_variations(string word, double expected, Dictionary<char, char> sub)
    {
        var match = new Match(PatternKind.Dictionary, 0, word.Length - 1, word) { L33t = sub.Count > 0, Sub = sub };
        Assert.Equal(expected, Scoring.L33tVariations(match));
    }

    [Fact]
    public void Dictionary_guesses()
    {
        // base guesses == the rank
        Assert.Equal(32, Guesses(new Match(PatternKind.Dictionary, 0, 4, "aaaaa") { Rank = 32 }));
        // extra guesses are added for capitalization
        Assert.Equal(32 * Scoring.UppercaseVariations("AAAaaa"), Guesses(new Match(PatternKind.Dictionary, 0, 5, "AAAaaa") { Rank = 32 }));
        // guesses are doubled when word is reversed
        Assert.Equal(32 * 2, Guesses(new Match(PatternKind.Dictionary, 0, 2, "aaa") { Rank = 32, Reversed = true }));
        // extra guesses are added for common l33t substitutions
        var l33t = new Match(PatternKind.Dictionary, 0, 5, "aaa@@@") { Rank = 32, L33t = true, Sub = new Dictionary<char, char> { ['@'] = 'a' } };
        Assert.Equal(32 * Scoring.L33tVariations(l33t), Guesses(l33t));
        // extra guesses are added for both capitalization and common l33t substitutions
        var both = new Match(PatternKind.Dictionary, 0, 5, "AaA@@@") { Rank = 32, L33t = true, Sub = new Dictionary<char, char> { ['@'] = 'a' } };
        Assert.Equal(32 * Scoring.L33tVariations(both) * Scoring.UppercaseVariations("AaA@@@"), Guesses(both));
    }

    [Theory]
    [InlineData("ab", true, 4 * 2)]
    [InlineData("XYZ", true, 26 * 3)]
    [InlineData("4567", true, 10 * 4)]
    [InlineData("7654", false, 10 * 4 * 2)]
    [InlineData("ZYX", false, 4 * 3 * 2)]
    public void Sequence_guesses(string token, bool ascending, double expected) =>
        Assert.Equal(expected, Guesses(new Match(PatternKind.Sequence, 0, token.Length - 1, token) { Ascending = ascending }));

    [Fact]
    public void Year_guesses()
    {
        // guesses of |year - REFERENCE_YEAR| for distant years, MIN_YEAR_SPACE for recent ones.
        Assert.Equal(Year - 1972, Guesses(new Match(PatternKind.Year, 0, 3, "1972") { Year = 1972 }));
        Assert.Equal(Scoring.MinYearSpace, Guesses(new Match(PatternKind.Year, 0, 3, "2015") { Year = 2015 }));
    }

    [Fact]
    public void Date_guesses()
    {
        // guesses for 1123 is 365 * distance_from_ref_year
        Assert.Equal(365 * (Year - 1923), Guesses(new Match(PatternKind.Date, 0, 3, "1123") { Year = 1923, Month = 1, Day = 1 }));
        // recent years assume MIN_YEAR_SPACE; extra guesses are added for separators
        Assert.Equal(365 * Scoring.MinYearSpace * 4, Guesses(new Match(PatternKind.Date, 0, 7, "1/1/2010") { Year = 2010, Month = 1, Day = 1, Separator = "/" }));
    }

    [Fact]
    public void Keyboard_graph_statistics_match_zxcvbn()
    {
        // zxcvbn: KEYBOARD_STARTING_POSITIONS = 94, KEYBOARD_AVERAGE_DEGREE = 432/94; keypad 15 and 76/15.
        Assert.Equal(94, AdjacencyGraph.Qwerty.StartingPositions);
        Assert.Equal(432.0 / 94, AdjacencyGraph.Qwerty.AverageDegree, 12);
        Assert.Equal(15, AdjacencyGraph.Keypad.StartingPositions);
        Assert.Equal(76.0 / 15, AdjacencyGraph.Keypad.AverageDegree, 12);
    }

    [Fact]
    public void Spatial_guesses()
    {
        double s = AdjacencyGraph.Qwerty.StartingPositions;
        double d = AdjacencyGraph.Qwerty.AverageDegree;
        // with no turns or shifts, guesses is starts * degree * (len - 1)
        double baseGuesses = s * d * 5;
        Assert.Equal(baseGuesses, Guesses(new Match(PatternKind.Spatial, 0, 5, "zxcvbn") { Graph = "qwerty", Turns = 1 }), 6);
        // guesses is added for shifted keys, similar to capitals in dictionary matching
        Assert.Equal(baseGuesses * (Scoring.NCk(6, 2) + Scoring.NCk(6, 1)),
            Guesses(new Match(PatternKind.Spatial, 0, 5, "ZxCvbn") { Graph = "qwerty", Turns = 1, ShiftedCount = 2 }), 6);
        // when everything is shifted, guesses are doubled
        Assert.Equal(baseGuesses * 2, Guesses(new Match(PatternKind.Spatial, 0, 5, "ZXCVBN") { Graph = "qwerty", Turns = 1, ShiftedCount = 6 }), 6);
        // spatial guesses accounts for turn positions, directions and starting keys
        double expected = 0;
        for (int i = 2; i <= 9; i++)
            for (int j = 1; j <= System.Math.Min(3, i - 1); j++)
                expected += Scoring.NCk(i - 1, j - 1) * s * System.Math.Pow(d, j);
        Assert.Equal(expected, Guesses(new Match(PatternKind.Spatial, 0, 8, "zxcft6yhn") { Graph = "qwerty", Turns = 3 }), 3);
    }

    [Theory]
    [InlineData("aa", "a", 2)]
    [InlineData("999", "9", 3)]
    [InlineData("$$$$", "$", 4)]
    [InlineData("abab", "ab", 2)]
    [InlineData("batterystaplebatterystaple", "batterystaple", 2)]
    public void Repeat_guesses(string token, string baseToken, int repeatCount)
    {
        var matching = new Matching(new[] { EmbeddedDictionaries.CommonPasswords, EmbeddedDictionaries.EnglishWords }, Year);
        Match repeat = Assert.Single(matching.RepeatMatch(token));
        double baseGuesses = Scoring.MostGuessableMatchSequence(baseToken, matching.Omnimatch(baseToken), Year).Guesses;

        Assert.Equal(baseToken, repeat.BaseToken);
        Assert.Equal(repeatCount, repeat.RepeatCount);
        Assert.Equal(baseGuesses, repeat.BaseGuesses);
        Assert.Equal(baseGuesses * repeatCount, Scoring.EstimateGuesses(repeat, token, Year));
    }

    [Fact]
    public void Submatches_get_a_minimum_guess_floor()
    {
        // estimate_guesses returns cached guesses when available; otherwise applies MIN_SUBMATCH_GUESSES.
        var cached = new Match(PatternKind.Dictionary, 0, 2, "abc") { Guesses = 1 };
        Assert.Equal(1, Scoring.EstimateGuesses(cached, "abcdef", Year));

        var single = new Match(PatternKind.Dictionary, 0, 0, "a") { Rank = 1 };
        Assert.Equal(Scoring.MinSubmatchGuessesSingleChar, Scoring.EstimateGuesses(single, "ab", Year));

        var multi = new Match(PatternKind.Dictionary, 0, 1, "ab") { Rank = 1 };
        Assert.Equal(Scoring.MinSubmatchGuessesMultiChar, Scoring.EstimateGuesses(multi, "abc", Year));

        var whole = new Match(PatternKind.Dictionary, 0, 2, "abc") { Rank = 1 };
        Assert.Equal(1, Scoring.EstimateGuesses(whole, "abc", Year));
    }

    // ---------------------------------------------------------------- most_guessable_match_sequence

    private const string Digits = "0123456789";

    [Fact]
    public void Dp_returns_one_bruteforce_match_given_no_matches()
    {
        GuessAnalysis result = Scoring.MostGuessableMatchSequence(Digits, new List<Match>(), Year, excludeAdditive: true);

        Match m = Assert.Single(result.Sequence);
        Assert.Equal(PatternKind.Bruteforce, m.Pattern);
        Assert.Equal(Digits, m.Token);
        Assert.Equal(0, m.I);
        Assert.Equal(9, m.J);
        Assert.Equal(1e10, result.Guesses);
    }

    [Fact]
    public void Dp_returns_match_plus_bruteforce_when_match_covers_a_prefix()
    {
        var m0 = new Match(PatternKind.Dictionary, 0, 5, "012345") { Guesses = 1 };
        GuessAnalysis result = Scoring.MostGuessableMatchSequence(Digits, new List<Match> { m0 }, Year, excludeAdditive: true);

        Assert.Equal(2, result.Sequence.Count);
        Assert.Same(m0, result.Sequence[0]);
        Assert.Equal(PatternKind.Bruteforce, result.Sequence[1].Pattern);
        Assert.Equal(6, result.Sequence[1].I);
        Assert.Equal(9, result.Sequence[1].J);
    }

    [Fact]
    public void Dp_returns_bruteforce_plus_match_when_match_covers_a_suffix()
    {
        var m0 = new Match(PatternKind.Dictionary, 3, 9, "3456789") { Guesses = 1 };
        GuessAnalysis result = Scoring.MostGuessableMatchSequence(Digits, new List<Match> { m0 }, Year, excludeAdditive: true);

        Assert.Equal(2, result.Sequence.Count);
        Assert.Equal(PatternKind.Bruteforce, result.Sequence[0].Pattern);
        Assert.Equal(0, result.Sequence[0].I);
        Assert.Equal(2, result.Sequence[0].J);
        Assert.Same(m0, result.Sequence[1]);
    }

    [Fact]
    public void Dp_returns_bruteforce_match_bruteforce_when_match_covers_an_infix()
    {
        var m0 = new Match(PatternKind.Dictionary, 1, 8, "12345678") { Guesses = 1 };
        GuessAnalysis result = Scoring.MostGuessableMatchSequence(Digits, new List<Match> { m0 }, Year, excludeAdditive: true);

        Assert.Equal(3, result.Sequence.Count);
        Assert.Same(m0, result.Sequence[1]);
        Assert.Equal((0, 0), (result.Sequence[0].I, result.Sequence[0].J));
        Assert.Equal((9, 9), (result.Sequence[2].I, result.Sequence[2].J));
    }

    [Fact]
    public void Dp_chooses_the_lower_guesses_match_of_the_same_span()
    {
        var m0 = new Match(PatternKind.Dictionary, 0, 9, Digits) { Guesses = 1 };
        var m1 = new Match(PatternKind.Dictionary, 0, 9, Digits) { Guesses = 2 };
        GuessAnalysis result = Scoring.MostGuessableMatchSequence(Digits, new List<Match> { m0, m1 }, Year, excludeAdditive: true);
        Assert.Same(m0, Assert.Single(result.Sequence));

        // Make sure ordering doesn't matter.
        m0.Guesses = 3;
        result = Scoring.MostGuessableMatchSequence(Digits, new List<Match> { m0, m1 }, Year, excludeAdditive: true);
        Assert.Same(m1, Assert.Single(result.Sequence));
    }

    [Fact]
    public void Dp_when_m0_covers_m1_and_m2_chooses_m0_only_if_cheaper_than_m1_times_m2_times_2()
    {
        var m0 = new Match(PatternKind.Dictionary, 0, 9, Digits) { Guesses = 3 };
        var m1 = new Match(PatternKind.Dictionary, 0, 3, "0123") { Guesses = 2 };
        var m2 = new Match(PatternKind.Dictionary, 4, 9, "456789") { Guesses = 1 };

        GuessAnalysis result = Scoring.MostGuessableMatchSequence(Digits, new List<Match> { m0, m1, m2 }, Year, excludeAdditive: true);
        Assert.Equal(3, result.Guesses);
        Assert.Same(m0, Assert.Single(result.Sequence));

        m0.Guesses = 5;
        result = Scoring.MostGuessableMatchSequence(Digits, new List<Match> { m0, m1, m2 }, Year, excludeAdditive: true);
        Assert.Equal(4, result.Guesses);
        Assert.Equal(new[] { m1, m2 }, result.Sequence);
    }

    [Fact]
    public void Dp_empty_password_has_one_guess()
    {
        GuessAnalysis result = Scoring.MostGuessableMatchSequence(string.Empty, new List<Match>(), Year);
        Assert.Equal(1, result.Guesses);
        Assert.Empty(result.Sequence);
    }

    [Theory]
    [InlineData(0, 0)]
    [InlineData(1004, 0)]
    [InlineData(1005, 1)]
    [InlineData(1e6 + 4, 1)]
    [InlineData(1e6 + 5, 2)]
    [InlineData(1e8 + 4, 2)]
    [InlineData(1e8 + 5, 3)]
    [InlineData(1e10 + 4, 3)]
    [InlineData(1e10 + 5, 4)]
    [InlineData(double.MaxValue, 4)]
    public void Score_thresholds_are_zxcvbns(double guesses, int expected) => Assert.Equal(expected, Scoring.GuessesToScore(guesses));

    private static double Guesses(Match match) => Scoring.EstimateGuesses(match, match.Token, Year);
}
