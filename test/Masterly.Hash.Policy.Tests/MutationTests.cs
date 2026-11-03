using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using Masterly.Hash.Policy.Internal;

namespace Masterly.Hash.Policy.Tests;

/// <summary>
/// Precise assertions on boundaries, orderings, exact texts and internal helpers, so that a wrong comparison,
/// a dropped statement or a changed string makes a test fail (Stryker.NET mutation testing), not just run.
/// </summary>
public class MutationTests
{
    private const int Year = Policies.ReferenceYear;

    private static readonly Matching Matcher = new(
        new[] { EmbeddedDictionaries.CommonPasswords, EmbeddedDictionaries.EnglishWords }, Year);

    private static RankedDictionary Dict(params string[] words) => new(DictionaryKind.CommonPasswords, words);

    private static Matching MatcherFor(params RankedDictionary[] dictionaries) => new(dictionaries, Year);

    // ================================================================ BreachCheckResult

    [Fact]
    public void Breached_rejects_fewer_than_one_occurrence_naming_the_parameter()
    {
        var ex = Assert.Throws<ArgumentOutOfRangeException>(() => BreachCheckResult.Breached(0));
        Assert.Equal("occurrences", ex.ParamName);
        Assert.Equal(1, BreachCheckResult.Breached(1).Occurrences);
    }

    // ================================================================ AdjacencyGraph

    private static readonly string[] KeypadFiveNeighbours = { "4", "7", "8", "9", "6", "3", "2", "1" };
    private static readonly string[] QwertyGNeighbours = { "fF", "tT", "yY", "hH", "bB", "vV" };

    [Fact]
    public void Keypad_neighbours_are_in_zxcvbns_direction_order()
    {
        Assert.True(AdjacencyGraph.Keypad.TryGetAdjacent('5', out string?[] adjacent));
        Assert.Equal(KeypadFiveNeighbours, adjacent);
        Assert.True(AdjacencyGraph.Keypad.TryGetAdjacent('7', out adjacent));
        Assert.Equal(new string?[] { null, null, null, "/", "8", "5", "4", null }, adjacent);
    }

    [Fact]
    public void Qwerty_neighbours_are_in_zxcvbns_direction_order()
    {
        Assert.True(AdjacencyGraph.Qwerty.TryGetAdjacent('g', out string?[] adjacent));
        Assert.Equal(QwertyGNeighbours, adjacent);
        Assert.True(AdjacencyGraph.Qwerty.TryGetAdjacent('G', out string?[] shifted));
        Assert.Same(adjacent, shifted);
        Assert.False(AdjacencyGraph.Qwerty.TryGetAdjacent('é', out _));
    }

    [Fact]
    public void Freshly_built_graphs_have_the_same_neighbours()
    {
        // The two graphs are static singletons; build new ones so the constructor itself is exercised by this test.
        AdjacencyGraph keypad = BuildGraph("keypad", "KeypadLayout", slanted: false);
        Assert.True(keypad.TryGetAdjacent('5', out string?[] adjacent));
        Assert.Equal(KeypadFiveNeighbours, adjacent);
        Assert.Equal(15, keypad.StartingPositions);
        Assert.Equal(76.0 / 15, keypad.AverageDegree, 12);

        AdjacencyGraph qwerty = BuildGraph("qwerty", "QwertyLayout", slanted: true);
        Assert.True(qwerty.TryGetAdjacent('g', out adjacent));
        Assert.Equal(QwertyGNeighbours, adjacent);
        Assert.Equal(94, qwerty.StartingPositions);
    }

    private static AdjacencyGraph BuildGraph(string name, string layoutField, bool slanted)
    {
        string layout = (string)typeof(AdjacencyGraph).GetField(layoutField, BindingFlags.NonPublic | BindingFlags.Static)!.GetRawConstantValue()!;
        ConstructorInfo ctor = typeof(AdjacencyGraph).GetConstructor(
            BindingFlags.NonPublic | BindingFlags.Instance, null, new[] { typeof(string), typeof(string), typeof(bool) }, null)!;
        return (AdjacencyGraph)ctor.Invoke(new object[] { name, layout, slanted });
    }

    // ================================================================ Feedback

    private static Match Dictionary(string token, DictionaryKind kind, int rank = 1, double guesses = 50, bool reversed = false, bool l33t = false) =>
        new(PatternKind.Dictionary, 0, token.Length - 1, token) { Dictionary = kind, Rank = rank, Guesses = guesses, Reversed = reversed, L33t = l33t };

    private static Match Bruteforce(int i, string token) => new(PatternKind.Bruteforce, i, i + token.Length - 1, token);

    private static (string Warning, List<string> Suggestions) Get(int score, params Match[] sequence) => Feedback.Get(score, sequence);

    [Fact]
    public void Feedback_for_an_empty_sequence_has_no_warning()
    {
        var (warning, suggestions) = Get(0);
        Assert.Equal(string.Empty, warning);
        Assert.Equal(new[] { Feedback.UseFewWords, Feedback.NoNeedForSymbols }, suggestions);
    }

    [Fact]
    public void Feedback_is_given_up_to_score_two_and_not_above()
    {
        Assert.Equal(new[] { Feedback.AddWord }, Get(2, Bruteforce(0, "kzq7")).Suggestions);

        var (warning, suggestions) = Get(3, Dictionary("password", DictionaryKind.CommonPasswords));
        Assert.Equal(string.Empty, warning);
        Assert.Empty(suggestions);
    }

    [Fact]
    public void Feedback_for_bruteforce_only_suggests_adding_a_word()
    {
        var (warning, suggestions) = Get(0, Bruteforce(0, "kzq7"));
        Assert.Equal(string.Empty, warning);
        Assert.Equal(new[] { Feedback.AddWord }, suggestions);
    }

    [Fact]
    public void Feedback_uses_the_first_of_equally_long_matches()
    {
        var sequence = new Match(PatternKind.Sequence, 0, 3, "abcd") { Ascending = true };
        var year = new Match(PatternKind.Year, 4, 7, "2019") { Year = 2019 };

        Assert.Equal("Sequences like \"abc\" or \"6543\" are easy to guess.", Get(0, sequence, year).Warning);
        Assert.Equal("Recent years are easy to guess.", Get(0, year, sequence).Warning);
    }

    [Fact]
    public void Feedback_texts_for_each_pattern()
    {
        var repeat = new Match(PatternKind.Repeat, 0, 5, "aaaaaa") { BaseToken = "a", RepeatCount = 6 };
        Assert.Equal(string.Join(" | ", new[] { "Repeated characters like \"aaa\" are easy to guess.", Feedback.AddWord, "Avoid repeated words and characters." }),
            Text(Get(0, repeat)));

        var sequence = new Match(PatternKind.Sequence, 0, 3, "abcd") { Ascending = true };
        Assert.Equal(string.Join(" | ", new[] { "Sequences like \"abc\" or \"6543\" are easy to guess.", Feedback.AddWord, "Avoid sequences." }),
            Text(Get(0, sequence)));

        var year = new Match(PatternKind.Year, 0, 3, "2019") { Year = 2019 };
        Assert.Equal(string.Join(" | ", new[] { "Recent years are easy to guess.", Feedback.AddWord, "Avoid recent years.", "Avoid years that are associated with you." }),
            Text(Get(0, year)));

        var date = new Match(PatternKind.Date, 0, 9, "11/20/1991") { Year = 1991, Month = 11, Day = 20, Separator = "/" };
        Assert.Equal(string.Join(" | ", new[] { "Dates are often easy to guess.", Feedback.AddWord, "Avoid dates and years that are associated with you." }),
            Text(Get(0, date)));

        var spatial = new Match(PatternKind.Spatial, 0, 4, "qwert") { Graph = "qwerty", Turns = 2 };
        Assert.Equal(string.Join(" | ", new[] { "Short keyboard patterns are easy to guess.", Feedback.AddWord, "Use a longer keyboard pattern with more turns, or better, a few words." }),
            Text(Get(0, spatial)));
    }

    private static string Text((string Warning, List<string> Suggestions) f) => f.Warning + " | " + string.Join(" | ", f.Suggestions);

    [Theory]
    [InlineData(1, "This is a top-10 common password.")]
    [InlineData(10, "This is a top-10 common password.")]
    [InlineData(11, "This is a top-100 common password.")]
    [InlineData(100, "This is a top-100 common password.")]
    [InlineData(101, "This is a very common password.")]
    public void Common_password_rank_buckets(int rank, string warning) =>
        Assert.Equal(warning, Get(0, Dictionary("sunshine", DictionaryKind.CommonPasswords, rank)).Warning);

    [Fact]
    public void Common_password_that_is_not_the_whole_password_is_called_similar()
    {
        const string Similar = "This is similar to a commonly used password.";
        Match word = Dictionary("password", DictionaryKind.CommonPasswords, rank: 1, guesses: 50);
        Assert.Equal(Similar, Get(0, word, Bruteforce(8, "x")).Warning);

        // Reversed or l33t, even alone: also "similar", and only while it costs at most 10^4 guesses.
        Assert.Equal(Similar, Get(0, Dictionary("drowssap", DictionaryKind.CommonPasswords, guesses: 10000, reversed: true)).Warning);
        Assert.Equal(string.Empty, Get(0, Dictionary("drowssap", DictionaryKind.CommonPasswords, guesses: 10001, reversed: true)).Warning);
        Assert.Equal(Similar, Get(0, Dictionary("p4ssword", DictionaryKind.CommonPasswords, guesses: 9999, l33t: true)).Warning);
        Assert.Equal(string.Empty, Get(0, Dictionary("p4ssword", DictionaryKind.CommonPasswords, guesses: 20000, l33t: true)).Warning);
    }

    [Fact]
    public void English_word_alone_is_called_out_but_not_inside_a_longer_password()
    {
        Assert.Equal("A word by itself is easy to guess.", Get(0, Dictionary("because", DictionaryKind.EnglishWords)).Warning);

        var (warning, suggestions) = Get(0, Dictionary("because", DictionaryKind.EnglishWords), Bruteforce(7, "q"));
        Assert.Equal(string.Empty, warning);
        Assert.Equal(new[] { Feedback.AddWord }, suggestions);
    }

    [Fact]
    public void Context_word_warning()
    {
        Assert.Equal("Words related to you or this service are easy to guess.",
            Get(0, Dictionary("johnsmith", DictionaryKind.ContextWords), Bruteforce(9, "q")).Warning);
    }

    private const string Capitalization = "Capitalization doesn't help very much.";
    private const string AllUpper = "All-uppercase is almost as easy to guess as all-lowercase.";
    private const string ReversedWords = "Reversed words aren't much harder to guess.";

    [Theory]
    [InlineData("sunshine", false, new string[0])]
    [InlineData("Sunshine", false, new[] { Capitalization })]
    [InlineData("SunShine", false, new string[0])]
    [InlineData("SUNSHINE", false, new[] { AllUpper })]
    [InlineData("QWERTY123", false, new[] { AllUpper })]
    [InlineData("123456", false, new string[0])]
    [InlineData("A", false, new[] { AllUpper })]
    [InlineData("evol", true, new[] { ReversedWords })]
    [InlineData("eye", true, new string[0])]
    public void Dictionary_suggestions(string token, bool reversed, string[] expected)
    {
        var (_, suggestions) = Get(0, Dictionary(token, DictionaryKind.EnglishWords, reversed: reversed));
        Assert.Equal(new[] { Feedback.AddWord }.Concat(expected), suggestions);
    }

    // ================================================================ L33t

    [Fact]
    public void L33t_table_entries()
    {
        Assert.Equal("4@", L33t.Table['a']);
        Assert.Equal("8", L33t.Table['b']);
        Assert.Equal("({[<", L33t.Table['c']);
        Assert.Equal("69", L33t.Table['g']);
        Assert.Equal("%", L33t.Table['x']);
        Assert.True(L33t.CharMatches('8', 'b'));
        Assert.True(L33t.CharMatches('<', 'c'));
        Assert.True(L33t.CharMatches('9', 'g'));
        Assert.True(L33t.CharMatches('%', 'x'));
        Assert.Equal("il", L33t.Reverse['1']);
    }

    [Fact]
    public void Equals_with_substitutions()
    {
        Assert.True(L33t.EqualsWithSubstitutions("p4ss", "pass"));
        Assert.True(L33t.EqualsWithSubstitutions("pass", "pass"));
        Assert.False(L33t.EqualsWithSubstitutions("pa", "pass"));
        Assert.False(L33t.EqualsWithSubstitutions("pass", "pa"));
        Assert.False(L33t.EqualsWithSubstitutions("pase", "pass"));
    }

    [Fact]
    public void An_empty_word_is_never_contained()
    {
        Assert.False(L33t.ContainsEquivalent("abc", string.Empty));
        Assert.False(L33t.ContainsEquivalent("ab", "abc"));
        Assert.True(L33t.ContainsEquivalent("abc", "abc"));
    }

    [Fact]
    public void Substitute_at_the_start_is_found()
    {
        Dictionary<char, char> sub = Assert.Single(L33t.EnumerateSubstitutions("4bc"));
        Assert.Equal(new Dictionary<char, char> { ['4'] = 'a' }, sub);
    }

    // ================================================================ Match defaults

    [Fact]
    public void Match_text_properties_default_to_empty()
    {
        var m = new Match(PatternKind.Bruteforce, 0, 0, "x");
        Assert.Equal(string.Empty, m.MatchedWord);
        Assert.Equal(string.Empty, m.Graph);
        Assert.Equal(string.Empty, m.BaseToken);
        Assert.Equal(string.Empty, m.Separator);
    }

    // ================================================================ Matching: sort and dictionary

    [Fact]
    public void Sort_is_stable_for_many_equal_spans()
    {
        // More than 16 elements, where List.Sort stops being an insertion sort and is no longer stable.
        var matches = Enumerable.Range(0, 20).Select(k => new Match(PatternKind.Dictionary, 0, 1, "ab") { Rank = k }).ToList();
        Matching.Sort(matches);
        Assert.Equal(Enumerable.Range(0, 20), matches.Select(m => m.Rank));
    }

    [Fact]
    public void Dictionary_match_finds_words_near_the_end_of_the_password()
    {
        Match m = Assert.Single(MatcherFor(Dict("ab")).DictionaryMatch("xxab"));
        Assert.Equal((2, 3), (m.I, m.J));
    }

    [Fact]
    public void Dictionary_match_sorts_across_dictionaries()
    {
        List<Match> matches = MatcherFor(Dict("cd"), Dict("ab")).DictionaryMatch("abcd");
        Assert.Equal(new[] { "ab", "cd" }, matches.Select(m => m.MatchedWord));
    }

    [Fact]
    public void Reverse_dictionary_match_is_sorted_by_position()
    {
        List<Match> matches = MatcherFor(Dict("ba", "dc")).ReverseDictionaryMatch("abcd");
        Assert.Equal(new[] { (0, 1, "ab"), (2, 3, "cd") }, matches.Select(m => (m.I, m.J, m.Token)));
    }

    [Fact]
    public void L33t_match_skips_unsubstituted_and_single_character_matches()
    {
        Assert.Empty(MatcherFor(Dict("password")).L33tMatch("password4"));
        Assert.Empty(MatcherFor(Dict("a")).L33tMatch("4"));
        Match m = Assert.Single(MatcherFor(Dict("ab")).L33tMatch("48"));
        Assert.Equal("ab", m.MatchedWord);
    }

    [Fact]
    public void L33t_match_records_a_substitute_at_the_start_of_the_token()
    {
        Match m = Assert.Single(MatcherFor(Dict("apple")).L33tMatch("4pple"));
        Assert.Equal(new Dictionary<char, char> { ['4'] = 'a' }, m.Sub);
    }

    [Fact]
    public void L33t_match_is_sorted_across_substitution_tables()
    {
        // '1' reads as 'i' first, then as 'l': "qiwi" finds "wi" before "qlwl" finds "ql".
        List<Match> matches = MatcherFor(Dict("wi", "ql")).L33tMatch("q1w1");
        Assert.Equal(new[] { (0, 1, "ql"), (2, 3, "wi") }, matches.Select(m => (m.I, m.J, m.MatchedWord)));
    }

    [Fact]
    public void L33t_match_keeps_one_of_identical_matches_from_different_tables()
    {
        Match m = Assert.Single(MatcherFor(Dict("pass")).L33tMatch("p4ss1"));
        Assert.Equal((0, 3), (m.I, m.J));

        // The same word at two positions, and two words at the same start, are all kept.
        Assert.Equal(new[] { (0, 3), (4, 7) }, MatcherFor(Dict("pass")).L33tMatch("p4ssp4ss").Select(x => (x.I, x.J)));
        Assert.Equal(new[] { "pa", "pass" }, MatcherFor(Dict("pa", "pass")).L33tMatch("p4ss1").Select(x => x.MatchedWord));
    }

    [Fact]
    public void L33t_match_keeps_the_same_span_from_two_dictionaries()
    {
        var english = new RankedDictionary(DictionaryKind.EnglishWords, new[] { "pass" });
        List<Match> matches = MatcherFor(Dict("pass"), english).L33tMatch("p4ss");
        Assert.Equal(new[] { DictionaryKind.CommonPasswords, DictionaryKind.EnglishWords }, matches.Select(m => m.Dictionary));
    }

    // ================================================================ Matching: spatial, repeat, sequence

    [Fact]
    public void Spatial_matches_are_sorted_across_graphs()
    {
        List<Match> matches = Matcher.SpatialMatch("159zqwer");
        Assert.Equal(new[] { (0, 2, "keypad"), (4, 7, "qwerty") }, matches.Select(m => (m.I, m.J, m.Graph)));
    }

    [Fact]
    public void Shifted_first_character_is_counted()
    {
        Match m = Assert.Single(Matcher.SpatialMatch("~!@#"), x => x.Graph == "qwerty");
        Assert.Equal(4, m.ShiftedCount);
    }

    [Fact]
    public void Repeat_that_reaches_the_end_uses_the_greedy_unit()
    {
        Match m = Assert.Single(Matcher.RepeatMatch("babbababba"));
        Assert.Equal((0, 9, "babba", 2), (m.I, m.J, m.BaseToken, m.RepeatCount));
    }

    [Theory]
    [InlineData("ab", true)]
    [InlineData("ba", true)]
    [InlineData("ac", false)]
    [InlineData("aaac", false)]
    [InlineData("afkp", true)]
    [InlineData("agms", false)]
    public void Two_character_sequences_need_a_step_of_one_and_steps_are_at_most_five(string password, bool isSequence)
    {
        List<Match> matches = Matching.SequenceMatch(password);
        if (isSequence)
            Assert.Equal((0, password.Length - 1), (Assert.Single(matches).I, matches[0].J));
        else
            Assert.Empty(matches);
    }

    // ================================================================ Matching: dates

    private static List<(int I, int J, int Year, int Month, int Day)> Dates(string password) =>
        Matcher.DateMatch(password).Select(m => (m.I, m.J, m.Year, m.Month, m.Day)).ToList();

    [Fact]
    public void Dates_at_the_very_end_are_found()
    {
        // "1191": 11-9-(20)01 is closer to the reference year than 1-1-(19)91.
        Assert.Equal(new[] { (0, 3, 2001, 9, 11) }, Dates("1191"));
        Assert.Equal(new[] { (0, 5, 1991, 1, 1) }, Dates("1/1/91"));
    }

    [Fact]
    public void Date_readings_equally_close_to_the_reference_year_keep_the_first()
    {
        // "0110" reads as 01-10-0 (2000-10-01) and 01-1-0 (2000-01-01): same distance, first wins.
        Assert.Equal(new[] { (0, 3, 2000, 10, 1) }, Dates("0110"));
    }

    [Fact]
    public void Date_matches_are_sorted_by_position()
    {
        Assert.Equal(new[] { (0, 5, 1991, 1, 1), (7, 10, 2001, 9, 11) }, Dates("1/1/91x1191"));
    }

    [Theory]
    [InlineData("111x")]
    [InlineData("/12/12")]
    [InlineData("1/001/91")]
    public void Malformed_dates_are_not_matched(string password) => Assert.Empty(Dates(password));

    [Theory]
    [InlineData(1, 31, 1991, 1991, 1, 31)]
    [InlineData(1, 1, 1000, 1000, 1, 1)]
    [InlineData(1, 1, 2050, 2050, 1, 1)]
    [InlineData(1, 1, 99, 1999, 1, 1)]
    [InlineData(1, 1, 51, 1951, 1, 1)]
    [InlineData(1, 1, 50, 2050, 1, 1)]
    [InlineData(31, 1, 31, 2031, 1, 31)]
    [InlineData(12, 12, 12, 2012, 12, 12)]
    [InlineData(31, 1, 1991, 1991, 1, 31)]
    [InlineData(1, 12, 1991, 1991, 12, 1)]
    [InlineData(5, 1, 1991, 1991, 1, 5)]
    [InlineData(12, 13, 1991, 1991, 12, 13)]
    [InlineData(1, 13, 1991, 1991, 1, 13)]
    [InlineData(5, 31, 1991, 1991, 5, 31)]
    public void Map_ints_to_dmy_boundaries(int a, int b, int c, int year, int month, int day) =>
        Assert.Equal((year, month, day), Matching.MapIntsToDmy(a, b, c));

    [Theory]
    [InlineData(0, 5, 1991)]
    [InlineData(1991, 5, 0)]
    [InlineData(1, 32, 1991)]
    [InlineData(1, 1, 100)]
    [InlineData(1, 1, 999)]
    [InlineData(1, 1, 2051)]
    public void Map_ints_to_dmy_rejects(int a, int b, int c) => Assert.Null(Matching.MapIntsToDmy(a, b, c));

    // ================================================================ RankedDictionary and embedded lists

    [Fact]
    public void Ranked_dictionary_skips_null_empty_and_duplicate_entries()
    {
        var dictionary = new RankedDictionary(DictionaryKind.EnglishWords, new string?[] { null, "", "  ", "A", "bc", "a", " BC " }!);

        Assert.Equal(2, dictionary.Count);
        Assert.Equal(DictionaryKind.EnglishWords, dictionary.Kind);
        Assert.Equal(2, dictionary.MaxWordLength);
        Assert.True(dictionary.TryGetRank("a", out int rank));
        Assert.Equal(1, rank);
        Assert.True(dictionary.TryGetRank("bc", out rank));
        Assert.Equal(2, rank);
        Assert.True(dictionary.Contains("a"));
        Assert.True(dictionary.Contains("bc"));
        Assert.False(dictionary.Contains(""));
        Assert.True(dictionary.ContainsWithSubstitutions("8c"));
        Assert.False(dictionary.ContainsWithSubstitutions("8d"));
        Assert.False(dictionary.ContainsWithSubstitutions("abc"));
    }

    [Fact]
    public void Embedded_resources_are_read_line_by_line()
    {
        // The lists are cached in static Lazy instances; read the resource again so the reader itself is exercised.
        MethodInfo read = typeof(EmbeddedDictionaries).GetMethod("ReadResource", BindingFlags.NonPublic | BindingFlags.Static)!;

        var lines = (List<string>)read.Invoke(null, new object[] { "Masterly.Hash.Policy.common-passwords-10k.txt" })!;
        Assert.True(lines.Count >= 10_000, lines.Count.ToString());
        Assert.Equal(new[] { "password", "123456", "12345678" }, lines.Take(3));

        var ex = Assert.Throws<TargetInvocationException>(() => read.Invoke(null, new object[] { "missing.txt" }));
        var missing = Assert.IsType<InvalidOperationException>(ex.InnerException);
        Assert.Equal("Embedded resource 'missing.txt' is missing.", missing.Message);
    }

    // ================================================================ RepetitionCheck

    [Theory]
    [InlineData("abc", true)] // a three-character sequence is enough
    [InlineData("zzab", false)] // a two-character sequence is not
    [InlineData("aaQ", false)] // a repeat does not run on past its end
    [InlineData("aakzmkzm", true)] // unit exactly half of what remains
    [InlineData("zzabcdabcda", true)] // partial last period of a longer unit
    [InlineData("zzaabaab", true)] // the farthest-reaching weak unit wins
    [InlineData("qqqq9q9", true)]
    [InlineData("bbabbaa", true)]
    [InlineData("qaqq", true)]
    public void Repetition_check_cases(string password, bool expected) =>
        Assert.Equal(expected, RepetitionCheck.IsRepetitiveOrSequential(password));

    [Fact]
    public void Whole_string_that_is_a_weak_unit_typed_twice_is_repetitive_beyond_the_local_unit_limit()
    {
        // w (33 chars) is covered by its two sequences; u = w + w + "ab" is weak through its period 33 (partial last
        // period "ab"). u + u has smallest period exactly n / 2 = 68: only the whole-string check sees it as weak,
        // because the trailing "ab" (after "...456") is no sequence of three, no keyboard run and no repeat of a unit
        // of at most MaxUnit = 32 characters.
        const string W = "abcdefghijklmnopqrstuvwxyz0123456";
        string u = W + W + "ab";
        string password = u + u;
        Assert.Equal(136, password.Length);
        Assert.True(RepetitionCheck.MaxUnit < u.Length / 2);
        Assert.Equal(password.Length / 2, RepetitionCheck.SmallestPeriod(password));

        Assert.True(RepetitionCheck.IsRepetitiveOrSequential(W));
        Assert.True(RepetitionCheck.IsRepetitiveOrSequential(u));
        Assert.True(RepetitionCheck.IsRepetitiveOrSequential(password));

        // Through the policy as well (MaxLength raised so the repetition rule runs on all 136 characters).
        PasswordPolicyResult result = Policies.Create(o => o.MaxLength = 256).Evaluate(password);
        Assert.Contains(result.Violations, v => v.Code == PasswordViolationCode.RepetitiveOrSequential);
    }

    [Theory]
    [InlineData("aab", 3)]
    [InlineData("abab", 2)]
    [InlineData("abcab", 3)]
    [InlineData("aabaab", 3)]
    public void Smallest_period(string value, int expected) => Assert.Equal(expected, RepetitionCheck.SmallestPeriod(value));

    // ================================================================ Scoring

    [Fact]
    public void Dp_ties_between_matches_ending_together_go_to_the_leftmost_start()
    {
        // Passed right to left; both cost 2 * 1000 with the bruteforce prefix before them.
        var right = new Match(PatternKind.Dictionary, 3, 3, "d") { Guesses = 1 };
        var left = new Match(PatternKind.Dictionary, 2, 3, "cd") { Guesses = 10 };

        GuessAnalysis result = Scoring.MostGuessableMatchSequence("abcd", new List<Match> { right, left }, Year, excludeAdditive: true);

        Assert.Equal(2000, result.Guesses);
        Assert.Equal(2, result.Sequence.Count);
        Assert.Equal((PatternKind.Bruteforce, 0, 1), (result.Sequence[0].Pattern, result.Sequence[0].I, result.Sequence[0].J));
        Assert.Same(left, result.Sequence[1]);
    }

    [Fact]
    public void Dp_sorts_three_matches_ending_together()
    {
        var c = new Match(PatternKind.Dictionary, 3, 3, "d") { Guesses = 5 };    // 2 * 1000 * 5 = 10000
        var b = new Match(PatternKind.Dictionary, 2, 3, "cd") { Guesses = 11 };  // 2 * 100 * 11 = 2200
        var a = new Match(PatternKind.Dictionary, 1, 3, "bcd") { Guesses = 100 }; // 2 * 11 * 100 = 2200

        GuessAnalysis result = Scoring.MostGuessableMatchSequence("abcd", new List<Match> { c, b, a }, Year, excludeAdditive: true);

        Assert.Equal(2200, result.Guesses);
        Assert.Same(a, result.Sequence[1]);
        Assert.Equal((0, 0), (result.Sequence[0].I, result.Sequence[0].J));
    }

    [Fact]
    public void Dp_sorts_many_matches_of_the_same_span_stably()
    {
        // More than 16 matches, where List.Sort is no longer stable: the first of the cheapest wins.
        var matches = new List<Match> { new(PatternKind.Dictionary, 0, 1, "kk") { Guesses = 50, Rank = 0 } };
        for (int k = 1; k < 20; k++)
            matches.Add(new Match(PatternKind.Dictionary, 0, 1, "kk") { Guesses = 10, Rank = k });

        GuessAnalysis result = Scoring.MostGuessableMatchSequence("kk", matches, Year, excludeAdditive: true);

        Assert.Equal(10, result.Guesses);
        Assert.Equal(1, Assert.Single(result.Sequence).Rank);
    }

    [Fact]
    public void Dp_ties_between_lengths_go_to_the_shorter_sequence()
    {
        // bruteforce "abc" (1000) against bruteforce "ab" then the match: 2! * 100 * 5 = 1000.
        var m = new Match(PatternKind.Dictionary, 2, 2, "c") { Guesses = 5 };

        GuessAnalysis result = Scoring.MostGuessableMatchSequence("abc", new List<Match> { m }, Year, excludeAdditive: true);

        Assert.Equal(1000, result.Guesses);
        Match only = Assert.Single(result.Sequence);
        Assert.Equal((PatternKind.Bruteforce, 0, 2), (only.Pattern, only.I, only.J));
    }

    [Fact]
    public void Single_character_bruteforce_costs_eleven_guesses()
    {
        Assert.Equal(11, Scoring.EstimateGuesses(new Match(PatternKind.Bruteforce, 0, 0, "x"), "x", Year));
        Assert.Equal(11, Scoring.EstimateGuesses(new Match(PatternKind.Bruteforce, 1, 1, "x"), "ax", Year));
        Assert.Equal(100, Scoring.EstimateGuesses(new Match(PatternKind.Bruteforce, 0, 1, "xy"), "xy", Year));
    }

    [Fact]
    public void L33t_variations_need_the_l33t_flag()
    {
        var notL33t = new Match(PatternKind.Dictionary, 0, 2, "4bc") { L33t = false, Sub = new Dictionary<char, char> { ['4'] = 'a' } };
        Assert.Equal(1, Scoring.L33tVariations(notL33t));

        var l33tWithoutTable = new Match(PatternKind.Dictionary, 0, 2, "4bc") { L33t = true, Sub = null };
        Assert.Equal(1, Scoring.L33tVariations(l33tWithoutTable));

        var l33t = new Match(PatternKind.Dictionary, 0, 2, "4bc") { L33t = true, Sub = new Dictionary<char, char> { ['4'] = 'a' } };
        Assert.Equal(2, Scoring.L33tVariations(l33t));
    }

    [Fact]
    public void Keypad_patterns_use_the_keypad_statistics()
    {
        double s = AdjacencyGraph.Keypad.StartingPositions;
        double d = AdjacencyGraph.Keypad.AverageDegree;
        var keypad = new Match(PatternKind.Spatial, 0, 2, "159") { Graph = "keypad", Turns = 1 };

        Assert.Equal(2 * s * d, Scoring.EstimateGuesses(keypad, "159", Year), 9);
        Assert.Equal(152, Scoring.EstimateGuesses(new Match(PatternKind.Spatial, 0, 2, "159") { Graph = "keypad", Turns = 1 }, "159", Year), 9);
        Assert.Equal(864, Scoring.EstimateGuesses(new Match(PatternKind.Spatial, 0, 2, "qwe") { Graph = "qwerty", Turns = 1 }, "qwe", Year), 9);
    }

    [Fact]
    public void NCk_of_a_negative_k_is_zero() => Assert.Equal(0, Scoring.NCk(5, -1));

    [Fact]
    public void Infinite_and_undefined_guesses_saturate_at_double_max_value()
    {
        string huge = new string('x', 400);
        Assert.Equal(double.MaxValue, Scoring.EstimateGuesses(new Match(PatternKind.Bruteforce, 0, huge.Length - 1, huge), huge, Year));

        var nan = new Match(PatternKind.Repeat, 0, 1, "xx") { BaseToken = "x", BaseGuesses = double.NaN, RepeatCount = 2 };
        Assert.Equal(double.MaxValue, Scoring.EstimateGuesses(nan, "xx", Year));
    }

    // ================================================================ TextUtil

    [Fact]
    public void Code_points_with_lone_surrogates()
    {
        Assert.Equal(2, TextUtil.CountCodePoints("a\uD83D"));
        Assert.Equal(2, TextUtil.CountCodePoints("a\uDC00"));
        Assert.Equal(1, TextUtil.CountCodePoints("😀"));
        Assert.Equal(2, TextUtil.CountCodePoints("\uDE00\uD83D"));
    }

    [Fact]
    public void Truncate_boundaries()
    {
        Assert.Equal("ab\uD83D", TextUtil.Truncate("ab\uD83D", 3));
        Assert.Equal("ab", TextUtil.Truncate("ab😀", 3));
        Assert.Equal(string.Empty, TextUtil.Truncate("abc", 0));
        Assert.Equal("ab", TextUtil.Truncate("abc", 2));
    }

    [Fact]
    public void Ascii_letter_classes()
    {
        Assert.True(TextUtil.IsAsciiLower('a'));
        Assert.True(TextUtil.IsAsciiLower('z'));
        Assert.False(TextUtil.IsAsciiLower('A'));
        Assert.False(TextUtil.IsAsciiLower('{'));
        Assert.True(TextUtil.IsAsciiUpper('A'));
        Assert.True(TextUtil.IsAsciiUpper('Z'));
        Assert.False(TextUtil.IsAsciiUpper('['));
        Assert.False(TextUtil.IsAsciiUpper('a'));
    }

    // ================================================================ PasswordPolicy: options

    [Fact]
    public void Invalid_options_name_the_options_parameter()
    {
        Action<PasswordPolicyOptions>[] invalid =
        {
            o => o.MaxLength = 63,
            o => o.MinLength = 7,
            o => o.MinimumScore = 5,
            o => o.MinContextWordLength = 0,
            o => o.MinContextWordLength = 65,
            o => o.MinimumBreachOccurrences = 0,
            o => o.ReferenceYear = 999,
            o => o.ReferenceYear = 10000,
        };
        foreach (Action<PasswordPolicyOptions> configure in invalid)
            Assert.Equal("options", Assert.Throws<ArgumentOutOfRangeException>(() => Policies.Create(configure)).ParamName);
    }

    [Fact]
    public void Option_boundaries_are_accepted()
    {
        Policies.Create(o => o.MinContextWordLength = 1);
        Policies.Create(o => o.MinContextWordLength = 64);
        Policies.Create(o => o.ReferenceYear = 1000);
        Policies.Create(o => o.ReferenceYear = 9999);
    }

    [Fact]
    public void Long_blocked_passwords_are_kept_whole()
    {
        string blocked = string.Concat(Enumerable.Repeat("violet-quartz-", 8)).Substring(0, 100);
        PasswordPolicy policy = Policies.Create(o => o.BlockedPasswords.Add(blocked));

        Assert.True(policy.Evaluate(blocked).HasViolation(PasswordViolationCode.CommonPassword));
    }

    [Fact]
    public void Option_context_words_are_split_into_parts()
    {
        PasswordPolicy policy = Policies.Create(o => o.ContextWords.Add("acme-widgets"));
        Assert.True(policy.Evaluate("widgets-violet-quartz-tundra").HasViolation(PasswordViolationCode.ContainsContextWord));
    }

    // ================================================================ PasswordPolicy: length

    [Fact]
    public void Input_exactly_at_the_hard_cap_is_measured_after_normalization()
    {
        // 4 * MaxLength UTF-16 units: not oversized, so its length is that of its NFKC form ("fi" per ligature).
        string ligatures = new string('ﬁ', 4 * 128);
        PasswordPolicyResult result = Policies.Create().Evaluate(ligatures);

        Assert.Equal(1024, result.Length);
        Assert.True(result.HasViolation(PasswordViolationCode.TooLong));
    }

    [Fact]
    public void Oversized_input_is_only_checked_up_to_the_hard_cap()
    {
        string password = new string('x', 600) + "johnsmith";
        PasswordPolicyResult result = Policies.Create().Evaluate(password, new PasswordContext { UserName = "johnsmith" });

        Assert.Equal(609, result.Length);
        Assert.True(result.HasViolation(PasswordViolationCode.TooLong));
        Assert.False(result.HasViolation(PasswordViolationCode.ContainsContextWord));
    }

    // ================================================================ PasswordPolicy: texts

    [Fact]
    public void Too_short_texts()
    {
        PasswordPolicyResult result = Policies.Create().Evaluate("kq9#vR2p");

        Assert.Equal("The password must be at least 15 characters long.", result.Violations.Single(v => v.Code == PasswordViolationCode.TooShort).Message);
        Assert.Contains("Use at least 15 characters. A few unrelated words make a long password that is easy to remember.", result.Suggestions);
        Assert.All(result.Suggestions, s => Assert.False(string.IsNullOrEmpty(s)));
    }

    [Fact]
    public void Too_long_texts()
    {
        PasswordPolicyResult result = Policies.Create().Evaluate(new string('k', 129));

        Assert.Equal("The password must be at most 128 characters long.", result.Violations.Single(v => v.Code == PasswordViolationCode.TooLong).Message);
        Assert.Contains("Use at most 128 characters.", result.Suggestions);
    }

    [Fact]
    public void Common_password_texts()
    {
        PasswordPolicyResult result = Policies.Create().Evaluate("password");

        Assert.Equal("This is one of the most commonly used passwords.", result.Violations.Single(v => v.Code == PasswordViolationCode.CommonPassword).Message);
        Assert.Contains("Avoid common passwords and simple variations of them.", result.Suggestions);
        Assert.Equal("The password is too easy to guess. This is a top-10 common password.",
            result.Violations.Single(v => v.Code == PasswordViolationCode.TooWeak).Message);
        // The estimator's suggestions are passed on.
        Assert.Contains(Feedback.AddWord, result.Suggestions);
        Assert.All(result.Suggestions, s => Assert.NotNull(s));
    }

    [Fact]
    public void Context_word_texts()
    {
        PasswordPolicyResult result = Policies.Create().Evaluate("johnsmith-violet-quartz", new PasswordContext { UserName = "johnsmith" });

        Assert.Equal("The password contains your user name, email address, name or the name of this service.",
            result.Violations.Single(v => v.Code == PasswordViolationCode.ContainsContextWord).Message);
        Assert.Contains("Avoid your name, user name, email address and the name of this service.", result.Suggestions);
    }

    [Fact]
    public void Repetitive_texts()
    {
        PasswordPolicyResult result = Policies.Create().Evaluate(new string('q', 16));

        Assert.Equal("The password consists only of repeated characters, sequences or keyboard patterns.",
            result.Violations.Single(v => v.Code == PasswordViolationCode.RepetitiveOrSequential).Message);
        Assert.Contains("Avoid repeated characters, sequences like \"abc\" or \"1234\", and keyboard patterns like \"qwerty\".", result.Suggestions);
    }

    [Fact]
    public void Too_weak_without_a_warning_has_the_bare_message()
    {
        PasswordPolicyResult result = Policies.Create(o => { o.MinLength = 8; o.MinimumScore = 4; }).Evaluate("kq9#vR2px");

        Assert.Equal(3, result.Score);
        Assert.Equal(string.Empty, result.StrengthEstimate.Warning);
        Assert.Equal("The password is too easy to guess.", result.Violations.Single(v => v.Code == PasswordViolationCode.TooWeak).Message);
    }

    [Fact]
    public void An_empty_password_is_not_reported_as_common()
    {
        PasswordPolicyResult result = Policies.Create().Evaluate(string.Empty);

        Assert.True(result.HasViolation(PasswordViolationCode.TooShort));
        Assert.False(result.HasViolation(PasswordViolationCode.CommonPassword));
    }

    [Fact]
    public void The_longest_list_entry_is_blocked()
    {
        int longest = EmbeddedDictionaries.CommonPasswords.MaxWordLength;
        Assert.Equal(18, longest);
        PasswordPolicyResult result = Policies.Create(o => o.MinimumScore = 0).Evaluate("films+pic+galeries");

        Assert.True(result.HasViolation(PasswordViolationCode.CommonPassword));
    }

    [Fact]
    public void Reference_year_option_is_used_for_the_estimate()
    {
        PasswordPolicyResult result = Policies.Create(o => o.ReferenceYear = 1500).Evaluate("1990");

        Assert.Equal(PasswordStrengthEstimator.Estimate("1990", null, 1500).Guesses, result.StrengthEstimate.Guesses);
        Assert.NotEqual(PasswordStrengthEstimator.Estimate("1990", null, DateTime.UtcNow.Year).Guesses, result.StrengthEstimate.Guesses);
    }

    [Fact]
    public void Acceptable_result_to_string()
    {
        PasswordPolicyResult result = Policies.Create().Evaluate("violet-quartz-tundra-mosaic");

        Assert.True(result.IsAcceptable);
        Assert.Equal($"Acceptable (score {result.Score}, 0 violation(s))", result.ToString());
    }

    // ================================================================ PasswordPolicy: context words

    private static bool HasContextViolation(string password, PasswordContext context, int minContextWordLength = 4) =>
        Policies.Create(o => o.MinContextWordLength = minContextWordLength).Evaluate(password, context).HasViolation(PasswordViolationCode.ContainsContextWord);

    [Fact]
    public void Every_part_of_names_and_words_is_checked()
    {
        const string Password = "widgets-violet-quartz-tundra";
        Assert.True(HasContextViolation(Password, new PasswordContext { UserName = "acme-widgets" }));
        Assert.True(HasContextViolation(Password, new PasswordContext { ApplicationName = "acme-widgets" }));
        Assert.True(HasContextViolation(Password, new PasswordContext { AdditionalWords = { "acme-widgets" } }));
        Assert.True(HasContextViolation(Password, new PasswordContext { DisplayName = "acme-widgets" }));
    }

    [Fact]
    public void Email_local_part_is_checked_whole_and_in_parts()
    {
        var context = new PasswordContext { Email = "hawkins.marlow@contoso.com" };
        Assert.True(HasContextViolation("marlow-violet-quartz-tundra", context));
        Assert.True(HasContextViolation("hawkins-violet-quartz-tundra", context));
        Assert.True(HasContextViolation("contoso-violet-quartz-tundra", context));
        Assert.False(HasContextViolation("com-violet-quartz-tundra", context, minContextWordLength: 3));
    }

    [Fact]
    public void Email_starting_with_an_at_sign_drops_the_top_level_domain()
    {
        var context = new PasswordContext { Email = "@example.com" };
        Assert.True(HasContextViolation("example-violet-quartz-tundra", context));
        Assert.False(HasContextViolation("violet-com-quartz-tundra", context, minContextWordLength: 3));
    }

    [Fact]
    public void Domain_starts_after_the_at_sign()
    {
        // Only "ab" and "contoso" are context words; "b" alone is not.
        Assert.False(HasContextViolation("kq9b-zrt-plmw-x", new PasswordContext { Email = "ab@contoso.com" }, minContextWordLength: 1));
        Assert.True(HasContextViolation("kq9ab-zrt-plmw-x", new PasswordContext { Email = "ab@contoso.com" }, minContextWordLength: 1));
    }

    [Fact]
    public void Single_label_domain_is_kept()
    {
        Assert.True(HasContextViolation("localhost-violet-quartz-tundra", new PasswordContext { Email = "user@localhost" }));
    }

    [Fact]
    public void Parts_start_at_their_first_character()
    {
        var context = new PasswordContext { UserName = "abcd efgh" };
        Assert.False(HasContextViolation("xbcd-violet-tundra-quartz", context, minContextWordLength: 3));
        Assert.True(HasContextViolation("abcd-violet-tundra-quartz", context, minContextWordLength: 3));
    }

    [Fact]
    public void Whole_value_and_compact_form_are_context_words()
    {
        var context = new PasswordContext { UserName = "ab.cd" };
        // The whole value (5 code points) when the parts are too short.
        Assert.True(HasContextViolation("ab.cd-violet-quartz-tundra", context, minContextWordLength: 5));
        // The parts run together.
        Assert.True(HasContextViolation("abcd-violet-quartz-tundra", context, minContextWordLength: 4));
        Assert.False(HasContextViolation("ab-cd-violet-quartz-tundra", context, minContextWordLength: 4));
    }

    [Fact]
    public void Single_part_value_adds_no_other_word()
    {
        // The estimate sees exactly the one context word: no compact form or placeholder is added for a single part.
        const string Password = "stryker was here!";
        PasswordPolicyResult result = Policies.Create().Evaluate(Password, new PasswordContext { UserName = "john" });

        Assert.Equal(PasswordStrengthEstimator.Estimate(Password, new[] { "john" }, Year).Guesses, result.StrengthEstimate.Guesses);
        Assert.Equal(PasswordStrengthEstimator.Estimate(Password, null, Year).Guesses, result.StrengthEstimate.Guesses);
    }

    // ================================================================ Strength estimator

    [Fact]
    public void Reference_year_boundaries()
    {
        Assert.Equal(0, PasswordStrengthEstimator.Estimate(string.Empty, null, 1000).Score);
        Assert.Equal(0, PasswordStrengthEstimator.Estimate(string.Empty, null, 9999).Score);
        Assert.Equal("referenceYear", Assert.Throws<ArgumentOutOfRangeException>(() => PasswordStrengthEstimator.Estimate("x", null, 999)).ParamName);
        Assert.Equal("referenceYear", Assert.Throws<ArgumentOutOfRangeException>(() => PasswordStrengthEstimator.Estimate("x", null, 10000)).ParamName);
    }

    [Fact]
    public void Pattern_match_to_string_shows_a_half_open_range()
    {
        Assert.Equal("Dictionary [2..10)", new PatternMatch(PatternKind.Dictionary, 2, 8, DictionaryKind.CommonPasswords, false, false).ToString());

        StrengthEstimate e = PasswordStrengthEstimator.Estimate("abcd2019", null, Year);
        Assert.Equal(new[] { "Sequence [0..4)", "Year [4..8)" }, e.Sequence.Select(m => m.ToString()));
    }
}
