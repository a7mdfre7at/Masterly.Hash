using System.Collections.Generic;
using System.Linq;
using Masterly.Hash.Policy.Internal;

namespace Masterly.Hash.Policy.Tests;

/// <summary>
/// Matcher behaviour. Where a case is marked "zxcvbn", the input and expected output come from zxcvbn's
/// test/test-matching.coffee (https://github.com/dropbox/zxcvbn/blob/master/test/test-matching.coffee, MIT).
/// </summary>
public class MatchingTests
{
    private static readonly Matching Matcher = new(
        new[] { EmbeddedDictionaries.CommonPasswords, EmbeddedDictionaries.EnglishWords }, Policies.ReferenceYear);

    [Fact]
    public void Embedded_lists_load_with_frequency_ranks()
    {
        RankedDictionary common = EmbeddedDictionaries.CommonPasswords;
        Assert.True(common.Count >= 10_000, common.Count.ToString());
        Assert.True(common.TryGetRank("password", out int rank));
        Assert.Equal(1, rank);
        Assert.True(common.TryGetRank("123456", out rank));
        Assert.Equal(2, rank);
        Assert.True(common.Contains("qwerty123"));
        Assert.False(common.Contains("violet-quartz-tundra-mosaic"));

        RankedDictionary english = EmbeddedDictionaries.EnglishWords;
        Assert.True(english.Count > 500);
        Assert.Same(common, EmbeddedDictionaries.CommonPasswords);
    }

    [Fact]
    public void Dictionary_matches_words_inside_the_password()
    {
        List<Match> matches = Matcher.DictionaryMatch("xPassWordx");

        Match password = Assert.Single(matches, m => m.MatchedWord == "password" && m.Dictionary == DictionaryKind.CommonPasswords);
        Assert.Equal(1, password.I);
        Assert.Equal(8, password.J);
        Assert.Equal("PassWord", password.Token);
        Assert.Equal(1, password.Rank);
    }

    [Fact]
    public void Reverse_dictionary_matches_reversed_words()
    {
        // zxcvbn: "matches against reversed words"
        List<Match> matches = Matcher.ReverseDictionaryMatch("drowssap");

        Match m = Assert.Single(matches, x => x.MatchedWord == "password" && x.Dictionary == DictionaryKind.CommonPasswords);
        Assert.True(m.Reversed);
        Assert.Equal(0, m.I);
        Assert.Equal(7, m.J);
        Assert.Equal("drowssap", m.Token);
    }

    [Theory]
    [InlineData("p4ssw0rd", "password", new[] { '4', '0' })]
    [InlineData("P@$$W0RD", "password", new[] { '@', '$', '0' })]
    public void L33t_matches_substituted_words(string password, string word, char[] substitutes)
    {
        Match m = Assert.Single(Matcher.L33tMatch(password), x => x.MatchedWord == word && x.Dictionary == DictionaryKind.CommonPasswords && x.I == 0 && x.J == password.Length - 1);

        Assert.True(m.L33t);
        Assert.Equal(password, m.Token);
        Assert.Equal(substitutes.OrderBy(c => c), m.Sub!.Keys.OrderBy(c => c));
    }

    [Fact]
    public void L33t_does_not_report_unsubstituted_or_single_character_matches()
    {
        Assert.Empty(Matcher.L33tMatch("password"));
        Assert.DoesNotContain(Matcher.L33tMatch("4"), m => m.Token.Length <= 1);
    }

    [Theory]
    // zxcvbn: "matches '#{pattern}' as a #{keyboard} pattern"
    [InlineData("12345", "qwerty", 1, 0)]
    [InlineData("@WSX", "qwerty", 1, 4)]
    [InlineData("6tfGHJ", "qwerty", 2, 3)]
    [InlineData("hGFd", "qwerty", 1, 2)]
    [InlineData("/;p09876yhn", "qwerty", 3, 0)]
    [InlineData("Xdr%", "qwerty", 1, 2)]
    [InlineData("159-", "keypad", 1, 0)]
    [InlineData("*84", "keypad", 1, 0)]
    [InlineData("/8520", "keypad", 1, 0)]
    [InlineData("369", "keypad", 1, 0)]
    public void Spatial_patterns(string pattern, string graph, int turns, int shifted)
    {
        Match m = Assert.Single(Matcher.SpatialMatch(pattern), x => x.Graph == graph);

        Assert.Equal(0, m.I);
        Assert.Equal(pattern.Length - 1, m.J);
        Assert.Equal(turns, m.Turns);
        Assert.Equal(shifted, m.ShiftedCount);
    }

    [Fact]
    public void Spatial_ignores_runs_shorter_than_three()
    {
        // zxcvbn: "doesn't match 1- and 2-character spatial patterns"
        Assert.Empty(Matcher.SpatialMatch("qw*/"));
    }

    [Fact]
    public void Sequences_split_where_direction_changes()
    {
        // zxcvbn: password = 'abcbabc' -> abc, cba, abc
        List<Match> matches = Matching.SequenceMatch("abcbabc");

        Assert.Equal(new[] { (0, 2, true), (2, 4, false), (4, 6, true) }, matches.Select(m => (m.I, m.J, m.Ascending)));
    }

    [Theory]
    // zxcvbn: "matches '#{pattern}' as a #{name} sequence"
    [InlineData("ABC", true)]
    [InlineData("CBA", false)]
    [InlineData("PQR", true)]
    [InlineData("RQP", false)]
    [InlineData("XYZ", true)]
    [InlineData("ZYX", false)]
    [InlineData("abcd", true)]
    [InlineData("dcba", false)]
    [InlineData("jihg", false)]
    [InlineData("wxyz", true)]
    [InlineData("zxvt", false)]
    [InlineData("0369", true)]
    [InlineData("97531", false)]
    public void Sequence_patterns(string pattern, bool ascending)
    {
        Match m = Assert.Single(Matching.SequenceMatch(pattern));
        Assert.Equal((0, pattern.Length - 1, ascending), (m.I, m.J, m.Ascending));
    }

    [Fact]
    public void Sequences_ignore_large_steps_and_single_characters()
    {
        // zxcvbn: "doesn't match length-#{password.length} sequences" for '', 'a', '1'
        Assert.Empty(Matching.SequenceMatch(string.Empty));
        Assert.Empty(Matching.SequenceMatch("a"));
        Assert.Empty(Matching.SequenceMatch("1"));
        Assert.Empty(Matching.SequenceMatch("aksz"));
    }

    [Theory]
    // zxcvbn: "matches embedded repeat patterns"
    [InlineData("&&&&&", "&")]
    [InlineData("aaaaaaa", "a")]
    [InlineData("abababab", "ab")]  // identifies ab as repeat string, even though abab is also repeated
    [InlineData("aabaab", "aab")]   // matches aab instead of aa
    [InlineData("abcabcabc", "abc")]
    public void Repeat_patterns(string pattern, string baseToken)
    {
        Match m = Assert.Single(Matcher.RepeatMatch(pattern));
        Assert.Equal(0, m.I);
        Assert.Equal(pattern.Length - 1, m.J);
        Assert.Equal(baseToken, m.BaseToken);
    }

    [Fact]
    public void Repeats_inside_other_text_are_found()
    {
        // zxcvbn: prefix/suffix "y4@" + "&&&&&" + "u%7"
        Match m = Assert.Single(Matcher.RepeatMatch("y4@&&&&&u%7"));
        Assert.Equal((3, 7), (m.I, m.J));
        Assert.Empty(Matcher.RepeatMatch(string.Empty));
        Assert.Empty(Matcher.RepeatMatch("#"));
    }

    [Fact]
    public void Repeat_matching_handles_long_input_quickly()
    {
        string s = string.Concat(Enumerable.Repeat("ab1!", 25));
        var sw = System.Diagnostics.Stopwatch.StartNew();
        Matcher.RepeatMatch(s);
        Assert.True(sw.Elapsed < System.TimeSpan.FromSeconds(2));
    }

    [Theory]
    [InlineData("1900")]
    [InlineData("1999")]
    [InlineData("2000")]
    [InlineData("2026")]
    [InlineData("2099")]
    public void Years(string year)
    {
        Match m = Assert.Single(Matching.YearMatch("x" + year + "y"));
        Assert.Equal(int.Parse(year), m.Year);
        Assert.Equal((1, 4), (m.I, m.J));
    }

    [Fact]
    public void Non_years_are_ignored()
    {
        Assert.Empty(Matching.YearMatch("1899"));
        Assert.Empty(Matching.YearMatch("2100"));
        Assert.Empty(Matching.YearMatch("19"));
    }

    [Theory]
    // zxcvbn: "matches dates that use '#{sep}' as a delimiter"
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("-")]
    [InlineData("/")]
    [InlineData("\\")]
    [InlineData("_")]
    [InlineData(".")]
    public void Dates_with_each_separator(string sep)
    {
        string password = $"13{sep}2{sep}1921";
        Match m = Assert.Single(Matcher.DateMatch(password));

        Assert.Equal((0, password.Length - 1), (m.I, m.J));
        Assert.Equal((1921, 2, 13), (m.Year, m.Month, m.Day));
        Assert.Equal(sep, m.Separator);
    }

    [Theory]
    // zxcvbn: "matches dates with '#{order}' format"
    [InlineData("1/3/1991")]
    [InlineData("3/1/1991")]
    [InlineData("1991/1/3")]
    [InlineData("1991/3/1")]
    public void Date_orders(string password)
    {
        Match m = Assert.Single(Matcher.DateMatch(password));
        Assert.Equal(1991, m.Year);
        Assert.Equal(new[] { 1, 3 }, new[] { m.Month, m.Day }.OrderBy(x => x));
    }

    [Fact]
    public void Date_with_year_closest_to_reference_year()
    {
        // zxcvbn: "matches the date with year closest to REFERENCE_YEAR when ambiguous": 111504 -> 2004-11-15
        Match m = Assert.Single(Matcher.DateMatch("111504"));
        Assert.Equal((2004, 11, 15), (m.Year, m.Month, m.Day));
    }

    [Theory]
    // zxcvbn: "matches #{password}" for "#{year}#{month}#{day}" and "#{year}.#{month}.#{day}" (checks year and separator)
    [InlineData(1, 1, 1999)]
    [InlineData(11, 8, 2000)]
    [InlineData(9, 12, 2005)]
    [InlineData(22, 11, 1551)]
    public void Specific_dates(int day, int month, int year)
    {
        foreach (string sep in new[] { "", "." })
        {
            string password = $"{year}{sep}{month}{sep}{day}";
            Match m = Assert.Single(Matcher.DateMatch(password));
            Assert.Equal((0, password.Length - 1), (m.I, m.J));
            Assert.Equal(year, m.Year);
            Assert.Equal(sep, m.Separator);
        }
    }

    [Fact]
    public void Dates_padded_by_other_digits_match_the_inner_date()
    {
        // zxcvbn: "matches embedded dates": prefix/suffix around 1/1/91
        Match m = Assert.Single(Matcher.DateMatch("a1/1/91b"));
        Assert.Equal((1, 6), (m.I, m.J));
        Assert.Equal(1991, m.Year);
    }

    [Fact]
    public void Map_ints_to_dmy()
    {
        Assert.Equal((2001, 1, 1), Matching.MapIntsToDmy(1, 1, 1));    // two-digit year
        Assert.Equal((1991, 3, 1), Matching.MapIntsToDmy(1, 3, 1991));
        Assert.Null(Matching.MapIntsToDmy(0, 0, 0));
        Assert.Null(Matching.MapIntsToDmy(32, 32, 32));
        Assert.Null(Matching.MapIntsToDmy(1999, 13, 13));
        Assert.Null(Matching.MapIntsToDmy(13, 13, 1999));
        Assert.Null(Matching.MapIntsToDmy(2051, 1, 1));
        Assert.Null(Matching.MapIntsToDmy(1, 1, 500));
    }

    [Fact]
    public void Omnimatch_returns_matches_sorted_by_position()
    {
        List<Match> matches = Matcher.Omnimatch("p4ssw0rdmaelstrom11/20/91aaaa");
        for (int k = 1; k < matches.Count; k++)
        {
            Assert.True(matches[k - 1].I < matches[k].I || (matches[k - 1].I == matches[k].I && matches[k - 1].J <= matches[k].J));
        }
        Assert.Contains(matches, m => m.Pattern == PatternKind.Date && m.Token == "11/20/91");
        Assert.Contains(matches, m => m.Pattern == PatternKind.Repeat && m.Token == "aaaa");
        Assert.Contains(matches, m => m.Pattern == PatternKind.Dictionary && m.L33t && m.MatchedWord == "password");
    }
}
