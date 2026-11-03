using System;
using System.Collections.Generic;
using System.Linq;
using Masterly.Hash.Detection.Internal;

namespace Masterly.Hash.Detection.Tests;

public class GeneratorTests
{
    public static IEnumerable<object[]> Generators() => new[]
    {
        new object[] { TweakingHoneywordGenerator.Default },
        new object[] { PasswordModelHoneywordGenerator.Default },
        new object[] { new TweakingHoneywordGenerator(1) },
        new object[] { new TweakingHoneywordGenerator(2, tweakCase: true) },
    };

    public static IEnumerable<object[]> GeneratorsAndPasswords()
    {
        string[] passwords =
        {
            "a", "7", "!", "ab", "Summer2024!", "password", "P@ssw0rd", "correct horse battery staple",
            "日本語", "   ", "x y", "ALLCAPS", "MiXeD123", "1234567890", "!!!!", "été",
        };
        foreach (object[] g in Generators())
            foreach (string p in passwords)
                yield return new[] { g[0], p };
    }

    [Theory]
    [MemberData(nameof(GeneratorsAndPasswords))]
    public void Decoys_AreDistinct_NonEmpty_AndNotTheRealPassword(IHoneywordGenerator generator, string password)
    {
        IReadOnlyList<string> decoys = generator.GenerateDecoys(password, 19);
        Assert.Equal(19, decoys.Count);
        Assert.All(decoys, d => Assert.False(string.IsNullOrEmpty(d)));
        Assert.DoesNotContain(password, decoys);
        Assert.Equal(19, decoys.Distinct(StringComparer.Ordinal).Count());
    }

    [Theory]
    [MemberData(nameof(Generators))]
    public void ManyDecoys_ForTinyPasswords_StillDistinct(IHoneywordGenerator generator)
    {
        IReadOnlyList<string> decoys = generator.GenerateDecoys("x", 999);
        Assert.Equal(999, decoys.Distinct(StringComparer.Ordinal).Count());
        Assert.DoesNotContain("x", decoys);
    }

    [Theory]
    [MemberData(nameof(Generators))]
    public void ZeroDecoys_ReturnsEmpty_AndArgumentsAreValidated(IHoneywordGenerator generator)
    {
        Assert.Empty(generator.GenerateDecoys("pw", 0));
        Assert.Throws<ArgumentNullException>(() => generator.GenerateDecoys(null!, 1));
        Assert.Throws<ArgumentException>(() => generator.GenerateDecoys("", 1));
        Assert.Throws<ArgumentOutOfRangeException>(() => generator.GenerateDecoys("pw", -1));
    }

    [Fact]
    public void Tweaking_KeepsPrefix_AndTweaksTailWithinClass()
    {
        // Juels & Rivest section 5.1 example: "BG+7y45" tail-tweaked with t = 3.
        IReadOnlyList<string> decoys = TweakingHoneywordGenerator.Default.GenerateDecoys("BG+7y45", 19);
        foreach (string decoy in decoys)
        {
            Assert.Equal(7, decoy.Length);
            Assert.StartsWith("BG+7", decoy);
            Assert.Equal(TestSupport.Pattern("BG+7y45"), TestSupport.Pattern(decoy));
        }
    }

    [Fact]
    public void Tweaking_ShortTail_WidensBeforeAppending()
    {
        // One digit has only 9 alternatives; 19 decoys force the tail to widen into the letters.
        IReadOnlyList<string> decoys = new TweakingHoneywordGenerator(1).GenerateDecoys("abc1", 19);
        Assert.All(decoys, d => Assert.Equal(TestSupport.Pattern("abc1"), TestSupport.Pattern(d)));
    }

    [Fact]
    public void Tweaking_KeepsPrefixWithNonAsciiAndSpacesVerbatim()
    {
        IReadOnlyList<string> decoys = TweakingHoneywordGenerator.Default.GenerateDecoys("naïve 42", 10);
        Assert.All(decoys, d => Assert.Equal("naïve ", d.Substring(0, 6)));
    }

    [Fact]
    public void Tweaking_CaseTweak_ChangesCaseOfTailLettersOnly()
    {
        var generator = new TweakingHoneywordGenerator(3, tweakCase: true);
        Assert.True(generator.TweakCase);
        Assert.False(TweakingHoneywordGenerator.Default.TweakCase);

        IReadOnlyList<string> decoys = generator.GenerateDecoys("prefixabc", 200);
        Assert.All(decoys, d => Assert.StartsWith("prefix", d));
        Assert.All(decoys, d => Assert.All(d.Substring(6), c => Assert.True(char.IsLetter(c))));
        // With 52 letters per position some tail must contain an upper-case letter.
        Assert.Contains(decoys, d => d.Substring(6).Any(char.IsUpper));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(17)]
    public void Tweaking_TailLengthIsValidated(int tail)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new TweakingHoneywordGenerator(tail));
    }

    [Theory]
    [InlineData("Summer2024!")]
    [InlineData("password")]
    [InlineData("P@ssw0rd")]
    [InlineData("ILoveYou")]
    [InlineData("MiXeD123")]
    [InlineData("hello world 99")]
    [InlineData("qwerty!!!")]
    public void Model_DecoysHaveTheSameCharacterClassPattern(string password)
    {
        IReadOnlyList<string> decoys = PasswordModelHoneywordGenerator.Default.GenerateDecoys(password, 19);
        foreach (string decoy in decoys)
            Assert.Equal(TestSupport.Pattern(password), TestSupport.Pattern(decoy));
    }

    [Fact]
    public void Model_DoesNotReuseTheRealPasswordsTokens()
    {
        // Tweaking would keep "Summer20"; the model replaces every run, so the prefix is not shared by most decoys.
        IReadOnlyList<string> decoys = PasswordModelHoneywordGenerator.Default.GenerateDecoys("Summer2024!", 19);
        Assert.True(decoys.Count(d => d.StartsWith("Summer", StringComparison.Ordinal)) < 5);
    }

    [Fact]
    public void Model_UsesTheSuppliedWordList()
    {
        var generator = new PasswordModelHoneywordGenerator(new[] { "alpha", "bravo", "delta", "Gamma", "echo1", "", null!, "toolongtoolongtoolongtoolongtoolong" });
        Assert.Equal(4, generator.WordCount);
        IReadOnlyList<string> decoys = generator.GenerateDecoys("tango", 3);
        Assert.All(decoys, d => Assert.Contains(d, new[] { "alpha", "bravo", "delta", "gamma" }));
    }

    [Fact]
    public void Model_FallsBackWhenTheStructureIsTooSmall()
    {
        IReadOnlyList<string> decoys = new PasswordModelHoneywordGenerator(new[] { "abc" }).GenerateDecoys("xyz", 19);
        Assert.Equal(19, decoys.Distinct().Count());
        Assert.DoesNotContain("xyz", decoys);
    }

    [Fact]
    public void Model_WordListValidation()
    {
        Assert.Throws<ArgumentNullException>(() => new PasswordModelHoneywordGenerator(null!));
        Assert.Throws<ArgumentException>(() => new PasswordModelHoneywordGenerator(new[] { "123", "", "a b" }));
        Assert.True(PasswordModelHoneywordGenerator.Default.WordCount > 300);
    }

    [Fact]
    public void Decoys_AreRandomised_BetweenCalls()
    {
        string a = string.Join("|", PasswordModelHoneywordGenerator.Default.GenerateDecoys("Summer2024!", 19));
        string b = string.Join("|", PasswordModelHoneywordGenerator.Default.GenerateDecoys("Summer2024!", 19));
        Assert.NotEqual(a, b);
    }

    [Fact]
    public void SecureRandom_IsUnbiasedEnough_AndShuffles()
    {
        var counts = new int[3];
        for (int i = 0; i < 3000; i++)
            counts[SecureRandom.Next(3)]++;
        Assert.All(counts, c => Assert.InRange(c, 800, 1200));

        Assert.Equal(0, SecureRandom.Next(1));
        Assert.Throws<ArgumentOutOfRangeException>(() => SecureRandom.Next(0));
        Assert.InRange(SecureRandom.Next(5, 7), 5, 6);

        int[] items = Enumerable.Range(0, 50).ToArray();
        SecureRandom.Shuffle(items);
        Assert.Equal(Enumerable.Range(0, 50), items.OrderBy(x => x));
        Assert.NotEqual(Enumerable.Range(0, 50), items);
    }

    [Fact]
    public void Service_WithModelGenerator_EndToEnd()
    {
        HoneywordService service = TestSupport.Service(PasswordModelHoneywordGenerator.Default);
        HoneywordRecord record = service.Create("Summer2024!");
        Assert.Equal(record.RealIndex, service.Verify("Summer2024!", record.StoredHash));
    }
}
