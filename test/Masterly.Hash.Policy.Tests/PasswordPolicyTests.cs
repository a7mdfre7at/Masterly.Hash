using System;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Masterly.Hash.Policy.Tests;

public class PasswordPolicyTests
{
    private const string Passphrase = "violet-quartz-tundra-mosaic";

    [Theory]
    [InlineData("password")]
    [InlineData("123456")]
    [InlineData("qwerty123")]
    public void Most_common_passwords_are_rejected(string password)
    {
        PasswordPolicyResult result = Policies.Create().Evaluate(password);

        Assert.False(result.IsAcceptable);
        Assert.True(result.HasViolation(PasswordViolationCode.CommonPassword));
        Assert.True(result.HasViolation(PasswordViolationCode.TooWeak));
        // qwerty123 is rank ~6,300 in the list: about 10^3.8 guesses, the bottom of score 1.
        Assert.True(result.Score <= 1);
    }

    [Theory]
    [InlineData("password")]
    [InlineData("123456")]
    public void Top_ten_passwords_score_zero(string password)
    {
        PasswordPolicyResult result = Policies.Create().Evaluate(password);

        Assert.Equal(0, result.Score);
        Assert.Equal("This is a top-10 common password.", result.StrengthEstimate.Warning);
    }

    [Theory]
    [InlineData("password")]
    [InlineData("qwerty123")]
    [InlineData("PASSWORD")]
    [InlineData("PassWord")]
    [InlineData("p@ssw0rd")]
    [InlineData("P4$$W0RD")]
    public void Blocklist_applies_even_when_the_length_is_fine_and_ignores_case_and_l33t(string password)
    {
        PasswordPolicyResult result = Policies.Create(o => { o.MinLength = 8; o.MinimumScore = 0; }).Evaluate(password);

        Assert.False(result.HasViolation(PasswordViolationCode.TooShort));
        Assert.True(result.HasViolation(PasswordViolationCode.CommonPassword));
        Assert.False(result.IsAcceptable);
    }

    [Fact]
    public void Blocklist_can_be_turned_off()
    {
        PasswordPolicyResult result = Policies.Create(o => { o.MinLength = 8; o.MinimumScore = 0; o.BlockCommonPasswords = false; }).Evaluate("password");

        Assert.False(result.HasViolation(PasswordViolationCode.CommonPassword));
        Assert.True(result.IsAcceptable);
    }

    [Fact]
    public void Custom_blocked_passwords_are_rejected_case_and_l33t_insensitive()
    {
        PasswordPolicy policy = Policies.Create(o => o.BlockedPasswords.Add("ContosoSpring2026!"));

        Assert.True(policy.Evaluate("contosospring2026!").HasViolation(PasswordViolationCode.CommonPassword));
        Assert.True(policy.Evaluate("C0NT0S0SPR1NG2026!").HasViolation(PasswordViolationCode.CommonPassword));
        Assert.False(policy.Evaluate(Passphrase).HasViolation(PasswordViolationCode.CommonPassword));
    }

    [Theory]
    [InlineData(Passphrase)]
    [InlineData("gx7#Lq2!vZ9pRm4wT8")]
    [InlineData("purple monkey dishwasher lantern")]
    [InlineData("Ünïcödé-fjord-wąż-🦊-teapot")]
    public void Long_random_passphrases_are_accepted(string password)
    {
        PasswordPolicyResult result = Policies.Create().Evaluate(password);

        Assert.True(result.IsAcceptable, string.Join("; ", result.Violations));
        Assert.Empty(result.Violations);
        Assert.True(result.Score >= 3);
        Assert.Null(result.BreachCheck);
    }

    [Fact]
    public void No_composition_rules_all_lower_case_letters_and_spaces_are_fine()
    {
        PasswordPolicyResult result = Policies.Create().Evaluate("lantern orbit cactus whisper");

        Assert.True(result.IsAcceptable, string.Join("; ", result.Violations));
    }

    [Fact]
    public void Default_minimum_is_15_and_8_is_allowed_for_mfa()
    {
        Assert.Equal(15, new PasswordPolicyOptions().MinLength);

        PasswordPolicy mfa = Policies.Create(o => { o.MinLength = 8; o.MinimumScore = 0; });
        Assert.False(mfa.Evaluate("k9#vR2pq").HasViolation(PasswordViolationCode.TooShort));
        Assert.True(mfa.Evaluate("k9#vR2p").HasViolation(PasswordViolationCode.TooShort));
    }

    [Fact]
    public void Fourteen_characters_are_too_short_by_default()
    {
        PasswordPolicyResult result = Policies.Create().Evaluate("kq9-vrz-plm-wx");

        Assert.Equal(14, result.Length);
        Assert.True(result.HasViolation(PasswordViolationCode.TooShort));
        Assert.Contains("15", result.Violations.First(v => v.Code == PasswordViolationCode.TooShort).Message);
    }

    [Fact]
    public void Length_is_counted_in_code_points_not_utf16_units()
    {
        // 15 astral-plane characters: 30 UTF-16 units, 15 code points.
        var sb = new StringBuilder();
        for (int k = 0; k < 15; k++)
            sb.Append(char.ConvertFromUtf32(0x1F400 + k * 3));
        string fifteen = sb.ToString();
        Assert.Equal(30, fifteen.Length);

        PasswordPolicyResult ok = Policies.Create(o => o.MinimumScore = 0).Evaluate(fifteen);
        Assert.Equal(15, ok.Length);
        Assert.False(ok.HasViolation(PasswordViolationCode.TooShort));

        string fourteen = fifteen.Substring(0, 28);
        PasswordPolicyResult tooShort = Policies.Create(o => o.MinimumScore = 0).Evaluate(fourteen);
        Assert.Equal(14, tooShort.Length);
        Assert.True(tooShort.HasViolation(PasswordViolationCode.TooShort));
    }

    [Fact]
    public void Length_is_counted_after_nfkc_normalization()
    {
        // 'e' + combining acute composes to one code point; the ﬀ ligature decomposes to "ff".
        string decomposed = string.Concat(Enumerable.Repeat("é", 8));
        Assert.Equal(16, decomposed.Length);
        Assert.Equal(8, Policies.Create().Evaluate(decomposed).Length);
        Assert.Equal(2, Policies.Create().Evaluate("ﬀ").Length);
    }

    [Fact]
    public void Arabic_ligature_that_expands_under_nfkc_is_measured_after_expansion()
    {
        // U+FDFA expands to 18 code points under NFKC.
        PasswordPolicyResult result = Policies.Create(o => o.MinimumScore = 0).Evaluate("ﷺ");
        Assert.Equal(18, result.Length);
        Assert.False(result.HasViolation(PasswordViolationCode.TooShort));
    }

    [Fact]
    public void At_least_64_characters_are_always_permitted()
    {
        string sixtyFour = "orbit-cactus-whisper-lantern-meadow-quartz-velvet-ember-k2v9zpx!";
        Assert.Equal(64, sixtyFour.Length);
        PasswordPolicyResult result = Policies.Create(o => o.MaxLength = 64).Evaluate(sixtyFour);
        Assert.True(result.IsAcceptable, string.Join("; ", result.Violations));

        Assert.Throws<ArgumentOutOfRangeException>(() => Policies.Create(o => o.MaxLength = 63));
    }

    [Fact]
    public void Default_maximum_is_128_code_points()
    {
        string p128 = string.Concat(Enumerable.Repeat("orbit-cactus-whisper-lantern-meadow-quartz-velvet-ember-", 3)).Substring(0, 128);
        Assert.False(Policies.Create().Evaluate(p128).HasViolation(PasswordViolationCode.TooLong));

        PasswordPolicyResult tooLong = Policies.Create().Evaluate(p128 + "x");
        Assert.True(tooLong.HasViolation(PasswordViolationCode.TooLong));
        Assert.Equal(129, tooLong.Length);
    }

    [Fact]
    public void Huge_input_is_rejected_quickly_without_throwing()
    {
        string huge = new string('x', 1_000_000);
        var sw = System.Diagnostics.Stopwatch.StartNew();
        PasswordPolicyResult result = Policies.Create().Evaluate(huge, new PasswordContext { UserName = "xxxx" });
        sw.Stop();

        Assert.True(result.HasViolation(PasswordViolationCode.TooLong));
        Assert.Equal(1_000_000, result.Length);
        Assert.True(result.StrengthEstimate.IsTruncated);
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(5), sw.Elapsed.ToString());
    }

    [Fact]
    public void Empty_password_is_rejected_and_does_not_throw()
    {
        PasswordPolicyResult result = Policies.Create().Evaluate(string.Empty);

        Assert.False(result.IsAcceptable);
        Assert.True(result.HasViolation(PasswordViolationCode.TooShort));
        Assert.Equal(0, result.Length);
        Assert.Equal(0, result.Score);
    }

    [Fact]
    public void Null_password_throws()
    {
        PasswordPolicy policy = Policies.Create();
        Assert.Throws<ArgumentNullException>(() => policy.Evaluate((string)null!));
        Assert.Throws<ArgumentNullException>(() => policy.Evaluate((SensitiveString)null!));
        Assert.Throws<ArgumentNullException>(() => new PasswordPolicy(null!));
    }

    [Theory]
    [InlineData("\uD800 lone high surrogate in a passphrase")]
    [InlineData("lone low surrogate \uDC00 in a passphrase")]
    [InlineData("\uDC00𐀀𐀀𐀀\uD800")]
    [InlineData("\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0")]
    [InlineData("tabs\tand\r\nnewlines\vand\fother controls")]
    [InlineData("‮right-to-left override passphrase")]
    [InlineData("1/1/1/1/1/1/1/1/1/1/1/1/1/1/")]
    [InlineData("--------------------------------")]
    [InlineData("@@@@@@@@||||||||11111111!!!!!!!!")]
    [InlineData("ﷺﷺﷺﷺﷺﷺ")]
    [InlineData("0000/00/00 9999-99-99 31.12.0000")]
    public async Task Malformed_or_odd_input_never_throws(string password)
    {
        PasswordPolicy policy = Policies.Create(checker: new FakeBreachChecker(BreachCheckResult.NotBreached));
        var context = new PasswordContext { UserName = "\uD800x", Email = "@@", DisplayName = "\uDC00", ApplicationName = "   " };
        context.AdditionalWords.Add(null!);
        context.AdditionalWords.Add(string.Empty);

        PasswordPolicyResult result = policy.Evaluate(password, context);

        Assert.NotNull(result.StrengthEstimate);
        Assert.InRange(result.Score, 0, 4);
        Assert.NotNull(await policy.EvaluateAsync(password, context));
    }

    [Theory]
    [InlineData("johnsmith-likes-tea-a-lot")]
    [InlineData("JohnSmith-likes-tea-a-lot")]
    [InlineData("JOHNSMITH-likes-tea-a-lot")]
    [InlineData("j0hnsm1th-likes-tea-a-lot")]
    [InlineData("J0HN5M17H-likes-tea-a-lot")]
    [InlineData("htimsnhoj-likes-tea-a-lot")]
    [InlineData("tea-a-lot-likes-Johnsmith")]
    public void User_name_inside_the_password_is_rejected_case_l33t_and_reverse_insensitive(string password)
    {
        PasswordPolicyResult result = Policies.Create().Evaluate(password, new PasswordContext { UserName = "JohnSmith" });

        Assert.True(result.HasViolation(PasswordViolationCode.ContainsContextWord));
        Assert.False(result.IsAcceptable);
    }

    [Fact]
    public void Without_context_the_same_password_is_fine()
    {
        PasswordPolicyResult result = Policies.Create().Evaluate("johnsmith-likes-tea-a-lot");
        Assert.True(result.IsAcceptable, string.Join("; ", result.Violations));
    }

    [Theory]
    [InlineData("margaret-orbit-cactus-lamp")]   // display name part
    [InlineData("thatcher-orbit-cactus-lamp")]   // display name part
    [InlineData("mthatcher-orbit-cactus-lamp")]  // email local part
    [InlineData("orbit-fabrikam-cactus-lamp")]   // email domain label
    [InlineData("orbit-cactus-contoso-lamp")]    // application name
    [InlineData("orbit-cactus-lamp-woodstock")]  // additional word
    [InlineData("orbit-tailspin-cactus-lamp")]   // options.ContextWords, split into parts
    [InlineData("orbit-maggie-cactus-lamp")]     // user name part
    public void Every_context_source_is_checked(string password)
    {
        PasswordPolicy policy = Policies.Create(o => o.ContextWords.Add("Tailspin Toys"));
        var context = new PasswordContext
        {
            UserName = "maggie_t",
            Email = "mthatcher@fabrikam.co.uk",
            DisplayName = "Margaret Thatcher",
            ApplicationName = "Contoso",
        };
        context.AdditionalWords.Add("Woodstock");

        PasswordPolicyResult result = policy.Evaluate(password, context);

        Assert.True(result.HasViolation(PasswordViolationCode.ContainsContextWord));
    }

    [Fact]
    public void Short_context_words_and_top_level_domains_are_not_violations_on_their_own()
    {
        var context = new PasswordContext { UserName = "Al", Email = "bob@example.info", DisplayName = "Al Bo" };

        PasswordPolicyResult result = Policies.Create().Evaluate("alpine information meadow river", context);

        Assert.False(result.HasViolation(PasswordViolationCode.ContainsContextWord), string.Join("; ", result.Violations));
    }

    [Fact]
    public void Min_context_word_length_is_configurable()
    {
        var context = new PasswordContext { UserName = "Al" };
        PasswordPolicyResult result = Policies.Create(o => o.MinContextWordLength = 2).Evaluate("alpine information meadow river", context);
        Assert.True(result.HasViolation(PasswordViolationCode.ContainsContextWord));
    }

    [Fact]
    public void Context_check_can_be_turned_off_but_context_still_lowers_the_estimate()
    {
        var context = new PasswordContext { UserName = "kxqvbzrt" };
        PasswordPolicyResult on = Policies.Create(o => o.MinimumScore = 0).Evaluate("kxqvbzrt-kxqvbzrt", context);
        PasswordPolicyResult off = Policies.Create(o => { o.MinimumScore = 0; o.CheckContextWords = false; }).Evaluate("kxqvbzrt-kxqvbzrt", context);
        PasswordPolicyResult none = Policies.Create(o => o.MinimumScore = 0).Evaluate("kxqvbzrt-kxqvbzrt");

        Assert.True(on.HasViolation(PasswordViolationCode.ContainsContextWord));
        Assert.False(off.HasViolation(PasswordViolationCode.ContainsContextWord));
        Assert.True(off.StrengthEstimate.Guesses < none.StrengthEstimate.Guesses);
        Assert.Contains(off.StrengthEstimate.Sequence, m => m.Dictionary == DictionaryKind.ContextWords);
    }

    [Theory]
    [InlineData("aaaaaaaaaaaaaaaa")]
    [InlineData("abcdefghijklmnop")]
    [InlineData("1234abcd1234abcd")]
    [InlineData("qwertyuiopasdfgh")]
    [InlineData("abcabcabcabcabcabc")]
    [InlineData("zyxwvutsrqponmlk")]
    [InlineData("1qaz2wsx3edc4rfv")]
    [InlineData("9876543210987654")]
    public void Repetitive_and_sequential_passwords_are_rejected(string password)
    {
        PasswordPolicyResult result = Policies.Create().Evaluate(password);

        Assert.True(result.HasViolation(PasswordViolationCode.RepetitiveOrSequential));
        Assert.False(result.IsAcceptable);
    }

    [Theory]
    [InlineData(Passphrase)]
    [InlineData("gx7#Lq2!vZ9pRm4wT8")]
    [InlineData("abcdefg-orbit-cactus")]
    public void Passwords_with_other_content_are_not_repetitive(string password)
    {
        Assert.False(Policies.Create().Evaluate(password).HasViolation(PasswordViolationCode.RepetitiveOrSequential));
    }

    [Fact]
    public void Repetitive_check_can_be_turned_off()
    {
        PasswordPolicyResult result = Policies.Create(o => o.RejectRepetitiveOrSequential = false).Evaluate("abcdefghijklmnop");
        Assert.False(result.HasViolation(PasswordViolationCode.RepetitiveOrSequential));
    }

    [Fact]
    public void Minimum_score_is_enforced_and_can_be_relaxed()
    {
        // 16 characters, not itself on the blocklist, but a common password plus a sequence.
        const string weak = "iloveyou12345678";
        PasswordPolicyResult strict = Policies.Create().Evaluate(weak);
        Assert.False(strict.HasViolation(PasswordViolationCode.CommonPassword));
        Assert.True(strict.HasViolation(PasswordViolationCode.TooWeak));
        Assert.True(strict.Score < 3);
        Assert.StartsWith("The password is too easy to guess.", strict.Violations.Single(v => v.Code == PasswordViolationCode.TooWeak).Message);

        PasswordPolicyResult relaxed = Policies.Create(o => o.MinimumScore = 0).Evaluate(weak);
        Assert.False(relaxed.HasViolation(PasswordViolationCode.TooWeak));
        Assert.Equal(strict.Score, relaxed.Score);

        Assert.True(Policies.Create(o => o.MinimumScore = 4).Evaluate("orbit-cactus-lamp").HasViolation(PasswordViolationCode.TooWeak)
            == (Policies.Create().Evaluate("orbit-cactus-lamp").Score < 4));
    }

    [Fact]
    public void Violations_are_reported_in_code_order_with_suggestions()
    {
        PasswordPolicyResult result = Policies.Create().Evaluate("password", new PasswordContext { UserName = "password" });

        PasswordViolationCode[] codes = result.Violations.Select(v => v.Code).ToArray();
        Assert.Equal(
            new[] { PasswordViolationCode.TooShort, PasswordViolationCode.CommonPassword, PasswordViolationCode.ContainsContextWord, PasswordViolationCode.TooWeak },
            codes);
        Assert.NotEmpty(result.Suggestions);
        Assert.Equal(result.Suggestions.Distinct().Count(), result.Suggestions.Count);
        Assert.Equal("Rejected (score 0, 4 violation(s))", result.ToString());
    }

    [Theory]
    [InlineData("hunter2hunter2")]
    [InlineData("kq9-vrz-plm-wx")]
    [InlineData("johnsmith-likes-tea-a-lot")]
    [InlineData("qwertyuiopasdfgh")]
    [InlineData(Passphrase)]
    public async Task Results_never_contain_the_password(string password)
    {
        PasswordPolicyResult result = await Policies.Create(checker: new FakeBreachChecker(BreachCheckResult.Breached(3)))
            .EvaluateAsync(password, new PasswordContext { UserName = "johnsmith" });

        foreach (string text in Policies.Texts(result))
            Assert.DoesNotContain(password, text, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Sensitive_string_overloads_match_the_string_overloads()
    {
        PasswordPolicy policy = Policies.Create();
        var context = new PasswordContext { UserName = "johnsmith" };

        PasswordPolicyResult plain = policy.Evaluate("johnsmith-likes-tea-a-lot", context);
        PasswordPolicyResult wrapped = policy.Evaluate(new SensitiveString("johnsmith-likes-tea-a-lot"), context);
        PasswordPolicyResult wrappedAsync = await policy.EvaluateAsync(new SensitiveString("johnsmith-likes-tea-a-lot"), context);

        Assert.Equal(plain.Violations.Select(v => v.Code), wrapped.Violations.Select(v => v.Code));
        Assert.Equal(plain.Violations.Select(v => v.Code), wrappedAsync.Violations.Select(v => v.Code));
        Assert.Equal(plain.StrengthEstimate.Guesses, wrapped.StrengthEstimate.Guesses);
        Assert.Throws<ArgumentNullException>(() => policy.EvaluateAsync((SensitiveString)null!));
    }

    [Fact]
    public void Options_are_copied_at_construction()
    {
        var options = new PasswordPolicyOptions { ReferenceYear = Policies.ReferenceYear };
        var policy = new PasswordPolicy(options);

        options.MinLength = 40;
        options.ContextWords.Add("violet");
        options.BlockedPasswords.Add(Passphrase);

        Assert.True(policy.Evaluate(Passphrase).IsAcceptable);
    }

    [Fact]
    public void Invalid_options_are_refused()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => Policies.Create(o => o.MinLength = 7));
        Assert.Throws<ArgumentOutOfRangeException>(() => Policies.Create(o => { o.MinLength = 100; o.MaxLength = 64; }));
        Assert.Throws<ArgumentOutOfRangeException>(() => Policies.Create(o => o.MaxLength = 4097));
        Assert.Throws<ArgumentOutOfRangeException>(() => Policies.Create(o => o.MinimumScore = -1));
        Assert.Throws<ArgumentOutOfRangeException>(() => Policies.Create(o => o.MinimumScore = 5));
        Assert.Throws<ArgumentOutOfRangeException>(() => Policies.Create(o => o.MinContextWordLength = 0));
        Assert.Throws<ArgumentOutOfRangeException>(() => Policies.Create(o => o.MinimumBreachOccurrences = 0));
        Assert.Throws<ArgumentOutOfRangeException>(() => Policies.Create(o => o.ReferenceYear = 99));

        // Boundaries are accepted.
        Policies.Create(o => { o.MinLength = 8; o.MaxLength = 64; o.MinimumScore = 4; });
        Policies.Create(o => { o.MinLength = 4096; o.MaxLength = 4096; o.MinimumScore = 0; });
    }

    [Fact]
    public void Default_instance_uses_the_default_options()
    {
        Assert.True(PasswordPolicy.Default.Evaluate(Passphrase).IsAcceptable);
        Assert.True(PasswordPolicy.Default.Evaluate("short").HasViolation(PasswordViolationCode.TooShort));
        IPasswordPolicy asInterface = PasswordPolicy.Default;
        Assert.False(asInterface.Evaluate("password").IsAcceptable);
    }

    [Fact]
    public void Accepted_password_round_trips_through_the_hasher()
    {
        PasswordPolicyResult result = Policies.Create().Evaluate(Passphrase);
        Assert.True(result.IsAcceptable);

        PasswordHasher hasher = Policies.FastHasher();
        string stored = hasher.Hash(Passphrase);
        Assert.True(hasher.Verify(Passphrase, stored).IsMatch);
    }

    [Fact]
    public void Violation_requires_a_message()
    {
        Assert.Throws<ArgumentNullException>(() => new PasswordViolation(PasswordViolationCode.TooWeak, null!));
        Assert.Equal("TooWeak: m", new PasswordViolation(PasswordViolationCode.TooWeak, "m").ToString());
    }
}
