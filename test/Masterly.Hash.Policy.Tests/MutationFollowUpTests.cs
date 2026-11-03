using System;

namespace Masterly.Hash.Policy.Tests;

/// <summary>
/// Second mutation-testing pass: exact exception messages (these reach configuration-error logs and callers)
/// and the e-mail-without-at-sign context-word path.
/// </summary>
public class MutationFollowUpTests
{
    /// <summary>The exact message the runtime builds for the given parameter, actual value and text.</summary>
    private static string Expected(string paramName, object actual, string text) =>
        new ArgumentOutOfRangeException(paramName, actual, text).Message;

    private static void AssertRejected(Action<PasswordPolicyOptions> configure, object actual, string text)
    {
        var ex = Assert.Throws<ArgumentOutOfRangeException>(() => Policies.Create(configure));
        Assert.Equal("options", ex.ParamName);
        Assert.Equal(actual, ex.ActualValue);
        Assert.Equal(Expected("options", actual, text), ex.Message);
        Assert.StartsWith(text, ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Breached_with_no_occurrences_explains_the_rule()
    {
        var ex = Assert.Throws<ArgumentOutOfRangeException>(() => BreachCheckResult.Breached(0));
        Assert.Equal("occurrences", ex.ParamName);
        Assert.Equal(0L, ex.ActualValue);
        Assert.Equal(Expected("occurrences", 0L, "A breached password occurs at least once."), ex.Message);
        Assert.StartsWith("A breached password occurs at least once.", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Max_length_out_of_range_explains_the_rule()
    {
        AssertRejected(o => o.MaxLength = 63, 63,
            "MaxLength must be between 64 and 4096 (NIST SP 800-63B: permit at least 64 characters).");
    }

    [Fact]
    public void Min_length_out_of_range_explains_the_rule()
    {
        AssertRejected(o => o.MinLength = 7, 7, "MinLength must be at least 8 (NIST SP 800-63B) and at most MaxLength.");
    }

    [Fact]
    public void Minimum_score_out_of_range_explains_the_rule()
    {
        AssertRejected(o => o.MinimumScore = 5, 5, "MinimumScore must be between 0 and 4.");
    }

    [Fact]
    public void Min_context_word_length_out_of_range_explains_the_rule()
    {
        AssertRejected(o => o.MinContextWordLength = 0, 0, "MinContextWordLength must be between 1 and 64.");
    }

    [Fact]
    public void Minimum_breach_occurrences_out_of_range_explains_the_rule()
    {
        AssertRejected(o => o.MinimumBreachOccurrences = 0, 0, "MinimumBreachOccurrences must be at least 1.");
    }

    [Fact]
    public void Reference_year_out_of_range_explains_the_rule()
    {
        AssertRejected(o => o.ReferenceYear = 999, 999, "ReferenceYear must have four digits.");
    }

    [Fact]
    public void Estimator_reference_year_out_of_range_explains_the_rule()
    {
        var ex = Assert.Throws<ArgumentOutOfRangeException>(() => PasswordStrengthEstimator.Estimate("x", null, 999));
        Assert.Equal("referenceYear", ex.ParamName);
        Assert.Equal(999, ex.ActualValue);
        Assert.Equal(Expected("referenceYear", 999, "Reference year must have four digits."), ex.Message);
        Assert.StartsWith("Reference year must have four digits.", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Email_without_an_at_sign_is_not_treated_as_a_domain()
    {
        // Without an '@' the whole value is a name: every part counts, including the last one
        // (a domain would drop it as the top-level label), and so do the whole and compact forms.
        var context = new PasswordContext { Email = "hawkins.marlow" };
        PasswordPolicy policy = Policies.Create();

        Assert.True(policy.Evaluate("marlow-violet-quartz-tundra", context).HasViolation(PasswordViolationCode.ContainsContextWord));
        Assert.True(policy.Evaluate("hawkinsmarlow-violet-quartz", context).HasViolation(PasswordViolationCode.ContainsContextWord));
        Assert.False(policy.Evaluate("zebra-violet-quartz-tundra", context).HasViolation(PasswordViolationCode.ContainsContextWord));
    }
}
