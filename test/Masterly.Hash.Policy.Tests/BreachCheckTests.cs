using System;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace Masterly.Hash.Policy.Tests;

public class BreachCheckTests
{
    private const string Passphrase = "violet-quartz-tundra-mosaic";

    [Fact]
    public async Task Breached_password_is_a_violation()
    {
        var checker = new FakeBreachChecker(BreachCheckResult.Breached(42));
        PasswordPolicyResult result = await Policies.Create(checker: checker).EvaluateAsync(Passphrase);

        Assert.False(result.IsAcceptable);
        Assert.True(result.HasViolation(PasswordViolationCode.Breached));
        Assert.NotNull(result.BreachCheck);
        Assert.True(result.BreachCheck!.IsBreached);
        Assert.Equal(42, result.BreachCheck.Occurrences);
        Assert.Equal(BreachCheckStatus.Ok, result.BreachCheck.Status);
        Assert.False(result.BreachCheckUnavailable);
        Assert.Equal(1, checker.Calls);
    }

    [Fact]
    public async Task Not_breached_password_is_accepted()
    {
        var checker = new FakeBreachChecker(BreachCheckResult.NotBreached);
        PasswordPolicyResult result = await Policies.Create(checker: checker).EvaluateAsync(Passphrase);

        Assert.True(result.IsAcceptable);
        Assert.Same(BreachCheckResult.NotBreached, result.BreachCheck);
    }

    [Fact]
    public async Task Unavailable_corpus_is_not_a_violation_but_is_surfaced()
    {
        var checker = new FakeBreachChecker(BreachCheckResult.Unavailable);
        PasswordPolicyResult result = await Policies.Create(checker: checker).EvaluateAsync(Passphrase);

        Assert.True(result.IsAcceptable);
        Assert.False(result.HasViolation(PasswordViolationCode.Breached));
        Assert.True(result.BreachCheckUnavailable);
        Assert.Equal(BreachCheckStatus.Unavailable, result.BreachCheck!.Status);
        Assert.False(result.BreachCheck.IsBreached);
    }

    [Fact]
    public async Task Throwing_checker_is_treated_as_unavailable_and_the_exception_is_not_surfaced()
    {
        var checker = FakeBreachChecker.Throwing(new HttpRequestException("boom " + Passphrase));
        PasswordPolicyResult result = await Policies.Create(checker: checker).EvaluateAsync(Passphrase);

        Assert.True(result.IsAcceptable);
        Assert.True(result.BreachCheckUnavailable);
        foreach (string text in Policies.Texts(result))
            Assert.DoesNotContain("boom", text, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Faulted_value_task_is_treated_as_unavailable()
    {
        var checker = new FakeBreachChecker(async (_, _) =>
        {
            await Task.Yield();
            throw new TimeoutException();
        });
        PasswordPolicyResult result = await Policies.Create(checker: checker).EvaluateAsync(Passphrase);

        Assert.True(result.BreachCheckUnavailable);
    }

    [Fact]
    public async Task Null_result_is_treated_as_unavailable()
    {
        PasswordPolicyResult result = await Policies.Create(checker: new FakeBreachChecker((BreachCheckResult?)null)).EvaluateAsync(Passphrase);

        Assert.True(result.BreachCheckUnavailable);
        Assert.True(result.IsAcceptable);
    }

    [Fact]
    public async Task Checker_timeout_that_is_not_our_cancellation_is_unavailable()
    {
        // e.g. HttpClient's own timeout surfaces as TaskCanceledException without the caller cancelling.
        var checker = FakeBreachChecker.Throwing(new TaskCanceledException());
        PasswordPolicyResult result = await Policies.Create(checker: checker).EvaluateAsync(Passphrase);

        Assert.True(result.BreachCheckUnavailable);
    }

    [Fact]
    public async Task Caller_cancellation_propagates()
    {
        using var cts = new CancellationTokenSource();
        var checker = new FakeBreachChecker((_, token) =>
        {
            cts.Cancel();
            token.ThrowIfCancellationRequested();
            return new ValueTask<BreachCheckResult>(BreachCheckResult.NotBreached);
        });

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => Policies.Create(checker: checker).EvaluateAsync(Passphrase, null, cts.Token).AsTask());
    }

    [Fact]
    public async Task Already_cancelled_token_throws_before_checking()
    {
        var checker = new FakeBreachChecker(BreachCheckResult.NotBreached);
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => Policies.Create(checker: checker).EvaluateAsync(Passphrase, null, cts.Token).AsTask());
        Assert.Equal(0, checker.Calls);
    }

    [Fact]
    public async Task Token_is_passed_to_the_checker()
    {
        using var cts = new CancellationTokenSource();
        CancellationToken seen = default;
        var checker = new FakeBreachChecker((_, token) =>
        {
            seen = token;
            return new ValueTask<BreachCheckResult>(BreachCheckResult.NotBreached);
        });

        await Policies.Create(checker: checker).EvaluateAsync(Passphrase, null, cts.Token);

        Assert.Equal(cts.Token, seen);
    }

    [Fact]
    public async Task Checker_receives_the_nfkc_normalized_password()
    {
        var checker = new FakeBreachChecker(BreachCheckResult.NotBreached);
        // U+FB00 (ﬀ) normalizes to "ff"; e + combining acute to é.
        await Policies.Create(checker: checker).EvaluateAsync("violet-ﬀjord-tundra-café");

        Assert.Equal("violet-ffjord-tundra-café", Assert.Single(checker.Received));
    }

    [Fact]
    public async Task Minimum_occurrences_threshold_is_respected()
    {
        var checker = new FakeBreachChecker(BreachCheckResult.Breached(3));
        PasswordPolicyResult result = await Policies.Create(o => o.MinimumBreachOccurrences = 10, checker).EvaluateAsync(Passphrase);

        Assert.True(result.IsAcceptable);
        Assert.True(result.BreachCheck!.IsBreached);
        Assert.Equal(3, result.BreachCheck.Occurrences);

        PasswordPolicyResult atThreshold = await Policies.Create(o => o.MinimumBreachOccurrences = 3, checker).EvaluateAsync(Passphrase);
        Assert.True(atThreshold.HasViolation(PasswordViolationCode.Breached));
    }

    [Fact]
    public void Synchronous_evaluate_never_calls_the_checker()
    {
        var checker = new FakeBreachChecker(BreachCheckResult.Breached(1));
        PasswordPolicyResult result = Policies.Create(checker: checker).Evaluate(Passphrase);

        Assert.True(result.IsAcceptable);
        Assert.Null(result.BreachCheck);
        Assert.False(result.BreachCheckUnavailable);
        Assert.Equal(0, checker.Calls);
    }

    [Theory]
    [InlineData("short")]
    [InlineData("")]
    public async Task Length_rejected_passwords_are_not_sent_to_the_checker(string password)
    {
        var checker = new FakeBreachChecker(BreachCheckResult.NotBreached);
        PasswordPolicyResult result = await Policies.Create(checker: checker).EvaluateAsync(password);

        Assert.False(result.IsAcceptable);
        Assert.Null(result.BreachCheck);
        Assert.Equal(0, checker.Calls);

        await Policies.Create(checker: checker).EvaluateAsync(new string('k', 500));
        Assert.Equal(0, checker.Calls);
    }

    [Fact]
    public async Task Without_a_checker_async_matches_sync()
    {
        PasswordPolicy policy = Policies.Create();
        PasswordPolicyResult sync = policy.Evaluate("iloveyou12345678");
        PasswordPolicyResult async = await policy.EvaluateAsync("iloveyou12345678");

        Assert.Equal(sync.Violations.Count, async.Violations.Count);
        Assert.Equal(sync.Score, async.Score);
        Assert.Null(async.BreachCheck);
    }

    [Fact]
    public async Task Breached_violation_is_ordered_last_among_other_violations()
    {
        var checker = new FakeBreachChecker(BreachCheckResult.Breached(1_000_000));
        PasswordPolicyResult result = await Policies.Create(checker: checker).EvaluateAsync("iloveyou12345678");

        Assert.Equal(PasswordViolationCode.Breached, result.Violations[result.Violations.Count - 1].Code);
        Assert.True(result.HasViolation(PasswordViolationCode.TooWeak));
    }

    [Fact]
    public void Breach_result_factories()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => BreachCheckResult.Breached(0));
        Assert.Throws<ArgumentOutOfRangeException>(() => BreachCheckResult.Breached(-5));

        BreachCheckResult big = BreachCheckResult.Breached(10_000_000_000L);
        Assert.Equal(10_000_000_000L, big.Occurrences);
        Assert.Equal("Breached (10000000000 occurrences)", big.ToString());
        Assert.Equal("Not breached", BreachCheckResult.NotBreached.ToString());
        Assert.Equal("Unavailable", BreachCheckResult.Unavailable.ToString());
        Assert.False(BreachCheckResult.Unavailable.IsBreached);
        Assert.Equal(0, BreachCheckResult.NotBreached.Occurrences);
    }

    [Fact]
    public async Task Null_password_throws_async()
    {
        await Assert.ThrowsAsync<ArgumentNullException>(() => Policies.Create().EvaluateAsync((string)null!).AsTask());
    }
}
