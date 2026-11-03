using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Masterly.Hash.Policy;

namespace Masterly.Hash.Tool.Tests;

public class BenchCommandTests
{
    private static Action<ToolEnvironment> Clock(double server, double constrained, double fips) =>
        e => e.MeasureMilliseconds = p => p.Id switch
        {
            "2026a" => server,
            "2026c" => constrained,
            "2026f" => fips,
            _ => throw new InvalidOperationException("unexpected profile"),
        };

    [Fact]
    public async Task FastMachine_RecommendsServer()
    {
        ToolRun run = await Tool.RunAsync(new[] { "bench" }, configure: Clock(120, 40, 90));

        Assert.Equal(ExitCodes.Success, run.ExitCode);
        Assert.Contains("Recommendation: Server2026a", run.Out);
        Assert.Contains("| 2026a | Argon2id m=65536 KiB, t=3, p=1 | 120.0 |", run.Out);
        Assert.Contains("| 2026f | PBKDF2-SHA512 i=210000 | 90.0 |", run.Out);
        Assert.Contains("| 120.0 | 40.0 | 90.0 | Server2026a |", run.Out);
        Assert.Contains("| OS | Arch | Cores | Runtime |", run.Out);
    }

    [Fact]
    public async Task SlowMachine_RecommendsConstrained()
    {
        ToolRun run = await Tool.RunAsync(new[] { "bench", "--target-ms", "100" }, configure: Clock(400, 90, 200));

        Assert.Equal(ExitCodes.Success, run.ExitCode);
        Assert.Contains("Recommendation: Constrained2026a", run.Out);
        Assert.DoesNotContain("Even 2026c", run.Out);
        Assert.Contains("| Constrained2026a |", run.Out);
    }

    [Fact]
    public async Task VerySlowMachine_WarnsNotToGoLower()
    {
        ToolRun run = await Tool.RunAsync(new[] { "bench", "--target-ms", "50" }, configure: Clock(400, 90, 200));

        Assert.Contains("Recommendation: Constrained2026a", run.Out);
        Assert.Contains("Even 2026c exceeds the target", run.Out);
    }

    [Fact]
    public async Task TargetBoundary_IsInclusive()
    {
        ToolRun run = await Tool.RunAsync(new[] { "bench", "--target-ms", "250" }, configure: Clock(250, 60, 100));

        Assert.Contains("Recommendation: Server2026a", run.Out);
    }

    [Fact]
    public async Task UsesMedianOfFive_AfterWarmup()
    {
        var calls = new Dictionary<string, int>();
        var sequence = new[] { 10_000.0, 50, 10, 30, 20, 40 };
        ToolRun run = await Tool.RunAsync(new[] { "bench" }, configure: e => e.MeasureMilliseconds = p =>
        {
            calls.TryGetValue(p.Id, out int n);
            calls[p.Id] = n + 1;
            return sequence[n];
        });

        Assert.Equal(ExitCodes.Success, run.ExitCode);
        Assert.Equal(6, calls["2026a"]);
        Assert.Equal(6, calls["2026c"]);
        Assert.Equal(6, calls["2026f"]);
        Assert.Contains("| 30.0 | 30.0 | 30.0 | Server2026a |", run.Out);
    }

    [Theory]
    [InlineData("0")]
    [InlineData("-5")]
    [InlineData("60001")]
    [InlineData("soon")]
    public async Task BadTarget_IsError(string target)
    {
        ToolRun run = await Tool.RunAsync(new[] { "bench", "--target-ms", target }, configure: Clock(1, 1, 1));

        Assert.Equal(ExitCodes.Error, run.ExitCode);
    }

    [Fact]
    public void MeasureOnce_TimesARealHash()
    {
        double ms = ToolEnvironment.MeasureOnce(TestHashers.Profile);

        Assert.True(ms > 0);
        Assert.Throws<ArgumentNullException>(() => ToolEnvironment.MeasureOnce(null!));
    }
}

public class PolicyCommandTests
{
    private const string Strong = "vX9#mQ2$pL7@nR4!kT8&";

    [Fact]
    public async Task CommonPassword_IsRejected()
    {
        ToolRun run = await Tool.RunAsync(new[] { "policy", "--stdin" }, "password1\n");

        Assert.Equal(ExitCodes.Failure, run.ExitCode);
        Assert.Contains("Result:     Rejected", run.Out);
        Assert.Contains("Score:      0/4", run.Out);
        Assert.Contains("TooShort", run.Out);
        Assert.Contains("CommonPassword", run.Out);
        Assert.Contains("Suggestions:", run.Out);
        Assert.Contains("online, rate-limited (100/hour)", run.Out);
        Assert.Contains("offline, fast hash", run.Out);
        Assert.Contains("Breach check: skipped (offline)", run.Out);
        Assert.DoesNotContain("password1", run.All);
    }

    [Fact]
    public async Task StrongPassword_IsAcceptable()
    {
        ToolRun run = await Tool.RunAsync(new[] { "policy", "--stdin" }, Strong + "\n");

        Assert.Equal(ExitCodes.Success, run.ExitCode);
        Assert.Contains("Result:     Acceptable", run.Out);
        Assert.Contains("Score:      4/4", run.Out);
        Assert.DoesNotContain("Violations:", run.Out);
        Assert.DoesNotContain(Strong, run.All);
    }

    [Fact]
    public async Task Prompt_IsUsedOnTerminal()
    {
        ToolRun run = await Tool.RunInteractiveAsync(new[] { "policy" }, new[] { Strong });

        Assert.Equal(ExitCodes.Success, run.ExitCode);
        Assert.Equal(new[] { "Password: " }, run.Console.Prompts);
    }

    [Fact]
    public async Task MinLength_IsApplied()
    {
        const string twelve = "Zq8#Lp2!Wv5&";
        ToolRun defaults = await Tool.RunAsync(new[] { "policy", "--stdin" }, twelve + "\n");
        ToolRun relaxed = await Tool.RunAsync(new[] { "policy", "--stdin", "--min-length", "12" }, twelve + "\n");

        Assert.Contains("TooShort", defaults.Out);
        Assert.DoesNotContain("TooShort", relaxed.Out);
    }

    [Theory]
    [InlineData("7")]
    [InlineData("129")]
    [InlineData("x")]
    public async Task BadMinLength_IsError(string value)
    {
        ToolRun run = await Tool.RunAsync(new[] { "policy", "--stdin", "--min-length", value }, Strong + "\n");

        Assert.Equal(ExitCodes.Error, run.ExitCode);
    }

    [Fact]
    public async Task UserName_IsAContextWord()
    {
        ToolRun run = await Tool.RunAsync(new[] { "policy", "--stdin", "--user-name", "margaret" }, "margaret-vX9#mQ2$pL7\n");

        Assert.Equal(ExitCodes.Failure, run.ExitCode);
        Assert.Contains("ContainsContextWord", run.Out);
    }

    [Fact]
    public async Task Pwned_Breached_IsRejectedAndLabelledOnline()
    {
        var checker = new FakeBreachChecker(BreachCheckResult.Breached(42));

        ToolRun run = await Tool.RunAsync(new[] { "policy", "--stdin", "--pwned" }, Strong + "\n", e => e.BreachCheckerFactory = () => checker);

        Assert.Equal(ExitCodes.Failure, run.ExitCode);
        Assert.Contains("Breached", run.Out);
        Assert.Contains("Breach check (online, Have I Been Pwned k-anonymity): BREACHED: seen 42 times", run.Out);
        Assert.Contains("online", run.Error);
        Assert.Equal(new[] { Strong }, checker.Checked);
        Assert.True(checker.Disposed);
    }

    [Fact]
    public async Task Pwned_NotBreached_IsAcceptable()
    {
        var checker = new FakeBreachChecker(BreachCheckResult.NotBreached);

        ToolRun run = await Tool.RunAsync(new[] { "policy", "--stdin", "--pwned" }, Strong + "\n", e => e.BreachCheckerFactory = () => checker);

        Assert.Equal(ExitCodes.Success, run.ExitCode);
        Assert.Contains("not found in known breaches", run.Out);
    }

    [Fact]
    public async Task Pwned_Unavailable_FailsClosed_WithErrorExitCode()
    {
        // A script running `policy --pwned && create_account` must not take "could not check" for "not breached".
        var checker = new FakeBreachChecker(BreachCheckResult.Unavailable);

        ToolRun run = await Tool.RunAsync(new[] { "policy", "--stdin", "--pwned" }, Strong + "\n", e => e.BreachCheckerFactory = () => checker);

        Assert.Equal(ExitCodes.Error, run.ExitCode);
        Assert.Contains("unavailable", run.Out);
        Assert.Contains("error:", run.Error);
        Assert.Contains("--allow-unavailable", run.Error);
        Assert.DoesNotContain(Strong, run.All);
    }

    [Fact]
    public async Task Pwned_Unavailable_WithAllowUnavailable_JudgesWithoutIt()
    {
        var checker = new FakeBreachChecker(BreachCheckResult.Unavailable);

        ToolRun run = await Tool.RunAsync(new[] { "policy", "--stdin", "--pwned", "--allow-unavailable" }, Strong + "\n", e => e.BreachCheckerFactory = () => checker);

        Assert.Equal(ExitCodes.Success, run.ExitCode);
        Assert.Contains("unavailable", run.Out);
    }

    [Fact]
    public async Task Pwned_Unavailable_RejectedPassword_IsStillRejected()
    {
        var checker = new FakeBreachChecker(BreachCheckResult.Unavailable);

        ToolRun run = await Tool.RunAsync(new[] { "policy", "--stdin", "--pwned", "--user-name", "margaret" },
            "margaret-vX9#mQ2$pL7\n", e => e.BreachCheckerFactory = () => checker);

        Assert.Equal(ExitCodes.Failure, run.ExitCode);
    }

    [Fact]
    public async Task AllowUnavailable_WithoutPwned_IsError()
    {
        ToolRun run = await Tool.RunAsync(new[] { "policy", "--stdin", "--allow-unavailable" }, Strong + "\n");

        Assert.Equal(ExitCodes.Error, run.ExitCode);
        Assert.Contains("only applies with --pwned", run.Error);
    }

    [Fact]
    public async Task Pwned_TooShort_SkipsLookup()
    {
        var checker = new FakeBreachChecker(BreachCheckResult.Breached(1));

        ToolRun run = await Tool.RunAsync(new[] { "policy", "--stdin", "--pwned" }, "abc\n", e => e.BreachCheckerFactory = () => checker);

        Assert.Equal(ExitCodes.Failure, run.ExitCode);
        Assert.Contains("not performed", run.Out);
        Assert.Empty(checker.Checked);
    }

    [Fact]
    public async Task WithoutPwned_NeverCreatesAChecker()
    {
        // The default test environment throws if the checker factory is used.
        ToolRun run = await Tool.RunAsync(new[] { "policy", "--stdin" }, Strong + "\n");

        Assert.Equal(ExitCodes.Success, run.ExitCode);
    }
}
