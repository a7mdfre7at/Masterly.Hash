using System;
using System.Threading.Tasks;

namespace Masterly.Hash.Tool.Tests;

public class HashCommandTests
{
    [Fact]
    public async Task Stdin_PrintsHashThatVerifies()
    {
        ToolRun run = await Tool.RunAsync(new[] { "hash", "--stdin" }, "s3cret-Passw0rd\n");

        Assert.Equal(ExitCodes.Success, run.ExitCode);
        string hash = run.Out.Trim();
        Assert.StartsWith("$mh$p=test$", hash);
        Assert.True(TestHashers.Hasher().Verify("s3cret-Passw0rd", hash).IsMatch);
        Assert.DoesNotContain("s3cret-Passw0rd", run.All);
    }

    [Fact]
    public async Task Stdin_ReadsOnlyFirstLine_AndStripsCrLf_ButKeepsSpaces()
    {
        ToolRun run = await Tool.RunAsync(new[] { "hash", "--stdin" }, "  spaced pw \r\nsecond line\n");

        Assert.Equal(ExitCodes.Success, run.ExitCode);
        PasswordHasher hasher = TestHashers.Hasher();
        Assert.True(hasher.Verify("  spaced pw ", run.Out.Trim()).IsMatch);
        Assert.False(hasher.Verify("spaced pw", run.Out.Trim()).IsMatch);
    }

    [Fact]
    public async Task Stdin_WithoutTrailingNewline_Works()
    {
        ToolRun run = await Tool.RunAsync(new[] { "hash", "--stdin" }, "no-newline");

        Assert.Equal(ExitCodes.Success, run.ExitCode);
        Assert.True(TestHashers.Hasher().Verify("no-newline", run.Out.Trim()).IsMatch);
    }

    [Theory]
    [InlineData("2026c")]
    [InlineData("2026f")]
    public async Task Profile_IsHonoured(string profile)
    {
        ToolRun run = await Tool.RunAsync(new[] { "hash", "--stdin", "--profile", profile }, "pw-for-profile\n");

        Assert.Equal(ExitCodes.Success, run.ExitCode);
        Assert.StartsWith("$mh$p=" + profile + "$", run.Out.Trim());
        Assert.True(TestHashers.Hasher().Verify("pw-for-profile", run.Out.Trim()).IsMatch);
    }

    [Fact]
    public async Task UnknownProfile_IsArgumentError()
    {
        ToolRun run = await Tool.RunAsync(new[] { "hash", "--stdin", "--profile", "2019x" }, "pw\n");

        Assert.Equal(ExitCodes.Error, run.ExitCode);
        Assert.Equal(string.Empty, run.Out);
    }

    [Fact]
    public async Task Prompt_AsksTwice_WithoutEcho()
    {
        ToolRun run = await Tool.RunInteractiveAsync(new[] { "hash" }, new[] { "typed-pass", "typed-pass" });

        Assert.Equal(ExitCodes.Success, run.ExitCode);
        Assert.Equal(new[] { "Password: ", "Confirm password: " }, run.Console.Prompts);
        Assert.True(TestHashers.Hasher().Verify("typed-pass", run.Out.Trim()).IsMatch);
        Assert.DoesNotContain("typed-pass", run.All);
    }

    [Fact]
    public async Task Prompt_ConfirmationMismatch_IsError()
    {
        ToolRun run = await Tool.RunInteractiveAsync(new[] { "hash" }, new[] { "first-pass", "other-pass" });

        Assert.Equal(ExitCodes.Error, run.ExitCode);
        Assert.Equal(string.Empty, run.Out);
        Assert.Contains("do not match", run.Error);
        Assert.DoesNotContain("first-pass", run.All);
    }

    [Fact]
    public async Task Prompt_Cancelled_IsError()
    {
        ToolRun run = await Tool.RunInteractiveAsync(new[] { "hash" }, new string?[] { null });

        Assert.Equal(ExitCodes.Error, run.ExitCode);
        Assert.Contains("No password entered", run.Error);
    }

    [Fact]
    public async Task RedirectedInput_WithoutStdinFlag_IsError()
    {
        ToolRun run = await Tool.RunAsync(new[] { "hash" }, "piped\n");

        Assert.Equal(ExitCodes.Error, run.ExitCode);
        Assert.Contains("--stdin", run.Error);
        Assert.Empty(run.Console.Prompts);
    }

    [Theory]
    [InlineData("")]
    [InlineData("\n")]
    public async Task EmptyPassword_IsError(string stdin)
    {
        ToolRun run = await Tool.RunAsync(new[] { "hash", "--stdin" }, stdin);

        Assert.Equal(ExitCodes.Error, run.ExitCode);
        Assert.Equal(string.Empty, run.Out);
    }

    [Fact]
    public async Task OverlongPassword_IsError()
    {
        ToolRun run = await Tool.RunAsync(new[] { "hash", "--stdin" }, new string('x', 5000) + "\n");

        Assert.Equal(ExitCodes.Error, run.ExitCode);
        Assert.Contains("longer than 4096", run.Error);
    }

    [Fact]
    public async Task PasswordOverHasherByteLimit_IsCleanError()
    {
        // 2000 characters fit the reader but exceed the hasher's 1024-byte cap.
        ToolRun run = await Tool.RunAsync(new[] { "hash", "--stdin" }, new string('y', 2000) + "\n");

        Assert.Equal(ExitCodes.Error, run.ExitCode);
        Assert.Contains("cannot be hashed", run.Error);
        Assert.DoesNotContain(new string('y', 50), run.All);
    }

    [Theory]
    [InlineData("hash", "MyPlainPassword1")]
    [InlineData("hash", "--stdin", "MyPlainPassword1")]
    [InlineData("verify", "$mh$p=test$AAAA$BBBB", "MyPlainPassword1")]
    [InlineData("policy", "MyPlainPassword1")]
    public async Task PasswordAsArgument_IsRefused_WithoutEchoingIt(params string[] args)
    {
        ToolRun run = await Tool.RunAsync(args, "pw\n");

        Assert.Equal(ExitCodes.Error, run.ExitCode);
        Assert.Contains("never accepted on the command line", run.Error);
        Assert.DoesNotContain("MyPlainPassword1", run.All);
    }

    [Fact]
    public async Task EachHashIsSalted()
    {
        ToolRun first = await Tool.RunAsync(new[] { "hash", "--stdin" }, "same\n");
        ToolRun second = await Tool.RunAsync(new[] { "hash", "--stdin" }, "same\n");

        Assert.NotEqual(first.Out, second.Out);
    }

    [Fact]
    public async Task Unicode_IsNormalized_LikeTheLibrary()
    {
        // U+00E9 vs e + U+0301: NFKC makes them the same password (NIST SP 800-63B).
        ToolRun run = await Tool.RunAsync(new[] { "hash", "--stdin" }, "café-latte\n");

        Assert.Equal(ExitCodes.Success, run.ExitCode);
        Assert.True(TestHashers.Hasher().Verify("café-latte", run.Out.Trim()).IsMatch);
    }

    [Fact]
    public void ToolEnvironment_RejectsNullFactories()
    {
        var environment = new ToolEnvironment(new FakeConsole(string.Empty, true, Array.Empty<string?>()));

        Assert.Throws<ArgumentNullException>(() => environment.HasherOptionsFactory = null!);
        Assert.Throws<ArgumentNullException>(() => environment.BreachCheckerFactory = null!);
        Assert.Throws<ArgumentNullException>(() => environment.MeasureMilliseconds = null!);
        Assert.Throws<ArgumentNullException>(() => environment.GetEnvironmentVariable = null!);
        Assert.Throws<ArgumentNullException>(() => new ToolEnvironment(null!));
    }
}
