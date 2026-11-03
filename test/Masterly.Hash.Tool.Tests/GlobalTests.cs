using System;
using System.Threading.Tasks;

namespace Masterly.Hash.Tool.Tests;

public class GlobalTests
{
    [Theory]
    [InlineData("--help")]
    [InlineData("-h")]
    public async Task Help_ListsEveryCommand(string flag)
    {
        ToolRun run = await Tool.RunAsync(new[] { flag });

        Assert.Equal(ExitCodes.Success, run.ExitCode);
        foreach (string command in new[] { "hash", "verify", "inspect", "audit", "wrap", "bench", "policy", "pepper", "apikey" })
            Assert.Contains(command, run.Out);
    }

    [Theory]
    [InlineData("hash")]
    [InlineData("verify")]
    [InlineData("wrap")]
    [InlineData("policy")]
    public async Task CommandHelp_Works(string command)
    {
        ToolRun run = await Tool.RunAsync(new[] { command, "--help" });

        Assert.Equal(ExitCodes.Success, run.ExitCode);
        Assert.Contains("Usage:", run.Out);
    }

    [Fact]
    public async Task ApiKeyGenerateHelp_Works()
    {
        ToolRun run = await Tool.RunAsync(new[] { "apikey", "generate", "--help" });

        Assert.Equal(ExitCodes.Success, run.ExitCode);
        Assert.Contains("--key-env", run.Out);
    }

    [Fact]
    public async Task Version_PrintsToolVersion()
    {
        ToolRun run = await Tool.RunAsync(new[] { "--version" });

        Assert.Equal(ExitCodes.Success, run.ExitCode);
        Assert.Equal(ToolApp.Version, run.Out.Trim());
        Assert.Matches(@"^\d+\.\d+\.\d+", ToolApp.Version);
    }

    [Fact]
    public async Task NoArguments_IsError()
    {
        ToolRun run = await Tool.RunAsync(Array.Empty<string>());

        Assert.Equal(ExitCodes.Error, run.ExitCode);
        Assert.Contains("masterly-hash --help", run.Error);
    }

    [Fact]
    public async Task UnknownCommand_IsError()
    {
        ToolRun run = await Tool.RunAsync(new[] { "frobnicate" });

        Assert.Equal(ExitCodes.Error, run.ExitCode);
        Assert.StartsWith("error:", run.Error);
    }

    [Fact]
    public async Task UnknownOption_IsError_WithCommandHint()
    {
        ToolRun run = await Tool.RunAsync(new[] { "apikey", "generate", "--prefix", "mh", "--bogus" });

        Assert.Equal(ExitCodes.Error, run.ExitCode);
        Assert.Contains("masterly-hash apikey generate --help", run.Error);
    }

    [Fact]
    public async Task RunAsync_RejectsNulls()
    {
        var environment = new ToolEnvironment(new FakeConsole(string.Empty, true, Array.Empty<string?>()));

        await Assert.ThrowsAsync<ArgumentNullException>(() => ToolApp.RunAsync(null!, environment));
        await Assert.ThrowsAsync<ArgumentNullException>(() => ToolApp.RunAsync(Array.Empty<string>(), null!));
    }

    [Fact]
    public async Task Cancellation_ExitsWithCancelledCode()
    {
        using var cts = new System.Threading.CancellationTokenSource();
        cts.Cancel();
        var console = new FakeConsole("x\n", true, Array.Empty<string?>());
        var environment = new ToolEnvironment(console)
        {
            HasherOptionsFactory = TestHashers.Options,
            BreachCheckerFactory = () => new FakeBreachChecker(Masterly.Hash.Policy.BreachCheckResult.NotBreached),
        };

        int exit = await ToolApp.RunAsync(new[] { "policy", "--stdin", "--pwned" }, environment, cts.Token);

        Assert.Equal(ExitCodes.Cancelled, exit);
    }
}
