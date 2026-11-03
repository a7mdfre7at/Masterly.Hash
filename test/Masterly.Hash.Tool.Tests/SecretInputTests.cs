using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using Masterly.Hash.Tool.IO;

namespace Masterly.Hash.Tool.Tests;

/// <summary>Secrets read from stdin are never echoed, are decoded as UTF-8, and never appear in argument errors.</summary>
public class SecretInputTests
{
    // ---- --stdin on a terminal -------------------------------------------------------------------------------

    [Fact]
    public void Stdin_OnTerminal_IsRefused_BeforeReading()
    {
        // On a terminal the line discipline echoes what is typed, so reading the secret there would show it.
        var console = new FakeConsole("typed-secret\n", redirected: false, Array.Empty<string?>());

        var ex = Assert.Throws<ToolException>(() => PasswordInput.Read(console, fromStdin: true, confirm: false));

        Assert.Contains("expects piped input", ex.Message);
        Assert.Contains("no-echo prompt", ex.Message);
        Assert.Equal('t', (char)console.In.Peek()); // nothing was consumed
    }

    [Theory]
    [InlineData("hash", "--stdin")]
    [InlineData("policy", "--stdin")]
    [InlineData("verify", "$mh$p=test$AAAA$BBBB", "--stdin")]
    public async Task PasswordCommands_WithStdinOnTerminal_AreRefused(params string[] args)
    {
        ToolRun run = await Tool.RunOnTerminalAsync(args, "typed-secret\n");

        Assert.Equal(ExitCodes.Error, run.ExitCode);
        Assert.Contains("--stdin expects piped input", run.Error);
        Assert.DoesNotContain("typed-secret", run.All);
        Assert.Empty(run.Console.Prompts);
    }

    [Fact]
    public async Task ApiKey_KeyStdinOnTerminal_IsRefused()
    {
        ToolRun run = await Tool.RunOnTerminalAsync(new[] { "apikey", "generate", "--prefix", "mh_live", "--key-stdin" }, "c2VjcmV0\n");

        Assert.Equal(ExitCodes.Error, run.ExitCode);
        Assert.Contains("--key-stdin expects piped input", run.Error);
        Assert.Contains("--key-env", run.Error);
        Assert.Equal(string.Empty, run.Out);
    }

    // ---- stdin is decoded as UTF-8 ---------------------------------------------------------------------------

    [Fact]
    public async Task Verify_PipedUtf8Password_IsDecodedAsUtf8()
    {
        // MD5 of the UTF-8 bytes of "pässword". With the console code page (e.g. OEM 437 on Windows) the piped
        // bytes C3 A4 would decode to two other characters and the verify would fail.
        string stored = TestHashers.Md5Hex("pässword");
        byte[] stdin = Encoding.UTF8.GetBytes("pässword\n");

        ToolRun run = await Tool.RunWithStdinBytesAsync(new[] { "verify", stored, "--stdin" }, stdin);

        Assert.Equal(ExitCodes.Success, run.ExitCode);
    }

    [Fact]
    public async Task Hash_PipedUtf8Password_VerifiesWithTheRealPassword()
    {
        byte[] stdin = Encoding.UTF8.GetBytes("пароль-密码\n");

        ToolRun run = await Tool.RunWithStdinBytesAsync(new[] { "hash", "--stdin" }, stdin);

        Assert.Equal(ExitCodes.Success, run.ExitCode);
        Assert.True(TestHashers.Hasher().Verify("пароль-密码", run.Out.Trim()).IsMatch);
    }

    [Fact]
    public async Task PipedUtf8Bom_IsSkipped()
    {
        byte[] stdin = new byte[] { 0xEF, 0xBB, 0xBF }.Concat(Encoding.UTF8.GetBytes("bom-pass\n"));

        ToolRun run = await Tool.RunWithStdinBytesAsync(new[] { "hash", "--stdin" }, stdin);

        Assert.Equal(ExitCodes.Success, run.ExitCode);
        Assert.True(TestHashers.Hasher().Verify("bom-pass", run.Out.Trim()).IsMatch);
    }

    [Fact]
    public async Task PipedInvalidUtf8_IsGenericError_WithoutTheBytes()
    {
        // "Jos" + 0xE9 (Windows-1252 e-acute): not UTF-8. It must not be silently replaced by U+FFFD and hashed.
        byte[] stdin = { (byte)'J', (byte)'o', (byte)'s', 0xE9, (byte)'\n' };

        ToolRun run = await Tool.RunWithStdinBytesAsync(new[] { "hash", "--stdin" }, stdin);

        Assert.Equal(ExitCodes.Error, run.ExitCode);
        Assert.Equal(string.Empty, run.Out);
        Assert.Contains("not valid UTF-8", run.Error);
        Assert.DoesNotContain("E9", run.Error);
        Assert.DoesNotContain("Jos", run.Error);
    }

    [Fact]
    public void CreateUtf8Reader_RejectsNull()
    {
        Assert.Throws<ArgumentNullException>(() => SystemConsole.CreateUtf8Reader(null!));
    }

    // ---- argument errors never echo a possible password ------------------------------------------------------

    [Theory]
    [InlineData("hash", "--profile", "Hunter2Secret")]
    [InlineData("hash", "--profile=Hunter2Secret")]
    [InlineData("policy", "--min-length", "Hunter2Secret")]
    [InlineData("policy", "--min-length:Hunter2Secret")]
    [InlineData("hash", "@Hunter2Secret")]
    [InlineData("hsah", "Hunter2Secret")]
    [InlineData("Hunter2Secret")]
    [InlineData("verify", "$mh$p=test$AAAA$BBBB", "Hunter2Secret")]
    public async Task BadArguments_NeverEchoAPossiblePassword(params string[] args)
    {
        ToolRun run = await Tool.RunAsync(args, "pw\n");

        Assert.Equal(ExitCodes.Error, run.ExitCode);
        Assert.StartsWith("error:", run.Error);
        Assert.DoesNotContain("Hunter2Secret", run.All);
        Assert.Contains("--help", run.Error);
    }

    [Fact]
    public async Task BadProfileValue_StillNamesTheOption()
    {
        ToolRun run = await Tool.RunAsync(new[] { "hash", "--profile", "Hunter2Secret" });

        Assert.Equal(ExitCodes.Error, run.ExitCode);
        Assert.Contains("'***'", run.Error);
        Assert.Contains("2026a", run.Error);
    }

    [Fact]
    public async Task ResponseFiles_AreDisabled()
    {
        using var dir = new TempDir();
        string file = dir.File("args.rsp");
        File.WriteAllText(file, "--profile\n2026c\n");

        ToolRun run = await Tool.RunAsync(new[] { "hash", "--stdin", "@" + file }, "pw\n");

        // The '@file' token is not expanded; it is a stray argument, refused without echo.
        Assert.Equal(ExitCodes.Error, run.ExitCode);
        Assert.DoesNotContain(file, run.All);
    }

    [Fact]
    public async Task NonPasswordCommands_StillEchoTheirBadValues()
    {
        // Only password commands (and the root) redact; elsewhere the value helps and is not a secret.
        ToolRun run = await Tool.RunAsync(new[] { "audit", "-", "--format", "markdwn" });

        Assert.Equal(ExitCodes.Error, run.ExitCode);
        Assert.Contains("markdwn", run.Error);
    }

    [Fact]
    public void Redact_ReplacesQuotedTokens_AndWithholdsUnquotedOnes()
    {
        var secrets = new[] { "Hunter2Secret" };

        Assert.Equal("Argument '***' not recognized.", ToolApp.Redact("Argument 'Hunter2Secret' not recognized.", secrets));
        Assert.DoesNotContain("Hunter2Secret", ToolApp.Redact("Bad value Hunter2Secret here.", secrets));
        Assert.Equal("Required argument missing.", ToolApp.Redact("Required argument missing.", Array.Empty<string>()));
    }

    [Fact]
    public void PossibleSecrets_ExcludesCommandAndOptionNames()
    {
        var root = ToolApp.BuildRootCommand(new ToolEnvironment(new FakeConsole(string.Empty, true, Array.Empty<string?>())));

        var secrets = ToolApp.PossibleSecrets(root, new[] { "hash", "--profile", "--stdin", "@abc", "--profile=xyz", "free" });

        Assert.DoesNotContain("hash", secrets);
        Assert.DoesNotContain("--profile", secrets);
        Assert.DoesNotContain("--stdin", secrets);
        Assert.Contains("@abc", secrets);
        Assert.Contains("abc", secrets);
        Assert.Contains("xyz", secrets);
        Assert.Contains("free", secrets);
    }
}

internal static class ByteArrayExtensions
{
    public static byte[] Concat(this byte[] first, byte[] second)
    {
        var result = new byte[first.Length + second.Length];
        first.CopyTo(result, 0);
        second.CopyTo(result, first.Length);
        return result;
    }
}
