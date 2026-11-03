using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Masterly.Hash.Pepper;
using Masterly.Hash.Tokens;

namespace Masterly.Hash.Tool.Tests;

public class PepperCommandTests
{
    [Fact]
    public async Task Generate_PrintsBase64Of32RandomBytes()
    {
        ToolRun first = await Tool.RunAsync(new[] { "pepper", "generate" });
        ToolRun second = await Tool.RunAsync(new[] { "pepper", "generate" });

        Assert.Equal(ExitCodes.Success, first.ExitCode);
        byte[] key = Convert.FromBase64String(first.Out.Trim());
        Assert.Equal(32, key.Length);
        Assert.NotEqual(first.Out, second.Out);
        Assert.Contains("secret store", first.Error);

        // The key is usable as an HmacPepper key.
        var pepper = HmacPepper.FromBase64("k1", new Dictionary<string, string> { ["k1"] = first.Out.Trim() });
        Assert.Equal("k1", pepper.CurrentKeyId);
    }

    [Fact]
    public async Task PepperWithoutSubcommand_IsError()
    {
        ToolRun run = await Tool.RunAsync(new[] { "pepper" });

        Assert.Equal(ExitCodes.Error, run.ExitCode);
    }
}

public class ApiKeyCommandTests
{
    private static Dictionary<string, string> Parse(string output) =>
        output.Split('\n', StringSplitOptions.RemoveEmptyEntries)
            .Select(line => line.Split(':', 2))
            .Where(parts => parts.Length == 2)
            .ToDictionary(parts => parts[0].Trim(), parts => parts[1].Trim());

    [Fact]
    public async Task Generate_WithNewLookupKey()
    {
        ToolRun run = await Tool.RunAsync(new[] { "apikey", "generate", "--prefix", "mh_live" });

        Assert.Equal(ExitCodes.Success, run.ExitCode);
        Dictionary<string, string> fields = Parse(run.Out);
        string apiKey = fields["API key"];
        Assert.StartsWith("mh_live_", apiKey);
        Assert.True(ApiKey.HasValidChecksum(apiKey));
        Assert.StartsWith("k1:", fields["Lookup hash"]);
        Assert.Equal("k1", fields["Lookup key id"]);
        Assert.Equal("mh_live_..." + apiKey.Substring(apiKey.Length - 4), fields["Hint"]);

        byte[] lookupKey = Convert.FromBase64String(fields["Lookup key"]);
        Assert.Equal(32, lookupKey.Length);
        var hasher = new ApiKeyHasher(new HmacKeyRing("k1", lookupKey));
        Assert.True(hasher.Verify(apiKey, fields["Lookup hash"]));
        Assert.False(hasher.Verify(apiKey + "x", fields["Lookup hash"]));
        Assert.Contains("secret store", run.Error);
    }

    [Fact]
    public async Task Generate_WithKeyFromEnvironment()
    {
        byte[] key = HmacKeyRing.GenerateKey();
        string base64 = Convert.ToBase64String(key);

        ToolRun run = await Tool.RunAsync(
            new[] { "apikey", "generate", "--prefix", "acme_test2", "--key-env", "API_LOOKUP_KEY", "--key-id", "2026-01", "--entropy-bytes", "16" },
            configure: e => e.GetEnvironmentVariable = name => name == "API_LOOKUP_KEY" ? base64 : null);

        Assert.Equal(ExitCodes.Success, run.ExitCode);
        Dictionary<string, string> fields = Parse(run.Out);
        Assert.Equal("(provided from environment variable API_LOOKUP_KEY)", fields["Lookup key"]);
        Assert.DoesNotContain(base64, run.All);
        Assert.True(ApiKey.TryParse(fields["API key"], out ApiKeyParts? parts));
        Assert.Equal("acme_test2", parts!.Prefix);
        Assert.Equal(16, parts.EntropyBytes);
        Assert.True(new ApiKeyHasher(new HmacKeyRing("2026-01", key)).Verify(fields["API key"], fields["Lookup hash"]));
    }

    [Fact]
    public async Task Generate_WithKeyFromStdin()
    {
        byte[] key = HmacKeyRing.GenerateKey();
        string base64 = Convert.ToBase64String(key);

        ToolRun run = await Tool.RunAsync(new[] { "apikey", "generate", "--prefix", "mh", "--key-stdin" }, base64 + "\r\n");

        Assert.Equal(ExitCodes.Success, run.ExitCode);
        Dictionary<string, string> fields = Parse(run.Out);
        Assert.DoesNotContain(base64, run.All);
        Assert.True(new ApiKeyHasher(new HmacKeyRing("k1", key)).Verify(fields["API key"], fields["Lookup hash"]));
    }

    [Theory]
    [InlineData("1abc")]
    [InlineData("mh__live")]
    [InlineData("mh_")]
    [InlineData("mh-live")]
    [InlineData("abcdefghijklmnopqrstuvwxyzabcdefg")]
    public async Task InvalidPrefix_IsError(string prefix)
    {
        ToolRun run = await Tool.RunAsync(new[] { "apikey", "generate", "--prefix", prefix });

        Assert.Equal(ExitCodes.Error, run.ExitCode);
        Assert.Contains("--prefix", run.Error);
        Assert.Equal(string.Empty, run.Out);
    }

    [Fact]
    public async Task MissingPrefix_IsError()
    {
        ToolRun run = await Tool.RunAsync(new[] { "apikey", "generate" });

        Assert.Equal(ExitCodes.Error, run.ExitCode);
        Assert.Contains("--prefix", run.Error);
    }

    [Theory]
    [InlineData("--key-id", "bad id")]
    [InlineData("--entropy-bytes", "15")]
    [InlineData("--entropy-bytes", "65")]
    public async Task InvalidOptions_AreErrors(string option, string value)
    {
        ToolRun run = await Tool.RunAsync(new[] { "apikey", "generate", "--prefix", "mh", option, value });

        Assert.Equal(ExitCodes.Error, run.ExitCode);
        Assert.Equal(string.Empty, run.Out);
    }

    [Fact]
    public async Task ShortKey_IsError()
    {
        string shortKey = Convert.ToBase64String(new byte[16]);

        ToolRun run = await Tool.RunAsync(new[] { "apikey", "generate", "--prefix", "mh", "--key-stdin" }, shortKey + "\n");

        Assert.Equal(ExitCodes.Error, run.ExitCode);
        Assert.Contains("at least 32 bytes", run.Error);
    }

    [Fact]
    public async Task BadBase64_IsError_WithoutEchoingTheKey()
    {
        ToolRun run = await Tool.RunAsync(
            new[] { "apikey", "generate", "--prefix", "mh", "--key-env", "K" },
            configure: e => e.GetEnvironmentVariable = _ => "not*base64*SECRETMATERIAL");

        Assert.Equal(ExitCodes.Error, run.ExitCode);
        Assert.Contains("not valid base64", run.Error);
        Assert.DoesNotContain("SECRETMATERIAL", run.All);
    }

    [Fact]
    public async Task UnsetEnvironmentVariable_IsError()
    {
        ToolRun run = await Tool.RunAsync(new[] { "apikey", "generate", "--prefix", "mh", "--key-env", "NOPE" });

        Assert.Equal(ExitCodes.Error, run.ExitCode);
        Assert.Contains("NOPE is not set", run.Error);
    }

    [Fact]
    public async Task BothKeySources_IsError()
    {
        ToolRun run = await Tool.RunAsync(new[] { "apikey", "generate", "--prefix", "mh", "--key-env", "K", "--key-stdin" }, "x\n");

        Assert.Equal(ExitCodes.Error, run.ExitCode);
        Assert.Contains("not both", run.Error);
    }

    [Fact]
    public async Task EmptyStdinKey_IsError()
    {
        ToolRun run = await Tool.RunAsync(new[] { "apikey", "generate", "--prefix", "mh", "--key-stdin" }, string.Empty);

        Assert.Equal(ExitCodes.Error, run.ExitCode);
    }
}
