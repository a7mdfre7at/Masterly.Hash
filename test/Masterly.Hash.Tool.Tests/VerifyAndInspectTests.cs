using System;
using System.Text;
using System.Threading.Tasks;
using Masterly.Hash.Legacy;
using Masterly.Hash.Primitives;

namespace Masterly.Hash.Tool.Tests;

public class VerifyCommandTests
{
    [Fact]
    public async Task Match_ExitsZero()
    {
        string stored = TestHashers.Hasher().Hash("right-pass");

        ToolRun run = await Tool.RunAsync(new[] { "verify", "--stdin", stored }, "right-pass\n");

        Assert.Equal(ExitCodes.Success, run.ExitCode);
        Assert.Contains("Status:         Success", run.Out);
        Assert.Contains("Match:          yes", run.Out);
        Assert.DoesNotContain("Failure reason", run.Out);
        Assert.DoesNotContain("Rehash", run.Out);
    }

    [Fact]
    public async Task Mismatch_ExitsOne()
    {
        string stored = TestHashers.Hasher().Hash("right-pass");

        ToolRun run = await Tool.RunAsync(new[] { "verify", "--stdin", stored }, "wrong-pass\n");

        Assert.Equal(ExitCodes.Failure, run.ExitCode);
        Assert.Contains("Failure reason: Mismatch", run.Out);
        Assert.DoesNotContain("wrong-pass", run.All);
    }

    [Fact]
    public async Task Prompt_IsUsedOnTerminal()
    {
        string stored = TestHashers.Hasher().Hash("prompted");

        ToolRun run = await Tool.RunInteractiveAsync(new[] { "verify", stored }, new[] { "prompted" });

        Assert.Equal(ExitCodes.Success, run.ExitCode);
        Assert.Equal(new[] { "Password: " }, run.Console.Prompts);
    }

    [Theory]
    [InlineData("garbage", "UnknownFormat")]
    [InlineData("$mh$p=test$notbase64!$x", "MalformedHash")]
    [InlineData("$mh$p=zzzz$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "UnknownProfile")]
    public async Task UnusableStoredHash_ExitsTwo_WithoutThrowing(string stored, string reason)
    {
        ToolRun run = await Tool.RunAsync(new[] { "verify", "--stdin", stored }, "anything\n");

        Assert.Equal(ExitCodes.Error, run.ExitCode);
        Assert.Contains("Failure reason: " + reason, run.Out);
    }

    [Fact]
    public async Task UnknownPepperKey_ExitsTwo()
    {
        string stored = "$mh$p=test,k=k9$" + HashPrimitives.ToB64(new byte[16]) + "$" + HashPrimitives.ToB64(new byte[32]);

        ToolRun run = await Tool.RunAsync(new[] { "verify", "--stdin", stored }, "anything\n");

        Assert.Equal(ExitCodes.Error, run.ExitCode);
        Assert.Contains("UnknownPepperKey", run.Out);
    }

    // RFC 1321 appendix A.5: MD5("abc") = 900150983cd24fb0d6963f7d28e17f72.
    // FIPS 180-2 appendix A.1: SHA-1("abc") = a9993e364706816aba3e25717850c26c9cd0d89d.
    [Theory]
    [InlineData("900150983cd24fb0d6963f7d28e17f72")]
    [InlineData("a9993e364706816aba3e25717850c26c9cd0d89d")]
    public async Task UnsaltedDigestVectors_MatchAndRequestRehash(string stored)
    {
        ToolRun run = await Tool.RunAsync(new[] { "verify", "--stdin", stored }, "abc\n");

        Assert.Equal(ExitCodes.Success, run.ExitCode);
        Assert.Contains("SuccessRehashNeeded", run.Out);
        Assert.Contains("Rehash reason:  LegacyFormat", run.Out);
        string rehash = run.Out.Split("Rehash:         ")[1].Trim();
        Assert.True(TestHashers.Hasher().Verify("abc", rehash).IsMatch);
    }

    // Openwall crypt_blowfish 1.3 test vectors (wrapper.c): "U*U" -> $2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW
    [Fact]
    public async Task BcryptVector_Matches()
    {
        ToolRun run = await Tool.RunAsync(new[] { "verify", "--stdin", "$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW" }, "U*U\n");

        Assert.Equal(ExitCodes.Success, run.ExitCode);
        Assert.Contains("LegacyFormat", run.Out);
    }

    [Fact]
    public async Task BcryptVector_WrongPassword_IsMismatch()
    {
        ToolRun run = await Tool.RunAsync(new[] { "verify", "--stdin", "$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW" }, "U*V\n");

        Assert.Equal(ExitCodes.Failure, run.ExitCode);
    }

    [Fact]
    public async Task V1Hash_Matches()
    {
        string stored = TestHashers.V1("old-1x-pass", Encoding.UTF8.GetBytes("salty-salt"), V1Algorithm.SHA512);

        ToolRun run = await Tool.RunAsync(new[] { "verify", "--stdin", stored }, "old-1x-pass\n");

        Assert.Equal(ExitCodes.Success, run.ExitCode);
        Assert.Contains("LegacyFormat", run.Out);
    }

    [Fact]
    public async Task OutdatedProfile_PrintsRehash()
    {
        string stored = new PasswordHasher(new PasswordHasherOptions
        {
            DefaultProfile = HashProfile.Argon2id("test-old", 64, 1),
            AllowWeakProfiles = true,
        }).Hash("pw");

        ToolRun run = await Tool.RunAsync(new[] { "verify", "--stdin", stored }, "pw\n", e =>
            e.HasherOptionsFactory = () =>
            {
                PasswordHasherOptions options = TestHashers.Options();
                options.AdditionalProfiles.Add(HashProfile.Argon2id("test-old", 64, 1));
                return options;
            });

        Assert.Equal(ExitCodes.Success, run.ExitCode);
        Assert.Contains("Rehash reason:  OutdatedProfile", run.Out);
        Assert.Contains("Rehash:         $mh$p=test$", run.Out);
    }

    [Fact]
    public async Task MissingStoredHash_IsArgumentError()
    {
        ToolRun run = await Tool.RunAsync(new[] { "verify", "--stdin" }, "pw\n");

        Assert.Equal(ExitCodes.Error, run.ExitCode);
        Assert.Contains("verify --help", run.Error);
    }

    [Fact]
    public async Task EmptyPassword_IsError()
    {
        string stored = TestHashers.Hasher().Hash("x-pass");

        ToolRun run = await Tool.RunAsync(new[] { "verify", "--stdin", stored }, "\n");

        Assert.Equal(ExitCodes.Error, run.ExitCode);
    }
}

public class InspectCommandTests
{
    private static string Mh(string parameters, int saltBytes = 16, int tagBytes = 32) =>
        "$mh$" + parameters + "$" + HashPrimitives.ToB64(new byte[saltBytes]) + "$" + HashPrimitives.ToB64(new byte[tagBytes]);

    [Fact]
    public async Task CurrentHash_IsRecognizedAndCurrent()
    {
        ToolRun run = await Tool.RunAsync(new[] { "inspect", TestHashers.Hasher().Hash("pw") });

        Assert.Equal(ExitCodes.Success, run.ExitCode);
        Assert.Contains("Format:       mh", run.Out);
        Assert.Contains("Recognized:   yes", run.Out);
        Assert.Contains("Profile:      test (Argon2id", run.Out);
        Assert.Contains("Pepper key:   none", run.Out);
        Assert.Contains("Wrapped:      no", run.Out);
        Assert.Contains("Needs rehash: no", run.Out);
        Assert.Contains("Weak:         no", run.Out);
    }

    [Fact]
    public async Task BuiltInProfile_IsOutdatedAgainstDefault()
    {
        ToolRun run = await Tool.RunAsync(new[] { "inspect", Mh("p=2026a") });

        Assert.Equal(ExitCodes.Success, run.ExitCode);
        Assert.Contains("2026a (Argon2id m=65536KiB t=3 p=1)", run.Out);
        Assert.Contains("Needs rehash: yes (OutdatedProfile)", run.Out);
    }

    [Fact]
    public async Task UnregisteredProfile_IsNotRecognized()
    {
        ToolRun run = await Tool.RunAsync(new[] { "inspect", Mh("p=old9") });

        Assert.Equal(ExitCodes.Failure, run.ExitCode);
        Assert.Contains("old9 (not registered)", run.Out);
    }

    [Fact]
    public async Task PepperKey_IsShown()
    {
        ToolRun run = await Tool.RunAsync(new[] { "inspect", Mh("p=test,k=k1") });

        Assert.Contains("Pepper key:   k1", run.Out);
        Assert.Contains("Recognized:   no", run.Out);
    }

    [Fact]
    public async Task LegacyDigest_IsWeak()
    {
        ToolRun run = await Tool.RunAsync(new[] { "inspect", TestHashers.Md5Hex("pw") });

        Assert.Equal(ExitCodes.Success, run.ExitCode);
        Assert.Contains("Format:       md5", run.Out);
        Assert.Contains("Needs rehash: yes (LegacyFormat)", run.Out);
        Assert.Contains("Weak:         yes", run.Out);
    }

    [Fact]
    public async Task WrappedHash_ShowsInnerFormat()
    {
        Assert.True(TestHashers.Hasher().TryWrap(TestHashers.Md5Hex("pw"), out string wrapped));

        ToolRun run = await Tool.RunAsync(new[] { "inspect", wrapped });

        Assert.Contains("Wrapped:      yes (md5)", run.Out);
        Assert.Contains("Needs rehash: yes (Wrapped)", run.Out);
    }

    [Theory]
    [InlineData("garbage")]
    [InlineData("$mh$")]
    [InlineData("$mh$p=test$$")]
    [InlineData("$2b$99$zzzz")]
    public async Task Garbage_IsUnknown_AndNeverThrows(string stored)
    {
        ToolRun run = await Tool.RunAsync(new[] { "inspect", stored });

        Assert.Equal(ExitCodes.Failure, run.ExitCode);
        Assert.Contains("Recognized:   no", run.Out);
    }

    [Fact]
    public async Task HugeInput_DoesNotThrow()
    {
        ToolRun run = await Tool.RunAsync(new[] { "inspect", "$mh$p=test$" + new string('A', 100_000) });

        Assert.Equal(ExitCodes.Failure, run.ExitCode);
    }

    [Fact]
    public async Task MissingArgument_IsError()
    {
        ToolRun run = await Tool.RunAsync(new[] { "inspect" });

        Assert.Equal(ExitCodes.Error, run.ExitCode);
        Assert.StartsWith("error:", run.Error);
    }
}
