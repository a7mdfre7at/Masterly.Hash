using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Masterly.Hash.Legacy;
using Masterly.Hash.Policy;
using Masterly.Hash.Primitives;
using Masterly.Hash.Tool.Commands;
using Masterly.Hash.Tool.IO;

namespace Masterly.Hash.Tool.Tests;

/// <summary>
/// Tests written to kill surviving Stryker mutants: exact help text, exact messages, exact report layouts and the
/// boundaries of every range check.
/// </summary>
public class MutationTests
{
    private static readonly string NL = Environment.NewLine;

    private static string Norm(string text) => Regex.Replace(text, @"\s+", " ").Trim();

    private static string Lines(params string[] lines) => string.Join(NL, lines) + NL;

    private static string Mh(string parameters) =>
        "$mh$" + parameters + "$" + HashPrimitives.ToB64(new byte[16]) + "$" + HashPrimitives.ToB64(new byte[32]);

    private static ToolEnvironment Environment0(FakeConsole? console = null) =>
        new ToolEnvironment(console ?? new FakeConsole(string.Empty, true, Array.Empty<string?>()))
        {
            HasherOptionsFactory = TestHashers.Options,
            GetEnvironmentVariable = _ => null,
        };

    // ---- Help text ----------------------------------------------------------------------------------------------

    public static IEnumerable<object[]> HelpCases()
    {
        yield return new object[]
        {
            new[] { "--help" },
            new[]
            {
                "masterly-hash: hash, verify, inspect, audit and migrate password hashes with Masterly.Hash. Passwords are read from a no-echo prompt or --stdin, never from arguments.",
                "pepper Pepper key utilities.",
                "apikey API key utilities.",
            },
        };
        yield return new object[]
        {
            new[] { "hash", "--help" },
            new[]
            {
                "Hash a password from a no-echo prompt (asked twice) or --stdin, and print the hash.",
                "--profile <2026a|2026c|2026f> Built-in profile for the new hash. Default: 2026a (Argon2id, 64 MiB, t=3).",
                "--stdin Read the password from the first line of standard input instead of prompting.",
            },
        };
        yield return new object[]
        {
            new[] { "verify", "--help" },
            new[]
            {
                "Verify a password from a no-echo prompt or --stdin against a stored hash. Exit code 0 = match, 1 = mismatch, 2 = error.",
                "<storedHash> The stored hash (Masterly or any supported legacy format). Quote it: it contains '$'.",
                "--stdin Read the password from the first line of standard input instead of prompting.",
            },
        };
        yield return new object[]
        {
            new[] { "inspect", "--help" },
            new[]
            {
                "Describe a stored hash: format, profile, pepper key, onion-wrapping and whether a login would rehash it.",
                "<storedHash> The stored hash to describe. Quote it: it contains '$'.",
                "--pepper-key-ids <IDS> Comma-separated pepper key ids your application knows, current key first (e.g. k2,k1). Peppered hashes ($mh$p=...,k=ID$...) are then classified instead of reported as unknown. Only the ids are needed, never the keys.",
            },
        };
        yield return new object[]
        {
            new[] { "audit", "--help" },
            new[]
            {
                "Audit stored hashes (every legacy format is recognized): formats, profiles, weak, needs-rehash and duplicate counts. Reads one hash per line, or one CSV column.",
                "<file> File with one stored hash per line (or a CSV with --column); '-' reads standard input.",
                "--column <N> Read the hash from this 1-based CSV column instead of taking whole lines.",
                "--delimiter <delimiter> CSV field delimiter: one character, or 'tab'. [default: ,]",
                "--header Skip the first line/record (a header row).",
                "--format <json|markdown> Report format. [default: markdown]",
                "--pepper-key-ids <IDS> Comma-separated pepper key ids your application knows",
            },
        };
        yield return new object[]
        {
            new[] { "wrap", "--help" },
            new[]
            {
                "Onion-wrap legacy hashes in one CSV column (Argon2id over the legacy digest), streaming. Other columns are kept; wrapped hashes verify with the original passwords and upgrade on the next login.",
                "<input.csv> CSV export of the password table.",
                "<output.csv> Where to write the CSV with wrapped hashes. Written to a temporary file and renamed on success.",
                "--column <N> (REQUIRED) 1-based column that holds the stored hash.",
                "--delimiter <delimiter> CSV field delimiter: one character, or 'tab'. [default: ,]",
                "--header The first record is a header row; copy it unchanged.",
                "--v1-algorithm <SHA256|SHA384|SHA512> Digest of Masterly.Hash 1.x hashes in this file. 1.x did not record it, so v1 hashes are only wrapped when it is given.",
                "--profile <2026a|2026c|2026f> Profile for the wrapping hash. Default: 2026a.",
                "--weak-only Only wrap weak hashes (unsalted digests, 1.x, phpass, low-cost bcrypt/PBKDF2); copy the rest unchanged.",
                "--force Overwrite the output file if it exists.",
                "--parallelism <N> Hashes computed at once. Each Argon2id hash uses the profile's memory (64 MiB for 2026a). [default: " +
                    WrapCommand.DefaultParallelism + "]",
                "--pepper-key-ids <IDS> Comma-separated pepper key ids",
            },
        };
        yield return new object[]
        {
            new[] { "bench", "--help" },
            new[]
            {
                "Time each built-in profile on this machine (median of 5 runs) and recommend Server2026a or Constrained2026a.",
                "--target-ms <ms> Longest acceptable time for one hash on this machine, in milliseconds. [default: 250]",
            },
        };
        yield return new object[]
        {
            new[] { "policy", "--help" },
            new[]
            {
                "Check a password from a no-echo prompt or --stdin against the NIST SP 800-63B policy: score, crack-time estimates, violations and suggestions. Exit code 0 = acceptable, 1 = rejected, 2 = error (including --pwned when the breach check is unavailable).",
                "--stdin Read the password from the first line of standard input instead of prompting.",
                "--min-length <N> Minimum length in code points (8-128). Default 15, the NIST minimum for a single-factor password.",
                "--pwned ONLINE: also look the password up in Have I Been Pwned. Only the first 5 hex characters of its SHA-1 hash are sent (k-anonymity).",
                "--allow-unavailable With --pwned: if Have I Been Pwned cannot be reached, judge the password without it (exit 0/1) instead of failing with exit code 2.",
                "--user-name <user-name> The account's user name; passwords containing it are rejected.",
                "--email <email> The account's email address; passwords containing its parts are rejected.",
            },
        };
        yield return new object[]
        {
            new[] { "pepper", "--help" },
            new[]
            {
                "Pepper key utilities.",
                "generate Print a new random 32-byte pepper key, base64-encoded, for HmacPepper.",
            },
        };
        yield return new object[]
        {
            new[] { "apikey", "--help" },
            new[]
            {
                "API key utilities.",
                "generate Print a new API key and its lookup hash (HMAC-SHA256). Without --key-env or --key-stdin a new lookup key is generated and printed.",
            },
        };
        yield return new object[]
        {
            new[] { "apikey", "generate", "--help" },
            new[]
            {
                "--prefix <prefix> (REQUIRED) Key prefix, e.g. mh_live: 1-32 ASCII letters, digits and single underscores, starting with a letter.",
                "--key-id <key-id> Id of the HMAC lookup key, stored in the lookup hash. [default: k1]",
                "--key-env <NAME> Read the base64 HMAC lookup key (32+ bytes) from this environment variable instead of generating one.",
                "--key-stdin Read the base64 HMAC lookup key from the first line of standard input instead of generating one.",
                "--entropy-bytes <N> Random bytes in the key (16-64). [default: 32]",
            },
        };
    }

    [Theory]
    [MemberData(nameof(HelpCases))]
    public async Task Help_ShowsEveryDescriptionAndHelpName(string[] args, string[] expected)
    {
        ToolRun run = await Tool.RunAsync(args);

        Assert.Equal(ExitCodes.Success, run.ExitCode);
        string help = Norm(run.Out);
        foreach (string line in expected)
            Assert.Contains(Norm(line), help);
    }

    // ---- ToolApp ------------------------------------------------------------------------------------------------

    [Fact]
    public async Task RunAsync_NullArgs_IsCheckedBeforeEnvironment()
    {
        await Assert.ThrowsAsync<ArgumentNullException>("args", () => ToolApp.RunAsync(null!, null!));
    }

    [Fact]
    public async Task NoArguments_PrintsTheParserErrorAndTheHelpHint()
    {
        ToolRun run = await Tool.RunAsync(Array.Empty<string>());

        Assert.Equal(ExitCodes.Error, run.ExitCode);
        Assert.Equal(Lines("error: Required command was not provided.", "Run 'masterly-hash --help' for usage."), run.Error);
    }

    [Fact]
    public async Task UnknownCommand_IsNotEchoed()
    {
        ToolRun run = await Tool.RunAsync(new[] { "hsah", "Secret-Pass-1" });

        Assert.Equal(ExitCodes.Error, run.ExitCode);
        Assert.Equal(Lines("error: unrecognized command or argument (not echoed, in case it is a password).",
            "Run 'masterly-hash --help' for usage."), run.Error);
    }

    [Fact]
    public async Task StrayArgumentToPasswordCommand_ExplainsWhyPasswordsAreNotArguments()
    {
        ToolRun run = await Tool.RunAsync(new[] { "hash", "Secret-Pass-1" });

        Assert.Equal(ExitCodes.Error, run.ExitCode);
        Assert.Equal(Lines(
            "error: unexpected argument. Passwords are never accepted on the command line (they would end up in " +
            "shell history and process listings): type it at the prompt, or pipe it in with --stdin.",
            "Run 'masterly-hash hash --help' for usage."), run.Error);
    }

    [Fact]
    public async Task NestedCommandError_PointsAtTheNestedHelp()
    {
        ToolRun run = await Tool.RunAsync(new[] { "apikey", "generate" });

        Assert.Equal(ExitCodes.Error, run.ExitCode);
        Assert.EndsWith(NL + "Run 'masterly-hash apikey generate --help' for usage." + NL, run.Error);
    }

    [Fact]
    public async Task Cancellation_PrintsCancelled()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        var console = new FakeConsole("x\n", true, Array.Empty<string?>());
        var environment = new ToolEnvironment(console)
        {
            HasherOptionsFactory = TestHashers.Options,
            BreachCheckerFactory = () => new FakeBreachChecker(BreachCheckResult.NotBreached),
        };

        int exit = await ToolApp.RunAsync(new[] { "policy", "--stdin", "--pwned" }, environment, cts.Token);

        Assert.Equal(ExitCodes.Cancelled, exit);
        Assert.EndsWith("error: cancelled." + NL, console.ErrorText);
    }

    private static RootCommandHolder Root() => new RootCommandHolder();

    private sealed class RootCommandHolder
    {
        public readonly System.CommandLine.RootCommand Command = ToolApp.BuildRootCommand(Environment0());

        public IReadOnlyList<string> Secrets(params string[] args) => ToolApp.PossibleSecrets(Command, args);
    }

    [Fact]
    public void PossibleSecrets_LoneAt_AddsNoEmptySecret()
    {
        Assert.Equal(new[] { "@" }, Root().Secrets("@"));
    }

    [Fact]
    public void PossibleSecrets_ValueSplitting_OnlyForOptions()
    {
        Assert.Equal(new[] { "a=bc" }, Root().Secrets("a=bc"));
        Assert.Equal(new[] { "b:cd" }, Root().Secrets("b:cd"));
    }

    [Fact]
    public void PossibleSecrets_TrailingSeparator_AddsNoEmptySecret()
    {
        Assert.Equal(new[] { "--x=" }, Root().Secrets("--x="));
        Assert.Equal(new[] { "--abc=xy", "xy" }, Root().Secrets("--abc=xy"));
    }

    [Fact]
    public void PossibleSecrets_AreSortedLongestFirst()
    {
        Assert.Equal(new[] { "abcdef", "abcd", "ab" }, Root().Secrets("ab", "abcdef", "abcd"));
    }

    [Fact]
    public void PossibleSecrets_CommandAliasesAreNotSecrets()
    {
        var sub = new System.CommandLine.Command("generate");
        sub.Aliases.Add("gen");
        var root = new System.CommandLine.RootCommand { sub };

        Assert.Equal(new[] { "zz-top" }, ToolApp.PossibleSecrets(root, new[] { "gen", "zz-top" }));
    }

    [Fact]
    public void Redact_ThreeCharacterSecret_StillWithholdsTheMessage()
    {
        Assert.Equal("invalid arguments (details withheld: an argument may be a password, which is never echoed).",
            ToolApp.Redact("bad abc here", new[] { "abc" }));
        Assert.Equal("bad ab here", ToolApp.Redact("bad ab here", new[] { "ab" }));
    }

    [Fact]
    public void Version_IsTheInformationalVersionWithoutBuildMetadata()
    {
        string? informational = typeof(ToolApp).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
        Assert.False(string.IsNullOrEmpty(informational));
        int plus = informational!.IndexOf('+');
        string expected = plus >= 0 ? informational.Substring(0, plus) : informational;

        Assert.Equal(expected, ToolApp.Version);
        Assert.DoesNotContain("+", ToolApp.Version);
    }

    [Fact]
    public void DefaultBreachChecker_SendsTheToolUserAgent()
    {
        IBreachedPasswordChecker checker = Environment0().BreachCheckerFactory();
        try
        {
            object client = checker.GetType().GetField("_client", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(checker)!;
            object? userAgent = client.GetType().GetField("_userAgent", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(client);

            Assert.Equal("masterly-hash-tool/2.0 (+https://github.com/a7mdfre7at/Masterly.Hash)", userAgent);
        }
        finally
        {
            ((IDisposable)checker).Dispose();
        }
    }

    // ---- apikey -------------------------------------------------------------------------------------------------

    private const string LookupKey = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="; // 32 bytes

    [Fact]
    public async Task ApiKey_BadKeyId_Message()
    {
        ToolRun run = await Tool.RunAsync(new[] { "apikey", "generate", "--prefix", "mh_live", "--key-id", "bad!" });

        Assert.Equal(ExitCodes.Error, run.ExitCode);
        Assert.Equal(Lines("error: --key-id must match ^[A-Za-z0-9-]{1,32}$."), run.Error);
    }

    [Theory]
    [InlineData(16)]
    [InlineData(64)]
    public async Task ApiKey_EntropyBounds_AreInclusive(int bytes)
    {
        ToolRun run = await Tool.RunAsync(new[] { "apikey", "generate", "--prefix", "mh_live", "--entropy-bytes", bytes.ToString() });

        Assert.Equal(ExitCodes.Success, run.ExitCode);
        Assert.Contains("API key:       mh_live_", run.Out);
    }

    [Theory]
    [InlineData(15)]
    [InlineData(65)]
    public async Task ApiKey_EntropyOutOfRange_Message(int bytes)
    {
        ToolRun run = await Tool.RunAsync(new[] { "apikey", "generate", "--prefix", "mh_live", "--entropy-bytes", bytes.ToString() });

        Assert.Equal(ExitCodes.Error, run.ExitCode);
        Assert.Equal(Lines("error: --entropy-bytes must be between 16 and 64."), run.Error);
    }

    [Fact]
    public async Task ApiKey_UnsetEnvironmentVariable_Message()
    {
        ToolRun run = await Tool.RunAsync(new[] { "apikey", "generate", "--prefix", "mh_live", "--key-env", "MH_KEY" });

        Assert.Equal(Lines("error: Environment variable MH_KEY is not set."), run.Error);
    }

    [Fact]
    public async Task ApiKey_BadBase64InEnvironment_Message()
    {
        ToolRun run = await Tool.RunAsync(new[] { "apikey", "generate", "--prefix", "mh_live", "--key-env", "MH_KEY" },
            configure: e => e.GetEnvironmentVariable = name => name == "MH_KEY" ? "not base64!!" : null);

        Assert.Equal(Lines("error: The lookup key in environment variable MH_KEY is not valid base64."), run.Error);
    }

    [Fact]
    public async Task ApiKey_KeyFromEnvironment_SaysWhereItCameFrom()
    {
        ToolRun run = await Tool.RunAsync(new[] { "apikey", "generate", "--prefix", "mh_live", "--key-env", "MH_KEY" },
            configure: e => e.GetEnvironmentVariable = name => name == "MH_KEY" ? LookupKey : null);

        Assert.Equal(ExitCodes.Success, run.ExitCode);
        Assert.Contains("Lookup key:    (provided from environment variable MH_KEY)" + NL, run.Out);
        Assert.Equal(Lines("Give the API key to its owner once; store only the lookup hash (ideally in a unique index)."), run.Error);
    }

    [Fact]
    public async Task ApiKey_KeyFromStdin_SaysWhereItCameFrom()
    {
        ToolRun run = await Tool.RunAsync(new[] { "apikey", "generate", "--prefix", "mh_live", "--key-stdin" }, LookupKey + "\n");

        Assert.Equal(ExitCodes.Success, run.ExitCode);
        Assert.Contains("Lookup key:    (provided from standard input)" + NL, run.Out);
        Assert.StartsWith("Give the API key to its owner once; store only the lookup hash (ideally in a unique index)." + NL, run.Error);
    }

    [Fact]
    public async Task ApiKey_NewKey_PrintsBothNotes()
    {
        ToolRun run = await Tool.RunAsync(new[] { "apikey", "generate", "--prefix", "mh_live" });

        Assert.Equal(Lines(
            "Give the API key to its owner once; store only the lookup hash (ideally in a unique index).",
            "The lookup key is new: keep it in a secret store, not the database. Every lookup hash depends on it."), run.Error);
    }

    [Fact]
    public async Task ApiKey_StdinKey_TooLong_EmptyAndBadBase64_Messages()
    {
        string[] args = { "apikey", "generate", "--prefix", "mh_live", "--key-stdin" };

        Assert.Equal(Lines("error: The lookup key on standard input is too long."), (await Tool.RunAsync(args, new string('A', 1025) + "\n")).Error);
        Assert.Equal(Lines("error: No lookup key on standard input."), (await Tool.RunAsync(args, "\n")).Error);
        Assert.Equal(Lines("error: The lookup key in standard input is not valid base64."), (await Tool.RunAsync(args, "%%%%\n")).Error);
    }

    [Fact]
    public async Task ApiKey_StdinOnTerminal_SuggestsKeyEnv()
    {
        ToolRun run = await Tool.RunOnTerminalAsync(new[] { "apikey", "generate", "--prefix", "mh_live", "--key-stdin" }, LookupKey + "\n");

        Assert.Equal(Lines("error: --key-stdin expects piped input, but standard input is a terminal (typing there would echo the secret). " +
            "Pipe the secret in, or use --key-env."), run.Error);
    }

    // ---- password input -----------------------------------------------------------------------------------------

    [Fact]
    public async Task Stdin_Messages()
    {
        Assert.Equal(Lines("error: No password on standard input."), (await Tool.RunAsync(new[] { "hash", "--stdin" }, "")).Error);
        Assert.Equal(Lines("error: The password is empty; empty passwords are never hashed and never match."),
            (await Tool.RunAsync(new[] { "hash", "--stdin" }, "\n")).Error);
    }

    [Fact]
    public async Task StdinOnTerminal_SuggestsThePrompt()
    {
        ToolRun run = await Tool.RunOnTerminalAsync(new[] { "hash", "--stdin" }, "pw\n");

        Assert.Equal(Lines("error: --stdin expects piped input, but standard input is a terminal (typing there would echo the secret). " +
            "Pipe the secret in, or omit --stdin to use the no-echo prompt."), run.Error);
    }

    [Fact]
    public async Task Prompt_PasswordOfExactlyTheMaximumLength_IsAccepted()
    {
        ToolRun run = await Tool.RunInteractiveAsync(new[] { "policy" }, new string?[] { new string('a', PasswordInput.MaxPasswordChars) });

        Assert.Equal(ExitCodes.Failure, run.ExitCode); // Rejected by the policy, not by the reader.
        Assert.Equal(string.Empty, run.Error);
    }

    // ---- bench --------------------------------------------------------------------------------------------------

    private static Action<ToolEnvironment> Clock(double server, double constrained, double fips) =>
        e => e.MeasureMilliseconds = p => p.Id switch
        {
            "2026a" => server,
            "2026c" => constrained,
            _ => fips,
        };

    private static string Params(HashProfile p) => p.Algorithm == HashAlgorithmKind.Argon2id
        ? "Argon2id m=" + p.MemoryKiB + " KiB, t=" + p.Iterations + ", p=" + p.Parallelism
        : "PBKDF2-SHA512 i=" + p.Iterations;

    private static string Cell(string value) => value.Replace("|", "\\|").Trim();

    private static string EnvironmentRow(string a, string c, string f, string recommended) =>
        "| " + Cell(RuntimeInformation.OSDescription) + " | " + RuntimeInformation.ProcessArchitecture + " | " + Environment.ProcessorCount +
        " | " + Cell(RuntimeInformation.FrameworkDescription) + " | " + a + " | " + c + " | " + f + " | " + recommended + " |";

    [Fact]
    public async Task Bench_FastMachine_ExactReport()
    {
        ToolRun run = await Tool.RunAsync(new[] { "bench" }, configure: Clock(120, 40, 90));

        Assert.Equal(ExitCodes.Success, run.ExitCode);
        Assert.Equal(Lines(
            "Median of 5 runs per profile; target 250 ms per hash.",
            "",
            "| Profile | Parameters | Median (ms) |",
            "|---|---|---:|",
            "| 2026a | " + Params(HashProfile.Server2026a) + " | 120.0 |",
            "| 2026c | " + Params(HashProfile.Constrained2026a) + " | 40.0 |",
            "| 2026f | " + Params(HashProfile.Fips2026a) + " | 90.0 |",
            "",
            "Recommendation: Server2026a (2026a takes 120.0 ms, within the 250 ms target).",
            "",
            "| OS | Arch | Cores | Runtime | 2026a (ms) | 2026c (ms) | 2026f (ms) | Recommended |",
            "|---|---|---:|---|---:|---:|---:|---|",
            EnvironmentRow("120.0", "40.0", "90.0", "Server2026a")), run.Out);
        Assert.Equal(Lines("bench: 2026a...", "bench: 2026c...", "bench: 2026f..."), run.Error);
    }

    [Fact]
    public async Task Bench_VerySlowMachine_ExactRecommendation()
    {
        ToolRun run = await Tool.RunAsync(new[] { "bench", "--target-ms", "50" }, configure: Clock(400, 90, 200));

        Assert.Contains(NL + "Recommendation: Constrained2026a (2026a takes 400.0 ms, over the 50 ms target; 2026c takes 90.0 ms)." + NL +
            "Even 2026c exceeds the target. It is the OWASP minimum, so do not go lower: add capacity or lower PasswordHasherOptions.MaxConcurrency instead." + NL +
            NL + "| OS |", run.Out);
    }

    [Fact]
    public async Task Bench_ConstrainedExactlyAtTarget_DoesNotWarn()
    {
        ToolRun run = await Tool.RunAsync(new[] { "bench", "--target-ms", "100" }, configure: Clock(400, 100, 200));

        Assert.Contains("Recommendation: Constrained2026a (2026a takes 400.0 ms, over the 100 ms target; 2026c takes 100.0 ms)." + NL + NL, run.Out);
        Assert.DoesNotContain("Even 2026c", run.Out);
    }

    [Theory]
    [InlineData("1")]
    [InlineData("60000")]
    public async Task Bench_TargetBounds_AreInclusive(string target)
    {
        ToolRun run = await Tool.RunAsync(new[] { "bench", "--target-ms", target }, configure: Clock(0.5, 0.5, 0.5));

        Assert.Equal(ExitCodes.Success, run.ExitCode);
        Assert.Contains("target " + target + " ms per hash.", run.Out);
    }

    [Theory]
    [InlineData("0")]
    [InlineData("60001")]
    public async Task Bench_TargetOutOfRange_Message(string target)
    {
        ToolRun run = await Tool.RunAsync(new[] { "bench", "--target-ms", target });

        Assert.Equal(Lines("error: --target-ms must be between 1 and 60000."), run.Error);
    }

    [Fact]
    public void Bench_Median_SortsTheSamples()
    {
        var sequence = new Queue<double>(new[] { 999.0, 10, 20, 50, 30, 40 });
        var environment = Environment0();
        environment.MeasureMilliseconds = _ => sequence.Dequeue();

        Assert.Equal(30.0, BenchCommand.Median(environment, HashProfile.Server2026a));
    }

    [Fact]
    public void Bench_Cell_EscapesPipesAndTrims()
    {
        MethodInfo cell = typeof(BenchCommand).GetMethod("Cell", BindingFlags.NonPublic | BindingFlags.Static)!;

        Assert.Equal("a\\|b", cell.Invoke(null, new object[] { " a|b " }));
    }

    // ---- ClassificationPepper / CommandHelpers ------------------------------------------------------------------

    [Fact]
    public void ClassificationPepper_ApplyAlwaysThrowsWithAClearMessage()
    {
        var pepper = new ClassificationPepper(new[] { "k1" });
        const string message = "--pepper-key-ids only classifies hashes; it holds no key and cannot hash or verify.";

        Assert.Equal(message, Assert.Throws<InvalidOperationException>(() => pepper.Apply("k1", new byte[1])).Message);
        Assert.Equal(message, Assert.Throws<InvalidOperationException>(() => { _ = pepper.ApplyAsync("k1", new byte[1]); }).Message);
        Assert.Throws<ArgumentException>("keyIds", () => new ClassificationPepper(Array.Empty<string>()));
    }

    [Fact]
    public void UseClassificationPepper_EmptyList_SetsNoPepper()
    {
        var options = TestHashers.Options();

        CommandHelpers.UseClassificationPepper(options, Array.Empty<string>());

        Assert.Null(options.Pepper);
    }

    [Fact]
    public void ParseDelimiter_Messages()
    {
        Assert.Equal("--delimiter must be a single character (or 'tab').", Assert.Throws<ToolException>(() => CsvFormat.ParseDelimiter("ab")).Message);
        Assert.Equal("--delimiter cannot be a quote or a line break.", Assert.Throws<ToolException>(() => CsvFormat.ParseDelimiter("\"")).Message);
    }

    // ---- inspect ------------------------------------------------------------------------------------------------

    [Fact]
    public async Task Inspect_Unknown_ShowsDashForProfile()
    {
        ToolRun run = await Tool.RunAsync(new[] { "inspect", "garbage" });

        Assert.Equal(ExitCodes.Failure, run.ExitCode);
        Assert.Contains(NL + "Profile:      -" + NL, run.Out);
    }

    [Fact]
    public async Task Inspect_UnknownPepperKey_ExplainsHowToClassify()
    {
        ToolRun run = await Tool.RunAsync(new[] { "inspect", Mh("p=test,k=k9") });

        Assert.Contains(NL + "Pepper key:   k9 (unknown; pass --pepper-key-ids k9 to classify it)" + NL, run.Out);
    }

    // ---- audit --------------------------------------------------------------------------------------------------

    [Fact]
    public async Task Audit_Json_HasEveryFieldWithSortedKeys()
    {
        PasswordHasher hasher = TestHashers.Hasher();
        Assert.True(hasher.TryWrap(TestHashers.Md5Hex("b"), out string wrapped));
        var values = new[] { hasher.Hash("delta-pass"), TestHashers.Md5Hex("a"), TestHashers.Md5Hex("a"), wrapped, "zzz" };
        HashAuditReport report = HashAudit.Audit(hasher, values);

        ToolRun run = await Tool.RunAsync(new[] { "audit", "-", "--format", "json" }, string.Join("\n", values) + "\n");

        Assert.Equal(ExitCodes.Success, run.ExitCode);
        Assert.Equal(string.Empty, run.Error);
        Assert.EndsWith("}\n", run.Out);
        using JsonDocument doc = JsonDocument.Parse(run.Out);
        JsonElement root = doc.RootElement;
        Assert.Equal(new[] { "total", "recognized", "unknown", "needsRehash", "weak", "wrapped", "duplicates", "percent", "byFormat", "byProfile", "weakByFormat" },
            root.EnumerateObject().Select(p => p.Name));
        Assert.Equal(report.Total, root.GetProperty("total").GetInt64());
        Assert.Equal(report.Recognized, root.GetProperty("recognized").GetInt64());
        Assert.Equal(report.Unknown, root.GetProperty("unknown").GetInt64());
        Assert.Equal(report.NeedsRehash, root.GetProperty("needsRehash").GetInt64());
        Assert.Equal(report.Weak, root.GetProperty("weak").GetInt64());
        Assert.Equal(report.Wrapped, root.GetProperty("wrapped").GetInt64());
        Assert.Equal(report.Duplicates, root.GetProperty("duplicates").GetInt64());
        Assert.Equal(1, report.Wrapped);
        Assert.True(report.Weak > 0);

        JsonElement percent = root.GetProperty("percent");
        Assert.Equal(new[] { "recognized", "unknown", "needsRehash", "weak", "wrapped", "duplicates" }, percent.EnumerateObject().Select(p => p.Name));
        Assert.Equal(Math.Round(report.RecognizedPercent, 2), percent.GetProperty("recognized").GetDouble());
        Assert.Equal(Math.Round(report.UnknownPercent, 2), percent.GetProperty("unknown").GetDouble());
        Assert.Equal(Math.Round(report.NeedsRehashPercent, 2), percent.GetProperty("needsRehash").GetDouble());
        Assert.Equal(Math.Round(report.WeakPercent, 2), percent.GetProperty("weak").GetDouble());
        Assert.Equal(Math.Round(report.WrappedPercent, 2), percent.GetProperty("wrapped").GetDouble());
        Assert.Equal(Math.Round(report.DuplicatePercent, 2), percent.GetProperty("duplicates").GetDouble());

        // Insertion order is mh, md5, unknown; the JSON is sorted ordinally.
        Assert.Equal(new[] { "mh", "md5", "unknown" }, report.ByFormat.Keys);
        Assert.Equal(new[] { "md5", "mh", "unknown" }, root.GetProperty("byFormat").EnumerateObject().Select(p => p.Name));
        foreach (JsonProperty p in root.GetProperty("byFormat").EnumerateObject())
            Assert.Equal(report.ByFormat[p.Name], p.Value.GetInt64());
    }

    [Fact]
    public async Task Audit_Header_SkipsOnlyTheFirstLine()
    {
        string stdin = "password_hash\n" + TestHashers.Md5Hex("a") + "\n" + TestHashers.Md5Hex("b") + "\n" + TestHashers.Md5Hex("c") + "\n";

        ToolRun run = await Tool.RunAsync(new[] { "audit", "-", "--header", "--format", "json" }, stdin);

        using JsonDocument doc = JsonDocument.Parse(run.Out);
        Assert.Equal(3, doc.RootElement.GetProperty("total").GetInt64());
    }

    [Fact]
    public async Task Audit_ColumnOne_IsValid_AndPrintsNoWarning()
    {
        ToolRun run = await Tool.RunAsync(new[] { "audit", "-", "--column", "1", "--format", "json" }, TestHashers.Md5Hex("a") + ",x\n");

        Assert.Equal(ExitCodes.Success, run.ExitCode);
        Assert.Equal(string.Empty, run.Error);
        using JsonDocument doc = JsonDocument.Parse(run.Out);
        Assert.Equal(1, doc.RootElement.GetProperty("recognized").GetInt64());
    }

    [Fact]
    public async Task Audit_ColumnZero_Message()
    {
        ToolRun run = await Tool.RunAsync(new[] { "audit", "-", "--column", "0" });

        Assert.Equal(Lines("error: --column is 1-based and must be at least 1."), run.Error);
    }

    [Fact]
    public async Task Audit_ExplicitMarkdownFormat_IsAccepted()
    {
        ToolRun run = await Tool.RunAsync(new[] { "audit", "-", "--format", "markdown" }, TestHashers.Md5Hex("a") + "\n");

        Assert.Equal(ExitCodes.Success, run.ExitCode);
        Assert.DoesNotContain("{", run.Out);
        Assert.Contains("md5", run.Out);
    }

    [Fact]
    public async Task Audit_UnknownPepperKey_ExactWarning()
    {
        ToolRun run = await Tool.RunAsync(new[] { "audit", "-" }, Mh("p=test,k=k9") + "\n");

        Assert.Equal(Lines("warning: 1 Masterly hash(es) are peppered with a key id this audit does not know, so they are counted as unknown. " +
            "Pass --pepper-key-ids (current key first, e.g. k2,k1) to classify them; the keys themselves are not needed."), run.Error);
    }

    [Fact]
    public async Task Audit_Utf16FileWithBom_IsDecoded()
    {
        using var dir = new TempDir();
        string path = dir.File("hashes.txt");
        File.WriteAllText(path, TestHashers.Md5Hex("a") + "\n", Encoding.Unicode);

        ToolRun run = await Tool.RunAsync(new[] { "audit", path, "--format", "json" });

        using JsonDocument doc = JsonDocument.Parse(run.Out);
        Assert.Equal(1, doc.RootElement.GetProperty("recognized").GetInt64());
    }

    // ---- policy -------------------------------------------------------------------------------------------------

    [Fact]
    public async Task Policy_WeakPassword_ExactReport()
    {
        ToolRun run = await Tool.RunAsync(new[] { "policy", "--stdin" }, "password\n");

        Assert.Equal(ExitCodes.Failure, run.ExitCode);
        PasswordPolicyResult result = new PasswordPolicy(new PasswordPolicyOptions()).Evaluate("password", new PasswordContext());
        CrackTimeEstimates times = result.StrengthEstimate.CrackTimes;
        Assert.NotEmpty(result.StrengthEstimate.Warning);
        var expected = new List<string>
        {
            "Result:     Rejected",
            string.Format(System.Globalization.CultureInfo.InvariantCulture, "Score:      {0}/4 (about 10^{1:0.0} guesses)", result.Score, result.StrengthEstimate.GuessesLog10),
            "Length:     8 code points",
            "Crack time (estimates):",
            "  online, rate-limited (100/hour):     " + times.OnlineThrottled.Display,
            "  online, not rate-limited (10/s):     " + times.OnlineUnthrottled.Display,
            "  offline, slow hash e.g. Argon2id (10^4/s): " + times.OfflineSlowHash.Display,
            "  offline, fast hash e.g. SHA-1 (10^10/s):   " + times.OfflineFastHash.Display,
            "Warning:    " + result.StrengthEstimate.Warning,
            "Violations:",
        };
        expected.AddRange(result.Violations.Select(v => "  - " + v.Code + ": " + v.Message));
        expected.Add("Suggestions:");
        expected.AddRange(result.Suggestions.Select(s => "  - " + s));
        expected.Add("Breach check: skipped (offline). Pass --pwned to query Have I Been Pwned.");
        Assert.Equal(Lines(expected.ToArray()), run.Out);
        Assert.Contains("  - TooShort: ", run.Out);
    }

    [Fact]
    public async Task Policy_StrongPassword_HasNoWarningViolationsOrSuggestions()
    {
        ToolRun run = await Tool.RunAsync(new[] { "policy", "--stdin" }, "Xq7#vR2m!Lp9@zW4&kT8^bN\n");

        Assert.Equal(ExitCodes.Success, run.ExitCode);
        string[] lines = run.Out.Split(NL);
        Assert.Equal("Length:     23 code points", lines[2]);
        Assert.Equal("Crack time (estimates):", lines[3]);
        Assert.StartsWith("  online, not rate-limited (10/s):     ", lines[5]);
        Assert.StartsWith("  offline, slow hash e.g. Argon2id (10^4/s): ", lines[6]);
        Assert.Equal("Breach check: skipped (offline). Pass --pwned to query Have I Been Pwned.", lines[8]);
        Assert.DoesNotContain("Warning:", run.Out);
        Assert.DoesNotContain("Violations:", run.Out);
        Assert.DoesNotContain("Suggestions:", run.Out);
    }

    [Theory]
    [InlineData("8")]
    [InlineData("128")]
    public async Task Policy_MinLengthBounds_AreInclusive(string min)
    {
        ToolRun run = await Tool.RunAsync(new[] { "policy", "--stdin", "--min-length", min }, "password\n");

        Assert.Equal(ExitCodes.Failure, run.ExitCode);
        Assert.Equal(string.Empty, run.Error);
    }

    [Theory]
    [InlineData("7")]
    [InlineData("129")]
    public async Task Policy_MinLengthOutOfRange_Message(string min)
    {
        ToolRun run = await Tool.RunAsync(new[] { "policy", "--stdin", "--min-length", min }, "password\n");

        Assert.Equal(Lines("error: --min-length must be between 8 (the NIST floor) and 128."), run.Error);
    }

    // ---- CSV / line readers -------------------------------------------------------------------------------------

    [Fact]
    public void CsvReader_MaxRecordCharsOfOne_IsAllowed()
    {
        CsvRecord? record = new CsvRecordReader(new StringReader("a"), ',', 1).Read();

        Assert.NotNull(record);
        Assert.Equal("a", record!.Fields[0].Value);
    }

    [Fact]
    public void CsvReader_TooLongRecord_Message()
    {
        var csv = new CsvRecordReader(new StringReader("abcd"), ',', 3);

        Assert.Equal("The record starting on line 1 is longer than 3 characters (unterminated quote?).",
            Assert.Throws<ToolException>(() => csv.Read()).Message);
    }

    [Fact]
    public void CsvReader_DoubledQuote_CountsBothCharacters()
    {
        CsvRecord record = new CsvRecordReader(new StringReader("\"a\"\"b\""), ',').Read()!;

        Assert.Equal("a\"b", record.Fields[0].Value);
        Assert.Equal(6, record.Length);
        Assert.Throws<ToolException>(() => new CsvRecordReader(new StringReader("\"a\"\"b\""), ',', 5).Read());
    }

    private sealed class ChunkReader : TextReader
    {
        private readonly Queue<string> _chunks;

        public ChunkReader(params string[] chunks)
        {
            _chunks = new Queue<string>(chunks);
        }

        public override int Read(char[] buffer, int index, int count)
        {
            if (_chunks.Count == 0)
                return 0;
            string chunk = _chunks.Dequeue();
            chunk.CopyTo(0, buffer, index, chunk.Length);
            return chunk.Length;
        }
    }

    [Fact]
    public void CsvReader_StopsReadingAtTheFirstEndOfInput()
    {
        var csv = new CsvRecordReader(new ChunkReader("a", "", "b"), ',');

        Assert.Equal("a", csv.Read()!.Fields[0].Value);
        Assert.Null(csv.Read());
        Assert.Null(csv.Read());
    }

    [Fact]
    public void LineReader_MaxCharsOfOne_ReadsOneCharacter()
    {
        Assert.Equal("a", LineReader.ReadLine(new StringReader("a"), 1, "too long"));
        Assert.Equal("b", LineReader.ReadLine(new StringReader("b\r\n"), 1, "too long"));
    }

    // ---- SystemConsole ------------------------------------------------------------------------------------------

    [Fact]
    public void CreateUtf8Reader_HonoursUtf16Bom_AndHasNoPreamble()
    {
        byte[] bytes = Encoding.Unicode.GetPreamble().Concat(Encoding.Unicode.GetBytes("hi")).ToArray();

        Assert.Equal("hi", SystemConsole.CreateUtf8Reader(new MemoryStream(bytes)).ReadToEnd());

        var reader = Assert.IsType<StreamReader>(SystemConsole.CreateUtf8Reader(new MemoryStream(Encoding.ASCII.GetBytes("x"))));
        Assert.Empty(reader.CurrentEncoding.GetPreamble());
    }

    private static ConsoleKeyInfo Char(char c) => new ConsoleKeyInfo(c, ConsoleKey.A, shift: false, alt: false, control: false);

    private static string? Keys(params ConsoleKeyInfo[] keys)
    {
        var queue = new Queue<ConsoleKeyInfo>(keys);
        return SystemConsole.ReadSecret("Password: ", queue.Dequeue, new StringWriter());
    }

    private static readonly ConsoleKeyInfo Enter = new ConsoleKeyInfo('\r', ConsoleKey.Enter, false, false, false);

    [Fact]
    public void ReadSecret_BackspaceAfterALoneLowSurrogate_DeletesIt()
    {
        Assert.Equal("a", Keys(Char('\uDC00'), new ConsoleKeyInfo('\b', ConsoleKey.Backspace, false, false, false), Char('a'), Enter));
    }

    [Fact]
    public void ReadSecret_BackspaceNeverInsertsItsKeyChar()
    {
        Assert.Equal("a", Keys(Char('a'), Char('b'), new ConsoleKeyInfo('x', ConsoleKey.Backspace, false, false, false), Enter));
    }

    [Fact]
    public void ReadSecret_CtrlUNeverInsertsItsKeyChar()
    {
        Assert.Equal("c", Keys(Char('a'), Char('b'), new ConsoleKeyInfo('u', ConsoleKey.U, false, false, true), Char('c'), Enter));
    }

    // ---- wrap ---------------------------------------------------------------------------------------------------

    [Fact]
    public void Wrap_DefaultParallelism_IsProcessorCountCappedAtEight()
    {
        Assert.Equal(Math.Clamp(Environment.ProcessorCount, 1, 8), WrapCommand.DefaultParallelism);
    }

    [Fact]
    public void Wrap_DefaultSettings_HaveEmptyPaths()
    {
        var settings = new WrapSettings();
        Assert.Equal(string.Empty, settings.Input);
        Assert.Equal(string.Empty, settings.Output);

        var ex = Assert.Throws<ToolException>(() => WrapCommand.Execute(Environment0(), new WrapSettings { Column = 1 }, CancellationToken.None));
        Assert.Equal("Input file not found: ", ex.Message);
    }

    [Fact]
    public void ApiKey_DefaultSettings_HaveEmptyPrefix()
    {
        Assert.Equal(string.Empty, new ApiKeySettings().Prefix);
    }

    [Fact]
    public async Task Wrap_V1AlgorithmIsValidatedByTheParser()
    {
        ToolRun run = await Tool.RunAsync(new[] { "wrap", "in.csv", "out.csv", "--column", "1", "--v1-algorithm", "MD5" });

        Assert.Equal(ExitCodes.Error, run.ExitCode);
        Assert.StartsWith("error: Argument 'MD5' not recognized. Must be one of:", run.Error);
        Assert.DoesNotContain("--v1-algorithm must be", run.Error);
    }

    [Fact]
    public async Task Wrap_ArgumentMessages()
    {
        using var dir = new TempDir();
        string input = dir.File("in.csv");
        File.WriteAllText(input, "x\n");

        Assert.Equal(Lines("error: --column is 1-based and must be at least 1."),
            (await Tool.RunAsync(new[] { "wrap", input, dir.File("o.csv"), "--column", "0" })).Error);
        Assert.Equal(Lines("error: --parallelism must be between 1 and 64."),
            (await Tool.RunAsync(new[] { "wrap", input, dir.File("o.csv"), "--column", "1", "--parallelism", "65" })).Error);
        Assert.Equal(Lines("error: The output file must differ from the input file."),
            (await Tool.RunAsync(new[] { "wrap", input, input, "--column", "1" })).Error);
    }

    [Fact]
    public async Task Wrap_MaximumParallelism_IsAccepted()
    {
        using var dir = new TempDir();
        string input = dir.File("in.csv");
        File.WriteAllText(input, "x\n");

        ToolRun run = await Tool.RunAsync(new[] { "wrap", input, dir.File("o.csv"), "--column", "1", "--parallelism", "64" });

        Assert.Equal(ExitCodes.Success, run.ExitCode);
    }

    [Fact]
    public async Task Wrap_Report_IsExact_WithSortedBreakdowns()
    {
        using var dir = new TempDir();
        string input = dir.File("in.csv");
        string output = dir.File("out.csv");
        File.WriteAllText(input, "a,not-a-hash\nb,\nc," + TestHashers.Md5Hex("pw") + "\n");

        ToolRun run = await Tool.RunAsync(new[] { "wrap", input, output, "--column", "2", "--parallelism", "1" });

        Assert.Equal(ExitCodes.Success, run.ExitCode);
        Assert.Equal(Lines(
            "Rows:            3",
            "Wrapped:         1",
            "Already current: 0",
            "Skipped:         2",
            "Wrapped by format:",
            "  md5: 1",
            "Skipped by reason:",
            "  empty: 1",
            "  unknown format: 1",
            "Output:          " + output), run.Out);
    }

    [Fact]
    public async Task Wrap_Report_OmitsEmptyBreakdowns()
    {
        using var dir = new TempDir();
        string input = dir.File("in.csv");
        string output = dir.File("out.csv");
        File.WriteAllText(input, TestHashers.Md5Hex("pw") + "\n");

        ToolRun run = await Tool.RunAsync(new[] { "wrap", input, output, "--column", "1" });

        Assert.Equal(Lines(
            "Rows:            1",
            "Wrapped:         1",
            "Already current: 0",
            "Skipped:         0",
            "Wrapped by format:",
            "  md5: 1",
            "Output:          " + output), run.Out);
    }

    private static byte[] Bytes(params object[] parts)
    {
        var all = new List<byte>();
        foreach (object part in parts)
            all.AddRange(part is string s ? Encoding.UTF8.GetBytes(s) : (byte[])part);
        return all.ToArray();
    }

    private static readonly byte[] Bom = { 0xEF, 0xBB, 0xBF };

    [Fact]
    public async Task Wrap_BomThenFeffCharacter_KeepsTheCharacter()
    {
        using var dir = new TempDir();
        string input = dir.File("in.csv");
        string output = dir.File("out.csv");
        File.WriteAllBytes(input, Bytes(Bom, Bom, "h\n", "x\n"));

        ToolRun run = await Tool.RunAsync(new[] { "wrap", input, output, "--column", "1", "--header" });

        Assert.Equal(ExitCodes.Success, run.ExitCode);
        Assert.Equal(Bytes(Bom, Bom, "h\n", "x\n"), File.ReadAllBytes(output));
    }

    [Fact]
    public async Task Wrap_BomFile_FirstDataRowIsWrapped()
    {
        using var dir = new TempDir();
        string input = dir.File("in.csv");
        string output = dir.File("out.csv");
        File.WriteAllBytes(input, Bytes(Bom, TestHashers.Md5Hex("pw") + "\n"));

        ToolRun run = await Tool.RunAsync(new[] { "wrap", input, output, "--column", "1" });

        Assert.Contains("Wrapped:         1" + NL, run.Out);
        byte[] written = File.ReadAllBytes(output);
        Assert.Equal(Bom, written.Take(3));
        Assert.StartsWith("\"$mh$p=test,w=md5$", Encoding.UTF8.GetString(written, 3, written.Length - 3)); // Quoted: it holds a comma.
    }

    [Fact]
    public async Task Wrap_BomOnlyFile_HasNoRows()
    {
        using var dir = new TempDir();
        string input = dir.File("in.csv");
        string output = dir.File("out.csv");
        File.WriteAllBytes(input, Bom);

        ToolRun run = await Tool.RunAsync(new[] { "wrap", input, output, "--column", "1" });

        Assert.Equal(ExitCodes.Success, run.ExitCode);
        Assert.StartsWith("Rows:            0" + NL, run.Out);
    }

    [Theory]
    [InlineData(0xEA, 0xBB, 0xBF)] // U+AEFF: shares the BOM's last two bytes.
    [InlineData(0xE2, 0x80, 0xBF)] // U+203F: shares the BOM's last byte.
    public async Task Wrap_CharacterResemblingTheBom_IsNotTreatedAsOne(int b0, int b1, int b2)
    {
        using var dir = new TempDir();
        string input = dir.File("in.csv");
        string output = dir.File("out.csv");
        byte[] content = Bytes(new[] { (byte)b0, (byte)b1, (byte)b2 }, ",h\n", "x,y\n");
        File.WriteAllBytes(input, content);

        ToolRun run = await Tool.RunAsync(new[] { "wrap", input, output, "--column", "2", "--header" });

        Assert.Equal(ExitCodes.Success, run.ExitCode);
        Assert.Equal(content, File.ReadAllBytes(output));
    }

    [Fact]
    public async Task Wrap_TwoByteUtf16Bom_IsRefused()
    {
        using var dir = new TempDir();
        string input = dir.File("in.csv");
        File.WriteAllBytes(input, new byte[] { 0xFF, 0xFE });

        ToolRun run = await Tool.RunAsync(new[] { "wrap", input, dir.File("out.csv"), "--column", "1" });

        Assert.Equal(Lines("error: The input is UTF-16 or UTF-32; wrap only reads UTF-8. Convert it first (e.g. iconv -f UTF-16 -t UTF-8)."), run.Error);
    }

    [Fact]
    public async Task Wrap_BytesEndingLikeUtf32BigEndianBom_AreJudgedAsUtf8()
    {
        using var dir = new TempDir();
        string input = dir.File("in.csv");
        File.WriteAllBytes(input, new byte[] { (byte)'a', 0, 0xFE, 0xFF });

        ToolRun run = await Tool.RunAsync(new[] { "wrap", input, dir.File("out.csv"), "--column", "1" });

        Assert.Equal(ExitCodes.Error, run.ExitCode);
        Assert.Matches(new Regex(@"^error: The input is not valid UTF-8 \(the first invalid bytes are at or after line \d+\)\. wrap copies other columns " +
            @"unchanged and will not guess an encoding: convert the file to UTF-8 first \(e\.g\. iconv -f WINDOWS-1252 -t UTF-8\)\.\r?\n$"), run.Error);
    }

    [Fact]
    public async Task Wrap_HostWithoutV1Format_GetsTheRestrictedOneAdded()
    {
        using var dir = new TempDir();
        string input = dir.File("in.csv");
        string output = dir.File("out.csv");
        File.WriteAllText(input, TestHashers.V1("pw", Encoding.UTF8.GetBytes("salt-salt-salt-1"), V1Algorithm.SHA256) + "\n");

        ToolRun run = await Tool.RunAsync(new[] { "wrap", input, output, "--column", "1", "--v1-algorithm", "SHA256" },
            configure: e => e.HasherOptionsFactory = () =>
            {
                PasswordHasherOptions options = TestHashers.Options();
                options.LegacyFormats.Clear();
                return options;
            });

        Assert.Equal(ExitCodes.Success, run.ExitCode);
        Assert.Contains("  v1: 1" + NL, run.Out);
    }

    [Fact]
    public async Task Wrap_HostWithoutV1Format_ClassifierAlsoGetsIt()
    {
        using var dir = new TempDir();
        string input = dir.File("in.csv");
        string output = dir.File("out.csv");
        File.WriteAllText(input, TestHashers.V1("pw", Encoding.UTF8.GetBytes("salt-salt-salt-1"), V1Algorithm.SHA256) + "\n");

        ToolRun run = await Tool.RunAsync(new[] { "wrap", input, output, "--column", "1", "--v1-algorithm", "SHA256", "--pepper-key-ids", "k1" },
            configure: e => e.HasherOptionsFactory = () =>
            {
                PasswordHasherOptions options = TestHashers.Options();
                options.LegacyFormats.Clear();
                return options;
            });

        Assert.Equal(ExitCodes.Success, run.ExitCode);
        Assert.Contains("  v1: 1" + NL, run.Out);
    }

    [Fact]
    public async Task Wrap_HostV1FormatAtIndexZero_IsReplaced()
    {
        using var dir = new TempDir();
        string input = dir.File("in.csv");
        string output = dir.File("out.csv");
        File.WriteAllText(input, TestHashers.V1("pw", Encoding.UTF8.GetBytes("salt-salt-salt-1"), V1Algorithm.SHA256) + "\n");

        ToolRun run = await Tool.RunAsync(new[] { "wrap", input, output, "--column", "1", "--v1-algorithm", "SHA256" },
            configure: e => e.HasherOptionsFactory = () =>
            {
                PasswordHasherOptions options = TestHashers.Options();
                options.LegacyFormats.Clear();
                options.LegacyFormats.Add(V1LegacyFormat.Instance);
                foreach (ILegacyHashFormat format in LegacyFormats.All)
                    options.LegacyFormats.Add(format);
                return options;
            });

        Assert.Equal(ExitCodes.Success, run.ExitCode);
        Assert.Contains("  v1: 1" + NL, run.Out);
    }

    [Fact]
    public async Task Wrap_SeparateClassifier_OnlyWithPepperKeyIds()
    {
        using var dir = new TempDir();
        string input = dir.File("in.csv");
        File.WriteAllText(input, "x\n");
        int calls = 0;
        Action<ToolEnvironment> counting = e => e.HasherOptionsFactory = () =>
        {
            Interlocked.Increment(ref calls);
            return TestHashers.Options();
        };

        await Tool.RunAsync(new[] { "wrap", input, dir.File("a.csv"), "--column", "1" }, configure: counting);
        Assert.Equal(1, calls);

        calls = 0;
        await Tool.RunAsync(new[] { "wrap", input, dir.File("b.csv"), "--column", "1", "--pepper-key-ids", "k1" }, configure: counting);
        Assert.Equal(2, calls);
    }

    [Fact]
    public void Wrap_UnknownPepperKey_IsToldApartFromAnUnregisteredWrapFormat()
    {
        PasswordHasher hasher = TestHashers.Hasher();
        WrapCommand.RowResult Process(string value) =>
            WrapCommand.Process(hasher, new CsvRecord(new List<CsvField> { new CsvField(value, value) }, "\n", 1), 0, weakOnly: false);

        Assert.Equal("mh (unknown pepper key; pass --pepper-key-ids)", Process(Mh("p=test,k=k9")).Detail);
        Assert.Equal("mh (malformed or unregistered profile)", Process(Mh("p=test,k=k9,w=zzz")).Detail);
    }

    private sealed class ProbeFormat : ILegacyHashFormat
    {
        private readonly string _directory;

        public ProbeFormat(string directory)
        {
            _directory = directory;
        }

        public List<string> Seen { get; } = new List<string>();

        public string Id => "probe";

        public bool CanHandle(string storedHash)
        {
            if (storedHash != "probe-hash")
                return false;
            lock (Seen)
                Seen.AddRange(Directory.GetFiles(_directory).Select(f => Path.GetFileName(f)!));
            return true;
        }

        public bool Verify(string password, string storedHash) => false;

        public bool TryExtractWrapInput(string storedHash, out byte[] digest, out byte[] parameter)
        {
            digest = Array.Empty<byte>();
            parameter = Array.Empty<byte>();
            return false;
        }

        public byte[] ComputeWrapInput(string password, byte[] parameter) => throw new NotSupportedException();
    }

    [Fact]
    public async Task Wrap_TemporaryFile_HasARandomHexSuffix()
    {
        using var dir = new TempDir();
        string input = dir.File("in.csv");
        File.WriteAllText(input, "probe-hash\n");
        var probe = new ProbeFormat(dir.Path);

        for (int i = 0; i < 3; i++)
        {
            ToolRun run = await Tool.RunAsync(new[] { "wrap", input, dir.File("out.csv"), "--column", "1", "--parallelism", "1", "--force" },
                configure: e => e.HasherOptionsFactory = () =>
                {
                    PasswordHasherOptions options = TestHashers.Options();
                    options.LegacyFormats.Add(probe);
                    return options;
                });
            Assert.Equal(ExitCodes.Success, run.ExitCode);
            Assert.Contains("  probe (cannot be wrapped): 1" + NL, run.Out);
        }

        string[] temps = probe.Seen.Where(n => n.EndsWith(".tmp", StringComparison.Ordinal)).Distinct().ToArray();
        Assert.Equal(3, temps.Length);
        foreach (string name in temps)
            Assert.Matches(new Regex(@"^\.out\.csv\.[0-9a-f]{8}\.tmp$"), name);
    }

    [Fact]
    public async Task Wrap_OutputFile_IsPrivateOnUnix()
    {
        if (OperatingSystem.IsWindows())
            return;
        using var dir = new TempDir();
        string input = dir.File("in.csv");
        string output = dir.File("out.csv");
        File.WriteAllText(input, "x\n");

        await Tool.RunAsync(new[] { "wrap", input, output, "--column", "1" });

#pragma warning disable CA1416 // Guarded by OperatingSystem.IsWindows above.
        Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(output));
#pragma warning restore CA1416
    }
}

/// <summary>Mutation tests that touch the real process console, so they run with the other real-console tests.</summary>
[Collection(RealConsoleCollection.Name)]
public class RealConsoleMutationTests
{
    [Fact]
    public void SystemConsole_In_IsTheConsoleReaderOnlyWhenNotRedirected()
    {
        TextReader reader = new SystemConsole().In;

        Assert.Equal(!Console.IsInputRedirected, ReferenceEquals(reader, Console.In));
        if (Console.IsInputRedirected)
            Assert.IsType<StreamReader>(reader);
    }
}

/// <summary>
/// Mutants first judged equivalent or unreachable that turned out to be observable: recorded calls, a captured
/// synchronization context, a scheduler that fails before any work starts, and a huge line-length cap.
/// </summary>
public class MutationRefutationTests
{
    /// <summary>A legacy format that recognizes nothing and counts how often it is asked and how often its id is read.</summary>
    private sealed class CountingFormat : ILegacyHashFormat
    {
        public int CanHandleCalls;
        public int IdReads;

        public string Id
        {
            get
            {
                IdReads++;
                return "counting";
            }
        }

        public bool CanHandle(string storedHash)
        {
            CanHandleCalls++;
            return false;
        }

        public bool Verify(string password, string storedHash) => false;

        public bool TryExtractWrapInput(string storedHash, out byte[] digest, out byte[] parameter)
        {
            digest = Array.Empty<byte>();
            parameter = Array.Empty<byte>();
            return false;
        }

        public byte[] ComputeWrapInput(string password, byte[] parameter) => throw new NotSupportedException();
    }

    [Fact]
    public async Task Audit_OnlyMasterlyHashesAreInspectedForTheirPepperKey()
    {
        // HashAudit inspects each value once. The pepper-key pre-pass must inspect only "$mh$" values: inspecting a
        // legacy or unknown value there too would ask every legacy format a second time.
        var counting = new CountingFormat();
        string mh = "$mh$p=test$" + HashPrimitives.ToB64(new byte[16]) + "$" + HashPrimitives.ToB64(new byte[32]);

        ToolRun run = await Tool.RunAsync(new[] { "audit", "-", "--format", "json" }, "zzz\n" + mh + "\n",
            configure: e => e.HasherOptionsFactory = () =>
            {
                PasswordHasherOptions options = TestHashers.Options();
                options.LegacyFormats.Insert(0, counting);
                return options;
            });

        Assert.Equal(ExitCodes.Success, run.ExitCode);
        Assert.Equal(1, counting.CanHandleCalls);
    }

    [Fact]
    public async Task Wrap_V1Replacement_StopsLookingAtTheFirstMatch()
    {
        using var dir = new TempDir();
        string input = dir.File("in.csv");
        File.WriteAllText(input, "x\n");

        async Task<int> IdReads(params string[] extra)
        {
            var counting = new CountingFormat();
            ToolRun run = await Tool.RunAsync(
                new[] { "wrap", input, dir.File("out.csv"), "--column", "1", "--force" }.Concat(extra).ToArray(),
                configure: e => e.HasherOptionsFactory = () =>
                {
                    PasswordHasherOptions options = TestHashers.Options();
                    options.LegacyFormats.Clear();
                    options.LegacyFormats.Add(V1LegacyFormat.Instance);
                    options.LegacyFormats.Add(counting);
                    return options;
                });
            Assert.Equal(ExitCodes.Success, run.ExitCode);
            return counting.IdReads;
        }

        int without = await IdReads();
        int with = await IdReads("--v1-algorithm", "SHA512");

        // The host's v1 is at index 0, so the replacement loop must stop there and never read the next format's id.
        Assert.True(without > 0);
        Assert.Equal(without, with);
    }

    /// <summary>A scheduler that fails as soon as Parallel.For asks how much concurrency it allows.</summary>
    private sealed class OutOfMemoryScheduler : TaskScheduler
    {
        public override int MaximumConcurrencyLevel => throw new OutOfMemoryException();

        protected override IEnumerable<Task> GetScheduledTasks() => Array.Empty<Task>();

        protected override void QueueTask(Task task) => throw new NotSupportedException();

        protected override bool TryExecuteTaskInline(Task task, bool taskWasPreviouslyQueued) => false;
    }

    [Fact]
    public void ProcessBatch_UnwrappedOutOfMemory_BecomesTheClearToolError()
    {
        // Parallel.For reads the scheduler's concurrency level before it starts any task, so this OutOfMemoryException
        // reaches ProcessBatch directly, not inside an AggregateException.
        var results = new WrapCommand.RowResult[2];
        var parallel = new ParallelOptions { TaskScheduler = new OutOfMemoryScheduler() };
        int calls = 0;

        var ex = Assert.Throws<ToolException>(() =>
            WrapCommand.ProcessBatch(2, results, parallel, _ =>
            {
                calls++;
                return WrapCommand.RowResult.Skip("x");
            }));

        Assert.Equal("Out of memory while hashing: each Argon2id hash needs the profile's memory (64 MiB for 2026a). " +
            "Try a lower --parallelism, or --profile 2026c.", ex.Message);
        Assert.Equal(0, calls);
    }

    [Fact]
    public void LineReader_HugeCap_GrowsTheBufferLazily()
    {
        // With a cap near int.MaxValue the buffer must start small and grow by doubling. Allocating the cap up front,
        // or on the first growth, fails with "Array dimensions exceeded supported range".
        string line = new string('a', 300);

        Assert.Equal(line, LineReader.ReadLine(new StringReader(line + "\r\n"), int.MaxValue - 1, "too long"));
    }

    /// <summary>
    /// Records which async method each posted continuation belongs to (the state machine type in the box's name) and
    /// runs it on the thread pool.
    /// </summary>
    private sealed class RecordingSynchronizationContext : SynchronizationContext
    {
        private readonly System.Collections.Concurrent.ConcurrentQueue<string> _posted = new System.Collections.Concurrent.ConcurrentQueue<string>();

        public IReadOnlyList<string> Posted => _posted.ToArray();

        public override void Post(SendOrPostCallback d, object? state)
        {
            _posted.Enqueue(((state as Delegate)?.Target ?? state)?.GetType().FullName ?? "(null)");
            ThreadPool.QueueUserWorkItem(_ => d(state));
        }

        public override void Send(SendOrPostCallback d, object? state) => throw new NotSupportedException();
    }

    /// <summary>A breach checker whose answer arrives later. It records the synchronization context it was called on.</summary>
    private sealed class PendingBreachChecker : IBreachedPasswordChecker
    {
        public readonly TaskCompletionSource<BreachCheckResult> Answer = new TaskCompletionSource<BreachCheckResult>();

        public SynchronizationContext? ContextAtCall { get; private set; }

        public ValueTask<BreachCheckResult> CheckAsync(string password, CancellationToken cancellationToken)
        {
            ContextAtCall = SynchronizationContext.Current;
            return new ValueTask<BreachCheckResult>(Answer.Task);
        }
    }

    [Fact]
    public async Task Policy_Pwned_NeverResumesOnTheCallersSynchronizationContext()
    {
        // ToolApp.RunAsync and PolicyCommand both await with ConfigureAwait(false). The in-process tool must not post
        // its own continuations back to the host's context, which could deadlock a UI thread or a single-threaded
        // context. (System.CommandLine's InvocationPipeline does post one; that is outside this tool.)
        var checker = new PendingBreachChecker();
        var console = new FakeConsole("Xq7#vR2m!Lp9@zW4&kT8^bN\n", true, Array.Empty<string?>());
        var environment = new ToolEnvironment(console)
        {
            HasherOptionsFactory = TestHashers.Options,
            BreachCheckerFactory = () => checker,
        };
        var context = new RecordingSynchronizationContext();

        SynchronizationContext? previous = SynchronizationContext.Current;
        Task<int> run;
        SynchronizationContext.SetSynchronizationContext(context);
        try
        {
            run = ToolApp.RunAsync(new[] { "policy", "--stdin", "--pwned" }, environment);
        }
        finally
        {
            SynchronizationContext.SetSynchronizationContext(previous);
        }

        // The command is suspended on the checker, and the checker ran on the caller's context, so a capturing await
        // would have to post its continuation there.
        Assert.False(run.IsCompleted);
        Assert.Same(context, checker.ContextAtCall);

        checker.Answer.SetResult(BreachCheckResult.NotBreached);
        int exit = await run;

        Assert.Equal(ExitCodes.Success, exit);
        // A capturing await in PolicyCommand.ExecuteAsync or ToolApp.RunAsync would show up here by its state machine name.
        Assert.All(context.Posted, name => Assert.DoesNotContain("Masterly.Hash.Tool.", name, StringComparison.Ordinal));
        Assert.All(context.Posted, name => Assert.Contains("+<", name, StringComparison.Ordinal)); // Names really are state machines.
        Assert.EndsWith("Breach check (online, Have I Been Pwned k-anonymity): not found in known breaches" + Environment.NewLine,
            console.OutText);
    }
}
