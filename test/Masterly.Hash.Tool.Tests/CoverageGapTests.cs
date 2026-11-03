using System;
using System.Collections.Generic;
using System.CommandLine;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Masterly.Hash.Legacy;
using Masterly.Hash.Pepper;
using Masterly.Hash.Policy;
using Masterly.Hash.Tool.Commands;
using Masterly.Hash.Tool.IO;

namespace Masterly.Hash.Tool.Tests;

/// <summary>Error handling, rarely taken wrap paths and argument validation of the internal command entry points.</summary>
public class CoverageGapTests
{
    private static readonly byte[] V1Salt = Encoding.UTF8.GetBytes("per-user-salt-1x");

    /// <summary>A hasher whose only legacy format is 1.x with the given digest.</summary>
    private static PasswordHasher V1Verifier(V1Algorithm algorithm)
    {
        PasswordHasherOptions options = TestHashers.Options();
        options.LegacyFormats.Clear();
        options.LegacyFormats.Add(new V1LegacyFormat(algorithm));
        return new PasswordHasher(options);
    }

    private static List<CsvRecord> ReadCsv(string path)
    {
        using var reader = new StreamReader(path);
        var csv = new CsvRecordReader(reader, ',');
        var records = new List<CsvRecord>();
        CsvRecord? record;
        while ((record = csv.Read()) != null)
            records.Add(record);
        return records;
    }

    // ---- ToolApp error handlers -----------------------------------------------------------------------------

    public static TheoryData<string> EnvironmentFailures => new() { "io", "access", "busy" };

    [Theory]
    [MemberData(nameof(EnvironmentFailures))]
    public async Task EnvironmentFailure_IsPrintedAsErrorWithExitTwo(string kind)
    {
        Exception failure = kind switch
        {
            "io" => new IOException("disk went away"),
            "access" => new UnauthorizedAccessException("access to the key store is denied"),
            _ => new PasswordHasherBusyException(),
        };

        ToolRun run = await Tool.RunAsync(new[] { "inspect", TestHashers.Md5Hex("pw") },
            configure: e => e.HasherOptionsFactory = () => throw failure);

        Assert.Equal(ExitCodes.Error, run.ExitCode);
        Assert.Equal("error: " + failure.Message + Environment.NewLine, run.Error);
        Assert.Equal(string.Empty, run.Out);
    }

    [Fact]
    public async Task HasherOptionsFactoryReturningNull_IsAProgrammingError()
    {
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            Tool.RunAsync(new[] { "inspect", TestHashers.Md5Hex("pw") }, configure: e => e.HasherOptionsFactory = () => null!));

        Assert.Equal("HasherOptionsFactory returned null.", ex.Message);
    }

    [Fact]
    public void PossibleSecrets_CommandAliasesAreNotSecrets()
    {
        var sub = new Command("generate");
        sub.Aliases.Add("gen");
        var root = new RootCommand { sub };

        IReadOnlyList<string> secrets = ToolApp.PossibleSecrets(root, new[] { "gen", "generate", "hunter22" });

        Assert.Equal(new[] { "hunter22" }, secrets);
    }

    // ---- CommandHelpers -------------------------------------------------------------------------------------

    [Fact]
    public void ResolveProfile_MapsEveryBuiltInId()
    {
        Assert.Same(HashProfile.Server2026a, CommandHelpers.ResolveProfile("2026a"));
        Assert.Same(HashProfile.Constrained2026a, CommandHelpers.ResolveProfile("2026c"));
        Assert.Same(HashProfile.Fips2026a, CommandHelpers.ResolveProfile("2026f"));
    }

    [Fact]
    public void ResolveProfile_UnknownId_IsToolError()
    {
        var ex = Assert.Throws<ToolException>(() => CommandHelpers.ResolveProfile("2019x"));

        Assert.Equal("Unknown profile; use 2026a, 2026c or 2026f.", ex.Message);
        Assert.Equal(ExitCodes.Error, ex.ExitCode);
    }

    // ---- wrap -----------------------------------------------------------------------------------------------

    [Fact]
    public async Task Wrap_OutputIsADirectory_IsError()
    {
        using var dir = new TempDir();
        string input = dir.File("in.csv");
        File.WriteAllText(input, TestHashers.Md5Hex("pw") + "\n");
        string output = dir.File("out.csv");
        Directory.CreateDirectory(output);

        ToolRun run = await Tool.RunAsync(new[] { "wrap", input, output, "--column", "1" });

        Assert.Equal(ExitCodes.Error, run.ExitCode);
        Assert.Equal("error: The output path is a directory: " + output + Environment.NewLine, run.Error);
        Assert.Empty(Directory.GetFileSystemEntries(output));
    }

    [Fact]
    public async Task Wrap_V1AlgorithmSha384_WrapsSha384Hashes()
    {
        using var dir = new TempDir();
        string input = dir.File("in.csv");
        string v1 = TestHashers.V1("sha384-pass", V1Salt, V1Algorithm.SHA384);
        File.WriteAllText(input, v1 + "\n");
        string output = dir.File("out.csv");

        ToolRun run = await Tool.RunAsync(new[] { "wrap", input, output, "--column", "1", "--v1-algorithm", "SHA384" });

        Assert.Equal(ExitCodes.Success, run.ExitCode);
        Assert.Contains("Wrapped:         1", run.Out);
        string wrapped = ReadCsv(output)[0].Fields[0].Value;
        Assert.StartsWith("$mh$p=test,w=v1,", wrapped);
        Assert.True(V1Verifier(V1Algorithm.SHA384).Verify("sha384-pass", wrapped).IsMatch);
    }

    [Fact]
    public async Task Wrap_V1Algorithm_ReplacesAV1FormatTheEnvironmentAlreadyRegistered()
    {
        // The host replaced the default v1 format with its own (SHA-512), as the migration guide shows. The tool must
        // replace that one by id for --v1-algorithm SHA256, not register a second 'v1' format.
        using var dir = new TempDir();
        string input = dir.File("in.csv");
        File.WriteAllText(input, TestHashers.V1("sha256-pass", V1Salt, V1Algorithm.SHA256) + "\n");
        string output = dir.File("out.csv");

        ToolRun run = await Tool.RunAsync(new[] { "wrap", input, output, "--column", "1", "--v1-algorithm", "SHA256" },
            configure: e => e.HasherOptionsFactory = () =>
            {
                PasswordHasherOptions options = TestHashers.Options();
                options.LegacyFormats[0] = new V1LegacyFormat(V1Algorithm.SHA512);
                return options;
            });

        Assert.Equal(ExitCodes.Success, run.ExitCode);
        Assert.Contains("Wrapped:         1", run.Out);
        string wrapped = ReadCsv(output)[0].Fields[0].Value;
        Assert.True(V1Verifier(V1Algorithm.SHA256).Verify("sha256-pass", wrapped).IsMatch);
    }

    [Fact]
    public async Task Wrap_ReportsProgressEveryTenThousandRows()
    {
        using var dir = new TempDir();
        string input = dir.File("in.csv");
        // Unrecognized values are skipped without hashing, so this is fast.
        File.WriteAllText(input, string.Concat(Enumerable.Repeat("not-a-hash\n", 25_000)));
        string output = dir.File("out.csv");

        ToolRun run = await Tool.RunAsync(new[] { "wrap", input, output, "--column", "1", "--parallelism", "1" });

        Assert.Equal(ExitCodes.Success, run.ExitCode);
        string[] progress = run.Error.Split(Environment.NewLine, StringSplitOptions.RemoveEmptyEntries);
        Assert.Equal(new[] { "wrap: 10000 rows processed", "wrap: 20000 rows processed" }, progress);
        Assert.Contains("Rows:            25000", run.Out);
        Assert.Contains("  unknown format: 25000", run.Out);
    }

    [Fact]
    public async Task Wrap_RecognizedFormatThatCannotBeWrapped_IsSkippedWithReason()
    {
        using var dir = new TempDir();
        string input = dir.File("in.csv");
        File.WriteAllText(input, "opaque:1\n");
        string output = dir.File("out.csv");

        ToolRun run = await Tool.RunAsync(new[] { "wrap", input, output, "--column", "1" },
            configure: e => e.HasherOptionsFactory = () =>
            {
                PasswordHasherOptions options = TestHashers.Options();
                options.LegacyFormats.Add(new OpaqueFormat());
                return options;
            });

        Assert.Equal(ExitCodes.Success, run.ExitCode);
        Assert.Contains("  opaque (cannot be wrapped): 1", run.Out);
        Assert.Equal("opaque:1\n", File.ReadAllText(output));
    }

    [Theory]
    [InlineData("FEFF0041", "UTF-16 or UTF-32")]      // UTF-16 big-endian BOM
    [InlineData("0000FEFF", "UTF-16 or UTF-32")]      // UTF-32 big-endian BOM
    [InlineData("FF41", "not valid UTF-8")]           // 0xFF that is not a BOM
    [InlineData("FE41", "not valid UTF-8")]           // 0xFE that is not a BOM
    [InlineData("0000FE41", "not valid UTF-8")]       // almost a UTF-32 BOM
    public async Task Wrap_ByteOrderMarkDetection_RefusesNonUtf8(string hex, string expected)
    {
        using var dir = new TempDir();
        string input = dir.File("in.csv");
        File.WriteAllBytes(input, Convert.FromHexString(hex));
        string output = dir.File("out.csv");

        ToolRun run = await Tool.RunAsync(new[] { "wrap", input, output, "--column", "1" });

        Assert.Equal(ExitCodes.Error, run.ExitCode);
        Assert.Contains(expected, run.Error);
        Assert.False(File.Exists(output));
        Assert.Equal(new[] { input }, Directory.GetFiles(dir.Path));
    }

    [Theory]
    [InlineData("78")]          // a single byte
    [InlineData("00000A")]      // three bytes, two of them zero
    [InlineData("0000000A")]    // four bytes, starts like UTF-32 but is not
    [InlineData("00010A")]
    [InlineData("01000A")]
    public async Task Wrap_ShortOrZeroLeadingUtf8Input_IsAccepted(string hex)
    {
        using var dir = new TempDir();
        string input = dir.File("in.csv");
        byte[] bytes = Convert.FromHexString(hex);
        File.WriteAllBytes(input, bytes);
        string output = dir.File("out.csv");

        ToolRun run = await Tool.RunAsync(new[] { "wrap", input, output, "--column", "1" });

        Assert.Equal(ExitCodes.Success, run.ExitCode);
        Assert.Equal(bytes, File.ReadAllBytes(output));
    }

    [Fact]
    public async Task Wrap_OutputLockedByAnotherProcess_IsCleanErrorAndTempFileIsRemoved()
    {
        if (!OperatingSystem.IsWindows())
            return; // Unix rename replaces an open file, so there is nothing to fail.

        using var dir = new TempDir();
        string input = dir.File("in.csv");
        File.WriteAllText(input, TestHashers.Md5Hex("pw") + "\n");
        string output = dir.File("out.csv");
        File.WriteAllText(output, "old");

        ToolRun run;
        using (new FileStream(output, FileMode.Open, FileAccess.Read, FileShare.None))
            run = await Tool.RunAsync(new[] { "wrap", input, output, "--column", "1", "--force" });

        Assert.Equal(ExitCodes.Error, run.ExitCode);
        Assert.StartsWith("error: ", run.Error);
        Assert.Equal("old", File.ReadAllText(output));
        Assert.Equal(new[] { input, output }.OrderBy(p => p), Directory.GetFiles(dir.Path).OrderBy(p => p));
    }

    [Fact]
    public async Task Wrap_TempFileThatCannotBeDeleted_DoesNotHideTheOriginalError()
    {
        if (!OperatingSystem.IsWindows())
            return; // Only Windows refuses to delete a read-only file.

        using var dir = new TempDir();
        string input = dir.File("in.csv");
        File.WriteAllText(input, TestHashers.Md5Hex("pw") + "\n");
        string output = dir.File("out.csv");
        try
        {
            // While the row is being wrapped the temporary output exists: make it read-only, then fail the run.
            ToolRun run = await Tool.RunAsync(new[] { "wrap", input, output, "--column", "1", "--parallelism", "1" },
                configure: e => e.HasherOptionsFactory = () =>
                {
                    PasswordHasherOptions options = TestHashers.Options();
                    options.Pepper = new CallbackPepper(() =>
                    {
                        foreach (string temp in Directory.GetFiles(dir.Path, ".out.csv.*.tmp"))
                            File.SetAttributes(temp, FileAttributes.ReadOnly);
                        throw new IOException("pepper service offline");
                    });
                    return options;
                });

            Assert.Equal(ExitCodes.Error, run.ExitCode);
            Assert.Equal("error: pepper service offline" + Environment.NewLine, run.Error);
            Assert.False(File.Exists(output));
            Assert.Single(Directory.GetFiles(dir.Path, ".out.csv.*.tmp"));
        }
        finally
        {
            foreach (string temp in Directory.GetFiles(dir.Path, ".out.csv.*.tmp"))
                File.SetAttributes(temp, FileAttributes.Normal);
        }
    }

    [Fact]
    public void ProcessBatch_AggregateWithoutInnerExceptions_IsRethrownAsIs()
    {
        var results = new WrapCommand.RowResult[2];
        var parallel = new ParallelOptions { MaxDegreeOfParallelism = 1 };

        var ex = Assert.Throws<AggregateException>(() =>
            WrapCommand.ProcessBatch(1, results, parallel, _ => throw new AggregateException()));

        AggregateException inner = Assert.IsType<AggregateException>(Assert.Single(ex.InnerExceptions));
        Assert.Empty(inner.InnerExceptions);
    }

    [Fact]
    public void Wrap_Execute_NullSettings_Throws()
    {
        var environment = new ToolEnvironment(new FakeConsole(string.Empty, true, Array.Empty<string?>()));

        Assert.Throws<ArgumentNullException>(() => WrapCommand.Execute(environment, null!, CancellationToken.None));
    }

    // ---- other commands -------------------------------------------------------------------------------------

    [Fact]
    public async Task Policy_Pwned_NonDisposableChecker_IsUsed()
    {
        var checker = new PlainBreachChecker();

        ToolRun run = await Tool.RunAsync(new[] { "policy", "--stdin", "--pwned" }, "correct horse battery staple\n",
            e => e.BreachCheckerFactory = () => checker);

        Assert.Equal(ExitCodes.Success, run.ExitCode);
        Assert.Equal(1, checker.Calls);
        Assert.Contains("Result:     Acceptable", run.Out);
    }

    [Fact]
    public async Task InternalEntryPoints_RejectNullSettings()
    {
        var environment = new ToolEnvironment(new FakeConsole(string.Empty, true, Array.Empty<string?>()));

        Assert.Throws<ArgumentNullException>(() => ApiKeyCommand.Generate(environment, null!));
        await Assert.ThrowsAsync<ArgumentNullException>(() => PolicyCommand.ExecuteAsync(environment, null!, CancellationToken.None));
    }

    [Fact]
    public void ClassificationPepper_ArgumentChecks()
    {
        Assert.Throws<ArgumentNullException>(() => new ClassificationPepper(null!));

        var pepper = new ClassificationPepper(new[] { "k2", "k1" });
        Assert.False(pepper.IsKnownKey(null!));
        Assert.True(pepper.IsKnownKey("k1"));
    }

    [Fact]
    public void Readers_ArgumentChecks()
    {
        Assert.Throws<ArgumentNullException>(() => new CsvRecordReader(null!, ','));
        Assert.Throws<ArgumentOutOfRangeException>(() => new CsvRecordReader(new StringReader("x"), ',', maxRecordChars: 0));
        Assert.Throws<ArgumentNullException>(() => LineReader.ReadLine(null!, 10, "too long"));
    }

    // ---- helpers --------------------------------------------------------------------------------------------

    /// <summary>A legacy format the hasher recognizes but cannot onion-wrap.</summary>
    private sealed class OpaqueFormat : ILegacyHashFormat
    {
        public string Id => "opaque";
        public bool CanHandle(string storedHash) => storedHash.StartsWith("opaque:", StringComparison.Ordinal);
        public bool Verify(string password, string storedHash) => false;

        public bool TryExtractWrapInput(string storedHash, out byte[] digest, out byte[] parameter)
        {
            digest = Array.Empty<byte>();
            parameter = Array.Empty<byte>();
            return false;
        }

        public byte[] ComputeWrapInput(string password, byte[] parameter) => Array.Empty<byte>();
    }

    /// <summary>A pepper whose key lookup runs a callback (which throws) - e.g. a remote key service going down.</summary>
    private sealed class CallbackPepper : IPasswordPepper
    {
        private readonly Action _onApply;

        public CallbackPepper(Action onApply)
        {
            _onApply = onApply;
        }

        public string CurrentKeyId => "k1";
        public bool IsKnownKey(string keyId) => keyId == "k1";

        public byte[] Apply(string keyId, byte[] input)
        {
            _onApply();
            return input;
        }

        public ValueTask<byte[]> ApplyAsync(string keyId, byte[] input, CancellationToken cancellationToken = default) =>
            new ValueTask<byte[]>(Apply(keyId, input));
    }

    /// <summary>A breach checker that is not <see cref="IDisposable"/>.</summary>
    private sealed class PlainBreachChecker : IBreachedPasswordChecker
    {
        public int Calls { get; private set; }

        public ValueTask<BreachCheckResult> CheckAsync(string password, CancellationToken cancellationToken)
        {
            Calls++;
            return new ValueTask<BreachCheckResult>(BreachCheckResult.NotBreached);
        }
    }
}
