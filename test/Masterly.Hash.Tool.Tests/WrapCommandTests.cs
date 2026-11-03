using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Masterly.Hash.Legacy;
using Masterly.Hash.Tool.IO;

namespace Masterly.Hash.Tool.Tests;

public class WrapCommandTests
{
    private static readonly byte[] V1Salt = Encoding.UTF8.GetBytes("per-user-salt-1x");

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

    [Fact]
    public async Task RoundTrip_WrappedHashesVerifyWithOriginalPasswords()
    {
        using var dir = new TempDir();
        string v1 = TestHashers.V1("alpha-pass", V1Salt, V1Algorithm.SHA512);
        string md5 = TestHashers.Md5Hex("bravo-pass");
        string bcrypt = BCrypt.Net.BCrypt.HashPassword("charlie-pass", 4);
        string current = TestHashers.Hasher().Hash("delta-pass");
        string input = dir.File("users.csv");
        File.WriteAllText(input,
            "id,email,password_hash,note\r\n" +
            "1,a@example.com," + v1 + ",plain\r\n" +
            "2,b@example.com," + md5 + ",\"has, comma\"\r\n" +
            "3,c@example.com," + bcrypt + ",\"multi\r\nline \"\"quoted\"\"\"\r\n" +
            "4,d@example.com,\"" + current + "\",current\r\n" +
            "5,e@example.com,not-a-hash,garbage\r\n" +
            "6,f@example.com,,empty\r\n");
        string output = dir.File("wrapped.csv");

        ToolRun run = await Tool.RunAsync(new[] { "wrap", input, output, "--column", "3", "--header", "--v1-algorithm", "SHA512", "--parallelism", "2" });

        Assert.Equal(ExitCodes.Success, run.ExitCode);
        Assert.Contains("Rows:            6", run.Out);
        Assert.Contains("Wrapped:         3", run.Out);
        Assert.Contains("Already current: 1", run.Out);
        Assert.Contains("Skipped:         2", run.Out);
        Assert.Contains("  bcrypt: 1", run.Out);
        Assert.Contains("  md5: 1", run.Out);
        Assert.Contains("  v1: 1", run.Out);
        Assert.Contains("  unknown format: 1", run.Out);
        Assert.Contains("  empty: 1", run.Out);

        List<CsvRecord> rows = ReadCsv(output);
        Assert.Equal(7, rows.Count);
        Assert.Equal("id,email,password_hash,note", string.Join(",", rows[0].Fields.Select(f => f.Raw)));

        PasswordHasher hasher = TestHashers.Hasher();
        var expected = new Dictionary<int, (string Password, string Format)>
        {
            [1] = ("alpha-pass", "v1"),
            [2] = ("bravo-pass", "md5"),
            [3] = ("charlie-pass", "bcrypt"),
        };
        foreach (KeyValuePair<int, (string Password, string Format)> entry in expected)
        {
            string wrapped = rows[entry.Key].Fields[2].Value;
            Assert.Matches(@"^\$mh\$p=test,w=" + entry.Value.Format + @"[,$]", wrapped);
            PasswordVerificationResult result = hasher.Verify(entry.Value.Password, wrapped);
            Assert.True(result.IsMatch, entry.Value.Format);
            Assert.Equal(RehashReason.Wrapped, result.RehashReason);
            Assert.False(hasher.Verify("wrong-password", wrapped).IsMatch);
        }

        // Other columns are byte-for-byte unchanged, including quoting and embedded line breaks.
        Assert.Equal("\"has, comma\"", rows[2].Fields[3].Raw);
        Assert.Equal("\"multi\r\nline \"\"quoted\"\"\"", rows[3].Fields[3].Raw);
        Assert.Equal("\"" + current + "\"", rows[4].Fields[2].Raw);
        Assert.Equal("not-a-hash", rows[5].Fields[2].Raw);
        Assert.Equal(string.Empty, rows[6].Fields[2].Raw);
        Assert.All(rows, r => Assert.Equal("\r\n", r.Terminator));

        // Wrapped hashes contain ',' so they are quoted; the legacy digests are gone.
        string text = File.ReadAllText(output);
        Assert.DoesNotContain(md5, text);
        Assert.DoesNotContain(v1, text);
        Assert.DoesNotContain(bcrypt, text);
        Assert.Equal(1, rows[1].Fields[2].Raw.Count(c => c == '"') / 2);
    }

    [Fact]
    public async Task RoundTrip_WrappedHashVerifiesThroughVerifyCommand()
    {
        using var dir = new TempDir();
        string input = dir.File("in.csv");
        File.WriteAllText(input, "u1;" + TestHashers.Md5Hex("echo-pass") + "\n");
        string output = dir.File("out.csv");

        ToolRun wrap = await Tool.RunAsync(new[] { "wrap", input, output, "--column", "2", "--delimiter", ";" });
        Assert.Equal(ExitCodes.Success, wrap.ExitCode);

        string wrapped = File.ReadAllText(output).Split(';')[1].TrimEnd('\n');
        ToolRun verify = await Tool.RunAsync(new[] { "verify", "--stdin", wrapped }, "echo-pass\n");

        Assert.Equal(ExitCodes.Success, verify.ExitCode);
        Assert.Contains("Rehash reason:  Wrapped", verify.Out);
    }

    [Fact]
    public async Task V1_WithoutAlgorithm_IsSkippedWithHint()
    {
        using var dir = new TempDir();
        string v1 = TestHashers.V1("pw", V1Salt, V1Algorithm.SHA256);
        string input = dir.File("in.csv");
        File.WriteAllText(input, v1 + "\n");
        string output = dir.File("out.csv");

        ToolRun run = await Tool.RunAsync(new[] { "wrap", input, output, "--column", "1" });

        Assert.Equal(ExitCodes.Success, run.ExitCode);
        Assert.Contains("Wrapped:         0", run.Out);
        Assert.Contains("--v1-algorithm", run.Out);
        Assert.Equal(v1 + "\n", File.ReadAllText(output));
    }

    [Fact]
    public async Task V1_Sha256_RoundTrips()
    {
        using var dir = new TempDir();
        string input = dir.File("in.csv");
        File.WriteAllText(input, TestHashers.V1("sha256-pass", V1Salt, V1Algorithm.SHA256) + "\n");
        string output = dir.File("out.csv");

        ToolRun run = await Tool.RunAsync(new[] { "wrap", input, output, "--column", "1", "--v1-algorithm", "SHA256" });

        Assert.Equal(ExitCodes.Success, run.ExitCode);
        string wrapped = ReadCsv(output)[0].Fields[0].Value;
        Assert.True(TestHashers.Hasher().Verify("sha256-pass", wrapped).IsMatch);
    }

    [Fact]
    public async Task WeakOnly_LeavesStrongLegacyHashesAlone()
    {
        using var dir = new TempDir();
        string strong = BCrypt.Net.BCrypt.HashPassword("strong-bcrypt", 10);
        string weak = BCrypt.Net.BCrypt.HashPassword("weak-bcrypt", 4);
        string input = dir.File("in.csv");
        File.WriteAllText(input, strong + "\n" + weak + "\n");
        string output = dir.File("out.csv");

        ToolRun run = await Tool.RunAsync(new[] { "wrap", input, output, "--column", "1", "--weak-only" });

        Assert.Equal(ExitCodes.Success, run.ExitCode);
        Assert.Contains("Wrapped:         1", run.Out);
        Assert.Contains("bcrypt (not weak): 1", run.Out);
        List<CsvRecord> rows = ReadCsv(output);
        Assert.Equal(strong, rows[0].Fields[0].Value);
        Assert.True(TestHashers.Hasher().Verify("weak-bcrypt", rows[1].Fields[0].Value).IsMatch);
    }

    [Fact]
    public async Task Streaming_ManyRows_PreservesOrder()
    {
        using var dir = new TempDir();
        string input = dir.File("big.csv");
        var sb = new StringBuilder();
        const int count = 1500;
        for (int i = 0; i < count; i++)
            sb.Append(i).Append(',').Append(TestHashers.Md5Hex("pw-" + i)).Append('\n');
        File.WriteAllText(input, sb.ToString());
        string output = dir.File("big-out.csv");

        ToolRun run = await Tool.RunAsync(new[] { "wrap", input, output, "--column", "2", "--parallelism", "4" });

        Assert.Equal(ExitCodes.Success, run.ExitCode);
        Assert.Contains("Wrapped:         1500", run.Out);
        List<CsvRecord> rows = ReadCsv(output);
        Assert.Equal(count, rows.Count);
        PasswordHasher hasher = TestHashers.Hasher();
        foreach (int i in new[] { 0, 1, 63, 64, 65, 777, count - 1 })
        {
            Assert.Equal(i.ToString(System.Globalization.CultureInfo.InvariantCulture), rows[i].Fields[0].Value);
            Assert.True(hasher.Verify("pw-" + i, rows[i].Fields[1].Value).IsMatch, "row " + i);
        }
    }

    [Fact]
    public async Task PreservesLfEndings_BlankLines_MissingFinalNewline_AndBom()
    {
        using var dir = new TempDir();
        string input = dir.File("in.csv");
        string md5 = TestHashers.Md5Hex("pw");
        File.WriteAllText(input, "a," + md5 + "\n\nb\nc," + md5, new UTF8Encoding(true));
        string output = dir.File("out.csv");

        ToolRun run = await Tool.RunAsync(new[] { "wrap", input, output, "--column", "2" });

        Assert.Equal(ExitCodes.Success, run.ExitCode);
        Assert.Contains("Rows:            3", run.Out);
        Assert.Contains("missing column: 1", run.Out);
        byte[] bytes = File.ReadAllBytes(output);
        Assert.Equal(new byte[] { 0xEF, 0xBB, 0xBF }, bytes.Take(3).ToArray());
        string text = new UTF8Encoding(false).GetString(bytes, 3, bytes.Length - 3);
        string[] lines = text.Split('\n');
        Assert.Equal(4, lines.Length);
        Assert.Equal(string.Empty, lines[1]);
        Assert.Equal("b", lines[2]);
        Assert.StartsWith("c,\"$mh$", lines[3]);
        Assert.EndsWith("\"", lines[3]);
        Assert.DoesNotContain("\r", text);
    }

    [Fact]
    public async Task NoBom_InputGivesNoBomOutput()
    {
        using var dir = new TempDir();
        string input = dir.File("in.csv");
        File.WriteAllText(input, "x\n", new UTF8Encoding(false));
        string output = dir.File("out.csv");

        ToolRun run = await Tool.RunAsync(new[] { "wrap", input, output, "--column", "1" });

        Assert.Equal(ExitCodes.Success, run.ExitCode);
        Assert.Equal(new byte[] { (byte)'x', (byte)'\n' }, File.ReadAllBytes(output));
    }

    [Fact]
    public async Task ExistingOutput_RequiresForce()
    {
        using var dir = new TempDir();
        string input = dir.File("in.csv");
        File.WriteAllText(input, TestHashers.Md5Hex("pw") + "\n");
        string output = dir.File("out.csv");
        File.WriteAllText(output, "keep me");

        ToolRun refused = await Tool.RunAsync(new[] { "wrap", input, output, "--column", "1" });
        Assert.Equal(ExitCodes.Error, refused.ExitCode);
        Assert.Contains("--force", refused.Error);
        Assert.Equal("keep me", File.ReadAllText(output));

        ToolRun forced = await Tool.RunAsync(new[] { "wrap", input, output, "--column", "1", "--force" });
        Assert.Equal(ExitCodes.Success, forced.ExitCode);
        Assert.StartsWith("\"$mh$", File.ReadAllText(output));
    }

    [Fact]
    public async Task SameInputAndOutput_IsRefused()
    {
        using var dir = new TempDir();
        string input = dir.File("in.csv");
        File.WriteAllText(input, "x\n");

        ToolRun run = await Tool.RunAsync(new[] { "wrap", input, input, "--column", "1", "--force" });

        Assert.Equal(ExitCodes.Error, run.ExitCode);
        Assert.Equal("x\n", File.ReadAllText(input));
    }

    [Fact]
    public async Task MalformedCsv_FailsCleanly_AndLeavesNoFiles()
    {
        using var dir = new TempDir();
        string input = dir.File("in.csv");
        File.WriteAllText(input, "ok\n\"unterminated quote\nmore");
        string output = dir.File("out.csv");

        ToolRun run = await Tool.RunAsync(new[] { "wrap", input, output, "--column", "1" });

        Assert.Equal(ExitCodes.Error, run.ExitCode);
        Assert.Contains("Unterminated quoted field", run.Error);
        Assert.False(File.Exists(output));
        Assert.Single(Directory.GetFiles(dir.Path));
    }

    [Theory]
    [InlineData("--column", "0")]
    [InlineData("--column", "abc")]
    [InlineData("--column", "1", "--parallelism", "0")]
    [InlineData("--column", "1", "--parallelism", "65")]
    [InlineData("--column", "1", "--v1-algorithm", "MD5")]
    [InlineData("--column", "1", "--delimiter", "ab")]
    [InlineData("--column", "1", "--delimiter", "\"")]
    [InlineData("--column", "1", "--profile", "weak")]
    public async Task ArgumentErrors_ExitTwo(params string[] options)
    {
        using var dir = new TempDir();
        string input = dir.File("in.csv");
        File.WriteAllText(input, "x\n");

        ToolRun run = await Tool.RunAsync(new[] { "wrap", input, dir.File("out.csv") }.Concat(options).ToArray());

        Assert.Equal(ExitCodes.Error, run.ExitCode);
        Assert.StartsWith("error:", run.Error);
        Assert.False(File.Exists(dir.File("out.csv")));
    }

    [Fact]
    public async Task MissingColumnOption_IsError()
    {
        using var dir = new TempDir();
        string input = dir.File("in.csv");
        File.WriteAllText(input, "x\n");

        ToolRun run = await Tool.RunAsync(new[] { "wrap", input, dir.File("out.csv") });

        Assert.Equal(ExitCodes.Error, run.ExitCode);
        Assert.Contains("--column", run.Error);
    }

    [Fact]
    public async Task MissingInput_IsError()
    {
        using var dir = new TempDir();

        ToolRun run = await Tool.RunAsync(new[] { "wrap", dir.File("nope.csv"), dir.File("out.csv"), "--column", "1" });

        Assert.Equal(ExitCodes.Error, run.ExitCode);
        Assert.Contains("not found", run.Error);
    }

    [Fact]
    public async Task Profile_SetsWrappingProfile()
    {
        using var dir = new TempDir();
        string input = dir.File("in.csv");
        File.WriteAllText(input, TestHashers.Md5Hex("fips-pass") + "\n");
        string output = dir.File("out.csv");

        ToolRun run = await Tool.RunAsync(new[] { "wrap", input, output, "--column", "1", "--profile", "2026f" });

        Assert.Equal(ExitCodes.Success, run.ExitCode);
        string wrapped = ReadCsv(output)[0].Fields[0].Value;
        Assert.StartsWith("$mh$p=2026f,w=md5$", wrapped);
        Assert.True(TestHashers.Hasher().Verify("fips-pass", wrapped).IsMatch);
    }

    [Fact]
    public async Task WrappedHash_IsAlreadyCurrentOnSecondPass()
    {
        using var dir = new TempDir();
        string input = dir.File("in.csv");
        File.WriteAllText(input, TestHashers.Md5Hex("pw") + "\n");
        string once = dir.File("once.csv");
        string twice = dir.File("twice.csv");

        Assert.Equal(ExitCodes.Success, (await Tool.RunAsync(new[] { "wrap", input, once, "--column", "1" })).ExitCode);
        ToolRun second = await Tool.RunAsync(new[] { "wrap", once, twice, "--column", "1" });

        Assert.Equal(ExitCodes.Success, second.ExitCode);
        Assert.Contains("Already current: 1", second.Out);
        Assert.Equal(File.ReadAllText(once), File.ReadAllText(twice));
    }
}
