using System.IO;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace Masterly.Hash.Tool.Tests;

public class AuditCommandTests
{
    private static string SampleLines()
    {
        PasswordHasher hasher = TestHashers.Hasher();
        return string.Join("\n",
            hasher.Hash("a"),
            hasher.Hash("b"),
            TestHashers.Md5Hex("c"),
            TestHashers.Md5Hex("c"),
            "$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW",
            "garbage",
            "",
            "   ") + "\n";
    }

    [Fact]
    public async Task Lines_FromStdin_Markdown()
    {
        ToolRun run = await Tool.RunAsync(new[] { "audit", "-" }, SampleLines());

        Assert.Equal(ExitCodes.Success, run.ExitCode);
        Assert.Contains("## Password hash audit", run.Out);
        Assert.Contains("| Total | 6 |", run.Out);
        Assert.Contains("| Recognized | 5 |", run.Out);
        Assert.Contains("| Unknown | 1 |", run.Out);
        Assert.Contains("| Weak | 3 |", run.Out);
        Assert.Contains("| Duplicates | 1 |", run.Out);
        Assert.Contains("| md5 | 2 |", run.Out);
        Assert.Contains("| test | 2 |", run.Out);
    }

    [Fact]
    public async Task Lines_FromFile_Json()
    {
        using var dir = new TempDir();
        string file = dir.File("hashes.txt");
        File.WriteAllText(file, SampleLines().Replace("\n", "\r\n"));

        ToolRun run = await Tool.RunAsync(new[] { "audit", file, "--format", "json" });

        Assert.Equal(ExitCodes.Success, run.ExitCode);
        using JsonDocument json = JsonDocument.Parse(run.Out);
        JsonElement root = json.RootElement;
        Assert.Equal(6, root.GetProperty("total").GetInt64());
        Assert.Equal(5, root.GetProperty("recognized").GetInt64());
        Assert.Equal(1, root.GetProperty("unknown").GetInt64());
        Assert.Equal(3, root.GetProperty("needsRehash").GetInt64());
        Assert.Equal(1, root.GetProperty("duplicates").GetInt64());
        Assert.Equal(2, root.GetProperty("byFormat").GetProperty("md5").GetInt64());
        Assert.Equal(1, root.GetProperty("byFormat").GetProperty("bcrypt").GetInt64());
        Assert.Equal(2, root.GetProperty("byProfile").GetProperty("test").GetInt64());
        Assert.Equal(2, root.GetProperty("weakByFormat").GetProperty("md5").GetInt64());
        Assert.Equal(50.0, root.GetProperty("percent").GetProperty("weak").GetDouble());
    }

    [Fact]
    public async Task Csv_Column_WithHeader()
    {
        string md5 = TestHashers.Md5Hex("x");
        string mh = TestHashers.Hasher().Hash("y");
        string csv = "id,hash\n1," + md5 + "\n2,\"" + mh + "\"\n\n3\n";

        ToolRun run = await Tool.RunAsync(new[] { "audit", "-", "--column", "2", "--header", "--format", "json" }, csv);

        Assert.Equal(ExitCodes.Success, run.ExitCode);
        using JsonDocument json = JsonDocument.Parse(run.Out);
        Assert.Equal(3, json.RootElement.GetProperty("total").GetInt64());
        Assert.Equal(2, json.RootElement.GetProperty("recognized").GetInt64());
        Assert.Equal(1, json.RootElement.GetProperty("byFormat").GetProperty("mh").GetInt64());
        Assert.Contains("1 record(s) have no column 2", run.Error);
    }

    [Fact]
    public async Task Csv_TabDelimiter()
    {
        string csv = "u\t" + TestHashers.Md5Hex("x") + "\n";

        ToolRun run = await Tool.RunAsync(new[] { "audit", "-", "--column", "2", "--delimiter", "tab", "--format", "json" }, csv);

        Assert.Equal(ExitCodes.Success, run.ExitCode);
        using JsonDocument json = JsonDocument.Parse(run.Out);
        Assert.Equal(1, json.RootElement.GetProperty("byFormat").GetProperty("md5").GetInt64());
    }

    [Fact]
    public async Task Lines_HeaderIsSkipped()
    {
        ToolRun run = await Tool.RunAsync(new[] { "audit", "-", "--header", "--format", "json" }, "password_hash\n" + TestHashers.Md5Hex("x") + "\n");

        using JsonDocument json = JsonDocument.Parse(run.Out);
        Assert.Equal(1, json.RootElement.GetProperty("total").GetInt64());
        Assert.Equal(0, json.RootElement.GetProperty("unknown").GetInt64());
    }

    [Fact]
    public async Task EmptyInput_GivesEmptyReport()
    {
        ToolRun run = await Tool.RunAsync(new[] { "audit", "-" }, string.Empty);

        Assert.Equal(ExitCodes.Success, run.ExitCode);
        Assert.Contains("| Total | 0 | 0.0% |", run.Out);
    }

    [Fact]
    public async Task Report_NeverContainsStoredHashes()
    {
        string md5 = TestHashers.Md5Hex("secret-ish");

        ToolRun run = await Tool.RunAsync(new[] { "audit", "-" }, md5 + "\n");

        Assert.DoesNotContain(md5, run.All);
    }

    [Fact]
    public async Task HostileLines_DoNotThrow()
    {
        var sb = new StringBuilder();
        sb.Append("$mh$p=test$").Append(new string('A', 60_000)).Append('\n');
        sb.Append("$mh$p=|evil|$x$y\n");
        sb.Append("$2b$99$").Append(new string('.', 53)).Append('\n');
        sb.Append("\u0000\u0001\u0002\n");

        ToolRun run = await Tool.RunAsync(new[] { "audit", "-" }, sb.ToString());

        Assert.Equal(ExitCodes.Success, run.ExitCode);
        Assert.Contains("| Total | 4 |", run.Out);
    }

    [Fact]
    public async Task OverlongLine_IsError()
    {
        ToolRun run = await Tool.RunAsync(new[] { "audit", "-" }, new string('A', 70_000) + "\n");

        Assert.Equal(ExitCodes.Error, run.ExitCode);
        Assert.Contains("longer than 65536", run.Error);
    }

    [Theory]
    [InlineData("--column", "0")]
    [InlineData("--format", "xml")]
    [InlineData("--delimiter", "::")]
    public async Task ArgumentErrors_ExitTwo(params string[] options)
    {
        string[] args = new string[options.Length + 2];
        args[0] = "audit";
        args[1] = "-";
        options.CopyTo(args, 2);

        ToolRun run = await Tool.RunAsync(args, "x\n");

        Assert.Equal(ExitCodes.Error, run.ExitCode);
        Assert.StartsWith("error:", run.Error);
    }

    [Fact]
    public async Task MissingFile_IsError()
    {
        using var dir = new TempDir();

        ToolRun run = await Tool.RunAsync(new[] { "audit", dir.File("missing.txt") });

        Assert.Equal(ExitCodes.Error, run.ExitCode);
        Assert.Contains("not found", run.Error);
    }

    [Fact]
    public async Task MissingArgument_IsError()
    {
        ToolRun run = await Tool.RunAsync(new[] { "audit" });

        Assert.Equal(ExitCodes.Error, run.ExitCode);
    }
}
