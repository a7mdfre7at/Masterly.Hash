using System;
using System.CommandLine;
using System.IO;
using System.Linq;
using System.Text;
using Masterly.Hash.Tool.Commands;
using Masterly.Hash.Tool.IO;
using Xunit;

namespace Masterly.Hash.Tool.Tests;

/// <summary>
/// Kills Stryker mutants that survived the earlier passes (see <see cref="MutationTests"/>).
/// </summary>
public class SurvivorMutationTests
{
    [Fact]
    public void ClassificationPepper_NoKeyIds_ExactMessage()
    {
        ArgumentException ex = Assert.Throws<ArgumentException>("keyIds", () => new ClassificationPepper(Array.Empty<string>()));

        Assert.Equal("At least one key id is required. (Parameter 'keyIds')", ex.Message);
    }

    [Theory]
    [InlineData('"')]
    [InlineData('\r')]
    [InlineData('\n')]
    public void CsvRecordReader_ForbiddenDelimiter_ExactMessage(char delimiter)
    {
        ArgumentException ex = Assert.Throws<ArgumentException>("delimiter", () => new CsvRecordReader(new StringReader("a"), delimiter));

        Assert.Equal("The delimiter cannot be a quote or a line break. (Parameter 'delimiter')", ex.Message);
    }

    [Fact]
    public void CreateUtf8Reader_SkipsUtf8Bom()
    {
        byte[] bytes = Encoding.UTF8.GetPreamble().Concat(Encoding.UTF8.GetBytes("hi\n")).ToArray();

        using TextReader reader = SystemConsole.CreateUtf8Reader(new MemoryStream(bytes));

        Assert.Equal("hi", reader.ReadLine());
    }

    [Fact]
    public void CreateUtf8Reader_SkipsUtf16BigEndianBom()
    {
        byte[] bytes = Encoding.BigEndianUnicode.GetPreamble().Concat(Encoding.BigEndianUnicode.GetBytes("hé")).ToArray();

        using TextReader reader = SystemConsole.CreateUtf8Reader(new MemoryStream(bytes));

        Assert.Equal("hé", reader.ReadToEnd());
    }

    [Fact]
    public void PossibleSecrets_OptionAliasesAreNotSecrets()
    {
        var option = new Option<bool>("--quiet");
        option.Aliases.Add("-q");
        var root = new RootCommand { option };

        Assert.Equal(new[] { "zz-top" }, ToolApp.PossibleSecrets(root, new[] { "-q", "--quiet", "zz-top" }));
    }

    [Fact]
    public void PossibleSecrets_RealRoot_HelpAliasesAreNotSecrets()
    {
        RootCommand root = ToolApp.BuildRootCommand(new ToolEnvironment(new FakeConsole(string.Empty, true, Array.Empty<string?>())));

        Assert.Equal(new[] { "hunter22" }, ToolApp.PossibleSecrets(root, new[] { "hash", "-h", "-?", "/h", "/?", "hunter22" }));
    }
}
