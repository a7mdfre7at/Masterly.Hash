using System;
using System.IO;
using System.Linq;
using Masterly.Hash.Tool.IO;

namespace Masterly.Hash.Tool.Tests;

public class CsvRecordReaderTests
{
    private static CsvRecord[] ReadAll(string text, char delimiter = ',', int max = CsvRecordReader.DefaultMaxRecordChars)
    {
        var reader = new CsvRecordReader(new StringReader(text), delimiter, max);
        var list = new System.Collections.Generic.List<CsvRecord>();
        CsvRecord? record;
        while ((record = reader.Read()) != null)
            list.Add(record);
        return list.ToArray();
    }

    // RFC 4180 section 2 examples.
    [Fact]
    public void Rfc4180_QuotedFields()
    {
        CsvRecord[] records = ReadAll("aaa,\"b\r\nbb\",ccc\r\nzzz,\"y\"\"yy\",xxx\r\n");

        Assert.Equal(2, records.Length);
        Assert.Equal(new[] { "aaa", "b\r\nbb", "ccc" }, records[0].Fields.Select(f => f.Value));
        Assert.Equal(new[] { "aaa", "\"b\r\nbb\"", "ccc" }, records[0].Fields.Select(f => f.Raw));
        Assert.Equal(new[] { "zzz", "y\"yy", "xxx" }, records[1].Fields.Select(f => f.Value));
        Assert.Equal("\r\n", records[0].Terminator);
        Assert.Equal(1, records[0].LineNumber);
        Assert.Equal(3, records[1].LineNumber);
    }

    [Fact]
    public void Terminators_ArePreserved()
    {
        CsvRecord[] records = ReadAll("a\nb\r\nc\rd");

        Assert.Equal(new[] { "\n", "\r\n", "\r", "" }, records.Select(r => r.Terminator));
        Assert.Equal(new[] { "a", "b", "c", "d" }, records.Select(r => r.Fields[0].Value));
    }

    [Fact]
    public void EmptyFields_AndBlankLines()
    {
        CsvRecord[] records = ReadAll(",,\n\nx\n");

        Assert.Equal(3, records[0].Fields.Count);
        Assert.False(records[0].IsBlank);
        Assert.True(records[1].IsBlank);
        Assert.False(records[2].IsBlank);
    }

    [Fact]
    public void EmptyInput_HasNoRecords()
    {
        Assert.Empty(ReadAll(string.Empty));
    }

    [Fact]
    public void QuoteInsideUnquotedField_IsLiteral()
    {
        CsvRecord[] records = ReadAll("ab\"c,d\n");

        Assert.Equal("ab\"c", records[0].Fields[0].Value);
    }

    [Fact]
    public void TextAfterClosingQuote_IsKeptLeniently()
    {
        CsvRecord[] records = ReadAll("\"ab\"cd,e\n");

        Assert.Equal("abcd", records[0].Fields[0].Value);
        Assert.Equal("\"ab\"cd", records[0].Fields[0].Raw);
    }

    [Fact]
    public void TabDelimiter()
    {
        CsvRecord[] records = ReadAll("a\tb,c\n", '\t');

        Assert.Equal(new[] { "a", "b,c" }, records[0].Fields.Select(f => f.Value));
    }

    [Fact]
    public void UnterminatedQuote_IsError()
    {
        var ex = Assert.Throws<ToolException>(() => ReadAll("ok\n\"never closed\nstill open"));
        Assert.Contains("line 2", ex.Message);
    }

    [Fact]
    public void OverlongRecord_IsError()
    {
        Assert.Throws<ToolException>(() => ReadAll(new string('a', 101) + "\n", max: 100));
        Assert.Single(ReadAll(new string('a', 100) + "\n", max: 101));
    }

    [Fact]
    public void LargeInput_StreamsAcrossBufferBoundaries()
    {
        string field = new string('q', 40_000);
        CsvRecord[] records = ReadAll("\"" + field + "\"\"x\"," + field + "\n");

        Assert.Equal(field + "\"x", records[0].Fields[0].Value);
        Assert.Equal(field, records[0].Fields[1].Value);
    }

    [Theory]
    [InlineData('"')]
    [InlineData('\n')]
    [InlineData('\r')]
    public void InvalidDelimiter_Throws(char delimiter)
    {
        Assert.Throws<ArgumentException>(() => new CsvRecordReader(new StringReader(""), delimiter));
    }

    [Theory]
    [InlineData("plain", "plain")]
    [InlineData("a,b", "\"a,b\"")]
    [InlineData("say \"hi\"", "\"say \"\"hi\"\"\"")]
    [InlineData("line\nbreak", "\"line\nbreak\"")]
    [InlineData("$mh$p=test,w=md5,wp=AA$x$y", "\"$mh$p=test,w=md5,wp=AA$x$y\"")]
    public void Quote_OnlyWhenNeeded(string value, string expected)
    {
        Assert.Equal(expected, CsvFormat.Quote(value, ','));
    }

    [Fact]
    public void Quote_RoundTripsThroughReader()
    {
        string value = "a,\"b\"\r\nc";
        CsvRecord[] records = ReadAll(CsvFormat.Quote(value, ',') + "\n");

        Assert.Equal(value, records[0].Fields[0].Value);
    }

    [Theory]
    [InlineData(null, ',')]
    [InlineData("", ',')]
    [InlineData(";", ';')]
    [InlineData("tab", '\t')]
    [InlineData("TAB", '\t')]
    [InlineData("\\t", '\t')]
    [InlineData("|", '|')]
    public void ParseDelimiter_Valid(string? text, char expected)
    {
        Assert.Equal(expected, CsvFormat.ParseDelimiter(text));
    }

    [Theory]
    [InlineData("ab")]
    [InlineData("\"")]
    [InlineData("\n")]
    public void ParseDelimiter_Invalid(string text)
    {
        Assert.Throws<ToolException>(() => CsvFormat.ParseDelimiter(text));
    }
}

public class LineReaderTests
{
    [Fact]
    public void ReadsLines_StripsCr_ReturnsNullAtEnd()
    {
        var reader = new StringReader("one\r\ntwo\nthree");

        Assert.Equal("one", LineReader.ReadLine(reader, 10, "too long"));
        Assert.Equal("two", LineReader.ReadLine(reader, 10, "too long"));
        Assert.Equal("three", LineReader.ReadLine(reader, 10, "too long"));
        Assert.Null(LineReader.ReadLine(reader, 10, "too long"));
    }

    [Fact]
    public void EmptyLine_IsEmptyString()
    {
        var reader = new StringReader("\n");

        Assert.Equal(string.Empty, LineReader.ReadLine(reader, 10, "too long"));
        Assert.Null(LineReader.ReadLine(reader, 10, "too long"));
    }

    [Theory]
    [InlineData("abcde\n")]
    [InlineData("abcde\r\n")]
    [InlineData("abcde")]
    public void ExactlyMax_IsAccepted(string text)
    {
        Assert.Equal("abcde", LineReader.ReadLine(new StringReader(text), 5, "too long"));
    }

    [Theory]
    [InlineData("abcdef\n")]
    [InlineData("abcdef")]
    [InlineData("abcde\rX\n")]
    public void OverMax_Throws(string text)
    {
        var ex = Assert.Throws<ToolException>(() => LineReader.ReadLine(new StringReader(text), 5, "too long"));
        Assert.Equal("too long", ex.Message);
    }

    [Fact]
    public void GrowsBuffer_ForLongLines()
    {
        string line = new string('z', 10_000);

        Assert.Equal(line, LineReader.ReadLine(new StringReader(line + "\n"), 20_000, "too long"));
    }
}

public class PasswordInputTests
{
    [Fact]
    public void SecretEquals_IsExact()
    {
        Assert.True(PasswordInput.SecretEquals("abc", "abc"));
        Assert.False(PasswordInput.SecretEquals("abc", "abd"));
        Assert.False(PasswordInput.SecretEquals("abc", "abcd"));
        Assert.False(PasswordInput.SecretEquals("abc", "ABC"));
    }

    [Fact]
    public void Prompt_OverlongAnswer_IsRejected()
    {
        var console = new FakeConsole(string.Empty, redirected: false, new string?[] { new string('p', PasswordInput.MaxPasswordChars + 1) });

        var ex = Assert.Throws<ToolException>(() => PasswordInput.Read(console, fromStdin: false, confirm: false));
        Assert.Equal(PasswordInput.TooLongMessage, ex.Message);
    }

    [Fact]
    public void Prompt_EmptyAnswer_DoesNotAskForConfirmation()
    {
        var console = new FakeConsole(string.Empty, redirected: false, new string?[] { string.Empty, string.Empty });

        Assert.Throws<ToolException>(() => PasswordInput.Read(console, fromStdin: false, confirm: true));
        Assert.Single(console.Prompts);
    }
}
