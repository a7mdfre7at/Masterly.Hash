using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Masterly.Hash.Pepper;
using Masterly.Hash.Tool.Commands;
using Masterly.Hash.Tool.IO;

namespace Masterly.Hash.Tool.Tests;

/// <summary>Peppered-hash classification, and wrap's encoding, permission, memory and error-handling guarantees.</summary>
public class PepperAndWrapSafetyTests
{
    private static string PepperedHash(string password, string keyId = "k1")
    {
        var options = TestHashers.Options();
        options.Pepper = new HmacPepper(keyId, HmacPepper.GenerateKey());
        return new PasswordHasher(options).Hash(password);
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

    // ---- peppered hashes -------------------------------------------------------------------------------------

    [Fact]
    public async Task Inspect_PepperedHash_WithoutKeyIds_ExplainsTheUnknownKey()
    {
        string stored = PepperedHash("pw-one");

        ToolRun run = await Tool.RunAsync(new[] { "inspect", stored });

        Assert.Equal(ExitCodes.Failure, run.ExitCode);
        Assert.Contains("Pepper key:   k1 (unknown; pass --pepper-key-ids k1", run.Out);
    }

    [Fact]
    public async Task Inspect_PepperedHash_WithKeyIds_IsRecognized()
    {
        string stored = PepperedHash("pw-one");

        ToolRun run = await Tool.RunAsync(new[] { "inspect", stored, "--pepper-key-ids", "k1" });

        Assert.Equal(ExitCodes.Success, run.ExitCode);
        Assert.Contains("Recognized:   yes", run.Out);
        Assert.Contains("Pepper key:   k1" + Environment.NewLine, run.Out);
        Assert.Contains("Needs rehash: no", run.Out);
    }

    [Fact]
    public async Task Inspect_PepperedWithOlderKey_NeedsRehash()
    {
        string stored = PepperedHash("pw-one", "k1");

        ToolRun run = await Tool.RunAsync(new[] { "inspect", stored, "--pepper-key-ids", "k2,k1" });

        Assert.Equal(ExitCodes.Success, run.ExitCode);
        Assert.Contains("Needs rehash: yes (OutdatedPepperKey)", run.Out);
    }

    [Theory]
    [InlineData("")]
    [InlineData("k1,,k2")]
    [InlineData("bad id")]
    [InlineData("k_1")]
    public async Task PepperKeyIds_Invalid_IsError(string ids)
    {
        ToolRun run = await Tool.RunAsync(new[] { "inspect", "x", "--pepper-key-ids", ids });

        Assert.Equal(ExitCodes.Error, run.ExitCode);
        Assert.Contains("--pepper-key-ids", run.Error);
    }

    [Fact]
    public void ClassificationPepper_CannotHash()
    {
        var pepper = new ClassificationPepper(new[] { "k1" });

        Assert.Equal("k1", pepper.CurrentKeyId);
        Assert.True(pepper.IsKnownKey("k1"));
        Assert.False(pepper.IsKnownKey("k2"));
        Assert.Throws<InvalidOperationException>(() => pepper.Apply("k1", new byte[] { 1 }));
        Assert.Throws<InvalidOperationException>(() => pepper.ApplyAsync("k1", new byte[] { 1 }));
        Assert.Throws<ArgumentException>(() => new ClassificationPepper(Array.Empty<string>()));
    }

    [Fact]
    public async Task Audit_PepperedHashes_WarnWithoutKeyIds_AndAreRecognizedWithThem()
    {
        string input = PepperedHash("a1") + "\n" + PepperedHash("b2") + "\n" + TestHashers.Md5Hex("c3") + "\n";

        ToolRun without = await Tool.RunAsync(new[] { "audit", "-", "--format", "json" }, input);
        ToolRun with = await Tool.RunAsync(new[] { "audit", "-", "--format", "json", "--pepper-key-ids", "k1" }, input);

        Assert.Equal(ExitCodes.Success, without.ExitCode);
        Assert.Contains("\"recognized\": 1,", without.Out);
        Assert.Contains("warning: 2 Masterly hash(es) are peppered", without.Error);

        Assert.Equal(ExitCodes.Success, with.ExitCode);
        Assert.Contains("\"recognized\": 3,", with.Out);
        Assert.DoesNotContain("peppered", with.Error);
    }

    [Fact]
    public async Task Wrap_PepperedHashes_AreSkippedWithAClearReason_OrCurrentWithKeyIds()
    {
        using var dir = new TempDir();
        string input = dir.File("in.csv");
        File.WriteAllText(input, "1,\"" + PepperedHash("pw-a") + "\"\n2," + TestHashers.Md5Hex("pw-b") + "\n");

        ToolRun without = await Tool.RunAsync(new[] { "wrap", input, dir.File("out1.csv"), "--column", "2" });
        ToolRun with = await Tool.RunAsync(new[] { "wrap", input, dir.File("out2.csv"), "--column", "2", "--pepper-key-ids", "k1" });

        Assert.Equal(ExitCodes.Success, without.ExitCode);
        Assert.Contains("mh (unknown pepper key; pass --pepper-key-ids): 1", without.Out);

        Assert.Equal(ExitCodes.Success, with.ExitCode);
        Assert.Contains("Already current: 1", with.Out);
        Assert.Contains("Wrapped:         1", with.Out);

        // The wrapping itself is unpeppered (the tool holds no key): it verifies with a pepper-less hasher.
        string wrapped = ReadCsv(dir.File("out2.csv"))[1].Fields[1].Value;
        Assert.DoesNotContain(",k=", wrapped);
        Assert.True(TestHashers.Hasher().Verify("pw-b", wrapped).IsMatch);
    }

    [Fact]
    public void Wrap_MalformedMh_IsStillReportedAsMalformed()
    {
        PasswordHasher hasher = TestHashers.Hasher();
        var record = new CsvRecord(new List<CsvField> { new CsvField("$mh$p=test,k=k1$AAAA$BBBB", "x") }, "\n", 1);

        WrapCommand.RowResult result = WrapCommand.Process(hasher, record, 0, weakOnly: false);

        Assert.Equal("mh (malformed or unregistered profile)", result.Detail);
    }

    // ---- encoding --------------------------------------------------------------------------------------------

    [Fact]
    public async Task Wrap_NonUtf8Input_IsRefused_AndNothingIsWritten()
    {
        using var dir = new TempDir();
        string input = dir.File("cp1252.csv");
        byte[] header = Encoding.ASCII.GetBytes("name,hash\n");
        byte[] row = new byte[] { (byte)'J', (byte)'o', (byte)'s', 0xE9, (byte)',' }
            .Concat(Encoding.ASCII.GetBytes(TestHashers.Md5Hex("pw") + "\n"));
        File.WriteAllBytes(input, header.Concat(row));
        string output = dir.File("out.csv");

        ToolRun run = await Tool.RunAsync(new[] { "wrap", input, output, "--column", "2", "--header" });

        Assert.Equal(ExitCodes.Error, run.ExitCode);
        Assert.Contains("not valid UTF-8", run.Error);
        Assert.Contains("line", run.Error);
        Assert.False(File.Exists(output));
        Assert.Single(Directory.GetFiles(dir.Path)); // no temporary file left behind
    }

    [Fact]
    public async Task Wrap_Utf16Input_IsRefused()
    {
        using var dir = new TempDir();
        string input = dir.File("utf16.csv");
        File.WriteAllText(input, "1," + TestHashers.Md5Hex("pw") + "\n", new UnicodeEncoding(bigEndian: false, byteOrderMark: true));

        ToolRun run = await Tool.RunAsync(new[] { "wrap", input, dir.File("out.csv"), "--column", "2" });

        Assert.Equal(ExitCodes.Error, run.ExitCode);
        Assert.Contains("UTF-16", run.Error);
    }

    [Fact]
    public async Task Wrap_Utf8WithNonAscii_IsCopiedByteForByte_IncludingBom()
    {
        using var dir = new TempDir();
        string input = dir.File("utf8.csv");
        string md5 = TestHashers.Md5Hex("pw");
        File.WriteAllText(input, "José 山田," + md5 + "\r\n", new UTF8Encoding(encoderShouldEmitUTF8Identifier: true));
        string output = dir.File("out.csv");

        ToolRun run = await Tool.RunAsync(new[] { "wrap", input, output, "--column", "2" });

        Assert.Equal(ExitCodes.Success, run.ExitCode);
        byte[] bytes = File.ReadAllBytes(output);
        byte[] expectedPrefix = new byte[] { 0xEF, 0xBB, 0xBF }.Concat(Encoding.UTF8.GetBytes("José 山田,"));
        Assert.Equal(expectedPrefix, bytes.Take(expectedPrefix.Length).ToArray());
        Assert.NotEqual(0xEF, bytes[expectedPrefix.Length]); // exactly one BOM
    }

    // ---- permissions -----------------------------------------------------------------------------------------

    [Fact]
    public async Task Wrap_Output_IsOwnerOnly_OnUnix_EvenOverAnExistingFile()
    {
        if (OperatingSystem.IsWindows())
            return; // Windows output inherits the folder ACL; Unix modes do not apply.

        using var dir = new TempDir();
        string input = dir.File("in.csv");
        File.WriteAllText(input, "1," + TestHashers.Md5Hex("pw") + "\n");
        string output = dir.File("out.csv");
        File.WriteAllText(output, "old");
        File.SetUnixFileMode(output, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead | UnixFileMode.OtherRead);

        ToolRun run = await Tool.RunAsync(new[] { "wrap", input, output, "--column", "2", "--force" });

        Assert.Equal(ExitCodes.Success, run.ExitCode);
        Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(output));
    }

    // ---- bounded batches -------------------------------------------------------------------------------------

    [Fact]
    public async Task Wrap_HugeRecords_AreBatchedByCharacters_AndStillCorrect()
    {
        // 8 records of ~900k characters: 16 records per batch would buffer ~7 Mi characters; the character budget
        // cuts each batch at ~4 Mi. The output must still be complete and correct.
        using var dir = new TempDir();
        string input = dir.File("big.csv");
        string filler = new string('x', 900_000);
        var passwords = Enumerable.Range(0, 8).Select(i => "pw-" + i).ToArray();
        using (var writer = new StreamWriter(input))
        {
            foreach (string password in passwords)
                writer.Write(filler + "," + TestHashers.Md5Hex(password) + "\n");
        }
        string output = dir.File("out.csv");

        ToolRun run = await Tool.RunAsync(new[] { "wrap", input, output, "--column", "2", "--parallelism", "1" });

        Assert.Equal(ExitCodes.Success, run.ExitCode);
        Assert.Contains("Wrapped:         8", run.Out);
        List<CsvRecord> rows = ReadCsv(output);
        Assert.Equal(8, rows.Count);
        PasswordHasher hasher = TestHashers.Hasher();
        for (int i = 0; i < rows.Count; i++)
        {
            Assert.Equal(filler, rows[i].Fields[0].Raw);
            Assert.True(hasher.Verify(passwords[i], rows[i].Fields[1].Value).IsMatch);
        }
        Assert.True(8L * 900_000 > WrapCommand.MaxBatchChars);
    }

    [Fact]
    public void CsvRecord_Length_CountsCharactersRead()
    {
        var reader = new CsvRecordReader(new StringReader("ab,\"c,d\"\nxyz"), ',');

        Assert.Equal(9, reader.Read()!.Length);
        Assert.Equal(3, reader.Read()!.Length);
        Assert.Equal(2, reader.Line);
    }

    // ---- worker exceptions -----------------------------------------------------------------------------------

    private static readonly System.Threading.Tasks.ParallelOptions TwoWorkers = new() { MaxDegreeOfParallelism = 2 };

    [Fact]
    public void ProcessBatch_WorkerToolException_IsRethrownUnwrapped()
    {
        var results = new WrapCommand.RowResult[4];

        var ex = Assert.Throws<ToolException>(() =>
            WrapCommand.ProcessBatch(4, results, TwoWorkers, i => i == 2 ? throw new ToolException("boom") : WrapCommand.RowResult.Skip("x")));

        Assert.Equal("boom", ex.Message);
    }

    [Fact]
    public void ProcessBatch_OutOfMemory_BecomesClearToolError()
    {
        var results = new WrapCommand.RowResult[4];

        var ex = Assert.Throws<ToolException>(() =>
            WrapCommand.ProcessBatch(4, results, TwoWorkers, _ => throw new OutOfMemoryException()));

        Assert.Contains("--parallelism", ex.Message);
    }

    [Fact]
    public async Task Wrap_WorkerFailure_IsCleanError_NotACrash()
    {
        // A custom legacy format that blows up while wrapping: the tool must report it like any other error.
        using var dir = new TempDir();
        string input = dir.File("in.csv");
        File.WriteAllText(input, "1,boom:1\n2,boom:2\n");

        ToolRun run = await Tool.RunAsync(new[] { "wrap", input, dir.File("out.csv"), "--column", "2", "--parallelism", "2" },
            configure: e => e.HasherOptionsFactory = () =>
            {
                PasswordHasherOptions options = TestHashers.Options();
                options.LegacyFormats.Add(new ExplodingFormat());
                return options;
            });

        Assert.Equal(ExitCodes.Error, run.ExitCode);
        Assert.Contains("error: Out of memory while hashing", run.Error);
        Assert.False(File.Exists(dir.File("out.csv")));
    }

    private sealed class ExplodingFormat : Masterly.Hash.Legacy.ILegacyHashFormat
    {
        public string Id => "boom";
        public bool CanHandle(string storedHash) => storedHash.StartsWith("boom:", StringComparison.Ordinal);
        public bool Verify(string password, string storedHash) => false;
        public bool TryExtractWrapInput(string storedHash, out byte[] digest, out byte[] parameter) => throw new OutOfMemoryException();
        public byte[] ComputeWrapInput(string password, byte[] parameter) => Array.Empty<byte>();
    }
}
