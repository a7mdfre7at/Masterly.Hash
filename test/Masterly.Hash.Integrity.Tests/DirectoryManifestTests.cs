using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using static Masterly.Hash.Integrity.Tests.TestUtil;

namespace Masterly.Hash.Integrity.Tests;

public class DirectoryManifestTests
{
    private static TempDirectory Sample()
    {
        var dir = new TempDirectory();
        dir.Write("readme.txt", "hello");
        dir.Write("bin/app.dll", new byte[] { 1, 2, 3 });
        dir.Write("bin/Z.dll", "upper");
        dir.Write("a/b/c/deep.json", "{}");
        dir.Write("empty.dat", Array.Empty<byte>());
        Directory.CreateDirectory(Path.Combine(dir.Path, "emptydir"));
        return dir;
    }

    [Fact]
    public async Task Create_ListsFilesWithCanonicalPathsInOrdinalOrder()
    {
        using TempDirectory dir = Sample();
        DirectoryManifest manifest = await DirectoryManifest.CreateAsync(dir.Path);

        Assert.Equal(new[] { "a/b/c/deep.json", "bin/Z.dll", "bin/app.dll", "empty.dat", "readme.txt" }, manifest.Entries.Select(e => e.Path));
        Assert.Equal("sha256", manifest.Algorithm);
        Assert.Null(manifest.KeyId);
        DirectoryManifestEntry readme = manifest.Entries.Single(e => e.Path == "readme.txt");
        Assert.Equal(5, readme.Length);
        Assert.Equal(ContentHasher.Compute(Utf8("hello")), readme.Hash);
        Assert.Equal(0, manifest.Entries.Single(e => e.Path == "empty.dat").Length);
        Assert.True(manifest.IsIntact());
    }

    [Fact]
    public async Task Root_IsRfc9162TreeOverDocumentedLeafEncoding()
    {
        using TempDirectory dir = Sample();
        DirectoryManifest manifest = await DirectoryManifest.CreateAsync(dir.Path);

        var leaves = manifest.Entries.Select(e =>
        {
            var bytes = new List<byte>();
            void U64(ulong v)
            {
                byte[] b = new byte[8];
                BinaryPrimitives.WriteUInt64BigEndian(b, v);
                bytes.AddRange(b);
            }
            void Field(byte[] v)
            {
                U64((ulong)v.Length);
                bytes.AddRange(v);
            }
            Field(Utf8("masterly-manifest/v1"));
            Field(Utf8(e.Path));
            U64((ulong)e.Length);
            Field(e.Hash.ToArray());
            return bytes.ToArray();
        }).ToList();

        Assert.Equal(leaves.Select(ToHex), manifest.Entries.Select(DirectoryManifest.EncodeLeaf).Select(ToHex));
        Assert.Equal(ToHex(MerkleTree.Build(leaves).Root), manifest.Root.ToHex());

        // Each file can be proven part of the manifest.
        MerkleTree tree = manifest.ToMerkleTree();
        for (int i = 0; i < leaves.Count; i++)
            Assert.True(MerkleTree.VerifyInclusion(leaves[i], i, tree.Size, tree.GetInclusionProof(i), manifest.Root.ToArray()));
    }

    [Fact]
    public async Task EmptyDirectory_HasEmptyTreeRoot()
    {
        using var dir = new TempDirectory();
        DirectoryManifest manifest = await DirectoryManifest.CreateAsync(dir.Path);
        Assert.Empty(manifest.Entries);
        Assert.Equal("sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", manifest.Root.ToString());
    }

    [Fact]
    public async Task Verify_UnchangedDirectory_Matches()
    {
        using TempDirectory dir = Sample();
        DirectoryManifest manifest = await DirectoryManifest.CreateAsync(dir.Path);
        DirectoryManifestDiff diff = await DirectoryManifest.VerifyAsync(dir.Path, manifest);
        Assert.True(diff.IsMatch);
        Assert.True(diff.ManifestIntact);
        Assert.Equal("Match", diff.ToString());
    }

    [Fact]
    public async Task Verify_ReportsAddedRemovedModified()
    {
        using TempDirectory dir = Sample();
        DirectoryManifest manifest = await DirectoryManifest.CreateAsync(dir.Path);

        dir.Write("bin/app.dll", new byte[] { 1, 2, 4 });      // same length, different content
        dir.Write("readme.txt", "hello world");                // different length
        dir.Delete("a/b/c/deep.json");
        dir.Write("bin/new.dll", "new");
        dir.Write("emptydir/x", "x");

        DirectoryManifestDiff diff = await DirectoryManifest.VerifyAsync(dir.Path, manifest);
        Assert.False(diff.IsMatch);
        Assert.True(diff.ManifestIntact);
        Assert.Equal(new[] { "bin/new.dll", "emptydir/x" }, diff.Added);
        Assert.Equal(new[] { "a/b/c/deep.json" }, diff.Removed);
        Assert.Equal(new[] { "bin/app.dll", "readme.txt" }, diff.Modified);
        Assert.Equal("2 added, 1 removed, 2 modified", diff.ToString());
    }

    [Fact]
    public async Task Json_RoundTrips()
    {
        using TempDirectory dir = Sample();
        DirectoryManifest manifest = await DirectoryManifest.CreateAsync(dir.Path);
        string json = manifest.ToJson();
        DirectoryManifest parsed = DirectoryManifest.FromJson(json);

        Assert.Equal(manifest.Root, parsed.Root);
        Assert.Equal(manifest.Entries.Select(e => (e.Path, e.Length, e.Hash.ToString())), parsed.Entries.Select(e => (e.Path, e.Length, e.Hash.ToString())));
        Assert.True(parsed.IsIntact());
        Assert.Equal(json, parsed.ToJson());
        Assert.Equal(manifest.ToJson(indented: false), DirectoryManifest.FromJson(manifest.ToJson(indented: false)).ToJson(false));
        Assert.True((await DirectoryManifest.VerifyAsync(dir.Path, parsed)).IsMatch);

        using JsonDocument doc = JsonDocument.Parse(json);
        Assert.Equal("masterly-manifest/v1", doc.RootElement.GetProperty("format").GetString());
        Assert.Equal("sha256", doc.RootElement.GetProperty("algorithm").GetString());
        Assert.Equal(5, doc.RootElement.GetProperty("files").GetArrayLength());
    }

    [Fact]
    public async Task TamperedManifest_IsNotIntact()
    {
        using TempDirectory dir = Sample();
        DirectoryManifest manifest = await DirectoryManifest.CreateAsync(dir.Path);

        // The attacker modifies a file and updates its hash in the manifest but cannot fix the trusted root.
        dir.Write("readme.txt", "evil!");
        JsonNode node = JsonNode.Parse(manifest.ToJson())!;
        JsonNode readme = node["files"]!.AsArray().Single(f => (string)f!["path"]! == "readme.txt")!;
        readme["hash"] = ContentHasher.Compute(Utf8("evil!")).ToString();
        DirectoryManifest tampered = DirectoryManifest.FromJson(node.ToJsonString());

        Assert.False(tampered.IsIntact());
        DirectoryManifestDiff diff = await DirectoryManifest.VerifyAsync(dir.Path, tampered);
        Assert.False(diff.ManifestIntact);
        Assert.False(diff.IsMatch);
        Assert.Empty(diff.Modified);
        Assert.StartsWith("manifest tampered", diff.ToString());
    }

    [Fact]
    public async Task Keyed_ManifestNeedsKey()
    {
        using TempDirectory dir = Sample();
        var mac = Hmac("m1");
        DirectoryManifest manifest = await DirectoryManifest.CreateAsync(dir.Path, mac);
        Assert.Equal("hmac-sha256", manifest.Algorithm);
        Assert.Equal("m1", manifest.KeyId);
        Assert.StartsWith("hmac-sha256:m1:", manifest.Root.ToString());

        DirectoryManifest parsed = DirectoryManifest.FromJson(manifest.ToJson());
        Assert.True(parsed.IsIntact(mac));
        Assert.False(parsed.IsIntact(Hmac("m1", "attacker")));
        // Without the key the manifest cannot be checked: a failure result, not an exception.
        Assert.False(parsed.IsIntact());
        DirectoryManifestDiff noKey = await DirectoryManifest.VerifyAsync(dir.Path, parsed);
        Assert.False(noKey.ManifestIntact);
        Assert.False(noKey.IsMatch);
        Assert.True((await DirectoryManifest.VerifyAsync(dir.Path, parsed, mac)).IsMatch);
        // Key rotation: a verifier holding another key id gets "not intact", not an exception.
        Assert.False(parsed.IsIntact(Hmac("m2")));
        Assert.False((await DirectoryManifest.VerifyAsync(dir.Path, parsed, Hmac("m2"))).IsMatch);

        // An attacker re-creating the whole manifest with their own key (same id) is detected.
        DirectoryManifest forged = await DirectoryManifest.CreateAsync(dir.Path, Hmac("m1", "attacker"));
        Assert.False(forged.IsIntact(mac));
    }

    [Fact]
    public async Task Options_FilterAndDepth()
    {
        using TempDirectory dir = Sample();
        DirectoryManifest filtered = await DirectoryManifest.CreateAsync(dir.Path, ContentHashAlgorithm.Sha256,
            new DirectoryManifestOptions { Filter = p => !p.StartsWith("bin/", StringComparison.Ordinal) });
        Assert.Equal(new[] { "a/b/c/deep.json", "empty.dat", "readme.txt" }, filtered.Entries.Select(e => e.Path));

        // a/b/c sits at depth 3: exactly the limit is fine.
        DirectoryManifest exact = await DirectoryManifest.CreateAsync(dir.Path, ContentHashAlgorithm.Sha256,
            new DirectoryManifestOptions { MaxDepth = 3 });
        Assert.Equal(5, exact.Entries.Count);

        // Below the limit the walk fails closed instead of silently leaving files out.
        await Assert.ThrowsAsync<IOException>(() => DirectoryManifest.CreateAsync(dir.Path, ContentHashAlgorithm.Sha256,
            new DirectoryManifestOptions { MaxDepth = 2 }));
        // Empty directories beyond the limit hold nothing to verify.
        using var flat = new TempDirectory();
        flat.Write("f", "f");
        Directory.CreateDirectory(Path.Combine(flat.Path, "empty"));
        Assert.Single((await DirectoryManifest.CreateAsync(flat.Path, ContentHashAlgorithm.Sha256, new DirectoryManifestOptions { MaxDepth = 0 })).Entries);

        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() =>
            DirectoryManifest.CreateAsync(dir.Path, ContentHashAlgorithm.Sha256, new DirectoryManifestOptions { MaxDepth = -1 }));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() =>
            DirectoryManifest.CreateAsync(dir.Path, ContentHashAlgorithm.Sha256, new DirectoryManifestOptions { MaxEntries = 0 }));
    }

    [Fact]
    public async Task FileAddedBeyondMaxDepth_FailsVerificationInsteadOfMatching()
    {
        using TempDirectory dir = Sample();
        DirectoryManifest manifest = await DirectoryManifest.CreateAsync(dir.Path);

        // 66 levels of "d/" is about 130 characters: short enough for every OS, too deep for the default limit.
        string deep = string.Concat(Enumerable.Repeat("d/", 66)) + "hidden.dll";
        try
        {
            dir.Write(deep, "planted");
        }
        catch (PathTooLongException)
        {
            return;
        }

        await Assert.ThrowsAsync<IOException>(() => DirectoryManifest.VerifyAsync(dir.Path, manifest));
    }

    [Fact]
    public async Task MaxEntries_BoundsTheWalk()
    {
        using TempDirectory dir = Sample();
        // Sample has 10 entries: 5 files and 5 directories (a, a/b, a/b/c, bin, emptydir).
        await Assert.ThrowsAsync<IOException>(() => DirectoryManifest.CreateAsync(dir.Path, ContentHashAlgorithm.Sha256,
            new DirectoryManifestOptions { MaxEntries = 5 }));
        Assert.Equal(5, (await DirectoryManifest.CreateAsync(dir.Path, ContentHashAlgorithm.Sha256,
            new DirectoryManifestOptions { MaxEntries = 10 })).Entries.Count);
    }

    private static bool TryLink(Action create)
    {
        try
        {
            create();
            return true;
        }
        catch (Exception e) when (e is IOException || e is UnauthorizedAccessException || e is PlatformNotSupportedException)
        {
            return false; // Creating links needs privileges on some Windows machines.
        }
    }

    [Fact]
    public async Task SymbolicLinks_AreRecordedNotFollowedByDefault()
    {
        using TempDirectory dir = Sample();
        using var outside = new TempDirectory();
        outside.Write("secret.txt", "outside the root");
        string secret = Path.Combine(outside.Path, "secret.txt");
        if (!TryLink(() =>
            {
                Directory.CreateSymbolicLink(Path.Combine(dir.Path, "link"), outside.Path);
                File.CreateSymbolicLink(Path.Combine(dir.Path, "filelink"), secret);
            }))
            return;

        DirectoryManifest manifest = await DirectoryManifest.CreateAsync(dir.Path);
        Assert.DoesNotContain(manifest.Entries, e => e.Path.StartsWith("link/", StringComparison.Ordinal));
        DirectoryManifestEntry fileLink = manifest.Entries.Single(e => e.Path == "filelink");
        DirectoryManifestEntry dirLink = manifest.Entries.Single(e => e.Path == "link");
        Assert.Equal(DirectoryManifestEntryKind.Link, fileLink.Kind);
        Assert.Equal(DirectoryManifestEntryKind.Link, dirLink.Kind);
        Assert.Equal(ContentHasher.Compute(Utf8(secret)), fileLink.Hash);
        Assert.Equal(ContentHasher.Compute(Utf8(outside.Path)), dirLink.Hash);
        Assert.Equal(Utf8(secret).Length, fileLink.Length);
        Assert.Equal(DirectoryManifestEntryKind.File, manifest.Entries.Single(e => e.Path == "readme.txt").Kind);
        Assert.True(manifest.IsIntact());

        // Links survive JSON, and the leaf encoding separates them from files.
        DirectoryManifest parsed = DirectoryManifest.FromJson(manifest.ToJson());
        Assert.Equal(DirectoryManifestEntryKind.Link, parsed.Entries.Single(e => e.Path == "filelink").Kind);
        Assert.True(parsed.IsIntact());
        Assert.True((await DirectoryManifest.VerifyAsync(dir.Path, parsed)).IsMatch);
        var asFile = new DirectoryManifestEntry(fileLink.Path, fileLink.Length, fileLink.Hash);
        Assert.NotEqual(ToHex(DirectoryManifest.EncodeLeaf(asFile)), ToHex(DirectoryManifest.EncodeLeaf(fileLink)));

        DirectoryManifest followed = await DirectoryManifest.CreateAsync(dir.Path, ContentHashAlgorithm.Sha256,
            new DirectoryManifestOptions { FollowReparsePoints = true });
        Assert.Contains(followed.Entries, e => e.Path == "link/secret.txt");
        DirectoryManifestEntry followedFile = followed.Entries.Single(e => e.Path == "filelink");
        Assert.Equal(DirectoryManifestEntryKind.File, followedFile.Kind);
        Assert.Equal(ContentHasher.Compute(Utf8("outside the root")), followedFile.Hash);
    }

    [Fact]
    public async Task PlantedOrRetargetedLinks_AreReported()
    {
        using TempDirectory dir = Sample();
        using var outside = new TempDirectory();
        outside.Write("evil.so", "evil");
        outside.Write("other.so", "other");
        DirectoryManifest manifest = await DirectoryManifest.CreateAsync(dir.Path);

        string plugin = Path.Combine(dir.Path, "bin", "plugin.dll");
        if (!TryLink(() =>
            {
                File.CreateSymbolicLink(plugin, Path.Combine(outside.Path, "evil.so"));
                Directory.CreateSymbolicLink(Path.Combine(dir.Path, "plugins"), outside.Path);
            }))
            return;

        DirectoryManifestDiff diff = await DirectoryManifest.VerifyAsync(dir.Path, manifest);
        Assert.False(diff.IsMatch);
        Assert.Equal(new[] { "bin/plugin.dll", "plugins" }, diff.Added);

        // Retargeting an existing link is a modification.
        DirectoryManifest withLinks = await DirectoryManifest.CreateAsync(dir.Path);
        File.Delete(plugin);
        File.CreateSymbolicLink(plugin, Path.Combine(outside.Path, "other.so"));
        Assert.Equal(new[] { "bin/plugin.dll" }, (await DirectoryManifest.VerifyAsync(dir.Path, withLinks)).Modified);

        // Replacing a link with a regular file of the same target text is a modification too (kind changed).
        File.Delete(plugin);
        File.WriteAllText(plugin, Path.Combine(outside.Path, "other.so"));
        DirectoryManifest relinked = await DirectoryManifest.CreateAsync(dir.Path);
        File.Delete(plugin);
        File.CreateSymbolicLink(plugin, Path.Combine(outside.Path, "other.so"));
        Assert.Equal(new[] { "bin/plugin.dll" }, (await DirectoryManifest.VerifyAsync(dir.Path, relinked)).Modified);
    }

    [Fact]
    public async Task FollowingLinks_LoopsAreRecordedNotWalked()
    {
        using TempDirectory dir = Sample();
        if (!TryLink(() =>
            {
                Directory.CreateSymbolicLink(Path.Combine(dir.Path, "a", "up"), dir.Path);
                Directory.CreateSymbolicLink(Path.Combine(dir.Path, "self"), dir.Path);
                Directory.CreateSymbolicLink(Path.Combine(dir.Path, "dot"), ".");
                File.CreateSymbolicLink(Path.Combine(dir.Path, "dangling"), Path.Combine(dir.Path, "missing"));
            }))
            return;

        var options = new DirectoryManifestOptions { FollowReparsePoints = true };
        DirectoryManifest manifest = await DirectoryManifest.CreateAsync(dir.Path, ContentHashAlgorithm.Sha256, options);
        // Each loop is visited once as a link entry; the real files appear exactly once.
        Assert.Equal(new[] { "a/b/c/deep.json", "a/up", "bin/Z.dll", "bin/app.dll", "dangling", "dot", "empty.dat", "readme.txt", "self" },
            manifest.Entries.Select(e => e.Path));
        Assert.All(new[] { "a/up", "self", "dot", "dangling" },
            p => Assert.Equal(DirectoryManifestEntryKind.Link, manifest.Entries.Single(e => e.Path == p).Kind));
        Assert.True((await DirectoryManifest.VerifyAsync(dir.Path, manifest, null, options)).IsMatch);
    }

    [Fact]
    public async Task Fifo_IsNotOpened()
    {
        if (OperatingSystem.IsWindows())
            return;
        using TempDirectory dir = Sample();
        string fifo = Path.Combine(dir.Path, "pipe");
        using (Process? mkfifo = Process.Start(new ProcessStartInfo("mkfifo", fifo) { UseShellExecute = false }))
        {
            if (mkfifo == null)
                return;
            mkfifo.WaitForExit();
            if (mkfifo.ExitCode != 0)
                return;
        }

        // Opening a FIFO for reading blocks until a writer appears; the walk must finish on its own.
        Task<DirectoryManifest> create = DirectoryManifest.CreateAsync(dir.Path);
        Assert.Same(create, await Task.WhenAny(create, Task.Delay(TimeSpan.FromSeconds(30))));
        DirectoryManifestEntry entry = (await create).Entries.Single(e => e.Path == "pipe");
        Assert.Equal(0, entry.Length);
        Assert.Equal(ContentHasher.Compute(Array.Empty<byte>()), entry.Hash);
    }

    [Fact]
    public async Task Create_HonoursCancellationAndMissingRoot()
    {
        using TempDirectory dir = Sample();
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => DirectoryManifest.CreateAsync(dir.Path, cts.Token));
        Assert.Throws<DirectoryNotFoundException>(() => { _ = DirectoryManifest.CreateAsync(Path.Combine(dir.Path, "missing")); });
        Assert.Throws<ArgumentNullException>(() => { _ = DirectoryManifest.CreateAsync(null!); });
    }

    [Theory]
    [InlineData("a")]
    [InlineData("a/b")]
    [InlineData("a b/c.d")]
    [InlineData(".hidden/..x/x..")]
    [InlineData("\u00e9/\U0001F600")]
    public void CanonicalPath_Accepts(string path) => Assert.True(DirectoryManifestEntry.IsCanonicalPath(path));

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("/a")]
    [InlineData("a/")]
    [InlineData("a//b")]
    [InlineData("./a")]
    [InlineData("a/./b")]
    [InlineData("../a")]
    [InlineData("a/../../b")]
    [InlineData("..")]
    [InlineData("a\\b")]
    [InlineData("C:\\x")]
    [InlineData("a\0b")]
    [InlineData("a\nb")]
    public void CanonicalPath_Rejects(string? path)
    {
        Assert.False(DirectoryManifestEntry.IsCanonicalPath(path));
        if (path != null)
            Assert.Throws<ArgumentException>(() => new DirectoryManifestEntry(path, 0, ContentHasher.Compute(Array.Empty<byte>())));
    }

    [Fact]
    public void CanonicalPath_RejectsUnpairedSurrogatesAndOverlongPaths()
    {
        foreach (string path in new[] { "\ud800", "a\udc00b", "a/\ud83d", "\ude00\ud83d" })
            Assert.False(DirectoryManifestEntry.IsCanonicalPath(path));
        Assert.True(DirectoryManifestEntry.IsCanonicalPath("😀"));
        Assert.False(DirectoryManifestEntry.IsCanonicalPath(new string('a', DirectoryManifestEntry.MaxPathLength + 1)));
    }

    [Fact]
    public void FromJson_IsStrict()
    {
        DirectoryManifest manifest = DirectoryManifest.FromEntries(new[]
        {
            new DirectoryManifestEntry("b", 1, ContentHasher.Compute(Utf8("b"))),
            new DirectoryManifestEntry("a", 1, ContentHasher.Compute(Utf8("a"))),
        }, ContentHashAlgorithm.Sha256);
        Assert.Equal(new[] { "a", "b" }, manifest.Entries.Select(e => e.Path));
        string valid = manifest.ToJson(false);
        Assert.True(DirectoryManifest.TryFromJson(valid, out _));

        string a = ContentHasher.Compute(Utf8("a")).ToString();
        string b = ContentHasher.Compute(Utf8("b")).ToString();
        string root = manifest.Root.ToString();
        string Doc(string files, string algorithm = "sha256", string? rootValue = null, string extra = "") =>
            $"{{\"format\":\"masterly-manifest/v1\",\"algorithm\":\"{algorithm}\",\"root\":\"{rootValue ?? root}\",\"files\":[{files}]{extra}}}";
        string FileJson(string path, string hash, string length = "1", string extra = "") =>
            $"{{\"path\":\"{path}\",\"length\":{length},\"hash\":\"{hash}\"{extra}}}";

        string[] invalid =
        {
            "",
            "null",
            "[]",
            "{}",
            "not json",
            Doc(FileJson("a", a) + "," + FileJson("b", b)).Replace("masterly-manifest/v1", "masterly-manifest/v2"),
            Doc(FileJson("b", b) + "," + FileJson("a", a)),                                     // unsorted
            Doc(FileJson("a", a) + "," + FileJson("a", a)),                                     // duplicate
            Doc(FileJson("../a", a)),
            Doc(FileJson("/a", a)),
            Doc(FileJson("a\\\\b", a)),
            Doc(FileJson("a", a.ToUpperInvariant())),
            Doc(FileJson("a", a, "-1")),
            Doc(FileJson("a", a, "1.5")),
            Doc(FileJson("a", a, "\"1\"")),
            Doc(FileJson("a", a, "99999999999999999999")),
            Doc(FileJson("a", a, "1", ",\"extra\":1")),                                     // unknown entry property
            Doc(FileJson("a", a), extra: ",\"extra\":1"),                                   // unknown top-level property
            Doc(FileJson("a", a), extra: ",\"root\":\"" + root + "\""),                     // duplicate property
            Doc(FileJson("a", a), algorithm: "sha512"),                                     // algorithm mismatch
            Doc(FileJson("a", ContentHasher.Compute(Utf8("a"), ContentHashAlgorithm.Sha512).ToString())), // mixed algorithms
            Doc(FileJson("a", a), rootValue: "sha256:00"),
            Doc("1"),
            Doc("[[[[[[[[[[[[[[[[[[[[]]]]]]]]]]]]]]]]]]]]"),
            "{\"format\":\"masterly-manifest/v1\",\"algorithm\":\"sha256\",\"root\":\"" + root + "\"}",
            "{\"format\":\"masterly-manifest/v1\",\"algorithm\":\"sha256\",\"root\":\"" + root + "\",\"files\":{}}",
        };

        foreach (string json in invalid)
        {
            Assert.False(DirectoryManifest.TryFromJson(json, out DirectoryManifest? result), json);
            Assert.Null(result);
            if (json.Length > 0)
                Assert.Throws<FormatException>(() => DirectoryManifest.FromJson(json));
        }
        Assert.False(DirectoryManifest.TryFromJson(null, out _));
        Assert.Throws<ArgumentNullException>(() => DirectoryManifest.FromJson(null!));
    }

    [Fact]
    public void TryFromJson_RandomMutations_NeverThrow()
    {
        string valid = DirectoryManifest.FromEntries(new[]
        {
            new DirectoryManifestEntry("dir/file.txt", 3, ContentHasher.Compute(Utf8("abc"))),
            new DirectoryManifestEntry("x", 0, ContentHasher.Compute(Array.Empty<byte>())),
        }, ContentHashAlgorithm.Sha256).ToJson(false);

        var random = new Random(42);
        const string noise = "{}[]\":,0123456789abcdef-./\\ \u0000\ud800";
        for (int i = 0; i < 3000; i++)
        {
            char[] chars = valid.ToCharArray();
            int edits = random.Next(1, 4);
            for (int e = 0; e < edits; e++)
                chars[random.Next(chars.Length)] = noise[random.Next(noise.Length)];
            if (DirectoryManifest.TryFromJson(new string(chars), out DirectoryManifest? parsed))
                _ = parsed!.IsIntact();
        }
    }

    [Fact]
    public void FromEntries_ValidatesInput()
    {
        ContentHash h = ContentHasher.Compute(Utf8("a"));
        Assert.Throws<ArgumentException>(() => DirectoryManifest.FromEntries(new[] { new DirectoryManifestEntry("a", 1, h), new DirectoryManifestEntry("a", 1, h) }, ContentHashAlgorithm.Sha256));
        Assert.Throws<ArgumentException>(() => DirectoryManifest.FromEntries(new[] { new DirectoryManifestEntry("a", 1, h) }, ContentHashAlgorithm.Sha512));
        Assert.Throws<ArgumentException>(() => DirectoryManifest.FromEntries(new DirectoryManifestEntry[] { null! }, ContentHashAlgorithm.Sha256));
        Assert.Throws<ArgumentOutOfRangeException>(() => new DirectoryManifestEntry("a", -1, h));
    }

    [Fact]
    public void Compare_DifferentAlgorithms_IsNotIntact_NeverThrows()
    {
        ContentHash h256 = ContentHasher.Compute(Utf8("a"));
        ContentHash h512 = ContentHasher.Compute(Utf8("a"), ContentHashAlgorithm.Sha512);
        DirectoryManifest m256 = DirectoryManifest.FromEntries(new[] { new DirectoryManifestEntry("a", 1, h256) }, ContentHashAlgorithm.Sha256);
        DirectoryManifest m512 = DirectoryManifest.FromEntries(new[] { new DirectoryManifestEntry("a", 1, h512) }, ContentHashAlgorithm.Sha512);
        DirectoryManifestDiff diff = DirectoryManifest.Compare(m256, m512);
        Assert.False(diff.ManifestIntact);
        Assert.False(diff.IsMatch);
        Assert.Equal(new[] { "a" }, diff.Modified);
        Assert.False(DirectoryManifest.Compare(m512, m512, ContentHashAlgorithm.Sha256).IsMatch);
        Assert.False(m256.IsIntact(ContentHashAlgorithm.Sha512));
        Assert.True(DirectoryManifest.Compare(m512, m512).IsMatch);
    }

    [Fact]
    public async Task SwappedManifestAlgorithm_IsNotIntact()
    {
        // Attacker with write access replaces a keyed manifest by a valid SHA-256 one describing tampered files.
        using TempDirectory dir = Sample();
        var mac = Hmac("m1");
        DirectoryManifest keyed = await DirectoryManifest.CreateAsync(dir.Path, mac);
        dir.Write("readme.txt", "evil!");
        DirectoryManifest swapped = DirectoryManifest.FromJson((await DirectoryManifest.CreateAsync(dir.Path)).ToJson());
        Assert.True(keyed.IsIntact(mac));

        DirectoryManifestDiff diff = await DirectoryManifest.VerifyAsync(dir.Path, swapped, mac);
        Assert.False(diff.ManifestIntact);
        Assert.False(diff.IsMatch);
        Assert.False(swapped.IsIntact(mac));
        Assert.False(DirectoryManifest.Compare(swapped, keyed, mac).IsMatch);
    }

    [Fact]
    public async Task TrustedRoot_DetectsRegeneratedManifest()
    {
        using TempDirectory dir = Sample();
        DirectoryManifest original = await DirectoryManifest.CreateAsync(dir.Path);
        ContentHash trustedRoot = ContentHash.Parse(original.Root.ToString());

        // The attacker modifies a file and regenerates a perfectly consistent unkeyed manifest.
        dir.Write("bin/app.dll", "backdoor");
        DirectoryManifest regenerated = DirectoryManifest.FromJson((await DirectoryManifest.CreateAsync(dir.Path)).ToJson());
        Assert.True((await DirectoryManifest.VerifyAsync(dir.Path, regenerated)).IsMatch); // what the root alone cannot catch

        DirectoryManifestDiff diff = await DirectoryManifest.VerifyAsync(dir.Path, regenerated, trustedRoot, null, null);
        Assert.False(diff.ManifestIntact);
        Assert.False(diff.IsMatch);
        Assert.False(DirectoryManifest.Compare(regenerated, regenerated, null, trustedRoot).IsMatch);

        // The genuine manifest passes against the trusted root and reports the change.
        DirectoryManifestDiff genuine = await DirectoryManifest.VerifyAsync(dir.Path, original, trustedRoot, null, null);
        Assert.True(genuine.ManifestIntact);
        Assert.Equal(new[] { "bin/app.dll" }, genuine.Modified);
        Assert.True(DirectoryManifest.Compare(original, original, null, trustedRoot).IsMatch);
        Assert.Throws<ArgumentNullException>(() => { _ = DirectoryManifest.VerifyAsync(dir.Path, original, (ContentHash)null!, null, null); });
    }

    [Fact]
    public void TryFromJson_EscapedLoneSurrogates_NeverThrow()
    {
        string valid = DirectoryManifest.FromEntries(new[] { new DirectoryManifestEntry("a", 1, ContentHasher.Compute(Utf8("a"))) },
            ContentHashAlgorithm.Sha256).ToJson(false);
        using JsonDocument doc = JsonDocument.Parse(valid);
        string root = doc.RootElement.GetProperty("root").GetString()!;
        string hash = doc.RootElement.GetProperty("files")[0].GetProperty("hash").GetString()!;

        var cases = new List<string> { "{\"format\":\"\\udc00\"}" };
        foreach (string bad in new[] { "\\udc00", "\\ud800", "\\ud800A", "a\\ud800b" })
        {
            cases.Add(valid.Replace("masterly-manifest/v1", bad));
            cases.Add(valid.Replace("\"algorithm\":\"sha256\"", "\"algorithm\":\"" + bad + "\""));
            cases.Add(valid.Replace(root, bad));
            cases.Add(valid.Replace("\"path\":\"a\"", "\"path\":\"" + bad + "\""));
            cases.Add(valid.Replace(hash, bad));
            cases.Add(valid.Replace("\"length\":1", "\"length\":1,\"kind\":\"" + bad + "\""));
        }

        foreach (string json in cases)
        {
            Assert.False(DirectoryManifest.TryFromJson(json, out DirectoryManifest? parsed), json);
            Assert.Null(parsed);
            Assert.Throws<FormatException>(() => DirectoryManifest.FromJson(json));
        }
    }

    [Fact]
    public void FromJson_LinkKind_IsStrict()
    {
        ContentHash h = ContentHasher.Compute(Utf8("target"));
        DirectoryManifest manifest = DirectoryManifest.FromEntries(new[] { new DirectoryManifestEntry("l", 6, h, DirectoryManifestEntryKind.Link) },
            ContentHashAlgorithm.Sha256);
        string json = manifest.ToJson(false);
        Assert.Contains("\"kind\":\"link\"", json);
        Assert.True(DirectoryManifest.FromJson(json).IsIntact());

        Assert.False(DirectoryManifest.TryFromJson(json.Replace("\"kind\":\"link\"", "\"kind\":\"file\""), out _));
        Assert.False(DirectoryManifest.TryFromJson(json.Replace("\"kind\":\"link\"", "\"kind\":\"link\",\"kind\":\"link\""), out _));
        Assert.False(DirectoryManifest.TryFromJson(json.Replace("\"kind\":\"link\"", "\"kind\":1"), out _));
        // Dropping the kind turns the link into a file, which no longer matches the root.
        Assert.False(DirectoryManifest.FromJson(json.Replace(",\"kind\":\"link\"", "")).IsIntact());
        Assert.Throws<ArgumentOutOfRangeException>(() => new DirectoryManifestEntry("l", 0, h, (DirectoryManifestEntryKind)7));
    }

    [Fact]
    public async Task Verify_NeverReadsPathsFromTheManifest()
    {
        // A hostile manifest naming files outside the root only produces "removed" entries.
        using TempDirectory dir = Sample();
        ContentHash h = ContentHasher.Compute(Utf8("x"));
        DirectoryManifest hostile = DirectoryManifest.FromEntries(new[] { new DirectoryManifestEntry("zz/secret", 1, h) }, ContentHashAlgorithm.Sha256);
        DirectoryManifestDiff diff = await DirectoryManifest.VerifyAsync(dir.Path, hostile);
        Assert.Equal(new[] { "zz/secret" }, diff.Removed);
        Assert.Equal(5, diff.Added.Count);
    }
}
