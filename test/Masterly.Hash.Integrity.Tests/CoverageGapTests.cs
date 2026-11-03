using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading.Tasks;
using Masterly.Hash.Integrity.Internal;
using static Masterly.Hash.Integrity.Tests.TestUtil;

namespace Masterly.Hash.Integrity.Tests;

/// <summary>Argument validation, the algorithm registry, custom algorithms and the rarer manifest walk paths.</summary>
public class CoverageGapTests
{
    // ---- custom algorithms -----------------------------------------------------------------------------------

    /// <summary>A user-defined algorithm: SHA-512 truncated (or padded) to <c>produce</c> bytes.</summary>
    private sealed class TestAlgorithm : ContentHashAlgorithm
    {
        private readonly int _produce;

        public TestAlgorithm(string name, int digestLength, string? keyId = null, int? produce = null)
            : base(name, digestLength, keyId)
        {
            _produce = produce ?? digestLength;
        }

        public override ContentDigest CreateDigest() => new TestDigest(_produce);
    }

    /// <summary>Keeps the default <see cref="ContentDigest"/> dispose behaviour.</summary>
    private sealed class TestDigest : ContentDigest
    {
        private readonly int _length;
        private readonly MemoryStream _data = new MemoryStream();

        public TestDigest(int length)
        {
            _length = length;
        }

        protected override void AppendCore(byte[] buffer, int offset, int count) => _data.Write(buffer, offset, count);

        protected override byte[] GetHashAndResetCore()
        {
            byte[] full = SHA512.HashData(_data.ToArray());
            _data.SetLength(0);
            byte[] result = new byte[_length];
            Array.Copy(full, result, Math.Min(full.Length, _length));
            return result;
        }
    }

    [Theory]
    [InlineData("Upper")]
    [InlineData("-leading")]
    [InlineData("")]
    [InlineData("name-that-is-much-longer-than-thirty-two")]
    public void CustomAlgorithm_InvalidName_Throws(string name)
    {
        var ex = Assert.Throws<ArgumentException>(() => new TestAlgorithm(name, 32));
        Assert.Equal("name", ex.ParamName);
    }

    [Theory]
    [InlineData(15)]
    [InlineData(129)]
    public void CustomAlgorithm_InvalidDigestLength_Throws(int length)
    {
        var ex = Assert.Throws<ArgumentOutOfRangeException>(() => new TestAlgorithm("cov-len", length));
        Assert.Equal("digestLength", ex.ParamName);
        Assert.Equal(length, ex.ActualValue);
    }

    [Fact]
    public void CustomAlgorithm_HashesAndDisposesThroughTheBaseClass()
    {
        var algorithm = new TestAlgorithm("cov-custom", 16);

        ContentHash hash = ContentHasher.Compute(Utf8("abc"), algorithm);

        Assert.Equal("cov-custom", hash.Algorithm);
        Assert.Equal(ToHex(SHA512.HashData(Utf8("abc")).Take(16).ToArray()), hash.ToHex());
        using ContentDigest digest = algorithm.CreateDigest();
        digest.Dispose();
        digest.Dispose(); // idempotent
        Assert.Throws<ObjectDisposedException>(() => digest.GetHashAndReset());
    }

    [Fact]
    public async Task CustomAlgorithm_WrongLengthDigest_IsDetected()
    {
        var algorithm = new TestAlgorithm("cov-short", 32, produce: 20);
        const string expected = "Algorithm 'cov-short' produced a digest of the wrong length.";

        Assert.Equal(expected, Assert.Throws<InvalidOperationException>(() => ContentHasher.Compute(Utf8("x"), algorithm)).Message);
        Assert.Equal(expected, Assert.Throws<InvalidOperationException>(() => ContentHasher.Compute(new MemoryStream(Utf8("x")), algorithm)).Message);
        Assert.Equal(expected, (await Assert.ThrowsAsync<InvalidOperationException>(() => ContentHasher.ComputeAsync(new MemoryStream(Utf8("x")), algorithm))).Message);
    }

    // ---- registry --------------------------------------------------------------------------------------------

    [Fact]
    public void Registry_ArgumentChecks()
    {
        Assert.Throws<ArgumentNullException>(() => ContentHashAlgorithm.Register(null!));
        Assert.Throws<ArgumentNullException>(() => ContentHashAlgorithm.HmacSha256(null!, Key("a")));
        Assert.False(ContentHashAlgorithm.IsRegistered(null));
        Assert.Equal("name", Assert.Throws<ArgumentException>(() => ContentHashAlgorithm.RegisterKeyedFamily("Not Valid", 32)).ParamName);
        var range = Assert.Throws<ArgumentOutOfRangeException>(() => ContentHashAlgorithm.RegisterKeyedFamily("cov-family", 8));
        Assert.Equal("digestLength", range.ParamName);
        Assert.Throws<ArgumentOutOfRangeException>(() => ContentHashAlgorithm.RegisterKeyedFamily("cov-family", 200));
        Assert.False(ContentHashAlgorithm.IsRegistered("cov-family"));
    }

    [Fact]
    public void Registry_KeyedAlgorithmRegistersOnlyItsFamily()
    {
        // hmac-sha256 is already a registered family; registering a keyed instance of it is a no-op.
        ContentHashAlgorithm.Register(Hmac("k1"));

        Assert.True(ContentHashAlgorithm.IsRegistered("hmac-sha256"));
        Assert.False(ContentHashAlgorithm.TryGet("hmac-sha256", out _));
    }

    [Fact]
    public void Registry_CustomUnkeyedAlgorithm_BecomesParseableAndResolvable()
    {
        var algorithm = new TestAlgorithm("cov-registered", 24);
        ContentHashAlgorithm.Register(algorithm);
        ContentHashAlgorithm.Register(new TestAlgorithm("cov-registered", 24)); // same type and length: no-op

        Assert.True(ContentHashAlgorithm.TryGet("cov-registered", out ContentHashAlgorithm? resolved));
        Assert.Same(algorithm, resolved);
        ContentHash hash = ContentHasher.Compute(Utf8("data"), algorithm);
        Assert.Equal(hash, ContentHash.Parse(hash.ToString()));
        Assert.True(ContentHasher.Verify(Utf8("data"), ContentHash.Parse(hash.ToString())));
    }

    [Fact]
    public void Registry_ConflictingRegistrations_Throw()
    {
        // Same name, different implementation type.
        Assert.Throws<InvalidOperationException>(() => ContentHashAlgorithm.Register(new TestAlgorithm("sha256", 32)));
        // Same name, different length.
        Assert.Throws<InvalidOperationException>(() => ContentHashAlgorithm.Register(new TestAlgorithm("sha512", 32)));
        Assert.Throws<InvalidOperationException>(() => ContentHashAlgorithm.RegisterKeyedFamily("hmac-sha256", 64));
        // Keyed instance whose family name is taken by an unkeyed algorithm.
        Assert.Throws<InvalidOperationException>(() => ContentHashAlgorithm.Register(new TestAlgorithm("sha384", 48, keyId: "k1")));
        Assert.Same(ContentHashAlgorithm.Sha256, ContentHashAlgorithm.TryGet("sha256", out var sha) ? sha : null);
    }

    [Fact]
    public void Algorithm_Equality_ComparesNameKeyIdAndLength()
    {
        ContentHashAlgorithm a = Hmac("k1", "a");
        ContentHashAlgorithm sameIdentityOtherKey = Hmac("k1", "b");

        Assert.True(ContentHashAlgorithm.Sha256.Equals(ContentHashAlgorithm.Sha256));
        Assert.True(a.Equals(sameIdentityOtherKey)); // the key is secret and never part of the identity
        Assert.True(a.Equals((object)sameIdentityOtherKey));
        Assert.Equal(a.GetHashCode(), sameIdentityOtherKey.GetHashCode());
        Assert.False(a.Equals(Hmac("k2")));
        Assert.False(ContentHashAlgorithm.Sha256.Equals(ContentHashAlgorithm.Sha512));
        Assert.False(ContentHashAlgorithm.Sha256.Equals(new TestAlgorithm("sha256", 48)));
        Assert.False(ContentHashAlgorithm.Sha256.Equals((ContentHashAlgorithm?)null));
        Assert.False(ContentHashAlgorithm.Sha256.Equals((object)"sha256"));
        Assert.Equal(StringComparer.Ordinal.GetHashCode("hmac-sha256:k1"), a.GetHashCode());
    }

    // ---- Resolve, through DirectoryManifest.ToMerkleTree ----------------------------------------------------

    private static DirectoryManifest Manifest(ContentHashAlgorithm algorithm, params string[] paths) =>
        DirectoryManifest.FromEntries(
            paths.Select(p => new DirectoryManifestEntry(p, p.Length, ContentHasher.Compute(Utf8(p), algorithm))), algorithm);

    [Fact]
    public void ToMerkleTree_ResolvesOrRejectsTheAlgorithm()
    {
        DirectoryManifest plain = Manifest(ContentHashAlgorithm.Sha256, "a", "b");
        ContentHashAlgorithm mac = Hmac("k1");
        DirectoryManifest keyed = Manifest(mac, "a", "b");
        var unregistered = new TestAlgorithm("cov-unregistered", 32);
        DirectoryManifest custom = Manifest(unregistered, "a");

        Assert.Equal(plain.Root, plain.ToMerkleTree().RootHash);
        Assert.Equal(keyed.Root, keyed.ToMerkleTree(mac).RootHash);
        Assert.Equal(custom.Root, custom.ToMerkleTree(unregistered).RootHash);

        var mismatch = Assert.Throws<ArgumentException>(() => plain.ToMerkleTree(ContentHashAlgorithm.Sha512));
        Assert.StartsWith("Algorithm 'sha512' does not match 'sha256'.", mismatch.Message);
        Assert.Equal("algorithm", mismatch.ParamName);
        Assert.StartsWith("Algorithm 'hmac-sha256:k2' does not match 'hmac-sha256:k1'.",
            Assert.Throws<ArgumentException>(() => keyed.ToMerkleTree(Hmac("k2"))).Message);
        Assert.StartsWith("'hmac-sha256:k1' is keyed; pass the algorithm with its key.",
            Assert.Throws<ArgumentException>(() => keyed.ToMerkleTree()).Message);
        Assert.StartsWith("Algorithm 'cov-unregistered' is not registered.",
            Assert.Throws<ArgumentException>(() => custom.ToMerkleTree()).Message);
    }

    // ---- ContentHash / JSON converter ----------------------------------------------------------------------

    [Fact]
    public void ContentHash_IsFrom_ChecksNameKeyIdAndLength()
    {
        ContentHash hash = ContentHasher.Compute(Utf8("x"));

        Assert.Throws<ArgumentNullException>(() => hash.IsFrom(null!));
        Assert.True(hash.IsFrom(ContentHashAlgorithm.Sha256));
        Assert.False(hash.IsFrom(new TestAlgorithm("sha256", 48)));
    }

    [Fact]
    public void JsonConverter_ReadsNullAndGuardsWrite()
    {
        var converter = new ContentHashJsonConverter();
        var reader = new Utf8JsonReader(Utf8("null"));
        Assert.True(reader.Read());

        Assert.Null(converter.Read(ref reader, typeof(ContentHash), new JsonSerializerOptions()));

        using var buffer = new MemoryStream();
        using var writer = new Utf8JsonWriter(buffer);
        Assert.Throws<ArgumentNullException>(() => converter.Write(null!, ContentHasher.Compute(Utf8("x")), new JsonSerializerOptions()));
        Assert.Throws<ArgumentNullException>(() => converter.Write(writer, null!, new JsonSerializerOptions()));
    }

    // ---- ContentHasher / ContentDigest argument checks -----------------------------------------------------

    [Fact]
    public void ContentHasher_ArgumentChecks()
    {
        using var dir = new TempDirectory();
        string path = dir.Write("f", "x");
        ContentHash hash = ContentHasher.Compute(Utf8("x"));
        var closed = new MemoryStream();
        closed.Dispose();

        Assert.Throws<ArgumentNullException>(() => ContentHasher.Compute((Stream)null!, ContentHashAlgorithm.Sha256));
        Assert.Throws<ArgumentNullException>(() => ContentHasher.Compute(new MemoryStream(), null!));
        Assert.Equal("stream", Assert.Throws<ArgumentException>(() => ContentHasher.Compute(closed, ContentHashAlgorithm.Sha256)).ParamName);
        Assert.Throws<ArgumentNullException>(() => { _ = ContentHasher.ComputeAsync(new MemoryStream(), null!); });
        Assert.Throws<ArgumentNullException>(() => { _ = ContentHasher.ComputeFileAsync(path, null!); });
        Assert.Throws<ArgumentNullException>(() => ContentHasher.Verify(Utf8("x"), null!));
        Assert.Throws<ArgumentNullException>(() => { _ = ContentHasher.VerifyAsync(null!, hash); });
        Assert.Equal("stream", Assert.Throws<ArgumentException>(() => { _ = ContentHasher.VerifyAsync(closed, hash); }).ParamName);
        Assert.Throws<ArgumentNullException>(() => { _ = ContentHasher.VerifyFileAsync(null!, hash); });
        Assert.Throws<ArgumentNullException>(() => { _ = ContentHasher.VerifyFileAsync(path, null!); });
    }

    [Fact]
    public void ContentDigest_NullBuffers_Throw()
    {
        using ContentDigest digest = ContentHashAlgorithm.Sha256.CreateDigest();

        Assert.Throws<ArgumentNullException>(() => digest.Append(null!));
        Assert.Throws<ArgumentNullException>(() => digest.Append(null!, 0, 0));
    }

    [Fact]
    public void DigestExtensions_AppendFieldFromPartOfABuffer_IsLengthPrefixed()
    {
        using ContentDigest partial = ContentHashAlgorithm.Sha256.CreateDigest();
        partial.AppendField(Utf8("xabcx"), 1, 3);

        using ContentDigest whole = ContentHashAlgorithm.Sha256.CreateDigest();
        whole.AppendField(Utf8("abc"));

        byte[] expected = SHA256.HashData(Hex("0000000000000003").Concat(Utf8("abc")).ToArray());
        byte[] actual = partial.GetHashAndReset();
        Assert.Equal(expected, actual);
        Assert.Equal(expected, whole.GetHashAndReset());
    }

    [Theory]
    [InlineData("", 0, 0)]
    [InlineData("abc", 0, 3)]
    [InlineData("abcd", 0, -2)]
    public void Hex_TryDecode_RejectsEmptyOddOrNegativeLengths(string value, int start, int length)
    {
        Assert.False(Internal.Hex.TryDecode(value, start, length, out byte[] bytes));
        Assert.Empty(bytes);
    }

    [Fact]
    public void Hex_TryDecode_DecodesARange()
    {
        Assert.True(Internal.Hex.TryDecode("xx0aff", 2, 4, out byte[] bytes));
        Assert.Equal(new byte[] { 0x0a, 0xff }, bytes);
    }

    // ---- DirectoryManifest ---------------------------------------------------------------------------------

    [Fact]
    public void Manifest_And_Entries_ToString()
    {
        ContentHash hash = ContentHasher.Compute(Utf8("x"));
        var file = new DirectoryManifestEntry("a/b.txt", 1, hash);
        var link = new DirectoryManifestEntry("a/l", 1, hash, DirectoryManifestEntryKind.Link);
        DirectoryManifest manifest = DirectoryManifest.FromEntries(new[] { file, link }, ContentHashAlgorithm.Sha256);

        Assert.Equal("a/b.txt " + hash, file.ToString());
        Assert.Equal("a/l (link) " + hash, link.ToString());
        Assert.Equal("2 files, root " + manifest.Root, manifest.ToString());
    }

    [Fact]
    public void Manifest_ArgumentChecks()
    {
        ContentHash hash = ContentHasher.Compute(Utf8("x"));
        DirectoryManifest manifest = Manifest(ContentHashAlgorithm.Sha256, "a");

        Assert.Throws<ArgumentNullException>(() => new DirectoryManifestEntry(null!, 0, hash));
        Assert.Throws<ArgumentNullException>(() => new DirectoryManifestEntry("a", 0, null!));
        Assert.Throws<ArgumentNullException>(() => DirectoryManifest.FromEntries(null!, ContentHashAlgorithm.Sha256));
        Assert.Throws<ArgumentNullException>(() => DirectoryManifest.FromEntries(Array.Empty<DirectoryManifestEntry>(), null!));
        Assert.Throws<ArgumentNullException>(() => { _ = DirectoryManifest.CreateAsync(".", null!); });
        Assert.Throws<ArgumentNullException>(() => { _ = DirectoryManifest.VerifyAsync(null!, manifest, null, null); });
        Assert.Throws<ArgumentNullException>(() => { _ = DirectoryManifest.VerifyAsync(".", null!, null, null); });
        Assert.Throws<ArgumentNullException>(() => { _ = DirectoryManifest.VerifyAsync(null!, manifest, manifest.Root, null, null); });
        Assert.Throws<ArgumentNullException>(() => { _ = DirectoryManifest.VerifyAsync(".", null!, manifest.Root, null, null); });
        Assert.Throws<ArgumentNullException>(() => { _ = DirectoryManifest.VerifyAsync(".", manifest, null!, null, null); });
        Assert.Throws<ArgumentNullException>(() => DirectoryManifest.Compare(null!, manifest));
        Assert.Throws<ArgumentNullException>(() => DirectoryManifest.Compare(manifest, null!));
        Assert.Throws<ArgumentNullException>(() => DirectoryManifest.Compare(null!, manifest, null, manifest.Root));
        Assert.Throws<ArgumentNullException>(() => DirectoryManifest.Compare(manifest, null!, null, manifest.Root));
        Assert.Throws<ArgumentNullException>(() => DirectoryManifest.Compare(manifest, manifest, null, null!));
        Assert.Throws<ArgumentNullException>(() => DirectoryManifest.EncodeLeaf(null!));
    }

    [Fact]
    public void IsIntact_AlgorithmWithSameNameButOtherLength_IsNotIntact()
    {
        var longSha = new TestAlgorithm("sha256", 48);

        // An entry hash is 32 bytes, not 48.
        Assert.False(Manifest(ContentHashAlgorithm.Sha256, "a").IsIntact(longSha));
        // No entries: the root itself has the wrong length.
        Assert.False(Manifest(ContentHashAlgorithm.Sha256).IsIntact(longSha));
        Assert.True(Manifest(ContentHashAlgorithm.Sha256).IsIntact());
    }

    [Fact]
    public void Compare_WalksBothListsToTheEnd()
    {
        DirectoryManifest expected = Manifest(ContentHashAlgorithm.Sha256, "a", "c");
        DirectoryManifest actual = Manifest(ContentHashAlgorithm.Sha256, "b", "c", "d");

        DirectoryManifestDiff diff = DirectoryManifest.Compare(expected, actual);
        Assert.Equal(new[] { "b", "d" }, diff.Added);
        Assert.Equal(new[] { "a" }, diff.Removed);
        Assert.Empty(diff.Modified);
        Assert.True(diff.ManifestIntact);

        DirectoryManifestDiff emptied = DirectoryManifest.Compare(expected, Manifest(ContentHashAlgorithm.Sha256));
        Assert.Equal(new[] { "a", "c" }, emptied.Removed);
        Assert.Empty(emptied.Added);

        DirectoryManifestDiff filled = DirectoryManifest.Compare(Manifest(ContentHashAlgorithm.Sha256), actual);
        Assert.Equal(new[] { "b", "c", "d" }, filled.Added);
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
    public async Task Links_ExcludedByTheFilter_AreNotRecorded()
    {
        using var dir = new TempDirectory();
        dir.Write("keep.txt", "k");
        using var outside = new TempDirectory();
        string target = outside.Write("t.txt", "t");
        if (!TryLink(() =>
            {
                File.CreateSymbolicLink(Path.Combine(dir.Path, "skip.lnk"), target);
                File.CreateSymbolicLink(Path.Combine(dir.Path, "keep.lnk"), target);
            }))
            return;

        var options = new DirectoryManifestOptions { Filter = p => !p.StartsWith("skip", StringComparison.Ordinal) };
        DirectoryManifest manifest = await DirectoryManifest.CreateAsync(dir.Path, ContentHashAlgorithm.Sha256, options);

        Assert.Equal(new[] { "keep.lnk", "keep.txt" }, manifest.Entries.Select(e => e.Path));
        Assert.Equal(DirectoryManifestEntryKind.Link, manifest.Entries[0].Kind);
    }

    [Fact]
    public async Task FollowedLink_ToAnEmptyFile_IsRecordedWithoutOpeningIt()
    {
        using var dir = new TempDirectory();
        using var outside = new TempDirectory();
        string empty = outside.Write("empty.txt", Array.Empty<byte>());
        if (!TryLink(() => File.CreateSymbolicLink(Path.Combine(dir.Path, "empty.lnk"), empty)))
            return;

        DirectoryManifest manifest = await DirectoryManifest.CreateAsync(dir.Path, ContentHashAlgorithm.Sha256,
            new DirectoryManifestOptions { FollowReparsePoints = true });

        DirectoryManifestEntry entry = Assert.Single(manifest.Entries);
        Assert.Equal("empty.lnk", entry.Path);
        Assert.Equal(DirectoryManifestEntryKind.File, entry.Kind);
        Assert.Equal(0, entry.Length);
        Assert.Equal(ContentHasher.Compute(Array.Empty<byte>()), entry.Hash);
    }

    [Fact]
    public async Task LinkChainThatLoops_IsRecordedAsABrokenLink()
    {
        using var dir = new TempDirectory();
        string a = Path.Combine(dir.Path, "a.lnk");
        string b = Path.Combine(dir.Path, "b.lnk");
        if (!TryLink(() =>
            {
                File.CreateSymbolicLink(a, b);
                File.CreateSymbolicLink(b, a);
            }))
            return;

        Assert.Equal(LinkResolution.Broken, FileSystemLinks.ResolveFinalTarget(new FileInfo(a), out FileSystemInfo? target));
        DirectoryManifest manifest = await DirectoryManifest.CreateAsync(dir.Path, ContentHashAlgorithm.Sha256,
            new DirectoryManifestOptions { FollowReparsePoints = true });

        Assert.Equal(new[] { "a.lnk", "b.lnk" }, manifest.Entries.Select(e => e.Path));
        Assert.All(manifest.Entries, e => Assert.Equal(DirectoryManifestEntryKind.Link, e.Kind));
        Assert.Equal(ContentHasher.Compute(Utf8(b)), manifest.Entries[0].Hash);
    }

    [Fact]
    public void ResolveFinalTarget_OnARegularFile_IsNotALink()
    {
        using var dir = new TempDirectory();
        string file = dir.Write("plain.txt", "x");

        Assert.Equal(LinkResolution.NotALink, FileSystemLinks.ResolveFinalTarget(new FileInfo(file), out FileSystemInfo? target));
        Assert.Null(target);
    }

    [Theory]
    [InlineData(@"C:\a", @"C:\a", true)]
    [InlineData(@"C:\a", @"c:\A", true)]
    [InlineData(@"C:\a", @"C:\a\b", true)]
    [InlineData(@"C:\a", @"C:\a/b", true)]
    [InlineData(@"C:\a", @"C:\ab", false)]
    [InlineData(@"C:\a\b", @"C:\a", false)]
    [InlineData(@"C:\a", @"D:\a\b", false)]
    public void IsAncestorOrSelf(string ancestor, string path, bool expected)
    {
        string sep = Path.DirectorySeparatorChar.ToString();
        Assert.Equal(expected, FileSystemLinks.IsAncestorOrSelf(ancestor.Replace(@"\", sep), path.Replace(@"\", sep)));
    }

    [Fact]
    public async Task RootThatIsALink_DetectsLoopsBackToItsTarget()
    {
        using var real = new TempDirectory();
        real.Write("file.txt", "content");
        using var holder = new TempDirectory();
        string root = Path.Combine(holder.Path, "root.lnk");
        if (!TryLink(() =>
            {
                Directory.CreateSymbolicLink(root, real.Path);
                Directory.CreateSymbolicLink(Path.Combine(real.Path, "back"), real.Path);
            }))
            return;

        DirectoryManifest manifest = await DirectoryManifest.CreateAsync(root, ContentHashAlgorithm.Sha256,
            new DirectoryManifestOptions { FollowReparsePoints = true });

        // "back" points at the root's real directory, so it is recorded as a link instead of walked again.
        Assert.Equal(new[] { "back", "file.txt" }, manifest.Entries.Select(e => e.Path));
        Assert.Equal(DirectoryManifestEntryKind.Link, manifest.Entries[0].Kind);
        Assert.Equal(DirectoryManifestEntryKind.File, manifest.Entries[1].Kind);
    }

    [Fact]
    public async Task FileNameThatCannotBeRepresented_IsAnError()
    {
        using var dir = new TempDirectory();
        // Windows file names are arbitrary UTF-16, so a lone surrogate is a legal name; Unix names may contain
        // control characters. Neither is a canonical manifest path.
        string name = OperatingSystem.IsWindows() ? "bad\uD800name" : "bad\u0001name";
        try
        {
            File.WriteAllText(Path.Combine(dir.Path, name), "x");
        }
        catch (Exception e) when (e is IOException || e is ArgumentException)
        {
            return; // The file system refused the name.
        }

        var ex = await Assert.ThrowsAsync<IOException>(() => DirectoryManifest.CreateAsync(dir.Path));
        Assert.Equal("A file path cannot be represented in a manifest.", ex.Message);
    }

    [Fact]
    public async Task FileNameWithABackslash_IsAnErrorOnUnix()
    {
        if (OperatingSystem.IsWindows())
            return; // A backslash is a separator on Windows.

        using var dir = new TempDirectory();
        File.WriteAllText(Path.Combine(dir.Path, "a\\b"), "x");

        var ex = await Assert.ThrowsAsync<IOException>(() => DirectoryManifest.CreateAsync(dir.Path));
        Assert.Equal("A file or directory name contains a backslash, which manifests cannot represent.", ex.Message);
    }

    // ---- hash chain and Merkle tree argument checks --------------------------------------------------------

    [Fact]
    public void HashChain_ArgumentChecks()
    {
        Assert.Throws<ArgumentNullException>(() => HashChain.GenesisHash(null!));
        Assert.Throws<ArgumentNullException>(() => HashChain.ComputeEntryHash(new byte[32], Array.Empty<byte>(), 0, null!));
        Assert.Throws<ArgumentNullException>(() => HashChain.CreateNext(null, null!, ContentHashAlgorithm.Sha256));
        Assert.Throws<ArgumentNullException>(() => HashChain.CreateNext(null, Array.Empty<byte>(), null!));
        Assert.Throws<ArgumentNullException>(() => new HashChainEntry(0, null!, Array.Empty<byte>(), new byte[32]));
        Assert.Throws<ArgumentNullException>(() => new HashChainEntry(0, new byte[32], null!, new byte[32]));
        Assert.Throws<ArgumentNullException>(() => new HashChainEntry(0, new byte[32], Array.Empty<byte>(), null!));
        Assert.Throws<ArgumentNullException>(() => new HashChainCheckpoint(0, null!));
        Assert.Throws<ArgumentNullException>(() => new HashChainLog(ContentHashAlgorithm.Sha256, null!));
        Assert.Throws<ArgumentNullException>(() => new HashChainLog().Verify(Array.Empty<HashChainEntry>(), null!));
    }

    [Fact]
    public void Checkpoint_ToString_ShowsOnlyTheSequence()
    {
        Assert.Equal("#42", new HashChainCheckpoint(42, new byte[32]).ToString());
    }

    [Fact]
    public void HashChain_Verify_AcceptsALazySequence()
    {
        var log = new HashChainLog();
        log.Append(Utf8("one"));
        log.Append(Utf8("two"));

        HashChainVerificationResult result = HashChain.Verify(log.Entries.Where(_ => true));

        Assert.True(result.IsValid);
        Assert.Equal(2, result.EntriesVerified);
    }

    [Fact]
    public void HashChain_Verify_EntryAtTheMaximumSequence()
    {
        byte[] anchorHash = SHA256.HashData(Utf8("anchor"));
        var anchor = new HashChainCheckpoint(long.MaxValue - 1, anchorHash);
        byte[] payload = Utf8("last");
        byte[] hash = HashChain.ComputeEntryHash(anchorHash, payload, long.MaxValue);
        var entry = new HashChainEntry(long.MaxValue, anchorHash, payload, hash);

        HashChainVerificationResult result = HashChain.Verify(new[] { entry }, ContentHashAlgorithm.Sha256, anchor, null);

        Assert.True(result.IsValid);
        Assert.Equal(long.MaxValue, result.Head!.Sequence);
    }

    [Fact]
    public void HashChain_Verify_FirstEntryBeforeTheAnchor_IsAReorder()
    {
        var log = new HashChainLog();
        log.Append(Utf8("zero"));
        log.Append(Utf8("one"));
        HashChainCheckpoint anchor = log.Entries[1].ToCheckpoint();

        HashChainVerificationResult result = HashChain.Verify(new[] { log.Entries[0] }, ContentHashAlgorithm.Sha256, anchor, null);

        Assert.False(result.IsValid);
        Assert.Equal(HashChainFailure.Reorder, result.Failure);
        Assert.Equal(0, result.FirstBrokenIndex);
    }

    [Fact]
    public void HashChain_Verify_EarlierSequenceThatIsNotARepeat_IsAReorder()
    {
        var log = new HashChainLog();
        for (int i = 0; i < 3; i++)
            log.Append(Utf8("e" + i));

        HashChainVerificationResult result = HashChain.Verify(new[] { log.Entries[0], log.Entries[1], log.Entries[2], log.Entries[1] });

        Assert.Equal(HashChainFailure.Reorder, result.Failure);
        Assert.Equal(3, result.FirstBrokenIndex);
    }

    [Fact]
    public void MerkleTree_ArgumentChecks()
    {
        MerkleTree tree = MerkleTree.Build(new[] { Utf8("a"), Utf8("b") });

        Assert.Throws<ArgumentNullException>(() => MerkleTree.Build(new[] { Utf8("a") }, null!));
        Assert.Throws<ArgumentNullException>(() => MerkleTree.FromLeafHashes(null!, ContentHashAlgorithm.Sha256));
        Assert.Throws<ArgumentNullException>(() => MerkleTree.FromLeafHashes(Array.Empty<byte[]>(), null!));
        Assert.Throws<ArgumentNullException>(() => MerkleTree.EmptyRoot(null!));
        Assert.Throws<ArgumentNullException>(() => MerkleTree.HashLeaf(null!, ContentHashAlgorithm.Sha256));
        Assert.Throws<ArgumentNullException>(() => MerkleTree.HashLeaf(Utf8("a"), null!));
        Assert.Throws<ArgumentNullException>(() => MerkleTree.HashChildren(null!, new byte[32], ContentHashAlgorithm.Sha256));
        Assert.Throws<ArgumentNullException>(() => MerkleTree.HashChildren(new byte[32], null!, ContentHashAlgorithm.Sha256));
        Assert.Throws<ArgumentNullException>(() => MerkleTree.HashChildren(new byte[32], new byte[32], null!));
        Assert.Throws<ArgumentNullException>(() => MerkleTree.VerifyInclusionOfLeafHash(new byte[32], 0, 1, Array.Empty<byte[]>(), new byte[32], null!));
        Assert.Throws<ArgumentNullException>(() => MerkleTree.VerifyConsistency(1, 2, new byte[32], new byte[32], Array.Empty<byte[]>(), null!));
        Assert.Throws<ArgumentOutOfRangeException>(() => tree.GetConsistencyProof(0, -1));
        Assert.Throws<ArgumentOutOfRangeException>(() => tree.GetConsistencyProof(0, 3));
    }

    [Fact]
    public void VerifyConsistency_FromTheEmptyTree_NeedsAnEmptyProofAndTheEmptyRoot()
    {
        MerkleTree tree = MerkleTree.Build(new[] { Utf8("a"), Utf8("b"), Utf8("c") });
        byte[] empty = MerkleTree.EmptyRoot(ContentHashAlgorithm.Sha256);

        Assert.True(MerkleTree.VerifyConsistency(0, 3, empty, tree.Root, Array.Empty<byte[]>()));
        Assert.False(MerkleTree.VerifyConsistency(0, 3, empty, tree.Root, new[] { tree.GetLeafHash(0) }));
        Assert.False(MerkleTree.VerifyConsistency(0, 3, tree.Root, tree.Root, Array.Empty<byte[]>()));
    }
}
