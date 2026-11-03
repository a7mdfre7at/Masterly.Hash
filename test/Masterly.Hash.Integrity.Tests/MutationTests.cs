using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Masterly.Hash.Integrity.Internal;
using static Masterly.Hash.Integrity.Tests.TestUtil;

namespace Masterly.Hash.Integrity.Tests;

/// <summary>
/// Precise assertions that pin exact boundaries, parameter names, messages, encodings and async behaviour, so that
/// a changed operator or a dropped statement in the library makes a test fail.
/// </summary>
public class MutationTests
{
    // ---- helpers -------------------------------------------------------------------------------------------

    /// <summary>An unkeyed or keyed custom algorithm backed by SHA-256 (only used with 32-byte digests when hashing).</summary>
    private sealed class MutAlgorithm : ContentHashAlgorithm
    {
        public MutAlgorithm(string name, int digestLength, string? keyId = null)
            : base(name, digestLength, keyId)
        {
        }

        public override ContentDigest CreateDigest() => Sha256.CreateDigest();
    }

    /// <summary>Records what the base class forwards to the implementation.</summary>
    private sealed class RecordingDigest : ContentDigest
    {
        public List<int> AppendCounts { get; } = new List<int>();

        public List<bool> DisposeCalls { get; } = new List<bool>();

        protected override void AppendCore(byte[] buffer, int offset, int count) => AppendCounts.Add(count);

        protected override byte[] GetHashAndResetCore() => new byte[16];

        protected override void Dispose(bool disposing) => DisposeCalls.Add(disposing);
    }

    private sealed class FinalizableDigest : ContentDigest
    {
        private static int _finalized;

        public static int Finalized => Volatile.Read(ref _finalized);

        ~FinalizableDigest()
        {
            Interlocked.Increment(ref _finalized);
        }

        protected override void AppendCore(byte[] buffer, int offset, int count)
        {
        }

        protected override byte[] GetHashAndResetCore() => new byte[16];
    }

    /// <summary>Counts continuations posted to it and runs them on the thread pool.</summary>
    private sealed class CountingContext : SynchronizationContext
    {
        private int _posts;

        public int Posts => Volatile.Read(ref _posts);

        public override void Post(SendOrPostCallback d, object? state)
        {
            Interlocked.Increment(ref _posts);
            ThreadPool.QueueUserWorkItem(_ => d(state));
        }

        public override void Send(SendOrPostCallback d, object? state) => d(state);

        public override SynchronizationContext CreateCopy() => this;
    }

    /// <summary>Starts <paramref name="start"/> under a counting context and waits for it without awaiting.</summary>
    private static T RunUnderContext<T>(Func<Task<T>> start, out int posts)
    {
        var context = new CountingContext();
        SynchronizationContext? previous = SynchronizationContext.Current;
        Task<T> task;
        SynchronizationContext.SetSynchronizationContext(context);
        try
        {
            task = start();
        }
        finally
        {
            SynchronizationContext.SetSynchronizationContext(previous);
        }
        T result = task.GetAwaiter().GetResult();
        posts = context.Posts;
        return result;
    }

    /// <summary>An <see cref="IReadOnlyList{T}"/> that can only be read by index.</summary>
    private sealed class IndexOnlyList<T> : IReadOnlyList<T>
    {
        private readonly T[] _items;

        public IndexOnlyList(IEnumerable<T> items)
        {
            _items = items.ToArray();
        }

        public int Count => _items.Length;

        public T this[int index] => _items[index];

        public IEnumerator<T> GetEnumerator() => throw new NotSupportedException();

        IEnumerator IEnumerable.GetEnumerator() => throw new NotSupportedException();
    }

    private static byte[] U64(ulong value)
    {
        byte[] bytes = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(bytes, value);
        return bytes;
    }

    private static byte[] Field(byte[] value) => U64((ulong)value.Length).Concat(value).ToArray();

    private static List<HashChainEntry> Chain(int count, ContentHashAlgorithm? algorithm = null)
    {
        var log = new HashChainLog(algorithm ?? ContentHashAlgorithm.Sha256);
        for (int i = 0; i < count; i++)
            log.Append(Utf8("entry-" + i));
        return log.Entries.ToList();
    }

    // ---- ContentDigest -------------------------------------------------------------------------------------

    [Theory]
    [InlineData(-1)]
    [InlineData(5)]
    public void Digest_Append_OffsetOutOfRange_ReportsOffset(int offset)
    {
        using var digest = new RecordingDigest();

        var ex = Assert.Throws<ArgumentOutOfRangeException>(() => digest.Append(new byte[4], offset, 0));
        Assert.Equal("offset", ex.ParamName);
        Assert.Empty(digest.AppendCounts);
    }

    [Fact]
    public void Digest_Append_AtTheEndOfTheBuffer_IsAccepted()
    {
        using var digest = new RecordingDigest();

        digest.Append(new byte[4], 4, 0);
        digest.Append(new byte[4], 1, 3);

        Assert.Equal(new[] { 3 }, digest.AppendCounts);
    }

    [Fact]
    public void Digest_Append_ZeroBytes_IsNotForwarded()
    {
        using var digest = new RecordingDigest();

        digest.Append(Array.Empty<byte>());
        digest.Append(new byte[3], 1, 0);
        digest.Append(new byte[3], 0, 1);

        Assert.Equal(new[] { 1 }, digest.AppendCounts);
    }

    [Fact]
    public void Digest_Append_AfterDispose_Throws()
    {
        var digest = new RecordingDigest();
        digest.Dispose();

        Assert.Throws<ObjectDisposedException>(() => digest.Append(new byte[2]));
        Assert.Throws<ObjectDisposedException>(() => digest.Append(Array.Empty<byte>()));
        Assert.Empty(digest.AppendCounts);

        using ContentDigest sha = ContentHashAlgorithm.Sha256.CreateDigest();
        sha.Dispose();
        Assert.Throws<ObjectDisposedException>(() => sha.Append(Array.Empty<byte>()));
    }

    [Fact]
    public void Digest_Dispose_CallsTheImplementationOnceWithDisposingTrue()
    {
        var digest = new RecordingDigest();

        digest.Dispose();
        digest.Dispose();

        Assert.Equal(new[] { true }, digest.DisposeCalls);
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static void CreateDigests(int count, bool dispose)
    {
        for (int i = 0; i < count; i++)
        {
            var digest = new FinalizableDigest();
            if (dispose)
                digest.Dispose();
        }
    }

    private static void CollectAll()
    {
        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();
    }

    [Fact]
    public void Digest_Dispose_SuppressesTheFinalizer()
    {
        // Control: an undisposed digest is finalized, so the check below is not vacuous.
        int start = FinalizableDigest.Finalized;
        CreateDigests(5, dispose: false);
        CollectAll();
        int afterUndisposed = FinalizableDigest.Finalized;
        Assert.True(afterUndisposed > start, "undisposed digests should have been finalized");

        CreateDigests(5, dispose: true);
        CollectAll();

        Assert.Equal(afterUndisposed, FinalizableDigest.Finalized);
    }

    [Fact]
    public void BuiltInDigests_DisposeTheirIncrementalHash()
    {
        foreach (ContentHashAlgorithm algorithm in new[] { ContentHashAlgorithm.Sha256, Hmac("mut-dispose") })
        {
            ContentDigest digest = algorithm.CreateDigest();
            FieldInfo field = digest.GetType().GetField("_hash", BindingFlags.NonPublic | BindingFlags.Instance)!;
            var inner = (IncrementalHash)field.GetValue(digest)!;
            inner.AppendData(new byte[1]); // usable before dispose

            digest.Dispose();

            Assert.Throws<ObjectDisposedException>(() => inner.AppendData(new byte[1]));
        }
    }

    // ---- ContentHash ---------------------------------------------------------------------------------------

    [Fact]
    public void ContentHash_IsFrom_RequiresTheSameName()
    {
        ContentHash hash = ContentHasher.Compute(Utf8("x"));

        Assert.True(hash.IsFrom(ContentHashAlgorithm.Sha256));
        Assert.False(hash.IsFrom(new MutAlgorithm("mut-isfrom", 32)));
    }

    [Fact]
    public void ContentHash_IsFrom_RequiresTheSameKeyId()
    {
        ContentHash hash = ContentHasher.Compute(Utf8("x"), Hmac("ka"));

        Assert.True(hash.IsFrom(Hmac("ka", "other key")));
        Assert.False(hash.IsFrom(Hmac("kb")));
    }

    [Fact]
    public void ContentHash_Parse_InvalidString_HasAFixedMessage()
    {
        var ex = Assert.Throws<FormatException>(() => ContentHash.Parse("sha256:nothex"));
        Assert.Equal("Not a valid content hash string.", ex.Message);
    }

    [Fact]
    public void ContentHash_TryParse_AcceptsAStringOfExactlyMaxStringLength()
    {
        string name = "mut-max".PadRight(32, 'x');
        ContentHashAlgorithm.RegisterKeyedFamily(name, 128);
        string value = name + ":" + new string('K', 32) + ":" + new string('a', 256);
        Assert.Equal(ContentHash.MaxStringLength, value.Length);

        Assert.True(ContentHash.TryParse(value, out ContentHash? parsed));
        Assert.Equal(name, parsed!.Algorithm);
        Assert.Equal(new string('K', 32), parsed.KeyId);
        Assert.Equal(128, parsed.Digest.Length);
        Assert.Equal(value, parsed.ToString());

        Assert.False(ContentHash.TryParse(value + "a", out _));
    }

    [Fact]
    public void ContentHash_GetHashCode_FoldsTheNameAndTheFirstFourDigestBytes()
    {
        ContentHash hash = ContentHasher.Compute(Utf8("hash code"));
        byte[] digest = hash.ToArray();

        int expected = StringComparer.Ordinal.GetHashCode("sha256");
        for (int i = 0; i < 4; i++)
            expected = (expected * 31) ^ digest[i];

        Assert.Equal(expected, hash.GetHashCode());

        // Only the first four bytes take part.
        byte[] changedTail = (byte[])digest.Clone();
        changedTail[4] ^= 0xFF;
        changedTail[31] ^= 0xFF;
        Assert.Equal(expected, new ContentHash(ContentHashAlgorithm.Sha256, changedTail).GetHashCode());
    }

    private static Exception? ReadWithConverter(string json)
    {
        var reader = new Utf8JsonReader(Utf8(json));
        reader.Read();
        try
        {
            new ContentHashJsonConverter().Read(ref reader, typeof(ContentHash), new JsonSerializerOptions());
            return null;
        }
        catch (Exception e)
        {
            return e;
        }
    }

    [Fact]
    public void JsonConverter_NonStringToken_IsAJsonException()
    {
        Exception? ex = ReadWithConverter("123");

        Assert.IsType<JsonException>(ex);
        Assert.Equal("Expected a content hash string.", ex!.Message);
    }

    [Fact]
    public void JsonConverter_InvalidString_IsAJsonException()
    {
        Exception? ex = ReadWithConverter("\"sha256:zz\"");

        Assert.IsType<JsonException>(ex);
        Assert.Equal("Not a valid content hash string.", ex!.Message);
    }

    // ---- ContentHashAlgorithm ------------------------------------------------------------------------------

    [Fact]
    public void CustomAlgorithm_DigestLengthLimits_AreInclusive()
    {
        Assert.Equal(16, new MutAlgorithm("mut-len16", 16).DigestLength);
        Assert.Equal(128, new MutAlgorithm("mut-len128", 128).DigestLength);
    }

    [Fact]
    public void RegisterKeyedFamily_DigestLengthLimits_AreInclusive()
    {
        ContentHashAlgorithm.RegisterKeyedFamily("mut-family16", 16);
        ContentHashAlgorithm.RegisterKeyedFamily("mut-family128", 128);

        Assert.True(ContentHashAlgorithm.IsRegistered("mut-family16"));
        Assert.True(ContentHashAlgorithm.IsRegistered("mut-family128"));
        Assert.True(ContentHash.TryParse("mut-family16:k:" + new string('0', 32), out _));
    }

    [Fact]
    public void Register_KeyedInstance_IsNeverResolvable()
    {
        var keyed = new MutAlgorithm("mut-keyed-instance", 32, "k1");

        ContentHashAlgorithm.Register(keyed);

        Assert.True(ContentHashAlgorithm.IsRegistered("mut-keyed-instance"));
        Assert.False(ContentHashAlgorithm.TryGet("mut-keyed-instance", out ContentHashAlgorithm? resolved));
        Assert.Null(resolved);
        Assert.True(ContentHash.TryParse("mut-keyed-instance:k1:" + new string('0', 64), out ContentHash? parsed));
        Assert.Equal("k1", parsed!.KeyId);
    }

    [Fact]
    public void Register_Conflict_NamesTheAlgorithm()
    {
        var ex = Assert.Throws<InvalidOperationException>(() => ContentHashAlgorithm.RegisterKeyedFamily("sha256", 32));
        Assert.Equal("A different algorithm named 'sha256' is already registered.", ex.Message);
    }

    [Fact]
    public async Task VerifyAsync_AlgorithmWithAnotherName_ReturnsFalseWithoutReadingTheStream()
    {
        ContentHash expected = ContentHasher.Compute(Utf8("data"));
        using var stream = new MemoryStream(Utf8("data"));

        Assert.False(await ContentHasher.VerifyAsync(stream, expected, new MutAlgorithm("mut-other-name", 32)));
        Assert.Equal(0, stream.Position);
    }

    [Fact]
    public async Task VerifyAsync_AlgorithmWithAnotherKeyId_ReturnsFalseWithoutReadingTheStream()
    {
        ContentHash expected = ContentHasher.Compute(Utf8("data"), Hmac("ka"));
        using var stream = new MemoryStream(Utf8("data"));

        Assert.False(await ContentHasher.VerifyAsync(stream, expected, Hmac("kb")));
        Assert.Equal(0, stream.Position);
    }

    // ---- ContentHasher -------------------------------------------------------------------------------------

    [Fact]
    public void Verify_NullData_ThrowsEvenWhenTheAlgorithmCannotBeResolved()
    {
        ContentHash keyed = ContentHasher.Compute(Utf8("x"), Hmac("k"));

        var ex = Assert.Throws<ArgumentNullException>(() => ContentHasher.Verify(null!, keyed));
        Assert.Equal("data", ex.ParamName);
    }

    [Fact]
    public void OpenRead_OpensForAsynchronousIo()
    {
        using var dir = new TempDirectory();
        string path = dir.Write("f.bin", "x");

        using FileStream stream = ContentHasher.OpenRead(path);

        Assert.True(stream.IsAsync);
        Assert.True(stream.CanRead);
        Assert.False(stream.CanWrite);
    }

    /// <summary>Puts a marked array into this thread's pool slot so that the next rent of the buffer size gets it.</summary>
    private static byte[] PrimePool()
    {
        byte[] mine = ArrayPool<byte>.Shared.Rent(ContentHasher.BufferSize);
        Assert.Equal(ContentHasher.BufferSize, mine.Length);
        mine.AsSpan().Fill(0xAA);
        ArrayPool<byte>.Shared.Return(mine);
        return mine;
    }

    [Fact]
    public void Compute_Stream_ReturnsTheBufferCleared()
    {
        byte[] mine = PrimePool();

        ContentHash hash = ContentHasher.Compute(new MemoryStream(Utf8("secret content")), ContentHashAlgorithm.Sha256);

        Assert.Equal(ContentHasher.Compute(Utf8("secret content")), hash);
        Assert.True(mine.All(b => b == 0), "the pooled buffer must be returned to the pool and cleared");
    }

    [Fact]
    public async Task ComputeAsync_Stream_ReturnsTheBufferCleared()
    {
        byte[] mine = PrimePool();

        // MemoryStream reads complete synchronously, so the whole computation runs on this thread.
        Task<ContentHash> task = ContentHasher.ComputeAsync(new MemoryStream(Utf8("secret content")), ContentHashAlgorithm.Sha256);

        Assert.True(task.IsCompleted);
        Assert.Equal(ContentHasher.Compute(Utf8("secret content")), await task);
        Assert.True(mine.All(b => b == 0), "the pooled buffer must be returned to the pool and cleared");
    }

    [Fact]
    public void ComputeFileAsync_DoesNotResumeOnTheCallersContext()
    {
        using var dir = new TempDirectory();
        byte[] data = RandomNumberGenerator.GetBytes(100_000);
        string path = dir.Write("f.bin", data);

        ContentHash hash = RunUnderContext(() => ContentHasher.ComputeFileAsync(path), out int posts);

        Assert.Equal(ContentHasher.Compute(data), hash);
        Assert.Equal(0, posts);

        if (OperatingSystem.IsWindows())
        {
            // Control: async file reads really suspend, so an await that keeps the context is seen by the counter.
            async Task<ContentHash> Capturing() => await ContentHasher.ComputeFileAsync(path);
            RunUnderContext(Capturing, out int capturedPosts);
            Assert.True(capturedPosts > 0, "a context-capturing await should have posted");
        }
    }

    [Fact]
    public void ComputeAsync_FileStream_DoesNotResumeOnTheCallersContext()
    {
        using var dir = new TempDirectory();
        byte[] data = RandomNumberGenerator.GetBytes(100_000);
        string path = dir.Write("f.bin", data);
        using FileStream stream = ContentHasher.OpenRead(path);

        ContentHash hash = RunUnderContext(() => ContentHasher.ComputeAsync(stream, ContentHashAlgorithm.Sha256), out int posts);

        Assert.Equal(ContentHasher.Compute(data), hash);
        Assert.Equal(0, posts);
    }

    [Fact]
    public void VerifyAsync_FileStream_DoesNotResumeOnTheCallersContext()
    {
        using var dir = new TempDirectory();
        byte[] data = RandomNumberGenerator.GetBytes(100_000);
        string path = dir.Write("f.bin", data);
        using FileStream stream = ContentHasher.OpenRead(path);

        bool ok = RunUnderContext(() => ContentHasher.VerifyAsync(stream, ContentHasher.Compute(data)), out int posts);

        Assert.True(ok);
        Assert.Equal(0, posts);
    }

    [Fact]
    public void VerifyFileAsync_DoesNotResumeOnTheCallersContext()
    {
        using var dir = new TempDirectory();
        byte[] data = RandomNumberGenerator.GetBytes(100_000);
        string path = dir.Write("f.bin", data);

        bool ok = RunUnderContext(() => ContentHasher.VerifyFileAsync(path, ContentHasher.Compute(data)), out int posts);

        Assert.True(ok);
        Assert.Equal(0, posts);
    }

    // ---- DirectoryManifest ---------------------------------------------------------------------------------

    [Fact]
    public async Task CreateAsync_NullRoot_NamesTheParameter()
    {
        var ex = await Assert.ThrowsAsync<ArgumentNullException>(() => DirectoryManifest.CreateAsync(null!, ContentHashAlgorithm.Sha256));
        Assert.Equal("rootPath", ex.ParamName);
    }

    [Fact]
    public async Task CreateAsync_MissingRoot_HasAFixedMessage()
    {
        using var dir = new TempDirectory();

        var ex = await Assert.ThrowsAsync<DirectoryNotFoundException>(() => DirectoryManifest.CreateAsync(Path.Combine(dir.Path, "missing")));
        Assert.Equal("The manifest root directory does not exist.", ex.Message);
    }

    [Fact]
    public async Task CreateAsync_RootWithATrailingSeparator_GivesTheSameManifest()
    {
        using var dir = new TempDirectory();
        dir.Write("a.txt", "a");
        dir.Write("sub/b.txt", "b");

        DirectoryManifest plain = await DirectoryManifest.CreateAsync(dir.Path);
        DirectoryManifest trailing = await DirectoryManifest.CreateAsync(dir.Path + Path.DirectorySeparatorChar);

        Assert.Equal(new[] { "a.txt", "sub/b.txt" }, trailing.Entries.Select(e => e.Path));
        Assert.Equal(plain.Root, trailing.Root);
    }

    [Fact]
    public async Task CreateAsync_CanceledToken_ThrowsEvenWhenNoFileIsRead()
    {
        using var dir = new TempDirectory();
        dir.Write("empty.txt", Array.Empty<byte>());
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => DirectoryManifest.CreateAsync(dir.Path, ContentHashAlgorithm.Sha256, null, cts.Token));
    }

    [Fact]
    public async Task CreateAsync_MaxEntriesOfOne_AllowsExactlyOneEntry()
    {
        using var dir = new TempDirectory();
        dir.Write("a.txt", "a");
        var options = new DirectoryManifestOptions { MaxEntries = 1 };

        DirectoryManifest manifest = await DirectoryManifest.CreateAsync(dir.Path, ContentHashAlgorithm.Sha256, options);
        Assert.Equal("a.txt", Assert.Single(manifest.Entries).Path);

        dir.Write("b.txt", "b");
        var ex = await Assert.ThrowsAsync<IOException>(() => DirectoryManifest.CreateAsync(dir.Path, ContentHashAlgorithm.Sha256, options));
        Assert.Equal("The directory tree has more entries than MaxEntries allows, so it cannot be fully verified.", ex.Message);
    }

    [Fact]
    public async Task CreateAsync_TooDeep_HasAFixedMessage()
    {
        using var dir = new TempDirectory();
        dir.Write("sub/a.txt", "a");

        var ex = await Assert.ThrowsAsync<IOException>(() => DirectoryManifest.CreateAsync(dir.Path, ContentHashAlgorithm.Sha256,
            new DirectoryManifestOptions { MaxDepth = 0 }));
        Assert.Equal("The directory tree is nested deeper than MaxDepth, so it cannot be fully verified.", ex.Message);
    }

    [Fact]
    public async Task CreateAsync_EmptyFile_IsNotOpened()
    {
        if (!OperatingSystem.IsWindows())
            return; // Relies on Windows sharing modes to detect an open.

        using var dir = new TempDirectory();
        string empty = dir.Write("empty.txt", Array.Empty<byte>());
        dir.Write("full.txt", "x");

        DirectoryManifest manifest;
        using (new FileStream(empty, FileMode.Open, FileAccess.Read, FileShare.None))
            manifest = await DirectoryManifest.CreateAsync(dir.Path);

        DirectoryManifestEntry entry = manifest.Entries[0];
        Assert.Equal("empty.txt", entry.Path);
        Assert.Equal(0, entry.Length);
        Assert.Equal(ContentHasher.Compute(Array.Empty<byte>()), entry.Hash);
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
    public async Task CreateAsync_FollowedLinkToAnEmptyFile_DoesNotOpenTheTarget()
    {
        if (!OperatingSystem.IsWindows())
            return; // Relies on Windows sharing modes to detect an open.

        using var dir = new TempDirectory();
        using var outside = new TempDirectory();
        string empty = outside.Write("empty.txt", Array.Empty<byte>());
        if (!TryLink(() => File.CreateSymbolicLink(Path.Combine(dir.Path, "empty.lnk"), empty)))
            return;

        DirectoryManifest manifest;
        using (new FileStream(empty, FileMode.Open, FileAccess.Read, FileShare.None))
            manifest = await DirectoryManifest.CreateAsync(dir.Path, ContentHashAlgorithm.Sha256,
                new DirectoryManifestOptions { FollowReparsePoints = true });

        DirectoryManifestEntry entry = Assert.Single(manifest.Entries);
        Assert.Equal(DirectoryManifestEntryKind.File, entry.Kind);
        Assert.Equal(0, entry.Length);
    }

    [Fact]
    public async Task CreateAsync_FileNameWithALeadingBackslash_IsAnErrorOnUnix()
    {
        if (OperatingSystem.IsWindows())
            return; // A backslash is a separator on Windows.

        using var dir = new TempDirectory();
        File.WriteAllText(Path.Combine(dir.Path, "\\lead"), "x");

        var ex = await Assert.ThrowsAsync<IOException>(() => DirectoryManifest.CreateAsync(dir.Path));
        Assert.Equal("A file or directory name contains a backslash, which manifests cannot represent.", ex.Message);
    }

    [Fact]
    public void CreateAsync_DoesNotResumeOnTheCallersContext()
    {
        using var dir = new TempDirectory();
        byte[] data = RandomNumberGenerator.GetBytes(100_000);
        dir.Write("a.bin", data);
        dir.Write("b.bin", data);

        DirectoryManifest manifest = RunUnderContext(() => DirectoryManifest.CreateAsync(dir.Path), out int posts);

        Assert.Equal(2, manifest.Entries.Count);
        Assert.Equal(0, posts);
    }

    [Fact]
    public async Task VerifyAsync_DoesNotResumeOnTheCallersContext()
    {
        using var dir = new TempDirectory();
        dir.Write("a.bin", RandomNumberGenerator.GetBytes(100_000));
        DirectoryManifest manifest = await DirectoryManifest.CreateAsync(dir.Path);

        DirectoryManifestDiff diff = RunUnderContext(() => DirectoryManifest.VerifyAsync(dir.Path, manifest), out int posts);

        Assert.True(diff.ManifestIntact);
        Assert.Empty(diff.Modified);
        Assert.Equal(0, posts);
    }

    [Fact]
    public void ToJson_Indented_HasLineBreaksAndCompactHasNone()
    {
        DirectoryManifest manifest = DirectoryManifest.FromEntries(
            new[] { new DirectoryManifestEntry("a.txt", 1, ContentHasher.Compute(Utf8("a"))) }, ContentHashAlgorithm.Sha256);

        Assert.Contains("\n  \"format\"", manifest.ToJson().Replace("\r\n", "\n"));
        Assert.Contains("\n", manifest.ToJson(indented: true));
        Assert.DoesNotContain("\n", manifest.ToJson(indented: false));
        Assert.StartsWith("{\"format\":\"masterly-manifest/v1\",\"algorithm\":\"sha256\",\"root\":\"sha256:", manifest.ToJson(false));
    }

    [Fact]
    public void FromJson_Invalid_HasAFixedMessage()
    {
        var ex = Assert.Throws<FormatException>(() => DirectoryManifest.FromJson("{}"));
        Assert.Equal("Not a valid directory manifest.", ex.Message);
    }

    private static string CompactJson(long length)
    {
        byte[] content = new byte[length];
        return DirectoryManifest.FromEntries(
            new[] { new DirectoryManifestEntry("a.txt", length, ContentHasher.Compute(content)) }, ContentHashAlgorithm.Sha256).ToJson(false);
    }

    [Fact]
    public void TryFromJson_BaseDocument_IsValid()
    {
        Assert.True(DirectoryManifest.TryFromJson(CompactJson(0), out _));
        Assert.True(DirectoryManifest.TryFromJson(CompactJson(1), out _));
    }

    [Fact]
    public void TryFromJson_RepeatedFormat_IsRejected()
    {
        string json = CompactJson(1);
        string repeated = "{\"format\":\"masterly-manifest/v1\"," + json.Substring(1);

        Assert.False(DirectoryManifest.TryFromJson(repeated, out _));
    }

    [Fact]
    public void TryFromJson_RepeatedAlgorithm_IsRejected()
    {
        string json = CompactJson(1);
        string repeated = "{\"algorithm\":\"sha256\"," + json.Substring(1);

        Assert.False(DirectoryManifest.TryFromJson(repeated, out _));
    }

    [Fact]
    public void TryFromJson_RepeatedFiles_IsRejected()
    {
        string json = CompactJson(1);
        string repeated = json.Substring(0, json.Length - 1) + ",\"files\":[]}";

        Assert.False(DirectoryManifest.TryFromJson(repeated, out _));
    }

    [Fact]
    public void TryFromJson_RepeatedPath_IsRejected()
    {
        string repeated = CompactJson(1).Replace("\"path\":\"a.txt\"", "\"path\":\"a.txt\",\"path\":\"a.txt\"", StringComparison.Ordinal);

        Assert.False(DirectoryManifest.TryFromJson(repeated, out _));
    }

    [Fact]
    public void TryFromJson_RepeatedHash_IsRejected()
    {
        string json = CompactJson(1);
        string hash = "\"hash\":\"" + ContentHasher.Compute(new byte[1]) + "\"";
        Assert.Contains(hash, json);
        string repeated = json.Replace(hash, hash + "," + hash, StringComparison.Ordinal);

        Assert.False(DirectoryManifest.TryFromJson(repeated, out _));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    public void TryFromJson_RepeatedLength_IsRejected(long length)
    {
        string field = "\"length\":" + length;
        string json = CompactJson(length);
        Assert.Contains(field, json);
        string repeated = json.Replace(field, field + "," + field, StringComparison.Ordinal);

        Assert.False(DirectoryManifest.TryFromJson(repeated, out _));
    }

    [Fact]
    public void EncodeLeaf_UsesEightByteBigEndianLengths()
    {
        ContentHash hash = ContentHasher.Compute(Utf8("x"));
        const long length = 0x0102030405060708;
        var entry = new DirectoryManifestEntry("d/f", length, hash);

        byte[] expected = Field(Utf8("masterly-manifest/v1"))
            .Concat(Field(Utf8("d/f")))
            .Concat(U64(length))
            .Concat(Field(hash.ToArray()))
            .ToArray();

        Assert.Equal(ToHex(expected), ToHex(DirectoryManifest.EncodeLeaf(entry)));
    }

    // ---- DirectoryManifestEntry ----------------------------------------------------------------------------

    [Fact]
    public void IsCanonicalPath_AcceptsExactlyMaxPathLength()
    {
        Assert.True(DirectoryManifestEntry.IsCanonicalPath(new string('a', DirectoryManifestEntry.MaxPathLength)));
        Assert.False(DirectoryManifestEntry.IsCanonicalPath(new string('a', DirectoryManifestEntry.MaxPathLength + 1)));
    }

    // ---- HashChain -----------------------------------------------------------------------------------------

    [Fact]
    public void ComputeEntryHash_MatchesTheDocumentedEncoding()
    {
        byte[] previous = Enumerable.Repeat((byte)0x11, 32).ToArray();
        byte[] payload = Utf8("payload");
        const long sequence = 0x0102030405060708;

        byte[] input = Field(Utf8("masterly-hash-chain/v1"))
            .Concat(Field(Utf8("sha256")))
            .Concat(U64(sequence))
            .Concat(Field(previous))
            .Concat(Field(payload))
            .ToArray();

        Assert.Equal(ToHex(SHA256.HashData(input)), ToHex(HashChain.ComputeEntryHash(previous, payload, sequence)));
    }

    [Fact]
    public void CreateNext_NullAlgorithmWithAPreviousEntry_NamesTheParameter()
    {
        HashChainEntry previous = Chain(1)[0];

        var ex = Assert.Throws<ArgumentNullException>(() => HashChain.CreateNext(previous, Utf8("p"), null!));
        Assert.Equal("algorithm", ex.ParamName);
    }

    [Fact]
    public void CreateNext_PreviousFromAnotherAlgorithm_NamesThePreviousParameter()
    {
        HashChainEntry previous = Chain(1, ContentHashAlgorithm.Sha512)[0];

        var ex = Assert.Throws<ArgumentException>(() => HashChain.CreateNext(previous, Utf8("p"), ContentHashAlgorithm.Sha256));
        Assert.Equal("previous", ex.ParamName);
    }

    [Fact]
    public void CreateNext_AfterTheMaximumSequence_Overflows()
    {
        var last = new HashChainEntry(long.MaxValue, new byte[32], Utf8("p"), new byte[32]);

        Assert.Throws<OverflowException>(() => HashChain.CreateNext(last, Utf8("q"), ContentHashAlgorithm.Sha256));
    }

    [Fact]
    public void Verify_NullEntries_NamesTheParameter()
    {
        var ex = Assert.Throws<ArgumentNullException>(() => HashChain.Verify(null!, ContentHashAlgorithm.Sha256, null, null));
        Assert.Equal("entries", ex.ParamName);
    }

    [Fact]
    public void Verify_NullAlgorithmWithAnAnchor_NamesTheParameter()
    {
        var anchor = new HashChainCheckpoint(0, new byte[32]);

        var ex = Assert.Throws<ArgumentNullException>(() => HashChain.Verify(Array.Empty<HashChainEntry>(), null!, anchor, null));
        Assert.Equal("algorithm", ex.ParamName);
    }

    [Fact]
    public void Verify_ReadOnlyList_IsReadByIndexWithoutCopying()
    {
        var list = new IndexOnlyList<HashChainEntry>(Chain(3));

        HashChainVerificationResult result = HashChain.Verify(list, ContentHashAlgorithm.Sha256);

        Assert.True(result.IsValid);
        Assert.Equal(3, result.EntriesVerified);
    }

    [Fact]
    public void Verify_NullEntry_Reason()
    {
        HashChainVerificationResult result = HashChain.Verify(new HashChainEntry[] { null! });

        Assert.Equal(HashChainFailure.InvalidEntry, result.Failure);
        Assert.Equal("Entry is null.", result.Reason);
    }

    [Fact]
    public void Verify_BrokenLink_Reason()
    {
        List<HashChainEntry> chain = Chain(2);
        HashChainEntry e = chain[1];
        chain[1] = new HashChainEntry(e.Sequence, Flip(e.PreviousHash.ToArray()), e.Payload.ToArray(), e.Hash.ToArray());

        HashChainVerificationResult result = HashChain.Verify(chain);

        Assert.Equal(HashChainFailure.PreviousHashMismatch, result.Failure);
        Assert.Equal("Entry does not link to the hash of the entry before it.", result.Reason);
    }

    [Fact]
    public void Verify_EditedEntry_Reason()
    {
        List<HashChainEntry> chain = Chain(2);
        HashChainEntry e = chain[1];
        chain[1] = new HashChainEntry(e.Sequence, e.PreviousHash.ToArray(), Utf8("edited"), e.Hash.ToArray());

        HashChainVerificationResult result = HashChain.Verify(chain);

        Assert.Equal(HashChainFailure.HashMismatch, result.Failure);
        Assert.Equal("Entry hash does not match its contents.", result.Reason);
    }

    [Fact]
    public void Verify_DifferentEntryAtTheHeadCheckpoint_Reason()
    {
        List<HashChainEntry> chain = Chain(3);
        var head = new HashChainCheckpoint(1, Flip(chain[1].Hash.ToArray()));

        HashChainVerificationResult result = HashChain.Verify(chain, ContentHashAlgorithm.Sha256, null, head);

        Assert.Equal(HashChainFailure.HeadMismatch, result.Failure);
        Assert.Equal(1, result.FirstBrokenIndex);
        Assert.Equal("The entry at the trusted checkpoint's sequence does not match it.", result.Reason);
    }

    [Fact]
    public void Verify_Truncated_ReportsTheFirstMissingSequenceAndReason()
    {
        List<HashChainEntry> chain = Chain(4);
        HashChainCheckpoint head = chain[3].ToCheckpoint();

        HashChainVerificationResult result = HashChain.Verify(chain.Take(2), ContentHashAlgorithm.Sha256, null, head);

        Assert.Equal(HashChainFailure.Truncated, result.Failure);
        Assert.Equal(2, result.FirstBrokenIndex);
        Assert.Equal(2, result.EntriesVerified);
        Assert.Equal(2L, result.BrokenSequence);
        Assert.Equal("The chain ends before the trusted head checkpoint.", result.Reason);
    }

    [Fact]
    public void Verify_HeadAtTheAnchorSequenceWithAnotherHash_IsAHeadMismatch()
    {
        byte[] anchorHash = SHA256.HashData(Utf8("anchor"));
        var anchor = new HashChainCheckpoint(2, anchorHash);
        var head = new HashChainCheckpoint(2, Flip(anchorHash));

        HashChainVerificationResult result = HashChain.Verify(Array.Empty<HashChainEntry>(), ContentHashAlgorithm.Sha256, anchor, head);

        Assert.False(result.IsValid);
        Assert.Equal(HashChainFailure.HeadMismatch, result.Failure);
        Assert.Equal(0, result.FirstBrokenIndex);
        Assert.Equal(2L, result.BrokenSequence);
        Assert.Equal("The trusted head checkpoint is not covered by this segment or its anchor.", result.Reason);

        // Control: the same hash at the same sequence is covered by the anchor.
        Assert.True(HashChain.Verify(Array.Empty<HashChainEntry>(), ContentHashAlgorithm.Sha256, anchor,
            new HashChainCheckpoint(2, anchorHash)).IsValid);
    }

    [Fact]
    public void Verify_HeadBeforeTheAnchorWithTheAnchorsHash_IsAHeadMismatch()
    {
        byte[] anchorHash = SHA256.HashData(Utf8("anchor"));
        var anchor = new HashChainCheckpoint(3, anchorHash);
        var head = new HashChainCheckpoint(2, anchorHash);

        HashChainVerificationResult result = HashChain.Verify(Array.Empty<HashChainEntry>(), ContentHashAlgorithm.Sha256, anchor, head);

        Assert.Equal(HashChainFailure.HeadMismatch, result.Failure);
        Assert.Equal(2L, result.BrokenSequence);
    }

    [Fact]
    public void Verify_Duplicate_Reason()
    {
        List<HashChainEntry> chain = Chain(3);

        HashChainVerificationResult result = HashChain.Verify(new[] { chain[0], chain[1], chain[1] });

        Assert.Equal(HashChainFailure.Duplicate, result.Failure);
        Assert.Equal("Sequence 1 appears twice.", result.Reason);
    }

    [Fact]
    public void Verify_EarlierSequence_Reason()
    {
        List<HashChainEntry> chain = Chain(4);

        HashChainVerificationResult result = HashChain.Verify(new[] { chain[0], chain[1], chain[2], chain[1] });

        Assert.Equal(HashChainFailure.Reorder, result.Failure);
        Assert.Equal("Expected sequence 3 but found 1.", result.Reason);
    }

    [Fact]
    public void Verify_LaterSequenceWhoseExpectedEntryFollows_Reason()
    {
        List<HashChainEntry> chain = Chain(3);

        HashChainVerificationResult result = HashChain.Verify(new[] { chain[0], chain[2], chain[1] });

        Assert.Equal(HashChainFailure.Reorder, result.Failure);
        Assert.Equal(1, result.FirstBrokenIndex);
        Assert.Equal(2L, result.BrokenSequence);
        Assert.Equal("Expected sequence 1 but found 2.", result.Reason);
    }

    [Fact]
    public void Verify_Gap_Reason()
    {
        List<HashChainEntry> chain = Chain(4);

        HashChainVerificationResult result = HashChain.Verify(new[] { chain[0], chain[3] });

        Assert.Equal(HashChainFailure.Gap, result.Failure);
        Assert.Equal(3L, result.BrokenSequence);
        Assert.Equal("Sequence 1 to 2 is missing.", result.Reason);
    }

    [Fact]
    public void VerificationResult_ToString()
    {
        List<HashChainEntry> chain = Chain(4);

        Assert.Equal("Valid (4 entries)", HashChain.Verify(chain).ToString());
        Assert.Equal("Gap at index 1: Sequence 1 to 2 is missing.", HashChain.Verify(new[] { chain[0], chain[3] }).ToString());
    }

    [Fact] // Regression: expectedSequence used to saturate at long.MaxValue.
    public void Verify_SecondEntryAtTheMaximumSequence_IsNotValid()
    {
        byte[] anchorHash = SHA256.HashData(Utf8("anchor"));
        var anchor = new HashChainCheckpoint(long.MaxValue - 1, anchorHash);
        byte[] firstHash = HashChain.ComputeEntryHash(anchorHash, Utf8("a"), long.MaxValue);
        var first = new HashChainEntry(long.MaxValue, anchorHash, Utf8("a"), firstHash);
        byte[] secondHash = HashChain.ComputeEntryHash(firstHash, Utf8("b"), long.MaxValue);
        var second = new HashChainEntry(long.MaxValue, firstHash, Utf8("b"), secondHash);

        HashChainVerificationResult result = HashChain.Verify(new[] { first, second }, ContentHashAlgorithm.Sha256, anchor, null);

        Assert.False(result.IsValid);
        Assert.Equal(HashChainFailure.Duplicate, result.Failure);
        Assert.Equal(1, result.FirstBrokenIndex);
    }

    [Fact]
    public void Entry_ToString_ShowsSequenceAndPayloadLength()
    {
        var entry = new HashChainEntry(2, new byte[32], Utf8("hello"), new byte[32]);

        Assert.Equal("#2 (5 bytes)", entry.ToString());
    }

    [Fact]
    public void Log_NullExisting_NamesTheParameter()
    {
        var ex = Assert.Throws<ArgumentNullException>(() => new HashChainLog(ContentHashAlgorithm.Sha256, null!));
        Assert.Equal("existing", ex.ParamName);
    }

    [Fact]
    public void Log_InvalidExisting_MessageIncludesTheResult()
    {
        List<HashChainEntry> chain = Chain(2);

        var ex = Assert.Throws<InvalidDataException>(() => new HashChainLog(ContentHashAlgorithm.Sha256, new[] { chain[1] }));
        Assert.Equal("The existing chain is invalid: Gap at index 0: Sequence 0 to 0 is missing.", ex.Message);
    }

    // ---- internals -----------------------------------------------------------------------------------------

    [Theory]
    [InlineData("0g")]
    [InlineData("g0")]
    [InlineData("0A")]
    public void Hex_TryDecode_RejectsASingleBadNibble(string value)
    {
        Assert.False(Internal.Hex.TryDecode(value, 0, 2, out byte[] bytes));
        Assert.Empty(bytes);
    }

    [Theory]
    [InlineData("0")]
    [InlineData("9")]
    [InlineData("a")]
    [InlineData("z")]
    [InlineData("a-0")]
    public void Identifiers_AlgorithmName_RangeEndsAreValid(string name)
    {
        Assert.True(Identifiers.IsValidAlgorithmName(name));
    }

    [Fact]
    public void Identifiers_AlgorithmName_LengthLimitIsInclusive()
    {
        Assert.True(Identifiers.IsValidAlgorithmName(new string('a', 32)));
        Assert.False(Identifiers.IsValidAlgorithmName(new string('a', 33)));
        Assert.False(Identifiers.IsValidAlgorithmName("-a"));
        Assert.False(Identifiers.IsValidAlgorithmName("a/"));
        Assert.False(Identifiers.IsValidAlgorithmName("a{"));
    }

    [Theory]
    [InlineData("0")]
    [InlineData("9")]
    [InlineData("A")]
    [InlineData("Z")]
    [InlineData("a")]
    [InlineData("z")]
    [InlineData("-")]
    public void Identifiers_KeyId_RangeEndsAreValid(string keyId)
    {
        Assert.True(Identifiers.IsValidKeyId(keyId));
    }

    [Fact]
    public void Identifiers_KeyId_LengthLimitIsInclusive()
    {
        Assert.True(Identifiers.IsValidKeyId(new string('K', 32)));
        Assert.False(Identifiers.IsValidKeyId(new string('K', 33)));
        Assert.False(Identifiers.IsValidKeyId("a_b"));
    }

    // ---- MerkleTree ----------------------------------------------------------------------------------------

    [Fact]
    public void VerifyInclusion_NullLeafAndNullAlgorithm_Throws()
    {
        var ex = Assert.Throws<ArgumentNullException>(() =>
            MerkleTree.VerifyInclusion(null!, 0, 1, Array.Empty<byte[]>(), new byte[32], null!));
        Assert.Equal("algorithm", ex.ParamName);
    }

    [Fact]
    public void VerifyInclusionOfLeafHash_WrongLengthLeafHash_IsRejectedEvenIfItHashesToTheRoot()
    {
        ContentHashAlgorithm sha = ContentHashAlgorithm.Sha256;
        byte[] shortLeaf = new byte[16];
        byte[] sibling = SHA256.HashData(Utf8("sibling"));
        byte[] root = MerkleTree.HashChildren(shortLeaf, sibling, sha);

        Assert.False(MerkleTree.VerifyInclusionOfLeafHash(shortLeaf, 0, 2, new[] { sibling }, root, sha));

        // Control: the same shape with a proper leaf hash verifies.
        byte[] leaf = SHA256.HashData(Utf8("leaf"));
        Assert.True(MerkleTree.VerifyInclusionOfLeafHash(leaf, 0, 2, new[] { sibling }, MerkleTree.HashChildren(leaf, sibling, sha), sha));
    }

    [Fact]
    public void VerifyInclusionOfLeafHash_NegativeIndex_IsRejected()
    {
        ContentHashAlgorithm sha = ContentHashAlgorithm.Sha256;
        byte[] leaf = SHA256.HashData(Utf8("leaf"));
        byte[] sibling = SHA256.HashData(Utf8("sibling"));
        byte[] root = MerkleTree.HashChildren(sibling, leaf, sha);

        Assert.True(MerkleTree.VerifyInclusionOfLeafHash(leaf, 1, 2, new[] { sibling }, root, sha));
        Assert.False(MerkleTree.VerifyInclusionOfLeafHash(leaf, -1, 2, new[] { sibling }, root, sha));
    }

    [Fact]
    public void VerifyConsistency_NewSizeSmallerThanOldSize_IsRejected()
    {
        ContentHashAlgorithm sha = ContentHashAlgorithm.Sha256;
        byte[] oldRoot = SHA256.HashData(Utf8("old"));
        byte[] c = SHA256.HashData(Utf8("c"));
        byte[] newRoot = MerkleTree.HashChildren(oldRoot, c, sha);

        Assert.False(MerkleTree.VerifyConsistency(3, 2, oldRoot, newRoot, new[] { oldRoot, c }, sha));
    }

    // ---- refuted "equivalent" / "unkilled" survivors ---------------------------------------------------------

    /// <summary>An <see cref="IReadOnlyList{T}"/> that reports a fixed <see cref="Count"/> whatever it holds.</summary>
    private sealed class FixedCountList<T> : IReadOnlyList<T>
    {
        private readonly T[] _items;

        public FixedCountList(int count, params T[] items)
        {
            Count = count;
            _items = items;
        }

        public int Count { get; }

        public T this[int index] => _items[index];

        public IEnumerator<T> GetEnumerator() => ((IEnumerable<T>)_items).GetEnumerator();

        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
    }

    [Fact]
    public void VerifyInclusion_ProofCountLimit_IsInclusive()
    {
        // The length guard reads Count; the audit path itself is enumerated. A one-element proof that reports
        // exactly MaxProofLength elements passes the guard, one more does not.
        ContentHashAlgorithm sha = ContentHashAlgorithm.Sha256;
        MerkleTree tree = MerkleTree.Build(new[] { Utf8("a"), Utf8("b") });
        byte[] sibling = tree.GetInclusionProof(0)[0];

        Assert.True(MerkleTree.VerifyInclusion(Utf8("a"), 0, 2,
            new FixedCountList<byte[]>(MerkleTree.MaxProofLength, sibling), tree.Root, sha));
        Assert.False(MerkleTree.VerifyInclusion(Utf8("a"), 0, 2,
            new FixedCountList<byte[]>(MerkleTree.MaxProofLength + 1, sibling), tree.Root, sha));
    }

    private static (HashChainCheckpoint Anchor, HashChainEntry Last) EntryAtTheMaximumSequence()
    {
        byte[] anchorHash = SHA256.HashData(Utf8("anchor"));
        var anchor = new HashChainCheckpoint(long.MaxValue - 1, anchorHash);
        byte[] hash = HashChain.ComputeEntryHash(anchorHash, Utf8("a"), long.MaxValue);
        return (anchor, new HashChainEntry(long.MaxValue, anchorHash, Utf8("a"), hash));
    }

    [Fact]
    public void Verify_EntryAtTheMaximumSequence_IsValid()
    {
        (HashChainCheckpoint anchor, HashChainEntry last) = EntryAtTheMaximumSequence();

        HashChainVerificationResult result = HashChain.Verify(new[] { last }, ContentHashAlgorithm.Sha256, anchor, null);

        Assert.True(result.IsValid);
        Assert.Equal(1, result.EntriesVerified);
        Assert.Equal(long.MaxValue, result.Head!.Sequence);
    }

    [Fact]
    public void Verify_LowerSequenceAfterTheMaximumSequence_IsAReorderNotAGap()
    {
        // Without saturation the expected next sequence would wrap to long.MinValue, and every later entry would
        // look like it skipped ahead (a Gap from a negative sequence).
        (HashChainCheckpoint anchor, HashChainEntry last) = EntryAtTheMaximumSequence();
        byte[] nextHash = HashChain.ComputeEntryHash(last.Hash.ToArray(), Utf8("b"), 5);
        var next = new HashChainEntry(5, last.Hash.ToArray(), Utf8("b"), nextHash);

        HashChainVerificationResult result = HashChain.Verify(new[] { last, next }, ContentHashAlgorithm.Sha256, anchor, null);

        Assert.False(result.IsValid);
        Assert.Equal(HashChainFailure.Reorder, result.Failure);
        Assert.Equal(1, result.FirstBrokenIndex);
        Assert.Equal(5L, result.BrokenSequence);
        Assert.Equal(1, result.EntriesVerified);
    }

    [Fact] // Regression: anchor.Sequence + 1 used to wrap to long.MinValue.
    public void Verify_HeadAtAnAnchorAtTheMaximumSequenceWithAnotherHash_IsAHeadMismatch()
    {
        byte[] anchorHash = SHA256.HashData(Utf8("anchor"));
        var anchor = new HashChainCheckpoint(long.MaxValue, anchorHash);
        var head = new HashChainCheckpoint(long.MaxValue, Flip(anchorHash));

        HashChainVerificationResult result = HashChain.Verify(Array.Empty<HashChainEntry>(), ContentHashAlgorithm.Sha256, anchor, head);

        Assert.False(result.IsValid);
        Assert.Equal(HashChainFailure.HeadMismatch, result.Failure);
    }

    [Fact]
    public async Task CreateAsync_DirectoryFoundEmptyAtMaxDepth_IsNotWalkedWhenFilledLater()
    {
        if (!OperatingSystem.IsWindows())
            return; // Relies on NTFS returning names in order ("e" before "f.txt").

        using var dir = new TempDirectory();
        Directory.CreateDirectory(Path.Combine(dir.Path, "e"));
        dir.Write("f.txt", "f");
        var filtered = new List<string>();
        var options = new DirectoryManifestOptions
        {
            MaxDepth = 0,
            Filter = relative =>
            {
                filtered.Add(relative);
                if (relative == "f.txt")
                    dir.Write("e/x.txt", "x"); // "e" was already checked and found empty
                return true;
            },
        };

        DirectoryManifest manifest = await DirectoryManifest.CreateAsync(dir.Path, ContentHashAlgorithm.Sha256, options);

        Assert.Equal(new[] { "f.txt" }, manifest.Entries.Select(e => e.Path));
        Assert.Equal(new[] { "f.txt" }, filtered);
    }

    /// <summary>
    /// Lays out <c>a.txt</c> and a directory link <c>b</c> (to a directory holding <c>o.txt</c>). While the walk
    /// filters <c>a.txt</c>, after the root listing (with <c>b</c> marked as a reparse point) has been read, the
    /// filter replaces the link with a real directory holding <c>c.txt</c>. The walk then meets a <c>b</c> that is
    /// marked as a reparse point but is no longer a link: it has no link target and does not resolve.
    /// </summary>
    private static bool TryPrepareLinkReplacedDuringTheWalk(TempDirectory dir, TempDirectory outside, out Func<string, bool> filter)
    {
        filter = _ => true;
        if (!OperatingSystem.IsWindows())
            return false; // Relies on NTFS returning names in order ("a.txt" before "b").

        outside.Write("o.txt", "outside");
        dir.Write("a.txt", "a");
        string link = Path.Combine(dir.Path, "b");
        if (!TryLink(() => Directory.CreateSymbolicLink(link, outside.Path)))
            return false;

        bool replaced = false;
        filter = relative =>
        {
            if (relative == "a.txt" && !replaced)
            {
                replaced = true;
                Directory.Delete(link); // removes the link only
                dir.Write("b/c.txt", "c");
            }
            return true;
        };
        return true;
    }

    [Fact]
    public async Task CreateAsync_UnfollowedReparsePointWithoutALinkTarget_RecordsAnEmptyTarget()
    {
        using var dir = new TempDirectory();
        using var outside = new TempDirectory();
        if (!TryPrepareLinkReplacedDuringTheWalk(dir, outside, out Func<string, bool> filter))
            return;

        DirectoryManifest manifest = await DirectoryManifest.CreateAsync(dir.Path, ContentHashAlgorithm.Sha256,
            new DirectoryManifestOptions { Filter = filter });

        Assert.Equal(new[] { "a.txt", "b" }, manifest.Entries.Select(e => e.Path));
        DirectoryManifestEntry link = manifest.Entries[1];
        Assert.Equal(DirectoryManifestEntryKind.Link, link.Kind);
        Assert.Equal(0, link.Length);
        Assert.Equal(ContentHasher.Compute(Array.Empty<byte>()), link.Hash);
    }

    [Fact]
    public async Task CreateAsync_FollowedReparsePointThatIsNotALink_IsWalkedAsADirectory()
    {
        using var dir = new TempDirectory();
        using var outside = new TempDirectory();
        if (!TryPrepareLinkReplacedDuringTheWalk(dir, outside, out Func<string, bool> filter))
            return;

        DirectoryManifest manifest = await DirectoryManifest.CreateAsync(dir.Path, ContentHashAlgorithm.Sha256,
            new DirectoryManifestOptions { Filter = filter, FollowReparsePoints = true });

        Assert.Equal(new[] { "a.txt", "b/c.txt" }, manifest.Entries.Select(e => e.Path));
        Assert.All(manifest.Entries, e => Assert.Equal(DirectoryManifestEntryKind.File, e.Kind));
        Assert.Equal(ContentHasher.Compute(Utf8("c")), manifest.Entries[1].Hash);
    }
}
