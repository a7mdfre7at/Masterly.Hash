using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading.Tasks;
using static Masterly.Hash.Integrity.Tests.TestUtil;

namespace Masterly.Hash.Integrity.Tests;

/// <summary>
/// Pins the exact text of the public argument exceptions (callers log and surface them), and the human-readable
/// reasons of chain verification failures past the maximum sequence.
/// </summary>
public class ArgumentMessageTests
{
    private sealed class CustomAlgorithm : ContentHashAlgorithm
    {
        public CustomAlgorithm(string name, int digestLength, string? keyId = null)
            : base(name, digestLength, keyId)
        {
        }

        public override ContentDigest CreateDigest() => Sha256.CreateDigest();
    }

    private static void AssertArgument(ArgumentException ex, string paramName, string message)
    {
        Assert.Equal(typeof(ArgumentException), ex.GetType());
        Assert.Equal(paramName, ex.ParamName);
        Assert.Equal(new ArgumentException(message, paramName).Message, ex.Message);
    }

    private static void AssertOutOfRange(ArgumentOutOfRangeException ex, string paramName, object actualValue, string message)
    {
        Assert.Equal(paramName, ex.ParamName);
        Assert.Equal(actualValue, ex.ActualValue);
        Assert.Equal(new ArgumentOutOfRangeException(paramName, actualValue, message).Message, ex.Message);
    }

    private static MemoryStream ClosedStream()
    {
        var stream = new MemoryStream(Utf8("x"));
        stream.Dispose();
        return stream;
    }

    // ---- ContentHash / ContentHashAlgorithm ----------------------------------------------------------------

    [Fact]
    public void ContentHash_WrongDigestLength_NamesLengthAndAlgorithm()
    {
        var ex = Assert.Throws<ArgumentException>(() => new ContentHash(ContentHashAlgorithm.Sha512, new byte[32]));

        AssertArgument(ex, "digest", "Digest must be 64 bytes for sha512.");
    }

    [Fact]
    public void Algorithm_InvalidName_HasAFixedMessage()
    {
        var ex = Assert.Throws<ArgumentException>(() => new CustomAlgorithm("Bad", 32));

        AssertArgument(ex, "name", "Algorithm name must match ^[a-z0-9][a-z0-9-]{0,31}$.");
    }

    [Fact]
    public void Algorithm_InvalidDigestLength_HasAFixedMessage()
    {
        var ex = Assert.Throws<ArgumentOutOfRangeException>(() => new CustomAlgorithm("custom-msg", 15));

        AssertOutOfRange(ex, "digestLength", 15, "Digest length must be between 16 and 128 bytes.");
    }

    [Fact]
    public void Algorithm_InvalidKeyId_HasAFixedMessage()
    {
        var ex = Assert.Throws<ArgumentException>(() => new CustomAlgorithm("custom-msg", 32, "bad id"));

        AssertArgument(ex, "keyId", "Key id must match ^[A-Za-z0-9-]{1,32}$.");
    }

    [Fact]
    public void HmacSha256_ShortKey_NamesTheMinimumLength()
    {
        var ex = Assert.Throws<ArgumentException>(() => ContentHashAlgorithm.HmacSha256("k1", new byte[31]));

        AssertArgument(ex, "key", "HMAC key must be at least 32 bytes.");
    }

    [Fact]
    public void RegisterKeyedFamily_InvalidName_HasAFixedMessage()
    {
        var ex = Assert.Throws<ArgumentException>(() => ContentHashAlgorithm.RegisterKeyedFamily("Not Valid", 32));

        AssertArgument(ex, "name", "Algorithm name must match ^[a-z0-9][a-z0-9-]{0,31}$.");
    }

    [Fact]
    public void RegisterKeyedFamily_InvalidDigestLength_HasAFixedMessage()
    {
        var ex = Assert.Throws<ArgumentOutOfRangeException>(() => ContentHashAlgorithm.RegisterKeyedFamily("never-registered-msg", 129));

        AssertOutOfRange(ex, "digestLength", 129, "Digest length must be between 16 and 128 bytes.");
    }

    // ---- ContentHasher ---------------------------------------------------------------------------------------

    [Fact]
    public void Compute_UnreadableStream_HasAFixedMessage()
    {
        var ex = Assert.Throws<ArgumentException>(() => ContentHasher.Compute(ClosedStream(), ContentHashAlgorithm.Sha256));

        AssertArgument(ex, "stream", "Stream must be readable.");
    }

    [Fact]
    public void ComputeAsync_UnreadableStream_HasAFixedMessage()
    {
        var ex = Assert.Throws<ArgumentException>(() => { _ = ContentHasher.ComputeAsync(ClosedStream(), ContentHashAlgorithm.Sha256); });

        AssertArgument(ex, "stream", "Stream must be readable.");
    }

    [Fact]
    public void VerifyAsync_UnreadableStream_HasAFixedMessage()
    {
        ContentHash hash = ContentHasher.Compute(Utf8("x"));

        var ex = Assert.Throws<ArgumentException>(() => { _ = ContentHasher.VerifyAsync(ClosedStream(), hash, null); });

        AssertArgument(ex, "stream", "Stream must be readable.");
    }

    // ---- DirectoryManifest -----------------------------------------------------------------------------------

    [Fact]
    public void FromEntries_NullEntry_HasAFixedMessage()
    {
        var ex = Assert.Throws<ArgumentException>(() => DirectoryManifest.FromEntries(new DirectoryManifestEntry[] { null! }, ContentHashAlgorithm.Sha256));

        AssertArgument(ex, "entries", "Entries cannot contain null.");
    }

    [Fact]
    public void FromEntries_EntryFromAnotherAlgorithm_NamesTheExpectedIdentifier()
    {
        var entry = new DirectoryManifestEntry("a.txt", 1, ContentHasher.Compute(Utf8("a")));

        var ex = Assert.Throws<ArgumentException>(() => DirectoryManifest.FromEntries(new[] { entry }, Hmac("k1")));

        AssertArgument(ex, "entries", "Every entry must be hashed with hmac-sha256:k1.");
    }

    [Fact]
    public void FromEntries_DuplicatePath_HasAFixedMessage()
    {
        var a = new DirectoryManifestEntry("a.txt", 1, ContentHasher.Compute(Utf8("a")));
        var b = new DirectoryManifestEntry("a.txt", 1, ContentHasher.Compute(Utf8("b")));

        var ex = Assert.Throws<ArgumentException>(() => DirectoryManifest.FromEntries(new[] { a, b }, ContentHashAlgorithm.Sha256));

        AssertArgument(ex, "entries", "Entries contain a duplicate path.");
    }

    [Fact]
    public void Entry_UnknownKind_HasAFixedMessage()
    {
        var kind = (DirectoryManifestEntryKind)99;

        var ex = Assert.Throws<ArgumentOutOfRangeException>(() => new DirectoryManifestEntry("a.txt", 1, ContentHasher.Compute(Utf8("a")), kind));

        AssertOutOfRange(ex, "kind", kind, "Unknown entry kind.");
    }

    [Fact]
    public void Entry_NonCanonicalPath_HasAFixedMessage()
    {
        var ex = Assert.Throws<ArgumentException>(() => new DirectoryManifestEntry("a\\b.txt", 1, ContentHasher.Compute(Utf8("a"))));

        AssertArgument(ex, "path", "Path must be a canonical relative path with '/' separators.");
    }

    [Fact]
    public void Entry_NegativeLength_HasAFixedMessage()
    {
        var ex = Assert.Throws<ArgumentOutOfRangeException>(() => new DirectoryManifestEntry("a.txt", -1, ContentHasher.Compute(Utf8("a"))));

        AssertOutOfRange(ex, "length", -1L, "Length cannot be negative.");
    }

    [Fact]
    public async Task CreateAsync_NegativeMaxDepth_HasAFixedMessage()
    {
        using var dir = new TempDirectory();

        var ex = await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() =>
            DirectoryManifest.CreateAsync(dir.Path, ContentHashAlgorithm.Sha256, new DirectoryManifestOptions { MaxDepth = -1 }));

        AssertOutOfRange(ex, "MaxDepth", -1, "MaxDepth cannot be negative.");
    }

    [Fact]
    public async Task CreateAsync_ZeroMaxEntries_HasAFixedMessage()
    {
        using var dir = new TempDirectory();

        var ex = await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() =>
            DirectoryManifest.CreateAsync(dir.Path, ContentHashAlgorithm.Sha256, new DirectoryManifestOptions { MaxEntries = 0 }));

        AssertOutOfRange(ex, "MaxEntries", 0, "MaxEntries must be positive.");
    }

    // ---- HashChain -------------------------------------------------------------------------------------------

    [Fact]
    public void ComputeEntryHash_NegativeSequence_HasAFixedMessage()
    {
        var ex = Assert.Throws<ArgumentOutOfRangeException>(() =>
            HashChain.ComputeEntryHash(new byte[32], Utf8("p"), -1, ContentHashAlgorithm.Sha256));

        AssertOutOfRange(ex, "sequence", -1L, "Sequence cannot be negative.");
    }

    [Fact]
    public void ComputeEntryHash_WrongPreviousHashLength_NamesLengthAndAlgorithm()
    {
        var ex = Assert.Throws<ArgumentException>(() =>
            HashChain.ComputeEntryHash(new byte[32], Utf8("p"), 0, ContentHashAlgorithm.Sha512));

        AssertArgument(ex, "previousHash", "Previous hash must be 64 bytes for sha512.");
    }

    [Fact]
    public void CreateNext_PreviousFromAnotherAlgorithm_HasAFixedMessage()
    {
        HashChainEntry previous = HashChain.CreateNext(null, Utf8("a"), ContentHashAlgorithm.Sha512);

        var ex = Assert.Throws<ArgumentException>(() => HashChain.CreateNext(previous, Utf8("b"), ContentHashAlgorithm.Sha256));

        AssertArgument(ex, "previous", "The previous entry was not produced by this algorithm.");
    }

    [Fact]
    public void Entry_NegativeSequence_HasAFixedMessage()
    {
        var ex = Assert.Throws<ArgumentOutOfRangeException>(() => new HashChainEntry(-1, new byte[32], Utf8("p"), new byte[32]));

        AssertOutOfRange(ex, "sequence", -1L, "Sequence cannot be negative.");
    }

    [Fact]
    public void Checkpoint_NegativeSequence_HasAFixedMessage()
    {
        var ex = Assert.Throws<ArgumentOutOfRangeException>(() => new HashChainCheckpoint(-1, new byte[32]));

        AssertOutOfRange(ex, "sequence", -1L, "Sequence cannot be negative.");
    }

    private static (HashChainCheckpoint Anchor, HashChainEntry Last) EntryAtTheMaximumSequence()
    {
        byte[] anchorHash = SHA256.HashData(Utf8("anchor"));
        var anchor = new HashChainCheckpoint(long.MaxValue - 1, anchorHash);
        byte[] hash = HashChain.ComputeEntryHash(anchorHash, Utf8("a"), long.MaxValue);
        return (anchor, new HashChainEntry(long.MaxValue, anchorHash, Utf8("a"), hash));
    }

    [Fact]
    public void Verify_DuplicateOfTheMaximumSequence_HasAFixedReason()
    {
        (HashChainCheckpoint anchor, HashChainEntry last) = EntryAtTheMaximumSequence();
        byte[] secondHash = HashChain.ComputeEntryHash(last.Hash.ToArray(), Utf8("b"), long.MaxValue);
        var second = new HashChainEntry(long.MaxValue, last.Hash.ToArray(), Utf8("b"), secondHash);

        HashChainVerificationResult result = HashChain.Verify(new[] { last, second }, ContentHashAlgorithm.Sha256, anchor, null);

        Assert.Equal(long.MaxValue, result.BrokenSequence);
        Assert.Equal("Sequence 9223372036854775807 appears twice.", result.Reason);
        Assert.Equal("Duplicate at index 1: Sequence 9223372036854775807 appears twice.", result.ToString());
    }

    [Fact]
    public void Verify_EntryAfterTheMaximumSequence_HasAFixedReason()
    {
        (HashChainCheckpoint anchor, HashChainEntry last) = EntryAtTheMaximumSequence();
        byte[] nextHash = HashChain.ComputeEntryHash(last.Hash.ToArray(), Utf8("b"), 5);
        var next = new HashChainEntry(5, last.Hash.ToArray(), Utf8("b"), nextHash);

        HashChainVerificationResult result = HashChain.Verify(new[] { last, next }, ContentHashAlgorithm.Sha256, anchor, null);

        Assert.Equal(HashChainFailure.Reorder, result.Failure);
        Assert.Equal(1, result.FirstBrokenIndex);
        Assert.Equal(1, result.EntriesVerified);
        Assert.Equal(5L, result.BrokenSequence);
        Assert.Equal("No entry can follow sequence 9223372036854775807, but found 5.", result.Reason);
        Assert.Equal("Reorder at index 1: No entry can follow sequence 9223372036854775807, but found 5.", result.ToString());
    }

    [Fact]
    public void Verify_EntryAfterAnAnchorAtTheMaximumSequence_HasAFixedReason()
    {
        byte[] anchorHash = SHA256.HashData(Utf8("anchor"));
        var anchor = new HashChainCheckpoint(long.MaxValue, anchorHash);
        var entry = new HashChainEntry(0, anchorHash, Utf8("a"), HashChain.ComputeEntryHash(anchorHash, Utf8("a"), 0));

        HashChainVerificationResult result = HashChain.Verify(new[] { entry }, ContentHashAlgorithm.Sha256, anchor, null);

        Assert.Equal(HashChainFailure.Reorder, result.Failure);
        Assert.Equal(0L, result.BrokenSequence);
        Assert.Equal("Reorder at index 0: No entry can follow sequence 9223372036854775807, but found 0.", result.ToString());
    }

    [Fact]
    public void Verify_NullEntryAfterTheMaximumSequence_IsAnInvalidEntry()
    {
        (HashChainCheckpoint anchor, HashChainEntry last) = EntryAtTheMaximumSequence();

        HashChainVerificationResult result = HashChain.Verify(new[] { last, null! }, ContentHashAlgorithm.Sha256, anchor, null);

        Assert.False(result.IsValid);
        Assert.Equal(HashChainFailure.InvalidEntry, result.Failure);
        Assert.Equal(1, result.FirstBrokenIndex);
        Assert.Equal(1, result.EntriesVerified);
        Assert.Equal("InvalidEntry at index 1: Entry is null.", result.ToString());
    }

    [Fact] // Regression: BrokenSequence wrapped to long.MinValue after an entry at long.MaxValue.
    public void Verify_NullEntryAfterTheMaximumSequence_ReportsANonNegativeSequence()
    {
        (HashChainCheckpoint anchor, HashChainEntry last) = EntryAtTheMaximumSequence();

        HashChainVerificationResult result = HashChain.Verify(new[] { last, null! }, ContentHashAlgorithm.Sha256, anchor, null);

        Assert.Equal(HashChainFailure.InvalidEntry, result.Failure);
        Assert.InRange(result.BrokenSequence!.Value, 0, long.MaxValue);
    }

    [Fact] // Regression: BrokenSequence wrapped to long.MinValue after an anchor at long.MaxValue.
    public void Verify_NullEntryAfterAnAnchorAtTheMaximumSequence_ReportsANonNegativeSequence()
    {
        var anchor = new HashChainCheckpoint(long.MaxValue, SHA256.HashData(Utf8("anchor")));

        HashChainVerificationResult result = HashChain.Verify(new HashChainEntry[] { null! }, ContentHashAlgorithm.Sha256, anchor, null);

        Assert.Equal(HashChainFailure.InvalidEntry, result.Failure);
        Assert.InRange(result.BrokenSequence!.Value, 0, long.MaxValue);
    }

    // ---- MerkleTree ------------------------------------------------------------------------------------------

    [Fact]
    public void Build_NullLeaf_HasAFixedMessage()
    {
        var ex = Assert.Throws<ArgumentException>(() => MerkleTree.Build(new[] { Utf8("a"), null! }, ContentHashAlgorithm.Sha256));

        AssertArgument(ex, "leaves", "Leaves cannot contain null.");
    }

    [Fact]
    public void FromLeafHashes_WrongLength_NamesTheDigestLength()
    {
        var ex = Assert.Throws<ArgumentException>(() => MerkleTree.FromLeafHashes(new[] { new byte[32] }, ContentHashAlgorithm.Sha512));

        AssertArgument(ex, "leafHashes", "Every leaf hash must be 64 bytes.");
    }
}
