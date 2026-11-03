using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Masterly.Hash.Integrity.Blake3.Tests;

public class Blake3Tests
{
    // Official BLAKE3 test vectors: github.com/BLAKE3-team/BLAKE3, test_vectors/test_vectors.json.
    // Input of length n is the repeating byte sequence 0, 1, ..., 250, 0, 1, ...; first 32 bytes of each output.
    private static readonly byte[] VectorKey = Encoding.ASCII.GetBytes("whats the Elvish word for friend");

    [Theory]
    [InlineData(0, "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262", "92b2b75604ed3c761f9d6f62392c8a9227ad0ea3f09573e783f1498a4ed60d26")]
    [InlineData(1, "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213", "6d7878dfff2f485635d39013278ae14f1454b8c0a3a2d34bc1ab38228a80c95b")]
    [InlineData(1023, "10108970eeda3eb932baac1428c7a2163b0e924c9a9e25b35bba72b28f70bd11", "c951ecdf03288d0fcc96ee3413563d8a6d3589547f2c2fb36d9786470f1b9d6e")]
    [InlineData(1024, "42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7", "75c46f6f3d9eb4f55ecaaee480db732e6c2105546f1e675003687c31719c7ba4")]
    [InlineData(1025, "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444", "357dc55de0c7e382c900fd6e320acc04146be01db6a8ce7210b7189bd664ea69")]
    [InlineData(8192, "aae792484c8efe4f19e2ca7d371d8c467ffb10748d8a5a1ae579948f718a2a63", "dc9637c8845a770b4cbf76b8daec0eebf7dc2eac11498517f08d44c8fc00d58a")]
    [InlineData(102400, "bc3e3d41a1146b069abffad3c0d44860cf664390afce4d9661f7902e7943e085", "1c35d1a5811083fd7119f5d5d1ba027b4d01c0c6c49fb6ff2cf75393ea5db4a7")]
    public async Task OfficialVectors(int length, string hash, string keyedHash)
    {
        byte[] input = Enumerable.Range(0, length).Select(i => (byte)(i % 251)).ToArray();

        Assert.Equal("blake3:" + hash, ContentHasher.Compute(input, Blake3Algorithms.Blake3).ToString());
        Assert.Equal("blake3:" + hash, (await ContentHasher.ComputeAsync(new MemoryStream(input), Blake3Algorithms.Blake3)).ToString());

        var mac = Blake3Algorithms.Keyed("vec", VectorKey);
        Assert.Equal("blake3-keyed:vec:" + keyedHash, ContentHasher.Compute(input, mac).ToString());
    }

    [Fact]
    public void Register_MakesStringsParse_AndResolvesForVerification()
    {
        Blake3Algorithms.Register();
        Blake3Algorithms.Register();
        Assert.True(ContentHashAlgorithm.TryGet("blake3", out ContentHashAlgorithm? algorithm));
        Assert.Same(Blake3Algorithms.Blake3, algorithm);
        Assert.True(ContentHashAlgorithm.IsRegistered("blake3-keyed"));

        ContentHash parsed = ContentHash.Parse("blake3:af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262");
        Assert.True(ContentHasher.Verify(Array.Empty<byte>(), parsed));
        Assert.False(ContentHasher.Verify(new byte[] { 0 }, parsed));
        Assert.True(ContentHash.TryParse("blake3-keyed:k1:" + new string('0', 64), out _));
        Assert.False(ContentHash.TryParse("blake3:" + new string('0', 62), out _));
    }

    [Fact]
    public void Keyed_ValidatesKey_AndDiffersByKey()
    {
        Assert.Throws<ArgumentException>(() => Blake3Algorithms.Keyed("k", new byte[31]));
        Assert.Throws<ArgumentException>(() => Blake3Algorithms.Keyed("k", new byte[33]));
        Assert.Throws<ArgumentNullException>(() => Blake3Algorithms.Keyed("k", null!));
        Assert.Throws<ArgumentNullException>(() => Blake3Algorithms.Keyed(null!, new byte[32]));
        Assert.Throws<ArgumentException>(() => Blake3Algorithms.Keyed("bad id", new byte[32]));

        byte[] key = (byte[])VectorKey.Clone();
        var mac = Blake3Algorithms.Keyed("k", key);
        ContentHash before = ContentHasher.Compute(new byte[] { 1 }, mac);
        key[0] ^= 1;
        Assert.Equal(before, ContentHasher.Compute(new byte[] { 1 }, mac));
        Assert.NotEqual(before, ContentHasher.Compute(new byte[] { 1 }, Blake3Algorithms.Keyed("k", key)));
        Assert.Equal("blake3-keyed:k", mac.ToString());
        Assert.False(ContentHasher.Verify(new byte[] { 1 }, before)); // keyed hash, no key given
        Assert.True(ContentHasher.Verify(new byte[] { 1 }, before, mac));
    }

    [Fact]
    public void Digest_IsReusableAfterReset()
    {
        using ContentDigest digest = Blake3Algorithms.Blake3.CreateDigest();
        digest.Append(Encoding.ASCII.GetBytes("BLAKE3"));
        // Example from the Blake3 package README.
        Assert.Equal("f890484173e516bfd935ef3d22b912dc9738de38743993cfedf2c9473b3216a4", Convert.ToHexString(digest.GetHashAndReset()).ToLowerInvariant());
        Assert.Equal("af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262", Convert.ToHexString(digest.GetHashAndReset()).ToLowerInvariant());
    }

    [Fact]
    public void WorksWithMerkleTreesAndHashChains()
    {
        byte[][] leaves = Enumerable.Range(0, 9).Select(i => new[] { (byte)i }).ToArray();
        MerkleTree tree = MerkleTree.Build(leaves, Blake3Algorithms.Blake3);
        Assert.True(MerkleTree.VerifyInclusion(leaves[4], 4, 9, tree.GetInclusionProof(4), tree.Root, Blake3Algorithms.Blake3));
        Assert.True(MerkleTree.VerifyConsistency(3, 9, tree.GetRoot(3), tree.Root, tree.GetConsistencyProof(3), Blake3Algorithms.Blake3));

        var log = new HashChainLog(Blake3Algorithms.Keyed("audit", VectorKey));
        for (int i = 0; i < 10; i++)
            log.Append(new[] { (byte)i });
        Assert.True(log.Verify().IsValid);
        Assert.False(HashChain.Verify(log.Entries, Blake3Algorithms.Keyed("audit", new byte[32])).IsValid);
    }

    [Fact]
    public void ManifestJson_RoundTripsBlake3()
    {
        DirectoryManifest manifest = DirectoryManifest.FromEntries(new[]
        {
            new DirectoryManifestEntry("a.txt", 1, ContentHasher.Compute(new byte[] { 65 }, Blake3Algorithms.Blake3)),
        }, Blake3Algorithms.Blake3);
        DirectoryManifest parsed = DirectoryManifest.FromJson(manifest.ToJson());
        Assert.Equal("blake3", parsed.Algorithm);
        Assert.True(parsed.IsIntact());
    }
}
