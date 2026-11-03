using System;
using Masterly.Hash.Legacy;
using static Masterly.Hash.Legacy.Tests.TestSupport;

namespace Masterly.Hash.Legacy.Tests;

public class UnsaltedDigestFormatTests
{
    // "abc" vectors: RFC 1321 appendix A.5 (MD5), FIPS 180-2 appendices A/B/C (SHA-1, SHA-256, SHA-512).
    // "password" digests are the widely published values (e.g. the RockYou/LinkedIn breach corpora).
    public static TheoryData<string, string, string> KnownVectors => new()
    {
        { "md5", "abc", "900150983cd24fb0d6963f7d28e17f72" },
        { "md5", "message digest", "f96b697d7cb7938d525a2f31aaf161d0" },
        { "md5", "password", "5f4dcc3b5aa765d61d8327deb882cf99" },
        { "sha1", "abc", "a9993e364706816aba3e25717850c26c9cd0d89d" },
        { "sha1", "password", "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8" },
        { "sha256", "abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" },
        { "sha256", "password", "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8" },
        { "sha512", "abc", "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f" },
        { "sha512", "password", "b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86" },
    };

    [Theory]
    [MemberData(nameof(KnownVectors))]
    public void Verifies_known_vectors_in_either_case(string id, string password, string hex)
    {
        ILegacyHashFormat format = Format(id);
        foreach (string hash in new[] { hex, Upper(hex) })
        {
            Assert.True(format.CanHandle(hash));
            Assert.True(format.Verify(password, hash));
            Assert.False(format.Verify(password + "1", hash));
        }
    }

    [Theory]
    [MemberData(nameof(KnownVectors))]
    public void Length_decides_the_algorithm(string id, string password, string hex)
    {
        _ = password;
        foreach (UnsaltedDigestFormat other in new[] { UnsaltedDigestFormat.Md5, UnsaltedDigestFormat.Sha1, UnsaltedDigestFormat.Sha256, UnsaltedDigestFormat.Sha512 })
            Assert.Equal(other.Id == id, other.CanHandle(hex));
        Assert.Equal(id, AllFormats().Inspect(hex).Format);
    }

    [Theory]
    [MemberData(nameof(KnownVectors))]
    public void Hasher_upgrades_on_login(string id, string password, string hex)
    {
        PasswordHasher hasher = Hasher(Format(id));
        PasswordVerificationResult result = hasher.Verify(password, hex);
        Assert.Equal(VerificationStatus.SuccessRehashNeeded, result.Status);
        Assert.Equal(VerificationStatus.Success, hasher.Verify(password, result.Rehash!).Status);
    }

    [Fact]
    public void Properties()
    {
        Assert.Equal(16, UnsaltedDigestFormat.Md5.DigestLength);
        Assert.Equal(20, UnsaltedDigestFormat.Sha1.DigestLength);
        Assert.Equal(32, UnsaltedDigestFormat.Sha256.DigestLength);
        Assert.Equal(64, UnsaltedDigestFormat.Sha512.DigestLength);
        Assert.Equal("sha256", UnsaltedDigestFormat.Sha256.ToString());
    }

    [Theory]
    [InlineData("5f4dcc3b5aa765d61d8327deb882cf9")]
    [InlineData("5f4dcc3b5aa765d61d8327deb882cf990")]
    [InlineData("5f4dcc3b5aa765d61d8327deb882cf9g")]
    [InlineData(" 5f4dcc3b5aa765d61d8327deb882cf99")]
    [InlineData("5f4dcc3b5aa765d61d8327deb882cf99\n")]
    [InlineData("0x5f4dcc3b5aa765d61d8327deb882cf")]
    public void Md5_rejects_malformed(string hash)
    {
        Assert.False(UnsaltedDigestFormat.Md5.CanHandle(hash));
        Assert.False(UnsaltedDigestFormat.Md5.Verify("password", hash));
        Assert.False(UnsaltedDigestFormat.Md5.TryExtractWrapInput(hash, out _, out _));
    }

    [Fact]
    public void Wrap_input_is_digest_with_empty_parameter()
    {
        Assert.True(UnsaltedDigestFormat.Md5.TryExtractWrapInput("5F4DCC3B5AA765D61D8327DEB882CF99", out byte[] digest, out byte[] parameter));
        Assert.Empty(parameter);
        Assert.Equal("5f4dcc3b5aa765d61d8327deb882cf99", Hex(digest));
        Assert.Equal(digest, UnsaltedDigestFormat.Md5.ComputeWrapInput("password", Array.Empty<byte>()));
        Assert.Throws<FormatException>(() => UnsaltedDigestFormat.Md5.ComputeWrapInput("password", new byte[1]));
    }
}
