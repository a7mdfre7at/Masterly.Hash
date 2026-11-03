using System;
using System.Collections.Generic;
using System.Linq;
using Masterly.Hash.Internal;
using Masterly.Hash.Primitives;

namespace Masterly.Hash.UnitTests;

/// <summary>
/// Conformance of the in-house Argon2 (RFC 9106) and BLAKE2b (RFC 7693): the published vectors, and a seeded
/// differential test against Konscious.Security.Cryptography.Argon2, which the core shipped with before.
/// </summary>
public class Argon2CoreTests
{
    private static readonly byte[] RfcPassword = Enumerable.Repeat((byte)0x01, 32).ToArray();
    private static readonly byte[] RfcSalt = Enumerable.Repeat((byte)0x02, 16).ToArray();
    private static readonly byte[] RfcSecret = Enumerable.Repeat((byte)0x03, 8).ToArray();
    private static readonly byte[] RfcAssociatedData = Enumerable.Repeat((byte)0x04, 12).ToArray();

    // RFC 9106 type y: 0 = Argon2d, 1 = Argon2i, 2 = Argon2id. Argon2Type is internal, so the theory takes the number.
    [Theory]
    [InlineData(0, "512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb")]
    [InlineData(1, "c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8")]
    [InlineData(2, "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659")]
    public void Derive_Rfc9106Section5Vector_ProducesPublishedTag(int type, string expectedHex)
    {
        byte[] tag = Argon2Core.Derive((Argon2Type)type, RfcPassword, RfcSalt, RfcSecret, RfcAssociatedData, 32, 3, 4, 32);

        Assert.Equal(expectedHex, Convert.ToHexString(tag).ToLowerInvariant());
    }

    [Fact]
    public void Blake2b_Rfc7693AppendixAVector_ProducesPublishedDigest()
    {
        byte[] digest = new byte[64];

        Blake2b.Hash("abc"u8, digest);

        Assert.Equal(
            "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1" +
            "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923",
            Convert.ToHexString(digest).ToLowerInvariant());
    }

    [Fact]
    public void Blake2b_InputSpanningSeveralBlocksInPieces_MatchesOneShot()
    {
        byte[] input = Enumerable.Range(0, 1000).Select(i => (byte)(i * 7)).ToArray();
        byte[] oneShot = new byte[48];
        byte[] pieces = new byte[48];
        Blake2b.Hash(input, oneShot);

        Blake2b blake = new Blake2b(48);
        blake.Update(input.AsSpan(0, 128));
        blake.Update(input.AsSpan(128, 1));
        blake.Update(input.AsSpan(129, 255));
        blake.Update(input.AsSpan(384));
        blake.Final(pieces);

        Assert.Equal(oneShot, pieces);
    }

    [Theory]
    [InlineData(4)]
    [InlineData(64)]
    [InlineData(65)]
    [InlineData(96)]
    [InlineData(97)]
    [InlineData(1024)]
    public void Argon2_TagLengthAroundTheHPrimeBoundaries_MatchesKonscious(int tagLength)
    {
        byte[] salt = Enumerable.Repeat((byte)9, 16).ToArray();

        byte[] actual = HashPrimitives.Argon2(Argon2Variant.Argon2id, "pw"u8.ToArray(), salt, 64, 1, 1, tagLength);

        Assert.Equal(Konscious(Argon2Variant.Argon2id, "pw"u8.ToArray(), salt, 64, 1, 1, tagLength), actual);
    }

    public static IEnumerable<object[]> DifferentialCases()
    {
        Random random = new Random(20261103);
        Argon2Variant[] variants = { Argon2Variant.Argon2d, Argon2Variant.Argon2i, Argon2Variant.Argon2id };
        for (int i = 0; i < 240; i++)
        {
            Argon2Variant variant = variants[i % 3];
            int parallelism = random.Next(1, 9);
            int memoryKiB = random.Next(8 * parallelism, (8 * parallelism) + 600);
            int iterations = random.Next(1, 4);
            int tagLength = random.Next(4, 160);
            // Konscious rejects an empty password, which RFC 9106 allows; empty passwords are checked against the C reference.
            byte[] password = new byte[random.Next(1, 80)];
            byte[] salt = new byte[random.Next(8, 48)];
            random.NextBytes(password);
            random.NextBytes(salt);
            yield return new object[] { i, variant, Convert.ToHexString(password), Convert.ToHexString(salt), memoryKiB, iterations, parallelism, tagLength };
        }
    }

    [Theory]
    [MemberData(nameof(DifferentialCases))]
    public void Argon2_SeededParameters_MatchKonscious(
        int caseNumber, Argon2Variant variant, string passwordHex, string saltHex, int memoryKiB, int iterations, int parallelism, int tagLength)
    {
        byte[] password = Convert.FromHexString(passwordHex);
        byte[] salt = Convert.FromHexString(saltHex);

        byte[] actual = HashPrimitives.Argon2(variant, password, salt, memoryKiB, iterations, parallelism, tagLength);

        Assert.True(caseNumber >= 0);
        Assert.Equal(Konscious(variant, password, salt, memoryKiB, iterations, parallelism, tagLength), actual);
    }

    [Fact]
    public void DeriveKey_DefaultProfile_MatchesKonsciousArgon2id()
    {
        HashProfile profile = HashProfile.Server2026a;
        byte[] input = "correct horse battery staple"u8.ToArray();
        byte[] salt = Enumerable.Range(0, 16).Select(i => (byte)i).ToArray();

        byte[] actual = HashPrimitives.DeriveKey(profile, input, salt);

        Assert.Equal(Konscious(Argon2Variant.Argon2id, input, salt, profile.MemoryKiB, profile.Iterations, profile.Parallelism, profile.TagLength), actual);
    }

    [Theory]
    [InlineData(-1, 16, 64, 1, 1, 32, "variant")]
    [InlineData(2, 7, 64, 1, 1, 32, "salt")]
    [InlineData(2, 16, 15, 1, 2, 32, "memoryKiB")]
    [InlineData(2, 16, 64, 0, 1, 32, "iterations")]
    [InlineData(2, 16, 64, 65, 1, 32, "iterations")]
    [InlineData(2, 16, 64, 1, 0, 32, "parallelism")]
    [InlineData(2, 16, 1024, 1, 17, 32, "parallelism")]
    [InlineData(2, 16, 64, 1, 1, 3, "tagLength")]
    [InlineData(2, 16, 64, 1, 1, 1025, "tagLength")]
    public void Argon2_ParameterOutOfRange_Throws(int variant, int saltLength, int memoryKiB, int iterations, int parallelism, int tagLength, string parameter)
    {
        ArgumentException exception = Assert.ThrowsAny<ArgumentException>(() =>
            HashPrimitives.Argon2((Argon2Variant)variant, new byte[1], new byte[saltLength], memoryKiB, iterations, parallelism, tagLength));

        Assert.Equal(parameter, exception.ParamName);
    }

    [Fact]
    public void Argon2_MemoryAboveTheProfileCap_Throws()
    {
        ArgumentOutOfRangeException exception = Assert.Throws<ArgumentOutOfRangeException>(() =>
            HashPrimitives.Argon2(Argon2Variant.Argon2id, new byte[1], new byte[16], HashProfile.MaxMemoryKiB + 1, 1, 1, 32));

        Assert.Equal("memoryKiB", exception.ParamName);
    }

    private static byte[] Konscious(Argon2Variant variant, byte[] password, byte[] salt, int memoryKiB, int iterations, int parallelism, int tagLength)
    {
        using Konscious.Security.Cryptography.Argon2 argon2 = variant switch
        {
            Argon2Variant.Argon2d => new Konscious.Security.Cryptography.Argon2d(password),
            Argon2Variant.Argon2i => new Konscious.Security.Cryptography.Argon2i(password),
            _ => new Konscious.Security.Cryptography.Argon2id(password),
        };
        argon2.Salt = salt;
        argon2.MemorySize = memoryKiB;
        argon2.Iterations = iterations;
        argon2.DegreeOfParallelism = parallelism;
        return argon2.GetBytes(tagLength);
    }
}
