using System;
using System.Collections.Generic;
using Masterly.Hash.Internal;
using Masterly.Hash.Pepper;
using Masterly.Hash.Primitives;

namespace Masterly.Hash.UnitTests;

/// <summary>
/// Profile, format and pepper key ids must match their rule in full. A <c>^...$</c> regex accepts a trailing newline in
/// .NET (<c>$</c> matches before a final <c>\n</c>), which let ids like <c>"k1\n"</c> through every check.
/// </summary>
public class IdentifierTests
{
    [Theory]
    [InlineData("\n")]
    [InlineData("\r\n")]
    [InlineData("\r")]
    [InlineData(" ")]
    public void Ids_with_a_trailing_line_break_or_space_are_invalid(string suffix)
    {
        Assert.False(HashPrimitives.IsValidProfileId("2026a" + suffix));
        Assert.False(HashPrimitives.IsValidFormatId("v1" + suffix));
        Assert.False(HashPrimitives.IsValidKeyId("k1" + suffix));
    }

    [Theory]
    [InlineData("a", true)]
    [InlineData("0", true)]
    [InlineData("a-", true)]
    [InlineData("2026a", true)]
    [InlineData("-a", false)]
    [InlineData("A", false)]
    [InlineData("a_b", false)]
    [InlineData("", false)]
    [InlineData("abcdefghijklmnopqrstuvwxyz012345", true)]   // 32 characters
    [InlineData("abcdefghijklmnopqrstuvwxyz0123456", false)] // 33 characters
    public void Profile_and_format_ids_follow_the_lowercase_rule(string id, bool valid)
    {
        Assert.Equal(valid, HashPrimitives.IsValidProfileId(id));
        Assert.Equal(valid, HashPrimitives.IsValidFormatId(id));
        Assert.Equal(valid, Identifiers.IsValidLowercaseId(id));
    }

    [Theory]
    [InlineData("k", true)]
    [InlineData("K-1", true)]
    [InlineData("-", true)]
    [InlineData("Key-2026", true)]
    [InlineData("k_1", false)]
    [InlineData("k.1", false)]
    [InlineData("", false)]
    [InlineData("ABCDEFGHIJKLMNOPQRSTUVWXYZ012345", true)]   // 32 characters
    [InlineData("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456", false)] // 33 characters
    public void Key_ids_follow_the_key_rule(string id, bool valid)
    {
        Assert.Equal(valid, HashPrimitives.IsValidKeyId(id));
        Assert.Equal(valid, Identifiers.IsValidKeyId(id));
    }

    [Fact]
    public void Null_ids_are_invalid()
    {
        Assert.False(Identifiers.IsValidLowercaseId(null));
        Assert.False(Identifiers.IsValidKeyId(null));
        Assert.False(HashPrimitives.IsValidProfileId(null!));
        Assert.False(HashPrimitives.IsValidKeyId(null!));
        Assert.False(HashPrimitives.IsValidFormatId(null!));
    }

    [Fact]
    public void A_profile_id_with_a_trailing_newline_is_rejected()
    {
        var ex = Assert.Throws<ArgumentException>(() => HashProfile.Argon2id("custom\n", 19456, 2));
        Assert.Equal("id", ex.ParamName);
        Assert.Throws<ArgumentException>(() => HashProfile.Pbkdf2Sha512("custom\n", 210_000));
    }

    [Fact]
    public void A_pepper_key_id_with_a_trailing_newline_is_rejected()
    {
        byte[] key = new byte[32];
        Assert.Throws<ArgumentException>(() => new HmacPepper("k1\n", new Dictionary<string, byte[]> { ["k1\n"] = key }));
        Assert.Throws<ArgumentException>(() => new HmacPepper("k1", new Dictionary<string, byte[]> { ["k1"] = key, ["k2\n"] = key }));
    }

    [Fact]
    public void A_stored_hash_with_a_newline_after_an_id_is_malformed()
    {
        // Real hashes, so only the inserted newline is wrong. Before the fix these parsed and then failed as an unknown
        // profile or key: the format accepted a second string form of an id.
        PasswordHasher hasher = TestHashers.Create(o => o.Pepper = TestHashers.Pepper("k1", "k1"));
        string peppered = hasher.Hash("pw");
        Assert.StartsWith("$mh$p=test-fast,k=k1$", peppered);

        foreach (string stored in new[]
        {
            peppered.Replace("p=test-fast,", "p=test-fast\n,"),
            peppered.Replace("k=k1$", "k=k1\n$"),
        })
        {
            Assert.False(MhHash.TryParse(stored, out MhHash? parsed));
            Assert.Null(parsed);
            Assert.Equal(VerificationFailureReason.MalformedHash, hasher.Verify("pw", stored).FailureReason);
        }
    }
}
