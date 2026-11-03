using System;
using System.Text;
using Masterly.Hash.Legacy;
using static Masterly.Hash.Legacy.Tests.TestSupport;

namespace Masterly.Hash.Legacy.Tests;

public class BCryptFormatTests
{
    // OpenBSD / Openwall crypt_blowfish test vectors (crypt_blowfish wrapper.c "tests[]").
    // The jBCrypt / BCrypt.Net vectors below come from the jBCrypt TestBCrypt suite.
    public static TheoryData<string, string> KnownVectors => new()
    {
        { "U*U", "$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW" },
        { "U*U*", "$2a$05$CCCCCCCCCCCCCCCCCCCCC.VGOzA784oUp/Z0DY336zx7pLYAy0lwK" },
        { "U*U*U", "$2a$05$XXXXXXXXXXXXXXXXXXXXXOAcXxm9kjPGEMsLznoKqmqw7tc8WCx4a" },
        { "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789chars after 72 are ignored",
          "$2a$05$abcdefghijklmnopqrstuu5s2v8.iXieOjg/.AySBTTZIIVFJeBui" },
        { "a", "$2a$06$m0CrhHm10qJ3lXRY.5zDGO3rS2KdeeWLuGmsfGlMfOxih58VYVfxe" },
        { "abc", "$2a$06$If6bvum7DFjUnE9p2uDeDu0YHzrHM6tf.iqN8.yx.jNN1ILEf7h0i" },
        { "abcdefghijklmnopqrstuvwxyz", "$2a$06$.rCVZVOThsIa97pEDOxvGuRRgzG64bvtJ0938xuqzv18d3ZpQhstC" },
        { "~!@#$%^&*()      ~!@#$%^&*()PNBFRD", "$2a$06$fPIsBO8qRqkjj273rfaOI.HtSV9jLDpTbZn782DC6/t7qT67P6FfO" },
        // $2b$ and $2y$ compute the same function as $2a$ for these inputs (no 8-bit characters, < 256 bytes).
        { "U*U", "$2b$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW" },
        { "U*U", "$2y$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW" },
    };

    [Theory]
    [MemberData(nameof(KnownVectors))]
    public void Verifies_known_vectors(string password, string hash)
    {
        Assert.True(BCryptFormat.Default.CanHandle(hash));
        Assert.True(BCryptFormat.Default.Verify(password, hash));
        if (Encoding.UTF8.GetByteCount(password) < 72)
            Assert.False(BCryptFormat.Default.Verify(password + "x", hash));
        Assert.False(BCryptFormat.Default.Verify(password.Substring(1), hash));
    }

    [Theory]
    [MemberData(nameof(KnownVectors))]
    public void Hasher_verifies_and_upgrades(string password, string hash)
    {
        PasswordHasher hasher = Hasher(BCryptFormat.Default);
        PasswordVerificationResult result = hasher.Verify(password, hash);
        Assert.Equal(VerificationStatus.SuccessRehashNeeded, result.Status);
        Assert.Equal(RehashReason.LegacyFormat, result.RehashReason);
        Assert.StartsWith("$mh$p=test$", result.Rehash);
        Assert.Equal(VerificationStatus.Success, hasher.Verify(password, result.Rehash!).Status);
        Assert.Equal("bcrypt", hasher.Inspect(hash).Format);
    }

    [Fact]
    public void Truncates_at_72_bytes_as_documented()
    {
        // From the vector above: everything after byte 72 is ignored by bcrypt itself.
        const string hash = "$2a$05$abcdefghijklmnopqrstuu5s2v8.iXieOjg/.AySBTTZIIVFJeBui";
        string first72 = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        Assert.Equal(72, Encoding.UTF8.GetByteCount(first72));
        Assert.True(BCryptFormat.Default.Verify(first72, hash));
        Assert.True(BCryptFormat.Default.Verify(first72 + "anything else", hash));
        Assert.False(BCryptFormat.Default.Verify(first72.Substring(0, 71), hash));
    }

    [Fact]
    public void Round_trips_with_bcrypt_net_and_unicode()
    {
        const string password = "pässwörd \U0001F600";
        foreach (string variant in new[] { "$2a$", "$2b$" })
        {
            string salt = BCrypt.Net.BCrypt.GenerateSalt(4);
            string hash = BCrypt.Net.BCrypt.HashPassword(password, variant + salt.Substring(4));
            Assert.True(BCryptFormat.Default.Verify(password, hash));
            Assert.False(BCryptFormat.Default.Verify("passwörd \U0001F600", hash));
        }
    }

    [Theory]
    [InlineData("$2b$16$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW")]
    [InlineData("$2b$31$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW")]
    public void Rejects_cost_above_cap_without_hashing(string hash)
    {
        // At cost 31 a single verify would take days; refusing it must cost nothing.
        AssertQuick(() =>
        {
            Assert.False(BCryptFormat.Default.CanHandle(hash));
            Assert.False(BCryptFormat.Default.Verify("U*U", hash));
            Assert.False(BCryptFormat.Default.TryExtractWrapInput(hash, out _, out _));
            Assert.Equal(VerificationFailureReason.UnknownFormat, Hasher(BCryptFormat.Default).Verify("U*U", hash).FailureReason);
        });
    }

    [Fact]
    public void Custom_cap_is_honored()
    {
        var format = new BCryptFormat(5);
        Assert.Equal(5, format.MaxCost);
        Assert.True(format.CanHandle("$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW"));
        Assert.False(format.CanHandle("$2a$06$m0CrhHm10qJ3lXRY.5zDGO3rS2KdeeWLuGmsfGlMfOxih58VYVfxe"));
        Assert.Equal(BCryptFormat.DefaultMaxCost, BCryptFormat.Default.MaxCost);
        Assert.Throws<ArgumentOutOfRangeException>(() => new BCryptFormat(3));
        Assert.Throws<ArgumentOutOfRangeException>(() => new BCryptFormat(32));
    }

    [Theory]
    [InlineData("$2x$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW")] // sign-extension bug mode
    [InlineData("$2$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW")]
    [InlineData("$2a$03$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW")]  // cost below 4
    [InlineData("$2a$5$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeWW")]
    [InlineData("$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeX")]  // non-canonical last char
    [InlineData("$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOe")]   // too short
    [InlineData("$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeWW")] // too long
    [InlineData("$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyO+W")]  // outside alphabet
    [InlineData("$2A$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW")]
    [InlineData(" $2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW")]
    public void Rejects_malformed(string hash)
    {
        Assert.False(BCryptFormat.Default.CanHandle(hash));
        Assert.False(BCryptFormat.Default.Verify("U*U", hash));
        Assert.False(BCryptFormat.Default.TryExtractWrapInput(hash, out byte[] d, out byte[] p));
        Assert.Empty(d);
        Assert.Empty(p);
    }

    [Fact]
    public void Wrap_input_splits_prefix_and_digest()
    {
        const string hash = "$2b$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW";
        Assert.True(BCryptFormat.Default.TryExtractWrapInput(hash, out byte[] digest, out byte[] parameter));
        Assert.Equal("$2b$05$CCCCCCCCCCCCCCCCCCCCC.", Encoding.ASCII.GetString(parameter));
        Assert.Equal("E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW", Encoding.ASCII.GetString(digest));
        Assert.Equal(digest, BCryptFormat.Default.ComputeWrapInput("U*U", parameter));
        Assert.NotEqual(digest, BCryptFormat.Default.ComputeWrapInput("U*V", parameter));
    }

    [Theory]
    [InlineData("$2b$31$CCCCCCCCCCCCCCCCCCCCC.")]  // forged cost in a wrapped hash: must not run
    [InlineData("$2b$05$CCCCCCCCCCCCCCCCCCCC")]
    [InlineData("$2q$05$CCCCCCCCCCCCCCCCCCCCC.")]
    [InlineData("")]
    public void Compute_wrap_input_rejects_bad_parameters(string parameter)
    {
        AssertQuick(() => Assert.Throws<FormatException>(() => BCryptFormat.Default.ComputeWrapInput("U*U", Encoding.ASCII.GetBytes(parameter))));
        Assert.Throws<FormatException>(() => BCryptFormat.Default.ComputeWrapInput("U*U", new byte[] { 0x24, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }));
    }

    [Fact]
    public void Null_password_throws_but_null_hash_does_not()
    {
        Assert.Throws<ArgumentNullException>(() => BCryptFormat.Default.Verify(null!, "$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW"));
        Assert.False(BCryptFormat.Default.CanHandle(null!));
        Assert.False(BCryptFormat.Default.Verify("x", null!));
        Assert.Equal("bcrypt", BCryptFormat.Default.Id);
    }
}
