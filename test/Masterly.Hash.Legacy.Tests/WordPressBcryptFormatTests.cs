using System;
using System.Security.Cryptography;
using System.Text;
using Masterly.Hash.Legacy;
using static Masterly.Hash.Legacy.Tests.TestSupport;

namespace Masterly.Hash.Legacy.Tests;

public class WordPressBcryptFormatTests
{
    private const string Salt = "$2y$05$CCCCCCCCCCCCCCCCCCCCC.";

    /// <summary>
    /// Reference construction from WordPress 6.8 wp-includes/pluggable.php (wp_hash_password / wp_check_password):
    /// '$wp' . password_hash(base64_encode(hash_hmac('sha384', $password, 'wp-sha384', true)), PASSWORD_BCRYPT).
    /// Built here independently of the format, with the BCL HMAC and BCrypt.Net.
    /// </summary>
    internal static string WordPressHash(string password, string salt = Salt)
    {
        using var hmac = new HMACSHA384(Encoding.ASCII.GetBytes("wp-sha384"));
        string preHash = Convert.ToBase64String(hmac.ComputeHash(Encoding.UTF8.GetBytes(password)));
        return "$wp" + BCrypt.Net.BCrypt.HashPassword(preHash, salt);
    }

    [Theory]
    [InlineData("password")]
    [InlineData("hunter2 é")]
    [InlineData("")]
    public void Verifies_reference_construction(string password)
    {
        string hash = WordPressHash(password);
        Assert.Equal(63, hash.Length);
        Assert.StartsWith("$wp$2y$05$", hash);
        Assert.True(WordPressBcryptFormat.Default.CanHandle(hash));
        Assert.True(WordPressBcryptFormat.Default.Verify(password, hash));
        Assert.False(WordPressBcryptFormat.Default.Verify(password + "x", hash));
        Assert.False(WordPressBcryptFormat.Default.Verify(" " + password, hash)); // wp_check_password does not trim
    }

    [Fact]
    public void Verifies_default_wordpress_cost_10()
    {
        string hash = WordPressHash("correct horse", "$2y$10$abcdefghijklmnopqrstuu");
        Assert.True(WordPressBcryptFormat.Default.Verify("correct horse", hash));
    }

    [Fact]
    public void Pre_hash_means_bytes_after_72_count()
    {
        string longPassword = new string('a', 100);
        string hash = WordPressHash(longPassword);
        Assert.True(WordPressBcryptFormat.Default.Verify(longPassword, hash));
        Assert.False(WordPressBcryptFormat.Default.Verify(longPassword.Substring(0, 72), hash));
        Assert.False(WordPressBcryptFormat.Default.Verify(longPassword.Substring(0, 99) + "b", hash));
    }

    [Fact]
    public void Is_not_plain_bcrypt_and_not_claimed_by_bcrypt()
    {
        // $wp + bcrypt(raw password) is not a WordPress hash: the pre-hash must be applied.
        string raw = "$wp" + BCrypt.Net.BCrypt.HashPassword("password", Salt);
        Assert.True(WordPressBcryptFormat.Default.CanHandle(raw));
        Assert.False(WordPressBcryptFormat.Default.Verify("password", raw));

        string hash = WordPressHash("password");
        Assert.False(BCryptFormat.Default.CanHandle(hash));
        Assert.False(WordPressBcryptFormat.Default.CanHandle(hash.Substring(3)));
    }

    [Fact]
    public void Hasher_upgrades_on_login()
    {
        string hash = WordPressHash("password");
        PasswordHasher hasher = AllFormats();
        Assert.Equal("wordpress-bcrypt", hasher.Inspect(hash).Format);
        PasswordVerificationResult result = hasher.Verify("password", hash);
        Assert.Equal(VerificationStatus.SuccessRehashNeeded, result.Status);
        Assert.Equal(VerificationStatus.Success, hasher.Verify("password", result.Rehash!).Status);
        Assert.Equal(VerificationFailureReason.Mismatch, hasher.Verify("Password", hash).FailureReason);
    }

    [Fact]
    public void Rejects_cost_above_cap_without_hashing()
    {
        string hash = "$wp$2y$31$" + WordPressHash("password").Substring(10);
        AssertQuick(() =>
        {
            Assert.False(WordPressBcryptFormat.Default.CanHandle(hash));
            Assert.False(WordPressBcryptFormat.Default.Verify("password", hash));
            Assert.Equal(VerificationFailureReason.UnknownFormat, Hasher(WordPressBcryptFormat.Default).Verify("password", hash).FailureReason);
            Assert.Throws<FormatException>(() => WordPressBcryptFormat.Default.ComputeWrapInput("password", Encoding.ASCII.GetBytes("$2y$31$CCCCCCCCCCCCCCCCCCCCC.")));
        });

        Assert.Equal(15, WordPressBcryptFormat.Default.MaxCost);
        Assert.False(new WordPressBcryptFormat(4).CanHandle(WordPressHash("password")));
        Assert.Throws<ArgumentOutOfRangeException>(() => new WordPressBcryptFormat(3));
        Assert.Throws<ArgumentOutOfRangeException>(() => new WordPressBcryptFormat(32));
    }

    [Fact]
    public void Rejects_passwords_over_4096_bytes_like_wordpress()
    {
        string password = new string('p', 4097);
        string hash = WordPressHash(password);
        Assert.False(WordPressBcryptFormat.Default.Verify(password, hash));
        Assert.True(WordPressBcryptFormat.Default.TryExtractWrapInput(hash, out _, out byte[] parameter));
        Assert.Throws<FormatException>(() => WordPressBcryptFormat.Default.ComputeWrapInput(password, parameter));

        string atLimit = new string('p', 4096);
        Assert.True(WordPressBcryptFormat.Default.Verify(atLimit, WordPressHash(atLimit)));
    }

    [Theory]
    [InlineData("$wp")]
    [InlineData("$wp$")]
    [InlineData("$wp$2y$05$CCCCCCCCCCCCCCCCCCCCC.")]
    [InlineData("$WP$2y$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW")]
    [InlineData("$wp$2x$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW")]
    [InlineData("$wp$2y$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeWW")]
    [InlineData("$wp$2y$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeX")] // last char low bits set
    [InlineData("$wp2y$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeWa")]
    [InlineData("$wp$$2y$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOe")]
    public void Rejects_malformed(string hash)
    {
        Assert.False(WordPressBcryptFormat.Default.CanHandle(hash));
        Assert.False(WordPressBcryptFormat.Default.Verify("password", hash));
        Assert.False(WordPressBcryptFormat.Default.TryExtractWrapInput(hash, out _, out _));
    }

    [Fact]
    public void Wrap_input()
    {
        string hash = WordPressHash("password");
        Assert.True(WordPressBcryptFormat.Default.TryExtractWrapInput(hash, out byte[] digest, out byte[] parameter));
        Assert.Equal(Salt, Encoding.ASCII.GetString(parameter));
        Assert.Equal(hash.Substring(32), Encoding.ASCII.GetString(digest));
        Assert.Equal(digest, WordPressBcryptFormat.Default.ComputeWrapInput("password", parameter));
        Assert.Throws<FormatException>(() => WordPressBcryptFormat.Default.ComputeWrapInput("password", new byte[29]));
        Assert.Throws<FormatException>(() => WordPressBcryptFormat.Default.ComputeWrapInput("password", Array.Empty<byte>()));
    }

    [Fact]
    public void Guards()
    {
        Assert.Throws<ArgumentNullException>(() => WordPressBcryptFormat.Default.Verify(null!, WordPressHash("x")));
        Assert.Throws<ArgumentNullException>(() => WordPressBcryptFormat.Default.ComputeWrapInput(null!, new byte[29]));
        Assert.False(WordPressBcryptFormat.Default.CanHandle(null!));
    }
}
