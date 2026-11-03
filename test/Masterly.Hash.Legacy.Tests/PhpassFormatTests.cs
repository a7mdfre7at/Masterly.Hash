using System;
using System.Text;
using Masterly.Hash.Legacy;
using static Masterly.Hash.Legacy.Tests.TestSupport;

namespace Masterly.Hash.Legacy.Tests;

public class PhpassFormatTests
{
    // Openwall phpass 0.3 test.php: $correct = 'test12345'; $hash = '$P$9IQRaTwmfeRo7ud9Fh4E2PdI0S3r.L0';
    // (cross-checked with an independent Python implementation of crypt_private).
    private const string Vector = "$P$9IQRaTwmfeRo7ud9Fh4E2PdI0S3r.L0";
    private const string VectorPassword = "test12345";

    [Fact]
    public void Verifies_phpass_test_vector()
    {
        Assert.True(PhpassFormat.Default.CanHandle(Vector));
        Assert.True(PhpassFormat.Default.Verify(VectorPassword, Vector));
        Assert.False(PhpassFormat.Default.Verify("test12346", Vector)); // test.php's $wrong
        Assert.False(PhpassFormat.Default.Verify("Test12345", Vector));
    }

    [Fact]
    public void Verifies_phpbb_H_prefix()
    {
        // phpBB3 writes the same construction with an $H$ marker.
        string phpbb = "$H$" + Vector.Substring(3);
        Assert.True(PhpassFormat.Default.CanHandle(phpbb));
        Assert.True(PhpassFormat.Default.Verify(VectorPassword, phpbb));
    }

    [Fact]
    public void Hasher_upgrades_on_login()
    {
        PasswordHasher hasher = Hasher(PhpassFormat.Default);
        PasswordVerificationResult result = hasher.Verify(VectorPassword, Vector);
        Assert.Equal(VerificationStatus.SuccessRehashNeeded, result.Status);
        Assert.Equal("phpass", hasher.Inspect(Vector).Format);
        Assert.Equal(VerificationStatus.Success, hasher.Verify(VectorPassword, result.Rehash!).Status);
    }

    [Theory]
    [InlineData('H')] // 19
    [InlineData('S')] // 30, the phpass maximum: 2^30 MD5 rounds
    public void Rejects_count_above_cap_without_hashing(char count)
    {
        string hash = "$P$" + count + Vector.Substring(4);
        AssertQuick(() =>
        {
            Assert.False(PhpassFormat.Default.CanHandle(hash));
            Assert.False(PhpassFormat.Default.Verify(VectorPassword, hash));
            Assert.Equal(VerificationFailureReason.UnknownFormat, Hasher(PhpassFormat.Default).Verify(VectorPassword, hash).FailureReason);
        });
    }

    [Fact]
    public void Rejects_passwords_over_4096_bytes_before_hashing()
    {
        // phpass re-hashes the whole password every round, so cost is linear in its length. Upstream phpass
        // (PasswordHash.php CheckPassword) and WordPress refuse passwords over 4096 bytes.
        string count18 = "$P$G" + Vector.Substring(4);
        string tooLong = new string('a', 4097);
        string tooLongUtf8 = new string('é', 2049); // 4098 UTF-8 bytes in 2049 chars
        AssertQuick(() =>
        {
            Assert.False(PhpassFormat.Default.Verify(tooLong, count18));
            Assert.False(PhpassFormat.Default.Verify(tooLongUtf8, count18));
            Assert.Throws<FormatException>(() => PhpassFormat.Default.ComputeWrapInput(tooLong, Encoding.ASCII.GetBytes("$P$GIQRaTwmf")));
        }, maxMs: 250);

        // Through a hasher that allows 1 MiB passwords, a 256 KiB password still costs nothing.
        var options = new PasswordHasherOptions { DefaultProfile = Fast, AllowWeakProfiles = true, MaxPasswordBytes = 1024 * 1024 };
        var hasher = new PasswordHasher(options.AddLegacyFormats(PhpassFormat.Default));
        AssertQuick(() => Assert.Equal(VerificationFailureReason.Mismatch, hasher.Verify(new string('a', 256 * 1024), Vector).FailureReason), maxMs: 200);
    }

    [Fact]
    public void Password_of_exactly_4096_bytes_is_still_hashed()
    {
        string password = new string('a', 4096);
        Assert.True(PhpassFormat.Default.TryExtractWrapInput(Vector, out byte[] digest, out byte[] parameter));
        byte[] computed = PhpassFormat.Default.ComputeWrapInput(password, parameter);
        Assert.Equal(22, computed.Length);
        Assert.NotEqual(digest, computed);
        Assert.False(PhpassFormat.Default.Verify(password, Vector));
    }

    [Fact]
    public void Custom_cap()
    {
        Assert.Equal(18, PhpassFormat.Default.MaxCostLog2);
        Assert.False(new PhpassFormat(10).CanHandle(Vector)); // '9' is 2^11
        Assert.True(new PhpassFormat(11).CanHandle(Vector));
        Assert.True(new PhpassFormat(30).CanHandle("$P$S" + Vector.Substring(4)));
        Assert.Throws<ArgumentOutOfRangeException>(() => new PhpassFormat(6));
        Assert.Throws<ArgumentOutOfRangeException>(() => new PhpassFormat(31));
    }

    [Theory]
    [InlineData("$P$4IQRaTwmfeRo7ud9Fh4E2PdI0S3r.L0")]   // count 6, below phpass minimum
    [InlineData("$P$TIQRaTwmfeRo7ud9Fh4E2PdI0S3r.L0")]   // count 31
    [InlineData("$P$9IQRaTwmfeRo7ud9Fh4E2PdI0S3r.L")]    // short
    [InlineData("$P$9IQRaTwmfeRo7ud9Fh4E2PdI0S3r.L00")]  // long
    [InlineData("$P$9IQRaTwmfeRo7ud9Fh4E2PdI0S3r.L4")]   // last char carries only 2 bits
    [InlineData("$P$9IQRa+wmfeRo7ud9Fh4E2PdI0S3r.L0")]   // outside alphabet
    [InlineData("$p$9IQRaTwmfeRo7ud9Fh4E2PdI0S3r.L0")]
    [InlineData("$S$9IQRaTwmfeRo7ud9Fh4E2PdI0S3r.L0")]   // Drupal 7 SHA-512 variant, not supported
    [InlineData("P$9IQRaTwmfeRo7ud9Fh4E2PdI0S3r.L0$")]
    public void Rejects_malformed(string hash)
    {
        Assert.False(PhpassFormat.Default.CanHandle(hash));
        Assert.False(PhpassFormat.Default.Verify(VectorPassword, hash));
        Assert.False(PhpassFormat.Default.TryExtractWrapInput(hash, out _, out _));
    }

    [Fact]
    public void Wrap_input()
    {
        Assert.True(PhpassFormat.Default.TryExtractWrapInput(Vector, out byte[] digest, out byte[] parameter));
        Assert.Equal("$P$9IQRaTwmf", Encoding.ASCII.GetString(parameter));
        Assert.Equal("eRo7ud9Fh4E2PdI0S3r.L0", Encoding.ASCII.GetString(digest));
        Assert.Equal(digest, PhpassFormat.Default.ComputeWrapInput(VectorPassword, parameter));

        AssertQuick(() => Assert.Throws<FormatException>(() => PhpassFormat.Default.ComputeWrapInput(VectorPassword, Encoding.ASCII.GetBytes("$P$SIQRaTwmf"))));
        Assert.Throws<FormatException>(() => PhpassFormat.Default.ComputeWrapInput(VectorPassword, Encoding.ASCII.GetBytes("$P$9IQRaTwm")));
        Assert.Throws<FormatException>(() => PhpassFormat.Default.ComputeWrapInput(VectorPassword, new byte[12]));
    }
}
