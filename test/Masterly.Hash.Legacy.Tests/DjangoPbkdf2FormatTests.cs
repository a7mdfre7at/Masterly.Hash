using System;
using System.Security.Cryptography;
using System.Text;
using Masterly.Hash.Legacy;
using static Masterly.Hash.Legacy.Tests.TestSupport;

namespace Masterly.Hash.Legacy.Tests;

public class DjangoPbkdf2FormatTests
{
    // Django's own tests, tests/auth_tests/test_hashers.py (password "lètmein", salt "seasalt"):
    // test_pbkdf2 / test_low_level_pbkdf2_sha1 at the 1.4 (10000) and 1.6 (12000) default iteration counts.
    // Cross-checked with Python's hashlib.pbkdf2_hmac.
    public static TheoryData<string, string> KnownVectors => new()
    {
        { "lètmein", "pbkdf2_sha256$10000$seasalt$CWWFdHOWwPnki7HvkcqN9iA2T3KLW1cf2uZ5kvArtVY=" },
        { "lètmein", "pbkdf2_sha1$10000$seasalt$oAfF6vgs95ncksAhGXOWf4Okq7o=" },
        { "lètmein", "pbkdf2_sha256$12000$seasalt$Ybw8zsFxqja97tY/o6G+Fy1ksY4U/Hw3DRrGED6Up4s=" },
        { "lètmein", "pbkdf2_sha1$12000$seasalt$RAzowyPatHQocn6USyo2fI984CU=" },
    };

    [Theory]
    [MemberData(nameof(KnownVectors))]
    public void Verifies_known_vectors(string password, string hash)
    {
        Assert.True(DjangoPbkdf2Format.Default.CanHandle(hash));
        Assert.True(DjangoPbkdf2Format.Default.Verify(password, hash));
        Assert.False(DjangoPbkdf2Format.Default.Verify("letmein", hash));
        Assert.False(DjangoPbkdf2Format.Default.Verify(password + " ", hash));

        PasswordVerificationResult result = Hasher(DjangoPbkdf2Format.Default).Verify(password, hash);
        Assert.Equal(RehashReason.LegacyFormat, result.RehashReason);
        Assert.NotNull(result.Rehash);
    }

    [Fact]
    public void Verifies_typical_modern_django_hash()
    {
        // Same layout Django 5.x writes: 22-char alphanumeric salt, 1,000,000 iterations would be the default;
        // fewer here to keep the test fast.
        const string salt = "aB3dE5gH7jK9mN1pQ3sT5v";
        byte[] dk = Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes("hunter2"), Encoding.ASCII.GetBytes(salt), 20000, HashAlgorithmName.SHA256, 32);
        string hash = $"pbkdf2_sha256$20000${salt}${Convert.ToBase64String(dk)}";
        Assert.True(DjangoPbkdf2Format.Default.Verify("hunter2", hash));
    }

    [Theory]
    [InlineData("pbkdf2_sha256$10000001$seasalt$CWWFdHOWwPnki7HvkcqN9iA2T3KLW1cf2uZ5kvArtVY=")]
    [InlineData("pbkdf2_sha256$2147483647$seasalt$CWWFdHOWwPnki7HvkcqN9iA2T3KLW1cf2uZ5kvArtVY=")]
    [InlineData("pbkdf2_sha256$9999999999$seasalt$CWWFdHOWwPnki7HvkcqN9iA2T3KLW1cf2uZ5kvArtVY=")]
    [InlineData("pbkdf2_sha256$99999999999999999999$seasalt$CWWFdHOWwPnki7HvkcqN9iA2T3KLW1cf2uZ5kvArtVY=")]
    public void Rejects_iterations_above_cap_without_hashing(string hash)
    {
        AssertQuick(() =>
        {
            Assert.False(DjangoPbkdf2Format.Default.CanHandle(hash));
            Assert.False(DjangoPbkdf2Format.Default.Verify("lètmein", hash));
            Assert.Equal(VerificationFailureReason.UnknownFormat, Hasher(DjangoPbkdf2Format.Default).Verify("lètmein", hash).FailureReason);
        });
    }

    [Fact]
    public void Custom_cap()
    {
        var format = new DjangoPbkdf2Format(10000);
        Assert.Equal(10000, format.MaxIterations);
        Assert.True(format.CanHandle("pbkdf2_sha256$10000$seasalt$CWWFdHOWwPnki7HvkcqN9iA2T3KLW1cf2uZ5kvArtVY="));
        Assert.False(format.CanHandle("pbkdf2_sha256$12000$seasalt$Ybw8zsFxqja97tY/o6G+Fy1ksY4U/Hw3DRrGED6Up4s="));
        Assert.Throws<ArgumentOutOfRangeException>(() => new DjangoPbkdf2Format(0));
    }

    [Theory]
    [InlineData("pbkdf2_sha256$010000$seasalt$CWWFdHOWwPnki7HvkcqN9iA2T3KLW1cf2uZ5kvArtVY=")] // leading zero
    [InlineData("pbkdf2_sha256$-10000$seasalt$CWWFdHOWwPnki7HvkcqN9iA2T3KLW1cf2uZ5kvArtVY=")]
    [InlineData("pbkdf2_sha256$0$seasalt$CWWFdHOWwPnki7HvkcqN9iA2T3KLW1cf2uZ5kvArtVY=")]
    [InlineData("pbkdf2_sha256$ 10000$seasalt$CWWFdHOWwPnki7HvkcqN9iA2T3KLW1cf2uZ5kvArtVY=")]
    [InlineData("pbkdf2_sha256$10000$$CWWFdHOWwPnki7HvkcqN9iA2T3KLW1cf2uZ5kvArtVY=")]           // empty salt
    [InlineData("pbkdf2_sha256$10000$sea salt$CWWFdHOWwPnki7HvkcqN9iA2T3KLW1cf2uZ5kvArtVY=")]   // space in salt
    [InlineData("pbkdf2_sha256$10000$seasalt$CWWFdHOWwPnki7HvkcqN9iA2T3KLW1cf2uZ5kvArtVY")]     // unpadded
    [InlineData("pbkdf2_sha256$10000$seasalt$oAfF6vgs95ncksAhGXOWf4Okq7o=")]                    // 20-byte hash for sha256
    [InlineData("pbkdf2_sha1$10000$seasalt$CWWFdHOWwPnki7HvkcqN9iA2T3KLW1cf2uZ5kvArtVY=")]      // 32-byte hash for sha1
    [InlineData("pbkdf2_sha512$10000$seasalt$CWWFdHOWwPnki7HvkcqN9iA2T3KLW1cf2uZ5kvArtVY=")]
    [InlineData("PBKDF2_SHA256$10000$seasalt$CWWFdHOWwPnki7HvkcqN9iA2T3KLW1cf2uZ5kvArtVY=")]
    [InlineData("pbkdf2_sha256$10000$seasalt$CWWFdHOWwPnki7HvkcqN9iA2T3KLW1cf2uZ5kvArtVY=$")]
    [InlineData("bcrypt_sha256$$2b$12$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW")]
    [InlineData("argon2$argon2id$v=19$m=102400,t=2,p=8$c29tZXNhbHQ$Y2FmZWJhYmU")]
    public void Rejects_malformed(string hash)
    {
        Assert.False(DjangoPbkdf2Format.Default.CanHandle(hash));
        Assert.False(DjangoPbkdf2Format.Default.Verify("lètmein", hash));
        Assert.False(DjangoPbkdf2Format.Default.TryExtractWrapInput(hash, out _, out _));
    }

    [Fact]
    public void Salt_of_128_characters_is_the_limit()
    {
        string salt128 = new('s', 128);
        string salt129 = new('s', 129);
        string Make(string salt) => $"pbkdf2_sha256$1000${salt}${Convert.ToBase64String(Rfc2898DeriveBytes.Pbkdf2("pw", Encoding.ASCII.GetBytes(salt), 1000, HashAlgorithmName.SHA256, 32))}";
        Assert.True(DjangoPbkdf2Format.Default.Verify("pw", Make(salt128)));
        Assert.False(DjangoPbkdf2Format.Default.CanHandle(Make(salt129)));
    }

    [Fact]
    public void Wrap_parameter_round_trips_and_rejects_forgery()
    {
        const string hash = "pbkdf2_sha1$10000$seasalt$oAfF6vgs95ncksAhGXOWf4Okq7o=";
        Assert.True(DjangoPbkdf2Format.Default.TryExtractWrapInput(hash, out byte[] digest, out byte[] parameter));
        Assert.Equal(Convert.FromBase64String("oAfF6vgs95ncksAhGXOWf4Okq7o="), digest);
        Assert.Equal(new byte[] { 0, 0, 0, 0x27, 0x10 }, parameter[..5]);
        Assert.Equal("seasalt", Encoding.ASCII.GetString(parameter, 5, parameter.Length - 5));
        Assert.Equal(digest, DjangoPbkdf2Format.Default.ComputeWrapInput("lètmein", parameter));

        byte[] forged = (byte[])parameter.Clone();
        forged[1] = 0xFF;
        AssertQuick(() => Assert.Throws<FormatException>(() => DjangoPbkdf2Format.Default.ComputeWrapInput("lètmein", forged)));
        byte[] badAlgorithm = (byte[])parameter.Clone();
        badAlgorithm[0] = 2;
        Assert.Throws<FormatException>(() => DjangoPbkdf2Format.Default.ComputeWrapInput("lètmein", badAlgorithm));
        Assert.Throws<FormatException>(() => DjangoPbkdf2Format.Default.ComputeWrapInput("lètmein", parameter[..5]));
        byte[] dollarSalt = (byte[])parameter.Clone();
        dollarSalt[6] = (byte)'$';
        Assert.Throws<FormatException>(() => DjangoPbkdf2Format.Default.ComputeWrapInput("lètmein", dollarSalt));
    }
}
