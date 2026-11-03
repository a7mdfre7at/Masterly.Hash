using System;
using System.Security.Cryptography;
using System.Text;
using Masterly.Hash.Legacy;
using Microsoft.Extensions.Options;
using static Masterly.Hash.Legacy.Tests.TestSupport;
using Ms = Microsoft.AspNetCore.Identity;

namespace Masterly.Hash.Legacy.Tests;

/// <summary>Differential tests against Microsoft's own <c>PasswordHasher&lt;TUser&gt;</c> (Microsoft.Extensions.Identity.Core).</summary>
public class AspNetIdentityFormatTests
{
    private sealed class User
    {
    }

    private static readonly User AUser = new();

    private static Ms.PasswordHasher<User> Microsoft(Ms.PasswordHasherCompatibilityMode mode, int iterations = 100_000) =>
        new(Options.Create(new Ms.PasswordHasherOptions { CompatibilityMode = mode, IterationCount = iterations }));

    public static TheoryData<string> Passwords => new()
    {
        "hunter2",
        "correct horse battery staple",
        "pässwörd \U0001F600 ünïcödé",
        "Å",            // NFC; Microsoft does not normalize, neither must we
        "Å",      // NFD spelling of the same: a different password for Identity
        new string('x', 300),
    };

    [Theory]
    [MemberData(nameof(Passwords))]
    public void V2_verifies_hashes_from_microsoft(string password)
    {
        string hash = Microsoft(Ms.PasswordHasherCompatibilityMode.IdentityV2).HashPassword(AUser, password);
        Assert.Equal(0x00, Convert.FromBase64String(hash)[0]);

        Assert.True(AspNetIdentityV2Format.Instance.CanHandle(hash));
        Assert.False(AspNetIdentityV3Format.Default.CanHandle(hash));
        Assert.True(AspNetIdentityV2Format.Instance.Verify(password, hash));
        Assert.False(AspNetIdentityV2Format.Instance.Verify(password + "!", hash));
    }

    [Theory]
    [MemberData(nameof(Passwords))]
    public void V3_verifies_hashes_from_microsoft(string password)
    {
        string hash = Microsoft(Ms.PasswordHasherCompatibilityMode.IdentityV3, iterations: 1000).HashPassword(AUser, password);
        Assert.Equal(0x01, Convert.FromBase64String(hash)[0]);

        Assert.True(AspNetIdentityV3Format.Default.CanHandle(hash));
        Assert.False(AspNetIdentityV2Format.Instance.CanHandle(hash));
        Assert.True(AspNetIdentityV3Format.Default.Verify(password, hash));
        Assert.False(AspNetIdentityV3Format.Default.Verify(password + "!", hash));
    }

    [Fact]
    public void Nfc_and_nfd_are_different_passwords_like_in_identity()
    {
        string hash = Microsoft(Ms.PasswordHasherCompatibilityMode.IdentityV3, 1000).HashPassword(AUser, "Å");
        Assert.True(AspNetIdentityV3Format.Default.Verify("Å", hash));
        Assert.False(AspNetIdentityV3Format.Default.Verify("Å", hash));
        Assert.Equal(Ms.PasswordVerificationResult.Failed, Microsoft(Ms.PasswordHasherCompatibilityMode.IdentityV3, 1000).VerifyHashedPassword(AUser, hash, "Å"));
    }

    [Fact]
    public void V3_verifies_microsoft_default_settings()
    {
        // Current default: HMAC-SHA512, 100,000 iterations, 16-byte salt, 32-byte subkey.
        string hash = new Ms.PasswordHasher<User>().HashPassword(AUser, "hunter2");
        byte[] raw = Convert.FromBase64String(hash);
        Assert.Equal(new byte[] { 1, 0, 0, 0, 2, 0, 1, 0x86, 0xA0, 0, 0, 0, 16 }, raw[..13]);
        Assert.True(AspNetIdentityV3Format.Default.Verify("hunter2", hash));
        Assert.Equal("aspnet-identity-v3", AllFormats().Inspect(hash).Format);
    }

    [Theory]
    [InlineData(0u, "SHA1")]
    [InlineData(1u, "SHA256")]
    [InlineData(2u, "SHA512")]
    public void V3_supports_every_prf_and_microsoft_agrees(uint prf, string algorithm)
    {
        byte[] salt = Bytes(16, 7);
        byte[] subkey = Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes("hunter2"), salt, 5000, new HashAlgorithmName(algorithm), 32);
        string hash = IdentityV3(prf, 5000, salt, subkey);

        Assert.NotEqual(Ms.PasswordVerificationResult.Failed, Microsoft(Ms.PasswordHasherCompatibilityMode.IdentityV3).VerifyHashedPassword(AUser, hash, "hunter2"));
        Assert.True(AspNetIdentityV3Format.Default.Verify("hunter2", hash));
        Assert.False(AspNetIdentityV3Format.Default.Verify("hunter3", hash));
    }

    [Fact]
    public void V3_accepts_salt_of_8_bytes_and_rejects_7()
    {
        byte[] salt8 = Bytes(8, 1);
        string ok = IdentityV3(1, 1000, salt8, Rfc2898DeriveBytes.Pbkdf2("pw", salt8, 1000, HashAlgorithmName.SHA256, 32));
        Assert.True(AspNetIdentityV3Format.Default.Verify("pw", ok));

        byte[] salt7 = Bytes(7, 1);
        string bad = IdentityV3(1, 1000, salt7, Rfc2898DeriveBytes.Pbkdf2("pw", salt7, 1000, HashAlgorithmName.SHA256, 32));
        Assert.False(AspNetIdentityV3Format.Default.CanHandle(bad));
        Assert.False(AspNetIdentityV3Format.Default.Verify("pw", bad));
    }

    [Theory]
    // PBKDF2 runs one iteration chain per PRF output block: SHA-1 20 bytes, SHA-256 32, SHA-512 64.
    [InlineData(0u, 64, 4)]
    [InlineData(0u, 32, 2)]
    [InlineData(0u, 20, 1)]
    [InlineData(1u, 64, 2)]
    [InlineData(1u, 33, 2)]
    [InlineData(1u, 32, 1)]
    [InlineData(2u, 64, 1)]
    public void V3_cap_counts_every_pbkdf2_output_block(uint prf, int subkeyLength, int blocks)
    {
        uint atCap = (uint)(AspNetIdentityV3Format.DefaultMaxIterations / blocks);
        AssertQuick(() =>
        {
            Assert.True(AspNetIdentityV3Format.Default.CanHandle(IdentityV3(prf, atCap, Bytes(16, 1), Bytes(subkeyLength, 2))));
            if (blocks > 1)
            {
                // Microsoft-style iteration count at the cap, but blocks x the work: refused.
                string planted = IdentityV3(prf, AspNetIdentityV3Format.DefaultMaxIterations, Bytes(16, 1), Bytes(subkeyLength, 2));
                Assert.False(AspNetIdentityV3Format.Default.CanHandle(planted));
                Assert.False(AspNetIdentityV3Format.Default.Verify("pw", planted));
                Assert.False(AspNetIdentityV3Format.Default.TryExtractWrapInput(planted, out _, out _));
            }
            Assert.False(AspNetIdentityV3Format.Default.CanHandle(IdentityV3(prf, atCap + 1, Bytes(16, 1), Bytes(subkeyLength, 2))));
        });
    }

    [Fact]
    public void V3_wrap_parameter_cap_counts_output_blocks()
    {
        // A wrapped hash whose parameter claims a 64-byte HMAC-SHA1 subkey at 10M iterations is 40M of work.
        var format = new AspNetIdentityV3Format(1000);
        byte[] salt = Bytes(16, 1);
        string hash = IdentityV3(0, 250, salt, Rfc2898DeriveBytes.Pbkdf2("pw", salt, 250, HashAlgorithmName.SHA1, 64));
        Assert.True(format.Verify("pw", hash));
        Assert.True(format.TryExtractWrapInput(hash, out byte[] digest, out byte[] parameter));
        Assert.Equal(digest, format.ComputeWrapInput("pw", parameter));

        Assert.False(format.CanHandle(IdentityV3(0, 251, salt, Bytes(64, 2))));
        byte[] forged = (byte[])parameter.Clone();
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(forged.AsSpan(5, 4), 251); // 4 x 251 > 1000
        AssertQuick(() => Assert.Throws<FormatException>(() => format.ComputeWrapInput("pw", forged)));
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(forged.AsSpan(5, 4), 10_000_000);
        AssertQuick(() => Assert.Throws<FormatException>(() => AspNetIdentityV3Format.Default.ComputeWrapInput("pw", forged)));
    }

    [Fact]
    public void V3_salt_is_capped_at_256_bytes_so_wrapped_hashes_stay_parseable()
    {
        byte[] salt256 = Bytes(256, 1);
        string ok = IdentityV3(1, 1000, salt256, Rfc2898DeriveBytes.Pbkdf2("hunter2", salt256, 1000, HashAlgorithmName.SHA256, 32));
        PasswordHasher hasher = Hasher(AspNetIdentityV3Format.Default);
        Assert.Equal(VerificationStatus.SuccessRehashNeeded, hasher.Verify("hunter2", ok).Status);
        Assert.True(hasher.TryWrap(ok, out string wrapped));
        Assert.True(wrapped.Length <= 1024, $"wrapped length {wrapped.Length}");
        Assert.Equal(VerificationStatus.SuccessRehashNeeded, hasher.Verify("hunter2", wrapped).Status);

        // 700-byte salt: a valid-looking 996-char hash whose wrap would exceed the 1024-char $mh$ limit.
        byte[] salt700 = Bytes(700, 1);
        string huge = IdentityV3(1, 1000, salt700, Rfc2898DeriveBytes.Pbkdf2("hunter2", salt700, 1000, HashAlgorithmName.SHA256, 32));
        Assert.False(AspNetIdentityV3Format.Default.CanHandle(huge));
        Assert.False(AspNetIdentityV3Format.Default.TryExtractWrapInput(huge, out _, out _));
        Assert.False(hasher.TryWrap(huge, out _));
        Assert.False(AspNetIdentityV3Format.Default.CanHandle(IdentityV3(1, 1000, Bytes(257, 1), Bytes(32, 2))));
    }

    [Theory]
    [InlineData(10_000_001u)]
    [InlineData(0x7FFFFFFFu)]
    [InlineData(0xFFFFFFFFu)]
    public void V3_rejects_iterations_above_cap_without_hashing(uint iterations)
    {
        string hash = IdentityV3(2, iterations, Bytes(16, 1), Bytes(32, 2));
        AssertQuick(() =>
        {
            Assert.False(AspNetIdentityV3Format.Default.CanHandle(hash));
            Assert.False(AspNetIdentityV3Format.Default.Verify("pw", hash));
            // The v3 format refuses it; the built-in 1.x format (plain base64) still gets a cheap SHA-2 look and misses.
            PasswordHasher hasher = Hasher(AspNetIdentityV3Format.Default);
            Assert.Equal("v1", hasher.Inspect(hash).Format);
            Assert.Equal(VerificationFailureReason.Mismatch, hasher.Verify("pw", hash).FailureReason);
        });
    }

    [Fact]
    public void V3_custom_cap()
    {
        var format = new AspNetIdentityV3Format(1000);
        Assert.Equal(1000, format.MaxIterations);
        Assert.True(format.CanHandle(IdentityV3(2, 1000, Bytes(16, 1), Bytes(32, 2))));
        Assert.False(format.CanHandle(IdentityV3(2, 1001, Bytes(16, 1), Bytes(32, 2))));
        Assert.Throws<ArgumentOutOfRangeException>(() => new AspNetIdentityV3Format(0));
    }

    public static TheoryData<string> MalformedV3 => new()
    {
        IdentityV3(3, 1000, Bytes(16, 1), Bytes(32, 2)),                         // unknown PRF
        IdentityV3(1, 0, Bytes(16, 1), Bytes(32, 2)),                            // zero iterations
        IdentityV3(1, 1000, Bytes(16, 1), Bytes(15, 2)),                         // subkey too short
        IdentityV3(1, 1000, Bytes(16, 1), Bytes(65, 2)),                         // subkey too long
        IdentityV3(1, 1000, Bytes(16, 1), Bytes(32, 2), declaredSaltLength: 40), // salt length past the end
        IdentityV3(1, 1000, Bytes(16, 1), Bytes(32, 2), declaredSaltLength: -1), // 0xFFFFFFFF
        IdentityV3(1, 1000, Bytes(16, 1), Bytes(32, 2)).TrimEnd('='),            // not padded
        "AQAAAAEAAAPoAAAAEA",
        "Ag" + IdentityV3(1, 1000, Bytes(16, 1), Bytes(32, 2)).Substring(2),     // version 0x02
    };

    [Theory]
    [MemberData(nameof(MalformedV3))]
    public void V3_rejects_malformed(string hash)
    {
        Assert.False(AspNetIdentityV3Format.Default.CanHandle(hash));
        Assert.False(AspNetIdentityV3Format.Default.Verify("pw", hash));
        Assert.False(AspNetIdentityV3Format.Default.TryExtractWrapInput(hash, out _, out _));
    }

    [Fact]
    public void V2_rejects_malformed()
    {
        string valid = Microsoft(Ms.PasswordHasherCompatibilityMode.IdentityV2).HashPassword(AUser, "pw");
        byte[] raw = Convert.FromBase64String(valid);

        byte[] wrongMarker = (byte[])raw.Clone();
        wrongMarker[0] = 0x02;
        byte[] longer = new byte[raw.Length + 3];
        Buffer.BlockCopy(raw, 0, longer, 0, raw.Length);

        foreach (string hash in new[] { Convert.ToBase64String(wrongMarker), Convert.ToBase64String(longer), Convert.ToBase64String(raw[..^1]), valid.ToLowerInvariant(), valid + "=" })
        {
            Assert.False(AspNetIdentityV2Format.Instance.CanHandle(hash));
            Assert.False(AspNetIdentityV2Format.Instance.Verify("pw", hash));
        }
    }

    [Fact]
    public void Wrap_parameters_are_rejected_when_forged()
    {
        Assert.Throws<FormatException>(() => AspNetIdentityV2Format.Instance.ComputeWrapInput("pw", new byte[15]));

        string hash = IdentityV3(2, 1000, Bytes(16, 1), Bytes(32, 2));
        Assert.True(AspNetIdentityV3Format.Default.TryExtractWrapInput(hash, out _, out byte[] parameter));
        Assert.Equal(13 + 16 + 1, parameter.Length);

        byte[] forged = (byte[])parameter.Clone();
        forged[5] = 0x7F; // iterations ~2 billion
        AssertQuick(() => Assert.Throws<FormatException>(() => AspNetIdentityV3Format.Default.ComputeWrapInput("pw", forged)));

        byte[] badSubkey = (byte[])parameter.Clone();
        badSubkey[^1] = 200;
        Assert.Throws<FormatException>(() => AspNetIdentityV3Format.Default.ComputeWrapInput("pw", badSubkey));
        Assert.Throws<FormatException>(() => AspNetIdentityV3Format.Default.ComputeWrapInput("pw", parameter[..^2]));
        Assert.Throws<FormatException>(() => AspNetIdentityV3Format.Default.ComputeWrapInput("pw", Array.Empty<byte>()));
    }

    [Fact]
    public void Hasher_upgrades_identity_hashes_on_login()
    {
        PasswordHasher hasher = AllFormats();
        foreach (string hash in new[]
        {
            Microsoft(Ms.PasswordHasherCompatibilityMode.IdentityV2).HashPassword(AUser, "hunter2"),
            Microsoft(Ms.PasswordHasherCompatibilityMode.IdentityV3, 1000).HashPassword(AUser, "hunter2"),
        })
        {
            PasswordVerificationResult result = hasher.Verify("hunter2", hash);
            Assert.Equal(VerificationStatus.SuccessRehashNeeded, result.Status);
            Assert.True(hasher.Verify("hunter2", result.Rehash!).IsMatch);
            Assert.Equal(VerificationFailureReason.Mismatch, hasher.Verify("hunter3", hash).FailureReason);
        }
    }
}
