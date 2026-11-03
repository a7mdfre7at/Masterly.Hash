using System;
using Masterly.Hash.Legacy;
using Masterly.Hash.Primitives;
using Microsoft.Extensions.Options;
using static Masterly.Hash.Legacy.Tests.TestSupport;
using Ms = Microsoft.AspNetCore.Identity;

namespace Masterly.Hash.Legacy.Tests;

/// <summary>Onion wrapping with a real <see cref="PasswordHasher"/> for every wrappable format.</summary>
public class WrapRoundTripTests
{
    private sealed class User
    {
    }

    private static string Identity(Ms.PasswordHasherCompatibilityMode mode, string password) =>
        new Ms.PasswordHasher<User>(Options.Create(new Ms.PasswordHasherOptions { CompatibilityMode = mode, IterationCount = 1000 }))
            .HashPassword(new User(), password);

    public static TheoryData<string, string, string> Wrappable => new()
    {
        { "bcrypt", "U*U", "$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW" },
        { "bcrypt", "abc", "$2a$06$If6bvum7DFjUnE9p2uDeDu0YHzrHM6tf.iqN8.yx.jNN1ILEf7h0i" },
        { "wordpress-bcrypt", "hunter2 é", WordPressBcryptFormatTests.WordPressHash("hunter2 é") },
        { "phpass", "test12345", "$P$9IQRaTwmfeRo7ud9Fh4E2PdI0S3r.L0" },
        { "phpass", "test12345", "$H$9IQRaTwmfeRo7ud9Fh4E2PdI0S3r.L0" },
        { "django-pbkdf2", "lètmein", "pbkdf2_sha256$10000$seasalt$CWWFdHOWwPnki7HvkcqN9iA2T3KLW1cf2uZ5kvArtVY=" },
        { "django-pbkdf2", "lètmein", "pbkdf2_sha1$10000$seasalt$oAfF6vgs95ncksAhGXOWf4Okq7o=" },
        { "aspnet-identity-v2", "hunter2 é", Identity(Ms.PasswordHasherCompatibilityMode.IdentityV2, "hunter2 é") },
        { "aspnet-identity-v3", "hunter2 é", Identity(Ms.PasswordHasherCompatibilityMode.IdentityV3, "hunter2 é") },
        { "md5", "password", "5f4dcc3b5aa765d61d8327deb882cf99" },
        { "md5", "password", "5F4DCC3B5AA765D61D8327DEB882CF99" },
        { "sha1", "password", "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8" },
        { "sha256", "password", "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8" },
        { "sha512", "password", "b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86" },
    };

    [Theory]
    [MemberData(nameof(Wrappable))]
    public void Wrapped_hash_verifies_with_original_password_and_upgrades(string formatId, string password, string legacyHash)
    {
        PasswordHasher hasher = AllFormats();
        Assert.True(hasher.TryWrap(legacyHash, out string wrapped));
        Assert.StartsWith($"$mh$p=test,w={formatId}", wrapped);
        Assert.DoesNotContain(legacyHash, wrapped);

        HashInfo info = hasher.Inspect(wrapped);
        Assert.True(info.IsRecognized);
        Assert.Equal(formatId, info.WrappedFormat);
        Assert.Equal(RehashReason.Wrapped, info.RehashReason);

        PasswordVerificationResult ok = hasher.Verify(password, wrapped);
        Assert.Equal(VerificationStatus.SuccessRehashNeeded, ok.Status);
        Assert.Equal(RehashReason.Wrapped, ok.RehashReason);
        Assert.StartsWith("$mh$p=test$", ok.Rehash);
        Assert.Equal(VerificationStatus.Success, hasher.Verify(password, ok.Rehash!).Status);

        Assert.Equal(VerificationFailureReason.Mismatch, hasher.Verify(password + "x", wrapped).FailureReason);
    }

    [Theory]
    [MemberData(nameof(Wrappable))]
    public void Wrapping_works_with_only_that_format_registered(string formatId, string password, string legacyHash)
    {
        PasswordHasher hasher = Hasher(Format(formatId));
        Assert.True(hasher.TryWrap(legacyHash, out string wrapped));
        Assert.True(hasher.Verify(password, wrapped).IsMatch);

        // Without the format the wrapped hash cannot be verified (but never throws).
        var bare = new PasswordHasher(new PasswordHasherOptions { DefaultProfile = Fast, AllowWeakProfiles = true });
        Assert.False(bare.Inspect(wrapped).IsRecognized);
        Assert.Equal(VerificationFailureReason.UnknownFormat, bare.Verify(password, wrapped).FailureReason);
    }

    [Theory]
    [MemberData(nameof(Wrappable))]
    public void Extract_and_compute_agree(string formatId, string password, string legacyHash)
    {
        ILegacyHashFormat format = Format(formatId);
        Assert.True(format.TryExtractWrapInput(legacyHash, out byte[] digest, out byte[] parameter));
        Assert.NotEmpty(digest);
        Assert.True(HashPrimitives.FixedTimeEquals(digest, format.ComputeWrapInput(password, parameter)));
        Assert.False(HashPrimitives.FixedTimeEquals(digest, format.ComputeWrapInput(password + "x", parameter)));
    }

    [Fact]
    public void Wrapped_hash_with_forged_cost_parameter_fails_fast()
    {
        PasswordHasher hasher = AllFormats();
        Assert.True(hasher.TryWrap("$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW", out string wrapped));

        // Someone with write access to the row raises the bcrypt cost inside the wrap parameter to 31.
        string[] parts = wrapped.Split('$');
        string forgedParam = HashPrimitives.ToB64(System.Text.Encoding.ASCII.GetBytes("$2a$31$CCCCCCCCCCCCCCCCCCCCC."));
        string forged = wrapped.Replace(parts[2], "p=test,w=bcrypt,wp=" + forgedParam);
        Assert.NotEqual(wrapped, forged);

        AssertQuick(() => Assert.Equal(VerificationFailureReason.MalformedHash, hasher.Verify("U*U", forged).FailureReason));
    }

    [Fact]
    public void Argon2_and_masterly_hashes_are_not_wrapped()
    {
        PasswordHasher hasher = AllFormats();
        Assert.False(hasher.TryWrap("$argon2i$v=19$m=256,t=2,p=1$c29tZXNhbHQ$iekCn0Y3spW+sCcFanM2xBT63UP2sghkUoHLIUpWRS8", out _));
        Assert.False(hasher.TryWrap(hasher.Hash("pw"), out _));
        Assert.False(hasher.TryWrap("garbage", out _));
    }
}
