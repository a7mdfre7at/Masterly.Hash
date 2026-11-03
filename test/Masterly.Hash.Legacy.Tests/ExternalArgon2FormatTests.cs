using System;
using System.Text;
using Masterly.Hash.Legacy;
using Masterly.Hash.Primitives;
using static Masterly.Hash.Legacy.Tests.TestSupport;

namespace Masterly.Hash.Legacy.Tests;

public class ExternalArgon2FormatTests
{
    // Argon2 reference implementation (github.com/P-H-C/phc-winner-argon2) src/test.c, version 0x13,
    // password "password", salt "somesalt" unless noted.
    public static TheoryData<string, string> KnownVectors => new()
    {
        { "password", "$argon2i$v=19$m=256,t=2,p=1$c29tZXNhbHQ$iekCn0Y3spW+sCcFanM2xBT63UP2sghkUoHLIUpWRS8" },
        { "password", "$argon2i$v=19$m=256,t=2,p=2$c29tZXNhbHQ$T/XOJ2mh1/TIpJHfCdQan76Q5esCFVoT5MAeIM1Oq2E" },
        { "password", "$argon2i$v=19$m=65536,t=1,p=1$c29tZXNhbHQ$0WgHXE2YXhPr6uVgz4uUw7XYoWxRkWtvSsLaOsEbvs8" },
        { "differentpassword", "$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$FK6NoBr+qHAMI1jc73xTWNkCEoK9iGY6RWL1n7dNIu4" },
        { "password", "$argon2i$v=19$m=65536,t=2,p=1$ZGlmZnNhbHQ$sDV8zPvvkfOGCw26RHsjSMvv7K2vmQq/6cxAcmxSEnE" }, // salt "diffsalt"
        { "password", "$argon2id$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc" },
    };

    [Theory]
    [MemberData(nameof(KnownVectors))]
    public void Verifies_reference_vectors(string password, string hash)
    {
        Assert.True(ExternalArgon2Format.Default.CanHandle(hash));
        Assert.True(ExternalArgon2Format.Default.Verify(password, hash));
        Assert.False(ExternalArgon2Format.Default.Verify(password + "x", hash));
    }

    [Fact]
    public void Verifies_argon2d_and_custom_lengths()
    {
        // No public non-keyed argon2d PHC vector exists; build one with the Konscious primitive directly.
        byte[] salt = Bytes(16, 3);
        byte[] tag;
        using (var argon2 = new Konscious.Security.Cryptography.Argon2d(Encoding.UTF8.GetBytes("hunter2")) { Salt = salt, MemorySize = 64, Iterations = 2, DegreeOfParallelism = 2 })
            tag = argon2.GetBytes(24);
        string hash = $"$argon2d$v=19$m=64,t=2,p=2${HashPrimitives.ToB64(salt)}${HashPrimitives.ToB64(tag)}";

        Assert.True(ExternalArgon2Format.Default.Verify("hunter2", hash));
        Assert.False(ExternalArgon2Format.Default.Verify("hunter3", hash));
        Assert.False(ExternalArgon2Format.Default.Verify("hunter2", hash.Replace("$argon2d$", "$argon2id$")));
    }

    [Fact]
    public void Hasher_upgrades_on_login_but_never_wraps()
    {
        const string hash = "$argon2i$v=19$m=256,t=2,p=1$c29tZXNhbHQ$iekCn0Y3spW+sCcFanM2xBT63UP2sghkUoHLIUpWRS8";
        PasswordHasher hasher = Hasher(ExternalArgon2Format.Default);
        Assert.Equal("argon2-phc", hasher.Inspect(hash).Format);
        Assert.True(hasher.NeedsRehash(hash));

        PasswordVerificationResult result = hasher.Verify("password", hash);
        Assert.Equal(VerificationStatus.SuccessRehashNeeded, result.Status);
        Assert.StartsWith("$mh$p=test$", result.Rehash);

        Assert.False(hasher.TryWrap(hash, out _));
        Assert.False(ExternalArgon2Format.Default.TryExtractWrapInput(hash, out byte[] d, out byte[] p));
        Assert.Empty(d);
        Assert.Empty(p);
        Assert.Throws<FormatException>(() => ExternalArgon2Format.Default.ComputeWrapInput("password", Array.Empty<byte>()));
    }

    [Theory]
    [InlineData("$argon2id$v=19$m=1048577,t=1,p=1$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc")]     // > 1 GiB
    [InlineData("$argon2id$v=19$m=4294967295,t=1,p=1$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc")]
    [InlineData("$argon2id$v=19$m=65536,t=11,p=1$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc")]     // t > 10
    [InlineData("$argon2id$v=19$m=65536,t=4294967295,p=1$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc")]
    [InlineData("$argon2id$v=19$m=65536,t=2,p=17$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc")]     // p > 16
    [InlineData("$argon2id$v=19$m=65536,t=2,p=255$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc")]
    public void Rejects_costs_above_caps_without_hashing(string hash)
    {
        AssertQuick(() =>
        {
            Assert.False(ExternalArgon2Format.Default.CanHandle(hash));
            Assert.False(ExternalArgon2Format.Default.Verify("password", hash));
            Assert.Equal(VerificationFailureReason.UnknownFormat, Hasher(ExternalArgon2Format.Default).Verify("password", hash).FailureReason);
        });
    }

    [Fact]
    public void Default_memory_cap_is_256_MiB_and_configurable_to_1_GiB()
    {
        // 1 GiB per verify, times MaxConcurrency, is too much for a planted row on a typical host.
        const string m256 = "$argon2id$v=19$m=262144,t=1,p=1$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc";
        const string m256Plus = "$argon2id$v=19$m=262145,t=1,p=1$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc";
        const string m1G = "$argon2id$v=19$m=1048576,t=10,p=16$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc";
        Assert.Equal(256 * 1024, ExternalArgon2Format.DefaultMaxMemoryKiB);
        Assert.Equal(256 * 1024, ExternalArgon2Format.Default.MaxMemoryKiB);
        Assert.True(ExternalArgon2Format.Default.CanHandle(m256));
        AssertQuick(() =>
        {
            Assert.False(ExternalArgon2Format.Default.CanHandle(m256Plus));
            Assert.False(ExternalArgon2Format.Default.CanHandle(m1G));
            Assert.Equal(VerificationFailureReason.UnknownFormat, AllFormats().Verify("password", m1G).FailureReason);
        });

        var large = new ExternalArgon2Format(HashProfile.MaxMemoryKiB, 10, 16);
        Assert.True(large.CanHandle(m1G));
    }

    [Fact]
    public void Custom_caps()
    {
        var small = new ExternalArgon2Format(maxMemoryKiB: 1024, maxIterations: 2, maxParallelism: 1);
        Assert.Equal(1024, small.MaxMemoryKiB);
        Assert.Equal(2, small.MaxIterations);
        Assert.Equal(1, small.MaxParallelism);
        Assert.True(small.CanHandle("$argon2i$v=19$m=256,t=2,p=1$c29tZXNhbHQ$iekCn0Y3spW+sCcFanM2xBT63UP2sghkUoHLIUpWRS8"));
        Assert.False(small.CanHandle("$argon2i$v=19$m=256,t=2,p=2$c29tZXNhbHQ$T/XOJ2mh1/TIpJHfCdQan76Q5esCFVoT5MAeIM1Oq2E"));
        Assert.False(small.CanHandle("$argon2id$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc"));

        Assert.Throws<ArgumentOutOfRangeException>(() => new ExternalArgon2Format(7, 1, 1));
        Assert.Throws<ArgumentOutOfRangeException>(() => new ExternalArgon2Format(HashProfile.MaxMemoryKiB + 1, 1, 1));
        Assert.Throws<ArgumentOutOfRangeException>(() => new ExternalArgon2Format(1024, 0, 1));
        Assert.Throws<ArgumentOutOfRangeException>(() => new ExternalArgon2Format(1024, 65, 1));
        Assert.Throws<ArgumentOutOfRangeException>(() => new ExternalArgon2Format(1024, 1, 0));
        Assert.Throws<ArgumentOutOfRangeException>(() => new ExternalArgon2Format(1024, 1, 17));
    }

    [Theory]
    [InlineData("$argon2i$m=256,t=2,p=1$c29tZXNhbHQ$iekCn0Y3spW+sCcFanM2xBT63UP2sghkUoHLIUpWRS8")]                 // v=16 (no version)
    [InlineData("$argon2i$v=16$m=256,t=2,p=1$c29tZXNhbHQ$iekCn0Y3spW+sCcFanM2xBT63UP2sghkUoHLIUpWRS8")]
    [InlineData("$argon2i$v=19$t=2,m=256,p=1$c29tZXNhbHQ$iekCn0Y3spW+sCcFanM2xBT63UP2sghkUoHLIUpWRS8")]          // order
    [InlineData("$argon2i$v=19$m=256,t=2,p=1,keyid=abc$c29tZXNhbHQ$iekCn0Y3spW+sCcFanM2xBT63UP2sghkUoHLIUpWRS8")]
    [InlineData("$argon2i$v=19$m=0256,t=2,p=1$c29tZXNhbHQ$iekCn0Y3spW+sCcFanM2xBT63UP2sghkUoHLIUpWRS8")]         // leading zero
    [InlineData("$argon2i$v=19$m=7,t=2,p=1$c29tZXNhbHQ$iekCn0Y3spW+sCcFanM2xBT63UP2sghkUoHLIUpWRS8")]            // m < 8p
    [InlineData("$argon2i$v=19$m=256,t=0,p=1$c29tZXNhbHQ$iekCn0Y3spW+sCcFanM2xBT63UP2sghkUoHLIUpWRS8")]
    [InlineData("$argon2i$v=19$m=256,t=2,p=0$c29tZXNhbHQ$iekCn0Y3spW+sCcFanM2xBT63UP2sghkUoHLIUpWRS8")]
    [InlineData("$argon2i$v=19$m=256,t=2,p=1$c29tZXNhbHQ=$iekCn0Y3spW+sCcFanM2xBT63UP2sghkUoHLIUpWRS8")]         // padded
    [InlineData("$argon2i$v=19$m=256,t=2,p=1$c29tZQ$iekCn0Y3spW+sCcFanM2xBT63UP2sghkUoHLIUpWRS8")]               // salt < 8 bytes
    [InlineData("$argon2i$v=19$m=256,t=2,p=1$c29tZXNhbHQ$aWU")]                                                  // hash < 4 bytes
    [InlineData("$argon2x$v=19$m=256,t=2,p=1$c29tZXNhbHQ$iekCn0Y3spW+sCcFanM2xBT63UP2sghkUoHLIUpWRS8")]
    [InlineData("$argon2i$v=19$m=256,t=2,p=1$c29tZXNhbHQ$iekCn0Y3spW+sCcFanM2xBT63UP2sghkUoHLIUpWRS8$")]
    [InlineData("$argon2i$v=19$m=256,t=2,p=1$c29tZXNhbHQ$iekCn0Y3spW-sCcFanM2xBT63UP2sghkUoHLIUpWRS8")]          // url-safe alphabet
    [InlineData("x$argon2i$v=19$m=256,t=2,p=1$c29tZXNhbHQ$iekCn0Y3spW+sCcFanM2xBT63UP2sghkUoHLIUpWRS8")]
    public void Rejects_malformed(string hash)
    {
        Assert.False(ExternalArgon2Format.Default.CanHandle(hash));
        Assert.False(ExternalArgon2Format.Default.Verify("password", hash));
    }
}
