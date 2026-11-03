using System;
using System.Collections.Generic;
using Masterly.Hash.Legacy;
using static Masterly.Hash.Legacy.Tests.TestSupport;

namespace Masterly.Hash.Legacy.Tests;

/// <summary>No stored value, however broken, may make a format or the hasher throw.</summary>
public class MalformedInputTests
{
    // Low caps keep random mutations of cost fields from turning into slow tests.
    private static readonly (ILegacyHashFormat Format, string Valid)[] Seeds =
    {
        (new BCryptFormat(6), "$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW"),
        (new PhpassFormat(12), "$P$9IQRaTwmfeRo7ud9Fh4E2PdI0S3r.L0"),
        (new DjangoPbkdf2Format(20000), "pbkdf2_sha256$10000$seasalt$CWWFdHOWwPnki7HvkcqN9iA2T3KLW1cf2uZ5kvArtVY="),
        (new AspNetIdentityV3Format(20000), IdentityV3(1, 1000, Bytes(16, 1), Bytes(32, 2))),
        (AspNetIdentityV2Format.Instance, Convert.ToBase64String(new byte[49])),
        (new ExternalArgon2Format(1024, 3, 4), "$argon2i$v=19$m=256,t=2,p=1$c29tZXNhbHQ$iekCn0Y3spW+sCcFanM2xBT63UP2sghkUoHLIUpWRS8"),
        (UnsaltedDigestFormat.Md5, "5f4dcc3b5aa765d61d8327deb882cf99"),
        (UnsaltedDigestFormat.Sha512, "b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86"),
    };

    public static IEnumerable<object[]> FormatIndexes()
    {
        for (int i = 0; i < Seeds.Length; i++)
            yield return new object[] { i };
    }

    [Theory]
    [MemberData(nameof(FormatIndexes))]
    public void Garbage_is_rejected_without_throwing(int index)
    {
        ILegacyHashFormat format = Seeds[index].Format;
        Assert.False(format.CanHandle(null!));
        Assert.False(format.Verify("pw", null!));
        foreach (string garbage in Garbage())
        {
            Assert.False(format.CanHandle(garbage), garbage);
            Assert.False(format.Verify("pw", garbage));
            Assert.False(format.TryExtractWrapInput(garbage, out _, out _));
        }
    }

    [Theory]
    [MemberData(nameof(FormatIndexes))]
    public void Mutations_never_throw(int index)
    {
        (ILegacyHashFormat format, string valid) = Seeds[index];
        Assert.True(format.CanHandle(valid));
        foreach (string mutated in Mutations(valid, 250, seed: index))
        {
            bool handled = format.CanHandle(mutated);
            bool verified = format.Verify("password", mutated);
            Assert.True(handled || !verified);
            if (format.TryExtractWrapInput(mutated, out _, out byte[] parameter))
                _ = format.ComputeWrapInput("password", parameter);
        }
    }

    [Theory]
    [MemberData(nameof(FormatIndexes))]
    public void Random_wrap_parameters_only_throw_format_exception(int index)
    {
        ILegacyHashFormat format = Seeds[index].Format;
        if (!format.TryExtractWrapInput(Seeds[index].Valid, out _, out byte[] parameter))
            return; // argon2-phc

        var random = new Random(index);
        for (int n = 0; n < 200; n++)
        {
            byte[] p = (byte[])parameter.Clone();
            if (p.Length > 0)
                p[random.Next(p.Length)] = (byte)random.Next(256);
            if (n % 5 == 0)
                Array.Resize(ref p, random.Next(p.Length + 3));
            try
            {
                format.ComputeWrapInput("password", p);
            }
            catch (FormatException)
            {
            }
        }
    }

    [Fact]
    public void Hasher_with_all_formats_never_throws_on_garbage()
    {
        PasswordHasher hasher = AllFormats();
        foreach (string garbage in Garbage())
        {
            PasswordVerificationResult result = hasher.Verify("pw", garbage);
            Assert.False(result.IsMatch);
            Assert.NotEqual(VerificationFailureReason.None, result.FailureReason);
            _ = hasher.Inspect(garbage);
            Assert.False(hasher.TryWrap(garbage, out _));
        }
    }
}
