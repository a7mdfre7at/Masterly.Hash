using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using Masterly.Hash.Legacy;

namespace Masterly.Hash.Legacy.Tests;

public class LegacyFormatsTests
{
    [Fact]
    public void All_contains_every_default_format_with_unique_valid_ids()
    {
        string[] ids = LegacyFormats.All.Select(f => f.Id).ToArray();
        Assert.Equal(
            new[] { "bcrypt", "wordpress-bcrypt", "argon2-phc", "phpass", "django-pbkdf2", "aspnet-identity-v3", "aspnet-identity-v2", "md5", "sha1", "sha256", "sha512" },
            ids);
        Assert.All(ids, id => Assert.Matches(new Regex("^[a-z0-9][a-z0-9-]{0,31}$"), id));
        Assert.Same(BCryptFormat.Default, LegacyFormats.All[0]);
        Assert.Throws<NotSupportedException>(() => ((IList<ILegacyHashFormat>)LegacyFormats.All).Add(BCryptFormat.Default));
    }

    [Fact]
    public void AddAllLegacyFormats_inserts_ahead_of_v1()
    {
        var options = new PasswordHasherOptions().AddAllLegacyFormats();
        Assert.Equal(LegacyFormats.All.Count + 1, options.LegacyFormats.Count);
        Assert.Same(V1LegacyFormat.Instance, options.LegacyFormats[^1]);
        Assert.Equal(LegacyFormats.All, options.LegacyFormats.Take(LegacyFormats.All.Count));
    }

    [Fact]
    public void Adding_twice_is_idempotent()
    {
        var options = new PasswordHasherOptions().AddAllLegacyFormats().AddAllLegacyFormats().AddLegacyFormats(BCryptFormat.Default);
        Assert.Equal(LegacyFormats.All.Count + 1, options.LegacyFormats.Count);
        _ = new PasswordHasher(options);
    }

    [Fact]
    public void Adding_a_different_instance_with_the_same_id_throws()
    {
        var options = new PasswordHasherOptions().AddLegacyFormats(BCryptFormat.Default);
        Assert.Throws<ArgumentException>(() => options.AddLegacyFormats(new BCryptFormat(12)));
    }

    [Fact]
    public void AddLegacyFormats_is_all_or_nothing()
    {
        var options = new PasswordHasherOptions().AddLegacyFormats(PhpassFormat.Default);
        // bcrypt and argon2-phc are valid, but the phpass clash comes later: nothing may be added.
        Assert.Throws<ArgumentException>(() => options.AddLegacyFormats(BCryptFormat.Default, ExternalArgon2Format.Default, new PhpassFormat(14)));
        Assert.Equal(new[] { "phpass", "v1" }, options.LegacyFormats.Select(f => f.Id));

        Assert.Throws<ArgumentException>(() => options.AddLegacyFormats(BCryptFormat.Default, new BCryptFormat(12)));
        Assert.Throws<ArgumentException>(() => options.AddLegacyFormats(BCryptFormat.Default, null!));
        Assert.Equal(new[] { "phpass", "v1" }, options.LegacyFormats.Select(f => f.Id));

        // The same instance twice in one call is fine.
        options.AddLegacyFormats(BCryptFormat.Default, BCryptFormat.Default);
        Assert.Equal(new[] { "phpass", "bcrypt", "v1" }, options.LegacyFormats.Select(f => f.Id));
    }

    [Fact]
    public void AddAllLegacyFormats_keeps_custom_instances_registered_first()
    {
        var phpass = new PhpassFormat(14);
        var bcrypt = new BCryptFormat(12);
        var options = new PasswordHasherOptions().AddLegacyFormats(phpass, bcrypt).AddAllLegacyFormats();

        Assert.Equal(LegacyFormats.All.Count + 1, options.LegacyFormats.Count);
        Assert.Same(phpass, options.LegacyFormats.Single(f => f.Id == "phpass"));
        Assert.Same(bcrypt, options.LegacyFormats.Single(f => f.Id == "bcrypt"));
        Assert.Equal(options.LegacyFormats.Count, options.LegacyFormats.Select(f => f.Id).Distinct().Count());
        Assert.Same(V1LegacyFormat.Instance, options.LegacyFormats[^1]);
        _ = new PasswordHasher(options);
    }

    [Fact]
    public void Custom_instances_can_replace_defaults()
    {
        var options = new PasswordHasherOptions().AddLegacyFormats(new BCryptFormat(12), new PhpassFormat(14));
        Assert.Equal(new[] { "bcrypt", "phpass", "v1" }, options.LegacyFormats.Select(f => f.Id));
    }

    [Fact]
    public void Works_without_v1_registered()
    {
        var options = new PasswordHasherOptions();
        options.LegacyFormats.Clear();
        options.AddLegacyFormats(UnsaltedDigestFormat.Md5);
        Assert.Same(UnsaltedDigestFormat.Md5, Assert.Single(options.LegacyFormats));
    }

    [Fact]
    public void Guards()
    {
        Assert.Throws<ArgumentNullException>(() => LegacyHashFormatOptionsExtensions.AddLegacyFormats(null!, BCryptFormat.Default));
        Assert.Throws<ArgumentNullException>(() => LegacyHashFormatOptionsExtensions.AddAllLegacyFormats(null!));
        Assert.Throws<ArgumentNullException>(() => new PasswordHasherOptions().AddLegacyFormats(null!));
        Assert.Throws<ArgumentException>(() => new PasswordHasherOptions().AddLegacyFormats(BCryptFormat.Default, null!));
    }

    [Fact]
    public void Sample_hashes_are_claimed_by_exactly_one_format()
    {
        string[] samples =
        {
            "$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW",
            WordPressBcryptFormatTests.WordPressHash("password"),
            "$argon2i$v=19$m=256,t=2,p=1$c29tZXNhbHQ$iekCn0Y3spW+sCcFanM2xBT63UP2sghkUoHLIUpWRS8",
            "$P$9IQRaTwmfeRo7ud9Fh4E2PdI0S3r.L0",
            "pbkdf2_sha256$10000$seasalt$CWWFdHOWwPnki7HvkcqN9iA2T3KLW1cf2uZ5kvArtVY=",
            TestSupport.IdentityV3(1, 1000, TestSupport.Bytes(16, 1), TestSupport.Bytes(32, 2)),
            "5f4dcc3b5aa765d61d8327deb882cf99",
            "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8",
            "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
            "b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86",
        };

        for (int i = 0; i < samples.Length; i++)
        {
            ILegacyHashFormat[] claimants = LegacyFormats.All.Where(f => f.CanHandle(samples[i])).ToArray();
            Assert.Single(claimants);
        }
    }
}
