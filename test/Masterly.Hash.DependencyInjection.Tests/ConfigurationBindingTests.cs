using System;
using System.Collections.Generic;
using System.Threading;
using Masterly.Hash.Pepper;
using Masterly.Hash.Primitives;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Masterly.Hash.DependencyInjection.Tests;

public class ConfigurationBindingTests
{
    private static PasswordHasherOptions OptionsFrom(IConfiguration section, Action<PasswordHasherOptions>? configure = null)
    {
        var services = new ServiceCollection();
        services.AddMasterlyHash(section, configure);
        using ServiceProvider provider = services.BuildServiceProvider();
        return provider.GetRequiredService<IOptions<PasswordHasherOptions>>().Value;
    }

    [Fact]
    public void Binds_every_setting()
    {
        IConfiguration config = TestSupport.Config(new Dictionary<string, string?>
        {
            ["MasterlyHash:DefaultProfile"] = "2026f",
            ["MasterlyHash:MaxConcurrency"] = "7",
            ["MasterlyHash:ConcurrencyTimeout"] = "00:00:05",
            ["MasterlyHash:MaxPasswordBytes"] = "256",
            ["MasterlyHash:ComputeRehashOnVerify"] = "false",
            ["MasterlyHash:Pepper:CurrentKeyId"] = "k2",
            ["MasterlyHash:Pepper:Keys:k1"] = TestSupport.KeyB64("k1"),
            ["MasterlyHash:Pepper:Keys:k2"] = TestSupport.KeyB64("k2"),
        });

        PasswordHasherOptions options = OptionsFrom(config.GetSection("MasterlyHash"));

        Assert.Same(HashProfile.Fips2026a, options.DefaultProfile);
        Assert.Equal(7, options.MaxConcurrency);
        Assert.Equal(TimeSpan.FromSeconds(5), options.ConcurrencyTimeout);
        Assert.Equal(256, options.MaxPasswordBytes);
        Assert.False(options.ComputeRehashOnVerify);
        HmacPepper pepper = Assert.IsType<HmacPepper>(options.Pepper);
        Assert.Equal("k2", pepper.CurrentKeyId);
        Assert.True(pepper.IsKnownKey("k1"));
        Assert.True(pepper.IsKnownKey("k2"));
        Assert.False(pepper.IsKnownKey("k3"));
    }

    [Theory]
    [InlineData("2026a")]
    [InlineData("2026c")]
    [InlineData("2026f")]
    [InlineData(" 2026c ")]
    public void Maps_built_in_profile_ids(string id)
    {
        IConfiguration config = TestSupport.Config(new Dictionary<string, string?> { ["MasterlyHash:DefaultProfile"] = id });

        PasswordHasherOptions options = OptionsFrom(config.GetSection("MasterlyHash"));

        Assert.Equal(id.Trim(), options.DefaultProfile.Id);
        Assert.True(options.DefaultProfile.MeetsRecommendedMinimum);
    }

    [Fact]
    public void Missing_section_keeps_defaults()
    {
        IConfiguration config = TestSupport.Config(new Dictionary<string, string?>());
        var defaults = new PasswordHasherOptions();

        PasswordHasherOptions options = OptionsFrom(config.GetSection("MasterlyHash"));

        Assert.Same(HashProfile.Server2026a, options.DefaultProfile);
        Assert.Equal(defaults.MaxConcurrency, options.MaxConcurrency);
        Assert.Equal(defaults.ConcurrencyTimeout, options.ConcurrencyTimeout);
        Assert.Equal(defaults.MaxPasswordBytes, options.MaxPasswordBytes);
        Assert.True(options.ComputeRehashOnVerify);
        Assert.Null(options.Pepper);
    }

    [Fact]
    public void Empty_pepper_section_means_no_pepper()
    {
        IConfiguration config = TestSupport.Config(new Dictionary<string, string?> { ["MasterlyHash:Pepper:CurrentKeyId"] = "" });

        Assert.Null(OptionsFrom(config.GetSection("MasterlyHash")).Pepper);
    }

    [Fact]
    public void Binds_from_json_including_infinite_timeout()
    {
        string json = $$"""
            {
              "MasterlyHash": {
                "DefaultProfile": "2026c",
                "MaxConcurrency": 0,
                "ConcurrencyTimeout": "-00:00:00.001",
                "Pepper": { "CurrentKeyId": "2026-01", "Keys": { "2026-01": "{{TestSupport.KeyB64("j")}}" } }
              }
            }
            """;

        PasswordHasherOptions options = OptionsFrom(TestSupport.Json(json).GetSection("MasterlyHash"));

        Assert.Same(HashProfile.Constrained2026a, options.DefaultProfile);
        Assert.Equal(0, options.MaxConcurrency);
        Assert.Equal(Timeout.InfiniteTimeSpan, options.ConcurrencyTimeout);
        Assert.Equal("2026-01", options.Pepper!.CurrentKeyId);
    }

    [Fact]
    public void Accepts_unpadded_base64_keys()
    {
        byte[] key = TestSupport.Key("u");
        string unpadded = HashPrimitives.ToB64(key);
        Assert.DoesNotContain("=", unpadded, StringComparison.Ordinal);
        IConfiguration config = TestSupport.Config(new Dictionary<string, string?>
        {
            ["MasterlyHash:Pepper:CurrentKeyId"] = "u",
            ["MasterlyHash:Pepper:Keys:u"] = unpadded,
        });

        PasswordHasherOptions options = OptionsFrom(config.GetSection("MasterlyHash"), TestSupport.UseFast);
        var expected = new HmacPepper("u", key);

        byte[] input = { 1, 2, 3 };
        Assert.Equal(expected.Apply("u", input), options.Pepper!.Apply("u", input));
    }

    [Fact]
    public void Configured_pepper_uses_the_configured_key_bytes()
    {
        using ServiceProvider provider = TestSupport.BuildFromConfig(new Dictionary<string, string?>
        {
            ["MasterlyHash:Pepper:CurrentKeyId"] = "k1",
            ["MasterlyHash:Pepper:Keys:k1"] = TestSupport.KeyB64("k1"),
        });
        IPasswordHasher fromConfig = provider.GetRequiredService<IPasswordHasher>();
        var direct = new PasswordHasher(new PasswordHasherOptions
        {
            DefaultProfile = TestSupport.Fast,
            AllowWeakProfiles = true,
            Pepper = new HmacPepper("k1", TestSupport.Key("k1")),
        });

        string hash = fromConfig.Hash("s3cret!");

        Assert.Contains(",k=k1$", hash, StringComparison.Ordinal);
        Assert.True(direct.Verify("s3cret!", hash).IsMatch);
        Assert.True(fromConfig.Verify("s3cret!", direct.Hash("s3cret!")).IsMatch);
    }

    [Fact]
    public void Pepper_key_rotation_through_configuration()
    {
        string oldHash;
        using (ServiceProvider before = TestSupport.BuildFromConfig(new Dictionary<string, string?>
        {
            ["MasterlyHash:Pepper:CurrentKeyId"] = "k1",
            ["MasterlyHash:Pepper:Keys:k1"] = TestSupport.KeyB64("k1"),
        }))
        {
            oldHash = before.GetRequiredService<IPasswordHasher>().Hash("rotate me");
        }

        using ServiceProvider after = TestSupport.BuildFromConfig(new Dictionary<string, string?>
        {
            ["MasterlyHash:Pepper:CurrentKeyId"] = "k2",
            ["MasterlyHash:Pepper:Keys:k1"] = TestSupport.KeyB64("k1"),
            ["MasterlyHash:Pepper:Keys:k2"] = TestSupport.KeyB64("k2"),
        });
        IPasswordHasher hasher = after.GetRequiredService<IPasswordHasher>();

        PasswordVerificationResult result = hasher.Verify("rotate me", oldHash);

        Assert.True(result.IsMatch);
        Assert.True(result.NeedsRehash);
        Assert.Equal(RehashReason.OutdatedPepperKey, result.RehashReason);
        Assert.Contains(",k=k2$", result.Rehash, StringComparison.Ordinal);
        Assert.True(hasher.Verify("rotate me", result.Rehash!).IsMatch);
    }

    [Fact]
    public void Removing_a_retired_key_fails_verification_without_throwing()
    {
        string oldHash;
        using (ServiceProvider before = TestSupport.BuildFromConfig(new Dictionary<string, string?>
        {
            ["MasterlyHash:Pepper:CurrentKeyId"] = "k1",
            ["MasterlyHash:Pepper:Keys:k1"] = TestSupport.KeyB64("k1"),
        }))
        {
            oldHash = before.GetRequiredService<IPasswordHasher>().Hash("gone");
        }

        using ServiceProvider after = TestSupport.BuildFromConfig(new Dictionary<string, string?>
        {
            ["MasterlyHash:Pepper:CurrentKeyId"] = "k2",
            ["MasterlyHash:Pepper:Keys:k2"] = TestSupport.KeyB64("k2"),
        });

        PasswordVerificationResult result = after.GetRequiredService<IPasswordHasher>().Verify("gone", oldHash);

        Assert.False(result.IsMatch);
        Assert.Equal(VerificationFailureReason.UnknownPepperKey, result.FailureReason);
    }

    [Fact]
    public void Configure_callback_overrides_configuration()
    {
        IConfiguration config = TestSupport.Config(new Dictionary<string, string?>
        {
            ["MasterlyHash:DefaultProfile"] = "2026f",
            ["MasterlyHash:MaxConcurrency"] = "7",
        });

        PasswordHasherOptions options = OptionsFrom(config.GetSection("MasterlyHash"), o =>
        {
            o.DefaultProfile = HashProfile.Constrained2026a;
            o.MaxConcurrency = 2;
        });

        Assert.Same(HashProfile.Constrained2026a, options.DefaultProfile);
        Assert.Equal(2, options.MaxConcurrency);
    }

    [Fact]
    public void Builder_calls_override_configuration()
    {
        var pepper = new HmacPepper("code", TestSupport.Key("code"));
        using ServiceProvider provider = TestSupport.BuildFromConfig(
            new Dictionary<string, string?>
            {
                ["MasterlyHash:DefaultProfile"] = "2026a",
                ["MasterlyHash:Pepper:CurrentKeyId"] = "cfg",
                ["MasterlyHash:Pepper:Keys:cfg"] = TestSupport.KeyB64("cfg"),
            },
            b => b.UseProfile(TestSupport.Fast2).WithPepper(pepper));

        PasswordHasherOptions options = provider.GetRequiredService<IOptions<PasswordHasherOptions>>().Value;

        Assert.Same(TestSupport.Fast2, options.DefaultProfile);
        Assert.Same(pepper, options.Pepper);
    }

    [Fact]
    public void Builder_steps_registered_before_configuration_still_override_it()
    {
        var pepper = new HmacPepper("code", TestSupport.Key("code"));
        IConfiguration config = TestSupport.Config(new Dictionary<string, string?>
        {
            ["MasterlyHash:DefaultProfile"] = "2026f",
            ["MasterlyHash:MaxConcurrency"] = "7",
            ["MasterlyHash:Pepper:CurrentKeyId"] = "cfg",
            ["MasterlyHash:Pepper:Keys:cfg"] = TestSupport.KeyB64("cfg"),
        });
        var services = new ServiceCollection();
        services.Configure<PasswordHasherOptions>(o => o.MaxConcurrency = 3);
        services.AddMasterlyHash().WithPepper(pepper).UseProfile(HashProfile.Constrained2026a);
        services.AddMasterlyHash(config.GetSection("MasterlyHash"));
        using ServiceProvider provider = services.BuildServiceProvider();

        PasswordHasherOptions options = provider.GetRequiredService<IOptions<PasswordHasherOptions>>().Value;

        Assert.Same(pepper, options.Pepper);
        Assert.Same(HashProfile.Constrained2026a, options.DefaultProfile);
        Assert.Equal(3, options.MaxConcurrency);
    }

    [Fact]
    public void Pepper_factory_registered_before_configuration_is_not_replaced_by_a_configured_key()
    {
        var kms = new HmacPepper("kms", TestSupport.Key("kms"));
        IConfiguration config = TestSupport.Config(new Dictionary<string, string?>
        {
            ["MasterlyHash:Pepper:CurrentKeyId"] = "local",
            ["MasterlyHash:Pepper:Keys:local"] = TestSupport.KeyB64("local"),
        });
        var services = new ServiceCollection();
        services.AddMasterlyHash(TestSupport.UseFast).WithPepper(_ => kms);
        services.AddMasterlyHash(config.GetSection("MasterlyHash"));
        using ServiceProvider provider = services.BuildServiceProvider();

        Assert.Contains(",k=kms$", provider.GetRequiredService<IPasswordHasher>().Hash("pw"), StringComparison.Ordinal);
    }

    [Fact]
    public void Configuration_values_still_apply_where_code_does_not_override_them()
    {
        IConfiguration config = TestSupport.Config(new Dictionary<string, string?> { ["MasterlyHash:MaxPasswordBytes"] = "300" });
        var services = new ServiceCollection();
        services.AddMasterlyHash(TestSupport.UseFast);
        services.AddMasterlyHash(config.GetSection("MasterlyHash"));
        using ServiceProvider provider = services.BuildServiceProvider();

        PasswordHasherOptions options = provider.GetRequiredService<IOptions<PasswordHasherOptions>>().Value;

        Assert.Equal(300, options.MaxPasswordBytes);
        Assert.Same(TestSupport.Fast, options.DefaultProfile);
    }

    [Fact]
    public void Configuration_model_is_available_through_options()
    {
        IConfiguration config = TestSupport.Config(new Dictionary<string, string?> { ["MasterlyHash:MaxPasswordBytes"] = "512" });
        var services = new ServiceCollection();
        services.AddMasterlyHash(config.GetSection("MasterlyHash"));
        using ServiceProvider provider = services.BuildServiceProvider();

        MasterlyHashConfiguration model = provider.GetRequiredService<IOptions<MasterlyHashConfiguration>>().Value;

        Assert.Equal(512, model.MaxPasswordBytes);
        Assert.Null(model.DefaultProfile);
        Assert.Null(model.MaxConcurrency);
    }

    [Fact]
    public void Adding_configuration_twice_maps_it_once()
    {
        IConfiguration config = TestSupport.Config(new Dictionary<string, string?> { ["MasterlyHash:MaxConcurrency"] = "5" });
        var services = new ServiceCollection();
        services.AddMasterlyHash(config.GetSection("MasterlyHash"));
        services.AddMasterlyHash(config.GetSection("MasterlyHash"));

        Assert.Single(services, d => d.ServiceType == typeof(IValidateOptions<MasterlyHashConfiguration>));
        Assert.Single(services, d => d.ImplementationType == typeof(Internal.ConfigurationOptionsSetup));
        using ServiceProvider provider = services.BuildServiceProvider();
        Assert.Equal(5, provider.GetRequiredService<IOptions<PasswordHasherOptions>>().Value.MaxConcurrency);
    }
}
