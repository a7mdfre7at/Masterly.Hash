using System;
using System.Collections.Generic;
using System.Threading;
using Masterly.Hash.DependencyInjection.Internal;
using Masterly.Hash.Pepper;
using Microsoft.Extensions.Options;

namespace Masterly.Hash.DependencyInjection.Tests;

/// <summary>
/// <see cref="ConfigurationOptionsSetup"/> on its own. In the container the configuration validator runs first; these
/// tests use <see cref="Options.Create{TOptions}"/>, which skips validation, to check the setup's own guards.
/// </summary>
public class ConfigurationOptionsSetupTests
{
    private static PasswordHasherOptions Configure(MasterlyHashConfiguration config)
    {
        var options = new PasswordHasherOptions();
        new ConfigurationOptionsSetup(Options.Create(config)).Configure(options);
        return options;
    }

    [Fact]
    public void Null_configuration_throws()
    {
        Assert.Equal("configuration", Assert.Throws<ArgumentNullException>(() => new ConfigurationOptionsSetup(null!)).ParamName);
    }

    [Fact]
    public void Null_options_throw()
    {
        var setup = new ConfigurationOptionsSetup(Options.Create(new MasterlyHashConfiguration()));
        Assert.Equal("options", Assert.Throws<ArgumentNullException>(() => setup.Configure(null!)).ParamName);
    }

    [Fact]
    public void Empty_configuration_leaves_the_defaults()
    {
        var defaults = new PasswordHasherOptions();

        PasswordHasherOptions options = Configure(new MasterlyHashConfiguration());

        Assert.Same(defaults.DefaultProfile, options.DefaultProfile);
        Assert.Equal(defaults.MaxConcurrency, options.MaxConcurrency);
        Assert.Equal(defaults.ConcurrencyTimeout, options.ConcurrencyTimeout);
        Assert.Equal(defaults.MaxPasswordBytes, options.MaxPasswordBytes);
        Assert.Equal(defaults.ComputeRehashOnVerify, options.ComputeRehashOnVerify);
        Assert.Null(options.Pepper);
    }

    [Fact]
    public void Every_setting_is_mapped_and_ids_are_trimmed()
    {
        PasswordHasherOptions options = Configure(new MasterlyHashConfiguration
        {
            DefaultProfile = " 2026c ",
            MaxConcurrency = 3,
            ConcurrencyTimeout = TimeSpan.FromSeconds(7),
            MaxPasswordBytes = 256,
            ComputeRehashOnVerify = false,
            Pepper = new MasterlyHashPepperConfiguration
            {
                CurrentKeyId = " k2 ",
                Keys = new Dictionary<string, string> { ["k1"] = TestSupport.KeyB64("k1"), ["k2"] = TestSupport.KeyB64("k2") },
            },
        });

        Assert.Same(HashProfile.Constrained2026a, options.DefaultProfile);
        Assert.Equal(3, options.MaxConcurrency);
        Assert.Equal(TimeSpan.FromSeconds(7), options.ConcurrencyTimeout);
        Assert.Equal(256, options.MaxPasswordBytes);
        Assert.False(options.ComputeRehashOnVerify);
        HmacPepper pepper = Assert.IsType<HmacPepper>(options.Pepper);
        Assert.Equal("k2", pepper.CurrentKeyId);
        Assert.True(pepper.IsKnownKey("k1"));
        Assert.Equal(new HmacPepper("k1", TestSupport.Key("k1")).Apply("k1", new byte[] { 1 }), pepper.Apply("k1", new byte[] { 1 }));
    }

    [Fact]
    public void Infinite_concurrency_timeout_is_mapped()
    {
        Assert.Equal(Timeout.InfiniteTimeSpan, Configure(new MasterlyHashConfiguration { ConcurrencyTimeout = Timeout.InfiniteTimeSpan }).ConcurrencyTimeout);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Blank_default_profile_keeps_the_default(string? value)
    {
        Assert.Same(HashProfile.Server2026a, Configure(new MasterlyHashConfiguration { DefaultProfile = value }).DefaultProfile);
    }

    [Fact]
    public void Pepper_with_no_current_key_and_null_keys_is_treated_as_absent()
    {
        PasswordHasherOptions options = Configure(new MasterlyHashConfiguration
        {
            Pepper = new MasterlyHashPepperConfiguration { CurrentKeyId = null, Keys = null! },
        });

        Assert.Null(options.Pepper);
    }

    [Theory]
    [InlineData("not base64!")]
    [InlineData("")]
    [InlineData(null)]
    public void Undecodable_key_that_bypassed_validation_throws_without_echoing_it(string? keyText)
    {
        var config = new MasterlyHashConfiguration
        {
            Pepper = new MasterlyHashPepperConfiguration
            {
                CurrentKeyId = "k1",
                Keys = new Dictionary<string, string> { ["k1"] = keyText! },
            },
        };

        var ex = Assert.Throws<InvalidOperationException>(() => Configure(config));

        Assert.Equal("MasterlyHash:Pepper:Keys:k1 is not a valid pepper key.", ex.Message);
    }

    [Fact]
    public void Oversized_key_that_bypassed_validation_throws()
    {
        var config = new MasterlyHashConfiguration
        {
            Pepper = new MasterlyHashPepperConfiguration
            {
                CurrentKeyId = "k1",
                Keys = new Dictionary<string, string> { ["k1"] = Convert.ToBase64String(new byte[PepperKeyDecoder.MaxKeyLength + 1]) },
            },
        };

        Assert.Contains("Keys:k1", Assert.Throws<InvalidOperationException>(() => Configure(config)).Message, StringComparison.Ordinal);
    }
}
