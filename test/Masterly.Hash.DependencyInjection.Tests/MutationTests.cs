using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Runtime.Loader;
using Masterly.Hash.DependencyInjection.Internal;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Masterly.Hash.DependencyInjection.Tests;

/// <summary>
/// Precise assertions (exact messages, boundaries, parameter names, descriptor order) that pin behaviour the broader
/// tests only touch loosely.
/// </summary>
public class MutationTests
{
    private const string TimeoutRule = "must be positive and at most 24.20:31:23.6470000, or infinite (-00:00:00.001)";
    private const string KeyIdRule = "^[A-Za-z0-9-]{1,32}$";

    private static readonly PasswordHasherOptionsValidator Validator = new();
    private static readonly MasterlyHashConfigurationValidator ConfigValidator = new();

    private static string[] Failures(ValidateOptionsResult result) => result.Failures?.ToArray() ?? Array.Empty<string>();

    private static string[] OptionsFailures(Action<PasswordHasherOptions> configure)
    {
        var options = new PasswordHasherOptions();
        configure(options);
        return Failures(Validator.Validate(null, options));
    }

    private static string[] ConfigFailures(MasterlyHashConfiguration config) => Failures(ConfigValidator.Validate(null, config));

    private static MasterlyHashConfiguration PepperConfig(string? currentKeyId, Dictionary<string, string> keys) =>
        new() { Pepper = new MasterlyHashPepperConfiguration { CurrentKeyId = currentKeyId, Keys = keys } };

    // ---- Ids ----

    [Fact]
    public void Concurrency_timeout_rule_text_is_exact()
    {
        Assert.Equal(TimeoutRule, Ids.ConcurrencyTimeoutRule);
    }

    [Fact]
    public void Concurrency_timeout_rule_text_is_exact_in_a_fresh_load_of_the_assembly()
    {
        // A static field initializer runs once per load, so a test host that is reused across runs keeps the first value.
        // A fresh collectible load runs the Ids initializers again and the text is checked once more.
        var context = new AssemblyLoadContext("fresh-ids", isCollectible: true);
        try
        {
            Assembly fresh = context.LoadFromAssemblyPath(typeof(Ids).Assembly.Location);
            Assert.NotSame(typeof(Ids).Assembly, fresh);
            Type ids = fresh.GetType(typeof(Ids).FullName!, throwOnError: true)!;
            FieldInfo field = ids.GetField(nameof(Ids.ConcurrencyTimeoutRule), BindingFlags.Public | BindingFlags.Static)!;

            Assert.Equal(TimeoutRule, field.GetValue(null));
        }
        finally
        {
            context.Unload();
        }
    }

    // ---- PasswordHasherOptionsValidator messages ----

    [Fact]
    public void Options_validator_reports_null_additional_profile_with_exact_message()
    {
        Assert.Equal(
            new[] { "PasswordHasherOptions.AdditionalProfiles contains null." },
            OptionsFailures(o => o.AdditionalProfiles.Add(null!)));
    }

    [Fact]
    public void Options_validator_reports_null_legacy_format_with_exact_message()
    {
        Assert.Equal(
            new[] { "PasswordHasherOptions.LegacyFormats contains null." },
            OptionsFailures(o => o.LegacyFormats.Add(null!)));
    }

    [Fact]
    public void Options_validator_reports_max_password_bytes_with_exact_message()
    {
        Assert.Equal(
            new[] { "PasswordHasherOptions.MaxPasswordBytes must be between 64 and 1048576." },
            OptionsFailures(o => o.MaxPasswordBytes = 63));
    }

    [Fact]
    public void Options_validator_reports_concurrency_timeout_with_exact_message()
    {
        Assert.Equal(
            new[] { "PasswordHasherOptions.ConcurrencyTimeout " + TimeoutRule + "." },
            OptionsFailures(o => o.ConcurrencyTimeout = TimeSpan.Zero));
    }

    // ---- MasterlyHashConfigurationValidator messages and boundaries ----

    [Fact]
    public void Config_validator_echoes_an_unknown_profile_id_that_looks_like_an_id()
    {
        Assert.Equal(
            new[] { "MasterlyHash:DefaultProfile 'unknown-x' is not a known profile. Known profiles: 2026a, 2026c, 2026f." },
            ConfigFailures(new MasterlyHashConfiguration { DefaultProfile = " unknown-x " }));
    }

    [Fact]
    public void Config_validator_does_not_echo_an_unknown_profile_that_is_not_an_id()
    {
        Assert.Equal(
            new[] { "MasterlyHash:DefaultProfile is not a known profile. Known profiles: 2026a, 2026c, 2026f." },
            ConfigFailures(new MasterlyHashConfiguration { DefaultProfile = "Secret Value!" }));
    }

    [Theory]
    [InlineData(64)]
    [InlineData(1024 * 1024)]
    public void Config_validator_accepts_max_password_bytes_at_the_limits(int value)
    {
        Assert.Empty(ConfigFailures(new MasterlyHashConfiguration { MaxPasswordBytes = value }));
    }

    [Theory]
    [InlineData(63)]
    [InlineData(1024 * 1024 + 1)]
    public void Config_validator_rejects_max_password_bytes_just_outside_the_limits(int value)
    {
        Assert.Equal(
            new[] { "MasterlyHash:MaxPasswordBytes must be between 64 and 1048576." },
            ConfigFailures(new MasterlyHashConfiguration { MaxPasswordBytes = value }));
    }

    [Fact]
    public void Config_validator_reports_concurrency_timeout_with_exact_message()
    {
        Assert.Equal(
            new[] { "MasterlyHash:ConcurrencyTimeout " + TimeoutRule + "." },
            ConfigFailures(new MasterlyHashConfiguration { ConcurrencyTimeout = TimeSpan.Zero }));
    }

    [Fact]
    public void Config_validator_reports_only_the_malformed_current_key_id_and_never_echoes_it()
    {
        string[] failures = ConfigFailures(PepperConfig("bad id", new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["k1"] = TestSupport.KeyB64("k1"),
        }));

        Assert.Equal(new[] { "MasterlyHash:Pepper:CurrentKeyId must match " + KeyIdRule + "." }, failures);
    }

    [Fact]
    public void Config_validator_reports_an_empty_key_ring_once()
    {
        Assert.Equal(
            new[] { "MasterlyHash:Pepper:Keys must contain at least one key." },
            ConfigFailures(PepperConfig("k1", new Dictionary<string, string>(StringComparer.Ordinal))));
    }

    [Fact]
    public void Config_validator_reports_a_malformed_key_id_without_inspecting_its_value()
    {
        string[] failures = ConfigFailures(PepperConfig("k1", new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["k1"] = TestSupport.KeyB64("k1"),
            ["bad id"] = "not base64!",
        }));

        Assert.Equal(new[] { "A MasterlyHash:Pepper:Keys entry has an id that does not match " + KeyIdRule + "." }, failures);
    }

    [Fact]
    public void Config_validator_reports_a_current_key_missing_from_the_ring()
    {
        string[] failures = ConfigFailures(PepperConfig("k2", new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["k1"] = TestSupport.KeyB64("k1"),
        }));

        Assert.Equal(new[] { "MasterlyHash:Pepper:CurrentKeyId 'k2' is not in MasterlyHash:Pepper:Keys." }, failures);
    }

    // ---- PepperKeyDecoder ----

    [Fact]
    public void Full_quantum_unpadded_key_with_embedded_whitespace_decodes_like_Convert()
    {
        // 33 bytes encode to 44 characters with no padding; 4 embedded spaces keep the length a multiple of 4,
        // so the value takes the Convert.FromBase64String path, which ignores whitespace.
        byte[] expected = Enumerable.Range(1, 33).Select(i => (byte)i).ToArray();
        string b64 = Convert.ToBase64String(expected);
        Assert.Equal(44, b64.Length);
        Assert.DoesNotContain('=', b64);
        string spaced = b64.Substring(0, 20) + "    " + b64.Substring(20);

        Assert.Equal(PepperKeyDecodeResult.Ok, PepperKeyDecoder.TryDecode(spaced, out byte[] key));
        Assert.Equal(expected, key);
    }

    [Fact]
    public void Padded_key_with_embedded_whitespace_decodes_like_Convert()
    {
        // Padded text always takes the Convert.FromBase64String path, even when whitespace makes its length odd.
        byte[] expected = TestSupport.Key("k1");
        string b64 = Convert.ToBase64String(expected);
        Assert.EndsWith("=", b64, StringComparison.Ordinal);
        string spaced = b64.Substring(0, 20) + " " + b64.Substring(20);
        Assert.NotEqual(0, spaced.Length % 4);

        Assert.Equal(PepperKeyDecodeResult.Ok, PepperKeyDecoder.TryDecode(spaced, out byte[] key));
        Assert.Equal(expected, key);
    }

    [Fact]
    public void Unpadded_key_takes_the_strict_decoder()
    {
        byte[] expected = TestSupport.Key("k1");
        string unpadded = Convert.ToBase64String(expected).TrimEnd('=');

        Assert.Equal(PepperKeyDecodeResult.Ok, PepperKeyDecoder.TryDecode(unpadded, out byte[] key));
        Assert.Equal(expected, key);
        Assert.Equal(PepperKeyDecodeResult.NotBase64, PepperKeyDecoder.TryDecode(unpadded.Substring(0, 20) + " " + unpadded.Substring(20), out byte[] rejected));
        Assert.Empty(rejected);
    }

    [Theory]
    [InlineData("=AA")]
    [InlineData("=AAAA")]
    [InlineData("=")]
    public void Leading_padding_is_rejected(string value)
    {
        Assert.Equal(PepperKeyDecodeResult.NotBase64, PepperKeyDecoder.TryDecode(value, out byte[] key));
        Assert.Empty(key);
    }

    // ---- MasterlyHashBuilder ----

    [Fact]
    public void Builder_configure_null_reports_its_own_parameter_name()
    {
        MasterlyHashBuilder builder = new ServiceCollection().AddMasterlyHash();

        Assert.Equal("configure", Assert.Throws<ArgumentNullException>(() => builder.Configure(null!)).ParamName);
        Assert.Equal("configure", Assert.Throws<ArgumentNullException>(() => builder.Configure<IServiceProvider>(null!)).ParamName);
    }

    [Fact]
    public void Legacy_format_factory_returning_null_fails_with_exact_message()
    {
        var services = new ServiceCollection();
        services.AddMasterlyHash(TestSupport.UseFast).AddLegacyFormat(_ => null!);
        using ServiceProvider provider = services.BuildServiceProvider();

        InvalidOperationException ex = Assert.Throws<InvalidOperationException>(() => provider.GetRequiredService<IPasswordHasher>());
        Assert.Equal("The legacy format factory returned null.", ex.Message);
    }

    // ---- AddMasterlyHash ----

    [Fact]
    public void Null_configuration_reports_its_parameter_name_and_registers_nothing()
    {
        var services = new ServiceCollection();

        ArgumentNullException ex = Assert.Throws<ArgumentNullException>(() => services.AddMasterlyHash((IConfiguration)null!));

        Assert.Equal("configuration", ex.ParamName);
        Assert.Empty(services);
    }

    [Fact]
    public void Null_services_and_provider_report_their_parameter_names()
    {
        Assert.Equal("services", Assert.Throws<ArgumentNullException>(() => ((IServiceCollection)null!).AddMasterlyHash()).ParamName);
        Assert.Equal("services", Assert.Throws<ArgumentNullException>(
            () => ((IServiceCollection)null!).AddMasterlyHash(TestSupport.Config(new Dictionary<string, string?>()))).ParamName);
        Assert.Equal("provider", Assert.Throws<ArgumentNullException>(() => ((IServiceProvider)null!).ValidateMasterlyHash()).ParamName);
    }

    [Fact]
    public void Foreign_registration_message_is_exact()
    {
        var services = new ServiceCollection();
        services.AddSingleton(new PasswordHasher(new PasswordHasherOptions { DefaultProfile = TestSupport.Fast, AllowWeakProfiles = true }));

        InvalidOperationException ex = Assert.Throws<InvalidOperationException>(() => services.AddMasterlyHash());

        Assert.Equal(
            "PasswordHasher is already registered, so AddMasterlyHash would configure a hasher that is never injected. " +
            "Remove the existing registration, or register an IPasswordHasher decorator after calling AddMasterlyHash.",
            ex.Message);
    }

    [Fact]
    public void PasswordHasher_override_registered_after_AddMasterlyHash_survives_a_second_call()
    {
        var custom = new PasswordHasher(new PasswordHasherOptions { DefaultProfile = TestSupport.Fast, AllowWeakProfiles = true });
        var services = new ServiceCollection();
        services.AddMasterlyHash(TestSupport.UseFast);
        services.AddSingleton(custom);

        services.AddMasterlyHash();
        services.AddMasterlyHash(TestSupport.Config(new Dictionary<string, string?>()).GetSection("MasterlyHash"));

        using ServiceProvider provider = services.BuildServiceProvider();
        Assert.Same(custom, provider.GetRequiredService<PasswordHasher>());
        Assert.Same(custom, provider.GetRequiredService<IPasswordHasher>());
    }

    [Fact]
    public void Configuration_runs_before_a_code_step_registered_first_in_the_collection()
    {
        var values = new Dictionary<string, string?> { ["MasterlyHash:MaxPasswordBytes"] = "300", ["MasterlyHash:MaxConcurrency"] = "7" };
        var services = new ServiceCollection();
        // First code configure step in the collection (behind the options infrastructure services.Configure adds).
        services.Configure<PasswordHasherOptions>(o => o.MaxPasswordBytes = 500);
        services.AddMasterlyHash(TestSupport.UseFast);

        services.AddMasterlyHash(TestSupport.Config(values).GetSection("MasterlyHash"));

        using ServiceProvider provider = services.BuildServiceProvider();
        PasswordHasherOptions options = provider.GetRequiredService<IOptions<PasswordHasherOptions>>().Value;
        Assert.Equal(500, options.MaxPasswordBytes);
        Assert.Equal(7, options.MaxConcurrency);
    }

    [Fact]
    public void Configuration_setup_is_appended_when_there_is_no_code_step()
    {
        var services = new ServiceCollection();
        services.AddSingleton(new FakeKeyStore());

        services.AddMasterlyHash(TestSupport.Config(new Dictionary<string, string?>()).GetSection("MasterlyHash"));

        Assert.Equal(typeof(FakeKeyStore), services[0].ServiceType);
        ServiceDescriptor last = services[services.Count - 1];
        Assert.Equal(typeof(IConfigureOptions<PasswordHasherOptions>), last.ServiceType);
        Assert.Equal(typeof(ConfigurationOptionsSetup), last.ImplementationType);
    }

    [Fact]
    public void Configuration_setup_is_inserted_immediately_before_the_first_code_step()
    {
        var services = new ServiceCollection();
        services.AddSingleton(new FakeKeyStore());
        services.AddMasterlyHash(TestSupport.UseFast);
        int firstStep = IndexOfFirstStep(services);
        ServiceDescriptor step = services[firstStep];
        Assert.True(firstStep > 0);

        services.AddMasterlyHash(TestSupport.Config(new Dictionary<string, string?>()).GetSection("MasterlyHash"));

        Assert.Equal(typeof(FakeKeyStore), services[0].ServiceType);
        Assert.Equal(typeof(ConfigurationOptionsSetup), services[firstStep].ImplementationType);
        Assert.Same(step, services[firstStep + 1]);
    }

    [Fact]
    public void Configuration_setup_goes_to_index_zero_when_the_first_code_step_is_the_first_descriptor()
    {
        // services.Configure adds the options infrastructure first, so a raw descriptor is the only way to put a
        // code step at index 0 (firstConfigure == 0: the "< 0" boundary in AddConfigurationSetupFirst).
        var values = new Dictionary<string, string?> { ["MasterlyHash:MaxPasswordBytes"] = "300", ["MasterlyHash:MaxConcurrency"] = "7" };
        var services = new ServiceCollection();
        ServiceDescriptor first = ServiceDescriptor.Singleton<IConfigureOptions<PasswordHasherOptions>>(
            new ConfigureOptions<PasswordHasherOptions>(o => o.MaxPasswordBytes = 500));
        ((ICollection<ServiceDescriptor>)services).Add(first);
        services.AddMasterlyHash(TestSupport.UseFast); // a second, later code step
        int countBefore = services.Count;

        services.AddMasterlyHash(TestSupport.Config(values).GetSection("MasterlyHash"));

        Assert.Equal(typeof(IConfigureOptions<PasswordHasherOptions>), services[0].ServiceType);
        Assert.Equal(typeof(ConfigurationOptionsSetup), services[0].ImplementationType);
        Assert.Same(first, services[1]);
        Assert.Single(services, d => d.ImplementationType == typeof(ConfigurationOptionsSetup));
        Assert.True(services.Count > countBefore);

        using ServiceProvider provider = services.BuildServiceProvider();
        PasswordHasherOptions options = provider.GetRequiredService<IOptions<PasswordHasherOptions>>().Value;
        Assert.Equal(500, options.MaxPasswordBytes);
        Assert.Equal(7, options.MaxConcurrency);
        Assert.Equal(TestSupport.Fast, options.DefaultProfile); // the later code step still runs after configuration
        Assert.True(options.AllowWeakProfiles);
    }

    private static int IndexOfFirstStep(IServiceCollection services)
    {
        for (int i = 0; i < services.Count; i++)
        {
            if (services[i].ServiceType == typeof(IConfigureOptions<PasswordHasherOptions>))
                return i;
        }
        return -1;
    }
}
