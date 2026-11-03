using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Masterly.Hash.Pepper;
using Microsoft.Extensions.Options;

namespace Masterly.Hash.DependencyInjection.Tests;

public class ValidatorTests
{
    private static readonly PasswordHasherOptionsValidator Validator = new();
    private static readonly MasterlyHashConfigurationValidator ConfigValidator = new();

    /// <summary>Pepper with an arbitrary current key id, to exercise validation of custom implementations.</summary>
    private sealed class OddPepper : IPasswordPepper
    {
        public OddPepper(string currentKeyId) => CurrentKeyId = currentKeyId;

        public string CurrentKeyId { get; }

        public bool IsKnownKey(string keyId) => keyId == CurrentKeyId;

        public byte[] Apply(string keyId, byte[] input) => (byte[])input.Clone();

        public ValueTask<byte[]> ApplyAsync(string keyId, byte[] input, CancellationToken cancellationToken = default) =>
            new(Apply(keyId, input));
    }

    private static ValidateOptionsResult Validate(Action<PasswordHasherOptions> configure)
    {
        var options = new PasswordHasherOptions();
        configure(options);
        return Validator.Validate(Microsoft.Extensions.Options.Options.DefaultName, options);
    }

    /// <summary>The validator must agree with the PasswordHasher constructor: whenever it passes, construction succeeds; whenever it fails, construction throws.</summary>
    private static void AssertAgreesWithConstructor(Action<PasswordHasherOptions> configure, bool expectedValid)
    {
        var options = new PasswordHasherOptions();
        configure(options);
        ValidateOptionsResult result = Validator.Validate(null, options);

        Assert.Equal(expectedValid, result.Succeeded);
        if (expectedValid)
            Assert.NotNull(new PasswordHasher(options));
        else
            Assert.ThrowsAny<ArgumentException>(() => new PasswordHasher(options));
    }

    [Fact]
    public void Defaults_are_valid()
    {
        Assert.True(Validate(_ => { }).Succeeded);
        AssertAgreesWithConstructor(_ => { }, expectedValid: true);
    }

    [Fact]
    public void Null_options_throw()
    {
        Assert.Throws<ArgumentNullException>(() => Validator.Validate(null, null!));
        Assert.Throws<ArgumentNullException>(() => ConfigValidator.Validate(null, null!));
    }

    [Fact]
    public void Null_default_profile_fails()
    {
        ValidateOptionsResult result = Validate(o => o.DefaultProfile = null!);

        Assert.True(result.Failed);
        Assert.Contains("DefaultProfile is required", result.FailureMessage, StringComparison.Ordinal);
    }

    [Fact]
    public void Weak_profile_requires_AllowWeakProfiles()
    {
        AssertAgreesWithConstructor(o => o.DefaultProfile = TestSupport.Fast, expectedValid: false);
        AssertAgreesWithConstructor(o => o.AdditionalProfiles.Add(TestSupport.Fast), expectedValid: false);
        AssertAgreesWithConstructor(o => { o.DefaultProfile = TestSupport.Fast; o.AllowWeakProfiles = true; }, expectedValid: true);
    }

    [Fact]
    public void Redefining_a_built_in_profile_id_fails()
    {
        HashProfile impostor = HashProfile.Argon2id("2026a", 32768, 4);

        AssertAgreesWithConstructor(o => o.DefaultProfile = impostor, expectedValid: false);
        Assert.Contains("'2026a' is already registered", Validate(o => o.AdditionalProfiles.Add(impostor)).FailureMessage, StringComparison.Ordinal);
    }

    [Fact]
    public void Conflicting_custom_profiles_fail()
    {
        HashProfile a = HashProfile.Argon2id("custom", 32768, 3);
        HashProfile b = HashProfile.Argon2id("custom", 65536, 3);

        AssertAgreesWithConstructor(o => { o.AdditionalProfiles.Add(a); o.DefaultProfile = b; }, expectedValid: false);
        AssertAgreesWithConstructor(o => { o.AdditionalProfiles.Add(a); o.DefaultProfile = a; }, expectedValid: true);
    }

    [Fact]
    public void Null_profile_in_additional_profiles_fails()
    {
        AssertAgreesWithConstructor(o => o.AdditionalProfiles.Add(null!), expectedValid: false);
    }

    [Fact]
    public void Legacy_format_problems_fail()
    {
        AssertAgreesWithConstructor(o => o.LegacyFormats.Add(null!), expectedValid: false);
        AssertAgreesWithConstructor(o => o.LegacyFormats.Add(new TestShaFormat("Bad Id")), expectedValid: false);
        AssertAgreesWithConstructor(o => o.LegacyFormats.Add(new TestShaFormat("v1")), expectedValid: false);
        AssertAgreesWithConstructor(o => o.LegacyFormats.Add(new TestShaFormat("ok-id")), expectedValid: true);
    }

    [Theory]
    [InlineData("")]
    [InlineData("has space")]
    [InlineData("under_score")]
    [InlineData("k1\n")] // a ^...$ regex would accept this
    public void Pepper_with_invalid_current_key_id_fails(string keyId)
    {
        AssertAgreesWithConstructor(o => o.Pepper = new OddPepper(keyId), expectedValid: false);
    }

    [Fact]
    public void Pepper_with_valid_current_key_id_passes()
    {
        AssertAgreesWithConstructor(o => o.Pepper = new OddPepper("Key-2026"), expectedValid: true);
    }

    [Theory]
    [InlineData(63, true)]
    [InlineData(1024 * 1024 + 1, true)]
    [InlineData(64, false)]
    [InlineData(1024 * 1024, false)]
    public void MaxPasswordBytes_range(int value, bool fails)
    {
        AssertAgreesWithConstructor(o => o.MaxPasswordBytes = value, expectedValid: !fails);
    }

    [Fact]
    public void Concurrency_settings_ranges()
    {
        Assert.True(Validate(o => o.MaxConcurrency = -1).Failed);
        Assert.True(Validate(o => o.ConcurrencyTimeout = TimeSpan.Zero).Failed);
        Assert.True(Validate(o => o.ConcurrencyTimeout = TimeSpan.FromSeconds(-1)).Failed);
        Assert.True(Validate(o => { o.MaxConcurrency = 0; o.ConcurrencyTimeout = Timeout.InfiniteTimeSpan; }).Succeeded);
        Assert.True(Validate(o => o.ConcurrencyTimeout = TimeSpan.FromMilliseconds(int.MaxValue)).Succeeded);
    }

    [Theory]
    [InlineData(30)]
    [InlineData(60)]
    [InlineData(3650)]
    public void Concurrency_timeout_above_int_max_milliseconds_fails(int days)
    {
        // Stricter than the core constructor on purpose: SemaphoreSlim.Wait(TimeSpan) and WaitAsync(TimeSpan) throw
        // ArgumentOutOfRangeException for finite timeouts above int.MaxValue ms on .NET 8.
        ValidateOptionsResult result = Validate(o => o.ConcurrencyTimeout = TimeSpan.FromDays(days));
        Assert.True(result.Failed);
        Assert.Contains("ConcurrencyTimeout must be positive and at most 24.20:31:23.647", result.FailureMessage, StringComparison.Ordinal);

        Assert.True(Validate(o => o.ConcurrencyTimeout = TimeSpan.FromMilliseconds(int.MaxValue) + TimeSpan.FromMilliseconds(1)).Failed);
        Assert.True(ConfigValidator.Validate(null, new MasterlyHashConfiguration { ConcurrencyTimeout = TimeSpan.FromDays(days) }).Failed);
    }

    [Fact]
    public void Multiple_problems_are_all_reported()
    {
        ValidateOptionsResult result = Validate(o =>
        {
            o.MaxConcurrency = -1;
            o.MaxPasswordBytes = 1;
            o.ConcurrencyTimeout = TimeSpan.Zero;
        });

        Assert.Equal(3, new List<string>(result.Failures!).Count);
    }

    [Fact]
    public void Configuration_validator_accepts_an_empty_model()
    {
        Assert.True(ConfigValidator.Validate(null, new MasterlyHashConfiguration()).Succeeded);
        Assert.True(ConfigValidator.Validate(null, new MasterlyHashConfiguration { Pepper = new MasterlyHashPepperConfiguration() }).Succeeded);
    }

    [Fact]
    public void Configuration_validator_handles_null_pepper_values_without_throwing()
    {
        var config = new MasterlyHashConfiguration
        {
            Pepper = new MasterlyHashPepperConfiguration { CurrentKeyId = "k1", Keys = new Dictionary<string, string> { ["k1"] = null! } },
        };

        ValidateOptionsResult result = ConfigValidator.Validate(null, config);

        Assert.True(result.Failed);
        Assert.Contains("not valid base64", result.FailureMessage, StringComparison.Ordinal);
    }

    [Fact]
    public void Pepper_with_null_current_key_id_fails()
    {
        AssertAgreesWithConstructor(o => o.Pepper = new OddPepper(null!), expectedValid: false);
        Assert.Contains("CurrentKeyId", Validate(o => o.Pepper = new OddPepper(null!)).FailureMessage, StringComparison.Ordinal);
    }

    [Fact]
    public void Legacy_format_with_null_id_fails()
    {
        AssertAgreesWithConstructor(o => o.LegacyFormats.Add(new TestShaFormat(null!)), expectedValid: false);
        Assert.Contains("legacy format id", Validate(o => o.LegacyFormats.Add(new TestShaFormat(null!))).FailureMessage, StringComparison.Ordinal);
    }

    [Fact]
    public void Configuration_validator_treats_pepper_with_null_keys_and_no_current_key_as_absent()
    {
        var config = new MasterlyHashConfiguration { Pepper = new MasterlyHashPepperConfiguration { CurrentKeyId = null, Keys = null! } };

        Assert.True(ConfigValidator.Validate(null, config).Succeeded);
        Assert.True(ConfigValidator.Validate(null, new MasterlyHashConfiguration { Pepper = new MasterlyHashPepperConfiguration { CurrentKeyId = "", Keys = null! } }).Succeeded);
    }

    [Fact]
    public void Configuration_validator_null_options_throw()
    {
        Assert.Equal("options", Assert.Throws<ArgumentNullException>(() => ConfigValidator.Validate(null, null!)).ParamName);
    }

    [Fact]
    public void Configuration_validator_handles_null_keys_dictionary()
    {
        var config = new MasterlyHashConfiguration { Pepper = new MasterlyHashPepperConfiguration { CurrentKeyId = "k1", Keys = null! } };

        Assert.True(ConfigValidator.Validate(null, config).Failed);
    }

    [Theory]
    [InlineData("====")]
    [InlineData("YQ")]
    [InlineData("a b c d")]
    [InlineData("éééé")]
    [InlineData(" ")]
    public void Malformed_base64_never_throws(string value)
    {
        var config = new MasterlyHashConfiguration
        {
            Pepper = new MasterlyHashPepperConfiguration { CurrentKeyId = "k1", Keys = new Dictionary<string, string> { ["k1"] = value } },
        };

        Assert.True(ConfigValidator.Validate(null, config).Failed);
    }
}
