using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace Masterly.Hash.DependencyInjection.Tests;

public class BadConfigurationTests
{
    private static string ResolveFailure(Dictionary<string, string?> values)
    {
        using ServiceProvider provider = TestSupport.BuildFromConfig(values);
        Exception ex = Assert.ThrowsAny<Exception>(() => provider.GetRequiredService<IPasswordHasher>());
        OptionsValidationException validation = Assert.IsType<OptionsValidationException>(ex);
        Assert.Equal(typeof(MasterlyHashConfiguration), validation.OptionsType);
        return TestSupport.AllMessages(ex);
    }

    [Theory]
    [InlineData("2025a")]
    [InlineData("2026A")]
    [InlineData("test")]
    public void Unknown_profile_id_is_a_startup_error(string id)
    {
        string message = ResolveFailure(new Dictionary<string, string?> { ["MasterlyHash:DefaultProfile"] = id });

        Assert.Contains("DefaultProfile", message, StringComparison.Ordinal);
        Assert.Contains("2026a, 2026c, 2026f", message, StringComparison.Ordinal);
    }

    [Fact]
    public void Unknown_profile_value_that_does_not_look_like_an_id_is_not_echoed()
    {
        const string leaked = "Sup3r/S3cret+Value==";
        string message = ResolveFailure(new Dictionary<string, string?> { ["MasterlyHash:DefaultProfile"] = leaked });

        Assert.DoesNotContain(leaked, message, StringComparison.Ordinal);
        Assert.Contains("DefaultProfile", message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("MaxConcurrency", "-1")]
    [InlineData("MaxPasswordBytes", "63")]
    [InlineData("MaxPasswordBytes", "2000000")]
    [InlineData("ConcurrencyTimeout", "00:00:00")]
    [InlineData("ConcurrencyTimeout", "-00:00:05")]
    // SemaphoreSlim.Wait/WaitAsync throw ArgumentOutOfRangeException above int.MaxValue ms on .NET 8.
    [InlineData("ConcurrencyTimeout", "30.00:00:00")]
    [InlineData("ConcurrencyTimeout", "24.20:31:23.648")]
    public void Out_of_range_values_are_startup_errors(string setting, string value)
    {
        string message = ResolveFailure(new Dictionary<string, string?> { ["MasterlyHash:" + setting] = value });

        Assert.Contains(setting, message, StringComparison.Ordinal);
    }

    [Fact]
    public void Largest_finite_concurrency_timeout_is_accepted()
    {
        using ServiceProvider provider = TestSupport.BuildFromConfig(new Dictionary<string, string?>
        {
            ["MasterlyHash:MaxConcurrency"] = "1",
            ["MasterlyHash:ConcurrencyTimeout"] = "24.20:31:23.647",
        });

        Assert.NotNull(provider.ValidateMasterlyHash());
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void Blank_default_profile_keeps_the_default_like_other_blank_settings(string value)
    {
        var services = new ServiceCollection();
        services.AddMasterlyHash(TestSupport.Config(new Dictionary<string, string?>
        {
            ["MasterlyHash:DefaultProfile"] = value,
            ["MasterlyHash:MaxPasswordBytes"] = "",
        }).GetSection("MasterlyHash"));
        using ServiceProvider provider = services.BuildServiceProvider();

        PasswordHasherOptions options = provider.GetRequiredService<IOptions<PasswordHasherOptions>>().Value;

        Assert.Same(HashProfile.Server2026a, options.DefaultProfile);
        Assert.Equal(new PasswordHasherOptions().MaxPasswordBytes, options.MaxPasswordBytes);
    }

    [Theory]
    [InlineData("MasterlyHash:Peper:CurrentKeyId", "Peper")]
    [InlineData("MasterlyHash:pepper_keys:k1", "pepper_keys")]
    [InlineData("MasterlyHash:Pepper:CurentKeyId", "CurentKeyId")]
    [InlineData("MasterlyHash:DefaultProfiel", "DefaultProfiel")]
    public void Unknown_or_misspelled_keys_are_startup_errors_without_echoing_values(string key, string misspelled)
    {
        string secret = TestSupport.KeyB64("typo");
        using ServiceProvider provider = TestSupport.BuildFromConfig(new Dictionary<string, string?> { [key] = secret });

        Exception ex = Assert.ThrowsAny<InvalidOperationException>(() => provider.GetRequiredService<IPasswordHasher>());
        string message = TestSupport.AllMessages(ex);

        Assert.Contains(misspelled, message, StringComparison.Ordinal);
        Assert.DoesNotContain(secret, message, StringComparison.Ordinal);
    }

    [Fact]
    public void Misspelled_pepper_section_fails_eager_validation_instead_of_running_unpeppered()
    {
        using ServiceProvider provider = TestSupport.BuildFromConfig(new Dictionary<string, string?>
        {
            ["MasterlyHash:Peper:CurrentKeyId"] = "k1",
            ["MasterlyHash:Peper:Keys:k1"] = TestSupport.KeyB64("k1"),
        });

        Assert.ThrowsAny<InvalidOperationException>(() => provider.ValidateMasterlyHash());
    }

    [Fact]
    public void Unparseable_number_is_a_startup_error()
    {
        using ServiceProvider provider = TestSupport.BuildFromConfig(new Dictionary<string, string?> { ["MasterlyHash:MaxConcurrency"] = "many" });

        Assert.Throws<InvalidOperationException>(() => provider.GetRequiredService<IPasswordHasher>());
    }

    [Fact]
    public void Pepper_key_shorter_than_32_bytes_is_rejected_without_echoing_it()
    {
        string shortKey = Convert.ToBase64String(new byte[] { 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 11, 12, 13, 14, 15, 16 });
        string message = ResolveFailure(new Dictionary<string, string?>
        {
            ["MasterlyHash:Pepper:CurrentKeyId"] = "k1",
            ["MasterlyHash:Pepper:Keys:k1"] = shortKey,
        });

        Assert.Contains("Keys:k1", message, StringComparison.Ordinal);
        Assert.Contains("32 bytes", message, StringComparison.Ordinal);
        Assert.DoesNotContain(shortKey, message, StringComparison.Ordinal);
    }

    [Fact]
    public void Pepper_key_that_is_not_base64_is_rejected_without_echoing_it()
    {
        const string notBase64 = "this-is-my-secret-pepper-not-base64!!";
        string message = ResolveFailure(new Dictionary<string, string?>
        {
            ["MasterlyHash:Pepper:CurrentKeyId"] = "k1",
            ["MasterlyHash:Pepper:Keys:k1"] = notBase64,
        });

        Assert.Contains("not valid base64", message, StringComparison.Ordinal);
        Assert.DoesNotContain(notBase64, message, StringComparison.Ordinal);
        Assert.DoesNotContain("secret-pepper", message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(1025)]
    [InlineData(1026)]
    [InlineData(1537)]
    [InlineData(2000)]
    [InlineData(4096)]
    public void Oversized_pepper_key_is_reported_as_too_long(int length)
    {
        string encoded = Convert.ToBase64String(new byte[length]);
        foreach (string value in new[] { encoded, encoded.TrimEnd('=') })
        {
            string message = ResolveFailure(new Dictionary<string, string?>
            {
                ["MasterlyHash:Pepper:CurrentKeyId"] = "k1",
                ["MasterlyHash:Pepper:Keys:k1"] = value,
            });

            Assert.Contains("Keys:k1 must decode to at most 1024 bytes", message, StringComparison.Ordinal);
            Assert.DoesNotContain("not valid base64", message, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void Largest_pepper_key_is_accepted()
    {
        using ServiceProvider provider = TestSupport.BuildFromConfig(new Dictionary<string, string?>
        {
            ["MasterlyHash:Pepper:CurrentKeyId"] = "k1",
            ["MasterlyHash:Pepper:Keys:k1"] = Convert.ToBase64String(new byte[1024]),
        });

        PasswordHasher hasher = provider.ValidateMasterlyHash();
        Assert.Equal("k1", provider.GetRequiredService<IOptions<PasswordHasherOptions>>().Value.Pepper!.CurrentKeyId);
        Assert.Contains("k=k1", hasher.Hash("pw"), StringComparison.Ordinal);
    }

    [Fact]
    public void Current_key_missing_from_ring_is_rejected()
    {
        string message = ResolveFailure(new Dictionary<string, string?>
        {
            ["MasterlyHash:Pepper:CurrentKeyId"] = "k9",
            ["MasterlyHash:Pepper:Keys:k1"] = TestSupport.KeyB64("k1"),
        });

        Assert.Contains("'k9' is not in", message, StringComparison.Ordinal);
        Assert.DoesNotContain(TestSupport.KeyB64("k1"), message, StringComparison.Ordinal);
    }

    [Fact]
    public void Keys_without_current_key_id_are_rejected()
    {
        string message = ResolveFailure(new Dictionary<string, string?> { ["MasterlyHash:Pepper:Keys:k1"] = TestSupport.KeyB64("k1") });

        Assert.Contains("CurrentKeyId is required", message, StringComparison.Ordinal);
    }

    [Fact]
    public void Current_key_id_without_keys_is_rejected()
    {
        string message = ResolveFailure(new Dictionary<string, string?> { ["MasterlyHash:Pepper:CurrentKeyId"] = "k1" });

        Assert.Contains("at least one key", message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("bad id")]
    [InlineData("bad_id")]
    [InlineData("waaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaay-too-long")]
    public void Invalid_key_ids_are_rejected(string id)
    {
        string message = ResolveFailure(new Dictionary<string, string?>
        {
            ["MasterlyHash:Pepper:CurrentKeyId"] = id,
            ["MasterlyHash:Pepper:Keys:" + id] = TestSupport.KeyB64("x"),
        });

        Assert.Contains("^[A-Za-z0-9-]{1,32}$", message, StringComparison.Ordinal);
    }

    [Fact]
    public void All_failures_are_reported_together_and_no_key_text_leaks()
    {
        string badKey = Convert.ToBase64String(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 });
        using ServiceProvider provider = TestSupport.BuildFromConfig(new Dictionary<string, string?>
        {
            ["MasterlyHash:DefaultProfile"] = "nope",
            ["MasterlyHash:MaxConcurrency"] = "-4",
            ["MasterlyHash:Pepper:CurrentKeyId"] = "k1",
            ["MasterlyHash:Pepper:Keys:k1"] = badKey,
        });

        OptionsValidationException ex = Assert.Throws<OptionsValidationException>(() => provider.GetRequiredService<IPasswordHasher>());

        Assert.Equal(3, new List<string>(ex.Failures).Count);
        Assert.DoesNotContain(badKey, ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Eager_helper_reports_bad_configuration()
    {
        using ServiceProvider provider = TestSupport.BuildFromConfig(new Dictionary<string, string?> { ["MasterlyHash:DefaultProfile"] = "2099z" });

        OptionsValidationException ex = Assert.Throws<OptionsValidationException>(() => provider.ValidateMasterlyHash());
        Assert.Contains("'2099z'", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Host_start_fails_fast_on_bad_configuration()
    {
        using IHost host = new HostBuilder()
            .ConfigureServices(services => services.AddMasterlyHash(
                TestSupport.Config(new Dictionary<string, string?> { ["MasterlyHash:DefaultProfile"] = "2026x" }).GetSection("MasterlyHash")))
            .Build();

        Exception ex = await Assert.ThrowsAnyAsync<Exception>(() => host.StartAsync());

        Assert.Contains("is not a known profile", TestSupport.AllMessages(ex), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Host_start_fails_fast_on_misspelled_configuration_key()
    {
        using IHost host = new HostBuilder()
            .ConfigureServices(services => services.AddMasterlyHash(
                TestSupport.Config(new Dictionary<string, string?>
                {
                    ["MasterlyHash:Peper:CurrentKeyId"] = "k1",
                    ["MasterlyHash:Peper:Keys:k1"] = TestSupport.KeyB64("k1"),
                }).GetSection("MasterlyHash")))
            .Build();

        Exception ex = await Assert.ThrowsAnyAsync<Exception>(() => host.StartAsync());

        Assert.Contains("Peper", TestSupport.AllMessages(ex), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Host_start_fails_fast_on_invalid_code_options()
    {
        using IHost host = new HostBuilder()
            .ConfigureServices(services => services.AddMasterlyHash(o => o.DefaultProfile = HashProfile.Argon2id("weak", 64, 1)))
            .Build();

        Exception ex = await Assert.ThrowsAnyAsync<Exception>(() => host.StartAsync());

        Assert.Contains("below the OWASP minimum", TestSupport.AllMessages(ex), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Host_starts_with_valid_configuration()
    {
        using IHost host = new HostBuilder()
            .ConfigureServices(services => services.AddMasterlyHash(
                TestSupport.Config(new Dictionary<string, string?>
                {
                    ["MasterlyHash:DefaultProfile"] = "2026c",
                    ["MasterlyHash:Pepper:CurrentKeyId"] = "k1",
                    ["MasterlyHash:Pepper:Keys:k1"] = TestSupport.KeyB64("k1"),
                }).GetSection("MasterlyHash")))
            .Build();

        await host.StartAsync();
        try
        {
            Assert.Same(HashProfile.Constrained2026a, host.Services.GetRequiredService<PasswordHasher>().DefaultProfile);
        }
        finally
        {
            await host.StopAsync();
        }
    }
}
