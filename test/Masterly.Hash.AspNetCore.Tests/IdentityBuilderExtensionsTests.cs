using System;
using System.Linq;
using System.Threading.Tasks;
using Masterly.Hash.Legacy;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using IdentityCompatibilityMode = Microsoft.AspNetCore.Identity.PasswordHasherCompatibilityMode;
using MasterlyOptions = Masterly.Hash.PasswordHasherOptions;

namespace Masterly.Hash.AspNetCore.Tests;

public class IdentityBuilderExtensionsTests
{
    private const string Password = "correct horse battery staple";

    private static ServiceProvider Build(Action<MasterlyOptions>? configure = null, InMemoryUserStore? store = null)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddIdentityCore<TestUser>().AddMasterlyPasswordHasher(o =>
        {
            TestHashers.Weak(o);
            configure?.Invoke(o);
        });
        if (store != null)
            services.AddSingleton<IUserStore<TestUser>>(store);
        return services.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true, ValidateOnBuild = store != null });
    }

    [Fact]
    public void NullBuilder_Throws() =>
        Assert.Throws<ArgumentNullException>(() => MasterlyIdentityBuilderExtensions.AddMasterlyPasswordHasher(null!));

    [Fact]
    public void ReplacesIdentityHasher_WithSingleScopedRegistration()
    {
        var services = new ServiceCollection();
        IdentityBuilder builder = services.AddIdentityCore<TestUser>();
        Assert.Contains(services, d => d.ServiceType == typeof(IPasswordHasher<TestUser>) && d.ImplementationType == typeof(PasswordHasher<TestUser>));

        builder.AddMasterlyPasswordHasher(TestHashers.Weak).AddMasterlyPasswordHasher(TestHashers.Weak);

        ServiceDescriptor descriptor = Assert.Single(services, d => d.ServiceType == typeof(IPasswordHasher<TestUser>));
        Assert.Equal(typeof(MasterlyIdentityPasswordHasher<TestUser>), descriptor.ImplementationType);
        Assert.Equal(ServiceLifetime.Scoped, descriptor.Lifetime);
        Assert.Single(services, d => d.ServiceType == typeof(IPasswordHasher));
    }

    [Fact]
    public void ResolvesAdapterOverTheSharedMasterlyHasher()
    {
        using ServiceProvider provider = Build();
        using IServiceScope scope = provider.CreateScope();

        var adapter = Assert.IsType<MasterlyIdentityPasswordHasher<TestUser>>(scope.ServiceProvider.GetRequiredService<IPasswordHasher<TestUser>>());
        IPasswordHasher masterly = provider.GetRequiredService<IPasswordHasher>();

        string hash = adapter.HashPassword(new TestUser(), Password);
        Assert.True(masterly.Verify(Password, hash).IsMatch);
    }

    [Fact]
    public void Options_DisableRehashOnVerify_AndRegisterIdentityFormatsAheadOfV1()
    {
        using ServiceProvider provider = Build();
        MasterlyOptions options = provider.GetRequiredService<IOptions<MasterlyOptions>>().Value;

        Assert.False(options.ComputeRehashOnVerify);
        int v3 = options.LegacyFormats.IndexOf(AspNetIdentityV3Format.Default);
        int v2 = options.LegacyFormats.IndexOf(AspNetIdentityV2Format.Instance);
        int v1 = options.LegacyFormats.IndexOf(V1LegacyFormat.Instance);
        Assert.True(v3 >= 0 && v2 >= 0 && v1 >= 0);
        Assert.True(v3 < v1 && v2 < v1);
    }

    [Fact]
    public void Configure_CanReEnableRehashOnVerify_AndSupplyCustomIdentityFormat()
    {
        var custom = new AspNetIdentityV3Format(2_000_000);
        using ServiceProvider provider = Build(o =>
        {
            o.ComputeRehashOnVerify = true;
            o.AddLegacyFormats(custom);
        });
        MasterlyOptions options = provider.GetRequiredService<IOptions<MasterlyOptions>>().Value;

        Assert.True(options.ComputeRehashOnVerify);
        Assert.Contains(custom, options.LegacyFormats);
        Assert.DoesNotContain(AspNetIdentityV3Format.Default, options.LegacyFormats);
        Assert.Equal(1, options.LegacyFormats.Count(f => f.Id == "aspnet-identity-v3"));
        _ = provider.ValidateMasterlyHash();
    }

    [Fact]
    public void InvalidOptions_FailValidation()
    {
        using ServiceProvider provider = Build(o => o.AllowWeakProfiles = false);
        Assert.Throws<OptionsValidationException>(() => provider.GetRequiredService<IPasswordHasher>());
    }

    [Theory]
    [InlineData(IdentityCompatibilityMode.IdentityV3)]
    [InlineData(IdentityCompatibilityMode.IdentityV2)]
    public async Task UserManager_UpgradesMicrosoftHashOnLogin(IdentityCompatibilityMode mode)
    {
        var store = new InMemoryUserStore();
        var user = new TestUser { UserName = "alice", NormalizedUserName = "ALICE" };
        user.PasswordHash = TestHashers.Microsoft(mode).HashPassword(user, Password);
        string original = user.PasswordHash;
        store.Add(user);

        using ServiceProvider provider = Build(store: store);
        using IServiceScope scope = provider.CreateScope();
        UserManager<TestUser> manager = scope.ServiceProvider.GetRequiredService<UserManager<TestUser>>();

        // Wrong password: no change.
        Assert.False(await manager.CheckPasswordAsync(user, "wrong password"));
        Assert.Equal(original, user.PasswordHash);
        Assert.Equal(0, store.Updates);

        // Right password: UserManager re-hashes with Masterly and saves.
        Assert.True(await manager.CheckPasswordAsync(user, Password));
        Assert.StartsWith("$mh$p=test$", user.PasswordHash, StringComparison.Ordinal);
        Assert.Equal(1, store.Updates);

        // Next login: current hash, no further update.
        Assert.True(await manager.CheckPasswordAsync(user, Password));
        Assert.Equal(1, store.Updates);
        Assert.False(await manager.CheckPasswordAsync(user, "wrong password"));
    }

    [Fact]
    public async Task UserManager_CreateWithPassword_StoresMasterlyHash()
    {
        var store = new InMemoryUserStore();
        using ServiceProvider provider = Build(store: store);
        using IServiceScope scope = provider.CreateScope();
        UserManager<TestUser> manager = scope.ServiceProvider.GetRequiredService<UserManager<TestUser>>();

        var user = new TestUser { UserName = "bob" };
        IdentityResult result = await manager.CreateAsync(user, "Str0ng!Passw0rd");

        Assert.True(result.Succeeded, string.Join("; ", result.Errors.Select(e => e.Code)));
        Assert.StartsWith("$mh$", user.PasswordHash, StringComparison.Ordinal);
        Assert.True(await manager.CheckPasswordAsync(user, "Str0ng!Passw0rd"));
    }

    [Fact]
    public void ConcurrencyTimeout_DefaultIsLoweredForSynchronousIdentityCalls()
    {
        using ServiceProvider provider = Build();
        Assert.Equal(MasterlyIdentityBuilderExtensions.IdentityConcurrencyTimeout, provider.GetRequiredService<IOptions<MasterlyOptions>>().Value.ConcurrencyTimeout);
        Assert.Equal(TimeSpan.FromSeconds(2), MasterlyIdentityBuilderExtensions.IdentityConcurrencyTimeout);
    }

    [Fact]
    public void WithoutConfigure_AppliesIdentityDefaults_AndResolves()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddIdentityCore<TestUser>().AddMasterlyPasswordHasher();
        using ServiceProvider provider = services.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true });

        MasterlyOptions options = provider.GetRequiredService<IOptions<MasterlyOptions>>().Value;
        Assert.False(options.ComputeRehashOnVerify);
        Assert.Equal(MasterlyIdentityBuilderExtensions.IdentityConcurrencyTimeout, options.ConcurrencyTimeout);
        Assert.Same(HashProfile.Server2026a, options.DefaultProfile);
        Assert.Contains(AspNetIdentityV3Format.Default, options.LegacyFormats);
        Assert.Contains(AspNetIdentityV2Format.Instance, options.LegacyFormats);

        using IServiceScope scope = provider.CreateScope();
        Assert.IsType<MasterlyIdentityPasswordHasher<TestUser>>(scope.ServiceProvider.GetRequiredService<IPasswordHasher<TestUser>>());
        Assert.Same(HashProfile.Server2026a, Assert.IsType<PasswordHasher>(provider.GetRequiredService<IPasswordHasher>()).DefaultProfile);
    }

    [Fact]
    public void ConcurrencyTimeout_ExplicitValues_AreKept()
    {
        using (ServiceProvider provider = Build(o => o.ConcurrencyTimeout = TimeSpan.FromSeconds(30)))
            Assert.Equal(TimeSpan.FromSeconds(30), provider.GetRequiredService<IOptions<MasterlyOptions>>().Value.ConcurrencyTimeout);

        // A value set by an earlier configure step (e.g. bound configuration) is not overwritten.
        var services = new ServiceCollection();
        services.Configure<MasterlyOptions>(o => o.ConcurrencyTimeout = TimeSpan.FromSeconds(7));
        services.AddIdentityCore<TestUser>().AddMasterlyPasswordHasher(TestHashers.Weak);
        using ServiceProvider other = services.BuildServiceProvider();
        Assert.Equal(TimeSpan.FromSeconds(7), other.GetRequiredService<IOptions<MasterlyOptions>>().Value.ConcurrencyTimeout);
    }

    [Fact]
    public void RegistersLengthValidatorOnce_AlongsideIdentityDefault()
    {
        var services = new ServiceCollection();
        services.AddIdentityCore<TestUser>().AddMasterlyPasswordHasher(TestHashers.Weak).AddMasterlyPasswordHasher(TestHashers.Weak);

        Assert.Single(services, d => d.ServiceType == typeof(IPasswordValidator<TestUser>) && d.ImplementationType == typeof(MasterlyPasswordLengthValidator<TestUser>));
        Assert.Single(services, d => d.ServiceType == typeof(IPasswordValidator<TestUser>) && d.ImplementationType == typeof(PasswordValidator<TestUser>));
    }

    [Fact]
    public async Task UserManager_OverLongPassword_FailsWithIdentityResult_InsteadOfThrowing()
    {
        var store = new InMemoryUserStore();
        using ServiceProvider provider = Build(store: store);
        using IServiceScope scope = provider.CreateScope();
        UserManager<TestUser> manager = scope.ServiceProvider.GetRequiredService<UserManager<TestUser>>();

        // Passes Identity's own rules (digit, upper, lower, symbol) but is 2,000 bytes.
        string tooLong = string.Concat(Enumerable.Repeat("Aa1!", 500));
        var user = new TestUser { UserName = "carol" };
        IdentityResult created = await manager.CreateAsync(user, tooLong);

        Assert.False(created.Succeeded);
        Assert.Contains(created.Errors, e => e.Code == MasterlyPasswordLengthValidator<TestUser>.PasswordTooLongCode);
        Assert.Null(user.PasswordHash);

        // Same for a password that is short in raw form but over the limit after NFKC.
        IdentityResult expanding = await manager.CreateAsync(new TestUser { UserName = "dave" }, "Aa1!" + new string('ﷺ', 60));
        Assert.False(expanding.Succeeded);
        Assert.Contains(expanding.Errors, e => e.Code == MasterlyPasswordLengthValidator<TestUser>.PasswordTooLongCode);

        // Changing to an over-long password fails the same way.
        var erin = new TestUser { UserName = "erin" };
        Assert.True((await manager.CreateAsync(erin, "Str0ng!Passw0rd")).Succeeded);
        IdentityResult changed = await manager.ChangePasswordAsync(erin, "Str0ng!Passw0rd", tooLong);
        Assert.False(changed.Succeeded);
        Assert.True(await manager.CheckPasswordAsync(erin, "Str0ng!Passw0rd"));
    }

    [Fact]
    public async Task UserManager_LegacyPasswordThatCannotBeRehashed_KeepsLegacyHash_AndDoesNotThrow()
    {
        // 60 x U+FDFA: 180 raw bytes (accepted by the v3 format) but 1,980 bytes after NFKC (cannot be re-hashed).
        string password = new('ﷺ', 60);
        var store = new InMemoryUserStore();
        var user = new TestUser { UserName = "frank", NormalizedUserName = "FRANK" };
        user.PasswordHash = TestHashers.Microsoft(IdentityCompatibilityMode.IdentityV3).HashPassword(user, password);
        string original = user.PasswordHash;
        store.Add(user);

        using ServiceProvider provider = Build(store: store);
        using IServiceScope scope = provider.CreateScope();
        UserManager<TestUser> manager = scope.ServiceProvider.GetRequiredService<UserManager<TestUser>>();

        Assert.True(await manager.CheckPasswordAsync(user, password));
        Assert.True(await manager.CheckPasswordAsync(user, password));
        Assert.Equal(original, user.PasswordHash);
        Assert.Equal(0, store.Updates);
    }
}
