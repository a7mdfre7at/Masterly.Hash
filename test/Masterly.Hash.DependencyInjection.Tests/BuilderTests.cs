using System;
using System.Linq;
using Masterly.Hash.Legacy;
using Masterly.Hash.Pepper;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Masterly.Hash.DependencyInjection.Tests;

/// <summary>What a satellite package (e.g. Masterly.Hash.Legacy) would ship: an extension over the builder.</summary>
internal static class SatelliteExtensions
{
    public static MasterlyHashBuilder AddTestShaFormat(this MasterlyHashBuilder builder) =>
        builder.AddLegacyFormat(new TestShaFormat());
}

public class BuilderTests
{
    private static ServiceProvider Build(Action<MasterlyHashBuilder> configure, Action<IServiceCollection>? services = null)
    {
        var collection = new ServiceCollection();
        services?.Invoke(collection);
        configure(collection.AddMasterlyHash(TestSupport.UseFast));
        return collection.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true, ValidateOnBuild = true });
    }

    private static PasswordHasherOptions Options(ServiceProvider provider) =>
        provider.GetRequiredService<IOptions<PasswordHasherOptions>>().Value;

    [Fact]
    public void MeterName_matches_the_core_meter()
    {
        Assert.Equal("Masterly.Hash", MasterlyHashBuilder.MeterName);
        Assert.Equal(PasswordHasher.MeterName, MasterlyHashBuilder.MeterName);
    }

    [Fact]
    public void Builder_exposes_the_service_collection_and_chains()
    {
        var services = new ServiceCollection();
        MasterlyHashBuilder builder = services.AddMasterlyHash();

        Assert.Same(services, builder.Services);
        Assert.Same(builder, builder.UseProfile(HashProfile.Fips2026a));
        Assert.Same(builder, builder.AddProfile(HashProfile.Constrained2026a));
        Assert.Same(builder, builder.WithPepper(new HmacPepper("k", TestSupport.Key("k"))));
        Assert.Same(builder, builder.AddLegacyFormat(new TestShaFormat()));
        Assert.Same(builder, builder.Configure(_ => { }));
    }

    [Fact]
    public void Null_arguments_throw()
    {
        MasterlyHashBuilder builder = new ServiceCollection().AddMasterlyHash();

        Assert.Throws<ArgumentNullException>(() => builder.WithPepper((IPasswordPepper)null!));
        Assert.Throws<ArgumentNullException>(() => builder.WithPepper((Func<IServiceProvider, IPasswordPepper>)null!));
        Assert.Throws<ArgumentNullException>(() => builder.AddLegacyFormat((ILegacyHashFormat)null!));
        Assert.Throws<ArgumentNullException>(() => builder.AddLegacyFormat((Func<IServiceProvider, ILegacyHashFormat>)null!));
        Assert.Throws<ArgumentNullException>(() => builder.UseProfile(null!));
        Assert.Throws<ArgumentNullException>(() => builder.AddProfile(null!));
        Assert.Throws<ArgumentNullException>(() => builder.Configure(null!));
        Assert.Throws<ArgumentNullException>(() => builder.Configure<IServiceProvider>(null!));
    }

    [Fact]
    public void WithPepper_instance_peppers_new_hashes()
    {
        var pepper = new HmacPepper("p1", TestSupport.Key("p1"));
        using ServiceProvider provider = Build(b => b.WithPepper(pepper));
        IPasswordHasher hasher = provider.GetRequiredService<IPasswordHasher>();

        string hash = hasher.Hash("peppered");

        Assert.Same(pepper, Options(provider).Pepper);
        Assert.Contains(",k=p1$", hash, StringComparison.Ordinal);
        Assert.True(hasher.Verify("peppered", hash).IsMatch);

        var withoutPepper = new PasswordHasher(new PasswordHasherOptions { DefaultProfile = TestSupport.Fast, AllowWeakProfiles = true });
        Assert.Equal(VerificationFailureReason.UnknownPepperKey, withoutPepper.Verify("peppered", hash).FailureReason);
    }

    [Fact]
    public void WithPepper_factory_resolves_dependencies_from_the_container()
    {
        var store = new FakeKeyStore();
        using ServiceProvider provider = Build(
            b => b.WithPepper(sp => new HmacPepper("vault", sp.GetRequiredService<FakeKeyStore>().GetKey("vault"))),
            s => s.AddSingleton(store));

        IPasswordHasher hasher = provider.GetRequiredService<IPasswordHasher>();
        string hash = hasher.Hash("from vault");

        Assert.Equal(1, store.Calls);
        Assert.Contains(",k=vault$", hash, StringComparison.Ordinal);
        Assert.True(new HmacPepper("vault", TestSupport.Key("vault")).IsKnownKey("vault"));
        Assert.True(hasher.Verify("from vault", hash).IsMatch);
    }

    [Fact]
    public void WithPepper_factory_returning_null_fails_clearly()
    {
        using ServiceProvider provider = Build(b => b.WithPepper(_ => null!));

        InvalidOperationException ex = Assert.Throws<InvalidOperationException>(() => provider.GetRequiredService<IPasswordHasher>());
        Assert.Contains("pepper factory returned null", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Last_pepper_wins()
    {
        var first = new HmacPepper("a", TestSupport.Key("a"));
        var second = new HmacPepper("b", TestSupport.Key("b"));
        using ServiceProvider provider = Build(b => b.WithPepper(first).WithPepper(_ => second));

        Assert.Same(second, Options(provider).Pepper);
    }

    [Fact]
    public void AddLegacyFormat_verifies_and_upgrades_legacy_hashes()
    {
        using ServiceProvider provider = Build(b => b.AddTestShaFormat());
        IPasswordHasher hasher = provider.GetRequiredService<IPasswordHasher>();
        string legacy = TestShaFormat.Create("old password");

        PasswordVerificationResult result = hasher.Verify("old password", legacy);

        Assert.True(result.IsMatch);
        Assert.Equal(RehashReason.LegacyFormat, result.RehashReason);
        Assert.StartsWith("$mh$p=test$", result.Rehash, StringComparison.Ordinal);
        Assert.False(hasher.Verify("wrong", legacy).IsMatch);
        Assert.Contains(Options(provider).LegacyFormats, f => f is V1LegacyFormat);
    }

    [Fact]
    public void AddLegacyFormat_same_instance_twice_is_idempotent()
    {
        var format = new TestShaFormat();
        using ServiceProvider provider = Build(b => b.AddLegacyFormat(format).AddLegacyFormat(format).AddLegacyFormat(V1LegacyFormat.Instance));

        Assert.Equal(1, Options(provider).LegacyFormats.Count(f => ReferenceEquals(f, format)));
        Assert.Equal(1, Options(provider).LegacyFormats.Count(f => ReferenceEquals(f, V1LegacyFormat.Instance)));
        Assert.NotNull(provider.GetRequiredService<IPasswordHasher>());
    }

    [Fact]
    public void AddLegacyFormat_factory_resolves_from_the_container()
    {
        using ServiceProvider provider = Build(
            b => b.AddLegacyFormat(sp => sp.GetRequiredService<TestShaFormat>()),
            s => s.AddSingleton(new TestShaFormat("from-di")));

        Assert.Contains(Options(provider).LegacyFormats, f => f.Id == "from-di");
        Assert.True(provider.GetRequiredService<IPasswordHasher>().Verify("x", TestShaFormat.Create("x")).IsMatch);
    }

    [Fact]
    public void AddLegacyFormat_factory_returning_null_fails_clearly()
    {
        using ServiceProvider provider = Build(b => b.AddLegacyFormat(_ => null!));

        Assert.Throws<InvalidOperationException>(() => provider.GetRequiredService<IPasswordHasher>());
    }

    [Fact]
    public void Two_formats_with_the_same_id_fail_validation()
    {
        using ServiceProvider provider = Build(b => b.AddLegacyFormat(new TestShaFormat("dup")).AddLegacyFormat(new TestShaFormat("dup")));

        OptionsValidationException ex = Assert.Throws<OptionsValidationException>(() => provider.GetRequiredService<IPasswordHasher>());
        Assert.Contains("'dup' is registered twice", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void UseProfile_sets_the_default_profile()
    {
        using ServiceProvider provider = Build(b => b.UseProfile(TestSupport.Fast2));

        string hash = provider.GetRequiredService<IPasswordHasher>().Hash("x1");

        Assert.StartsWith("$mh$p=test2$", hash, StringComparison.Ordinal);
    }

    [Fact]
    public void AddProfile_keeps_old_custom_profile_hashes_verifiable()
    {
        string oldHash;
        using (ServiceProvider before = Build(_ => { }))
            oldHash = before.GetRequiredService<IPasswordHasher>().Hash("migrate");

        using ServiceProvider withoutOld = Build(b => b.UseProfile(TestSupport.Fast2));
        Assert.Equal(VerificationFailureReason.UnknownProfile,
            withoutOld.GetRequiredService<IPasswordHasher>().Verify("migrate", oldHash).FailureReason);

        using ServiceProvider withOld = Build(b => b.UseProfile(TestSupport.Fast2).AddProfile(TestSupport.Fast).AddProfile(TestSupport.Fast));
        PasswordVerificationResult result = withOld.GetRequiredService<IPasswordHasher>().Verify("migrate", oldHash);

        Assert.Single(Options(withOld).AdditionalProfiles);
        Assert.True(result.IsMatch);
        Assert.Equal(RehashReason.OutdatedProfile, result.RehashReason);
        Assert.StartsWith("$mh$p=test2$", result.Rehash, StringComparison.Ordinal);
    }

    [Fact]
    public void Configure_with_dependency_receives_the_service()
    {
        using ServiceProvider provider = Build(
            b => b.Configure<FakeKeyStore>((o, store) => o.MaxPasswordBytes = 64 + store.Calls),
            s => s.AddSingleton(new FakeKeyStore()));

        Assert.Equal(64, Options(provider).MaxPasswordBytes);
    }

    [Fact]
    public void Weak_profile_via_builder_without_AllowWeakProfiles_fails_validation()
    {
        var services = new ServiceCollection();
        services.AddMasterlyHash().UseProfile(TestSupport.Fast);
        using ServiceProvider provider = services.BuildServiceProvider();

        OptionsValidationException ex = Assert.Throws<OptionsValidationException>(() => provider.GetRequiredService<IPasswordHasher>());
        Assert.Contains("below the OWASP minimum", ex.Message, StringComparison.Ordinal);
    }
}
