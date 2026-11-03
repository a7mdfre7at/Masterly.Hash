using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Masterly.Hash.Pepper;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Masterly.Hash.DependencyInjection.Tests;

public class RegistrationTests
{
    private static ServiceProvider Build(Action<IServiceCollection> register) =>
        Register(register).BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true, ValidateOnBuild = true });

    private static ServiceCollection Register(Action<IServiceCollection> register)
    {
        var services = new ServiceCollection();
        register(services);
        return services;
    }

    [Fact]
    public void Resolves_PasswordHasher_and_interface_as_the_same_singleton()
    {
        using ServiceProvider provider = Build(s => s.AddMasterlyHash(TestSupport.UseFast));

        PasswordHasher concrete = provider.GetRequiredService<PasswordHasher>();
        IPasswordHasher iface = provider.GetRequiredService<IPasswordHasher>();

        Assert.Same(concrete, iface);
        Assert.Same(concrete, provider.GetRequiredService<PasswordHasher>());
        using IServiceScope scope = provider.CreateScope();
        Assert.Same(concrete, scope.ServiceProvider.GetRequiredService<IPasswordHasher>());
    }

    [Fact]
    public void Registrations_are_singletons()
    {
        ServiceCollection services = Register(s => s.AddMasterlyHash());

        Assert.Equal(ServiceLifetime.Singleton, services.Single(d => d.ServiceType == typeof(PasswordHasher)).Lifetime);
        Assert.Equal(ServiceLifetime.Singleton, services.Single(d => d.ServiceType == typeof(IPasswordHasher)).Lifetime);
    }

    [Fact]
    public void Default_registration_uses_safe_defaults()
    {
        using ServiceProvider provider = Build(s => s.AddMasterlyHash());

        PasswordHasher hasher = provider.GetRequiredService<PasswordHasher>();

        Assert.Same(HashProfile.Server2026a, hasher.DefaultProfile);
        PasswordHasherOptions options = provider.GetRequiredService<IOptions<PasswordHasherOptions>>().Value;
        Assert.Null(options.Pepper);
        Assert.Equal(1024, options.MaxPasswordBytes);
        Assert.Single(options.LegacyFormats);
    }

    [Fact]
    public void Configure_callback_is_applied_and_hasher_round_trips()
    {
        using ServiceProvider provider = Build(s => s.AddMasterlyHash(o =>
        {
            TestSupport.UseFast(o);
            o.MaxPasswordBytes = 128;
        }));

        IPasswordHasher hasher = provider.GetRequiredService<IPasswordHasher>();
        string hash = hasher.Hash("correct horse");

        Assert.StartsWith("$mh$p=test$", hash, StringComparison.Ordinal);
        Assert.True(hasher.Verify("correct horse", hash).IsMatch);
        Assert.False(hasher.Verify("wrong horse", hash).IsMatch);
        Assert.Equal(128, provider.GetRequiredService<IOptions<PasswordHasherOptions>>().Value.MaxPasswordBytes);
        Assert.Throws<ArgumentException>(() => hasher.Hash(new string('a', 129)));
    }

    [Fact]
    public async Task Async_api_works_through_the_container()
    {
        using ServiceProvider provider = Build(s => s.AddMasterlyHash(TestSupport.UseFast));
        IPasswordHasher hasher = provider.GetRequiredService<IPasswordHasher>();

        string hash = await hasher.HashAsync("pa55word");
        PasswordVerificationResult result = await hasher.VerifyOrDummyAsync("pa55word", hash);

        Assert.True(result.IsMatch);
        Assert.False((await hasher.VerifyOrDummyAsync("pa55word", null)).IsMatch);
    }

    [Fact]
    public void Calling_twice_registers_one_hasher_and_accumulates_configuration()
    {
        ServiceCollection services = Register(s =>
        {
            s.AddMasterlyHash(TestSupport.UseFast);
            s.AddMasterlyHash(o => o.MaxConcurrency = 3);
        });

        Assert.Single(services, d => d.ServiceType == typeof(PasswordHasher));
        Assert.Single(services, d => d.ServiceType == typeof(IPasswordHasher));
        Assert.Single(services, d => d.ServiceType == typeof(IValidateOptions<PasswordHasherOptions>));

        using ServiceProvider provider = services.BuildServiceProvider();
        PasswordHasherOptions options = provider.GetRequiredService<IOptions<PasswordHasherOptions>>().Value;
        Assert.Same(TestSupport.Fast, options.DefaultProfile);
        Assert.Equal(3, options.MaxConcurrency);
    }

    [Fact]
    public void Existing_IPasswordHasher_registration_is_rejected_because_options_would_be_ignored()
    {
        var custom = new PasswordHasher(new PasswordHasherOptions { DefaultProfile = TestSupport.Fast, AllowWeakProfiles = true });
        var services = new ServiceCollection();
        services.AddSingleton<IPasswordHasher>(custom);

        InvalidOperationException ex = Assert.Throws<InvalidOperationException>(() => services.AddMasterlyHash(TestSupport.UseFast));
        Assert.Contains("IPasswordHasher is already registered", ex.Message, StringComparison.Ordinal);
        Assert.Throws<InvalidOperationException>(() =>
            services.AddMasterlyHash(TestSupport.Config(new System.Collections.Generic.Dictionary<string, string?>()).GetSection("MasterlyHash")));
    }

    [Fact]
    public void Existing_PasswordHasher_registration_is_rejected()
    {
        var services = new ServiceCollection();
        services.AddSingleton(new PasswordHasher(new PasswordHasherOptions { DefaultProfile = TestSupport.Fast, AllowWeakProfiles = true }));

        InvalidOperationException ex = Assert.Throws<InvalidOperationException>(() => services.AddMasterlyHash());
        Assert.Contains("PasswordHasher is already registered", ex.Message, StringComparison.Ordinal);
    }

    private sealed class CountingDecorator : IPasswordHasher
    {
        private readonly IPasswordHasher _inner;
        private int _hashes;

        public CountingDecorator(IPasswordHasher inner) => _inner = inner;

        public int Hashes => Volatile.Read(ref _hashes);

        public string Hash(string password)
        {
            Interlocked.Increment(ref _hashes);
            return _inner.Hash(password);
        }

        public string Hash(string password, HashProfile profile) => _inner.Hash(password, profile);

        public PasswordVerificationResult Verify(string password, string storedHash) => _inner.Verify(password, storedHash);

        public PasswordVerificationResult VerifyOrDummy(string password, string? storedHash) => _inner.VerifyOrDummy(password, storedHash);

        public ValueTask<string> HashAsync(string password, CancellationToken cancellationToken = default) =>
            _inner.HashAsync(password, cancellationToken);

        public ValueTask<PasswordVerificationResult> VerifyAsync(string password, string storedHash, CancellationToken cancellationToken = default) =>
            _inner.VerifyAsync(password, storedHash, cancellationToken);

        public ValueTask<PasswordVerificationResult> VerifyOrDummyAsync(string password, string? storedHash, CancellationToken cancellationToken = default) =>
            _inner.VerifyOrDummyAsync(password, storedHash, cancellationToken);

        public bool NeedsRehash(string storedHash) => _inner.NeedsRehash(storedHash);

        public HashInfo Inspect(string storedHash) => _inner.Inspect(storedHash);

        public bool TryWrap(string legacyHash, out string wrappedHash) => _inner.TryWrap(legacyHash, out wrappedHash);
    }

    [Fact]
    public void Decorator_registered_after_AddMasterlyHash_wraps_the_configured_hasher()
    {
        using ServiceProvider provider = Build(s =>
        {
            s.AddMasterlyHash(TestSupport.UseFast);
            s.AddSingleton<IPasswordHasher>(sp => new CountingDecorator(sp.GetRequiredService<PasswordHasher>()));
            s.AddMasterlyHash(o => o.MaxConcurrency = 2); // a later call (e.g. from a satellite package) is still allowed
        });

        PasswordHasher inner = provider.ValidateMasterlyHash();
        CountingDecorator decorator = Assert.IsType<CountingDecorator>(provider.GetRequiredService<IPasswordHasher>());
        string hash = decorator.Hash("pw");

        Assert.Equal(1, decorator.Hashes);
        Assert.Same(TestSupport.Fast, inner.DefaultProfile);
        Assert.True(inner.Verify("pw", hash).IsMatch);
        Assert.Equal(2, provider.GetRequiredService<IOptions<PasswordHasherOptions>>().Value.MaxConcurrency);
    }

    [Fact]
    public void Options_configured_outside_the_package_are_honoured()
    {
        using ServiceProvider provider = Build(s =>
        {
            s.Configure<PasswordHasherOptions>(o => o.ComputeRehashOnVerify = false);
            s.AddMasterlyHash(TestSupport.UseFast);
        });

        Assert.False(provider.GetRequiredService<IOptions<PasswordHasherOptions>>().Value.ComputeRehashOnVerify);
    }

    [Fact]
    public void Null_arguments_throw()
    {
        var services = new ServiceCollection();

        Assert.Throws<ArgumentNullException>(() => ((IServiceCollection)null!).AddMasterlyHash());
        Assert.Throws<ArgumentNullException>(() => ((IServiceCollection)null!).AddMasterlyHash(new ConfigurationBuilder().Build()));
        Assert.Throws<ArgumentNullException>(() => services.AddMasterlyHash((IConfiguration)null!));
        Assert.Throws<ArgumentNullException>(() => ((IServiceProvider)null!).ValidateMasterlyHash());
    }

    [Fact]
    public void ValidateMasterlyHash_returns_the_singleton()
    {
        using ServiceProvider provider = Build(s => s.AddMasterlyHash(TestSupport.UseFast));

        PasswordHasher hasher = provider.ValidateMasterlyHash();

        Assert.Same(provider.GetRequiredService<IPasswordHasher>(), hasher);
    }

    [Fact]
    public void ValidateMasterlyHash_without_registration_throws_InvalidOperation()
    {
        using ServiceProvider provider = new ServiceCollection().BuildServiceProvider();

        InvalidOperationException ex = Assert.Throws<InvalidOperationException>(() => provider.ValidateMasterlyHash());
        Assert.Contains("AddMasterlyHash", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ValidateMasterlyHash_surfaces_invalid_options_eagerly()
    {
        using ServiceProvider provider = Build(s => s.AddMasterlyHash(o => o.MaxConcurrency = -1));

        OptionsValidationException ex = Assert.Throws<OptionsValidationException>(() => provider.ValidateMasterlyHash());
        Assert.Contains("MaxConcurrency", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Concurrent_first_resolution_builds_exactly_one_hasher_and_one_pepper()
    {
        for (int round = 0; round < 20; round++)
        {
            var store = new FakeKeyStore();
            using ServiceProvider provider = Build(s =>
            {
                s.AddSingleton(store);
                s.AddMasterlyHash(TestSupport.UseFast)
                    .WithPepper(sp => new HmacPepper("k1", sp.GetRequiredService<FakeKeyStore>().GetKey("k1")));
            });

            const int threads = 32;
            var results = new IPasswordHasher[threads];
            using var start = new Barrier(threads);
            Parallel.For(0, threads, new ParallelOptions { MaxDegreeOfParallelism = threads }, i =>
            {
                start.SignalAndWait();
                results[i] = i % 2 == 0
                    ? provider.GetRequiredService<IPasswordHasher>()
                    : provider.GetRequiredService<PasswordHasher>();
            });

            Assert.All(results, r => Assert.Same(results[0], r));
            Assert.Equal(1, store.Calls);
        }
    }

    [Fact]
    public void Resolved_singleton_is_safe_to_use_concurrently()
    {
        using ServiceProvider provider = Build(s => s.AddMasterlyHash(o =>
        {
            TestSupport.UseFast(o);
            o.MaxConcurrency = 4;
        }));
        IPasswordHasher hasher = provider.GetRequiredService<IPasswordHasher>();

        bool[] ok = new bool[40];
        Parallel.For(0, ok.Length, i =>
        {
            string password = "pw-" + i;
            string hash = hasher.Hash(password);
            ok[i] = hasher.Verify(password, hash).IsMatch && !hasher.Verify(password + "x", hash).IsMatch;
        });

        Assert.All(ok, Assert.True);
    }

    [Fact]
    public void Hasher_is_built_once_so_later_option_changes_have_no_effect()
    {
        using ServiceProvider provider = Build(s => s.AddMasterlyHash(TestSupport.UseFast));
        PasswordHasher hasher = provider.GetRequiredService<PasswordHasher>();

        provider.GetRequiredService<IOptions<PasswordHasherOptions>>().Value.DefaultProfile = HashProfile.Fips2026a;

        Assert.Same(TestSupport.Fast, hasher.DefaultProfile);
        Assert.Same(hasher, provider.GetRequiredService<PasswordHasher>());
    }
}
