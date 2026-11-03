using System;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Masterly.Hash.Policy;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Masterly.Hash.Pwned.Tests;

public class PwnedPasswordsOptionsTests
{
    private static void Rejected(Action<PwnedPasswordsOptions> configure)
    {
        var options = new PwnedPasswordsOptions();
        configure(options);
        using var http = new HttpClient(FakeRangeApi.Ok(""));
        Assert.Throws<ArgumentException>(() => new PwnedPasswordsClient(http, options));
    }

    [Fact]
    public void Defaults_match_the_documentation()
    {
        var o = new PwnedPasswordsOptions();
        Assert.Equal(new Uri("https://api.pwnedpasswords.com/"), o.BaseAddress);
        Assert.Equal(TimeSpan.FromSeconds(3), o.Timeout);
        Assert.Equal(PwnedPasswordsFailureMode.FailOpen, o.FailureMode);
        Assert.Equal(1, o.MinimumOccurrences);
        Assert.False(o.EnableCache);
        Assert.False(o.AllowInsecureHttp);
        Assert.False(string.IsNullOrWhiteSpace(o.UserAgent));
    }

    [Fact] public void Http_is_rejected_by_default() => Rejected(o => o.BaseAddress = new Uri("http://mirror.example/"));
    [Fact] public void Other_schemes_are_rejected() => Rejected(o => { o.BaseAddress = new Uri("ftp://mirror.example/"); o.AllowInsecureHttp = true; });
    [Fact] public void Relative_base_is_rejected() => Rejected(o => o.BaseAddress = new Uri("/range", UriKind.Relative));
    [Fact] public void Null_base_is_rejected() => Rejected(o => o.BaseAddress = null!);
    [Fact] public void Query_is_rejected() => Rejected(o => o.BaseAddress = new Uri("https://mirror.example/?a=1"));
    [Fact] public void Fragment_is_rejected() => Rejected(o => o.BaseAddress = new Uri("https://mirror.example/#x"));
    [Fact] public void User_info_is_rejected() => Rejected(o => o.BaseAddress = new Uri("https://user:pw@mirror.example/"));
    [Fact] public void Zero_timeout_is_rejected() => Rejected(o => o.Timeout = TimeSpan.Zero);
    [Fact] public void Huge_timeout_is_rejected() => Rejected(o => o.Timeout = TimeSpan.FromHours(1));
    [Fact] public void Null_user_agent_is_rejected() => Rejected(o => o.UserAgent = null!);
    [Fact] public void Blank_user_agent_is_rejected() => Rejected(o => o.UserAgent = "  ");
    [Fact] public void Header_injection_in_user_agent_is_rejected() => Rejected(o => o.UserAgent = "App/1.0\r\nX-Evil: 1");
    [Fact] public void Unparseable_user_agent_is_rejected() => Rejected(o => o.UserAgent = "(((");
    [Fact] public void Undefined_failure_mode_is_rejected() => Rejected(o => o.FailureMode = (PwnedPasswordsFailureMode)42);
    [Fact] public void Zero_minimum_occurrences_is_rejected() => Rejected(o => o.MinimumOccurrences = 0);
    [Fact] public void Zero_cache_size_is_rejected() => Rejected(o => { o.EnableCache = true; o.CacheMaxEntries = 0; });
    [Fact] public void Huge_cache_size_is_rejected() => Rejected(o => { o.EnableCache = true; o.CacheMaxEntries = 1_000_000; });
    [Fact] public void Zero_cache_duration_is_rejected() => Rejected(o => { o.EnableCache = true; o.CacheDuration = TimeSpan.Zero; });
    [Fact] public void Huge_cache_duration_is_rejected() => Rejected(o => { o.EnableCache = true; o.CacheDuration = TimeSpan.FromDays(30); });

    [Fact]
    public void Cache_limits_are_ignored_when_the_cache_is_off()
    {
        using var http = new HttpClient(FakeRangeApi.Ok(""));
        _ = new PwnedPasswordsClient(http, new PwnedPasswordsOptions { CacheMaxEntries = 0, CacheDuration = TimeSpan.Zero });
    }

    [Fact]
    public async Task Http_is_allowed_when_opted_in()
    {
        var api = FakeRangeApi.Ok("");
        var client = new PwnedPasswordsClient(api.CreateClient(), new PwnedPasswordsOptions
        {
            BaseAddress = new Uri("http://localhost:5080/"),
            AllowInsecureHttp = true,
        });
        await client.CheckAsync("password");
        Assert.Equal(new Uri("http://localhost:5080/range/5BAA6"), api.Requests[0].Uri);
    }

    [Fact]
    public async Task Options_are_copied_at_construction()
    {
        var api = FakeRangeApi.Ok("1E4C9B93F3F0682250B6CF8331B7EE68FD8:5");
        var options = new PwnedPasswordsOptions { MinimumOccurrences = 10 };
        var client = new PwnedPasswordsClient(api.CreateClient(), options);

        options.MinimumOccurrences = 1;
        options.BaseAddress = new Uri("https://elsewhere.example/");

        BreachCheckResult result = await client.CheckAsync("password");
        Assert.False(result.IsBreached);
        Assert.Equal("api.pwnedpasswords.com", api.Requests[0].Uri.Host);
    }
}

public class PwnedPasswordsServiceCollectionExtensionsTests
{
    private const string PasswordSuffix = "1E4C9B93F3F0682250B6CF8331B7EE68FD8";

    [Fact]
    public async Task Registers_a_breach_checker_backed_by_the_named_client()
    {
        var api = FakeRangeApi.Ok(PasswordSuffix + ":3");
        var services = new ServiceCollection();
        services.AddPwnedPasswords(o => o.UserAgent = "Test/1.0")
            .ConfigurePrimaryHttpMessageHandler(() => api);

        using ServiceProvider provider = services.BuildServiceProvider();
        IBreachedPasswordChecker checker = provider.GetRequiredService<IBreachedPasswordChecker>();

        BreachCheckResult result = await checker.CheckAsync("password", CancellationToken.None);
        Assert.True(result.IsBreached);
        Assert.Equal("Test/1.0", api.Requests[0].Headers["User-Agent"]);
        Assert.Equal("true", api.Requests[0].Headers["Add-Padding"]);
    }

    [Fact]
    public async Task Cache_is_shared_across_transient_client_instances()
    {
        var api = FakeRangeApi.Ok(PasswordSuffix + ":3");
        var services = new ServiceCollection();
        services.AddPwnedPasswords(o => o.EnableCache = true)
            .ConfigurePrimaryHttpMessageHandler(() => api);

        using ServiceProvider provider = services.BuildServiceProvider();
        PwnedPasswordsClient first = provider.GetRequiredService<PwnedPasswordsClient>();
        PwnedPasswordsClient second = provider.GetRequiredService<PwnedPasswordsClient>();
        Assert.NotSame(first, second);

        await first.CheckAsync("password");
        await second.CheckAsync("password");
        await provider.GetRequiredService<IBreachedPasswordChecker>().CheckAsync("password", CancellationToken.None);
        Assert.Equal(1, api.Count);
    }

    [Fact]
    public async Task Breach_checker_is_a_singleton_that_takes_a_fresh_HttpClient_per_lookup()
    {
        // Capturing a transient typed client in a singleton (e.g. PasswordPolicy) would pin one handler forever and
        // defeat IHttpClientFactory's handler rotation. HttpClient configure actions run once per CreateClient call.
        var api = FakeRangeApi.Ok(PasswordSuffix + ":3");
        int created = 0;
        var services = new ServiceCollection();
        services.AddPwnedPasswords()
            .ConfigurePrimaryHttpMessageHandler(() => api)
            .ConfigureHttpClient(_ => Interlocked.Increment(ref created));

        using ServiceProvider provider = services.BuildServiceProvider();
        IBreachedPasswordChecker checker = provider.GetRequiredService<IBreachedPasswordChecker>();
        Assert.Same(checker, provider.GetRequiredService<IBreachedPasswordChecker>());

        for (int i = 0; i < 3; i++)
            Assert.True((await checker.CheckAsync("password", CancellationToken.None)).IsBreached);
        Assert.Equal(3, created);
    }

    [Fact]
    public async Task Breach_checker_honours_the_failure_mode()
    {
        var services = new ServiceCollection();
        services.AddPwnedPasswords(o => o.FailureMode = PwnedPasswordsFailureMode.Throw)
            .ConfigurePrimaryHttpMessageHandler(() => FakeRangeApi.Status(HttpStatusCode.ServiceUnavailable));

        using ServiceProvider provider = services.BuildServiceProvider();
        IBreachedPasswordChecker checker = provider.GetRequiredService<IBreachedPasswordChecker>();
        await Assert.ThrowsAsync<PwnedPasswordsUnavailableException>(() => checker.CheckAsync("password", CancellationToken.None).AsTask());
    }

    [Fact]
    public async Task Default_http_client_loggers_are_removed_so_the_prefix_is_never_logged()
    {
        // IHttpClientFactory's default loggers write the request URI (".../range/5BAA6") at Information level. The
        // prefix is 20 bits of the password's SHA-1, so it must not reach application logs.
        var sink = new CapturingLoggerProvider();
        var services = new ServiceCollection();
        services.AddLogging(b => b.SetMinimumLevel(LogLevel.Trace).AddProvider(sink));
        services.AddPwnedPasswords()
            .ConfigurePrimaryHttpMessageHandler(() => FakeRangeApi.Ok(PasswordSuffix + ":3"));

        using ServiceProvider provider = services.BuildServiceProvider();
        await provider.GetRequiredService<IBreachedPasswordChecker>().CheckAsync("password", CancellationToken.None);
        await provider.GetRequiredService<PwnedPasswordsClient>().CheckAsync("password");

        Assert.DoesNotContain(sink.Messages, m => m.Contains("5BAA6", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(sink.Messages, m => m.Contains("/range/", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Without_configure_uses_defaults()
    {
        var api = FakeRangeApi.Ok("");
        var services = new ServiceCollection();
        services.AddPwnedPasswords().ConfigurePrimaryHttpMessageHandler(() => api);

        using ServiceProvider provider = services.BuildServiceProvider();
        await provider.GetRequiredService<PwnedPasswordsClient>().CheckAsync("password");
        Assert.Equal(new Uri("https://api.pwnedpasswords.com/range/5BAA6"), api.Requests[0].Uri);
        Assert.Equal(PwnedPasswordsOptions.DefaultUserAgent, api.Requests[0].Headers["User-Agent"]);
    }

    [Fact]
    public void Keeps_an_existing_breach_checker()
    {
        var services = new ServiceCollection();
        var mine = new StubChecker();
        services.AddSingleton<IBreachedPasswordChecker>(mine);
        services.AddPwnedPasswords();

        using ServiceProvider provider = services.BuildServiceProvider();
        Assert.Same(mine, provider.GetRequiredService<IBreachedPasswordChecker>());
        Assert.NotNull(provider.GetRequiredService<PwnedPasswordsClient>());
    }

    [Fact]
    public void Invalid_options_fail_on_resolve()
    {
        var services = new ServiceCollection();
        services.AddPwnedPasswords(o => o.Timeout = TimeSpan.Zero);
        using ServiceProvider provider = services.BuildServiceProvider();
        Assert.Throws<ArgumentException>(() => provider.GetRequiredService<IBreachedPasswordChecker>());
    }

    [Fact]
    public void Null_services_throw()
    {
        Assert.Equal("services", Assert.Throws<ArgumentNullException>(() => PwnedPasswordsServiceCollectionExtensions.AddPwnedPasswords(null!)).ParamName);
    }

    private sealed class CapturingLoggerProvider : ILoggerProvider, ILogger
    {
        private readonly ConcurrentQueue<string> _messages = new();

        public string[] Messages => _messages.ToArray();

        public ILogger CreateLogger(string categoryName) => this;

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull
        {
            _messages.Enqueue("scope: " + state);
            return null;
        }

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) =>
            _messages.Enqueue(formatter(state, exception));

        public void Dispose() { }
    }

    private sealed class StubChecker : IBreachedPasswordChecker
    {
        public ValueTask<BreachCheckResult> CheckAsync(string password, CancellationToken cancellationToken) =>
            new(BreachCheckResult.NotBreached);
    }
}
