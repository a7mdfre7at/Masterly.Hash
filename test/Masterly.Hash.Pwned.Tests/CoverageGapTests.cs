using System;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Masterly.Hash.Policy;
using Masterly.Hash.Pwned.Internal;

namespace Masterly.Hash.Pwned.Tests;

/// <summary>Edge paths not reached by the scenario tests.</summary>
public class CoverageGapTests
{
    [Fact]
    public void Exception_constructors_set_message_and_inner_exception()
    {
        var plain = new PwnedPasswordsUnavailableException();
        Assert.Equal("The Pwned Passwords service is unavailable.", plain.Message);
        Assert.Null(plain.InnerException);

        Assert.Equal("custom", new PwnedPasswordsUnavailableException("custom").Message);

        var inner = new TimeoutException();
        var wrapped = new PwnedPasswordsUnavailableException("outer", inner);
        Assert.Equal("outer", wrapped.Message);
        Assert.Same(inner, wrapped.InnerException);
    }

    [Fact]
    public async Task Response_with_null_content_is_reported_as_malformed()
    {
        // On modern runtimes a null Content reads back as an empty body; either way it must not count as "not breached".
        var api = new FakeRangeApi((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = null! }));
        var client = new PwnedPasswordsClient(api.CreateClient(), new PwnedPasswordsOptions { FailureMode = PwnedPasswordsFailureMode.Throw });

        var ex = await Assert.ThrowsAsync<PwnedPasswordsUnavailableException>(() => client.CheckAsync("password").AsTask());
        Assert.Equal("The Pwned Passwords service returned a malformed range.", ex.Message);
    }

    [Fact]
    public void Breach_checker_rejects_null_arguments()
    {
        var factory = new SingleClientFactory(FakeRangeApi.Ok(""));
        var options = new PwnedPasswordsOptions();

        Assert.Equal("httpClientFactory", Assert.Throws<ArgumentNullException>(() => new PwnedPasswordsBreachChecker(null!, "n", options, null)).ParamName);
        Assert.Equal("clientName", Assert.Throws<ArgumentNullException>(() => new PwnedPasswordsBreachChecker(factory, null!, options, null)).ParamName);
        Assert.Equal("options", Assert.Throws<ArgumentNullException>(() => new PwnedPasswordsBreachChecker(factory, "n", null!, null)).ParamName);

        var checker = new PwnedPasswordsBreachChecker(factory, "n", options, null);
        Assert.Equal("password", Assert.Throws<ArgumentNullException>(() => { _ = checker.CheckAsync(null!, CancellationToken.None); }).ParamName);
        Assert.Equal(0, factory.Created);
    }

    [Fact]
    public void Validate_and_CreateCache_reject_null_options()
    {
        Assert.Equal("options", Assert.Throws<ArgumentNullException>(() => PwnedPasswordsClient.Validate(null!)).ParamName);
        Assert.Equal("options", Assert.Throws<ArgumentNullException>(() => PwnedPasswordsClient.CreateCache(null!)).ParamName);
    }

    [Fact]
    public async Task Breach_checker_uses_the_named_client()
    {
        const string suffix = "1E4C9B93F3F0682250B6CF8331B7EE68FD8"; // SHA-1("password") minus the 5BAA6 prefix
        var factory = new SingleClientFactory(FakeRangeApi.Ok(suffix + ":7"));
        var checker = new PwnedPasswordsBreachChecker(factory, "pwned", new PwnedPasswordsOptions(), null);

        BreachCheckResult result = await checker.CheckAsync("password", CancellationToken.None);

        Assert.True(result.IsBreached);
        Assert.Equal(7, result.Occurrences);
        Assert.Equal("pwned", factory.LastName);
    }

    private sealed class SingleClientFactory : IHttpClientFactory
    {
        private readonly FakeRangeApi _api;

        public SingleClientFactory(FakeRangeApi api) => _api = api;

        public int Created { get; private set; }

        public string? LastName { get; private set; }

        public HttpClient CreateClient(string name)
        {
            Created++;
            LastName = name;
            return _api.CreateClient();
        }
    }
}
