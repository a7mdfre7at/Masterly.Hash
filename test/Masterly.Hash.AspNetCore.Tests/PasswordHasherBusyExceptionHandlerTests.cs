using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Reflection;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Masterly.Hash.AspNetCore.Tests;

public class PasswordHasherBusyExceptionHandlerTests
{
    private static PasswordHasherBusyExceptionHandler CreateHandler(Action<MasterlyHashExceptionHandlerOptions>? configure = null)
    {
        var options = new MasterlyHashExceptionHandlerOptions();
        configure?.Invoke(options);
        return new PasswordHasherBusyExceptionHandler(Options.Create(options), NullLogger<PasswordHasherBusyExceptionHandler>.Instance);
    }

    private static DefaultHttpContext CreateContext(IServiceProvider? services = null)
    {
        var context = new DefaultHttpContext();
        context.Response.Body = new MemoryStream();
        if (services != null)
            context.RequestServices = services;
        return context;
    }

    private static string ReadBody(HttpContext context)
    {
        context.Response.Body.Position = 0;
        return new StreamReader(context.Response.Body).ReadToEnd();
    }

    [Fact]
    public async Task BusyException_Returns503WithRetryAfterAndProblemDetails()
    {
        DefaultHttpContext context = CreateContext();

        bool handled = await CreateHandler().TryHandleAsync(context, new PasswordHasherBusyException(), CancellationToken.None);

        Assert.True(handled);
        Assert.Equal(503, context.Response.StatusCode);
        Assert.Equal("5", context.Response.Headers.RetryAfter.ToString());
        Assert.Equal("no-store", context.Response.Headers.CacheControl.ToString());
        Assert.StartsWith("application/problem+json", context.Response.ContentType, StringComparison.Ordinal);

        using JsonDocument body = JsonDocument.Parse(ReadBody(context));
        Assert.Equal(503, body.RootElement.GetProperty("status").GetInt32());
        Assert.Equal("Service Unavailable", body.RootElement.GetProperty("title").GetString());
    }

    [Theory]
    [InlineData(1000, "1")]
    [InlineData(2500, "3")]
    [InlineData(60_000, "60")]
    [InlineData(86_400_000, "86400")]
    public async Task RetryAfter_IsRoundedUpToWholeSeconds(int milliseconds, string expected)
    {
        DefaultHttpContext context = CreateContext();
        await CreateHandler(o => o.RetryAfter = TimeSpan.FromMilliseconds(milliseconds)).TryHandleAsync(context, new PasswordHasherBusyException(), CancellationToken.None);
        Assert.Equal(expected, context.Response.Headers.RetryAfter.ToString());
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1000)]
    [InlineData(999)]
    [InlineData(86_400_001)]
    public void RetryAfter_OutOfRange_Throws(int milliseconds) =>
        Assert.Equal("value", Assert.Throws<ArgumentOutOfRangeException>(() => new MasterlyHashExceptionHandlerOptions { RetryAfter = TimeSpan.FromMilliseconds(milliseconds) }).ParamName);

    [Fact]
    public void Constructor_GuardsNulls()
    {
        Assert.Equal("options", Assert.Throws<ArgumentNullException>(() => new PasswordHasherBusyExceptionHandler(null!, NullLogger<PasswordHasherBusyExceptionHandler>.Instance)).ParamName);
        Assert.Equal("logger", Assert.Throws<ArgumentNullException>(() => new PasswordHasherBusyExceptionHandler(Options.Create(new MasterlyHashExceptionHandlerOptions()), null!)).ParamName);
    }

    [Fact]
    public void Constructor_NullOptionsValue_Throws()
    {
        var ex = Assert.Throws<ArgumentException>(() => new PasswordHasherBusyExceptionHandler(new NullValueOptions(), NullLogger<PasswordHasherBusyExceptionHandler>.Instance));
        Assert.Equal("options", ex.ParamName);
    }

    [Fact]
    public async Task AggregateWithoutBusyInner_IsNotHandled()
    {
        var notBusy = new Exception[]
        {
            new AggregateException(),
            new AggregateException(new InvalidOperationException(), new TimeoutException("t", new ArgumentException())),
            new InvalidOperationException("outer", new AggregateException(new OperationCanceledException())),
        };
        foreach (Exception exception in notBusy)
        {
            DefaultHttpContext context = CreateContext();
            Assert.False(await CreateHandler().TryHandleAsync(context, exception, CancellationToken.None));
            Assert.Equal(200, context.Response.StatusCode);
            Assert.False(context.Response.Headers.ContainsKey("Retry-After"));
        }
    }

    [Fact]
    public void IsBusy_AggregateIsSearchedPastNonBusyInnerExceptions()
    {
        Assert.True(PasswordHasherBusyExceptionHandler.IsBusy(
            new AggregateException(new InvalidOperationException(), new AggregateException(new TimeoutException(), new PasswordHasherBusyException())), 0));
        Assert.False(PasswordHasherBusyExceptionHandler.IsBusy(new AggregateException(new InvalidOperationException()), 0));
    }

    [Fact]
    public async Task TryHandle_GuardsNulls()
    {
        PasswordHasherBusyExceptionHandler handler = CreateHandler();
        await Assert.ThrowsAsync<ArgumentNullException>(() => handler.TryHandleAsync(null!, new PasswordHasherBusyException(), CancellationToken.None).AsTask());
        await Assert.ThrowsAsync<ArgumentNullException>(() => handler.TryHandleAsync(new DefaultHttpContext(), null!, CancellationToken.None).AsTask());
    }

    [Theory]
    [InlineData(typeof(InvalidOperationException))]
    [InlineData(typeof(TimeoutException))]
    [InlineData(typeof(OperationCanceledException))]
    public async Task OtherExceptions_AreNotHandled(Type exceptionType)
    {
        DefaultHttpContext context = CreateContext();
        var exception = (Exception)Activator.CreateInstance(exceptionType)!;

        bool handled = await CreateHandler().TryHandleAsync(context, exception, CancellationToken.None);

        Assert.False(handled);
        Assert.Equal(200, context.Response.StatusCode);
        Assert.False(context.Response.Headers.ContainsKey("Retry-After"));
        Assert.Equal(0, context.Response.Body.Length);
    }

    [Fact]
    public async Task WrappedBusyException_IsHandled()
    {
        var wrapped = new Exception[]
        {
            new InvalidOperationException("outer", new PasswordHasherBusyException()),
            new AggregateException(new ArgumentException(), new PasswordHasherBusyException()),
            new TargetInvocationException(new AggregateException(new PasswordHasherBusyException())),
        };
        foreach (Exception exception in wrapped)
        {
            DefaultHttpContext context = CreateContext();
            Assert.True(await CreateHandler().TryHandleAsync(context, exception, CancellationToken.None));
            Assert.Equal(503, context.Response.StatusCode);
        }
    }

    [Fact]
    public void IsBusy_StopsAtDepthLimit()
    {
        Exception exception = new PasswordHasherBusyException();
        for (int i = 0; i < 20; i++)
            exception = new InvalidOperationException("wrap", exception);
        Assert.False(PasswordHasherBusyExceptionHandler.IsBusy(exception, 0));
        Assert.False(PasswordHasherBusyExceptionHandler.IsBusy(null, 0));
    }

    [Fact]
    public async Task ResponseAlreadyStarted_IsNotHandled()
    {
        var context = new DefaultHttpContext();
        context.Features.Set<IHttpResponseFeature>(new StartedResponseFeature());

        Assert.False(await CreateHandler().TryHandleAsync(context, new PasswordHasherBusyException(), CancellationToken.None));
        Assert.Equal(200, context.Response.StatusCode);
    }

    [Fact]
    public async Task UsesRegisteredProblemDetailsService()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddProblemDetails(o => o.CustomizeProblemDetails = c => c.ProblemDetails.Extensions["custom"] = "yes");
        using ServiceProvider provider = services.BuildServiceProvider();
        DefaultHttpContext context = CreateContext(provider);
        context.Request.Headers.Accept = "application/json";

        Assert.True(await CreateHandler().TryHandleAsync(context, new PasswordHasherBusyException(), CancellationToken.None));

        Assert.Equal(503, context.Response.StatusCode);
        Assert.Equal("5", context.Response.Headers.RetryAfter.ToString());
        using JsonDocument body = JsonDocument.Parse(ReadBody(context));
        Assert.Equal("yes", body.RootElement.GetProperty("custom").GetString());
        Assert.Equal(503, body.RootElement.GetProperty("status").GetInt32());
    }

    [Fact]
    public void AddMasterlyHashExceptionHandler_RegistersOnce_AndAppliesOptions()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddMasterlyHashExceptionHandler().AddMasterlyHashExceptionHandler(o => o.RetryAfter = TimeSpan.FromSeconds(30));

        Assert.Single(services, d => d.ServiceType == typeof(IExceptionHandler));
        using ServiceProvider provider = services.BuildServiceProvider();
        Assert.IsType<PasswordHasherBusyExceptionHandler>(Assert.Single(provider.GetServices<IExceptionHandler>()));
        Assert.Equal(TimeSpan.FromSeconds(30), provider.GetRequiredService<IOptions<MasterlyHashExceptionHandlerOptions>>().Value.RetryAfter);
    }

    [Fact]
    public void AddMasterlyHashExceptionHandler_NullServices_Throws() =>
        Assert.Throws<ArgumentNullException>(() => MasterlyHashAspNetCoreServiceCollectionExtensions.AddMasterlyHashExceptionHandler(null!));

    [Fact]
    public async Task Pipeline_MapsBusyTo503_AndLeavesOtherErrorsAlone()
    {
        WebApplicationBuilder builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Logging.ClearProviders();
        builder.Services.AddProblemDetails();
        builder.Services.AddMasterlyHashExceptionHandler(o => o.RetryAfter = TimeSpan.FromSeconds(7));
        await using WebApplication app = builder.Build();
        app.UseExceptionHandler();
        app.MapGet("/busy", string () => throw new PasswordHasherBusyException());
        app.MapGet("/boom", string () => throw new InvalidOperationException("secret detail"));
        await app.StartAsync();
        HttpClient client = app.GetTestClient();

        HttpResponseMessage busy = await client.GetAsync("/busy");
        Assert.Equal(HttpStatusCode.ServiceUnavailable, busy.StatusCode);
        Assert.Equal(TimeSpan.FromSeconds(7), busy.Headers.RetryAfter?.Delta);
        string busyBody = await busy.Content.ReadAsStringAsync();
        Assert.DoesNotContain("concurrency limit", busyBody, StringComparison.Ordinal);

        HttpResponseMessage boom = await client.GetAsync("/boom");
        Assert.Equal(HttpStatusCode.InternalServerError, boom.StatusCode);
        Assert.Null(boom.Headers.RetryAfter);
    }

    [Fact]
    public async Task Pipeline_BusyThroughIdentityAdapter_Returns503()
    {
        WebApplicationBuilder builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Logging.ClearProviders();
        builder.Services.AddProblemDetails();
        builder.Services.AddMasterlyHashExceptionHandler();
        await using WebApplication app = builder.Build();
        app.UseExceptionHandler();
        var adapter = new MasterlyIdentityPasswordHasher<TestUser>(new BusyHasher(), 1024);
        app.MapPost("/register", string () => adapter.HashPassword(new TestUser(), "password"));
        await app.StartAsync();

        HttpResponseMessage response = await app.GetTestClient().PostAsync("/register", null);

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.Equal(TimeSpan.FromSeconds(5), response.Headers.RetryAfter?.Delta);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        Assert.True(response.Headers.CacheControl?.NoStore);
        Assert.Equal("5", Assert.Single(response.Headers.GetValues("Retry-After")));
    }

    private sealed class NullValueOptions : IOptions<MasterlyHashExceptionHandlerOptions>
    {
        public MasterlyHashExceptionHandlerOptions Value => null!;
    }

    private sealed class StartedResponseFeature : HttpResponseFeature
    {
        public override bool HasStarted => true;
    }
}
