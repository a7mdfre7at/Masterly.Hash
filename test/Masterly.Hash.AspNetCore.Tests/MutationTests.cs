using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using IdentityResult = Microsoft.AspNetCore.Identity.IdentityResult;
using IdentityVerificationResult = Microsoft.AspNetCore.Identity.PasswordVerificationResult;

namespace Masterly.Hash.AspNetCore.Tests;

/// <summary>Tests that pin exact boundaries, observable strings and side effects (mutation testing).</summary>
public class MutationTests
{
    // ---- Constructor limits: 1 is the smallest valid limit ----

    [Fact]
    public void Limits_OfOne_AreAccepted()
    {
        Assert.Equal(1, new PasswordLengthEndpointFilter(1).MaxPasswordBytes);
        Assert.Equal(1, new MasterlyPasswordLengthValidator<TestUser>(1).MaxPasswordBytes);

        // The adapter accepts 1 and enforces it: 8 chars is within the raw bound (reaches the hasher), 9 is not.
        var adapter = new MasterlyIdentityPasswordHasher<TestUser>(new BusyHasher(), 1);
        Assert.Throws<PasswordHasherBusyException>(() => adapter.HashPassword(new TestUser(), "a"));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void Limits_BelowOne_AreRejected_WithParamName(int limit)
    {
        Assert.Equal("maxPasswordBytes", Assert.Throws<ArgumentOutOfRangeException>(() => new PasswordLengthEndpointFilter(limit)).ParamName);
        Assert.Equal("maxPasswordBytes", Assert.Throws<ArgumentOutOfRangeException>(() => new MasterlyPasswordLengthValidator<TestUser>(limit)).ParamName);
        Assert.Equal("maxPasswordBytes", Assert.Throws<ArgumentOutOfRangeException>(() => new MasterlyIdentityPasswordHasher<TestUser>(new BusyHasher(), limit)).ParamName);
    }

    // ---- Configuration error messages (surface in startup logs when options are misconfigured) ----

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void Limits_BelowOne_HaveExactMessage(int limit)
    {
        string expected = new ArgumentOutOfRangeException("maxPasswordBytes", limit, "The limit must be positive.").Message;

        ArgumentOutOfRangeException filter = Assert.Throws<ArgumentOutOfRangeException>(() => new PasswordLengthEndpointFilter(limit));
        Assert.Equal(expected, filter.Message);
        Assert.StartsWith("The limit must be positive.", filter.Message, StringComparison.Ordinal);
        Assert.Equal(limit, filter.ActualValue);

        ArgumentOutOfRangeException validator = Assert.Throws<ArgumentOutOfRangeException>(() => new MasterlyPasswordLengthValidator<TestUser>(limit));
        Assert.Equal(expected, validator.Message);
        Assert.StartsWith("The limit must be positive.", validator.Message, StringComparison.Ordinal);
        Assert.Equal(limit, validator.ActualValue);

        ArgumentOutOfRangeException adapter = Assert.Throws<ArgumentOutOfRangeException>(() => new MasterlyIdentityPasswordHasher<TestUser>(new BusyHasher(), limit));
        Assert.Equal(expected, adapter.Message);
        Assert.StartsWith("The limit must be positive.", adapter.Message, StringComparison.Ordinal);
        Assert.Equal(limit, adapter.ActualValue);
    }

    [Theory]
    [InlineData(999)]
    [InlineData(86_400_001)]
    public void RetryAfter_OutOfRange_HasExactMessage(int milliseconds)
    {
        TimeSpan value = TimeSpan.FromMilliseconds(milliseconds);
        string expected = new ArgumentOutOfRangeException("value", value, "RetryAfter must be between 1 second and 1 day.").Message;

        ArgumentOutOfRangeException ex = Assert.Throws<ArgumentOutOfRangeException>(() => new MasterlyHashExceptionHandlerOptions { RetryAfter = value });
        Assert.Equal(expected, ex.Message);
        Assert.StartsWith("RetryAfter must be between 1 second and 1 day.", ex.Message, StringComparison.Ordinal);
        Assert.Equal("value", ex.ParamName);
        Assert.Equal(value, ex.ActualValue);
    }

    [Fact]
    public void Handler_NullOptionsValue_HasExactMessage()
    {
        string expected = new ArgumentException("Options value is null.", "options").Message;

        ArgumentException ex = Assert.Throws<ArgumentException>(() =>
            new PasswordHasherBusyExceptionHandler(new NullValueOptions(), NullLogger<PasswordHasherBusyExceptionHandler>.Instance));
        Assert.Equal(expected, ex.Message);
        Assert.StartsWith("Options value is null.", ex.Message, StringComparison.Ordinal);
        Assert.Equal("options", ex.ParamName);
    }

    // ---- Raw bound: exactly 8 x limit passes the cheap pre-check, 8 x limit + 1 does not ----

    [Fact]
    public void Adapter_RawBound_IsExclusiveAtEightTimesTheLimit()
    {
        var adapter = new MasterlyIdentityPasswordHasher<TestUser>(new BusyHasher(), 2);
        string atBound = new('a', 16);
        string overBound = new('a', 17);

        // At the bound the hasher is reached (and here reports busy); over it the adapter refuses up front.
        Assert.Throws<PasswordHasherBusyException>(() => adapter.HashPassword(new TestUser(), atBound));
        Assert.Throws<PasswordHasherBusyException>(() => adapter.VerifyHashedPassword(new TestUser(), "$mh$x", atBound));

        ArgumentException ex = Assert.Throws<ArgumentException>(() => adapter.HashPassword(new TestUser(), overBound));
        Assert.Equal("password", ex.ParamName);
        Assert.StartsWith("Password exceeds 2 bytes.", ex.Message, StringComparison.Ordinal);
        Assert.Equal(IdentityVerificationResult.Failed, adapter.VerifyHashedPassword(new TestUser(), "$mh$x", overBound));
    }

    [Fact]
    public void PasswordLength_RawBound_Boundary()
    {
        Assert.False(PasswordLength.ExceedsRawBound(new string('a', 8 * 3), 3));
        Assert.True(PasswordLength.ExceedsRawBound(new string('a', 8 * 3 + 1), 3));
    }

    // ---- Validator error descriptions ----

    [Fact]
    public async Task Validator_ErrorDescriptions_AreExact()
    {
        var validator = new MasterlyPasswordLengthValidator<TestUser>(64);

        IdentityResult empty = await validator.ValidateAsync(null!, new TestUser(), "");
        IdentityError required = Assert.Single(empty.Errors);
        Assert.Equal("PasswordRequired", required.Code);
        Assert.Equal("A password is required.", required.Description);

        IdentityResult tooLong = await validator.ValidateAsync(null!, new TestUser(), new string('a', 65));
        IdentityError error = Assert.Single(tooLong.Errors);
        Assert.Equal("PasswordTooLong", error.Code);
        Assert.Equal("Passwords must be at most 64 bytes long.", error.Description);
    }

    // ---- Endpoint filter problem details ----

    [Fact]
    public async Task Filter_Rejection_HasExactTitleAndDetail()
    {
        var filter = new PasswordLengthEndpointFilter(64);
        var context = new DefaultEndpointFilterInvocationContext(new DefaultHttpContext(), new SensitiveString(new string('a', 65)));

        object? result = await filter.InvokeAsync(context, _ => new ValueTask<object?>("ok"));

        ProblemHttpResult problem = Assert.IsType<ProblemHttpResult>(result);
        Assert.Equal(400, problem.StatusCode);
        Assert.Equal("Password too long", problem.ProblemDetails.Title);
        Assert.Equal("The password exceeds the maximum length of 64 bytes.", problem.ProblemDetails.Detail);
    }

    // ---- Exception handler: body fields ----

    [Fact]
    public async Task Handler_FallbackBody_HasExactProblemFields()
    {
        var context = new DefaultHttpContext();
        context.Response.Body = new MemoryStream();

        Assert.True(await CreateHandler(NullLogger<PasswordHasherBusyExceptionHandler>.Instance)
            .TryHandleAsync(context, new PasswordHasherBusyException(), CancellationToken.None));

        context.Response.Body.Position = 0;
        using JsonDocument body = JsonDocument.Parse(await new StreamReader(context.Response.Body).ReadToEndAsync());
        Assert.Equal("The server is busy. Try again later.", body.RootElement.GetProperty("detail").GetString());
        Assert.Equal("https://tools.ietf.org/html/rfc9110#section-15.6.4", body.RootElement.GetProperty("type").GetString());
        Assert.Equal("Service Unavailable", body.RootElement.GetProperty("title").GetString());
        Assert.Equal(503, body.RootElement.GetProperty("status").GetInt32());
    }

    [Fact]
    public async Task Handler_ProblemDetailsService_ReceivesExactProblem()
    {
        var service = new RecordingProblemDetailsService(Task.FromResult(true));
        var context = new DefaultHttpContext { RequestServices = new SingleServiceProvider(service) };
        var exception = new PasswordHasherBusyException();

        Assert.True(await CreateHandler(NullLogger<PasswordHasherBusyExceptionHandler>.Instance).TryHandleAsync(context, exception, CancellationToken.None));

        ProblemDetailsContext written = Assert.Single(service.Contexts);
        Assert.Same(context, written.HttpContext);
        Assert.Same(exception, written.Exception);
        Assert.Equal(503, written.ProblemDetails.Status);
        Assert.Equal("The server is busy. Try again later.", written.ProblemDetails.Detail);
        Assert.Equal("https://tools.ietf.org/html/rfc9110#section-15.6.4", written.ProblemDetails.Type);
    }

    // ---- Exception handler: logging ----

    [Fact]
    public async Task Handler_LogsWarning_WhenResponding503()
    {
        var logger = new CapturingLogger();
        var context = new DefaultHttpContext();
        context.Response.Body = new MemoryStream();

        await CreateHandler(logger, TimeSpan.FromSeconds(7)).TryHandleAsync(context, new PasswordHasherBusyException(), CancellationToken.None);

        CapturingLogger.Entry entry = Assert.Single(logger.Entries);
        Assert.Equal(LogLevel.Warning, entry.Level);
        Assert.Equal("The password hasher is at its concurrency limit; responding 503 with Retry-After 7s.", entry.Message);
        Assert.Contains(entry.State, kv => kv.Key == "RetryAfter" && Equals(kv.Value, "7"));
        Assert.Contains(entry.State, kv => kv.Key == "{OriginalFormat}" &&
            Equals(kv.Value, "The password hasher is at its concurrency limit; responding 503 with Retry-After {RetryAfter}s."));
    }

    [Fact]
    public async Task Handler_LogsWarning_WhenResponseAlreadyStarted()
    {
        var logger = new CapturingLogger();
        var context = new DefaultHttpContext();
        context.Features.Set<IHttpResponseFeature>(new StartedResponseFeature());

        Assert.False(await CreateHandler(logger).TryHandleAsync(context, new PasswordHasherBusyException(), CancellationToken.None));

        CapturingLogger.Entry entry = Assert.Single(logger.Entries);
        Assert.Equal(LogLevel.Warning, entry.Level);
        Assert.Equal("The password hasher is at its concurrency limit, but the response has already started; cannot send 503.", entry.Message);
    }

    [Fact]
    public async Task Handler_DoesNotLog_ForOtherExceptions()
    {
        var logger = new CapturingLogger();
        Assert.False(await CreateHandler(logger).TryHandleAsync(new DefaultHttpContext(), new InvalidOperationException(), CancellationToken.None));
        Assert.Empty(logger.Entries);
    }

    // ---- Exception handler: continuations do not capture the caller's synchronization context ----

    [Fact]
    public async Task Handler_ProblemDetailsWrite_DoesNotResumeOnCapturedContext()
    {
        var pending = new TaskCompletionSource<bool>();
        var context = new DefaultHttpContext { RequestServices = new SingleServiceProvider(new RecordingProblemDetailsService(pending.Task)) };
        PasswordHasherBusyExceptionHandler handler = CreateHandler(NullLogger<PasswordHasherBusyExceptionHandler>.Instance);

        var syncContext = new RecordingSynchronizationContext();
        ValueTask<bool> result = RunUnder(syncContext, () => handler.TryHandleAsync(context, new PasswordHasherBusyException(), CancellationToken.None));
        Assert.False(result.IsCompleted);

        // Completed with no context current, where the runtime may inline continuations.
        RunUnder(null, () => pending.TrySetResult(true));

        Assert.True(await result);
        Assert.False(syncContext.ResumedHandler, "The handler must not resume on the caller's synchronization context.");
    }

    [Fact]
    public async Task Handler_FallbackWrite_DoesNotResumeOnCapturedContext()
    {
        var body = new PendingWriteStream();
        var context = new DefaultHttpContext();
        context.Response.Body = body;
        PasswordHasherBusyExceptionHandler handler = CreateHandler(NullLogger<PasswordHasherBusyExceptionHandler>.Instance);

        var syncContext = new RecordingSynchronizationContext();
        ValueTask<bool> result = RunUnder(syncContext, () => handler.TryHandleAsync(context, new PasswordHasherBusyException(), CancellationToken.None));
        Assert.False(result.IsCompleted);

        // Completed with no context current, where the runtime may inline continuations.
        RunUnder(null, () => body.Pending.TrySetResult());

        Assert.True(await result);
        Assert.False(syncContext.ResumedHandler, "The handler must not resume on the caller's synchronization context.");
        Assert.Contains("\"status\":503", System.Text.Encoding.UTF8.GetString(body.Written.ToArray()), StringComparison.Ordinal);
    }

    // ---- IsBusy depth limit: depth 8 is searched, depth 9 is not ----

    [Fact]
    public void IsBusy_InnerExceptionChain_DepthBoundary()
    {
        Assert.True(PasswordHasherBusyExceptionHandler.IsBusy(WrapInner(8), 0));
        Assert.False(PasswordHasherBusyExceptionHandler.IsBusy(WrapInner(9), 0));
        Assert.True(PasswordHasherBusyExceptionHandler.IsBusy(new PasswordHasherBusyException(), 8));
        Assert.False(PasswordHasherBusyExceptionHandler.IsBusy(new PasswordHasherBusyException(), 9));
    }

    [Fact]
    public void IsBusy_AggregateChain_DepthBoundary()
    {
        Assert.True(PasswordHasherBusyExceptionHandler.IsBusy(WrapAggregate(8), 0));
        Assert.False(PasswordHasherBusyExceptionHandler.IsBusy(WrapAggregate(9), 0));
        Assert.False(PasswordHasherBusyExceptionHandler.IsBusy(WrapAggregate(20), 0));
    }

    // ---- Service registration ----

    [Fact]
    public void AddMasterlyHashExceptionHandler_RegistersOptions_WithoutOtherOptionsUsers()
    {
        // No AddLogging (which would register the options infrastructure itself) and no configure step.
        var services = new ServiceCollection();
        services.AddSingleton(typeof(ILogger<>), typeof(NullLogger<>));

        services.AddMasterlyHashExceptionHandler();

        using ServiceProvider provider = services.BuildServiceProvider();
        Assert.IsType<PasswordHasherBusyExceptionHandler>(Assert.Single(provider.GetServices<IExceptionHandler>()));
        Assert.Equal(TimeSpan.FromSeconds(5), provider.GetRequiredService<IOptions<MasterlyHashExceptionHandlerOptions>>().Value.RetryAfter);
    }

    [Fact]
    public void AddMasterlyHashExceptionHandler_NullServices_ThrowsWithParamName() =>
        Assert.Equal("services", Assert.Throws<ArgumentNullException>(() =>
            MasterlyHashAspNetCoreServiceCollectionExtensions.AddMasterlyHashExceptionHandler(null!)).ParamName);

    // ---- helpers ----

    private static Exception WrapInner(int levels)
    {
        Exception exception = new PasswordHasherBusyException();
        for (int i = 0; i < levels; i++)
            exception = new InvalidOperationException("wrap", exception);
        return exception;
    }

    private static Exception WrapAggregate(int levels)
    {
        Exception exception = new PasswordHasherBusyException();
        for (int i = 0; i < levels; i++)
            exception = new AggregateException(exception);
        return exception;
    }

    private static PasswordHasherBusyExceptionHandler CreateHandler(ILogger<PasswordHasherBusyExceptionHandler> logger, TimeSpan? retryAfter = null)
    {
        var options = new MasterlyHashExceptionHandlerOptions();
        if (retryAfter.HasValue)
            options.RetryAfter = retryAfter.Value;
        return new PasswordHasherBusyExceptionHandler(Options.Create(options), logger);
    }

    private static T RunUnder<T>(SynchronizationContext? context, Func<T> action)
    {
        SynchronizationContext? previous = SynchronizationContext.Current;
        SynchronizationContext.SetSynchronizationContext(context);
        try
        {
            return action();
        }
        finally
        {
            SynchronizationContext.SetSynchronizationContext(previous);
        }
    }

    /// <summary>
    /// Records which async methods resume through it, then runs them on the thread pool (so a captured continuation
    /// still completes and the test cannot hang).
    /// </summary>
    private sealed class RecordingSynchronizationContext : SynchronizationContext
    {
        private readonly List<string> _resumed = new();

        public bool ResumedHandler
        {
            get
            {
                lock (_resumed)
                    return _resumed.Exists(name => name.Contains(nameof(PasswordHasherBusyExceptionHandler), StringComparison.Ordinal));
            }
        }

        public override void Post(SendOrPostCallback d, object? state)
        {
            // An await continuation is posted with the state machine box's MoveNext delegate as state.
            string name = (state is Delegate continuation ? continuation.Target?.GetType().FullName : state?.GetType().FullName) ?? "";
            lock (_resumed)
                _resumed.Add(name);
            ThreadPool.UnsafeQueueUserWorkItem(_ => d(state), null);
        }
    }

    private sealed class PendingWriteStream : Stream
    {
        public TaskCompletionSource Pending { get; } = new();
        public MemoryStream Written { get; } = new();

        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => Written.Write(buffer, offset, count);

        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            Written.Write(buffer, offset, count);
            return Pending.Task;
        }

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            Written.Write(buffer.Span);
            return new ValueTask(Pending.Task);
        }
    }

    private sealed class RecordingProblemDetailsService : IProblemDetailsService
    {
        private readonly Task<bool> _result;

        public RecordingProblemDetailsService(Task<bool> result) => _result = result;

        public List<ProblemDetailsContext> Contexts { get; } = new();

        public ValueTask WriteAsync(ProblemDetailsContext context) => throw new NotSupportedException();

        public ValueTask<bool> TryWriteAsync(ProblemDetailsContext context)
        {
            Contexts.Add(context);
            return new ValueTask<bool>(_result);
        }
    }

    private sealed class SingleServiceProvider : IServiceProvider
    {
        private readonly IProblemDetailsService _service;

        public SingleServiceProvider(IProblemDetailsService service) => _service = service;

        public object? GetService(Type serviceType) => serviceType == typeof(IProblemDetailsService) ? _service : null;
    }

    private sealed class CapturingLogger : ILogger<PasswordHasherBusyExceptionHandler>
    {
        public sealed record Entry(LogLevel Level, string Message, IReadOnlyList<KeyValuePair<string, object?>> State);

        public List<Entry> Entries { get; } = new();

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            IReadOnlyList<KeyValuePair<string, object?>> pairs = state as IReadOnlyList<KeyValuePair<string, object?>> ?? Array.Empty<KeyValuePair<string, object?>>();
            Entries.Add(new Entry(logLevel, formatter(state, exception), pairs));
        }
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
