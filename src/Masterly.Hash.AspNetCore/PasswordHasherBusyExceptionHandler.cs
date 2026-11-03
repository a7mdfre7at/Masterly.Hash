using System;
using System.Globalization;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Masterly.Hash.AspNetCore
{
    /// <summary>Options for <see cref="PasswordHasherBusyExceptionHandler"/>.</summary>
    public sealed class MasterlyHashExceptionHandlerOptions
    {
        private TimeSpan _retryAfter = TimeSpan.FromSeconds(5);

        /// <summary>
        /// Value of the <c>Retry-After</c> header, rounded up to whole seconds. Default 5 seconds; must be between
        /// 1 second and 1 day.
        /// </summary>
        public TimeSpan RetryAfter
        {
            get => _retryAfter;
            set
            {
                if (value < TimeSpan.FromSeconds(1) || value > TimeSpan.FromDays(1))
                    throw new ArgumentOutOfRangeException(nameof(value), value, "RetryAfter must be between 1 second and 1 day.");
                _retryAfter = value;
            }
        }
    }

    /// <summary>
    /// Turns a <see cref="PasswordHasherBusyException"/> into <c>503 Service Unavailable</c> with a <c>Retry-After</c>
    /// header and a problem details body, so clients back off instead of piling more logins onto a saturated hasher.
    /// Other exceptions are left to the next handler. Register it with <c>services.AddMasterlyHashExceptionHandler()</c>
    /// and enable the middleware with <c>app.UseExceptionHandler()</c>.
    /// </summary>
    public sealed class PasswordHasherBusyExceptionHandler : IExceptionHandler
    {
        private const int MaxDepth = 8;

        private readonly string _retryAfterSeconds;
        private readonly ILogger<PasswordHasherBusyExceptionHandler> _logger;

        /// <summary>Creates the handler.</summary>
        public PasswordHasherBusyExceptionHandler(IOptions<MasterlyHashExceptionHandlerOptions> options, ILogger<PasswordHasherBusyExceptionHandler> logger)
        {
            if (options == null) throw new ArgumentNullException(nameof(options));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));

            MasterlyHashExceptionHandlerOptions value = options.Value ?? throw new ArgumentException("Options value is null.", nameof(options));
            _retryAfterSeconds = ((long)Math.Ceiling(value.RetryAfter.TotalSeconds)).ToString(CultureInfo.InvariantCulture);
        }

        /// <inheritdoc />
        public async ValueTask<bool> TryHandleAsync(HttpContext httpContext, Exception exception, CancellationToken cancellationToken)
        {
            if (httpContext == null) throw new ArgumentNullException(nameof(httpContext));
            if (exception == null) throw new ArgumentNullException(nameof(exception));

            if (!IsBusy(exception, 0))
                return false;

            HttpResponse response = httpContext.Response;
            if (response.HasStarted)
            {
                _logger.LogWarning("The password hasher is at its concurrency limit, but the response has already started; cannot send 503.");
                return false;
            }

            _logger.LogWarning("The password hasher is at its concurrency limit; responding 503 with Retry-After {RetryAfter}s.", _retryAfterSeconds);

            response.StatusCode = StatusCodes.Status503ServiceUnavailable;
            response.Headers.RetryAfter = _retryAfterSeconds;
            response.Headers.CacheControl = "no-store";

            var problem = new ProblemDetails
            {
                Status = StatusCodes.Status503ServiceUnavailable,
                Title = "Service Unavailable",
                Detail = "The server is busy. Try again later.",
                Type = "https://tools.ietf.org/html/rfc9110#section-15.6.4",
            };

            IProblemDetailsService? problemDetails = httpContext.RequestServices?.GetService<IProblemDetailsService>();
            if (problemDetails != null &&
                await problemDetails.TryWriteAsync(new ProblemDetailsContext { HttpContext = httpContext, ProblemDetails = problem, Exception = exception }).ConfigureAwait(false))
            {
                return true;
            }

            await response.WriteAsJsonAsync(problem, (JsonSerializerOptions?)null, "application/problem+json", cancellationToken).ConfigureAwait(false);
            return true;
        }

        /// <summary>True if <paramref name="exception"/> is, or wraps, a <see cref="PasswordHasherBusyException"/>.</summary>
        internal static bool IsBusy(Exception? exception, int depth)
        {
            if (exception == null || depth > MaxDepth)
                return false;
            if (exception is PasswordHasherBusyException)
                return true;
            if (exception is AggregateException aggregate)
            {
                foreach (Exception inner in aggregate.InnerExceptions)
                {
                    if (IsBusy(inner, depth + 1))
                        return true;
                }
                return false;
            }
            return IsBusy(exception.InnerException, depth + 1);
        }
    }
}
