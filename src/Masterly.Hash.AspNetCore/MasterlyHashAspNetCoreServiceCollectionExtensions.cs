using System;
using Masterly.Hash.AspNetCore;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Microsoft.Extensions.DependencyInjection
{
    /// <summary>Registers the Masterly.Hash ASP.NET Core services.</summary>
    public static class MasterlyHashAspNetCoreServiceCollectionExtensions
    {
        /// <summary>
        /// Registers <see cref="PasswordHasherBusyExceptionHandler"/>, which answers a <see cref="Masterly.Hash.PasswordHasherBusyException"/>
        /// with <c>503 Service Unavailable</c> and <c>Retry-After</c>. Calling it again only adds configure steps.
        /// </summary>
        /// <remarks>
        /// Exception handlers run in registration order, so call this before registering a catch-all handler.
        /// The handlers run inside the exception handler middleware: also call <c>app.UseExceptionHandler()</c>, which on
        /// .NET 8 additionally needs <c>services.AddProblemDetails()</c> (or an error path) to start.
        /// </remarks>
        /// <param name="services">The service collection.</param>
        /// <param name="configure">Optional configure step, e.g. <c>o =&gt; o.RetryAfter = TimeSpan.FromSeconds(10)</c>.</param>
        /// <returns>The same service collection, for chaining.</returns>
        public static IServiceCollection AddMasterlyHashExceptionHandler(this IServiceCollection services, Action<MasterlyHashExceptionHandlerOptions>? configure = null)
        {
            if (services == null) throw new ArgumentNullException(nameof(services));

            services.AddOptions<MasterlyHashExceptionHandlerOptions>();
            if (configure != null)
                services.Configure(configure);
            services.TryAddEnumerable(ServiceDescriptor.Singleton<IExceptionHandler, PasswordHasherBusyExceptionHandler>());
            return services;
        }
    }
}
