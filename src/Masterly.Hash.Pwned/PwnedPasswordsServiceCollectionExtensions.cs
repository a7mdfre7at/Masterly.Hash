using System;
using System.Net.Http;
using Masterly.Hash.Policy;
using Masterly.Hash.Pwned;
using Masterly.Hash.Pwned.Internal;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace Microsoft.Extensions.DependencyInjection
{
    /// <summary>Registers the Pwned Passwords breach checker.</summary>
    public static class PwnedPasswordsServiceCollectionExtensions
    {
        /// <summary>The name of the <see cref="HttpClient"/> registered by <see cref="AddPwnedPasswords"/>.</summary>
        public const string HttpClientName = nameof(PwnedPasswordsClient);

        /// <summary>
        /// Registers a named <see cref="HttpClient"/> (<see cref="HttpClientName"/>), <see cref="PwnedPasswordsClient"/>
        /// as a transient typed client on it, and a singleton <see cref="IBreachedPasswordChecker"/> (unless one is
        /// already registered). Options come from <c>IOptions&lt;PwnedPasswordsOptions&gt;</c>;
        /// <paramref name="configure"/> adds a configure step. Invalid options throw <see cref="ArgumentException"/>
        /// when the checker or client is first resolved.
        /// </summary>
        /// <remarks>
        /// <para>
        /// The <see cref="IBreachedPasswordChecker"/> is safe to capture in singletons: it creates a fresh
        /// <see cref="HttpClient"/> from <c>IHttpClientFactory</c> for each lookup. Do not capture the transient
        /// <see cref="PwnedPasswordsClient"/> in a singleton; that pins one handler and stops DNS changes being seen.
        /// </para>
        /// <para>
        /// The factory's default request loggers are removed from this client, because they log the request URI and
        /// the 5-character prefix in it is derived from the password. Adding a logger back (<c>AddLogger</c>) or a
        /// handler that records URIs reintroduces that leak.
        /// </para>
        /// <para>
        /// The range cache (when <see cref="PwnedPasswordsOptions.EnableCache"/> is set) is a singleton shared by
        /// every instance, built from the options as they are on first use.
        /// </para>
        /// </remarks>
        /// <param name="services">The service collection.</param>
        /// <param name="configure">Optional configure step, e.g. <c>o =&gt; o.UserAgent = "Contoso-SignUp/1.4"</c>.</param>
        /// <returns>The HTTP client builder, to add handlers such as a resilience pipeline.</returns>
        public static IHttpClientBuilder AddPwnedPasswords(this IServiceCollection services, Action<PwnedPasswordsOptions>? configure = null)
        {
            if (services == null) throw new ArgumentNullException(nameof(services));

            services.AddOptions<PwnedPasswordsOptions>();
            if (configure != null)
                services.Configure(configure);

            services.TryAddSingleton(sp => new PwnedPasswordsCacheHolder(
                PwnedPasswordsClient.CreateCache(sp.GetRequiredService<IOptions<PwnedPasswordsOptions>>().Value)));
            services.TryAddSingleton<IBreachedPasswordChecker>(sp => new PwnedPasswordsBreachChecker(
                sp.GetRequiredService<IHttpClientFactory>(),
                HttpClientName,
                sp.GetRequiredService<IOptions<PwnedPasswordsOptions>>().Value,
                sp.GetRequiredService<PwnedPasswordsCacheHolder>().Cache));

            return services
                .AddHttpClient<PwnedPasswordsClient, PwnedPasswordsClient>(HttpClientName, (HttpClient http, IServiceProvider sp) => new PwnedPasswordsClient(
                    http,
                    sp.GetRequiredService<IOptions<PwnedPasswordsOptions>>().Value,
                    sp.GetRequiredService<PwnedPasswordsCacheHolder>().Cache))
                .RemoveAllLoggers();
        }
    }
}
