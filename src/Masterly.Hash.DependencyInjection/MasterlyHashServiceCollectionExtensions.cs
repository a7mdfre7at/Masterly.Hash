using System;
using Masterly.Hash;
using Masterly.Hash.DependencyInjection;
using Masterly.Hash.DependencyInjection.Internal;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace Microsoft.Extensions.DependencyInjection
{
    /// <summary>Registers Masterly.Hash in an <see cref="IServiceCollection"/>.</summary>
    public static class MasterlyHashServiceCollectionExtensions
    {
        private static readonly Func<IServiceProvider, object> CreateHasher =
            provider => new PasswordHasher(provider.GetRequiredService<IOptions<PasswordHasherOptions>>().Value);

        private static readonly Func<IServiceProvider, object> ForwardHasher =
            provider => provider.GetRequiredService<PasswordHasher>();

        /// <summary>
        /// Registers <see cref="PasswordHasher"/> and <see cref="IPasswordHasher"/> as one singleton, built once from
        /// <see cref="IOptions{TOptions}"/> of <see cref="PasswordHasherOptions"/>. Options are validated on first
        /// resolution and, on hosts that run <see cref="IStartupValidator"/> (Microsoft.Extensions.Hosting 8.0+),
        /// at startup. Calling it again adds configure steps but does not register a second hasher.
        /// </summary>
        /// <remarks>
        /// To decorate the hasher, register your own <see cref="IPasswordHasher"/> after this call (the last registration
        /// wins) and resolve <see cref="PasswordHasher"/> inside it.
        /// </remarks>
        /// <param name="services">The service collection.</param>
        /// <param name="configure">Optional configure step, e.g. <c>o =&gt; o.DefaultProfile = HashProfile.Fips2026a</c>.</param>
        /// <exception cref="InvalidOperationException">
        /// <see cref="IPasswordHasher"/> or <see cref="PasswordHasher"/> was already registered by something other than
        /// <c>AddMasterlyHash</c>; that registration would silently ignore every option and builder call.
        /// </exception>
        public static MasterlyHashBuilder AddMasterlyHash(this IServiceCollection services, Action<PasswordHasherOptions>? configure = null)
        {
            if (services == null) throw new ArgumentNullException(nameof(services));

            AddCore(services);
            var builder = new MasterlyHashBuilder(services);
            if (configure != null)
                builder.Configure(configure);
            return builder;
        }

        /// <summary>
        /// Like <see cref="AddMasterlyHash(IServiceCollection, Action{PasswordHasherOptions})"/>, but also binds
        /// <paramref name="configuration"/> (typically <c>Configuration.GetSection("MasterlyHash")</c>) to a
        /// <see cref="MasterlyHashConfiguration"/> and maps it onto the options. Unknown profile ids, out-of-range
        /// values and malformed pepper keys are startup errors (<see cref="OptionsValidationException"/>), and so are
        /// unknown or misspelled keys under the section (<see cref="InvalidOperationException"/> from the binder).
        /// </summary>
        /// <remarks>
        /// The configuration is applied before every code configure step for <see cref="PasswordHasherOptions"/>,
        /// whenever that step was registered (earlier or later builder calls, <c>services.Configure</c>, satellite
        /// packages), so code always wins over configuration.
        /// </remarks>
        /// <param name="services">The service collection.</param>
        /// <param name="configuration">The configuration section to bind.</param>
        /// <param name="configure">Optional configure step that runs after the configuration is applied.</param>
        /// <exception cref="InvalidOperationException">
        /// <see cref="IPasswordHasher"/> or <see cref="PasswordHasher"/> was already registered by something other than
        /// <c>AddMasterlyHash</c>.
        /// </exception>
        public static MasterlyHashBuilder AddMasterlyHash(this IServiceCollection services, IConfiguration configuration, Action<PasswordHasherOptions>? configure = null)
        {
            if (services == null) throw new ArgumentNullException(nameof(services));
            if (configuration == null) throw new ArgumentNullException(nameof(configuration));

            AddCore(services);

            // Unknown keys are errors, so a typo such as "Peper" cannot silently turn off a security control.
            // The binder's message names properties only, never values.
            services.AddOptions<MasterlyHashConfiguration>()
                .Bind(configuration, binder => binder.ErrorOnUnknownConfiguration = true)
                .ValidateOnStart();
            services.TryAddEnumerable(ServiceDescriptor.Singleton<IValidateOptions<MasterlyHashConfiguration>, MasterlyHashConfigurationValidator>());
            AddConfigurationSetupFirst(services);

            var builder = new MasterlyHashBuilder(services);
            if (configure != null)
                builder.Configure(configure);
            return builder;
        }

        private static void AddCore(IServiceCollection services)
        {
            // A registration made before the first AddMasterlyHash call would shadow ours and ignore every option.
            // One made after it is a deliberate override or decorator and is left alone.
            bool ownHasher = false, ownInterface = false;
            foreach (ServiceDescriptor descriptor in services)
            {
                if (descriptor.ServiceType == typeof(PasswordHasher))
                {
                    if (ReferenceEquals(descriptor.ImplementationFactory, CreateHasher))
                        ownHasher = true;
                    else if (!ownHasher)
                        throw ForeignRegistration(nameof(PasswordHasher));
                }
                else if (descriptor.ServiceType == typeof(IPasswordHasher))
                {
                    if (ReferenceEquals(descriptor.ImplementationFactory, ForwardHasher))
                        ownInterface = true;
                    else if (!ownInterface)
                        throw ForeignRegistration(nameof(IPasswordHasher));
                }
            }

            services.AddOptions<PasswordHasherOptions>().ValidateOnStart();
            services.TryAddEnumerable(ServiceDescriptor.Singleton<IValidateOptions<PasswordHasherOptions>, PasswordHasherOptionsValidator>());
            services.TryAdd(new ServiceDescriptor(typeof(PasswordHasher), CreateHasher, ServiceLifetime.Singleton));
            services.TryAdd(new ServiceDescriptor(typeof(IPasswordHasher), ForwardHasher, ServiceLifetime.Singleton));
        }

        private static InvalidOperationException ForeignRegistration(string service) =>
            new InvalidOperationException(
                service + " is already registered, so AddMasterlyHash would configure a hasher that is never injected. " +
                "Remove the existing registration, or register an IPasswordHasher decorator after calling AddMasterlyHash.");

        /// <summary>
        /// Registers the configuration mapping ahead of every existing configure step (options run
        /// <see cref="IConfigureOptions{TOptions}"/> in descriptor order), so configuration never overwrites code.
        /// </summary>
        private static void AddConfigurationSetupFirst(IServiceCollection services)
        {
            int firstConfigure = -1;
            for (int i = 0; i < services.Count; i++)
            {
                ServiceDescriptor descriptor = services[i];
                if (descriptor.ServiceType != typeof(IConfigureOptions<PasswordHasherOptions>))
                    continue;
                if (descriptor.ImplementationType == typeof(ConfigurationOptionsSetup))
                    return;
                if (firstConfigure < 0)
                    firstConfigure = i;
            }

            ServiceDescriptor setup = ServiceDescriptor.Transient<IConfigureOptions<PasswordHasherOptions>, ConfigurationOptionsSetup>();
            if (firstConfigure < 0)
                services.Add(setup);
            else
                services.Insert(firstConfigure, setup);
        }
    }

    /// <summary>Eager validation for Masterly.Hash registrations.</summary>
    public static class MasterlyHashServiceProviderExtensions
    {
        /// <summary>
        /// Builds the registered <see cref="PasswordHasher"/> (and <see cref="IPasswordHasher"/>) now, so configuration
        /// errors surface at startup rather than on the first login. Use it on hosts without Microsoft.Extensions.Hosting
        /// 8.0+ (console apps, older hosts, tests), e.g. right after <c>BuildServiceProvider()</c>.
        /// </summary>
        /// <returns>The singleton hasher.</returns>
        /// <exception cref="OptionsValidationException">The options or the bound configuration are invalid.</exception>
        /// <exception cref="InvalidOperationException"><c>AddMasterlyHash</c> was not called.</exception>
        public static PasswordHasher ValidateMasterlyHash(this IServiceProvider provider)
        {
            if (provider == null) throw new ArgumentNullException(nameof(provider));
            PasswordHasher hasher = provider.GetService<PasswordHasher>()
                ?? throw new InvalidOperationException("Masterly.Hash is not registered. Call services.AddMasterlyHash() first.");

            // Also build IPasswordHasher: the hasher itself, or a decorator registered after AddMasterlyHash.
            _ = provider.GetRequiredService<IPasswordHasher>();
            return hasher;
        }
    }
}
