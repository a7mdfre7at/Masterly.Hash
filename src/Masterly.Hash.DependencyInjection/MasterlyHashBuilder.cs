using System;
using Masterly.Hash.Legacy;
using Masterly.Hash.Pepper;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Masterly.Hash.DependencyInjection
{
    /// <summary>
    /// Fluent builder returned by <c>AddMasterlyHash</c>. Every call adds a configure step for
    /// <see cref="PasswordHasherOptions"/>; steps run in registration order. Configuration bound by
    /// <c>AddMasterlyHash(IConfiguration)</c> is always applied before every step, even steps registered earlier,
    /// so code wins over configuration. Satellite packages extend it with extension methods over <see cref="Services"/>.
    /// </summary>
    /// <remarks>
    /// The hasher is built once, on first resolution, from the final options. Later changes to configuration
    /// (reload-on-change) do not affect an already-built hasher.
    /// </remarks>
    /// <example>
    /// Export the hasher metrics with OpenTelemetry:
    /// <code>
    /// services.AddOpenTelemetry()
    ///     .WithMetrics(m => m.AddMeter(MasterlyHashBuilder.MeterName)); // "Masterly.Hash"
    /// </code>
    /// </example>
    public sealed class MasterlyHashBuilder
    {
        /// <summary>
        /// Name of the <c>System.Diagnostics.Metrics</c> meter the hasher publishes to (<c>"Masterly.Hash"</c>).
        /// Pass it to OpenTelemetry: <c>.WithMetrics(m =&gt; m.AddMeter(MasterlyHashBuilder.MeterName))</c>.
        /// </summary>
        public const string MeterName = PasswordHasher.MeterName;

        internal MasterlyHashBuilder(IServiceCollection services)
        {
            Services = services;
        }

        /// <summary>The service collection the hasher is registered in.</summary>
        public IServiceCollection Services { get; }

        /// <summary>Adds a configure step for <see cref="PasswordHasherOptions"/>.</summary>
        public MasterlyHashBuilder Configure(Action<PasswordHasherOptions> configure)
        {
            if (configure == null) throw new ArgumentNullException(nameof(configure));
            Services.Configure(configure);
            return this;
        }

        /// <summary>Adds a configure step for <see cref="PasswordHasherOptions"/> that needs a service.</summary>
        public MasterlyHashBuilder Configure<TDep>(Action<PasswordHasherOptions, TDep> configure)
            where TDep : class
        {
            if (configure == null) throw new ArgumentNullException(nameof(configure));
            Services.AddOptions<PasswordHasherOptions>().Configure(configure);
            return this;
        }

        /// <summary>Uses <paramref name="pepper"/> for new hashes and to verify peppered ones. Replaces any earlier pepper.</summary>
        public MasterlyHashBuilder WithPepper(IPasswordPepper pepper)
        {
            if (pepper == null) throw new ArgumentNullException(nameof(pepper));
            return Configure(options => options.Pepper = pepper);
        }

        /// <summary>
        /// Uses a pepper created from the container (e.g. one backed by a secret store client). The factory runs
        /// while the options are built, which may happen more than once (startup validation and first resolution),
        /// so it should be cheap and idempotent. Replaces any earlier pepper.
        /// </summary>
        public MasterlyHashBuilder WithPepper(Func<IServiceProvider, IPasswordPepper> factory)
        {
            if (factory == null) throw new ArgumentNullException(nameof(factory));
            return Configure<IServiceProvider>((options, provider) =>
                options.Pepper = factory(provider)
                    ?? throw new InvalidOperationException("The pepper factory returned null."));
        }

        /// <summary>Accepts hashes in a legacy format. Adding the same instance twice has no effect.</summary>
        public MasterlyHashBuilder AddLegacyFormat(ILegacyHashFormat format)
        {
            if (format == null) throw new ArgumentNullException(nameof(format));
            return Configure(options => AddFormat(options, format));
        }

        /// <summary>Accepts hashes in a legacy format created from the container.</summary>
        public MasterlyHashBuilder AddLegacyFormat(Func<IServiceProvider, ILegacyHashFormat> factory)
        {
            if (factory == null) throw new ArgumentNullException(nameof(factory));
            return Configure<IServiceProvider>((options, provider) =>
                AddFormat(options, factory(provider) ?? throw new InvalidOperationException("The legacy format factory returned null.")));
        }

        /// <summary>Uses <paramref name="profile"/> for new hashes (overrides <c>DefaultProfile</c> from configuration).</summary>
        public MasterlyHashBuilder UseProfile(HashProfile profile)
        {
            if (profile == null) throw new ArgumentNullException(nameof(profile));
            return Configure(options => options.DefaultProfile = profile);
        }

        /// <summary>
        /// Keeps accepting hashes made with a custom <paramref name="profile"/> that is no longer the default.
        /// Built-in profiles are always accepted and need not be added.
        /// </summary>
        public MasterlyHashBuilder AddProfile(HashProfile profile)
        {
            if (profile == null) throw new ArgumentNullException(nameof(profile));
            return Configure(options =>
            {
                if (!options.AdditionalProfiles.Contains(profile))
                    options.AdditionalProfiles.Add(profile);
            });
        }

        private static void AddFormat(PasswordHasherOptions options, ILegacyHashFormat format)
        {
            foreach (ILegacyHashFormat existing in options.LegacyFormats)
            {
                if (ReferenceEquals(existing, format))
                    return;
            }
            options.LegacyFormats.Add(format);
        }
    }
}
