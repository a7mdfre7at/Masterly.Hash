using System;
using Masterly.Hash.AspNetCore;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection.Extensions;
using MasterlyHasherOptions = Masterly.Hash.PasswordHasherOptions;

namespace Microsoft.Extensions.DependencyInjection
{
    /// <summary>Replaces ASP.NET Core Identity's password hasher with Masterly.Hash.</summary>
    public static class MasterlyIdentityBuilderExtensions
    {
        /// <summary>
        /// The <see cref="MasterlyHasherOptions.ConcurrencyTimeout"/> applied by <see cref="AddMasterlyPasswordHasher"/>
        /// when the timeout was left at its default: 2 seconds.
        /// </summary>
        public static readonly TimeSpan IdentityConcurrencyTimeout = TimeSpan.FromSeconds(2);

        private static readonly TimeSpan CoreDefaultConcurrencyTimeout = new MasterlyHasherOptions().ConcurrencyTimeout;

        /// <summary>
        /// Registers Masterly.Hash (<c>AddMasterlyHash</c>) and replaces the Identity <see cref="IPasswordHasher{TUser}"/>
        /// with <see cref="MasterlyIdentityPasswordHasher{TUser}"/>.
        /// </summary>
        /// <remarks>
        /// <para>The registered configure step, in order:</para>
        /// <list type="number">
        /// <item><description>sets <see cref="MasterlyHasherOptions.ComputeRehashOnVerify"/> to <c>false</c>, because
        /// <see cref="UserManager{TUser}"/> re-hashes on its own;</description></item>
        /// <item><description>lowers <see cref="MasterlyHasherOptions.ConcurrencyTimeout"/> to <see cref="IdentityConcurrencyTimeout"/>
        /// if it is still the core default of 30 seconds: Identity's hasher interface is synchronous, so a waiting login
        /// blocks a thread-pool thread, and a short wait turns a login flood into fast 503s
        /// (<c>AddMasterlyHashExceptionHandler</c>) instead of thread-pool starvation;</description></item>
        /// <item><description>runs <paramref name="configure"/>, which may override anything above;</description></item>
        /// <item><description>adds the ASP.NET Core Identity v3 and v2 formats
        /// (<see cref="AspNetIdentityPasswordHasherOptionsExtensions.AddAspNetIdentityFormats"/>) unless formats with those
        /// ids were already registered, so existing users keep logging in and are upgraded on their next login.</description></item>
        /// </list>
        /// <para>
        /// It also adds <see cref="MasterlyPasswordLengthValidator{TUser}"/>, so <see cref="UserManager{TUser}"/> reports an
        /// over-long password as a failed <see cref="IdentityResult"/> rather than throwing from the hasher.
        /// </para>
        /// <para>
        /// The hasher is the singleton shared with every other <see cref="Masterly.Hash.IPasswordHasher"/> consumer in the application, so
        /// these settings apply to them too. Configuration bound with <c>AddMasterlyHash(IConfiguration)</c> is applied first.
        /// Register custom Identity format instances inside <paramref name="configure"/> rather than through the
        /// <c>MasterlyHashBuilder</c>, or startup validation will report a duplicate format id.
        /// </para>
        /// </remarks>
        /// <param name="builder">The Identity builder from <c>AddIdentity</c>, <c>AddIdentityCore</c> or <c>AddDefaultIdentity</c>.</param>
        /// <param name="configure">Optional configure step for the Masterly.Hash options.</param>
        /// <returns>The same builder, for chaining.</returns>
        public static IdentityBuilder AddMasterlyPasswordHasher(this IdentityBuilder builder, Action<MasterlyHasherOptions>? configure = null)
        {
            if (builder == null) throw new ArgumentNullException(nameof(builder));

            builder.Services.AddMasterlyHash(options =>
            {
                options.ComputeRehashOnVerify = false;
                if (options.ConcurrencyTimeout == CoreDefaultConcurrencyTimeout)
                    options.ConcurrencyTimeout = IdentityConcurrencyTimeout;
                configure?.Invoke(options);
                options.AddAspNetIdentityFormats();
            });

            Type service = typeof(IPasswordHasher<>).MakeGenericType(builder.UserType);
            Type implementation = typeof(MasterlyIdentityPasswordHasher<>).MakeGenericType(builder.UserType);
            builder.Services.RemoveAll(service);
            builder.Services.Add(ServiceDescriptor.Scoped(service, implementation));

            builder.Services.TryAddEnumerable(ServiceDescriptor.Scoped(
                typeof(IPasswordValidator<>).MakeGenericType(builder.UserType),
                typeof(MasterlyPasswordLengthValidator<>).MakeGenericType(builder.UserType)));
            return builder;
        }
    }
}
