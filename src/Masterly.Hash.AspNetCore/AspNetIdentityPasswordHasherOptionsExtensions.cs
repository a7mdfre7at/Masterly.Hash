using System;
using Masterly.Hash.Legacy;

namespace Masterly.Hash.AspNetCore
{
    /// <summary>Configures <see cref="PasswordHasherOptions"/> for use behind ASP.NET Core Identity.</summary>
    public static class AspNetIdentityPasswordHasherOptionsExtensions
    {
        /// <summary>
        /// Accepts the hashes ASP.NET Core Identity's own <c>PasswordHasher&lt;TUser&gt;</c> writes in both compatibility
        /// modes (<see cref="AspNetIdentityV3Format.Default"/> and <see cref="AspNetIdentityV2Format.Instance"/>), so users
        /// keep logging in after the switch and are upgraded on their next successful login.
        /// </summary>
        /// <remarks>
        /// A format whose id is already registered is left in place, so a custom
        /// <see cref="AspNetIdentityV3Format"/> with a different iteration cap can be registered before this call.
        /// </remarks>
        /// <returns>The same options, for chaining.</returns>
        public static PasswordHasherOptions AddAspNetIdentityFormats(this PasswordHasherOptions options)
        {
            if (options == null) throw new ArgumentNullException(nameof(options));

            AddIfMissing(options, AspNetIdentityV3Format.Default);
            AddIfMissing(options, AspNetIdentityV2Format.Instance);
            return options;
        }

        private static void AddIfMissing(PasswordHasherOptions options, ILegacyHashFormat format)
        {
            foreach (ILegacyHashFormat? existing in options.LegacyFormats)
            {
                if (existing != null && string.Equals(existing.Id, format.Id, StringComparison.Ordinal))
                    return;
            }
            options.AddLegacyFormats(format);
        }
    }
}
