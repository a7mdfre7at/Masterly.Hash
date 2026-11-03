using System;
using System.Collections.Generic;
using Masterly.Hash.DependencyInjection.Internal;
using Masterly.Hash.Legacy;
using Microsoft.Extensions.Options;

namespace Masterly.Hash.DependencyInjection
{
    /// <summary>
    /// Validates <see cref="PasswordHasherOptions"/> with the same rules the <see cref="PasswordHasher"/> constructor
    /// enforces, reporting every problem at once as an <see cref="OptionsValidationException"/>.
    /// Messages name the offending setting but never contain key material.
    /// </summary>
    /// <remarks>
    /// One rule is stricter than the constructor: a finite <see cref="PasswordHasherOptions.ConcurrencyTimeout"/> must be
    /// at most <see cref="int.MaxValue"/> milliseconds (about 24.8 days). Larger values make the concurrency gate throw
    /// <see cref="ArgumentOutOfRangeException"/> on .NET 8 as soon as a call has to wait.
    /// </remarks>
    public sealed class PasswordHasherOptionsValidator : IValidateOptions<PasswordHasherOptions>
    {
        /// <inheritdoc />
        public ValidateOptionsResult Validate(string? name, PasswordHasherOptions options)
        {
            if (options == null) throw new ArgumentNullException(nameof(options));

            var failures = new List<string>();
            var profiles = new Dictionary<string, HashProfile>(StringComparer.Ordinal);
            foreach (KeyValuePair<string, HashProfile> builtIn in Ids.BuiltInProfiles)
                profiles[builtIn.Key] = builtIn.Value;

            foreach (HashProfile? profile in options.AdditionalProfiles)
                CheckProfile(profile, "AdditionalProfiles", options.AllowWeakProfiles, profiles, failures);

            if (options.DefaultProfile == null)
                failures.Add("PasswordHasherOptions.DefaultProfile is required.");
            else
                CheckProfile(options.DefaultProfile, "DefaultProfile", options.AllowWeakProfiles, profiles, failures);

            var formatIds = new HashSet<string>(StringComparer.Ordinal);
            foreach (ILegacyHashFormat? format in options.LegacyFormats)
            {
                if (format == null)
                    failures.Add("PasswordHasherOptions.LegacyFormats contains null.");
                else if (!Ids.IsValidProfileOrFormatId(format.Id))
                    failures.Add("A legacy format id must match ^[a-z0-9][a-z0-9-]{0,31}$.");
                else if (!formatIds.Add(format.Id))
                    failures.Add($"Legacy format id '{format.Id}' is registered twice.");
            }

            if (options.Pepper != null && !Ids.IsValidKeyId(options.Pepper.CurrentKeyId))
                failures.Add("PasswordHasherOptions.Pepper.CurrentKeyId must match ^[A-Za-z0-9-]{1,32}$.");

            if (options.MaxPasswordBytes < 64 || options.MaxPasswordBytes > 1024 * 1024)
                failures.Add("PasswordHasherOptions.MaxPasswordBytes must be between 64 and 1048576.");
            if (options.MaxConcurrency < 0)
                failures.Add("PasswordHasherOptions.MaxConcurrency cannot be negative.");
            if (!Ids.IsValidConcurrencyTimeout(options.ConcurrencyTimeout))
                failures.Add("PasswordHasherOptions.ConcurrencyTimeout " + Ids.ConcurrencyTimeoutRule + ".");

            return failures.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(failures);
        }

        private static void CheckProfile(HashProfile? profile, string setting, bool allowWeak, Dictionary<string, HashProfile> registered, List<string> failures)
        {
            if (profile == null)
            {
                failures.Add($"PasswordHasherOptions.{setting} contains null.");
                return;
            }

            if (!allowWeak && !profile.MeetsRecommendedMinimum)
                failures.Add($"Profile {profile} is below the OWASP minimum. Set AllowWeakProfiles only in tests.");

            if (registered.TryGetValue(profile.Id, out HashProfile? existing) && !existing.Equals(profile))
                failures.Add($"Profile id '{profile.Id}' is already registered with different parameters. Profile ids are permanent; pick a new id.");
            else
                registered[profile.Id] = profile;
        }
    }
}
