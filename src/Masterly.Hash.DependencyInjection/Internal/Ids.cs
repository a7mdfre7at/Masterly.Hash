using System;
using System.Collections.Generic;
using System.Threading;
using Masterly.Hash.Primitives;

namespace Masterly.Hash.DependencyInjection.Internal
{
    /// <summary>Id and timeout rules for configuration validation; the id rules are the core's own (HashPrimitives).</summary>
    internal static class Ids
    {

        public static readonly IReadOnlyDictionary<string, HashProfile> BuiltInProfiles =
            new Dictionary<string, HashProfile>(StringComparer.Ordinal)
            {
                [HashProfile.Server2026a.Id] = HashProfile.Server2026a,
                [HashProfile.Constrained2026a.Id] = HashProfile.Constrained2026a,
                [HashProfile.Fips2026a.Id] = HashProfile.Fips2026a,
            };

        public static string BuiltInProfileList => string.Join(", ", BuiltInProfiles.Keys);

        public static bool IsValidProfileOrFormatId(string? id) => id != null && HashPrimitives.IsValidProfileId(id);

        public static bool IsValidKeyId(string? id) => id != null && HashPrimitives.IsValidKeyId(id);

        /// <summary>Largest finite gate timeout <see cref="SemaphoreSlim"/> accepts on every runtime (int.MaxValue ms, about 24.8 days).</summary>
        public static readonly TimeSpan MaxConcurrencyTimeout = TimeSpan.FromMilliseconds(int.MaxValue);

        /// <summary>
        /// A gate timeout is valid when it is infinite or in (0, <see cref="MaxConcurrencyTimeout"/>]. Larger values pass the
        /// core constructor but make <see cref="SemaphoreSlim.Wait(TimeSpan)"/> throw on .NET 8 under contention.
        /// </summary>
        public static bool IsValidConcurrencyTimeout(TimeSpan timeout) =>
            timeout == Timeout.InfiniteTimeSpan || (timeout > TimeSpan.Zero && timeout <= MaxConcurrencyTimeout);

        /// <summary>Human-readable rule for <see cref="IsValidConcurrencyTimeout"/>, used in validation messages.</summary>
        public static readonly string ConcurrencyTimeoutRule =
            "must be positive and at most " + MaxConcurrencyTimeout.ToString("c", System.Globalization.CultureInfo.InvariantCulture) + ", or infinite (-00:00:00.001)";
    }
}
