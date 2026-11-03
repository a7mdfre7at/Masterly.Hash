using System;

namespace Masterly.Hash.Detection
{
    /// <summary>Configuration for <see cref="CredentialStuffingDetector"/>.</summary>
    public sealed class CredentialStuffingOptions
    {
        /// <summary>
        /// Length of a detection window (1 second to 1 day). Counts and the fingerprint key are discarded when the
        /// window ends. Default 10 minutes.
        /// </summary>
        public TimeSpan Window { get; set; } = TimeSpan.FromMinutes(10);

        /// <summary>
        /// Number of distinct accounts the same wrong password must fail against within one window to count as
        /// stuffing or spraying (2 to 10,000). Default 20.
        /// </summary>
        public int DistinctAccountThreshold { get; set; } = 20;

        /// <summary>
        /// Most password fingerprints tracked at once (1 to 10,000,000); the least recently seen is evicted beyond
        /// that. Worst-case managed memory (every fingerprint one account short of the threshold, 64-bit runtime) is
        /// roughly this times (350 + 40 x <see cref="DistinctAccountThreshold"/>) bytes, measured on .NET 10: about
        /// 115 MB with the defaults. Default 100,000.
        /// </summary>
        public int MaxTrackedFingerprints { get; set; } = 100_000;

        /// <summary>Passwords longer than this many UTF-16 code units are not fingerprinted (1 to 1,048,576). Default 4096.</summary>
        public int MaxPasswordLength { get; set; } = 4096;

        /// <summary>
        /// Account names longer than this many UTF-16 code units are not recorded, so an attacker-supplied
        /// multi-megabyte user name cannot make the detector normalize it (1 to 1,048,576). Default 1024.
        /// </summary>
        public int MaxAccountLength { get; set; } = 1024;

        /// <summary>Clock used for windows and event timestamps. Defaults to <see cref="DateTimeOffset.UtcNow"/>; inject one in tests.</summary>
        public Func<DateTimeOffset>? Clock { get; set; }
    }
}
