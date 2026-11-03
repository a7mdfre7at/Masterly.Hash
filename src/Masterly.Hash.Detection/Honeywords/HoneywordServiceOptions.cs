using System;
using Masterly.Hash.Pepper;

namespace Masterly.Hash.Detection
{
    /// <summary>Configuration for <see cref="HoneywordService"/>.</summary>
    public sealed class HoneywordServiceOptions
    {
        /// <summary>
        /// Decoy generator. Defaults to <see cref="TweakingHoneywordGenerator.Default"/> (chaffing by tweaking, as in the
        /// paper); <see cref="PasswordModelHoneywordGenerator.Default"/> is recommended because tweaked decoys are easy
        /// to distinguish (Wang, Cheng, Wang, Yan and Huang, NDSS 2018). Both built-in generators keep decoys more
        /// than one typo away from the real password, so a single mistyped character cannot trigger a breach alarm.
        /// </summary>
        public IHoneywordGenerator Generator { get; set; } = TweakingHoneywordGenerator.Default;

        /// <summary>
        /// Optional pepper. Its current key id is written into new honeyword hashes (<c>,k=</c>) so keys can rotate.
        /// <see cref="PasswordHasher"/> does not expose its own pepper, so pass the same instance here if you use one.
        /// </summary>
        public IPasswordPepper? Pepper { get; set; }

        /// <summary>
        /// Largest sweetword count accepted when creating and when parsing a stored hash (bounds the work an
        /// attacker-supplied string can cause). Default 100; at most <see cref="HoneywordService.MaxSweetwordLimit"/>.
        /// </summary>
        public int MaxSweetwordCount { get; set; } = 100;

        /// <summary>Longest accepted password, in UTF-8 bytes after normalization. Default 1024, as in the core hasher.</summary>
        public int MaxPasswordBytes { get; set; } = 1024;

        /// <summary>
        /// Maximum key derivations running at the same time, so a login flood cannot exhaust memory.
        /// Defaults to the processor count; 0 disables the limit.
        /// </summary>
        public int MaxConcurrency { get; set; } = Environment.ProcessorCount;

        /// <summary>How long a call waits for a free slot before throwing <see cref="PasswordHasherBusyException"/>. Default 30 seconds.</summary>
        public TimeSpan ConcurrencyTimeout { get; set; } = TimeSpan.FromSeconds(30);

        /// <summary>
        /// Allows profiles below the OWASP minimums when profiles are given explicitly rather than through a
        /// <see cref="PasswordHasher"/>. Only for tests.
        /// </summary>
        public bool AllowWeakProfiles { get; set; }
    }
}
