using System;
using System.Collections.Generic;
using Masterly.Hash.Legacy;
using Masterly.Hash.Pepper;

namespace Masterly.Hash
{
    /// <summary>Configuration for <see cref="PasswordHasher"/>. The defaults are safe; most apps change nothing.</summary>
    public sealed class PasswordHasherOptions
    {
        /// <summary>Profile used for new hashes. Defaults to <see cref="HashProfile.Server2026a"/>.</summary>
        public HashProfile DefaultProfile { get; set; } = HashProfile.Server2026a;

        /// <summary>
        /// Extra profiles to accept when verifying. The built-in profiles are always accepted. A stored hash naming
        /// any other profile fails with <see cref="VerificationFailureReason.UnknownProfile"/>.
        /// </summary>
        public IList<HashProfile> AdditionalProfiles { get; } = new List<HashProfile>();

        /// <summary>Optional pepper. Null by default.</summary>
        public IPasswordPepper? Pepper { get; set; }

        /// <summary>
        /// Read-only legacy formats to accept. Contains <see cref="V1LegacyFormat.Instance"/> by default so that
        /// Masterly.Hash 1.x hashes keep working. Add formats from <c>Masterly.Hash.Legacy</c> to migrate other systems.
        /// </summary>
        public IList<ILegacyHashFormat> LegacyFormats { get; } = new List<ILegacyHashFormat> { V1LegacyFormat.Instance };

        /// <summary>Longest accepted password, in UTF-8 bytes after normalization. Guards against hash-DoS. Default 1024.</summary>
        public int MaxPasswordBytes { get; set; } = 1024;

        /// <summary>
        /// Maximum hashes computed at the same time, so a login flood cannot exhaust memory
        /// (each Argon2 call allocates the profile's memory cost). Defaults to the processor count; 0 disables the limit.
        /// </summary>
        public int MaxConcurrency { get; set; } = Environment.ProcessorCount;

        /// <summary>How long a call waits for a free slot before throwing <see cref="PasswordHasherBusyException"/>. Default 30 seconds.</summary>
        public TimeSpan ConcurrencyTimeout { get; set; } = TimeSpan.FromSeconds(30);

        /// <summary>If true (default), a successful verify of an outdated hash also returns the replacement hash.</summary>
        public bool ComputeRehashOnVerify { get; set; } = true;

        /// <summary>Allows profiles below the OWASP minimums. Only for tests.</summary>
        public bool AllowWeakProfiles { get; set; }
    }
}
