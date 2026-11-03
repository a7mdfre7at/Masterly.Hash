using System;
using System.Collections.Generic;

namespace Masterly.Hash.DependencyInjection
{
    /// <summary>
    /// Configuration model bound from an <c>IConfiguration</c> section by
    /// <c>AddMasterlyHash(IConfiguration)</c> and mapped onto <see cref="PasswordHasherOptions"/>.
    /// Every property is optional; an absent or empty value keeps the <see cref="PasswordHasherOptions"/> default.
    /// Unknown or misspelled keys under the section are startup errors.
    /// </summary>
    /// <example>
    /// <code language="json">
    /// "MasterlyHash": {
    ///   "DefaultProfile": "2026a",
    ///   "MaxConcurrency": 8,
    ///   "ConcurrencyTimeout": "00:00:10",
    ///   "MaxPasswordBytes": 1024,
    ///   "ComputeRehashOnVerify": true,
    ///   "Pepper": {
    ///     "CurrentKeyId": "k2",
    ///     "Keys": { "k1": "&lt;base64&gt;", "k2": "&lt;base64&gt;" }
    ///   }
    /// }
    /// </code>
    /// </example>
    public sealed class MasterlyHashConfiguration
    {
        /// <summary>
        /// Id of a built-in profile used for new hashes: <c>2026a</c> (Argon2id 64 MiB), <c>2026c</c> (Argon2id 19 MiB)
        /// or <c>2026f</c> (PBKDF2-SHA512). Empty or whitespace keeps the default; any other value is a startup error. Custom profiles are set in code
        /// with <see cref="MasterlyHashBuilder.UseProfile"/>.
        /// </summary>
        public string? DefaultProfile { get; set; }

        /// <summary>Maps to <see cref="PasswordHasherOptions.MaxConcurrency"/>. 0 disables the limit.</summary>
        public int? MaxConcurrency { get; set; }

        /// <summary>
        /// Maps to <see cref="PasswordHasherOptions.ConcurrencyTimeout"/>, e.g. <c>"00:00:30"</c>. Must be positive and at most
        /// <c>24.20:31:23.647</c> (int.MaxValue ms), or <c>-00:00:00.001</c> for infinite.
        /// </summary>
        public TimeSpan? ConcurrencyTimeout { get; set; }

        /// <summary>Maps to <see cref="PasswordHasherOptions.MaxPasswordBytes"/> (64 to 1048576).</summary>
        public int? MaxPasswordBytes { get; set; }

        /// <summary>Maps to <see cref="PasswordHasherOptions.ComputeRehashOnVerify"/>.</summary>
        public bool? ComputeRehashOnVerify { get; set; }

        /// <summary>Optional HMAC-SHA256 pepper key ring. When set, a <see cref="Pepper.HmacPepper"/> is created from it.</summary>
        public MasterlyHashPepperConfiguration? Pepper { get; set; }
    }

    /// <summary>Pepper key ring in configuration. Keep it in a secret store (Key Vault, user secrets, environment), never in source control.</summary>
    public sealed class MasterlyHashPepperConfiguration
    {
        /// <summary>Key id used for new hashes. Must match <c>^[A-Za-z0-9-]{1,32}$</c> and be present in <see cref="Keys"/>.</summary>
        public string? CurrentKeyId { get; set; }

        /// <summary>
        /// Key id to standard base64 key (at least 32 bytes decoded). Keep retired keys here until every hash made
        /// with them has been rehashed. Note that configuration keys are case-insensitive, so ids that differ only
        /// by case cannot both be configured.
        /// </summary>
        public Dictionary<string, string> Keys { get; set; } = new Dictionary<string, string>(StringComparer.Ordinal);

        internal bool IsEmpty => string.IsNullOrEmpty(CurrentKeyId) && (Keys == null || Keys.Count == 0);
    }
}
