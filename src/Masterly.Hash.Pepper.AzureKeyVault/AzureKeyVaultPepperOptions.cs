using System;
using System.Collections.Generic;

namespace Masterly.Hash.Pepper.AzureKeyVault
{
    /// <summary>
    /// Configuration for <see cref="AzureKeyVaultPepper"/>. Set exactly one of <see cref="SecretName"/>
    /// (versions mode) and <see cref="Keys"/> (map mode). Validated and copied by <see cref="AzureKeyVaultPepper.CreateAsync"/>.
    /// </summary>
    /// <remarks>
    /// Every secret value must be the base64 encoding of a random key of at least 32 bytes,
    /// e.g. <c>openssl rand -base64 32</c>.
    /// </remarks>
    public sealed class AzureKeyVaultPepperOptions
    {
        /// <summary>
        /// Versions mode: the name of one secret whose enabled versions are the pepper keys. Each version id
        /// (32 hex characters) is the pepper key id stored in the hash. To rotate, add a new secret version.
        /// </summary>
        public string? SecretName { get; set; }

        /// <summary>
        /// Map mode: explicit pepper key id to secret mapping. The keys are loaded once, when the pepper is created. A reference
        /// without a version is pinned to the version that is current at load time.
        /// </summary>
        public IDictionary<string, AzureKeyVaultSecretReference> Keys { get; } =
            new Dictionary<string, AzureKeyVaultSecretReference>(StringComparer.Ordinal);

        /// <summary>
        /// Pepper key id used for new hashes. Required in map mode. Optional in versions mode, where it pins a specific
        /// version id. By default the newest version that has passed its <see cref="ActivationDelay"/> is used.
        /// </summary>
        public string? CurrentKeyId { get; set; }

        /// <summary>
        /// Versions mode: how often the version list is re-read, so new versions are picked up and disabled ones dropped.
        /// Refresh runs in the background, triggered by use; requests keep using the cached keys meanwhile.
        /// Default 5 minutes. <see cref="System.Threading.Timeout.InfiniteTimeSpan"/> disables refresh.
        /// </summary>
        public TimeSpan RefreshInterval { get; set; } = TimeSpan.FromMinutes(5);

        /// <summary>
        /// Versions mode: a new secret version becomes the current key only once it is this old (by its
        /// <c>CreatedOn</c>). Until then it is only accepted for verification. This gives every instance time to load it
        /// before any instance writes hashes with it. Keep it above <see cref="RefreshInterval"/> plus clock skew. Default 15 minutes.
        /// </summary>
        public TimeSpan ActivationDelay { get; set; } = TimeSpan.FromMinutes(15);

        /// <summary>Versions mode: at most this many of the newest enabled versions are loaded. Default 25.</summary>
        public int MaxVersions { get; set; } = 25;

        /// <summary>Time limit for one load or refresh, covering all Key Vault requests it makes. Default 30 seconds.</summary>
        public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(30);

        /// <summary>
        /// Called when a background refresh fails or finds problems. If Key Vault could not be reached, the cached keys
        /// stay in use. If it answered, the answer was applied, but no current key could be chosen or some versions were
        /// skipped. Use it for logging and alerting. The exception never contains key material. Exceptions thrown by the
        /// callback are ignored.
        /// </summary>
        public Action<Exception>? OnRefreshFailed { get; set; }
    }

    /// <summary>A Key Vault secret, optionally at a specific version, holding one base64-encoded pepper key.</summary>
    public sealed class AzureKeyVaultSecretReference
    {
        /// <summary>Creates a reference.</summary>
        /// <param name="name">Secret name.</param>
        /// <param name="version">Secret version. Null means the latest version at load time, which is then pinned.</param>
        /// <exception cref="ArgumentNullException"><paramref name="name"/> is null.</exception>
        public AzureKeyVaultSecretReference(string name, string? version = null)
        {
            Name = name ?? throw new ArgumentNullException(nameof(name));
            Version = version;
        }

        /// <summary>Secret name.</summary>
        public string Name { get; }

        /// <summary>Secret version, or null for the latest version at load time.</summary>
        public string? Version { get; }
    }
}
