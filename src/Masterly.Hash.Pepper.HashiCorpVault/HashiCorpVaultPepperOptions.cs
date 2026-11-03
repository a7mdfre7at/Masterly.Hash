using System;
using System.Threading;
using System.Threading.Tasks;

namespace Masterly.Hash.Pepper.HashiCorpVault
{
    /// <summary>Configuration for <see cref="HashiCorpVaultPepper"/>. Validated and copied by its constructor.</summary>
    public sealed class HashiCorpVaultPepperOptions
    {
        /// <summary>Vault base address, e.g. <c>https://vault.example.com:8200</c>. Required. Must be https unless <see cref="AllowInsecureHttp"/> is set.</summary>
        public Uri? VaultAddress { get; set; }

        /// <summary>Mount path of the Transit secrets engine. Defaults to <c>transit</c>. May contain <c>/</c> (e.g. <c>team-a/transit</c>).</summary>
        public string MountPath { get; set; } = "transit";

        /// <summary>Name of the Transit key that computes the pepper HMAC. Required.</summary>
        public string? KeyName { get; set; }

        /// <summary>
        /// Static Vault token sent as <c>X-Vault-Token</c>. Set exactly one of <see cref="Token"/> and <see cref="TokenProvider"/>.
        /// The token only needs <c>update</c> on <c>{mount}/hmac/{key}/sha2-256</c>.
        /// </summary>
        public string? Token { get; set; }

        /// <summary>
        /// Callback that returns the current Vault token for each request (for tokens that are renewed or re-issued,
        /// e.g. from AppRole or Kubernetes auth). Set exactly one of <see cref="Token"/> and <see cref="TokenProvider"/>.
        /// </summary>
        public Func<CancellationToken, Task<string>>? TokenProvider { get; set; }

        /// <summary>Optional Vault Enterprise namespace, sent as <c>X-Vault-Namespace</c>.</summary>
        public string? Namespace { get; set; }

        /// <summary>Transit key version used for new hashes (key id <c>v{N}</c>). Required, at least 1.</summary>
        public int CurrentKeyVersion { get; set; }

        /// <summary>
        /// Oldest Transit key version still accepted for verification. Default 1. Hashes made with older versions
        /// fail with <see cref="VerificationFailureReason.UnknownPepperKey"/>. Must not be below the Transit key's
        /// <c>min_encryption_version</c>, or Vault will refuse the HMAC.
        /// </summary>
        public int MinKeyVersion { get; set; } = 1;

        /// <summary>
        /// Newest Transit key version accepted for verification. Defaults to <see cref="CurrentKeyVersion"/>.
        /// Set it higher during a rolling deployment so instances still on the old current version can verify
        /// hashes written by instances already on the new one.
        /// </summary>
        public int? MaxKeyVersion { get; set; }

        /// <summary>Time limit for one Vault request, including reading the response. Default 10 seconds.</summary>
        public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(10);

        /// <summary>Allows an <c>http://</c> <see cref="VaultAddress"/>. Only for local development: the token and the pepper input would travel in clear text.</summary>
        public bool AllowInsecureHttp { get; set; }
    }
}
