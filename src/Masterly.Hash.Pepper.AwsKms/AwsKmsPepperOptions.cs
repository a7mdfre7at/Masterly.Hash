using System;
using System.Collections.Generic;

namespace Masterly.Hash.Pepper.AwsKms
{
    /// <summary>Configuration for <see cref="AwsKmsPepper"/>. Validated and copied by its constructor.</summary>
    public sealed class AwsKmsPepperOptions
    {
        /// <summary>Pepper key id used for new hashes. Must be a key in <see cref="Keys"/>. Required.</summary>
        public string? CurrentKeyId { get; set; }

        /// <summary>
        /// Maps pepper key ids (stored in the hash, <c>^[A-Za-z0-9-]{1,32}$</c>) to HMAC KMS keys: key ARN, key id,
        /// alias ARN or alias name (<c>alias/...</c>). The key must have spec <c>HMAC_256</c> and usage
        /// <c>GENERATE_VERIFY_MAC</c>.
        /// </summary>
        /// <remarks>
        /// Prefer key ARNs. An alias can be repointed to a different KMS key, and every hash stored under that
        /// pepper key id would then stop verifying. Never change the KMS key a pepper key id maps to;
        /// to rotate, add a new id.
        /// </remarks>
        public IDictionary<string, string> Keys { get; } = new Dictionary<string, string>(StringComparer.Ordinal);

        /// <summary>Optional KMS grant tokens sent with every <c>GenerateMac</c> request.</summary>
        public IList<string> GrantTokens { get; } = new List<string>();

        /// <summary>Time limit for one <c>GenerateMac</c> call, including SDK retries. Default 10 seconds.</summary>
        public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(10);
    }
}
