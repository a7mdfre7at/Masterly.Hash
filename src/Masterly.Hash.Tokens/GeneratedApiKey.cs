using System;
using System.Diagnostics;

namespace Masterly.Hash.Tokens
{
    /// <summary>A newly generated API key and the lookup hash to store for it.</summary>
    [DebuggerDisplay("{ToString(),nq}")]
    public sealed class GeneratedApiKey
    {
        /// <summary>Wraps a key and its lookup hash.</summary>
        public GeneratedApiKey(string plainText, string prefix, string lookupHash)
        {
            PlainText = plainText ?? throw new ArgumentNullException(nameof(plainText));
            Prefix = prefix ?? throw new ArgumentNullException(nameof(prefix));
            LookupHash = lookupHash ?? throw new ArgumentNullException(nameof(lookupHash));
        }

        /// <summary>
        /// The key itself. Show it to its owner exactly once and do not store or log it;
        /// it cannot be recovered from <see cref="LookupHash"/>.
        /// </summary>
        public string PlainText { get; }

        /// <summary>The key's prefix, e.g. <c>mh_live</c>.</summary>
        public string Prefix { get; }

        /// <summary>
        /// Deterministic keyed hash to store, ideally in a unique index: <c>&lt;keyId&gt;:&lt;base64 HMAC-SHA256&gt;</c>.
        /// </summary>
        public string LookupHash { get; }

        /// <summary>
        /// A non-secret label for UIs, e.g. <c>mh_live_...a1B2</c>: the prefix and the last four (checksum) characters.
        /// </summary>
        public string Hint => Prefix + "_..." + PlainText.Substring(Math.Max(0, PlainText.Length - 4));

        /// <summary>Returns <see cref="Hint"/>; never the key.</summary>
        public override string ToString() => Hint;
    }
}
