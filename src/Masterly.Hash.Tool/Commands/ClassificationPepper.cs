using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Masterly.Hash.Pepper;
using Masterly.Hash.Tokens;

namespace Masterly.Hash.Tool.Commands
{
    /// <summary>
    /// A pepper that knows only key ids, not keys. It lets <c>inspect</c>, <c>audit</c> and <c>wrap</c> classify
    /// peppered hashes (which needs no key) without the secret. It cannot hash or verify: <see cref="Apply"/> throws.
    /// </summary>
    internal sealed class ClassificationPepper : IPasswordPepper
    {
        private readonly HashSet<string> _keyIds;

        /// <summary>Creates the pepper. The first id is treated as the current key.</summary>
        public ClassificationPepper(IReadOnlyList<string> keyIds)
        {
            if (keyIds == null) throw new ArgumentNullException(nameof(keyIds));
            if (keyIds.Count == 0) throw new ArgumentException("At least one key id is required.", nameof(keyIds));
            CurrentKeyId = keyIds[0];
            _keyIds = new HashSet<string>(keyIds, StringComparer.Ordinal);
        }

        /// <inheritdoc />
        public string CurrentKeyId { get; }

        /// <inheritdoc />
        public bool IsKnownKey(string keyId) => keyId != null && _keyIds.Contains(keyId);

        /// <inheritdoc />
        public byte[] Apply(string keyId, byte[] input) =>
            throw new InvalidOperationException("--pepper-key-ids only classifies hashes; it holds no key and cannot hash or verify.");

        /// <inheritdoc />
        public ValueTask<byte[]> ApplyAsync(string keyId, byte[] input, CancellationToken cancellationToken = default) =>
            throw new InvalidOperationException("--pepper-key-ids only classifies hashes; it holds no key and cannot hash or verify.");

        /// <summary>
        /// Parses a <c>--pepper-key-ids</c> value (comma-separated, current key first). Returns null for null input.
        /// </summary>
        public static IReadOnlyList<string>? ParseKeyIds(string? text)
        {
            if (text == null)
                return null;
            var ids = new List<string>();
            foreach (string part in text.Split(','))
            {
                string id = part.Trim();
                if (!HmacKeyRing.IsValidKeyId(id))
                    throw new ToolException("--pepper-key-ids must be a comma-separated list of key ids matching ^[A-Za-z0-9-]{1,32}$ (current key first).");
                if (!ids.Contains(id))
                    ids.Add(id);
            }
            return ids;
        }
    }
}
