using System;
using System.Collections.Generic;
using System.Text;

namespace Masterly.Hash.Analyzers.Internal
{
    /// <summary>
    /// Decides whether an identifier names a secret. Identifiers are split into words at camelCase/PascalCase
    /// humps, underscores and digits (<c>userPassword</c> = user + password, <c>HTTPToken</c> = http + token,
    /// <c>pwd_2</c> = pwd). A name matches when one to three consecutive words spell a pattern
    /// (<c>apiKey</c> spells <c>apikey</c>, <c>PassWord</c> spells <c>password</c>), so the match is on word
    /// boundaries: <c>spinner</c> and <c>pinned</c> do not contain the word <c>pin</c>.
    /// <para>
    /// A match followed by a qualifier word, anywhere after it, describes metadata about the secret rather than
    /// the secret itself, and does not count: <c>passwordPolicy</c>, <c>maxPasswordLength</c>,
    /// <c>passwordSaltBytes</c>, <c>storedPasswordHashBase64</c>, <c>tokenType</c>, <c>hashAlgorithm</c>,
    /// <c>pepperKeyId</c>, <c>macAddressBytes</c>, <c>GetHashCode</c>.
    /// </para>
    /// <para>
    /// A match preceded by a prefix qualifier also does not count: for passwords, <c>hashedPassword</c>,
    /// <c>encryptedPassword</c> and <c>saltedPassword</c> name a stored hash or ciphertext, not the password.
    /// </para>
    /// </summary>
    internal sealed class NameMatcher
    {
        private const int MaxWordsPerPattern = 3;

        private readonly HashSet<string> _patterns;
        private readonly HashSet<string> _qualifiers;
        private readonly HashSet<string> _prefixQualifiers;

        public NameMatcher(IEnumerable<string> patterns, IEnumerable<string> qualifiers, IEnumerable<string>? prefixQualifiers = null)
        {
            _patterns = new HashSet<string>(patterns, StringComparer.Ordinal);
            _qualifiers = new HashSet<string>(qualifiers, StringComparer.Ordinal);
            _prefixQualifiers = new HashSet<string>(prefixQualifiers ?? Array.Empty<string>(), StringComparer.Ordinal);
        }

        /// <summary>password | passwd | pwd | passphrase | pin.</summary>
        public static NameMatcher Password { get; } = new NameMatcher(
            new[] { "password", "passwd", "pwd", "passphrase", "pin" },
            new[]
            {
                "policy", "policies", "length", "len", "rule", "rules", "hint", "hints", "strength", "option", "options",
                "settings", "config", "configuration", "requirement", "requirements", "validator", "validation", "regex",
                "pattern", "expiry", "expiration", "expires", "expired", "age", "count", "attempt", "attempts", "field",
                "label", "prompt", "placeholder", "token", "reset", "changed", "date", "time", "timestamp", "version",
                "format", "id", "min", "max", "salt", "iterations", "enabled", "required", "history", "error", "errors",
                "message", "type", "mode", "provider", "hasher", "hash", "hashed", "hashes", "manager", "service",
                "url", "uri", "path", "file", "name", "visible", "visibility", "char", "chars", "encrypted",
                "salted", "digest", "mac",
            },
            new[] { "hashed", "encrypted", "salted", "masked", "redacted" });

        /// <summary>hash | hashed | digest | mac | hmac | signature | token | apikey | secret.</summary>
        public static NameMatcher Secret { get; } = new NameMatcher(
            new[] { "hash", "hashed", "digest", "mac", "hmac", "signature", "token", "apikey", "secret" },
            new[]
            {
                "algorithm", "algorithms", "alg", "name", "names", "type", "types", "kind", "length", "len", "size",
                "count", "id", "code", "set", "table", "map", "provider", "options", "settings", "address",
                "expiry", "expiration", "expires", "lifetime", "header", "prefix", "format", "version", "mode", "field",
                "label", "url", "uri", "endpoint", "path", "file", "enabled", "required", "scheme", "policy", "handler",
                "service", "manager", "factory", "builder", "generator", "validator", "parameters", "params", "status",
                "state", "source", "location", "claim", "claims",
            });

        /// <summary>pepper | hmacKey | secretKey | signingKey.</summary>
        public static NameMatcher Key { get; } = new NameMatcher(
            new[] { "pepper", "hmackey", "secretkey", "signingkey" },
            new[]
            {
                "id", "ids", "name", "names", "length", "len", "size", "path", "file", "options", "provider", "version",
                "env", "variable", "config", "configuration", "setting", "settings", "location", "uri", "url", "count",
                "enabled", "required", "section", "store", "vault",
            });

        public bool IsMatch(string? name)
        {
            if (string.IsNullOrEmpty(name))
                return false;

            List<string> words = SplitWords(name!);
            if (words.Count == 0)
                return false;

            // qualifierFrom[k]: whether any word at index >= k is a qualifier.
            var qualifierFrom = new bool[words.Count + 1];
            for (int k = words.Count - 1; k >= 0; k--)
                qualifierFrom[k] = qualifierFrom[k + 1] || _qualifiers.Contains(words[k]);

            bool prefixQualified = false;
            var sb = new StringBuilder();
            for (int i = 0; i < words.Count; i++)
            {
                if (i > 0 && _prefixQualifiers.Contains(words[i - 1]))
                    prefixQualified = true;
                if (prefixQualified)
                    continue;

                sb.Clear();
                for (int j = i; j < words.Count && j < i + MaxWordsPerPattern; j++)
                {
                    sb.Append(words[j]);
                    if (_patterns.Contains(sb.ToString()) && !qualifierFrom[j + 1])
                        return true;
                }
            }

            return false;
        }

        /// <summary>Splits an identifier into lower-case words.</summary>
        internal static List<string> SplitWords(string name)
        {
            var words = new List<string>();
            int start = -1;
            for (int i = 0; i < name.Length; i++)
            {
                char c = name[i];
                if (!char.IsLetter(c))
                {
                    if (start >= 0)
                        words.Add(name.Substring(start, i - start).ToLowerInvariant());
                    start = -1;
                    continue;
                }

                if (start < 0)
                {
                    start = i;
                    continue;
                }

                char prev = name[i - 1];
                bool boundary =
                    (char.IsUpper(c) && char.IsLower(prev)) ||
                    (char.IsUpper(c) && char.IsUpper(prev) && i + 1 < name.Length && char.IsLower(name[i + 1]));
                if (boundary)
                {
                    words.Add(name.Substring(start, i - start).ToLowerInvariant());
                    start = i;
                }
            }

            if (start >= 0)
                words.Add(name.Substring(start).ToLowerInvariant());
            return words;
        }
    }
}
