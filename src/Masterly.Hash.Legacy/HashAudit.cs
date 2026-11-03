using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Masterly.Hash.Legacy
{
    /// <summary>
    /// Surveys a password table: which formats and profiles are stored, how many hashes are weak, how many would be
    /// upgraded on the next login, and how many rows share a hash. Nothing is verified and no password is needed.
    /// </summary>
    /// <example>
    /// <code>
    /// var hasher = new PasswordHasher(new PasswordHasherOptions().AddAllLegacyFormats());
    /// HashAuditReport report = HashAudit.Audit(hasher, File.ReadLines("hashes.txt"));
    /// Console.WriteLine(report.ToMarkdown());
    /// </code>
    /// </example>
    public static class HashAudit
    {
        /// <summary>bcrypt hashes with a cost below this (2^10 rounds) are counted as weak.</summary>
        public const int WeakBCryptCostBelow = 10;

        /// <summary>PBKDF2 hashes (Django, ASP.NET Core Identity v3) with fewer iterations than this are counted as weak.</summary>
        public const int WeakPbkdf2IterationsBelow = 100_000;

        /// <summary>
        /// Audits stored hashes in a single streaming pass. Each value is classified with
        /// <see cref="IPasswordHasher.Inspect"/>, so register the same formats and profiles as the application.
        /// </summary>
        /// <remarks>
        /// Never throws for a bad entry: null, empty, garbage and values that make <c>Inspect</c> throw are all
        /// counted as unknown. Duplicates are detected from a 128-bit SHA-256 fingerprint of each value, so memory
        /// grows by about 40 bytes per distinct hash and the stored strings themselves are not retained.
        /// </remarks>
        /// <param name="hasher">The hasher whose formats and profiles define what is recognized.</param>
        /// <param name="storedHashes">Stored hash values, e.g. one database column. Enumerated once.</param>
        public static HashAuditReport Audit(IPasswordHasher hasher, IEnumerable<string?> storedHashes)
        {
            if (hasher == null) throw new ArgumentNullException(nameof(hasher));
            if (storedHashes == null) throw new ArgumentNullException(nameof(storedHashes));

            var builder = new Builder();
            using (SHA256 sha = SHA256.Create())
            {
                var seen = new HashSet<Fingerprint>();
                foreach (string? storedHash in storedHashes)
                {
                    builder.Total++;
                    if (string.IsNullOrEmpty(storedHash))
                    {
                        builder.Add(builder.ByFormat, "unknown");
                        builder.Unknown++;
                        continue;
                    }

                    if (!seen.Add(Fingerprint.Of(sha, storedHash!)))
                        builder.Duplicates++;

                    Classify(hasher, storedHash!, builder);
                }
            }

            return builder.Build();
        }

        /// <summary>
        /// True if a recognized hash of format <paramref name="formatId"/> is weak by this audit's rules: unsalted
        /// digests, Masterly.Hash 1.x, phpass, ASP.NET Identity v2, bcrypt below cost 10 and PBKDF2 below 100,000 iterations.
        /// </summary>
        public static bool IsWeak(string formatId, string storedHash)
        {
            if (formatId == null) throw new ArgumentNullException(nameof(formatId));
            if (storedHash == null) throw new ArgumentNullException(nameof(storedHash));

            switch (formatId)
            {
                case "md5":
                case "sha1":
                case "sha256":
                case "sha512":
                case "v1":
                case "phpass":
                case "aspnet-identity-v2":
                    return true;
                case "bcrypt":
                    return BCryptFormat.TryReadCost(storedHash, out int cost) && cost < WeakBCryptCostBelow;
                case "wordpress-bcrypt":
                    return WordPressBcryptFormat.TryReadCost(storedHash, out int wpCost) && wpCost < WeakBCryptCostBelow;
                case "django-pbkdf2":
                    return DjangoPbkdf2Format.TryReadIterations(storedHash, out int djangoIterations) && djangoIterations < WeakPbkdf2IterationsBelow;
                case "aspnet-identity-v3":
                    return AspNetIdentityV3Format.TryReadIterations(storedHash, out int identityIterations) && identityIterations < WeakPbkdf2IterationsBelow;
                default:
                    return false;
            }
        }

        private static void Classify(IPasswordHasher hasher, string storedHash, Builder builder)
        {
            HashInfo? info;
            try
            {
                info = hasher.Inspect(storedHash);
            }
#pragma warning disable CA1031 // An audit must survive any single bad row, whatever a custom hasher throws.
            catch (Exception)
#pragma warning restore CA1031
            {
                info = null;
            }

            string? format = info?.Format;
            if (info == null || string.IsNullOrEmpty(format))
            {
                builder.Add(builder.ByFormat, "unknown");
                builder.Unknown++;
                return;
            }

            builder.Add(builder.ByFormat, format!);
            if (info.ProfileId != null)
                builder.Add(builder.ByProfile, info.ProfileId);

            if (!info.IsRecognized)
            {
                builder.Unknown++;
                return;
            }

            builder.Recognized++;
            if (info.NeedsRehash)
                builder.NeedsRehash++;
            if (info.WrappedFormat != null)
                builder.Wrapped++;

            bool weak;
            try
            {
                weak = IsWeak(format!, storedHash);
            }
#pragma warning disable CA1031
            catch (Exception)
#pragma warning restore CA1031
            {
                weak = false;
            }

            if (weak)
            {
                builder.Weak++;
                builder.Add(builder.WeakByFormat, format!);
            }
        }

        private sealed class Builder
        {
            public long Total;
            public long Recognized;
            public long Unknown;
            public long NeedsRehash;
            public long Weak;
            public long Wrapped;
            public long Duplicates;
            public readonly Dictionary<string, long> ByFormat = new Dictionary<string, long>(StringComparer.Ordinal);
            public readonly Dictionary<string, long> ByProfile = new Dictionary<string, long>(StringComparer.Ordinal);
            public readonly Dictionary<string, long> WeakByFormat = new Dictionary<string, long>(StringComparer.Ordinal);

            public void Add(Dictionary<string, long> counts, string key)
            {
                counts.TryGetValue(key, out long count);
                counts[key] = count + 1;
            }

            public HashAuditReport Build() =>
                new HashAuditReport(Total, Recognized, Unknown, NeedsRehash, Weak, Wrapped, Duplicates, ByFormat, ByProfile, WeakByFormat);
        }

        /// <summary>First 128 bits of SHA-256(UTF-8(value)): collision-free in practice and holds no plaintext.</summary>
        private readonly struct Fingerprint : IEquatable<Fingerprint>
        {
            private readonly ulong _high;
            private readonly ulong _low;

            private Fingerprint(ulong high, ulong low)
            {
                _high = high;
                _low = low;
            }

            public static Fingerprint Of(SHA256 sha, string value)
            {
                byte[] digest = sha.ComputeHash(Encoding.UTF8.GetBytes(value));
                return new Fingerprint(BitConverter.ToUInt64(digest, 0), BitConverter.ToUInt64(digest, 8));
            }

            public bool Equals(Fingerprint other) => _high == other._high && _low == other._low;

            public override bool Equals(object? obj) => obj is Fingerprint other && Equals(other);

            public override int GetHashCode() => unchecked((int)_low ^ (int)(_low >> 32));
        }
    }
}
