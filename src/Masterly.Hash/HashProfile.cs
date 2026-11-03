using System.Collections.Generic;
using System;

namespace Masterly.Hash
{
    /// <summary>The key-derivation function a <see cref="HashProfile"/> uses.</summary>
    public enum HashAlgorithmKind
    {
        /// <summary>Argon2id (RFC 9106). The default and recommended choice.</summary>
        Argon2id,

        /// <summary>PBKDF2-HMAC-SHA512 (RFC 8018). For environments that require NIST-approved primitives.</summary>
        Pbkdf2Sha512,
    }

    /// <summary>
    /// A named, immutable set of hashing parameters. The stored hash records only the profile <see cref="Id"/>;
    /// the parameters come from code, never from the database row.
    /// </summary>
    public sealed class HashProfile : IEquatable<HashProfile>
    {

        /// <summary>Upper bound on Argon2 memory (1 GiB) so no profile can exhaust a host.</summary>
        public const int MaxMemoryKiB = 1024 * 1024;

        /// <summary>
        /// Default profile for web backends. Argon2id, m=64 MiB, t=3, p=1, 16-byte salt, 32-byte tag
        /// (RFC 9106 second recommended option).
        /// </summary>
        public static readonly HashProfile Server2026a = new HashProfile("2026a", HashAlgorithmKind.Argon2id, 65536, 3, 1, 16, 32);

        /// <summary>
        /// Profile for memory-constrained hosts (serverless, small containers). Argon2id, m=19 MiB, t=2, p=1
        /// (OWASP Password Storage Cheat Sheet minimum).
        /// </summary>
        public static readonly HashProfile Constrained2026a = new HashProfile("2026c", HashAlgorithmKind.Argon2id, 19456, 2, 1, 16, 32);

        /// <summary>
        /// Profile for environments that only allow NIST-approved primitives. PBKDF2-HMAC-SHA512 with
        /// 210,000 iterations (OWASP recommendation), 16-byte salt, 64-byte tag.
        /// </summary>
        public static readonly HashProfile Fips2026a = new HashProfile("2026f", HashAlgorithmKind.Pbkdf2Sha512, 0, 210_000, 1, 16, 64);

        /// <summary>Every built-in profile, oldest first. Each hasher always registers all of them.</summary>
        public static IReadOnlyList<HashProfile> BuiltIn { get; } = new[] { Server2026a, Constrained2026a, Fips2026a };

        /// <summary>Looks up a built-in profile by id.</summary>
        public static bool TryGetBuiltIn(string id, out HashProfile profile)
        {
            foreach (HashProfile p in BuiltIn)
            {
                if (p.Id == id)
                {
                    profile = p;
                    return true;
                }
            }
            profile = null!;
            return false;
        }

        private HashProfile(string id, HashAlgorithmKind algorithm, int memoryKiB, int iterations, int parallelism, int saltLength, int tagLength)
        {
            Id = id;
            Algorithm = algorithm;
            MemoryKiB = memoryKiB;
            Iterations = iterations;
            Parallelism = parallelism;
            SaltLength = saltLength;
            TagLength = tagLength;
        }

        /// <summary>Identifier written into the hash string, e.g. <c>2026a</c>.</summary>
        public string Id { get; }

        /// <summary>Key-derivation function.</summary>
        public HashAlgorithmKind Algorithm { get; }

        /// <summary>Argon2 memory cost in KiB. Zero for PBKDF2.</summary>
        public int MemoryKiB { get; }

        /// <summary>Argon2 passes, or PBKDF2 iterations.</summary>
        public int Iterations { get; }

        /// <summary>Argon2 lanes. Always 1 for PBKDF2.</summary>
        public int Parallelism { get; }

        /// <summary>Salt length in bytes.</summary>
        public int SaltLength { get; }

        /// <summary>Output tag length in bytes.</summary>
        public int TagLength { get; }

        /// <summary>
        /// True if the parameters meet the OWASP minimums. Profiles below them can only be registered with
        /// <see cref="PasswordHasherOptions.AllowWeakProfiles"/>.
        /// </summary>
        public bool MeetsRecommendedMinimum =>
            Algorithm == HashAlgorithmKind.Argon2id
                ? MemoryKiB >= 19456 && Iterations >= 2
                : Iterations >= 210_000;

        /// <summary>Creates a custom Argon2id profile.</summary>
        public static HashProfile Argon2id(string id, int memoryKiB, int iterations, int parallelism = 1, int saltLength = 16, int tagLength = 32)
        {
            ValidateCommon(id, saltLength, tagLength);
            if (memoryKiB < 8 * parallelism || memoryKiB > MaxMemoryKiB)
                throw new ArgumentOutOfRangeException(nameof(memoryKiB), memoryKiB, $"Memory must be between {8 * parallelism} and {MaxMemoryKiB} KiB.");
            if (iterations < 1 || iterations > 64)
                throw new ArgumentOutOfRangeException(nameof(iterations), iterations, "Iterations must be between 1 and 64.");
            if (parallelism < 1 || parallelism > 16)
                throw new ArgumentOutOfRangeException(nameof(parallelism), parallelism, "Parallelism must be between 1 and 16.");
            return new HashProfile(id, HashAlgorithmKind.Argon2id, memoryKiB, iterations, parallelism, saltLength, tagLength);
        }

        /// <summary>Creates a custom PBKDF2-HMAC-SHA512 profile.</summary>
        public static HashProfile Pbkdf2Sha512(string id, int iterations, int saltLength = 16, int tagLength = 64)
        {
            ValidateCommon(id, saltLength, tagLength);
            if (iterations < 1 || iterations > 10_000_000)
                throw new ArgumentOutOfRangeException(nameof(iterations), iterations, "Iterations must be between 1 and 10,000,000.");
            return new HashProfile(id, HashAlgorithmKind.Pbkdf2Sha512, 0, iterations, 1, saltLength, tagLength);
        }

        internal static bool IsValidId(string id) => Internal.Identifiers.IsValidLowercaseId(id);

        private static void ValidateCommon(string id, int saltLength, int tagLength)
        {
            if (!IsValidId(id))
                throw new ArgumentException("Profile id must match ^[a-z0-9][a-z0-9-]{0,31}$.", nameof(id));
            if (saltLength < 16 || saltLength > 64)
                throw new ArgumentOutOfRangeException(nameof(saltLength), saltLength, "Salt length must be between 16 and 64 bytes.");
            if (tagLength < 16 || tagLength > 64)
                throw new ArgumentOutOfRangeException(nameof(tagLength), tagLength, "Tag length must be between 16 and 64 bytes.");
        }

        /// <inheritdoc />
        public bool Equals(HashProfile? other) =>
            other != null && Id == other.Id && Algorithm == other.Algorithm && MemoryKiB == other.MemoryKiB &&
            Iterations == other.Iterations && Parallelism == other.Parallelism &&
            SaltLength == other.SaltLength && TagLength == other.TagLength;

        /// <inheritdoc />
        public override bool Equals(object? obj) => Equals(obj as HashProfile);

        /// <inheritdoc />
        public override int GetHashCode() => Id.GetHashCode();

        /// <inheritdoc />
        public override string ToString() =>
            Algorithm == HashAlgorithmKind.Argon2id
                ? $"{Id} (Argon2id m={MemoryKiB}KiB t={Iterations} p={Parallelism})"
                : $"{Id} (PBKDF2-SHA512 i={Iterations})";
    }
}
