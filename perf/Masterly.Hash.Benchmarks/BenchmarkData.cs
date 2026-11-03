using System;
using Masterly.Hash.Pepper;

namespace Masterly.Hash.Benchmarks
{
    /// <summary>Shared inputs for the benchmarks and the quick runner.</summary>
    internal static class BenchmarkData
    {
        /// <summary>A typical user password (16 ASCII characters).</summary>
        public const string Password = "correct-horse-42";

        /// <summary>The built-in profiles, cheapest memory first.</summary>
        public static readonly HashProfile[] BuiltInProfiles =
        {
            HashProfile.Fips2026a, HashProfile.Constrained2026a, HashProfile.Server2026a,
        };

        /// <summary>Resolves a built-in profile by its id.</summary>
        public static HashProfile Profile(string id)
        {
            foreach (HashProfile profile in BuiltInProfiles)
            {
                if (string.Equals(profile.Id, id, StringComparison.Ordinal))
                    return profile;
            }
            throw new ArgumentOutOfRangeException(nameof(id), id, "Not a built-in profile id.");
        }

        /// <summary>A hasher whose default profile is <paramref name="profile"/>, with no concurrency limit.</summary>
        public static PasswordHasher Hasher(HashProfile profile, IPasswordPepper? pepper = null, bool computeRehash = true)
        {
            if (profile == null) throw new ArgumentNullException(nameof(profile));
            return new PasswordHasher(new PasswordHasherOptions
            {
                DefaultProfile = profile,
                Pepper = pepper,
                MaxConcurrency = 0,
                ComputeRehashOnVerify = computeRehash,
            });
        }

        /// <summary>A pepper with a freshly generated random key.</summary>
        public static HmacPepper NewPepper() => new HmacPepper("bench", HmacPepper.GenerateKey());

        /// <summary>A hash in the Masterly.Hash 1.x format (salted SHA-512), produced by the 1.x API itself.</summary>
        public static string V1Hash(string password)
        {
#pragma warning disable CS0618 // The obsolete 1.x API is exactly what produces v1 hashes.
            return new Hash().ComputeHash(password, SupportedHash.SHA512);
#pragma warning restore CS0618
        }

        /// <summary>Throws if a benchmark's setup did not produce a matching hash, so a broken setup cannot be timed.</summary>
        public static void EnsureMatch(PasswordVerificationResult result, string what)
        {
            if (result == null) throw new ArgumentNullException(nameof(result));
            if (!result.IsMatch)
                throw new InvalidOperationException($"Benchmark setup failed: {what} did not verify ({result.FailureReason}).");
        }
    }
}
