using System;
using Masterly.Hash.Legacy.Internal;
using Masterly.Hash.Primitives;

namespace Masterly.Hash.Legacy
{
    /// <summary>
    /// Argon2 PHC strings produced by other systems (libsodium, argon2-cffi, PHP <c>password_hash</c>,
    /// node-argon2, Spring Security, ...): <c>$argon2id$v=19$m=65536,t=3,p=4$&lt;salt&gt;$&lt;hash&gt;</c>, also
    /// <c>$argon2i$</c> and <c>$argon2d$</c>. Computed by the core package's own Argon2 (RFC 9106), on the calling thread.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Only version 19 (0x13, the current Argon2) is supported; strings without <c>v=</c> (version 16) and strings
    /// with a secret or associated-data parameter are not handled. Salt and hash are unpadded base64.
    /// </para>
    /// <para>
    /// The cost parameters come from the stored string, so they are capped: <see cref="MaxMemoryKiB"/>
    /// (default 256 MiB, configurable up to 1 GiB), <see cref="MaxIterations"/> (default 10) and
    /// <see cref="MaxParallelism"/> (default 16). Hashes over a cap are not handled.
    /// </para>
    /// <para>
    /// Each concurrent verify allocates <c>m</c> KiB, so size <see cref="MaxMemoryKiB"/> times the hasher's
    /// concurrency to the host's memory. If the allocation fails anyway, <see cref="Verify"/> returns false
    /// instead of throwing <see cref="OutOfMemoryException"/>.
    /// </para>
    /// <para>
    /// These hashes are already strong, so they are not onion-wrapped, but a successful verify still replaces them
    /// with a Masterly hash, which moves the cost parameters out of the database row.
    /// </para>
    /// </remarks>
    public sealed class ExternalArgon2Format : ILegacyHashFormat
    {
        /// <summary>
        /// Default <see cref="MaxMemoryKiB"/>: 256 MiB, four times the 64 MiB default of argon2-cffi, PHP and
        /// RFC 9106's second recommended option, and libsodium's MODERATE limit.
        /// </summary>
        public const int DefaultMaxMemoryKiB = 256 * 1024;

        /// <summary>Default <see cref="MaxIterations"/>: 10.</summary>
        public const int DefaultMaxIterations = 10;

        /// <summary>Default <see cref="MaxParallelism"/>: 16.</summary>
        public const int DefaultMaxParallelism = 16;

        private const int MinSaltLength = 8;
        private const int MaxSaltLength = 64;
        private const int MinHashLength = 4;
        private const int MaxHashLength = 128;

        /// <summary>External Argon2 with the default caps.</summary>
        public static readonly ExternalArgon2Format Default = new ExternalArgon2Format();

        /// <summary>Creates the format with the default caps.</summary>
        public ExternalArgon2Format()
            : this(DefaultMaxMemoryKiB, DefaultMaxIterations, DefaultMaxParallelism)
        {
        }

        /// <summary>Creates the format with custom cost caps.</summary>
        /// <param name="maxMemoryKiB">Highest accepted <c>m</c>, 8..1048576 KiB.</param>
        /// <param name="maxIterations">Highest accepted <c>t</c>, 1..64.</param>
        /// <param name="maxParallelism">Highest accepted <c>p</c>, 1..16.</param>
        public ExternalArgon2Format(int maxMemoryKiB, int maxIterations, int maxParallelism)
        {
            if (maxMemoryKiB < 8 || maxMemoryKiB > HashProfile.MaxMemoryKiB)
                throw new ArgumentOutOfRangeException(nameof(maxMemoryKiB), maxMemoryKiB, $"Max memory must be between 8 and {HashProfile.MaxMemoryKiB} KiB.");
            if (maxIterations < 1 || maxIterations > 64)
                throw new ArgumentOutOfRangeException(nameof(maxIterations), maxIterations, "Max iterations must be between 1 and 64.");
            if (maxParallelism < 1 || maxParallelism > 16)
                throw new ArgumentOutOfRangeException(nameof(maxParallelism), maxParallelism, "Max parallelism must be between 1 and 16.");
            MaxMemoryKiB = maxMemoryKiB;
            MaxIterations = maxIterations;
            MaxParallelism = maxParallelism;
        }

        /// <inheritdoc />
        public string Id => "argon2-phc";

        /// <summary>Highest accepted memory cost <c>m</c>, in KiB.</summary>
        public int MaxMemoryKiB { get; }

        /// <summary>Highest accepted time cost <c>t</c>.</summary>
        public int MaxIterations { get; }

        /// <summary>Highest accepted parallelism <c>p</c>.</summary>
        public int MaxParallelism { get; }

        /// <inheritdoc />
        public bool CanHandle(string storedHash) => TryParse(storedHash, out _);

        /// <inheritdoc />
        public bool Verify(string password, string storedHash)
        {
            if (password == null) throw new ArgumentNullException(nameof(password));
            if (!TryParse(storedHash, out Parsed parsed))
                return false;

            byte[] plain = LegacyEncoding.Utf8(password);
            byte[] actual;
            try
            {
                // Runs on the calling thread, so it cannot starve the thread pool behind the hasher's concurrency gate.
                actual = HashPrimitives.Argon2(
                    ToPrimitive(parsed.Variant), plain, parsed.Salt,
                    parsed.MemoryKiB, parsed.Iterations, parsed.Parallelism, parsed.Hash.Length);
            }
            catch (Exception ex) when (IsOutOfMemory(ex))
            {
                // The m KiB block allocation failed: report a non-match rather than break "Verify never throws".
                return false;
            }
            finally
            {
                HashPrimitives.Zero(plain);
            }

            bool match = HashPrimitives.FixedTimeEquals(parsed.Hash, actual);
            HashPrimitives.Zero(actual);
            return match;
        }

        /// <summary>True for an OutOfMemoryException, bare or as the only kind inside an AggregateException.</summary>
        internal static bool IsOutOfMemory(Exception ex)
        {
            if (ex is OutOfMemoryException)
                return true;
            if (!(ex is AggregateException aggregate))
                return false;
            var inner = aggregate.Flatten().InnerExceptions;
            if (inner.Count == 0)
                return false;
            foreach (Exception e in inner)
            {
                if (!(e is OutOfMemoryException))
                    return false;
            }
            return true;
        }

        /// <summary>Always false: Argon2 hashes are strong enough not to need wrapping.</summary>
        public bool TryExtractWrapInput(string storedHash, out byte[] digest, out byte[] parameter)
        {
            digest = Array.Empty<byte>();
            parameter = Array.Empty<byte>();
            return false;
        }

        /// <summary>Always throws <see cref="FormatException"/>: this format is never wrapped.</summary>
        public byte[] ComputeWrapInput(string password, byte[] parameter) =>
            throw new FormatException("argon2-phc hashes are not onion-wrapped.");

        private bool TryParse(string storedHash, out Parsed parsed)
        {
            parsed = default;
            if (storedHash == null || storedHash.Length > LegacyEncoding.MaxStoredLength || !storedHash.StartsWith("$argon2", StringComparison.Ordinal))
                return false;

            // "", variant, "v=19", "m=..,t=..,p=..", salt, hash
            string[] parts = storedHash.Split('$');
            if (parts.Length != 6 || parts[0].Length != 0)
                return false;

            Variant variant;
            switch (parts[1])
            {
                case "argon2id": variant = Variant.Argon2id; break;
                case "argon2i": variant = Variant.Argon2i; break;
                case "argon2d": variant = Variant.Argon2d; break;
                default: return false;
            }

            if (!string.Equals(parts[2], "v=19", StringComparison.Ordinal))
                return false;

            string[] costs = parts[3].Split(',');
            if (costs.Length != 3 ||
                !TryParseParameter(costs[0], "m=", out long m) ||
                !TryParseParameter(costs[1], "t=", out long t) ||
                !TryParseParameter(costs[2], "p=", out long p))
                return false;

            if (p < 1 || p > MaxParallelism || t < 1 || t > MaxIterations || m < 8 * p || m > MaxMemoryKiB)
                return false;

            if (!HashPrimitives.TryFromB64(parts[4], out byte[] salt) || salt.Length < MinSaltLength || salt.Length > MaxSaltLength)
                return false;
            if (!HashPrimitives.TryFromB64(parts[5], out byte[] hash) || hash.Length < MinHashLength || hash.Length > MaxHashLength)
                return false;

            parsed = new Parsed(variant, (int)m, (int)t, (int)p, salt, hash);
            return true;
        }

        private static bool TryParseParameter(string pair, string name, out long value)
        {
            value = 0;
            return pair.StartsWith(name, StringComparison.Ordinal) && LegacyEncoding.TryParseDecimal(pair.Substring(name.Length), out value);
        }

        private static Argon2Variant ToPrimitive(Variant variant)
        {
            switch (variant)
            {
                case Variant.Argon2i: return Argon2Variant.Argon2i;
                case Variant.Argon2d: return Argon2Variant.Argon2d;
                default: return Argon2Variant.Argon2id;
            }
        }

        private enum Variant
        {
            Argon2id,
            Argon2i,
            Argon2d,
        }

        private readonly struct Parsed
        {
            public Parsed(Variant variant, int memoryKiB, int iterations, int parallelism, byte[] salt, byte[] hash)
            {
                Variant = variant;
                MemoryKiB = memoryKiB;
                Iterations = iterations;
                Parallelism = parallelism;
                Salt = salt;
                Hash = hash;
            }

            public Variant Variant { get; }
            public int MemoryKiB { get; }
            public int Iterations { get; }
            public int Parallelism { get; }
            public byte[] Salt { get; }
            public byte[] Hash { get; }
        }
    }
}
