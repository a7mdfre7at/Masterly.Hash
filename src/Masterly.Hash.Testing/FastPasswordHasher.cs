using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace Masterly.Hash.Testing
{
    /// <summary>
    /// A real <see cref="PasswordHasher"/> configured with a tiny Argon2id profile (<c>test-fast</c>: m=64 KiB, t=1, p=1),
    /// so that hashing and verification take microseconds while every behaviour (upgrade-on-login, 1.x legacy hashes,
    /// peppers, <see cref="IPasswordHasher.VerifyOrDummy"/>, onion wrapping) is exactly the production code path.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>WARNING: NEVER USE THIS IN PRODUCTION.</b> The <c>test-fast</c> profile offers essentially no resistance to
    /// offline guessing. It exists only so unit tests run quickly.
    /// </para>
    /// <para>
    /// As a safety net, hashes produced by this hasher carry the profile id <c>test-fast</c>, which is not in the
    /// allowlist of a production <see cref="PasswordHasher"/>: if such a hash ever reaches a production database,
    /// verification fails with <see cref="VerificationFailureReason.UnknownProfile"/> instead of silently accepting a
    /// weak hash. The reverse is allowed: this hasher accepts the built-in profiles, so hashes made in production verify.
    /// </para>
    /// </remarks>
    public sealed class FastPasswordHasher : IPasswordHasher
    {
        /// <summary>Profile id written into every hash this hasher produces by default.</summary>
        public const string ProfileId = "test-fast";

        /// <summary>The <c>test-fast</c> profile: Argon2id, m=64 KiB, t=1, p=1, 16-byte salt, 32-byte tag. Insecure by design.</summary>
        public static readonly HashProfile Profile = HashProfile.Argon2id(ProfileId, memoryKiB: 64, iterations: 1);

        private static readonly Lazy<FastPasswordHasher> LazyShared =
            new Lazy<FastPasswordHasher>(() => new FastPasswordHasher(), LazyThreadSafetyMode.ExecutionAndPublication);

        private readonly PasswordHasher _inner;

        /// <summary>Creates a fast hasher with the default test options (see <see cref="CreateOptions"/>).</summary>
        public FastPasswordHasher()
            : this(null)
        {
        }

        /// <summary>
        /// Creates a fast hasher. <paramref name="configure"/> runs after the test defaults are applied, so it can add a
        /// pepper, legacy formats, extra profiles, or even change <see cref="PasswordHasherOptions.DefaultProfile"/>.
        /// </summary>
        /// <param name="configure">Optional callback that adjusts the options.</param>
        /// <exception cref="ArgumentException">The configured options are invalid (for example <see cref="PasswordHasherOptions.AllowWeakProfiles"/> was turned off).</exception>
        public FastPasswordHasher(Action<PasswordHasherOptions>? configure)
        {
            _inner = new PasswordHasher(CreateOptions(configure));
        }

        /// <summary>A shared instance with the default test options. Thread-safe.</summary>
        public static FastPasswordHasher Shared => LazyShared.Value;

        /// <summary>The underlying, fully real <see cref="PasswordHasher"/>.</summary>
        public PasswordHasher Inner => _inner;

        /// <summary>Profile used for new hashes (<see cref="Profile"/> unless reconfigured).</summary>
        public HashProfile DefaultProfile => _inner.DefaultProfile;

        /// <summary>All profiles this hasher accepts: <c>test-fast</c>, the built-in profiles and any added ones.</summary>
        public IReadOnlyCollection<HashProfile> Profiles => _inner.Profiles;

        /// <summary>
        /// Builds the options used by this hasher: <see cref="Profile"/> as default and registered profile,
        /// <see cref="PasswordHasherOptions.AllowWeakProfiles"/> on, no concurrency limit, then <paramref name="configure"/>.
        /// </summary>
        /// <param name="configure">Optional callback that adjusts the options.</param>
        /// <returns>A new options instance.</returns>
        public static PasswordHasherOptions CreateOptions(Action<PasswordHasherOptions>? configure = null)
        {
            var options = new PasswordHasherOptions
            {
                DefaultProfile = Profile,
                AllowWeakProfiles = true,
                MaxConcurrency = 0,
            };
            // Keep test-fast hashes verifiable even if the callback switches the default profile.
            options.AdditionalProfiles.Add(Profile);
            configure?.Invoke(options);
            return options;
        }

        /// <inheritdoc />
        public string Hash(string password) => _inner.Hash(password);

        /// <inheritdoc />
        public string Hash(string password, HashProfile profile) => _inner.Hash(password, profile);

        /// <inheritdoc />
        public PasswordVerificationResult Verify(string password, string storedHash) => _inner.Verify(password, storedHash);

        /// <inheritdoc />
        public PasswordVerificationResult VerifyOrDummy(string password, string? storedHash) => _inner.VerifyOrDummy(password, storedHash);

        /// <inheritdoc />
        public ValueTask<string> HashAsync(string password, CancellationToken cancellationToken = default) =>
            _inner.HashAsync(password, cancellationToken);

        /// <inheritdoc />
        public ValueTask<PasswordVerificationResult> VerifyAsync(string password, string storedHash, CancellationToken cancellationToken = default) =>
            _inner.VerifyAsync(password, storedHash, cancellationToken);

        /// <inheritdoc />
        public ValueTask<PasswordVerificationResult> VerifyOrDummyAsync(string password, string? storedHash, CancellationToken cancellationToken = default) =>
            _inner.VerifyOrDummyAsync(password, storedHash, cancellationToken);

        /// <inheritdoc />
        public bool NeedsRehash(string storedHash) => _inner.NeedsRehash(storedHash);

        /// <inheritdoc />
        public HashInfo Inspect(string storedHash) => _inner.Inspect(storedHash);

        /// <inheritdoc />
        public bool TryWrap(string legacyHash, out string wrappedHash) => _inner.TryWrap(legacyHash, out wrappedHash);
    }
}
