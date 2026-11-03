using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Masterly.Hash.Detection.Internal;
using Masterly.Hash.Pepper;
using Masterly.Hash.Primitives;

namespace Masterly.Hash.Detection
{
    /// <summary>
    /// Honeywords (Juels and Rivest, <i>Honeywords: Making Password-Cracking Detectable</i>, ACM CCS 2013): each user
    /// has k "sweetwords", the real password and k-1 decoys, all hashed under one per-user salt. An attacker who
    /// steals and cracks the database sees k equally plausible passwords; logging in with a decoy reveals the breach.
    /// Which sweetword is real is known only to a separate <see cref="IHoneychecker"/>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Stored format: <c>$mhw$p=&lt;profileId&gt;[,k=&lt;pepperKeyId&gt;]$&lt;salt&gt;$&lt;tag1&gt;,...,&lt;tagk&gt;</c>.
    /// Each tag is <c>KDF(profile, NFKC-UTF8(sweetword), salt)</c>. As in the core format, cost parameters are never
    /// stored: the profile id is resolved against an allowlist and unknown ids are rejected.
    /// </para>
    /// <para>
    /// Because all sweetwords share the salt, a login costs exactly one key derivation, compared against every tag
    /// in constant time. Creating a record costs k derivations, so prefer a modest k (the paper suggests 20) and,
    /// with the expensive server profiles, create records off the request path or with <see cref="CreateAsync"/>.
    /// </para>
    /// <para>
    /// Do not regenerate the decoys for an unchanged password (e.g. to move to a newer profile): an attacker holding
    /// two copies of the database can intersect the two sweetword sets and find the real password. Upgrade the
    /// profile when the user next changes their password.
    /// </para>
    /// </remarks>
    public sealed class HoneywordService
    {
        /// <summary>Sweetword count recommended by Juels and Rivest.</summary>
        public const int DefaultSweetwordCount = 20;

        /// <summary>Smallest allowed sweetword count.</summary>
        public const int MinSweetwordCount = 2;

        /// <summary>Hard upper bound for <see cref="HoneywordServiceOptions.MaxSweetwordCount"/>.</summary>
        public const int MaxSweetwordLimit = 1000;

        private readonly HashProfile _defaultProfile;
        private readonly Dictionary<string, HashProfile> _profiles = new Dictionary<string, HashProfile>(StringComparer.Ordinal);
        private readonly IHoneywordGenerator _generator;
        private readonly IPasswordPepper? _pepper;
        private readonly int _maxSweetwords;
        private readonly int _maxPasswordBytes;
        private readonly SemaphoreSlim? _gate;
        private readonly TimeSpan _gateTimeout;

        /// <summary>
        /// Creates a service that uses <paramref name="hasher"/>'s default profile for new records and accepts any
        /// profile registered with it.
        /// </summary>
        public HoneywordService(PasswordHasher hasher, HoneywordServiceOptions? options = null)
            : this(RequireHasher(hasher).DefaultProfile, hasher.Profiles, options, profilesAreVetted: true)
        {
        }

        /// <summary>
        /// Creates a service with an explicit allowlist. <paramref name="defaultProfile"/> is used for new records
        /// and is always allowed. Profiles below the OWASP minimums need <see cref="HoneywordServiceOptions.AllowWeakProfiles"/>.
        /// </summary>
        public HoneywordService(HashProfile defaultProfile, IEnumerable<HashProfile> allowedProfiles, HoneywordServiceOptions? options = null)
            : this(defaultProfile, allowedProfiles, options, profilesAreVetted: false)
        {
        }

        private HoneywordService(HashProfile defaultProfile, IEnumerable<HashProfile> allowedProfiles, HoneywordServiceOptions? options, bool profilesAreVetted)
        {
            if (defaultProfile == null) throw new ArgumentNullException(nameof(defaultProfile));
            if (allowedProfiles == null) throw new ArgumentNullException(nameof(allowedProfiles));
            options ??= new HoneywordServiceOptions();

            bool allowWeak = profilesAreVetted || options.AllowWeakProfiles;
            foreach (HashProfile profile in allowedProfiles)
                Register(profile, allowWeak);
            Register(defaultProfile, allowWeak);
            _defaultProfile = defaultProfile;

            _generator = options.Generator ?? throw new ArgumentException("Generator is required.", nameof(options));

            if (options.Pepper != null && !HoneywordHash.IsValidKeyId(options.Pepper.CurrentKeyId))
                throw new ArgumentException("Pepper.CurrentKeyId must match ^[A-Za-z0-9-]{1,32}$.", nameof(options));
            _pepper = options.Pepper;

            if (options.MaxSweetwordCount < MinSweetwordCount || options.MaxSweetwordCount > MaxSweetwordLimit)
                throw new ArgumentOutOfRangeException(nameof(options), options.MaxSweetwordCount, $"MaxSweetwordCount must be between {MinSweetwordCount} and {MaxSweetwordLimit}.");
            _maxSweetwords = options.MaxSweetwordCount;

            if (options.MaxPasswordBytes < 64 || options.MaxPasswordBytes > 1024 * 1024)
                throw new ArgumentOutOfRangeException(nameof(options), options.MaxPasswordBytes, "MaxPasswordBytes must be between 64 and 1048576.");
            _maxPasswordBytes = options.MaxPasswordBytes;

            if (options.MaxConcurrency < 0)
                throw new ArgumentOutOfRangeException(nameof(options), options.MaxConcurrency, "MaxConcurrency cannot be negative.");
            if (options.ConcurrencyTimeout <= TimeSpan.Zero && options.ConcurrencyTimeout != Timeout.InfiniteTimeSpan)
                throw new ArgumentOutOfRangeException(nameof(options), options.ConcurrencyTimeout, "ConcurrencyTimeout must be positive or infinite.");
            _gate = options.MaxConcurrency > 0 ? new SemaphoreSlim(options.MaxConcurrency, options.MaxConcurrency) : null;
            _gateTimeout = options.ConcurrencyTimeout;
        }

        /// <summary>Profile used for new records.</summary>
        public HashProfile DefaultProfile => _defaultProfile;

        /// <summary>All profiles accepted in stored hashes.</summary>
        public IReadOnlyCollection<HashProfile> Profiles => _profiles.Values;

        /// <summary>The decoy generator in use.</summary>
        public IHoneywordGenerator Generator => _generator;

        /// <summary>Key derivation; replaceable by tests to count calls.</summary>
        internal Func<HashProfile, byte[], byte[], byte[]> Derive { get; set; } = HashPrimitives.DeriveKey;

        /// <summary>True if <paramref name="storedHash"/> looks like a honeyword hash (starts with <c>$mhw$</c>). Does not validate it.</summary>
        public static bool IsHoneywordHash(string? storedHash) =>
            storedHash != null && storedHash.StartsWith(HoneywordHash.Prefix, StringComparison.Ordinal);

        /// <summary>
        /// Generates decoys for <paramref name="password"/>, shuffles the real password in at a random position and
        /// hashes all <paramref name="sweetwordCount"/> sweetwords under one fresh salt.
        /// </summary>
        /// <exception cref="ArgumentException">The password is empty or too long.</exception>
        /// <exception cref="ArgumentOutOfRangeException">The sweetword count is outside 2..<see cref="HoneywordServiceOptions.MaxSweetwordCount"/>.</exception>
        /// <exception cref="InvalidOperationException">The generator returned an invalid decoy set.</exception>
        /// <exception cref="PasswordHasherBusyException">No derivation slot became free in time.</exception>
        public HoneywordRecord Create(string password, int sweetwordCount = DefaultSweetwordCount) =>
            RunSync(CreateCoreAsync(password, sweetwordCount, useAsync: false, CancellationToken.None));

        /// <summary>Async <see cref="Create"/>: waits asynchronously for derivation slots and uses the async pepper.</summary>
        public ValueTask<HoneywordRecord> CreateAsync(string password, int sweetwordCount = DefaultSweetwordCount, CancellationToken cancellationToken = default) =>
            CreateCoreAsync(password, sweetwordCount, useAsync: true, cancellationToken);

        /// <summary>
        /// Returns the zero-based index of the sweetword equal to <paramref name="password"/>, or -1 if there is none
        /// or the stored hash cannot be used. Never throws for a bad stored hash.
        /// </summary>
        public int Verify(string password, string storedHash) => VerifyDetailed(password, storedHash).Index;

        /// <summary>Like <see cref="Verify"/>, but also says why a check failed. Never throws for a bad stored hash.</summary>
        public HoneywordVerification VerifyDetailed(string password, string? storedHash) =>
            RunSync(VerifyCoreAsync(password, storedHash, dummyIfMissing: false, useAsync: false, CancellationToken.None));

        /// <summary>Async <see cref="VerifyDetailed"/>.</summary>
        public ValueTask<HoneywordVerification> VerifyDetailedAsync(string password, string? storedHash, CancellationToken cancellationToken = default) =>
            VerifyCoreAsync(password, storedHash, dummyIfMissing: false, useAsync: true, cancellationToken);

        /// <summary>
        /// Like <see cref="VerifyDetailed"/>, but when <paramref name="storedHash"/> is null (unknown user) it still
        /// performs one key derivation, so response timing does not reveal which accounts exist. A password longer
        /// than <see cref="HoneywordServiceOptions.MaxPasswordBytes"/> is rejected without a derivation on both paths.
        /// </summary>
        public HoneywordVerification VerifyOrDummy(string password, string? storedHash) =>
            RunSync(VerifyCoreAsync(password, storedHash, dummyIfMissing: true, useAsync: false, CancellationToken.None));

        /// <summary>Async <see cref="VerifyOrDummy"/>.</summary>
        public ValueTask<HoneywordVerification> VerifyOrDummyAsync(string password, string? storedHash, CancellationToken cancellationToken = default) =>
            VerifyCoreAsync(password, storedHash, dummyIfMissing: true, useAsync: true, cancellationToken);

        private void Register(HashProfile profile, bool allowWeak)
        {
            if (profile == null) throw new ArgumentException("Profiles cannot contain null.");
            if (!allowWeak && !profile.MeetsRecommendedMinimum)
                throw new ArgumentException($"Profile {profile} is below the OWASP minimum. Set AllowWeakProfiles only in tests.");
            if (_profiles.TryGetValue(profile.Id, out HashProfile? existing) && !existing.Equals(profile))
                throw new ArgumentException($"Profile id '{profile.Id}' is listed twice with different parameters.");
            _profiles[profile.Id] = profile;
        }

        private async ValueTask<HoneywordRecord> CreateCoreAsync(string password, int sweetwordCount, bool useAsync, CancellationToken ct)
        {
            if (password == null) throw new ArgumentNullException(nameof(password));
            if (password.Length == 0) throw new ArgumentException("Password cannot be empty.", nameof(password));
            if (!HashPrimitives.IsWellFormedPassword(password))
                throw new ArgumentException("Password contains invalid UTF-16 or a code point that cannot be normalized.", nameof(password));
            if (sweetwordCount < MinSweetwordCount || sweetwordCount > _maxSweetwords)
                throw new ArgumentOutOfRangeException(nameof(sweetwordCount), sweetwordCount, $"Sweetword count must be between {MinSweetwordCount} and {_maxSweetwords}.");

            if (password.Length > MaxPreNormalizationLength)
                throw new ArgumentException($"Password exceeds {_maxPasswordBytes} bytes.", nameof(password));
            string real = TextNormalization.Nfkc(password);
            if (Encoding.UTF8.GetByteCount(real) > _maxPasswordBytes)
                throw new ArgumentException($"Password exceeds {_maxPasswordBytes} bytes.", nameof(password));

            List<string> sweetwords = BuildSweetwords(real, sweetwordCount, out int realIndex);

            HashProfile profile = _defaultProfile;
            string? keyId = _pepper?.CurrentKeyId;
            byte[] salt = HashPrimitives.RandomBytes(profile.SaltLength);
            var tags = new byte[sweetwordCount][];
            try
            {
                for (int i = 0; i < sweetwords.Count; i++)
                {
                    byte[] input = TextNormalization.FingerprintBytes(sweetwords[i]); // a decoy generator may emit ill-formed text
                    if (keyId != null)
                        input = await ApplyPepperAsync(keyId, input, useAsync, ct).ConfigureAwait(false);
                    tags[i] = await DeriveAsync(profile, input, salt, useAsync, ct).ConfigureAwait(false);
                }

                string stored = new HoneywordHash(profile.Id, keyId, salt, tags).ToString();
                return new HoneywordRecord(stored, realIndex, sweetwordCount);
            }
            finally
            {
                foreach (byte[] tag in tags)
                    HashPrimitives.Zero(tag);
                sweetwords.Clear();
            }
        }

        /// <summary>Real password plus validated decoys, CSPRNG-shuffled.</summary>
        private List<string> BuildSweetwords(string real, int count, out int realIndex)
        {
            IReadOnlyList<string> decoys = _generator.GenerateDecoys(real, count - 1);
            if (decoys == null || decoys.Count != count - 1)
                throw new InvalidOperationException("The honeyword generator returned the wrong number of decoys.");

            var distinct = new HashSet<string>(StringComparer.Ordinal) { real };
            var sweetwords = new List<string>(count) { real };
            foreach (string decoy in decoys)
            {
                if (string.IsNullOrEmpty(decoy))
                    throw new InvalidOperationException("The honeyword generator returned an empty decoy.");
                string normalized = TextNormalization.Nfkc(decoy);
                if (Encoding.UTF8.GetByteCount(normalized) > _maxPasswordBytes)
                    throw new InvalidOperationException("The honeyword generator returned a decoy longer than MaxPasswordBytes.");
                if (!distinct.Add(normalized))
                    throw new InvalidOperationException("The honeyword generator returned duplicate decoys or the real password.");
                sweetwords.Add(normalized);
            }

            // Fisher-Yates over positions; track where the real password (index 0) lands.
            var order = new int[count];
            for (int i = 0; i < count; i++)
                order[i] = i;
            SecureRandom.Shuffle(order);

            var shuffled = new List<string>(count);
            realIndex = -1;
            for (int i = 0; i < count; i++)
            {
                shuffled.Add(sweetwords[order[i]]);
                if (order[i] == 0)
                    realIndex = i;
            }
            sweetwords.Clear();
            return shuffled;
        }

        private async ValueTask<HoneywordVerification> VerifyCoreAsync(string password, string? storedHash, bool dummyIfMissing, bool useAsync, CancellationToken ct)
        {
            if (password == null) throw new ArgumentNullException(nameof(password));

            if (string.IsNullOrEmpty(storedHash))
            {
                if (dummyIfMissing && password.Length > 0 && HashPrimitives.IsWellFormedPassword(password))
                    await DummyAsync(password, useAsync, ct).ConfigureAwait(false);
                return HoneywordVerification.Fail(HoneywordVerificationStatus.NoStoredHash);
            }

            if (password.Length == 0)
                return HoneywordVerification.Fail(HoneywordVerificationStatus.EmptyPassword);
            if (!HashPrimitives.IsWellFormedPassword(password))
                return HoneywordVerification.Fail(HoneywordVerificationStatus.InvalidPassword);
            if (!HoneywordHash.TryParse(storedHash!, _maxSweetwords, out HoneywordHash? hash) || hash == null)
                return HoneywordVerification.Fail(HoneywordVerificationStatus.MalformedHash);
            if (!_profiles.TryGetValue(hash.ProfileId, out HashProfile? profile))
                return HoneywordVerification.Fail(HoneywordVerificationStatus.UnknownProfile);
            if (hash.Salt.Length != profile.SaltLength)
                return HoneywordVerification.Fail(HoneywordVerificationStatus.MalformedHash);
            foreach (byte[] tag in hash.Tags)
            {
                if (tag.Length != profile.TagLength)
                    return HoneywordVerification.Fail(HoneywordVerificationStatus.MalformedHash);
            }
            if (hash.PepperKeyId != null && (_pepper == null || !_pepper.IsKnownKey(hash.PepperKeyId)))
                return HoneywordVerification.Fail(HoneywordVerificationStatus.UnknownPepperKey);

            byte[]? encoded = Encode(password);
            if (encoded == null)
                return HoneywordVerification.Fail(HoneywordVerificationStatus.PasswordTooLong);

            byte[] input = hash.PepperKeyId == null
                ? encoded
                : await ApplyPepperAsync(hash.PepperKeyId, encoded, useAsync, ct).ConfigureAwait(false);

            byte[] computed = await DeriveAsync(profile, input, hash.Salt, useAsync, ct).ConfigureAwait(false);
            int index = ConstantTimeIndexOf(computed, hash.Tags);
            HashPrimitives.Zero(computed);

            return index >= 0
                ? new HoneywordVerification(HoneywordVerificationStatus.SweetwordMatch, index)
                : HoneywordVerification.Fail(HoneywordVerificationStatus.Mismatch);
        }

        /// <summary>
        /// One derivation with the default profile and a throwaway salt, to equalize timing for unknown users.
        /// An over-long password is rejected without a derivation, exactly as it is for a known user.
        /// </summary>
        private async ValueTask DummyAsync(string password, bool useAsync, CancellationToken ct)
        {
            byte[]? input = Encode(password);
            if (input == null)
                return;
            string? keyId = _pepper?.CurrentKeyId;
            if (keyId != null)
                input = await ApplyPepperAsync(keyId, input, useAsync, ct).ConfigureAwait(false);
            byte[] salt = HashPrimitives.RandomBytes(_defaultProfile.SaltLength);
            HashPrimitives.Zero(await DeriveAsync(_defaultProfile, input, salt, useAsync, ct).ConfigureAwait(false));
        }

        /// <summary>
        /// Index of the tag equal to <paramref name="computed"/>, or -1. Every tag is compared, with a fixed-time
        /// comparison and a branch-free select, so timing does not depend on which (if any) sweetword matched.
        /// </summary>
        private static int ConstantTimeIndexOf(byte[] computed, byte[][] tags)
        {
            int index = -1;
            for (int i = 0; i < tags.Length; i++)
            {
                int equal = HashPrimitives.FixedTimeEquals(computed, tags[i]) ? 1 : 0;
                int mask = -equal;
                index = (index & ~mask) | (i & mask);
            }
            return index;
        }

        /// <summary>
        /// Longest password, in UTF-16 code units, that is normalized at all. NFKC can expand a string up to 18-fold,
        /// so an attacker-supplied megabyte password is rejected before normalization. NFKC composition shrinks
        /// UTF-8 at most about three-fold, so four times the byte limit never rejects a password that would fit.
        /// </summary>
        private long MaxPreNormalizationLength => 4L * _maxPasswordBytes;

        /// <summary>UTF-8 of the NFKC-normalized password, or null if it is too long.</summary>
        private byte[]? Encode(string password)
        {
            if (password.Length > MaxPreNormalizationLength)
                return null;
            byte[] encoded = HashPrimitives.EncodePassword(password);
            if (encoded.Length <= _maxPasswordBytes)
                return encoded;
            HashPrimitives.Zero(encoded);
            return null;
        }

        /// <summary>Applies the pepper and zeroes <paramref name="input"/>.</summary>
        private async ValueTask<byte[]> ApplyPepperAsync(string keyId, byte[] input, bool useAsync, CancellationToken ct)
        {
            try
            {
                return useAsync
                    ? await _pepper!.ApplyAsync(keyId, input, ct).ConfigureAwait(false)
                    : _pepper!.Apply(keyId, input);
            }
            finally
            {
                HashPrimitives.Zero(input);
            }
        }

        /// <summary>Runs the KDF inside the concurrency gate and zeroes <paramref name="input"/>.</summary>
        private async ValueTask<byte[]> DeriveAsync(HashProfile profile, byte[] input, byte[] salt, bool useAsync, CancellationToken ct)
        {
            try
            {
                if (_gate != null)
                {
                    bool entered = useAsync
                        ? await _gate.WaitAsync(_gateTimeout, ct).ConfigureAwait(false)
                        : _gate.Wait(_gateTimeout, ct);
                    if (!entered)
                        throw new PasswordHasherBusyException();
                }

                try
                {
                    return Derive(profile, input, salt);
                }
                finally
                {
                    _gate?.Release();
                }
            }
            finally
            {
                HashPrimitives.Zero(input);
            }
        }

        private static PasswordHasher RequireHasher(PasswordHasher hasher) =>
            hasher ?? throw new ArgumentNullException(nameof(hasher));

        private static T RunSync<T>(ValueTask<T> task)
        {
            // Every await completes synchronously when useAsync is false (sync pepper, sync gate).
            Debug.Assert(task.IsCompleted, "Synchronous path must not suspend.");
            return task.GetAwaiter().GetResult();
        }
    }
}
