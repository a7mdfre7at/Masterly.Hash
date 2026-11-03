using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Masterly.Hash.Internal;
using Masterly.Hash.Legacy;
using Masterly.Hash.Pepper;

namespace Masterly.Hash
{
    /// <summary>
    /// Thread-safe password hasher. Create one per application (or register it as a singleton) and reuse it.
    /// </summary>
    public sealed class PasswordHasher : IPasswordHasher
    {
        private static readonly Lazy<PasswordHasher> LazyDefault =
            new Lazy<PasswordHasher>(() => new PasswordHasher(), LazyThreadSafetyMode.ExecutionAndPublication);

        private static readonly HashProfile[] BuiltInProfiles =
        {
            HashProfile.Server2026a, HashProfile.Constrained2026a, HashProfile.Fips2026a,
        };

        private readonly HashProfile _defaultProfile;
        private readonly Dictionary<string, HashProfile> _profiles = new Dictionary<string, HashProfile>(StringComparer.Ordinal);
        private readonly IPasswordPepper? _pepper;
        private readonly ILegacyHashFormat[] _legacyFormats;
        private readonly Dictionary<string, ILegacyHashFormat> _legacyById = new Dictionary<string, ILegacyHashFormat>(StringComparer.Ordinal);
        private readonly int _maxPasswordBytes;
        private readonly SemaphoreSlim? _gate;
        private readonly TimeSpan _gateTimeout;
        private readonly bool _computeRehash;

        /// <summary>Creates a hasher with the default options.</summary>
        public PasswordHasher()
            : this(new PasswordHasherOptions())
        {
        }

        /// <summary>Creates a hasher. The options are copied; later changes to them have no effect.</summary>
        public PasswordHasher(PasswordHasherOptions options)
        {
            if (options == null) throw new ArgumentNullException(nameof(options));
            if (options.DefaultProfile == null) throw new ArgumentException("DefaultProfile is required.", nameof(options));

            foreach (HashProfile profile in BuiltInProfiles)
                _profiles[profile.Id] = profile;

            foreach (HashProfile profile in options.AdditionalProfiles)
                Register(profile, options.AllowWeakProfiles);
            Register(options.DefaultProfile, options.AllowWeakProfiles);
            _defaultProfile = options.DefaultProfile;

            var legacy = new List<ILegacyHashFormat>();
            foreach (ILegacyHashFormat format in options.LegacyFormats)
            {
                if (format == null) throw new ArgumentException("LegacyFormats contains null.", nameof(options));
                if (!MhHash.IsValidFormatId(format.Id))
                    throw new ArgumentException($"Legacy format id '{format.Id}' must match ^[a-z0-9][a-z0-9-]{{0,31}}$.", nameof(options));
                if (_legacyById.ContainsKey(format.Id))
                    throw new ArgumentException($"Legacy format id '{format.Id}' is registered twice.", nameof(options));
                _legacyById[format.Id] = format;
                legacy.Add(format);
            }
            _legacyFormats = legacy.ToArray();

            if (options.Pepper != null && !MhHash.IsValidKeyId(options.Pepper.CurrentKeyId))
                throw new ArgumentException("Pepper.CurrentKeyId must match ^[A-Za-z0-9-]{1,32}$.", nameof(options));
            _pepper = options.Pepper;

            if (options.MaxPasswordBytes < 64 || options.MaxPasswordBytes > 1024 * 1024)
                throw new ArgumentOutOfRangeException(nameof(options), options.MaxPasswordBytes, "MaxPasswordBytes must be between 64 and 1048576.");
            _maxPasswordBytes = options.MaxPasswordBytes;

            if (options.MaxConcurrency < 0)
                throw new ArgumentOutOfRangeException(nameof(options), options.MaxConcurrency, "MaxConcurrency cannot be negative.");
            if (options.ConcurrencyTimeout <= TimeSpan.Zero && options.ConcurrencyTimeout != Timeout.InfiniteTimeSpan)
                throw new ArgumentOutOfRangeException(nameof(options), options.ConcurrencyTimeout, "ConcurrencyTimeout must be positive or infinite.");
            _gate = options.MaxConcurrency > 0 ? new SemaphoreSlim(options.MaxConcurrency, options.MaxConcurrency) : null;
            _gateTimeout = options.ConcurrencyTimeout;

            _computeRehash = options.ComputeRehashOnVerify;
        }

        /// <summary>Shared hasher with the default options, used by <see cref="Password"/>.</summary>
        public static PasswordHasher Default => LazyDefault.Value;

        /// <summary>Profile used for new hashes.</summary>
        public HashProfile DefaultProfile => _defaultProfile;

        /// <summary>The longest password, in UTF-8 bytes after normalization, this hasher accepts.</summary>
        public int MaxPasswordBytes => _maxPasswordBytes;

        /// <summary>All profiles this hasher accepts.</summary>
        public IReadOnlyCollection<HashProfile> Profiles => _profiles.Values;

        /// <summary>Name of the <c>System.Diagnostics.Metrics</c> meter, for <c>AddMeter(...)</c>.</summary>
        public const string MeterName = HashMetrics.MeterName;

        /// <inheritdoc />
        public string Hash(string password) => Hash(password, _defaultProfile);

        /// <inheritdoc />
        public string Hash(string password, HashProfile profile) =>
            RunSync(HashCoreAsync(password, profile, useAsync: false, CancellationToken.None));

        /// <inheritdoc />
        public ValueTask<string> HashAsync(string password, CancellationToken cancellationToken = default) =>
            HashCoreAsync(password, _defaultProfile, useAsync: true, cancellationToken);

        /// <inheritdoc />
        public PasswordVerificationResult Verify(string password, string storedHash) =>
            RunSync(VerifyCoreAsync(password, storedHash, useAsync: false, CancellationToken.None));

        /// <inheritdoc />
        public ValueTask<PasswordVerificationResult> VerifyAsync(string password, string storedHash, CancellationToken cancellationToken = default) =>
            VerifyCoreAsync(password, storedHash, useAsync: true, cancellationToken);

        /// <inheritdoc />
        public PasswordVerificationResult VerifyOrDummy(string password, string? storedHash) =>
            RunSync(VerifyOrDummyCoreAsync(password, storedHash, useAsync: false, CancellationToken.None));

        /// <inheritdoc />
        public ValueTask<PasswordVerificationResult> VerifyOrDummyAsync(string password, string? storedHash, CancellationToken cancellationToken = default) =>
            VerifyOrDummyCoreAsync(password, storedHash, useAsync: true, cancellationToken);

        /// <inheritdoc />
        public bool NeedsRehash(string storedHash) => Inspect(storedHash).NeedsRehash;

        /// <inheritdoc />
        public HashInfo Inspect(string storedHash)
        {
            if (string.IsNullOrEmpty(storedHash))
                return new HashInfo(HashInfo.UnknownFormat, false, null, null, null, null, RehashReason.None);

            if (storedHash.StartsWith(MhHash.Prefix, StringComparison.Ordinal))
            {
                if (!MhHash.TryParse(storedHash, out MhHash? mh) || mh == null)
                    return new HashInfo(HashInfo.NativeFormat, false, null, null, null, null, RehashReason.None);

                _profiles.TryGetValue(mh.ProfileId, out HashProfile? profile);
                bool keyOk = mh.PepperKeyId == null || (_pepper != null && _pepper.IsKnownKey(mh.PepperKeyId));
                bool wrapOk = mh.WrapFormat == null || _legacyById.ContainsKey(mh.WrapFormat);
                bool shapeOk = profile != null && mh.Salt.Length == profile.SaltLength && mh.Tag.Length == profile.TagLength;
                bool recognized = shapeOk && keyOk && wrapOk;
                return new HashInfo(HashInfo.NativeFormat, recognized, mh.ProfileId, profile, mh.PepperKeyId, mh.WrapFormat,
                    recognized ? RehashReasonFor(mh) : RehashReason.None);
            }

            foreach (ILegacyHashFormat format in _legacyFormats)
            {
                if (SafeCanHandle(format, storedHash))
                    return new HashInfo(format.Id, true, null, null, null, null, RehashReason.LegacyFormat);
            }

            return new HashInfo(HashInfo.UnknownFormat, false, null, null, null, null, RehashReason.None);
        }

        /// <inheritdoc />
        public bool TryWrap(string legacyHash, out string wrappedHash)
        {
            wrappedHash = string.Empty;
            if (string.IsNullOrEmpty(legacyHash) || legacyHash.StartsWith(MhHash.Prefix, StringComparison.Ordinal))
                return false;

            foreach (ILegacyHashFormat format in _legacyFormats)
            {
                if (!SafeCanHandle(format, legacyHash))
                    continue;

                byte[] digest, parameter;
                try
                {
                    if (!format.TryExtractWrapInput(legacyHash, out digest, out parameter))
                        continue;
                }
                catch (Exception ex) when (IsRecoverable(ex))
                {
                    continue;
                }

                string? keyId = _pepper?.CurrentKeyId;
                byte[] input = keyId != null ? _pepper!.Apply(keyId, digest) : digest;
                if (!ReferenceEquals(input, digest))
                    CryptoUtil.Zero(digest);

                wrappedHash = RunSync(ComputeAsync(_defaultProfile, keyId, format.Id, parameter, input, useAsync: false, CancellationToken.None));
                return true;
            }

            return false;
        }

        private void Register(HashProfile profile, bool allowWeak)
        {
            if (profile == null) throw new ArgumentException("Profiles cannot contain null.");
            if (!allowWeak && !profile.MeetsRecommendedMinimum)
                throw new ArgumentException($"Profile {profile} is below the OWASP minimum. Set AllowWeakProfiles only in tests.");
            if (_profiles.TryGetValue(profile.Id, out HashProfile? existing) && !existing.Equals(profile))
                throw new ArgumentException($"Profile id '{profile.Id}' is already registered with different parameters. Profile ids are permanent; pick a new id.");
            _profiles[profile.Id] = profile;
        }

        private async ValueTask<string> HashCoreAsync(string password, HashProfile profile, bool useAsync, CancellationToken ct)
        {
            if (password == null) throw new ArgumentNullException(nameof(password));
            if (profile == null) throw new ArgumentNullException(nameof(profile));
            if (!_profiles.TryGetValue(profile.Id, out HashProfile? registered) || !registered.Equals(profile))
                throw new ArgumentException($"Profile '{profile.Id}' is not registered with this hasher.", nameof(profile));
            if (password.Length == 0)
                throw new ArgumentException("Password cannot be empty.", nameof(password));
            if (!PasswordEncoding.IsWellFormed(password))
                throw new ArgumentException("Password contains invalid UTF-16 or a code point that cannot be normalized.", nameof(password));

            byte[] encoded = Encode(password)
                ?? throw new ArgumentException($"Password exceeds {_maxPasswordBytes} bytes.", nameof(password));

            string? keyId = _pepper?.CurrentKeyId;
            byte[] input = keyId == null ? encoded : await ApplyPepperAsync(keyId, encoded, useAsync, ct).ConfigureAwait(false);
            return await ComputeAsync(registered, keyId, null, null, input, useAsync, ct).ConfigureAwait(false);
        }

        /// <summary>Derives the tag and formats the hash string. Zeroes <paramref name="input"/>.</summary>
        private async ValueTask<string> ComputeAsync(HashProfile profile, string? keyId, string? wrapFormat, byte[]? wrapParameter, byte[] input, bool useAsync, CancellationToken ct)
        {
            long start = Stopwatch.GetTimestamp();
            byte[] salt = CryptoUtil.RandomBytes(profile.SaltLength);
            byte[] tag;
            try
            {
                await EnterAsync(useAsync, ct).ConfigureAwait(false);
                try
                {
                    tag = Kdf.Derive(profile, input, salt);
                }
                finally
                {
                    _gate?.Release();
                }
            }
            finally
            {
                CryptoUtil.Zero(input);
            }

            string result = new MhHash(profile.Id, keyId, wrapFormat, wrapParameter, salt, tag).ToString();
            CryptoUtil.Zero(tag);
            HashMetrics.RecordHash(profile.Id, ElapsedMs(start));
            return result;
        }

        private async ValueTask<PasswordVerificationResult> VerifyOrDummyCoreAsync(string password, string? storedHash, bool useAsync, CancellationToken ct)
        {
            if (password == null) throw new ArgumentNullException(nameof(password));
            if (storedHash != null)
                return await VerifyCoreAsync(password, storedHash, useAsync, ct).ConfigureAwait(false);

            // Unknown user: do the same work as a real verification, then fail.
            if (password.Length > 0 && PasswordEncoding.IsWellFormed(password))
                await VerifyMhAsync(password, CreateDummyHash(), allowRehash: false, useAsync, ct).ConfigureAwait(false);
            return PasswordVerificationResult.Fail(VerificationFailureReason.NoStoredHash);
        }

        /// <summary>
        /// A hash in the current format that nothing matches: the default profile, the pepper's current key, random salt and
        /// tag. Built per call, so it follows key rotation; a dummy under a revoked key would skip the pepper and KDF and make
        /// unknown users measurably cheaper than real ones.
        /// </summary>
        private string CreateDummyHash() =>
            new MhHash(_defaultProfile.Id, _pepper?.CurrentKeyId, null, null,
                CryptoUtil.RandomBytes(_defaultProfile.SaltLength), CryptoUtil.RandomBytes(_defaultProfile.TagLength)).ToString();

        private async ValueTask<PasswordVerificationResult> VerifyCoreAsync(string password, string storedHash, bool useAsync, CancellationToken ct)
        {
            if (password == null) throw new ArgumentNullException(nameof(password));
            if (string.IsNullOrEmpty(storedHash))
                return PasswordVerificationResult.Fail(VerificationFailureReason.NoStoredHash);
            if (password.Length == 0)
                return PasswordVerificationResult.Fail(VerificationFailureReason.EmptyPassword);
            if (!PasswordEncoding.IsWellFormed(password))
                return PasswordVerificationResult.Fail(VerificationFailureReason.InvalidPassword);

            long start = Stopwatch.GetTimestamp();
            string format;
            PasswordVerificationResult result;

            if (storedHash.StartsWith(MhHash.Prefix, StringComparison.Ordinal))
            {
                format = "mh";
                result = await VerifyMhAsync(password, storedHash, allowRehash: true, useAsync, ct).ConfigureAwait(false);
            }
            else
            {
                (format, result) = await VerifyLegacyAsync(password, storedHash, useAsync, ct).ConfigureAwait(false);
            }

            HashMetrics.RecordVerify(format, result, ElapsedMs(start));
            return result;
        }

        private async ValueTask<PasswordVerificationResult> VerifyMhAsync(string password, string storedHash, bool allowRehash, bool useAsync, CancellationToken ct)
        {
            if (!MhHash.TryParse(storedHash, out MhHash? mh) || mh == null)
                return PasswordVerificationResult.Fail(VerificationFailureReason.MalformedHash);
            if (!_profiles.TryGetValue(mh.ProfileId, out HashProfile? profile))
                return PasswordVerificationResult.Fail(VerificationFailureReason.UnknownProfile);
            if (mh.Salt.Length != profile.SaltLength || mh.Tag.Length != profile.TagLength)
                return PasswordVerificationResult.Fail(VerificationFailureReason.MalformedHash);
            if (mh.PepperKeyId != null && (_pepper == null || !_pepper.IsKnownKey(mh.PepperKeyId)))
                return PasswordVerificationResult.Fail(VerificationFailureReason.UnknownPepperKey);

            byte[] baseInput;
            if (mh.WrapFormat != null)
            {
                if (!_legacyById.TryGetValue(mh.WrapFormat, out ILegacyHashFormat? wrapped))
                    return PasswordVerificationResult.Fail(VerificationFailureReason.UnknownFormat);
                if (Encoding.UTF8.GetByteCount(password) > _maxPasswordBytes)
                    return PasswordVerificationResult.Fail(VerificationFailureReason.PasswordTooLong);
                try
                {
                    baseInput = wrapped.ComputeWrapInput(password, mh.WrapParameter ?? Array.Empty<byte>());
                }
                catch (Exception ex) when (IsRecoverable(ex))
                {
                    return PasswordVerificationResult.Fail(VerificationFailureReason.MalformedHash);
                }
            }
            else
            {
                byte[]? encoded = Encode(password);
                if (encoded == null)
                    return PasswordVerificationResult.Fail(VerificationFailureReason.PasswordTooLong);
                baseInput = encoded;
            }

            byte[] input = mh.PepperKeyId == null
                ? baseInput
                : await ApplyPepperAsync(mh.PepperKeyId, baseInput, useAsync, ct).ConfigureAwait(false);

            byte[] computed;
            try
            {
                await EnterAsync(useAsync, ct).ConfigureAwait(false);
                try
                {
                    computed = Kdf.Derive(profile, input, mh.Salt);
                }
                finally
                {
                    _gate?.Release();
                }
            }
            finally
            {
                CryptoUtil.Zero(input);
            }

            bool match = CryptoUtil.FixedTimeEquals(computed, mh.Tag);
            CryptoUtil.Zero(computed);
            if (!match)
                return PasswordVerificationResult.Fail(VerificationFailureReason.Mismatch);

            RehashReason reason = RehashReasonFor(mh);
            if (reason == RehashReason.None)
                return PasswordVerificationResult.Current;

            string? rehash = allowRehash && _computeRehash
                ? await RehashAsync(password, useAsync, ct).ConfigureAwait(false)
                : null;
            return new PasswordVerificationResult(VerificationStatus.SuccessRehashNeeded, VerificationFailureReason.None, reason, rehash);
        }

        private async ValueTask<(string Format, PasswordVerificationResult Result)> VerifyLegacyAsync(string password, string storedHash, bool useAsync, CancellationToken ct)
        {
            var candidates = new List<ILegacyHashFormat>();
            foreach (ILegacyHashFormat format in _legacyFormats)
            {
                if (SafeCanHandle(format, storedHash))
                    candidates.Add(format);
            }

            if (candidates.Count == 0)
                return ("unknown", PasswordVerificationResult.Fail(VerificationFailureReason.UnknownFormat));
            if (Encoding.UTF8.GetByteCount(password) > _maxPasswordBytes)
                return (candidates[0].Id, PasswordVerificationResult.Fail(VerificationFailureReason.PasswordTooLong));

            string matchedFormat = candidates[0].Id;
            bool match = false;
            await EnterAsync(useAsync, ct).ConfigureAwait(false);
            try
            {
                foreach (ILegacyHashFormat format in candidates)
                {
                    bool verified;
                    try
                    {
                        verified = format.Verify(password, storedHash);
                    }
                    catch (Exception ex) when (IsRecoverable(ex))
                    {
                        verified = false;
                    }

                    if (verified)
                    {
                        match = true;
                        matchedFormat = format.Id;
                        break;
                    }
                }
            }
            finally
            {
                _gate?.Release();
            }

            if (!match)
                return (matchedFormat, PasswordVerificationResult.Fail(VerificationFailureReason.Mismatch));

            string? rehash = _computeRehash
                ? await RehashAsync(password, useAsync, ct).ConfigureAwait(false)
                : null;
            return (matchedFormat, new PasswordVerificationResult(VerificationStatus.SuccessRehashNeeded, VerificationFailureReason.None, RehashReason.LegacyFormat, rehash));
        }

        /// <summary>
        /// The replacement hash after a successful verify, or null when the password cannot be stored natively:
        /// legacy and wrapped formats check the raw UTF-8 length, but NFKC can expand it past MaxPasswordBytes
        /// (e.g. U+FDFA becomes 18 characters). The login still succeeds; the hash just stays as it is.
        /// </summary>
        private async ValueTask<string?> RehashAsync(string password, bool useAsync, CancellationToken ct)
        {
            if (Encoding.UTF8.GetByteCount(PasswordEncoding.Normalize(password)) > _maxPasswordBytes)
                return null;
            return await HashCoreAsync(password, _defaultProfile, useAsync, ct).ConfigureAwait(false);
        }

        private RehashReason RehashReasonFor(MhHash mh)
        {
            if (mh.WrapFormat != null)
                return RehashReason.Wrapped;
            if (mh.ProfileId != _defaultProfile.Id)
                return RehashReason.OutdatedProfile;
            if (_pepper != null && mh.PepperKeyId != _pepper.CurrentKeyId)
                return RehashReason.OutdatedPepperKey;
            return RehashReason.None;
        }

        /// <summary>UTF-8 of the NFKC-normalized password (NIST SP 800-63B §5.1.1.2), or null if it is too long.</summary>
        private byte[]? Encode(string password)
        {
            string normalized = PasswordEncoding.Normalize(password);
            if (Encoding.UTF8.GetByteCount(normalized) > _maxPasswordBytes)
                return null;
            return Encoding.UTF8.GetBytes(normalized);
        }

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
                CryptoUtil.Zero(input);
            }
        }

        private async ValueTask EnterAsync(bool useAsync, CancellationToken ct)
        {
            if (_gate == null)
                return;

            bool entered = useAsync
                ? await _gate.WaitAsync(_gateTimeout, ct).ConfigureAwait(false)
                : _gate.Wait(_gateTimeout, ct);

            if (!entered)
            {
                HashMetrics.RecordBusy();
                throw new PasswordHasherBusyException();
            }
        }

        /// <summary>
        /// Exceptions from a (possibly third-party) legacy format that are treated as "does not match" rather than
        /// escaping Verify. Cancellation and out-of-memory always propagate.
        /// </summary>
        private static bool IsRecoverable(Exception ex) => !(ex is OperationCanceledException || ex is OutOfMemoryException);

        private static bool SafeCanHandle(ILegacyHashFormat format, string storedHash)
        {
            try
            {
                return format.CanHandle(storedHash);
            }
            catch (Exception ex) when (IsRecoverable(ex))
            {
                return false;
            }
        }

        private static T RunSync<T>(ValueTask<T> task)
        {
            // Every await in the core completes synchronously when useAsync is false.
            Debug.Assert(task.IsCompleted, "Synchronous path must not suspend.");
            return task.GetAwaiter().GetResult();
        }

        private static double ElapsedMs(long start) =>
            (Stopwatch.GetTimestamp() - start) * 1000.0 / Stopwatch.Frequency;
    }
}
