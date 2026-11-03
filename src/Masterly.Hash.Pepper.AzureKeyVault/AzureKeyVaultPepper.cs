using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Azure;
using Azure.Security.KeyVault.Secrets;
using Masterly.Hash.Primitives;

namespace Masterly.Hash.Pepper.AzureKeyVault
{
    /// <summary>
    /// Pepper whose keys are stored as Azure Key Vault secrets. Key Vault cannot compute HMACs, so the keys are
    /// <b>loaded into application memory</b>, cached, and used locally through <see cref="HmacPepper"/> (HMAC-SHA256).
    /// </summary>
    /// <remarks>
    /// <para>
    /// Unlike the HashiCorp Vault and AWS KMS peppers, the key material lives in this process. A database leak alone
    /// does not expose it, but a memory dump or code execution on the host does. Restrict secret access to the
    /// application identity (<c>Get</c> and <c>List</c> on secrets only).
    /// </para>
    /// <para>
    /// <b>Versions mode</b> (<see cref="AzureKeyVaultPepperOptions.SecretName"/>): each enabled version of one secret
    /// is a key, and its version id is the pepper key id. To rotate, add a new version. After
    /// <see cref="AzureKeyVaultPepperOptions.ActivationDelay"/> it becomes current. To revoke a version, disable or
    /// delete it. The version list is refreshed in the background every <see cref="AzureKeyVaultPepperOptions.RefreshInterval"/>.
    /// </para>
    /// <para>
    /// <b>Revocation fails closed.</b> Whenever Key Vault answers the version listing, the answer is applied, even if
    /// it leaves no usable current key. Disabled and deleted versions leave the ring, and hashes that use them fail
    /// with <c>UnknownPepperKey</c>. If no current key can be chosen (the pinned <see cref="AzureKeyVaultPepperOptions.CurrentKeyId"/>
    /// was disabled, every version was disabled or deleted, or every remaining version is expired or not yet valid), then
    /// <see cref="CurrentKeyId"/> throws <see cref="PepperUnavailableException"/>. New hashes then cannot be written, and
    /// successful verifications, which check the current key for rehash, also throw, until Key Vault or the
    /// configuration is fixed. An enabled version that cannot be used (invalid value, or one that cannot be read) is
    /// skipped and reported through <see cref="AzureKeyVaultPepperOptions.OnRefreshFailed"/>. It does not block the rest
    /// of the refresh. Only failures to reach Key Vault (network, timeout, throttling, server errors) keep the cached keys.
    /// </para>
    /// <para>
    /// When a refresh removes a key, calls already in flight that saw that key still complete. <see cref="Apply"/>
    /// accepts a key removed by the most recent refresh for <see cref="RemovedKeyGrace"/> afterwards. This covers the gap
    /// between the hasher's <see cref="IsKnownKey"/> or <see cref="CurrentKeyId"/> check and its <see cref="Apply"/> call.
    /// </para>
    /// <para>
    /// <b>Map mode</b> (<see cref="AzureKeyVaultPepperOptions.Keys"/>): explicit key ids mapped to secrets, loaded once.
    /// </para>
    /// <para>
    /// After <see cref="CreateAsync"/> succeeds, <see cref="Apply"/> and <see cref="ApplyAsync"/> are purely local and
    /// never block on Key Vault. If Key Vault cannot be reached during a refresh, the cached keys stay in use; see
    /// <see cref="LastRefreshError"/>.
    /// Thread-safe.
    /// </para>
    /// </remarks>
    public sealed class AzureKeyVaultPepper : IPasswordPepper
    {
        /// <summary>Minimum decoded key length in bytes.</summary>
        public const int MinKeyLength = HmacPepper.MinKeyLength;

        /// <summary>After a failed refresh, the next background attempt waits at most this long.</summary>
        internal static readonly TimeSpan FailedRefreshRetry = TimeSpan.FromMinutes(1);

        /// <summary>
        /// How long after a refresh <see cref="Apply"/> still accepts a key that the refresh removed, so a hash or verify
        /// already in flight does not fail between its key check and its HMAC call.
        /// </summary>
        public static readonly TimeSpan RemovedKeyGrace = TimeSpan.FromSeconds(30);

        private const int MaxSecretValueLength = 8192;

        private static readonly Regex SecretNamePattern = new Regex(@"^[0-9A-Za-z-]{1,127}\z", RegexOptions.CultureInvariant);
        private static readonly Regex VersionPattern = new Regex(@"^[0-9A-Za-z]{1,64}\z", RegexOptions.CultureInvariant);

        private readonly SecretClient _client;
        private readonly string? _secretName;
        private readonly Dictionary<string, AzureKeyVaultSecretReference>? _map;
        private readonly string? _pinnedCurrent;
        private readonly TimeSpan _refreshInterval;
        private readonly TimeSpan _activationDelay;
        private readonly TimeSpan _timeout;
        private readonly int _maxVersions;
        private readonly Action<Exception>? _onRefreshFailed;
        private readonly Func<DateTimeOffset> _clock;
        private readonly SemaphoreSlim _refreshLock = new SemaphoreSlim(1, 1);

        // Decoded keys of secret versions already fetched (versions are immutable). Guarded by _refreshLock.
        private readonly Dictionary<string, byte[]> _versionCache = new Dictionary<string, byte[]>(StringComparer.Ordinal);

        private Snapshot _snapshot = null!;
        private long _nextRefreshUtcTicks = long.MaxValue;
        private int _backgroundRefreshing;
        private Exception? _lastRefreshError;

        private AzureKeyVaultPepper(SecretClient client, AzureKeyVaultPepperOptions options, Func<DateTimeOffset> clock)
        {
            if (client == null) throw new ArgumentNullException(nameof(client));
            if (options == null) throw new ArgumentNullException(nameof(options));

            bool versionsMode = options.SecretName != null;
            if (versionsMode == (options.Keys.Count > 0))
                throw new ArgumentException("Set exactly one of SecretName (versions mode) and Keys (map mode).", nameof(options));

            if (options.CurrentKeyId != null && !HashPrimitives.IsValidKeyId(options.CurrentKeyId))
                throw new ArgumentException("CurrentKeyId must match ^[A-Za-z0-9-]{1,32}$.", nameof(options));

            if (versionsMode)
            {
                if (!SecretNamePattern.IsMatch(options.SecretName!))
                    throw new ArgumentException("SecretName must be 1-127 letters, digits or '-'.", nameof(options));
                _secretName = options.SecretName;
            }
            else
            {
                if (options.CurrentKeyId == null || !options.Keys.ContainsKey(options.CurrentKeyId))
                    throw new ArgumentException("In map mode CurrentKeyId is required and must be a key in Keys.", nameof(options));
                _map = new Dictionary<string, AzureKeyVaultSecretReference>(StringComparer.Ordinal);
                foreach (KeyValuePair<string, AzureKeyVaultSecretReference> pair in options.Keys)
                {
                    if (pair.Key == null || !HashPrimitives.IsValidKeyId(pair.Key))
                        throw new ArgumentException($"Pepper key id '{pair.Key}' must match ^[A-Za-z0-9-]{{1,32}}$.", nameof(options));
                    AzureKeyVaultSecretReference? reference = pair.Value;
                    if (reference == null || !SecretNamePattern.IsMatch(reference.Name) ||
                        (reference.Version != null && !VersionPattern.IsMatch(reference.Version)))
                        throw new ArgumentException($"Secret reference for pepper key id '{pair.Key}' has an invalid name or version.", nameof(options));
                    _map[pair.Key] = reference;
                }
            }

            if (options.RefreshInterval != Timeout.InfiniteTimeSpan &&
                (options.RefreshInterval < TimeSpan.FromSeconds(1) || options.RefreshInterval > TimeSpan.FromDays(30)))
                throw new ArgumentException("RefreshInterval must be between 1 second and 30 days, or Timeout.InfiniteTimeSpan.", nameof(options));
            if (options.ActivationDelay < TimeSpan.Zero || options.ActivationDelay > TimeSpan.FromDays(365))
                throw new ArgumentException("ActivationDelay must be between zero and 365 days.", nameof(options));
            if (options.MaxVersions < 1 || options.MaxVersions > 500)
                throw new ArgumentException("MaxVersions must be between 1 and 500.", nameof(options));
            if (options.Timeout <= TimeSpan.Zero || options.Timeout > TimeSpan.FromMinutes(10))
                throw new ArgumentException("Timeout must be greater than zero and at most 10 minutes.", nameof(options));

            _client = client;
            _pinnedCurrent = options.CurrentKeyId;
            _refreshInterval = options.RefreshInterval;
            _activationDelay = options.ActivationDelay;
            _maxVersions = options.MaxVersions;
            _timeout = options.Timeout;
            _onRefreshFailed = options.OnRefreshFailed;
            _clock = clock;
        }

        /// <summary>
        /// Validates <paramref name="options"/>, loads the pepper keys from Key Vault and returns a ready pepper.
        /// Later changes to <paramref name="options"/> have no effect.
        /// </summary>
        /// <param name="client">Secret client for the vault, e.g. <c>new SecretClient(vaultUri, new DefaultAzureCredential())</c>.</param>
        /// <param name="options">Secret name or key map, plus refresh settings.</param>
        /// <param name="cancellationToken">Cancels the initial load.</param>
        /// <exception cref="ArgumentNullException"><paramref name="client"/> or <paramref name="options"/> is null.</exception>
        /// <exception cref="ArgumentException">The options are invalid.</exception>
        /// <exception cref="PepperUnavailableException">The keys could not be loaded.</exception>
        public static Task<AzureKeyVaultPepper> CreateAsync(SecretClient client, AzureKeyVaultPepperOptions options, CancellationToken cancellationToken = default) =>
            CreateWithClockAsync(client, options, () => DateTimeOffset.UtcNow, cancellationToken);

        /// <summary>Synchronous <see cref="CreateAsync"/>, for startup code that cannot await. Blocks on the initial load.</summary>
        /// <exception cref="ArgumentNullException"><paramref name="client"/> or <paramref name="options"/> is null.</exception>
        /// <exception cref="ArgumentException">The options are invalid.</exception>
        /// <exception cref="PepperUnavailableException">The keys could not be loaded.</exception>
        public static AzureKeyVaultPepper Create(SecretClient client, AzureKeyVaultPepperOptions options)
        {
            var pepper = new AzureKeyVaultPepper(client, options, () => DateTimeOffset.UtcNow);
            Task.Run(() => pepper.RefreshCoreAsync(initial: true, CancellationToken.None)).GetAwaiter().GetResult();
            return pepper;
        }

        internal static Task<AzureKeyVaultPepper> CreateWithClockAsync(SecretClient client, AzureKeyVaultPepperOptions options, Func<DateTimeOffset> clock, CancellationToken cancellationToken)
        {
            var pepper = new AzureKeyVaultPepper(client, options, clock);
            return InitializeAsync(pepper, cancellationToken);
        }

        private static async Task<AzureKeyVaultPepper> InitializeAsync(AzureKeyVaultPepper pepper, CancellationToken cancellationToken)
        {
            await pepper.RefreshCoreAsync(initial: true, cancellationToken).ConfigureAwait(false);
            return pepper;
        }

        /// <inheritdoc />
        /// <exception cref="PepperUnavailableException">
        /// Key Vault reported no usable current key: the pinned version was disabled or deleted, or no enabled version is
        /// active and unexpired. New hashes cannot be written until this is fixed.
        /// </exception>
        public string CurrentKeyId
        {
            get
            {
                MaybeRefreshInBackground();
                Snapshot snapshot = Volatile.Read(ref _snapshot);
                if (snapshot.CurrentKeyId == null)
                    throw new PepperUnavailableException(snapshot.Problems[0].Message);
                return snapshot.CurrentKeyId;
            }
        }

        /// <summary>The pepper key ids currently loaded, newest first in versions mode.</summary>
        public IReadOnlyList<string> KeyIds => Volatile.Read(ref _snapshot).KeyIds;

        /// <summary>When the keys were last loaded successfully.</summary>
        public DateTimeOffset LastRefreshed => Volatile.Read(ref _snapshot).LoadedAt;

        /// <summary>The error of the most recent refresh if it failed, otherwise null. Never contains key material.</summary>
        public Exception? LastRefreshError => Volatile.Read(ref _lastRefreshError);

        /// <summary>The most recent background refresh, for tests.</summary>
        internal Task? BackgroundRefresh { get; private set; }

        /// <inheritdoc />
        /// <remarks>Checks the cached key ring; makes no network call.</remarks>
        public bool IsKnownKey(string keyId)
        {
            MaybeRefreshInBackground();
            HmacPepper? pepper = Volatile.Read(ref _snapshot).Pepper;
            return keyId != null && pepper != null && pepper.IsKnownKey(keyId);
        }

        /// <inheritdoc />
        /// <remarks>HMAC-SHA256 computed locally with the cached key.</remarks>
        /// <exception cref="KeyNotFoundException"><paramref name="keyId"/> is not loaded.</exception>
        public byte[] Apply(string keyId, byte[] input)
        {
            if (input == null) throw new ArgumentNullException(nameof(input));
            MaybeRefreshInBackground();
            Snapshot snapshot = Volatile.Read(ref _snapshot);
            HmacPepper? pepper = snapshot.Pepper;
            if (keyId != null && (pepper == null || !pepper.IsKnownKey(keyId)))
            {
                // A refresh may have removed the key after the caller's IsKnownKey or CurrentKeyId check.
                HmacPepper? retired = snapshot.Retired;
                if (retired != null && retired.IsKnownKey(keyId) && _clock() - snapshot.LoadedAt <= RemovedKeyGrace)
                    pepper = retired;
            }
            if (pepper == null)
                throw new KeyNotFoundException($"Unknown pepper key '{keyId}'.");
            return pepper.Apply(keyId!, input); // HmacPepper throws KeyNotFoundException for null or unknown ids.
        }

        /// <inheritdoc />
        /// <remarks>Completes synchronously: the HMAC is computed locally with the cached key.</remarks>
        /// <exception cref="KeyNotFoundException"><paramref name="keyId"/> is not loaded.</exception>
        public ValueTask<byte[]> ApplyAsync(string keyId, byte[] input, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return new ValueTask<byte[]>(Apply(keyId, input));
        }

        /// <summary>
        /// Versions mode: re-reads the version list now, loads new versions and drops disabled or deleted ones.
        /// If Key Vault cannot be reached, the cached keys stay in use. If it answers, the answer is applied even when
        /// it leaves no usable current key or some versions had to be skipped. That degraded state is then also
        /// reported by throwing. Map mode: does nothing (keys are loaded once).
        /// </summary>
        /// <exception cref="PepperUnavailableException">
        /// Key Vault could not be reached (cached keys kept), or the applied result has problems: no usable current key,
        /// or skipped versions.
        /// </exception>
        public Task RefreshAsync(CancellationToken cancellationToken = default)
        {
            if (_map != null)
                return Task.CompletedTask;
            return RefreshCoreAsync(initial: false, cancellationToken);
        }

        private void MaybeRefreshInBackground()
        {
            if (_clock().UtcTicks < Volatile.Read(ref _nextRefreshUtcTicks))
                return;
            if (Interlocked.CompareExchange(ref _backgroundRefreshing, 1, 0) != 0)
                return;

            BackgroundRefresh = Task.Run(async () =>
            {
                try
                {
                    await RefreshCoreAsync(initial: false, CancellationToken.None).ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    try
                    {
                        _onRefreshFailed?.Invoke(ex);
                    }
                    catch (Exception)
                    {
                        // A failing logging callback must not crash the process.
                    }
                }
                finally
                {
                    Volatile.Write(ref _backgroundRefreshing, 0);
                }
            });
        }

        private async Task RefreshCoreAsync(bool initial, CancellationToken cancellationToken)
        {
            await _refreshLock.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                Snapshot next;
                try
                {
                    next = await LoadWithTimeoutAsync(cancellationToken).ConfigureAwait(false);
                }
                catch (Exception ex) when (!initial && !(ex is OperationCanceledException && cancellationToken.IsCancellationRequested))
                {
                    Volatile.Write(ref _lastRefreshError, ex);
                    Schedule(_refreshInterval < FailedRefreshRetry ? _refreshInterval : FailedRefreshRetry);
                    throw;
                }

                if (initial && next.CurrentKeyId == null)
                    throw Combine(next.Problems);

                // Snapshot is null only before the initial load.
                next.Retired = Volatile.Read(ref _snapshot)?.Pepper;
                Volatile.Write(ref _snapshot, next);

                PepperUnavailableException? problem = next.Problems.Count == 0 ? null : Combine(next.Problems);
                Volatile.Write(ref _lastRefreshError, problem);
                Schedule(problem == null || _refreshInterval < FailedRefreshRetry ? _refreshInterval : FailedRefreshRetry);
                if (problem != null && !initial)
                    throw problem;
            }
            finally
            {
                _refreshLock.Release();
            }
        }

        private void Schedule(TimeSpan delay)
        {
            long next = long.MaxValue;
            if (_map == null && delay != Timeout.InfiniteTimeSpan)
            {
                long now = _clock().UtcTicks;
                next = now > long.MaxValue - delay.Ticks ? long.MaxValue : now + delay.Ticks;
            }
            Volatile.Write(ref _nextRefreshUtcTicks, next);
        }

        private async Task<Snapshot> LoadWithTimeoutAsync(CancellationToken cancellationToken)
        {
            using (var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
            {
                timeout.CancelAfter(_timeout);
                try
                {
                    return _map != null
                        ? await LoadMapAsync(timeout.Token).ConfigureAwait(false)
                        : await LoadVersionsAsync(timeout.Token).ConfigureAwait(false);
                }
                catch (PepperUnavailableException)
                {
                    throw;
                }
                catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
                {
                    throw new PepperUnavailableException("Azure Key Vault did not answer within the configured timeout.");
                }
                catch (OperationCanceledException)
                {
                    throw;
                }
                catch (RequestFailedException ex)
                {
                    throw new PepperUnavailableException(
                        "Azure Key Vault request failed (HTTP " + ex.Status.ToString(CultureInfo.InvariantCulture) + ", " + SafeCode(ex.ErrorCode) + ").", ex);
                }
                catch (Exception ex)
                {
                    throw new PepperUnavailableException("Loading pepper keys from Azure Key Vault failed.", ex);
                }
            }
        }

        private async Task<Snapshot> LoadVersionsAsync(CancellationToken ct)
        {
            var problems = new List<PepperUnavailableException>();
            PepperUnavailableException? secretGone = null;
            var enabled = new List<SecretProperties>();
            try
            {
                await foreach (SecretProperties properties in _client.GetPropertiesOfSecretVersionsAsync(_secretName!, ct).ConfigureAwait(false))
                {
                    if (properties != null && properties.Enabled == true)
                        enabled.Add(properties);
                }
            }
            catch (RequestFailedException ex) when (ex.Status == 404)
            {
                // Authoritative answer: the secret itself is gone, so every version is revoked.
                enabled.Clear();
                secretGone = new PepperUnavailableException(
                    $"Azure Key Vault request failed (HTTP 404, {SafeCode(ex.ErrorCode)}): secret '{_secretName}' was not found.", ex);
            }

            enabled.Sort((a, b) =>
            {
                int byDate = (b.CreatedOn ?? DateTimeOffset.MinValue).CompareTo(a.CreatedOn ?? DateTimeOffset.MinValue);
                return byDate != 0 ? byDate : string.CompareOrdinal(b.Version, a.Version);
            });
            if (enabled.Count > _maxVersions)
                enabled.RemoveRange(_maxVersions, enabled.Count - _maxVersions);

            var ring = new Dictionary<string, byte[]>(StringComparer.Ordinal);
            var ids = new List<string>(enabled.Count);
            var usable = new List<SecretProperties>(enabled.Count);
            foreach (SecretProperties properties in enabled)
            {
                string? version = properties.Version;
                if (version == null || !HashPrimitives.IsValidKeyId(version))
                {
                    problems.Add(new PepperUnavailableException($"Secret '{_secretName}' has a version id that is not a valid pepper key id; it was skipped."));
                    continue;
                }

                if (!_versionCache.TryGetValue(version, out byte[]? key))
                {
                    try
                    {
                        Response<KeyVaultSecret> response = await _client.GetSecretAsync(_secretName!, version, ct).ConfigureAwait(false);
                        key = DecodeKey(response?.Value?.Value, $"Secret '{_secretName}' version '{version}'");
                    }
                    catch (PepperUnavailableException ex)
                    {
                        // Unusable value: no instance can have used this version, so skipping it is safe.
                        problems.Add(new PepperUnavailableException(ex.Message + " It was skipped."));
                        continue;
                    }
                    catch (RequestFailedException ex) when (ex.Status == 403 || ex.Status == 404)
                    {
                        // Disabled or deleted after it was listed, or not readable by this identity.
                        problems.Add(new PepperUnavailableException(
                            $"Secret '{_secretName}' version '{version}' could not be read (HTTP {ex.Status.ToString(CultureInfo.InvariantCulture)}, {SafeCode(ex.ErrorCode)}); it was skipped.", ex));
                        continue;
                    }
                    _versionCache[version] = key;
                }
                ring[version] = key;
                ids.Add(version);
                usable.Add(properties);
            }

            string? current = null;
            PepperUnavailableException? noCurrent = null;
            if (ring.Count == 0)
            {
                noCurrent = secretGone ?? new PepperUnavailableException(enabled.Count == 0
                    ? $"Secret '{_secretName}' has no enabled versions."
                    : $"Secret '{_secretName}' has no enabled version holding a valid pepper key.");
            }
            else if (_pinnedCurrent != null)
            {
                if (ring.ContainsKey(_pinnedCurrent))
                    current = _pinnedCurrent;
                else
                    noCurrent = new PepperUnavailableException($"CurrentKeyId '{_pinnedCurrent}' is not an enabled, usable version of secret '{_secretName}'.");
            }
            else
            {
                current = SelectCurrent(usable);
                if (current == null)
                    noCurrent = new PepperUnavailableException($"Secret '{_secretName}' has no version that is enabled, active and not expired.");
            }
            if (noCurrent != null)
                problems.Insert(0, noCurrent);

            HmacPepper? pepper = ring.Count == 0 ? null : new HmacPepper(current ?? ids[0], ring);
            var snapshot = new Snapshot(pepper, current, ids.ToArray(), _clock(), problems);

            // Key Vault answered, so its answer is authoritative: forget versions that were disabled, deleted or
            // pushed out by MaxVersions, even when the new ring has no usable current key.
            var stale = new List<string>();
            foreach (string cached in _versionCache.Keys)
            {
                if (!ring.ContainsKey(cached))
                    stale.Add(cached);
            }
            foreach (string version in stale)
            {
                HashPrimitives.Zero(_versionCache[version]);
                _versionCache.Remove(version);
            }

            return snapshot;
        }

        /// <summary>Newest usable version that has passed the activation delay, else the oldest usable one, else null.</summary>
        private string? SelectCurrent(List<SecretProperties> newestFirst)
        {
            DateTimeOffset now = _clock();
            DateTimeOffset activatedBefore = now - _activationDelay;
            SecretProperties? newestActive = null;
            SecretProperties? oldestUsable = null;
            foreach (SecretProperties p in newestFirst)
            {
                bool usable = (p.NotBefore == null || p.NotBefore <= now) && (p.ExpiresOn == null || p.ExpiresOn > now);
                if (!usable)
                    continue;
                if (newestActive == null && (p.CreatedOn ?? DateTimeOffset.MinValue) <= activatedBefore)
                    newestActive = p;
                oldestUsable = p;
            }

            return (newestActive ?? oldestUsable)?.Version;
        }

        private static PepperUnavailableException Combine(IReadOnlyList<PepperUnavailableException> problems)
        {
            if (problems.Count == 1)
                return problems[0];
            return new PepperUnavailableException(
                problems[0].Message + " " + (problems.Count - 1).ToString(CultureInfo.InvariantCulture) + " more problem(s); see InnerException.",
                new AggregateException(problems));
        }

        private async Task<Snapshot> LoadMapAsync(CancellationToken ct)
        {
            var ring = new Dictionary<string, byte[]>(StringComparer.Ordinal);
            try
            {
                foreach (KeyValuePair<string, AzureKeyVaultSecretReference> pair in _map!)
                {
                    AzureKeyVaultSecretReference reference = pair.Value;
                    Response<KeyVaultSecret> response = await _client.GetSecretAsync(reference.Name, reference.Version, ct).ConfigureAwait(false);
                    KeyVaultSecret? secret = response?.Value;
                    if (secret?.Properties != null && secret.Properties.Enabled == false)
                        throw new PepperUnavailableException($"Secret '{reference.Name}' for pepper key id '{pair.Key}' is disabled.");
                    ring[pair.Key] = DecodeKey(secret?.Value, $"Secret '{reference.Name}' for pepper key id '{pair.Key}'");
                }

                string[] ids = new string[ring.Count];
                ring.Keys.CopyTo(ids, 0);
                return new Snapshot(new HmacPepper(_pinnedCurrent!, ring), _pinnedCurrent!, ids, _clock(), Array.Empty<PepperUnavailableException>());
            }
            finally
            {
                // HmacPepper keeps its own copies.
                foreach (byte[] key in ring.Values)
                    HashPrimitives.Zero(key);
            }
        }

        private static byte[] DecodeKey(string? value, string description)
        {
            if (string.IsNullOrEmpty(value) || value!.Length > MaxSecretValueLength)
                throw new PepperUnavailableException($"{description} is empty or too long.");
            byte[] key;
            try
            {
                key = Convert.FromBase64String(value);
            }
            catch (FormatException)
            {
                throw new PepperUnavailableException($"{description} is not valid base64.");
            }
            if (key.Length < MinKeyLength)
            {
                HashPrimitives.Zero(key);
                throw new PepperUnavailableException($"{description} must decode to at least {MinKeyLength} bytes.");
            }
            return key;
        }

        private static string SafeCode(string? code)
        {
            if (string.IsNullOrEmpty(code))
                return "no error code";
            foreach (char c in code!)
            {
                bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-';
                if (!ok)
                    return "invalid error code";
            }
            return code.Length > 64 ? code.Substring(0, 64) : code;
        }

        private sealed class Snapshot
        {
            public Snapshot(HmacPepper? pepper, string? currentKeyId, string[] keyIds, DateTimeOffset loadedAt, IReadOnlyList<PepperUnavailableException> problems)
            {
                Pepper = pepper;
                CurrentKeyId = currentKeyId;
                KeyIds = keyIds;
                LoadedAt = loadedAt;
                Problems = problems;
            }

            /// <summary>Key ring; null when Key Vault reported no usable version.</summary>
            public HmacPepper? Pepper { get; }

            /// <summary>Current key id; null when none can be chosen, and then <see cref="Problems"/>[0] says why.</summary>
            public string? CurrentKeyId { get; }

            public IReadOnlyList<string> KeyIds { get; }

            public DateTimeOffset LoadedAt { get; }

            /// <summary>Problems found by the load that produced this snapshot. The snapshot was applied anyway.</summary>
            public IReadOnlyList<PepperUnavailableException> Problems { get; }

            /// <summary>The ring this snapshot replaced, used within <see cref="RemovedKeyGrace"/>. Set before publishing.</summary>
            public HmacPepper? Retired { get; set; }
        }
    }
}
