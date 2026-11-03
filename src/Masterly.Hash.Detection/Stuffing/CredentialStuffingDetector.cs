using System;
using System.Collections.Generic;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Masterly.Hash.Detection.Internal;
using Masterly.Hash.Primitives;

namespace Masterly.Hash.Detection
{
    /// <summary>
    /// Detects credential stuffing and password spraying: the same wrong password failing against many distinct
    /// accounts in a short time. Neither passwords nor account names are retained, only
    /// <c>HMAC-SHA256(windowKey, password)</c> truncated to 128 bits (and a 64-bit HMAC of each account name under a
    /// second key). Both keys are random per window and are zeroed when the window ends, after which the recorded
    /// fingerprints can no longer be reversed by dictionary attack or correlated with later ones.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Windows are fixed (tumbling): a new window starts on the first call after the previous one ends. An attack
    /// that straddles a boundary is counted in two halves, so an attacker who knows the window can stay just under
    /// the threshold; keep the window long and the threshold low enough for your traffic.
    /// </para>
    /// <para>
    /// Memory is bounded by <see cref="CredentialStuffingOptions.MaxTrackedFingerprints"/>; beyond it the least
    /// recently seen fingerprint is evicted (O(1)). A flood of unique garbage passwords can therefore evict a tracked
    /// fingerprint, and a fingerprint flagged, evicted and seen again is reported again. Both
    /// <see cref="RecordFailedLogin(string, string)"/> and a positive <see cref="IsFlagged"/> mark a fingerprint as
    /// recently seen, so a password that keeps being sprayed stays flagged. While a window is open its
    /// keys are in process memory, so a memory dump taken during the window allows guessing the passwords behind
    /// that window's fingerprints. Thread-safe.
    /// </para>
    /// </remarks>
    public sealed class CredentialStuffingDetector : IDisposable
    {
        /// <summary>Length in bytes of a password fingerprint (truncated HMAC-SHA256).</summary>
        public const int FingerprintLength = 16;

        private readonly object _lock = new object();
        private readonly TimeSpan _window;
        private readonly int _threshold;
        private readonly int _maxFingerprints;
        private readonly int _maxPasswordLength;
        private readonly int _maxAccountLength;
        private readonly Func<DateTimeOffset> _clock;
        private readonly Dictionary<FingerprintKey, LinkedListNode<Entry>> _entries = new Dictionary<FingerprintKey, LinkedListNode<Entry>>();
        private readonly LinkedList<Entry> _lru = new LinkedList<Entry>();
        private Generation? _generation;
        private long _evicted;
        private bool _disposed;

        /// <summary>Creates a detector with the default options.</summary>
        public CredentialStuffingDetector()
            : this(new CredentialStuffingOptions())
        {
        }

        /// <summary>Creates a detector. The options are copied.</summary>
        public CredentialStuffingDetector(CredentialStuffingOptions options)
        {
            if (options == null) throw new ArgumentNullException(nameof(options));
            if (options.Window < TimeSpan.FromSeconds(1) || options.Window > TimeSpan.FromDays(1))
                throw new ArgumentOutOfRangeException(nameof(options), options.Window, "Window must be between 1 second and 1 day.");
            if (options.DistinctAccountThreshold < 2 || options.DistinctAccountThreshold > 10_000)
                throw new ArgumentOutOfRangeException(nameof(options), options.DistinctAccountThreshold, "DistinctAccountThreshold must be between 2 and 10000.");
            if (options.MaxTrackedFingerprints < 1 || options.MaxTrackedFingerprints > 10_000_000)
                throw new ArgumentOutOfRangeException(nameof(options), options.MaxTrackedFingerprints, "MaxTrackedFingerprints must be between 1 and 10000000.");
            if (options.MaxPasswordLength < 1 || options.MaxPasswordLength > 1024 * 1024)
                throw new ArgumentOutOfRangeException(nameof(options), options.MaxPasswordLength, "MaxPasswordLength must be between 1 and 1048576.");
            if (options.MaxAccountLength < 1 || options.MaxAccountLength > 1024 * 1024)
                throw new ArgumentOutOfRangeException(nameof(options), options.MaxAccountLength, "MaxAccountLength must be between 1 and 1048576.");

            _window = options.Window;
            _threshold = options.DistinctAccountThreshold;
            _maxFingerprints = options.MaxTrackedFingerprints;
            _maxPasswordLength = options.MaxPasswordLength;
            _maxAccountLength = options.MaxAccountLength;
            _clock = options.Clock ?? (() => DateTimeOffset.UtcNow);
        }

        /// <summary>
        /// Raised once per fingerprint per window when it reaches the threshold. Raised outside the detector's lock,
        /// on the thread that recorded the failure; exceptions thrown by handlers propagate to that caller.
        /// </summary>
        public event EventHandler<CredentialStuffingDetectedEventArgs>? StuffingDetected;

        /// <summary>Distinct-account threshold.</summary>
        public int DistinctAccountThreshold => _threshold;

        /// <summary>Window length.</summary>
        public TimeSpan Window => _window;

        /// <summary>Number of fingerprints tracked in the current window.</summary>
        public int TrackedFingerprintCount
        {
            get
            {
                lock (_lock)
                {
                    CurrentGeneration();
                    return _entries.Count;
                }
            }
        }

        /// <summary>Fingerprints evicted because of <see cref="CredentialStuffingOptions.MaxTrackedFingerprints"/>, since creation.</summary>
        public long EvictedCount
        {
            get
            {
                lock (_lock)
                    return _evicted;
            }
        }

        /// <summary>Start of the current window.</summary>
        public DateTimeOffset WindowStart
        {
            get
            {
                lock (_lock)
                    return CurrentGeneration().Start;
            }
        }

        /// <summary>
        /// Records a failed login. Returns true if this password is flagged as being stuffed in the current window
        /// (the threshold has been reached, by this call or earlier), so the caller can add friction such as a
        /// CAPTCHA or a block. Passwords longer than <see cref="CredentialStuffingOptions.MaxPasswordLength"/> and
        /// accounts longer than <see cref="CredentialStuffingOptions.MaxAccountLength"/> are ignored (nothing is
        /// recorded and false is returned) before any normalization.
        /// </summary>
        public bool RecordFailedLogin(string account, string password)
        {
            if (account == null) throw new ArgumentNullException(nameof(account));
            if (password == null) throw new ArgumentNullException(nameof(password));
            if (password.Length > _maxPasswordLength || account.Length > _maxAccountLength)
                return false;

            CredentialStuffingDetectedEventArgs? detected = null;
            bool flagged;
            while (true)
            {
                Generation generation;
                lock (_lock)
                    generation = CurrentGeneration();

                // HMACs are computed outside the lock; if the window rotates meanwhile, retry under the new keys.
                FingerprintKey fingerprint = PasswordFingerprint(generation, password);
                ulong accountTag = AccountTag(generation, account);

                lock (_lock)
                {
                    if (!ReferenceEquals(CurrentGeneration(), generation))
                        continue;

                    Entry entry = Touch(fingerprint);
                    if (!entry.Flagged && entry.Accounts!.Add(accountTag) && entry.Accounts.Count >= _threshold)
                    {
                        entry.Flagged = true;
                        entry.Count = entry.Accounts.Count;
                        entry.Accounts = null;
                        detected = new CredentialStuffingDetectedEventArgs(
                            fingerprint.ToString(), entry.Count, generation.Start, generation.End, _clock());
                    }
                    flagged = entry.Flagged;
                }
                break;
            }

            if (detected != null)
                StuffingDetected?.Invoke(this, detected);
            return flagged;
        }

        /// <summary>Records a failed login.</summary>
        public bool RecordFailedLogin(string account, SensitiveString password)
        {
            if (password == null) throw new ArgumentNullException(nameof(password));
            return RecordFailedLogin(account, password.Reveal());
        }

        /// <summary>
        /// True if <paramref name="password"/> has been flagged in the current window. Use it before verifying a login
        /// to slow down or block a password that is being sprayed. Does not record a failure, but a flagged
        /// fingerprint is marked as recently seen, so callers that block flagged passwords without recording them
        /// keep it from being evicted by other traffic for as long as the spraying continues.
        /// </summary>
        public bool IsFlagged(string password)
        {
            if (password == null) throw new ArgumentNullException(nameof(password));
            if (password.Length > _maxPasswordLength)
                return false;

            while (true)
            {
                Generation generation;
                lock (_lock)
                    generation = CurrentGeneration();

                FingerprintKey fingerprint = PasswordFingerprint(generation, password);
                lock (_lock)
                {
                    if (!ReferenceEquals(CurrentGeneration(), generation))
                        continue;
                    if (!_entries.TryGetValue(fingerprint, out LinkedListNode<Entry>? node) || !node.Value.Flagged)
                        return false;
                    MoveToFront(node);
                    return true;
                }
            }
        }

        /// <summary>The fingerprints tracked in the current window, most recently seen first. Contains no secrets.</summary>
        public IReadOnlyList<FingerprintStatistics> GetSnapshot()
        {
            lock (_lock)
            {
                CurrentGeneration();
                var result = new List<FingerprintStatistics>(_entries.Count);
                foreach (Entry entry in _lru)
                {
                    int count = entry.Flagged ? entry.Count : entry.Accounts!.Count;
                    result.Add(new FingerprintStatistics(entry.Key.ToString(), count, entry.Flagged));
                }
                return result;
            }
        }

        /// <summary>Ends the current window immediately: discards all counts and zeroes the keys.</summary>
        public void Reset()
        {
            lock (_lock)
            {
                ThrowIfDisposed();
                EndGeneration();
            }
        }

        /// <summary>Zeroes the keys and discards all state.</summary>
        public void Dispose()
        {
            lock (_lock)
            {
                if (_disposed)
                    return;
                EndGeneration();
                _disposed = true;
            }
        }

        /// <summary>Returns the live generation, rotating it if the window has ended. Caller holds the lock.</summary>
        private Generation CurrentGeneration()
        {
            ThrowIfDisposed();
            DateTimeOffset now = _clock();
            if (_generation != null && now < _generation.End)
                return _generation;

            EndGeneration();
            _generation = new Generation(HashPrimitives.RandomBytes(32), HashPrimitives.RandomBytes(32), now, now + _window);
            return _generation;
        }

        private void EndGeneration()
        {
            if (_generation != null)
            {
                HashPrimitives.Zero(_generation.PasswordKey);
                HashPrimitives.Zero(_generation.AccountKey);
                _generation = null;
            }
            _entries.Clear();
            _lru.Clear();
        }

        /// <summary>Finds or creates the entry and marks it most recently used, evicting the oldest if full. Caller holds the lock.</summary>
        private Entry Touch(FingerprintKey fingerprint)
        {
            if (_entries.TryGetValue(fingerprint, out LinkedListNode<Entry>? node))
            {
                MoveToFront(node);
                return node.Value;
            }

            if (_entries.Count >= _maxFingerprints)
            {
                LinkedListNode<Entry> oldest = _lru.Last!;
                _lru.RemoveLast();
                _entries.Remove(oldest.Value.Key);
                _evicted++;
            }

            node = _lru.AddFirst(new Entry(fingerprint));
            _entries[fingerprint] = node;
            return node.Value;
        }

        /// <summary>Marks <paramref name="node"/> most recently used. Caller holds the lock.</summary>
        private void MoveToFront(LinkedListNode<Entry> node)
        {
            if (!ReferenceEquals(_lru.First, node))
            {
                _lru.Remove(node);
                _lru.AddFirst(node);
            }
        }

        private static FingerprintKey PasswordFingerprint(Generation generation, string password)
        {
            byte[] encoded = TextNormalization.FingerprintBytes(password);
            byte[] mac = Hmac(generation.PasswordKey, encoded);
            HashPrimitives.Zero(encoded);
            var key = new FingerprintKey(ReadUInt64(mac, 0), ReadUInt64(mac, 8));
            HashPrimitives.Zero(mac);
            return key;
        }

        private static ulong AccountTag(Generation generation, string account)
        {
            byte[] encoded = Encoding.UTF8.GetBytes(TextNormalization.Account(account));
            byte[] mac = Hmac(generation.AccountKey, encoded);
            ulong tag = ReadUInt64(mac, 0);
            HashPrimitives.Zero(mac);
            return tag;
        }

        private static byte[] Hmac(byte[] key, byte[] data)
        {
            return HMACSHA256.HashData(key, data);
        }

        private static ulong ReadUInt64(byte[] bytes, int offset)
        {
            ulong value = 0;
            for (int i = 0; i < 8; i++)
                value = (value << 8) | bytes[offset + i];
            return value;
        }

        private void ThrowIfDisposed()
        {
            if (_disposed)
                throw new ObjectDisposedException(nameof(CredentialStuffingDetector));
        }

        private sealed class Generation
        {
            public Generation(byte[] passwordKey, byte[] accountKey, DateTimeOffset start, DateTimeOffset end)
            {
                PasswordKey = passwordKey;
                AccountKey = accountKey;
                Start = start;
                End = end;
            }

            public byte[] PasswordKey { get; }

            public byte[] AccountKey { get; }

            public DateTimeOffset Start { get; }

            public DateTimeOffset End { get; }
        }

        private sealed class Entry
        {
            public Entry(FingerprintKey key)
            {
                Key = key;
            }

            public FingerprintKey Key { get; }

            /// <summary>Account tags seen; null once flagged (no longer needed).</summary>
            public HashSet<ulong>? Accounts { get; set; } = new HashSet<ulong>();

            public int Count { get; set; }

            public bool Flagged { get; set; }
        }

        private readonly struct FingerprintKey : IEquatable<FingerprintKey>
        {
            private readonly ulong _high;
            private readonly ulong _low;

            public FingerprintKey(ulong high, ulong low)
            {
                _high = high;
                _low = low;
            }

            public bool Equals(FingerprintKey other) => _high == other._high && _low == other._low;

            public override bool Equals(object? obj) => obj is FingerprintKey other && Equals(other);

            // The key is HMAC output under a secret key: uniformly distributed and not attacker-controllable.
            public override int GetHashCode() => (int)_low ^ (int)(_low >> 32);

            public override string ToString() =>
                _high.ToString("x16", CultureInfo.InvariantCulture) + _low.ToString("x16", CultureInfo.InvariantCulture);
        }
    }
}
