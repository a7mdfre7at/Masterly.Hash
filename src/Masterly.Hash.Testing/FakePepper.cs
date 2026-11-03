using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Masterly.Hash.Pepper;
using Masterly.Hash.Primitives;

namespace Masterly.Hash.Testing
{
    /// <summary>
    /// A deterministic, instrumented <see cref="IPasswordPepper"/> for tests. Each key id maps to a fixed key derived
    /// from the id itself (<see cref="KeyFor"/>), so two <see cref="FakePepper"/> instances with the same key ids are
    /// interchangeable: a hash made with one verifies with the other.
    /// </summary>
    /// <remarks>
    /// <para><b>NEVER USE THIS IN PRODUCTION.</b> The keys are public (derived from the key id), so it adds no secrecy.</para>
    /// <para>
    /// The transform is HMAC-SHA256, like <see cref="HmacPepper"/>. Calls are counted separately for the synchronous and
    /// asynchronous paths; <see cref="AsyncDelay"/> and <see cref="ForceAsynchronous"/> simulate a remote key service, and
    /// <see cref="ThrowOnApply"/> simulates an outage. Thread-safe.
    /// </para>
    /// </remarks>
    public sealed class FakePepper : IPasswordPepper
    {
        /// <summary>Key id used by the parameterless constructor.</summary>
        public const string DefaultKeyId = "test-key";

        private const string KeyDomain = "Masterly.Hash.Testing.FakePepper/";

        private readonly object _sync = new object();
        private readonly HashSet<string> _keys = new HashSet<string>(StringComparer.Ordinal);
        private readonly List<string> _keyIdsUsed = new List<string>();
        private string _currentKeyId;
        private int _applyCount;
        private int _applyAsyncCount;

        /// <summary>Creates a pepper with the single key <see cref="DefaultKeyId"/>.</summary>
        public FakePepper()
            : this(DefaultKeyId)
        {
        }

        /// <summary>Creates a pepper whose current key is <paramref name="currentKeyId"/>, also accepting <paramref name="otherKeyIds"/>.</summary>
        /// <param name="currentKeyId">Key id for new hashes. Must match <c>^[A-Za-z0-9-]{1,32}$</c>.</param>
        /// <param name="otherKeyIds">Additional (for example retired) key ids that still verify.</param>
        /// <exception cref="ArgumentException">A key id is invalid.</exception>
        public FakePepper(string currentKeyId, params string[] otherKeyIds)
        {
            ValidateKeyId(currentKeyId, nameof(currentKeyId));
            _keys.Add(currentKeyId);
            if (otherKeyIds != null)
            {
                foreach (string keyId in otherKeyIds)
                {
                    ValidateKeyId(keyId, nameof(otherKeyIds));
                    _keys.Add(keyId);
                }
            }
            _currentKeyId = currentKeyId;
        }

        /// <inheritdoc />
        public string CurrentKeyId
        {
            get
            {
                lock (_sync)
                    return _currentKeyId;
            }
        }

        /// <summary>All key ids this pepper accepts.</summary>
        public IReadOnlyCollection<string> KeyIds
        {
            get
            {
                lock (_sync)
                    return new List<string>(_keys);
            }
        }

        /// <summary>Number of synchronous <see cref="Apply"/> calls.</summary>
        public int ApplyCount => Volatile.Read(ref _applyCount);

        /// <summary>Number of <see cref="ApplyAsync"/> calls.</summary>
        public int ApplyAsyncCount => Volatile.Read(ref _applyAsyncCount);

        /// <summary>The key id passed to each <see cref="Apply"/>/<see cref="ApplyAsync"/> call, in call order.</summary>
        public IReadOnlyList<string> KeyIdsUsed
        {
            get
            {
                lock (_sync)
                    return _keyIdsUsed.ToArray();
            }
        }

        /// <summary>If positive, <see cref="ApplyAsync"/> waits this long (honouring cancellation) before returning.</summary>
        public TimeSpan AsyncDelay { get; set; }

        /// <summary>If true, <see cref="ApplyAsync"/> always completes asynchronously (yields), like a network call.</summary>
        public bool ForceAsynchronous { get; set; }

        /// <summary>If set, both <see cref="Apply"/> and <see cref="ApplyAsync"/> throw this exception, simulating an outage.</summary>
        public Exception? ThrowOnApply { get; set; }

        /// <summary>The fixed 32-byte key used for <paramref name="keyId"/>: SHA-256 of a domain string and the id. Not secret.</summary>
        /// <param name="keyId">The key id.</param>
        /// <returns>A new array holding the key.</returns>
        public static byte[] KeyFor(string keyId)
        {
            if (keyId == null) throw new ArgumentNullException(nameof(keyId));
            using (SHA256 sha = SHA256.Create())
                return sha.ComputeHash(Encoding.UTF8.GetBytes(KeyDomain + keyId));
        }

        /// <inheritdoc />
        public bool IsKnownKey(string keyId)
        {
            if (keyId == null)
                return false;
            lock (_sync)
                return _keys.Contains(keyId);
        }

        /// <summary>Adds a key id that will be accepted from now on.</summary>
        /// <param name="keyId">Key id to accept.</param>
        public void AddKey(string keyId)
        {
            ValidateKeyId(keyId, nameof(keyId));
            lock (_sync)
                _keys.Add(keyId);
        }

        /// <summary>Makes <paramref name="keyId"/> the current key (adding it if needed). Older keys keep verifying.</summary>
        /// <param name="keyId">New current key id.</param>
        public void RotateTo(string keyId)
        {
            ValidateKeyId(keyId, nameof(keyId));
            lock (_sync)
            {
                _keys.Add(keyId);
                _currentKeyId = keyId;
            }
        }

        /// <summary>Stops accepting <paramref name="keyId"/>; hashes made with it then fail with <see cref="VerificationFailureReason.UnknownPepperKey"/>.</summary>
        /// <param name="keyId">Key id to retire.</param>
        /// <returns>True if the key was known.</returns>
        /// <exception cref="InvalidOperationException"><paramref name="keyId"/> is the current key.</exception>
        public bool RetireKey(string keyId)
        {
            if (keyId == null) throw new ArgumentNullException(nameof(keyId));
            lock (_sync)
            {
                if (string.Equals(keyId, _currentKeyId, StringComparison.Ordinal))
                    throw new InvalidOperationException("The current key cannot be retired; rotate to another key first.");
                return _keys.Remove(keyId);
            }
        }

        /// <summary>Resets <see cref="ApplyCount"/>, <see cref="ApplyAsyncCount"/> and <see cref="KeyIdsUsed"/>.</summary>
        public void ResetCounters()
        {
            lock (_sync)
            {
                _keyIdsUsed.Clear();
                Volatile.Write(ref _applyCount, 0);
                Volatile.Write(ref _applyAsyncCount, 0);
            }
        }

        /// <inheritdoc />
        public byte[] Apply(string keyId, byte[] input)
        {
            Interlocked.Increment(ref _applyCount);
            return Compute(keyId, input);
        }

        /// <inheritdoc />
        public async ValueTask<byte[]> ApplyAsync(string keyId, byte[] input, CancellationToken cancellationToken = default)
        {
            Interlocked.Increment(ref _applyAsyncCount);
            cancellationToken.ThrowIfCancellationRequested();
            TimeSpan delay = AsyncDelay;
            if (delay > TimeSpan.Zero)
                await Task.Delay(delay, cancellationToken).ConfigureAwait(false);
            else if (ForceAsynchronous)
                // A timer, not Task.Yield: a yielded continuation can finish on the thread pool before the caller
                // even inspects the returned task, so "always completes asynchronously" would not hold under load.
                await Task.Delay(1, cancellationToken).ConfigureAwait(false);
            return Compute(keyId, input);
        }

        private byte[] Compute(string keyId, byte[] input)
        {
            if (input == null) throw new ArgumentNullException(nameof(input));
            lock (_sync)
            {
                if (keyId != null)
                    _keyIdsUsed.Add(keyId);
            }

            Exception? failure = ThrowOnApply;
            if (failure != null)
                throw failure;
            if (keyId == null || !IsKnownKey(keyId))
                throw new KeyNotFoundException($"Unknown pepper key '{keyId}'.");

            byte[] key = KeyFor(keyId);
            try
            {
                using (var hmac = new HMACSHA256(key))
                    return hmac.ComputeHash(input);
            }
            finally
            {
                HashPrimitives.Zero(key);
            }
        }

        internal static bool IsValidKeyId(string? keyId) => keyId != null && HashPrimitives.IsValidKeyId(keyId);

        private static void ValidateKeyId(string keyId, string paramName)
        {
            if (keyId == null) throw new ArgumentNullException(paramName);
            if (!IsValidKeyId(keyId))
                throw new ArgumentException("Key id must match ^[A-Za-z0-9-]{1,32}$.", paramName);
        }
    }
}
