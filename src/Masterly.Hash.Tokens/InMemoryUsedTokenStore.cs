using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace Masterly.Hash.Tokens
{
    /// <summary>
    /// Thread-safe in-process <see cref="IUsedTokenStore"/>. Entries are purged some time after they expire.
    /// Use it for single-instance applications and tests; a web farm needs a shared store.
    /// </summary>
    /// <remarks>
    /// Only tokens with a valid signature reach the store, so its size is bounded by the number of tokens the
    /// application issues within their lifetime.
    /// </remarks>
    public sealed class InMemoryUsedTokenStore : IUsedTokenStore
    {
        /// <summary>
        /// How long past its <c>retainUntil</c> an entry is kept, as margin against a token that was validated just
        /// before expiry and recorded just after.
        /// </summary>
        public static readonly TimeSpan PurgeGrace = TimeSpan.FromMinutes(5);

        private const int PurgeEvery = 256;

        private readonly ConcurrentDictionary<string, DateTimeOffset> _used =
            new ConcurrentDictionary<string, DateTimeOffset>(StringComparer.Ordinal);
        private readonly Func<DateTimeOffset> _clock;
        private int _operations;

        /// <summary>Creates a store. <paramref name="clock"/> defaults to <see cref="DateTimeOffset.UtcNow"/>.</summary>
        public InMemoryUsedTokenStore(Func<DateTimeOffset>? clock = null)
        {
            _clock = clock ?? (() => DateTimeOffset.UtcNow);
        }

        /// <summary>Number of nonces currently recorded.</summary>
        public int Count => _used.Count;

        /// <summary>Synchronous form of <see cref="TryMarkUsedAsync"/>.</summary>
        public bool TryMarkUsed(string nonce, DateTimeOffset retainUntil)
        {
            if (nonce == null) throw new ArgumentNullException(nameof(nonce));
            if (Interlocked.Increment(ref _operations) % PurgeEvery == 0)
                Purge();
            return _used.TryAdd(nonce, retainUntil);
        }

        /// <inheritdoc />
        public ValueTask<bool> TryMarkUsedAsync(string nonce, DateTimeOffset retainUntil, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return new ValueTask<bool>(TryMarkUsed(nonce, retainUntil));
        }

        /// <summary>True if <paramref name="nonce"/> is recorded.</summary>
        public bool Contains(string nonce) => nonce != null && _used.ContainsKey(nonce);

        /// <summary>Removes entries older than their <c>retainUntil</c> plus <see cref="PurgeGrace"/>.</summary>
        public void Purge()
        {
            DateTimeOffset cutoff = _clock() - PurgeGrace;
            foreach (KeyValuePair<string, DateTimeOffset> entry in _used)
            {
                if (entry.Value < cutoff)
                    _used.TryRemove(entry.Key, out _);
            }
        }
    }
}
