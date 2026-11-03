using System;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;

namespace Masterly.Hash.Detection
{
    /// <summary>
    /// Reference <see cref="IHoneychecker"/> that keeps indexes in process memory. For tests, demos and as a model
    /// for a real implementation only.
    /// </summary>
    /// <remarks>
    /// <b>Do not use in production.</b> The whole point of a honeychecker is that it lives outside the application
    /// that holds the password hashes: a separate hardened service with its own storage, credentials and alerting,
    /// reachable only through the two calls of <see cref="IHoneychecker"/>. An in-process honeychecker falls to the
    /// same breach as the database and loses its state on restart.
    /// </remarks>
    public sealed class InMemoryHoneychecker : IHoneychecker
    {
        private readonly ConcurrentDictionary<string, int> _indexes = new ConcurrentDictionary<string, int>(StringComparer.Ordinal);

        /// <summary>Number of users with a recorded index.</summary>
        public int Count => _indexes.Count;

        /// <inheritdoc />
        public Task SetAsync(string userId, int index, CancellationToken cancellationToken = default)
        {
            if (userId == null) throw new ArgumentNullException(nameof(userId));
            if (index < 0) throw new ArgumentOutOfRangeException(nameof(index), index, "Index cannot be negative.");
            cancellationToken.ThrowIfCancellationRequested();
            _indexes[userId] = index;
            return Task.CompletedTask;
        }

        /// <inheritdoc />
        public Task<bool> IsRealAsync(string userId, int index, CancellationToken cancellationToken = default)
        {
            if (userId == null) throw new ArgumentNullException(nameof(userId));
            cancellationToken.ThrowIfCancellationRequested();
            bool real = _indexes.TryGetValue(userId, out int stored) && stored == index && index >= 0;
            return Task.FromResult(real);
        }

        /// <summary>Forgets a user (e.g. on account deletion).</summary>
        public bool Remove(string userId)
        {
            if (userId == null) throw new ArgumentNullException(nameof(userId));
            return _indexes.TryRemove(userId, out _);
        }
    }
}
