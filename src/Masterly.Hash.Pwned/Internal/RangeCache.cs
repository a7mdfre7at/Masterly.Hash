using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace Masterly.Hash.Pwned.Internal
{
    /// <summary>
    /// Thread-safe, size-bounded LRU cache of parsed ranges with a fixed time-to-live, keyed by the uppercase
    /// 5-character prefix. Uses a monotonic clock so wall-clock changes do not extend or cut lifetimes.
    /// </summary>
    internal sealed class RangeCache
    {
        private readonly object _gate = new object();
        private readonly Dictionary<string, LinkedListNode<Entry>> _map = new Dictionary<string, LinkedListNode<Entry>>(StringComparer.Ordinal);
        private readonly LinkedList<Entry> _lru = new LinkedList<Entry>();
        private readonly int _maxEntries;
        private readonly TimeSpan _ttl;
        private readonly Func<TimeSpan> _clock;

        public RangeCache(int maxEntries, TimeSpan ttl, Func<TimeSpan>? clock = null)
        {
            if (maxEntries < 1) throw new ArgumentOutOfRangeException(nameof(maxEntries));
            if (ttl <= TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(ttl));
            _maxEntries = maxEntries;
            _ttl = ttl;
            _clock = clock ?? MonotonicNow;
        }

        /// <summary>Entries currently held, including expired ones not yet removed.</summary>
        public int Count
        {
            get
            {
                lock (_gate)
                    return _map.Count;
            }
        }

        public bool TryGet(string prefix, out RangeResponse? response)
        {
            TimeSpan now = _clock();
            lock (_gate)
            {
                if (_map.TryGetValue(prefix, out LinkedListNode<Entry>? node))
                {
                    if (now < node.Value.ExpiresAt)
                    {
                        _lru.Remove(node);
                        _lru.AddFirst(node);
                        response = node.Value.Response;
                        return true;
                    }
                    _lru.Remove(node);
                    _map.Remove(prefix);
                }
            }
            response = null;
            return false;
        }

        public void Set(string prefix, RangeResponse response)
        {
            var entry = new Entry(prefix, response, _clock() + _ttl);
            lock (_gate)
            {
                if (_map.TryGetValue(prefix, out LinkedListNode<Entry>? existing))
                {
                    _lru.Remove(existing);
                    _map.Remove(prefix);
                }
                while (_map.Count >= _maxEntries && _lru.Last != null)
                {
                    _map.Remove(_lru.Last.Value.Prefix);
                    _lru.RemoveLast();
                }
                _map[prefix] = _lru.AddFirst(entry);
            }
        }

        public void Clear()
        {
            lock (_gate)
            {
                _map.Clear();
                _lru.Clear();
            }
        }

        private static TimeSpan MonotonicNow() =>
            TimeSpan.FromTicks((long)(Stopwatch.GetTimestamp() * ((double)TimeSpan.TicksPerSecond / Stopwatch.Frequency)));

        private sealed class Entry
        {
            public Entry(string prefix, RangeResponse response, TimeSpan expiresAt)
            {
                Prefix = prefix;
                Response = response;
                ExpiresAt = expiresAt;
            }

            public string Prefix { get; }

            public RangeResponse Response { get; }

            public TimeSpan ExpiresAt { get; }
        }
    }
}
