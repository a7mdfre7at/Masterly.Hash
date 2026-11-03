using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Masterly.Hash.Primitives;

namespace Masterly.Hash.Testing
{
    /// <summary>
    /// An <see cref="IPasswordHasher"/> decorator that records every call, so tests can assert how application code
    /// uses the hasher: that it stores <see cref="PasswordVerificationResult.Rehash"/> after login, uses
    /// <see cref="IPasswordHasher.VerifyOrDummy"/> for unknown users, never hashes twice, and so on.
    /// </summary>
    /// <remarks>
    /// Passwords are never recorded. Each call stores a fingerprint: HMAC-SHA256 of the password bytes the hasher sees
    /// (<see cref="HashPrimitives.EncodePassword"/>) under a random key private to this recorder, so a recorded call
    /// that ends up in test output cannot be reversed with a dictionary or rainbow table. Use <see cref="Fingerprint"/>
    /// or <see cref="CallsWithPassword"/> to match calls against a known password. Thread-safe.
    /// </remarks>
    public sealed class RecordingPasswordHasher : IPasswordHasher
    {
        private readonly IPasswordHasher _inner;
        private readonly byte[] _fingerprintKey = HashPrimitives.RandomBytes(32);
        private readonly object _sync = new object();
        private readonly List<PasswordHasherCall> _calls = new List<PasswordHasherCall>();
        private long _sequence;

        /// <summary>Records calls to a new <see cref="FastPasswordHasher"/>.</summary>
        public RecordingPasswordHasher()
            : this(new FastPasswordHasher())
        {
        }

        /// <summary>Records calls to <paramref name="inner"/>.</summary>
        /// <param name="inner">The hasher that does the work.</param>
        public RecordingPasswordHasher(IPasswordHasher inner)
        {
            _inner = inner ?? throw new ArgumentNullException(nameof(inner));
        }

        /// <summary>The decorated hasher.</summary>
        public IPasswordHasher Inner => _inner;

        /// <summary>A snapshot of the recorded calls, ordered by <see cref="PasswordHasherCall.Sequence"/>.</summary>
        public IReadOnlyList<PasswordHasherCall> Calls
        {
            get
            {
                PasswordHasherCall[] snapshot;
                lock (_sync)
                    snapshot = _calls.ToArray();
                Array.Sort(snapshot, (a, b) => a.Sequence.CompareTo(b.Sequence));
                return snapshot;
            }
        }

        /// <summary>The most recently started call that has completed, or null.</summary>
        public PasswordHasherCall? LastCall
        {
            get
            {
                IReadOnlyList<PasswordHasherCall> calls = Calls;
                return calls.Count == 0 ? null : calls[calls.Count - 1];
            }
        }

        /// <summary>Every non-null <see cref="PasswordVerificationResult.Rehash"/> returned by a verify call, in call order.</summary>
        public IReadOnlyList<string> RehashesIssued
        {
            get
            {
                var list = new List<string>();
                foreach (PasswordHasherCall call in Calls)
                {
                    if (call.Result?.Rehash is string rehash)
                        list.Add(rehash);
                }
                return list;
            }
        }

        /// <summary>True if any verify call was made through <see cref="IPasswordHasher.VerifyOrDummy"/> without a stored hash.</summary>
        public bool UsedDummyVerification
        {
            get
            {
                foreach (PasswordHasherCall call in Calls)
                {
                    if (call.Operation == PasswordHasherOperation.VerifyOrDummy && call.StoredHash == null)
                        return true;
                }
                return false;
            }
        }

        /// <summary>Recorded calls of one kind (sync and async).</summary>
        /// <param name="operation">The operation to select.</param>
        /// <returns>The matching calls in call order.</returns>
        public IReadOnlyList<PasswordHasherCall> CallsOf(PasswordHasherOperation operation)
        {
            var list = new List<PasswordHasherCall>();
            foreach (PasswordHasherCall call in Calls)
            {
                if (call.Operation == operation)
                    list.Add(call);
            }
            return list;
        }

        /// <summary>Number of recorded calls of one kind (sync and async).</summary>
        /// <param name="operation">The operation to count.</param>
        /// <returns>The count.</returns>
        public int Count(PasswordHasherOperation operation) => CallsOf(operation).Count;

        /// <summary>Recorded calls that were given <paramref name="password"/>.</summary>
        /// <param name="password">The password to look for.</param>
        /// <returns>The matching calls in call order.</returns>
        public IReadOnlyList<PasswordHasherCall> CallsWithPassword(string password)
        {
            string fingerprint = Fingerprint(password);
            var list = new List<PasswordHasherCall>();
            foreach (PasswordHasherCall call in Calls)
            {
                if (call.PasswordFingerprint != null && FixedTimeEquals(call.PasswordFingerprint, fingerprint))
                    list.Add(call);
            }
            return list;
        }

        /// <summary>
        /// The fingerprint this recorder stores for <paramref name="password"/>: lowercase hex HMAC-SHA256, keyed with a
        /// random per-recorder key, of the NFKC/UTF-8 password bytes. Fingerprints from different recorders differ.
        /// </summary>
        /// <param name="password">The password.</param>
        /// <returns>64 lowercase hex characters.</returns>
        public string Fingerprint(string password)
        {
            if (password == null) throw new ArgumentNullException(nameof(password));
            byte[] encoded = FingerprintBytes(password);
            byte[]? mac = null;
            try
            {
                using (var hmac = new HMACSHA256(_fingerprintKey))
                    mac = hmac.ComputeHash(encoded);
                return ToHex(mac);
            }
            finally
            {
                HashPrimitives.Zero(encoded);
                HashPrimitives.Zero(mac);
            }
        }

        /// <summary>Forgets all recorded calls.</summary>
        public void Clear()
        {
            lock (_sync)
                _calls.Clear();
        }

        /// <inheritdoc />
        public string Hash(string password)
        {
            long seq = Next();
            string? fp = SafeFingerprint(password);
            try
            {
                string hash = _inner.Hash(password);
                Add(new PasswordHasherCall(seq, PasswordHasherOperation.Hash, false, fp, null, null, null, hash, null, null, null));
                return hash;
            }
            catch (Exception ex)
            {
                Add(new PasswordHasherCall(seq, PasswordHasherOperation.Hash, false, fp, null, null, null, null, null, null, ex));
                throw;
            }
        }

        /// <inheritdoc />
        public string Hash(string password, HashProfile profile)
        {
            long seq = Next();
            string? fp = SafeFingerprint(password);
            string? profileId = profile?.Id;
            try
            {
                string hash = _inner.Hash(password, profile!);
                Add(new PasswordHasherCall(seq, PasswordHasherOperation.Hash, false, fp, null, profileId, null, hash, null, null, null));
                return hash;
            }
            catch (Exception ex)
            {
                Add(new PasswordHasherCall(seq, PasswordHasherOperation.Hash, false, fp, null, profileId, null, null, null, null, ex));
                throw;
            }
        }

        /// <inheritdoc />
        public async ValueTask<string> HashAsync(string password, CancellationToken cancellationToken = default)
        {
            long seq = Next();
            string? fp = SafeFingerprint(password);
            try
            {
                string hash = await _inner.HashAsync(password, cancellationToken).ConfigureAwait(false);
                Add(new PasswordHasherCall(seq, PasswordHasherOperation.Hash, true, fp, null, null, null, hash, null, null, null));
                return hash;
            }
            catch (Exception ex)
            {
                Add(new PasswordHasherCall(seq, PasswordHasherOperation.Hash, true, fp, null, null, null, null, null, null, ex));
                throw;
            }
        }

        /// <inheritdoc />
        public PasswordVerificationResult Verify(string password, string storedHash) =>
            RecordVerify(PasswordHasherOperation.Verify, password, storedHash, () => _inner.Verify(password, storedHash));

        /// <inheritdoc />
        public PasswordVerificationResult VerifyOrDummy(string password, string? storedHash) =>
            RecordVerify(PasswordHasherOperation.VerifyOrDummy, password, storedHash, () => _inner.VerifyOrDummy(password, storedHash));

        /// <inheritdoc />
        public ValueTask<PasswordVerificationResult> VerifyAsync(string password, string storedHash, CancellationToken cancellationToken = default) =>
            RecordVerifyAsync(PasswordHasherOperation.Verify, password, storedHash, () => _inner.VerifyAsync(password, storedHash, cancellationToken));

        /// <inheritdoc />
        public ValueTask<PasswordVerificationResult> VerifyOrDummyAsync(string password, string? storedHash, CancellationToken cancellationToken = default) =>
            RecordVerifyAsync(PasswordHasherOperation.VerifyOrDummy, password, storedHash, () => _inner.VerifyOrDummyAsync(password, storedHash, cancellationToken));

        /// <inheritdoc />
        public bool NeedsRehash(string storedHash)
        {
            long seq = Next();
            try
            {
                bool result = _inner.NeedsRehash(storedHash);
                Add(new PasswordHasherCall(seq, PasswordHasherOperation.NeedsRehash, false, null, storedHash, null, null, null, result, null, null));
                return result;
            }
            catch (Exception ex)
            {
                Add(new PasswordHasherCall(seq, PasswordHasherOperation.NeedsRehash, false, null, storedHash, null, null, null, null, null, ex));
                throw;
            }
        }

        /// <inheritdoc />
        public HashInfo Inspect(string storedHash)
        {
            long seq = Next();
            try
            {
                HashInfo info = _inner.Inspect(storedHash);
                Add(new PasswordHasherCall(seq, PasswordHasherOperation.Inspect, false, null, storedHash, null, null, null, null, info, null));
                return info;
            }
            catch (Exception ex)
            {
                Add(new PasswordHasherCall(seq, PasswordHasherOperation.Inspect, false, null, storedHash, null, null, null, null, null, ex));
                throw;
            }
        }

        /// <inheritdoc />
        public bool TryWrap(string legacyHash, out string wrappedHash)
        {
            long seq = Next();
            try
            {
                bool ok = _inner.TryWrap(legacyHash, out wrappedHash);
                Add(new PasswordHasherCall(seq, PasswordHasherOperation.TryWrap, false, null, legacyHash, null, null, ok ? wrappedHash : null, ok, null, null));
                return ok;
            }
            catch (Exception ex)
            {
                Add(new PasswordHasherCall(seq, PasswordHasherOperation.TryWrap, false, null, legacyHash, null, null, null, null, null, ex));
                throw;
            }
        }

        private PasswordVerificationResult RecordVerify(PasswordHasherOperation op, string password, string? storedHash, Func<PasswordVerificationResult> call)
        {
            long seq = Next();
            string? fp = SafeFingerprint(password);
            try
            {
                PasswordVerificationResult result = call();
                Add(new PasswordHasherCall(seq, op, false, fp, storedHash, null, result, null, null, null, null));
                return result;
            }
            catch (Exception ex)
            {
                Add(new PasswordHasherCall(seq, op, false, fp, storedHash, null, null, null, null, null, ex));
                throw;
            }
        }

        private async ValueTask<PasswordVerificationResult> RecordVerifyAsync(PasswordHasherOperation op, string password, string? storedHash, Func<ValueTask<PasswordVerificationResult>> call)
        {
            long seq = Next();
            string? fp = SafeFingerprint(password);
            try
            {
                PasswordVerificationResult result = await call().ConfigureAwait(false);
                Add(new PasswordHasherCall(seq, op, true, fp, storedHash, null, result, null, null, null, null));
                return result;
            }
            catch (Exception ex)
            {
                Add(new PasswordHasherCall(seq, op, true, fp, storedHash, null, null, null, null, null, ex));
                throw;
            }
        }

        private long Next() => Interlocked.Increment(ref _sequence);

        private void Add(PasswordHasherCall call)
        {
            lock (_sync)
                _calls.Add(call);
        }

        /// <summary>
        /// <see cref="HashPrimitives.EncodePassword"/> for well-formed text. Invalid UTF-16, which hashers reject, is
        /// encoded losslessly as 0xFF plus its UTF-16LE code units (0xFF never occurs in UTF-8), so it can still be recorded.
        /// </summary>
        private static byte[] FingerprintBytes(string password)
        {
            if (HashPrimitives.IsWellFormedPassword(password))
                return HashPrimitives.EncodePassword(password);
            var result = new byte[1 + 2 * password.Length];
            result[0] = 0xFF;
            for (int i = 0; i < password.Length; i++)
            {
                result[1 + 2 * i] = (byte)password[i];
                result[2 + 2 * i] = (byte)(password[i] >> 8);
            }
            return result;
        }

        private string? SafeFingerprint(string? password) => password == null ? null : Fingerprint(password);

        private static bool FixedTimeEquals(string left, string right) =>
            HashPrimitives.FixedTimeEquals(Encoding.ASCII.GetBytes(left), Encoding.ASCII.GetBytes(right));

        private static string ToHex(byte[] bytes)
        {
            var sb = new StringBuilder(bytes.Length * 2);
            foreach (byte b in bytes)
                sb.Append(b.ToString("x2", System.Globalization.CultureInfo.InvariantCulture));
            return sb.ToString();
        }
    }
}
