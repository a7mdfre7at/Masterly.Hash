using System;

namespace Masterly.Hash.Testing
{
    /// <summary>The <see cref="IPasswordHasher"/> member a <see cref="PasswordHasherCall"/> records.</summary>
    public enum PasswordHasherOperation
    {
        /// <summary><see cref="IPasswordHasher.Hash(string)"/>, <see cref="IPasswordHasher.Hash(string, HashProfile)"/> or <see cref="IPasswordHasher.HashAsync"/>.</summary>
        Hash,

        /// <summary><see cref="IPasswordHasher.Verify"/> or <see cref="IPasswordHasher.VerifyAsync"/>.</summary>
        Verify,

        /// <summary><see cref="IPasswordHasher.VerifyOrDummy"/> or <see cref="IPasswordHasher.VerifyOrDummyAsync"/>.</summary>
        VerifyOrDummy,

        /// <summary><see cref="IPasswordHasher.NeedsRehash"/>.</summary>
        NeedsRehash,

        /// <summary><see cref="IPasswordHasher.Inspect"/>.</summary>
        Inspect,

        /// <summary><see cref="IPasswordHasher.TryWrap"/>.</summary>
        TryWrap,
    }

    /// <summary>
    /// One call recorded by <see cref="RecordingPasswordHasher"/>. The password itself is never stored, only a keyed
    /// SHA-256 fingerprint of it (see <see cref="RecordingPasswordHasher.Fingerprint"/>).
    /// </summary>
    public sealed class PasswordHasherCall
    {
        internal PasswordHasherCall(
            long sequence,
            PasswordHasherOperation operation,
            bool isAsync,
            string? passwordFingerprint,
            string? storedHash,
            string? profileId,
            PasswordVerificationResult? result,
            string? producedHash,
            bool? booleanResult,
            HashInfo? info,
            Exception? exception)
        {
            Sequence = sequence;
            Operation = operation;
            IsAsync = isAsync;
            PasswordFingerprint = passwordFingerprint;
            StoredHash = storedHash;
            ProfileId = profileId;
            Result = result;
            ProducedHash = producedHash;
            BooleanResult = booleanResult;
            Info = info;
            Exception = exception;
        }

        /// <summary>Order in which the call started, starting at 1 for each recorder.</summary>
        public long Sequence { get; }

        /// <summary>Which member was called.</summary>
        public PasswordHasherOperation Operation { get; }

        /// <summary>True for the <c>...Async</c> members.</summary>
        public bool IsAsync { get; }

        /// <summary>
        /// Lowercase hex HMAC-SHA256 fingerprint of the password, keyed per recorder; null if the call took no password
        /// or the password was null. Compare with <see cref="RecordingPasswordHasher.Fingerprint"/>.
        /// </summary>
        public string? PasswordFingerprint { get; }

        /// <summary>The stored hash passed in (verify, inspect, needs-rehash) or the legacy hash passed to <c>TryWrap</c>.</summary>
        public string? StoredHash { get; }

        /// <summary>Profile id passed to <see cref="IPasswordHasher.Hash(string, HashProfile)"/>, otherwise null.</summary>
        public string? ProfileId { get; }

        /// <summary>The verification result, for verify calls that returned.</summary>
        public PasswordVerificationResult? Result { get; }

        /// <summary>Shortcut for <see cref="PasswordVerificationResult.Status"/> of <see cref="Result"/>.</summary>
        public VerificationStatus? Status => Result?.Status;

        /// <summary>The hash returned by a hash call or the wrapped hash returned by <c>TryWrap</c>.</summary>
        public string? ProducedHash { get; }

        /// <summary>The return value of <see cref="IPasswordHasher.NeedsRehash"/> or <see cref="IPasswordHasher.TryWrap"/>.</summary>
        public bool? BooleanResult { get; }

        /// <summary>The return value of <see cref="IPasswordHasher.Inspect"/>.</summary>
        public HashInfo? Info { get; }

        /// <summary>The exception the inner hasher threw, if any. The exception was rethrown to the caller.</summary>
        public Exception? Exception { get; }

        /// <summary>True for a verify call made without a stored hash (an unknown user).</summary>
        public bool IsUnknownUser =>
            (Operation == PasswordHasherOperation.Verify || Operation == PasswordHasherOperation.VerifyOrDummy) && StoredHash == null;

        /// <inheritdoc />
        public override string ToString()
        {
            string name = Operation + (IsAsync ? "Async" : string.Empty);
            if (Exception != null)
                return $"#{Sequence} {name} threw {Exception.GetType().Name}";
            if (Result != null)
                return $"#{Sequence} {name} -> {Result}";
            if (BooleanResult.HasValue)
                return $"#{Sequence} {name} -> {BooleanResult.Value}";
            return $"#{Sequence} {name}";
        }
    }
}
