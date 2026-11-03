using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using Masterly.Hash.Detection.Internal;

namespace Masterly.Hash.Detection
{
    /// <summary>Event data for <see cref="HoneyAccountRegistry.HoneyAccountAccessed"/>.</summary>
    public sealed class HoneyAccountAccessedEventArgs : EventArgs
    {
        internal HoneyAccountAccessedEventArgs(string account, string? context, DateTimeOffset timestamp)
        {
            Account = account;
            Context = context;
            Timestamp = timestamp;
        }

        /// <summary>The account name as it was supplied in the login attempt.</summary>
        public string Account { get; }

        /// <summary>Caller-supplied context such as the client address or request id. Never a password.</summary>
        public string? Context { get; }

        /// <summary>When the attempt happened.</summary>
        public DateTimeOffset Timestamp { get; }
    }

    /// <summary>
    /// A set of decoy accounts that no legitimate user owns. Seed them into the user table (with honeyword or random
    /// hashes) and on public-looking lists; any login that targets one is an attacker working from a stolen list or
    /// a cracked database. Matching is case-insensitive and NFKC-normalized, so <c>Admin</c>, <c>ADMIN</c> and the
    /// full-width <c>ａｄｍｉｎ</c> are the same account.
    /// </summary>
    /// <remarks>
    /// Thread-safe. Call <see cref="CheckLogin"/> on every attempt, and keep the response identical to a wrong
    /// password, including its timing: still run the usual password verification (or a dummy one such as
    /// <c>PasswordHasher.VerifyOrDummy(password, null)</c>) before failing, otherwise the fast response marks the
    /// account as a honeypot.
    /// </remarks>
    public sealed class HoneyAccountRegistry
    {
        /// <summary>
        /// Longest account name, in UTF-16 code units, that can be a honey account. Longer names are rejected by
        /// <see cref="Add"/> and are never honey accounts, and they are not normalized, so an attacker-supplied
        /// multi-megabyte user name costs nothing.
        /// </summary>
        public const int MaxAccountLength = 1024;

        private readonly ConcurrentDictionary<string, byte> _accounts = new ConcurrentDictionary<string, byte>(StringComparer.Ordinal);
        private readonly Func<DateTimeOffset> _clock;

        /// <summary>Creates an empty registry.</summary>
        public HoneyAccountRegistry()
            : this(Array.Empty<string>(), null)
        {
        }

        /// <summary>Creates a registry containing <paramref name="accounts"/>.</summary>
        public HoneyAccountRegistry(IEnumerable<string> accounts)
            : this(accounts, null)
        {
        }

        /// <summary>Creates a registry containing <paramref name="accounts"/>, with a clock for event timestamps.</summary>
        public HoneyAccountRegistry(IEnumerable<string> accounts, Func<DateTimeOffset>? clock)
        {
            if (accounts == null) throw new ArgumentNullException(nameof(accounts));
            _clock = clock ?? (() => DateTimeOffset.UtcNow);
            foreach (string account in accounts)
                Add(account);
        }

        /// <summary>
        /// Raised by <see cref="CheckLogin"/> when the account is a honey account. Handlers run on the login path;
        /// exceptions they throw propagate to the caller.
        /// </summary>
        public event EventHandler<HoneyAccountAccessedEventArgs>? HoneyAccountAccessed;

        /// <summary>Number of honey accounts.</summary>
        public int Count => _accounts.Count;

        /// <summary>Adds a honey account. Returns false if it was already present.</summary>
        public bool Add(string account)
        {
            if (account == null) throw new ArgumentNullException(nameof(account));
            if (account.Length == 0) throw new ArgumentException("Account cannot be empty.", nameof(account));
            if (account.Length > MaxAccountLength)
                throw new ArgumentException($"Account cannot be longer than {MaxAccountLength} characters.", nameof(account));
            return _accounts.TryAdd(TextNormalization.Account(account), 0);
        }

        /// <summary>Removes a honey account. Returns false if it was not present.</summary>
        public bool Remove(string account)
        {
            if (account == null) throw new ArgumentNullException(nameof(account));
            if (account.Length > MaxAccountLength)
                return false;
            return _accounts.TryRemove(TextNormalization.Account(account), out _);
        }

        /// <summary>True if <paramref name="account"/> is a honey account. Does not raise the event.</summary>
        public bool IsHoneyAccount(string account)
        {
            if (account == null) throw new ArgumentNullException(nameof(account));
            return account.Length != 0 && account.Length <= MaxAccountLength && _accounts.ContainsKey(TextNormalization.Account(account));
        }

        /// <summary>
        /// Call on every login attempt. If <paramref name="account"/> is a honey account, raises
        /// <see cref="HoneyAccountAccessed"/> and returns true; the caller should then fail the login the same way as
        /// a wrong password, so the attacker learns nothing. That includes timing: run the same password
        /// verification (or a dummy one) before responding, rather than returning immediately.
        /// </summary>
        /// <param name="account">The account name from the login request.</param>
        /// <param name="context">Optional context for the alert (client address, request id). Never pass the password.</param>
        public bool CheckLogin(string account, string? context = null)
        {
            if (!IsHoneyAccount(account))
                return false;
            HoneyAccountAccessed?.Invoke(this, new HoneyAccountAccessedEventArgs(account, context, _clock()));
            return true;
        }
    }
}
