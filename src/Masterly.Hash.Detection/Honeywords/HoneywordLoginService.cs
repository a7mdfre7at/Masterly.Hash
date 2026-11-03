using System;
using System.Threading;
using System.Threading.Tasks;

namespace Masterly.Hash.Detection
{
    /// <summary>Outcome of <see cref="HoneywordLoginService.LoginAsync"/>.</summary>
    /// <remarks>The zero (default) value is <see cref="Mismatch"/>, so an uninitialized outcome never reads as a success.</remarks>
    public enum HoneywordLoginOutcome
    {
        /// <summary>
        /// The password matches no sweetword (an ordinary wrong password), or the stored hash is unusable. Also the
        /// default value.
        /// </summary>
        Mismatch = 0,

        /// <summary>The password is the user's real password.</summary>
        Success,

        /// <summary>
        /// The password is a decoy. Most likely someone who has cracked the password file is logging in: deny the
        /// login exactly as for <see cref="Mismatch"/> (do not tip off the attacker) and investigate. The built-in
        /// generators never place a decoy within one typo of the real password, but a user who makes two or more
        /// typos, or a custom generator, can still land on a decoy, so treat a single hit as a strong signal to
        /// investigate (and hits across many accounts as a confirmed breach) rather than as proof.
        /// </summary>
        BreachDetected,
    }

    /// <summary>Result of <see cref="HoneywordLoginService.LoginAsync"/>.</summary>
    public sealed class HoneywordLoginResult
    {
        internal HoneywordLoginResult(HoneywordLoginOutcome outcome, HoneywordVerification verification)
        {
            Outcome = outcome;
            Verification = verification;
        }

        /// <summary>What happened.</summary>
        public HoneywordLoginOutcome Outcome { get; }

        /// <summary>True only for <see cref="HoneywordLoginOutcome.Success"/>.</summary>
        public bool IsSuccess => Outcome == HoneywordLoginOutcome.Success;

        /// <summary>
        /// Details of the sweetword check, including why it failed. For logs and metrics, never for the end user.
        /// After <see cref="HoneywordLoginOutcome.Success"/> the index is withheld (-1): the real index is the secret
        /// only the honeychecker should hold. Log <see cref="HoneywordVerification.Status"/> (or the struct's
        /// <c>ToString()</c>, which leaves the index out), not the index.
        /// </summary>
        public HoneywordVerification Verification { get; }

        /// <inheritdoc />
        public override string ToString() => Outcome.ToString();
    }

    /// <summary>Event data for <see cref="HoneywordLoginService.BreachDetected"/>.</summary>
    public sealed class HoneywordBreachDetectedEventArgs : EventArgs
    {
        internal HoneywordBreachDetectedEventArgs(string userId, int sweetwordIndex, DateTimeOffset detectedAt)
        {
            UserId = userId;
            SweetwordIndex = sweetwordIndex;
            DetectedAt = detectedAt;
        }

        /// <summary>The account a decoy password was used for.</summary>
        public string UserId { get; }

        /// <summary>Index of the decoy that was entered (not the real index).</summary>
        public int SweetwordIndex { get; }

        /// <summary>When the decoy login happened.</summary>
        public DateTimeOffset DetectedAt { get; }
    }

    /// <summary>
    /// Ties <see cref="HoneywordService"/> to an <see cref="IHoneychecker"/>: registration sends the real index to the
    /// honeychecker, login asks it whether a matching sweetword is the real one.
    /// </summary>
    /// <example>
    /// <code>
    /// var login = new HoneywordLoginService(new HoneywordService(hasher, new HoneywordServiceOptions
    /// {
    ///     Generator = PasswordModelHoneywordGenerator.Default,
    /// }), honeycheckerClient);
    /// login.BreachDetected += (_, e) =&gt; alerts.Page($"Honeyword used for {e.UserId}");
    ///
    /// user.PasswordHash = await login.RegisterAsync(user.Id, password);
    /// var result = await login.LoginAsync(user.Id, password, user.PasswordHash);
    /// if (!result.IsSuccess) return Unauthorized();
    /// </code>
    /// </example>
    public sealed class HoneywordLoginService
    {
        private readonly HoneywordService _honeywords;
        private readonly IHoneychecker _honeychecker;
        private readonly Func<DateTimeOffset> _clock;

        /// <summary>Creates the service.</summary>
        public HoneywordLoginService(HoneywordService honeywords, IHoneychecker honeychecker)
            : this(honeywords, honeychecker, null)
        {
        }

        /// <summary>Creates the service with a clock for event timestamps.</summary>
        public HoneywordLoginService(HoneywordService honeywords, IHoneychecker honeychecker, Func<DateTimeOffset>? clock)
        {
            _honeywords = honeywords ?? throw new ArgumentNullException(nameof(honeywords));
            _honeychecker = honeychecker ?? throw new ArgumentNullException(nameof(honeychecker));
            _clock = clock ?? (() => DateTimeOffset.UtcNow);
        }

        /// <summary>
        /// Raised when a decoy password is used. Handlers run on the login path; exceptions they throw propagate to
        /// the caller of <see cref="LoginAsync"/>.
        /// </summary>
        public event EventHandler<HoneywordBreachDetectedEventArgs>? BreachDetected;

        /// <summary>
        /// Creates a honeyword record, stores its real index in the honeychecker, and returns the hash to store with
        /// the user. Persist the returned hash only after this completes; if persisting fails, the honeychecker holds
        /// an index for a hash that was never stored, and the user's next correct login is reported as a breach, so
        /// call this again rather than keeping the old hash.
        /// </summary>
        public async Task<string> RegisterAsync(string userId, string password, int sweetwordCount = HoneywordService.DefaultSweetwordCount, CancellationToken cancellationToken = default)
        {
            if (userId == null) throw new ArgumentNullException(nameof(userId));
            if (password == null) throw new ArgumentNullException(nameof(password));

            HoneywordRecord record = await _honeywords.CreateAsync(password, sweetwordCount, cancellationToken).ConfigureAwait(false);
            await _honeychecker.SetAsync(userId, record.RealIndex, cancellationToken).ConfigureAwait(false);
            return record.StoredHash;
        }

        /// <summary>
        /// Checks a login. One key derivation is performed even when <paramref name="storedHash"/> is null (unknown
        /// user), so timing does not reveal which accounts exist (over-long passwords fail fast in both cases). The honeychecker is consulted only when the
        /// password matches a sweetword; if it is unreachable the exception propagates (fail closed).
        /// </summary>
        public async Task<HoneywordLoginResult> LoginAsync(string userId, string password, string? storedHash, CancellationToken cancellationToken = default)
        {
            if (userId == null) throw new ArgumentNullException(nameof(userId));
            if (password == null) throw new ArgumentNullException(nameof(password));

            HoneywordVerification verification = await _honeywords.VerifyOrDummyAsync(password, storedHash, cancellationToken).ConfigureAwait(false);
            if (!verification.IsSweetwordMatch)
                return new HoneywordLoginResult(HoneywordLoginOutcome.Mismatch, verification);

            bool real = await _honeychecker.IsRealAsync(userId, verification.Index, cancellationToken).ConfigureAwait(false);
            if (real)
            {
                // Withhold the real index so it cannot leak into logs next to the user id.
                return new HoneywordLoginResult(
                    HoneywordLoginOutcome.Success,
                    new HoneywordVerification(HoneywordVerificationStatus.SweetwordMatch, -1));
            }

            BreachDetected?.Invoke(this, new HoneywordBreachDetectedEventArgs(userId, verification.Index, _clock()));
            return new HoneywordLoginResult(HoneywordLoginOutcome.BreachDetected, verification);
        }
    }
}
