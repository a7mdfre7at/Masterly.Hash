using System;

namespace Masterly.Hash.Pwned
{
    /// <summary>What <see cref="PwnedPasswordsClient"/> does when the Pwned Passwords service cannot answer.</summary>
    public enum PwnedPasswordsFailureMode
    {
        /// <summary>
        /// Return <see cref="Masterly.Hash.Policy.BreachCheckResult.Unavailable"/> so the password is judged on local
        /// checks only. An outage of a third-party service does not block sign-ups or password changes.
        /// </summary>
        FailOpen,

        /// <summary>
        /// Throw <see cref="PwnedPasswordsUnavailableException"/>. This only has an effect when
        /// <see cref="PwnedPasswordsClient"/> is called directly: <see cref="Masterly.Hash.Policy.PasswordPolicy"/>
        /// turns any checker exception into <see cref="Masterly.Hash.Policy.BreachCheckResult.Unavailable"/>, as the
        /// <see cref="Masterly.Hash.Policy.IBreachedPasswordChecker"/> contract asks. To require the check through
        /// <c>PasswordPolicy</c>, reject when <c>PasswordPolicyResult.BreachCheckUnavailable</c> is true.
        /// </summary>
        Throw,
    }

    /// <summary>Settings for <see cref="PwnedPasswordsClient"/>. The client copies them when it is created.</summary>
    public sealed class PwnedPasswordsOptions
    {
        /// <summary>The public Pwned Passwords API, <c>https://api.pwnedpasswords.com/</c>.</summary>
        public static readonly Uri DefaultBaseAddress = new Uri("https://api.pwnedpasswords.com/");

        /// <summary>The User-Agent sent when none is configured.</summary>
        public const string DefaultUserAgent = "Masterly.Hash.Pwned/2.0 (+https://github.com/a7mdfre7at/Masterly.Hash)";

        /// <summary>Largest accepted <see cref="Timeout"/>.</summary>
        public static readonly TimeSpan MaxTimeout = TimeSpan.FromMinutes(5);

        /// <summary>Largest accepted <see cref="CacheDuration"/>.</summary>
        public static readonly TimeSpan MaxCacheDuration = TimeSpan.FromDays(7);

        /// <summary>Largest accepted <see cref="CacheMaxEntries"/>.</summary>
        public const int MaxCacheEntriesLimit = 100_000;

        /// <summary>
        /// Root of the API. Requests go to <c>{BaseAddress}range/{prefix}</c>. Must be absolute https (http only with
        /// <see cref="AllowInsecureHttp"/>), without query or fragment. Default <see cref="DefaultBaseAddress"/>.
        /// </summary>
        public Uri BaseAddress { get; set; } = DefaultBaseAddress;

        /// <summary>
        /// Allows an http <see cref="BaseAddress"/>, e.g. a local mirror. Without TLS an attacker on the network can
        /// rewrite answers so breached passwords look clean. Default false.
        /// </summary>
        public bool AllowInsecureHttp { get; set; }

        /// <summary>
        /// How long one lookup may take, including reading the response, before it counts as unavailable.
        /// Greater than zero and at most <see cref="MaxTimeout"/>. Default 3 seconds.
        /// </summary>
        public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(3);

        /// <summary>
        /// The User-Agent header. The Pwned Passwords API rejects requests without one; name your application,
        /// e.g. <c>Contoso-SignUp/1.4</c>. Default <see cref="DefaultUserAgent"/>.
        /// </summary>
        public string UserAgent { get; set; } = DefaultUserAgent;

        /// <summary>What to do when the service cannot answer. Default <see cref="PwnedPasswordsFailureMode.FailOpen"/>.</summary>
        public PwnedPasswordsFailureMode FailureMode { get; set; } = PwnedPasswordsFailureMode.FailOpen;

        /// <summary>
        /// A password counts as breached only if it appears at least this many times in the corpus. At least 1.
        /// Default 1 (any appearance).
        /// </summary>
        public int MinimumOccurrences { get; set; } = 1;

        /// <summary>
        /// Keeps parsed range responses in memory, keyed by the 5-character hash prefix, so repeated lookups in the
        /// same range skip the network. Default false.
        /// </summary>
        public bool EnableCache { get; set; }

        /// <summary>How long a cached range stays valid. Greater than zero and at most <see cref="MaxCacheDuration"/>. Default 1 hour.</summary>
        public TimeSpan CacheDuration { get; set; } = TimeSpan.FromHours(1);

        /// <summary>
        /// Most ranges kept in the cache; the least recently used is evicted first. One range holds roughly
        /// 1,000 entries (about 25 KiB). Between 1 and <see cref="MaxCacheEntriesLimit"/>. Default 256.
        /// </summary>
        public int CacheMaxEntries { get; set; } = 256;
    }
}
