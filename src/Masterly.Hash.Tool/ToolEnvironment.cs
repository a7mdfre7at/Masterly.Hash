using System;
using System.Diagnostics;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Masterly.Hash.Policy;
using Masterly.Hash.Primitives;
using Masterly.Hash.Pwned;

namespace Masterly.Hash.Tool
{
    /// <summary>
    /// Everything a command depends on: the console, how hashers are configured, the breach checker, the benchmark
    /// clock and environment variables. <see cref="CreateDefault"/> wires the real ones; tests replace them.
    /// </summary>
    public sealed class ToolEnvironment
    {
        private Func<PasswordHasherOptions> _hasherOptionsFactory = () => new PasswordHasherOptions();
        private Func<IBreachedPasswordChecker> _breachCheckerFactory = () => new OwnedPwnedPasswordsClient();
        private Func<HashProfile, double> _measureMilliseconds = MeasureOnce;
        private Func<string, string?> _getEnvironmentVariable = Environment.GetEnvironmentVariable;

        /// <summary>Creates an environment around a console, with the default factories.</summary>
        public ToolEnvironment(IToolConsole console)
        {
            Console = console ?? throw new ArgumentNullException(nameof(console));
        }

        /// <summary>The console commands read from and write to.</summary>
        public IToolConsole Console { get; }

        /// <summary>
        /// Creates the base hasher options for every command. Defaults to <c>new PasswordHasherOptions()</c>
        /// (profile <see cref="HashProfile.Server2026a"/>). Commands add the legacy formats themselves.
        /// </summary>
        public Func<PasswordHasherOptions> HasherOptionsFactory
        {
            get => _hasherOptionsFactory;
            set => _hasherOptionsFactory = value ?? throw new ArgumentNullException(nameof(value));
        }

        /// <summary>
        /// Creates the breached-password checker used by <c>policy --pwned</c>. Defaults to a Have I Been Pwned
        /// k-anonymity client over a new <see cref="HttpClient"/>. A checker that implements
        /// <see cref="IDisposable"/> is disposed after use.
        /// </summary>
        public Func<IBreachedPasswordChecker> BreachCheckerFactory
        {
            get => _breachCheckerFactory;
            set => _breachCheckerFactory = value ?? throw new ArgumentNullException(nameof(value));
        }

        /// <summary>Times one hash with a profile, in milliseconds. Used by <c>bench</c>.</summary>
        public Func<HashProfile, double> MeasureMilliseconds
        {
            get => _measureMilliseconds;
            set => _measureMilliseconds = value ?? throw new ArgumentNullException(nameof(value));
        }

        /// <summary>Reads an environment variable. Used by <c>apikey generate --key-env</c>.</summary>
        public Func<string, string?> GetEnvironmentVariable
        {
            get => _getEnvironmentVariable;
            set => _getEnvironmentVariable = value ?? throw new ArgumentNullException(nameof(value));
        }

        /// <summary>The real process environment: <see cref="SystemConsole"/> and the default factories.</summary>
        public static ToolEnvironment CreateDefault() => new ToolEnvironment(new SystemConsole());

        /// <summary>
        /// Runs the profile's key-derivation function once on a random input and salt and returns the elapsed time.
        /// This is the work the hasher does for one hash or verify.
        /// </summary>
        public static double MeasureOnce(HashProfile profile)
        {
            if (profile == null) throw new ArgumentNullException(nameof(profile));
            byte[] input = HashPrimitives.RandomBytes(16);
            byte[] salt = HashPrimitives.RandomBytes(profile.SaltLength);
            try
            {
                var stopwatch = Stopwatch.StartNew();
                byte[] tag = HashPrimitives.DeriveKey(profile, input, salt);
                stopwatch.Stop();
                HashPrimitives.Zero(tag);
                return stopwatch.Elapsed.TotalMilliseconds;
            }
            finally
            {
                HashPrimitives.Zero(input);
            }
        }

        /// <summary>A Pwned Passwords client that owns (and disposes) its <see cref="HttpClient"/>.</summary>
        private sealed class OwnedPwnedPasswordsClient : IBreachedPasswordChecker, IDisposable
        {
            private const string UserAgent = "masterly-hash-tool/2.0 (+https://github.com/a7mdfre7at/Masterly.Hash)";

            private readonly HttpClient _http = new HttpClient();
            private readonly PwnedPasswordsClient _client;

            public OwnedPwnedPasswordsClient()
            {
                _client = new PwnedPasswordsClient(_http, new PwnedPasswordsOptions { UserAgent = UserAgent });
            }

            public ValueTask<BreachCheckResult> CheckAsync(string password, CancellationToken cancellationToken) =>
                _client.CheckAsync(password, cancellationToken);

            public void Dispose() => _http.Dispose();
        }
    }
}
