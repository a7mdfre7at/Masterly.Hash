using System;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Masterly.Hash.Policy;

namespace Masterly.Hash.Pwned.Internal
{
    /// <summary>
    /// The <see cref="IBreachedPasswordChecker"/> registered by <c>AddPwnedPasswords</c>. A singleton that is safe to
    /// capture (e.g. in a singleton <c>PasswordPolicy</c>): every lookup asks <see cref="IHttpClientFactory"/> for a
    /// fresh <see cref="HttpClient"/>, so the factory's handler rotation (and with it DNS changes) still applies.
    /// The range cache is shared across lookups.
    /// </summary>
    internal sealed class PwnedPasswordsBreachChecker : IBreachedPasswordChecker
    {
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly string _clientName;
        private readonly PwnedPasswordsOptions _options;
        private readonly RangeCache? _cache;

        public PwnedPasswordsBreachChecker(IHttpClientFactory httpClientFactory, string clientName, PwnedPasswordsOptions options, RangeCache? cache)
        {
            if (httpClientFactory == null) throw new ArgumentNullException(nameof(httpClientFactory));
            if (clientName == null) throw new ArgumentNullException(nameof(clientName));
            if (options == null) throw new ArgumentNullException(nameof(options));
            PwnedPasswordsClient.Validate(options);

            _httpClientFactory = httpClientFactory;
            _clientName = clientName;
            _options = options;
            _cache = cache;
        }

        public ValueTask<BreachCheckResult> CheckAsync(string password, CancellationToken cancellationToken)
        {
            if (password == null) throw new ArgumentNullException(nameof(password));
            HttpClient http = _httpClientFactory.CreateClient(_clientName);
            return new PwnedPasswordsClient(http, _options, _cache).CheckAsync(password, cancellationToken);
        }
    }
}
