using System;
using System.Globalization;
using System.IO;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Masterly.Hash.Policy;
using Masterly.Hash.Primitives;
using Masterly.Hash.Pwned.Internal;

namespace Masterly.Hash.Pwned
{
    /// <summary>
    /// Checks passwords against Have I Been Pwned's Pwned Passwords corpus with the k-anonymity range API.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The password is hashed locally with SHA-1 over its UTF-8 bytes. Only the first 5 hex digits of that hash are
    /// sent (<c>GET {BaseAddress}range/{prefix}</c>, with <c>Add-Padding: true</c> so the response size does not
    /// hint at the prefix). The service answers with every suffix in that range; the match happens locally.
    /// Neither the password, the full hash nor the suffix leaves the process, is logged or appears in exceptions.
    /// </para>
    /// <para>
    /// Thread-safe; reuse one instance (or let <c>AddPwnedPasswords</c> manage it). The <see cref="HttpClient"/> is
    /// not disposed by this class.
    /// </para>
    /// </remarks>
    public sealed class PwnedPasswordsClient : IBreachedPasswordChecker
    {
        /// <summary>Largest accepted response body. Real padded ranges are about 40 KiB.</summary>
        public const int MaxResponseBytes = 1024 * 1024;

        private const int ReadChunk = 16 * 1024;

        private readonly HttpClient _http;
        private readonly Uri _rangeBase;
        private readonly TimeSpan _timeout;
        private readonly string _userAgent;
        private readonly PwnedPasswordsFailureMode _failureMode;
        private readonly int _minimumOccurrences;
        private readonly RangeCache? _cache;

        /// <summary>Creates a client.</summary>
        /// <param name="httpClient">Client used for requests. Typically from <c>IHttpClientFactory</c>; not disposed by this class.</param>
        /// <param name="options">Settings; defaults when null. Copied, so later changes have no effect.</param>
        /// <exception cref="ArgumentNullException"><paramref name="httpClient"/> is null.</exception>
        /// <exception cref="ArgumentException"><paramref name="options"/> holds an invalid value.</exception>
        public PwnedPasswordsClient(HttpClient httpClient, PwnedPasswordsOptions? options = null)
            : this(httpClient, options ?? new PwnedPasswordsOptions(), CreateCache(options ?? new PwnedPasswordsOptions()))
        {
        }

        /// <summary>Creates a client with an explicit cache (null for none), e.g. one shared across typed-client instances.</summary>
        internal PwnedPasswordsClient(HttpClient httpClient, PwnedPasswordsOptions options, RangeCache? cache)
        {
            if (httpClient == null) throw new ArgumentNullException(nameof(httpClient));
            Validate(options);

            _http = httpClient;
            _rangeBase = new Uri(WithTrailingSlash(options.BaseAddress), "range/");
            _timeout = options.Timeout;
            _userAgent = options.UserAgent.Trim();
            _failureMode = options.FailureMode;
            _minimumOccurrences = options.MinimumOccurrences;
            _cache = cache;
        }

        /// <summary>
        /// Looks a password up. Returns <see cref="BreachCheckResult.Breached"/> with the corpus count when it
        /// appears at least <see cref="PwnedPasswordsOptions.MinimumOccurrences"/> times, otherwise
        /// <see cref="BreachCheckResult.NotBreached"/>. When the service cannot answer (timeout, network error,
        /// non-success status, malformed or empty answer) returns <see cref="BreachCheckResult.Unavailable"/> or throws,
        /// depending on <see cref="PwnedPasswordsOptions.FailureMode"/>.
        /// </summary>
        /// <param name="password">The candidate password, hashed exactly as given (UTF-8, no normalization).</param>
        /// <param name="cancellationToken">Cancels the lookup.</param>
        /// <exception cref="ArgumentNullException"><paramref name="password"/> is null.</exception>
        /// <exception cref="ArgumentException"><paramref name="password"/> is empty.</exception>
        /// <exception cref="PwnedPasswordsUnavailableException">The service could not answer and <see cref="PwnedPasswordsOptions.FailureMode"/> is <see cref="PwnedPasswordsFailureMode.Throw"/>.</exception>
        /// <exception cref="OperationCanceledException"><paramref name="cancellationToken"/> was cancelled.</exception>
        public ValueTask<BreachCheckResult> CheckAsync(string password, CancellationToken cancellationToken = default)
        {
            if (password == null) throw new ArgumentNullException(nameof(password));
            if (password.Length == 0) throw new ArgumentException("Password cannot be empty.", nameof(password));
            cancellationToken.ThrowIfCancellationRequested();
            return CheckCoreAsync(password, cancellationToken);
        }

        /// <summary>Looks up a password held in a <see cref="SensitiveString"/>. See <see cref="CheckAsync(string, CancellationToken)"/>.</summary>
        /// <param name="password">The candidate password.</param>
        /// <param name="cancellationToken">Cancels the lookup.</param>
        /// <exception cref="ArgumentNullException"><paramref name="password"/> is null.</exception>
        /// <exception cref="ArgumentException"><paramref name="password"/> is empty.</exception>
        /// <exception cref="PwnedPasswordsUnavailableException">The service could not answer and <see cref="PwnedPasswordsOptions.FailureMode"/> is <see cref="PwnedPasswordsFailureMode.Throw"/>.</exception>
        /// <exception cref="OperationCanceledException"><paramref name="cancellationToken"/> was cancelled.</exception>
        public ValueTask<BreachCheckResult> CheckAsync(SensitiveString password, CancellationToken cancellationToken = default)
        {
            if (password == null) throw new ArgumentNullException(nameof(password));
            return CheckAsync(password.Reveal(), cancellationToken);
        }

        /// <summary>Removes every cached range. Does nothing when the cache is disabled.</summary>
        public void ClearCache() => _cache?.Clear();

        private async ValueTask<BreachCheckResult> CheckCoreAsync(string password, CancellationToken cancellationToken)
        {
            PwnedHash.Compute(password, out string prefix, out byte[] suffix);
            try
            {
                RangeResponse? range = null;
                if (_cache == null || !_cache.TryGet(prefix, out range) || range == null)
                {
                    range = await FetchAsync(prefix, cancellationToken).ConfigureAwait(false);
                    if (range == null)
                        return BreachCheckResult.Unavailable;
                    _cache?.Set(prefix, range);
                }

                long occurrences = range.Lookup(suffix);
                return occurrences >= _minimumOccurrences
                    ? BreachCheckResult.Breached(occurrences)
                    : BreachCheckResult.NotBreached;
            }
            finally
            {
                HashPrimitives.Zero(suffix);
            }
        }

        /// <summary>Fetches and parses a range. Returns null on failure in fail-open mode; throws otherwise.</summary>
        private async Task<RangeResponse?> FetchAsync(string prefix, CancellationToken cancellationToken)
        {
            using (var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
            {
                timeout.CancelAfter(_timeout);
                try
                {
                    return await SendAsync(prefix, timeout.Token).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
                {
                    // Our timeout, HttpClient.Timeout or a resilience handler gave up: the service did not answer.
                    return Fail(new PwnedPasswordsUnavailableException("The Pwned Passwords service did not answer within the configured timeout."));
                }
                catch (PwnedPasswordsUnavailableException ex)
                {
                    return Fail(ex);
                }
                catch (HttpRequestException ex)
                {
                    return Fail(new PwnedPasswordsUnavailableException("The Pwned Passwords service could not be reached.", ex));
                }
                catch (IOException ex)
                {
                    return Fail(new PwnedPasswordsUnavailableException("The connection to the Pwned Passwords service failed.", ex));
                }
                catch (Exception ex) when (!(ex is OperationCanceledException))
                {
                    // Anything else from the injected HttpClient pipeline (custom handlers, circuit breakers,
                    // a disposed client) still honours the configured failure mode.
                    return Fail(new PwnedPasswordsUnavailableException("The Pwned Passwords request failed.", ex));
                }
            }
        }

        private RangeResponse? Fail(PwnedPasswordsUnavailableException exception)
        {
            if (_failureMode == PwnedPasswordsFailureMode.Throw)
                throw exception;
            return null;
        }

        private async Task<RangeResponse> SendAsync(string prefix, CancellationToken ct)
        {
            using (var request = new HttpRequestMessage(HttpMethod.Get, new Uri(_rangeBase, prefix)))
            {
                request.Headers.TryAddWithoutValidation("User-Agent", _userAgent);
                request.Headers.TryAddWithoutValidation("Add-Padding", "true");

                using (HttpResponseMessage response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false))
                {
                    if (!response.IsSuccessStatusCode)
                        throw new PwnedPasswordsUnavailableException(
                            "The Pwned Passwords service answered with HTTP " +
                            ((int)response.StatusCode).ToString(CultureInfo.InvariantCulture) + ".");

                    long? declared = response.Content?.Headers.ContentLength;
                    if (declared > MaxResponseBytes)
                        throw TooLarge();
                    if (response.Content == null)
                        throw Malformed();

                    (byte[] body, int length) = await ReadLimitedAsync(response.Content, ct).ConfigureAwait(false);
                    if (!RangeResponse.TryParse(body, length, out RangeResponse? range) || range == null)
                        throw Malformed();

                    // Every real range holds hundreds of breached suffixes. An empty body, a 204 or a body of padding
                    // only comes from a proxy, a fallback handler or a broken mirror; treating it as "not breached"
                    // (and caching that) would let breached passwords through, so it counts as unavailable.
                    if (range.Count == 0)
                        throw Malformed();
                    return range;
                }
            }
        }

        /// <summary>
        /// Reads at most <see cref="MaxResponseBytes"/>; a longer body is rejected rather than truncated.
        /// </summary>
        /// <remarks>
        /// Not every response stream observes the token once a read is in progress (a custom handler's stream may
        /// ignore it), so cancellation also disposes the stream
        /// to tear a stalled read down. Whatever that read then does (throw, or return 0 as if the body ended) is
        /// reported as cancellation, never parsed as a complete, truncated range.
        /// </remarks>
        private static async Task<(byte[] Buffer, int Length)> ReadLimitedAsync(HttpContent content, CancellationToken ct)
        {
            Stream stream = await content.ReadAsStreamAsync(ct).ConfigureAwait(false);
            using (stream)
            using (ct.Register(DisposeStream, stream))
            {
                var buffer = new byte[ReadChunk];
                int length = 0;
                try
                {
                    while (true)
                    {
                        if (length == buffer.Length)
                        {
                            if (buffer.Length > MaxResponseBytes)
                                throw TooLarge();
                            Array.Resize(ref buffer, Math.Min(buffer.Length * 2, MaxResponseBytes + 1));
                        }
                        int read = await stream.ReadAsync(buffer, length, buffer.Length - length, ct).ConfigureAwait(false);
                        if (read <= 0)
                            break;
                        length += read;
                        if (length > MaxResponseBytes)
                            throw TooLarge();
                    }
                }
                catch (Exception ex) when (ct.IsCancellationRequested && !(ex is OperationCanceledException))
                {
                    throw new OperationCanceledException("Reading the Pwned Passwords response was cancelled.", ex, ct);
                }

                ct.ThrowIfCancellationRequested();
                return (buffer, length);
            }
        }

        private static void DisposeStream(object? state) => ((IDisposable)state!).Dispose();

        private static PwnedPasswordsUnavailableException TooLarge() =>
            new PwnedPasswordsUnavailableException(
                "The Pwned Passwords response exceeded " + MaxResponseBytes.ToString(CultureInfo.InvariantCulture) + " bytes.");

        private static PwnedPasswordsUnavailableException Malformed() =>
            new PwnedPasswordsUnavailableException("The Pwned Passwords service returned a malformed range.");

        /// <summary>Validates the options and builds the cache they ask for, or null when caching is off.</summary>
        internal static RangeCache? CreateCache(PwnedPasswordsOptions options, Func<TimeSpan>? clock = null)
        {
            Validate(options);
            return options.EnableCache ? new RangeCache(options.CacheMaxEntries, options.CacheDuration, clock) : null;
        }

        /// <summary>Checks every option; throws <see cref="ArgumentException"/> naming the first bad one.</summary>
        internal static void Validate(PwnedPasswordsOptions options)
        {
            if (options == null) throw new ArgumentNullException(nameof(options));

            Uri? baseAddress = options.BaseAddress;
            if (baseAddress == null || !baseAddress.IsAbsoluteUri)
                throw new ArgumentException("BaseAddress must be an absolute URI.", nameof(options));
            bool https = string.Equals(baseAddress.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase);
            bool http = string.Equals(baseAddress.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase);
            if (!https && !(http && options.AllowInsecureHttp))
                throw new ArgumentException(http
                    ? "BaseAddress must use https; set AllowInsecureHttp to permit http."
                    : "BaseAddress must use https.", nameof(options));
            if (baseAddress.Query.Length > 0 || baseAddress.Fragment.Length > 0 || baseAddress.UserInfo.Length > 0)
                throw new ArgumentException("BaseAddress must not contain user info, a query or a fragment.", nameof(options));

            if (options.Timeout <= TimeSpan.Zero || options.Timeout > PwnedPasswordsOptions.MaxTimeout)
                throw new ArgumentException("Timeout must be greater than zero and at most 5 minutes.", nameof(options));

            if (!IsValidUserAgent(options.UserAgent))
                throw new ArgumentException("UserAgent must be a non-empty, valid User-Agent header value.", nameof(options));

            if (options.FailureMode != PwnedPasswordsFailureMode.FailOpen && options.FailureMode != PwnedPasswordsFailureMode.Throw)
                throw new ArgumentException("FailureMode is not a defined value.", nameof(options));

            if (options.MinimumOccurrences < 1)
                throw new ArgumentException("MinimumOccurrences must be at least 1.", nameof(options));

            if (options.EnableCache)
            {
                if (options.CacheDuration <= TimeSpan.Zero || options.CacheDuration > PwnedPasswordsOptions.MaxCacheDuration)
                    throw new ArgumentException("CacheDuration must be greater than zero and at most 7 days.", nameof(options));
                if (options.CacheMaxEntries < 1 || options.CacheMaxEntries > PwnedPasswordsOptions.MaxCacheEntriesLimit)
                    throw new ArgumentException("CacheMaxEntries must be between 1 and 100000.", nameof(options));
            }
        }

        private static bool IsValidUserAgent(string? value)
        {
            if (value == null || value.Trim().Length == 0 || value.Length > 512)
                return false;
            foreach (char c in value)
            {
                if (c < 0x20 || c > 0x7E)
                    return false;
            }
            using (var probe = new HttpRequestMessage())
                return probe.Headers.UserAgent.TryParseAdd(value.Trim());
        }

        private static Uri WithTrailingSlash(Uri uri)
        {
            if (uri.AbsolutePath.EndsWith("/", StringComparison.Ordinal))
                return uri;
            var builder = new UriBuilder(uri);
            builder.Path += "/";
            return builder.Uri;
        }
    }
}
