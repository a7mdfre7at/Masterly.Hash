using System;
using System.Buffers;
using System.Buffers.Text;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Masterly.Hash.Primitives;

namespace Masterly.Hash.Pepper.HashiCorpVault
{
    /// <summary>
    /// Pepper computed by the HashiCorp Vault Transit secrets engine (<c>POST /v1/{mount}/hmac/{key}/sha2-256</c>).
    /// The HMAC key never leaves Vault; the password-derived pepper input is sent to Vault over TLS for every
    /// hash and verify, which is how Transit works.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Pepper key ids map to Transit key versions: <c>v1</c> is version 1, <c>v2</c> is version 2, and so on.
    /// New hashes use <see cref="HashiCorpVaultPepperOptions.CurrentKeyVersion"/>; hashes made with any version between
    /// <see cref="HashiCorpVaultPepperOptions.MinKeyVersion"/> and <see cref="HashiCorpVaultPepperOptions.MaxKeyVersion"/>
    /// keep verifying and are flagged for rehash. Rotate the Transit key, then raise <c>CurrentKeyVersion</c>.
    /// </para>
    /// <para>
    /// Every failure to obtain the HMAC (Vault unreachable, timeout, HTTP error, malformed response) throws
    /// <see cref="PepperUnavailableException"/>. Messages never contain the token, the input or the HMAC.
    /// </para>
    /// <para>
    /// <see cref="ApplyAsync"/> is the real implementation. <see cref="Apply"/> blocks on it (sync-over-async on a
    /// thread-pool thread, with <c>ConfigureAwait(false)</c> throughout); prefer the async hasher API with this pepper.
    /// </para>
    /// <para>Thread-safe. The <see cref="HttpClient"/> is not disposed by this class.</para>
    /// </remarks>
    public sealed class HashiCorpVaultPepper : IPasswordPepper
    {
        /// <summary>Length in bytes of a Transit <c>sha2-256</c> HMAC.</summary>
        public const int HmacLength = 32;

        /// <summary>Largest response body accepted from Vault, so a misbehaving endpoint cannot exhaust memory.</summary>
        internal const int MaxResponseBytes = 64 * 1024;

        private static readonly MediaTypeHeaderValue JsonMediaType = new MediaTypeHeaderValue("application/json");
        private static readonly byte[] BodyPrefix = Encoding.ASCII.GetBytes("{\"input\":\"");
        private static readonly byte[] BodyMiddle = Encoding.ASCII.GetBytes("\",\"key_version\":");
        private static readonly byte[] HmacPrefix = Encoding.ASCII.GetBytes("vault:v");

        private readonly HttpClient _http;
        private readonly Uri _endpoint;
        private readonly string? _token;
        private readonly Func<CancellationToken, Task<string>>? _tokenProvider;
        private readonly string? _namespace;
        private readonly int _minVersion;
        private readonly int _maxVersion;
        private readonly TimeSpan _timeout;

        /// <summary>Creates the pepper. Validates and copies <paramref name="options"/>; later changes to it have no effect.</summary>
        /// <param name="httpClient">Client used for Vault requests. Typically from <c>IHttpClientFactory</c>; not disposed by this class.</param>
        /// <param name="options">Vault address, mount, key, token and key-version range.</param>
        /// <exception cref="ArgumentNullException"><paramref name="httpClient"/> or <paramref name="options"/> is null.</exception>
        /// <exception cref="ArgumentException">The options are invalid.</exception>
        public HashiCorpVaultPepper(HttpClient httpClient, HashiCorpVaultPepperOptions options)
        {
            if (httpClient == null) throw new ArgumentNullException(nameof(httpClient));
            if (options == null) throw new ArgumentNullException(nameof(options));

            _endpoint = BuildEndpoint(options);

            if ((options.Token == null) == (options.TokenProvider == null))
                throw new ArgumentException("Set exactly one of Token and TokenProvider.", nameof(options));
            if (options.Token != null && !IsValidHeaderValue(options.Token))
                throw new ArgumentException("Token must be non-empty printable ASCII without spaces.", nameof(options));
            if (options.Namespace != null && (options.Namespace.Length > 256 || !IsValidHeaderValue(options.Namespace)))
                throw new ArgumentException("Namespace must be 1-256 printable ASCII characters without spaces.", nameof(options));

            if (options.CurrentKeyVersion < 1)
                throw new ArgumentException("CurrentKeyVersion must be at least 1.", nameof(options));
            if (options.MinKeyVersion < 1 || options.MinKeyVersion > options.CurrentKeyVersion)
                throw new ArgumentException("MinKeyVersion must be between 1 and CurrentKeyVersion.", nameof(options));
            int max = options.MaxKeyVersion ?? options.CurrentKeyVersion;
            if (max < options.CurrentKeyVersion)
                throw new ArgumentException("MaxKeyVersion must not be below CurrentKeyVersion.", nameof(options));
            if (options.Timeout <= TimeSpan.Zero || options.Timeout > TimeSpan.FromMinutes(10))
                throw new ArgumentException("Timeout must be greater than zero and at most 10 minutes.", nameof(options));

            _http = httpClient;
            _token = options.Token;
            _tokenProvider = options.TokenProvider;
            _namespace = options.Namespace;
            _minVersion = options.MinKeyVersion;
            _maxVersion = max;
            _timeout = options.Timeout;
            CurrentKeyId = KeyIdFor(options.CurrentKeyVersion);
        }

        /// <inheritdoc />
        public string CurrentKeyId { get; }

        /// <summary>The Transit HMAC endpoint this pepper calls.</summary>
        public Uri Endpoint => _endpoint;

        /// <summary>Returns the pepper key id for a Transit key version, e.g. <c>v3</c> for version 3.</summary>
        /// <exception cref="ArgumentOutOfRangeException"><paramref name="version"/> is below 1.</exception>
        public static string KeyIdFor(int version)
        {
            if (version < 1) throw new ArgumentOutOfRangeException(nameof(version), version, "Transit key versions start at 1.");
            return "v" + version.ToString(CultureInfo.InvariantCulture);
        }

        /// <summary>Parses a pepper key id of the form <c>v{N}</c> (no leading zeros) into a Transit key version.</summary>
        public static bool TryParseKeyId(string? keyId, out int version)
        {
            version = 0;
            if (keyId == null || keyId.Length < 2 || keyId.Length > 11 || keyId[0] != 'v' || keyId[1] == '0')
                return false;
            long value = 0;
            for (int i = 1; i < keyId.Length; i++)
            {
                char c = keyId[i];
                if (c < '0' || c > '9')
                    return false;
                value = (value * 10) + (c - '0');
                if (value > int.MaxValue)
                    return false;
            }
            version = (int)value;
            return true;
        }

        /// <inheritdoc />
        /// <remarks>True for <c>v{N}</c> with N between the configured minimum and maximum key versions. Makes no network call.</remarks>
        public bool IsKnownKey(string keyId) =>
            TryParseKeyId(keyId, out int version) && version >= _minVersion && version <= _maxVersion;

        /// <inheritdoc />
        /// <remarks>Blocks the calling thread on <see cref="ApplyAsync"/>. Prefer the hasher's async methods.</remarks>
        /// <exception cref="PepperUnavailableException">Vault could not compute the HMAC.</exception>
        public byte[] Apply(string keyId, byte[] input)
        {
            if (input == null) throw new ArgumentNullException(nameof(input));
            return Task.Run(() => ApplyAsync(keyId, input, CancellationToken.None).AsTask()).GetAwaiter().GetResult();
        }

        /// <inheritdoc />
        /// <exception cref="ArgumentNullException"><paramref name="input"/> is null.</exception>
        /// <exception cref="KeyNotFoundException"><paramref name="keyId"/> is not a known key version.</exception>
        /// <exception cref="PepperUnavailableException">Vault could not compute the HMAC.</exception>
        /// <exception cref="OperationCanceledException"><paramref name="cancellationToken"/> was cancelled.</exception>
        public async ValueTask<byte[]> ApplyAsync(string keyId, byte[] input, CancellationToken cancellationToken = default)
        {
            if (input == null) throw new ArgumentNullException(nameof(input));
            if (!TryParseKeyId(keyId, out int version) || version < _minVersion || version > _maxVersion)
                throw new KeyNotFoundException($"Unknown pepper key '{keyId}'.");
            cancellationToken.ThrowIfCancellationRequested();

            using (var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
            {
                timeout.CancelAfter(_timeout);
                byte[]? body = null;
                try
                {
                    string token = await GetTokenAsync(timeout.Token).ConfigureAwait(false);
                    body = BuildBody(input, version);
                    return await SendAsync(body, token, version, timeout.Token).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
                {
                    throw new PepperUnavailableException("HashiCorp Vault did not answer within the configured timeout.");
                }
                catch (HttpRequestException ex)
                {
                    throw new PepperUnavailableException("HashiCorp Vault could not be reached.", ex);
                }
                catch (IOException ex)
                {
                    throw new PepperUnavailableException("The connection to HashiCorp Vault failed.", ex);
                }
                catch (Exception ex) when (!(ex is OperationCanceledException) && !(ex is PepperUnavailableException))
                {
                    // Anything else from the injected HttpClient pipeline (resilience handlers, custom
                    // DelegatingHandlers, a disposed client) still honours the documented contract.
                    throw new PepperUnavailableException("HashiCorp Vault request failed.", ex);
                }
                finally
                {
                    HashPrimitives.Zero(body);
                }
            }
        }

        private async Task<byte[]> SendAsync(byte[] body, string token, int version, CancellationToken ct)
        {
            using (var request = new HttpRequestMessage(HttpMethod.Post, _endpoint))
            {
                request.Headers.TryAddWithoutValidation("X-Vault-Token", token);
                if (_namespace != null)
                    request.Headers.TryAddWithoutValidation("X-Vault-Namespace", _namespace);
                var content = new ByteArrayContent(body);
                content.Headers.ContentType = JsonMediaType;
                request.Content = content;

                using (HttpResponseMessage response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false))
                {
                    if (!response.IsSuccessStatusCode)
                        throw new PepperUnavailableException(
                            "HashiCorp Vault refused the Transit HMAC request with HTTP " +
                            ((int)response.StatusCode).ToString(CultureInfo.InvariantCulture) + ".");

                    byte[] payload = await ReadLimitedAsync(response.Content, ct).ConfigureAwait(false);
                    try
                    {
                        return ParseHmac(payload, version);
                    }
                    finally
                    {
                        HashPrimitives.Zero(payload);
                    }
                }
            }
        }

        private async Task<string> GetTokenAsync(CancellationToken ct)
        {
            if (_tokenProvider == null)
                return _token!;

            string token;
            try
            {
                token = await _tokenProvider(ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                throw new PepperUnavailableException("The Vault token provider failed.", ex);
            }

            if (token == null || !IsValidHeaderValue(token))
                throw new PepperUnavailableException("The Vault token provider returned an empty or invalid token.");
            return token;
        }

        /// <summary>Builds <c>{"input":"&lt;b64&gt;","key_version":N}</c> into a single zeroable buffer.</summary>
        internal static byte[] BuildBody(byte[] input, int version)
        {
            byte[] versionBytes = Encoding.ASCII.GetBytes(version.ToString(CultureInfo.InvariantCulture));
            int b64Length = Base64.GetMaxEncodedToUtf8Length(input.Length);
            var body = new byte[BodyPrefix.Length + b64Length + BodyMiddle.Length + versionBytes.Length + 1];
            int pos = 0;
            Buffer.BlockCopy(BodyPrefix, 0, body, pos, BodyPrefix.Length);
            pos += BodyPrefix.Length;
            OperationStatus status = Base64.EncodeToUtf8(input, body.AsSpan(pos, b64Length), out _, out int written);
            if (status != OperationStatus.Done || written != b64Length)
                throw new InvalidOperationException("Base64 encoding failed.");
            pos += written;
            Buffer.BlockCopy(BodyMiddle, 0, body, pos, BodyMiddle.Length);
            pos += BodyMiddle.Length;
            Buffer.BlockCopy(versionBytes, 0, body, pos, versionBytes.Length);
            pos += versionBytes.Length;
            body[pos] = (byte)'}';
            return body;
        }

        /// <summary>
        /// Extracts the raw HMAC from a Transit response <c>{"data":{"hmac":"vault:vN:&lt;b64&gt;"}}</c>, checking that
        /// N is the requested version. Works on UTF-8 bytes so no password-derived string is created.
        /// </summary>
        internal static byte[] ParseHmac(ReadOnlySpan<byte> payload, int expectedVersion)
        {
            byte[]? hmacField = null;
            try
            {
                var reader = new Utf8JsonReader(payload, new JsonReaderOptions { MaxDepth = 16 });
                if (!reader.Read() || reader.TokenType != JsonTokenType.StartObject)
                    throw Unexpected();

                while (reader.Read() && reader.TokenType == JsonTokenType.PropertyName)
                {
                    bool isData = reader.ValueTextEquals("data");
                    if (!reader.Read())
                        throw Unexpected();
                    if (isData && reader.TokenType == JsonTokenType.StartObject)
                    {
                        while (reader.Read() && reader.TokenType == JsonTokenType.PropertyName)
                        {
                            bool isHmac = reader.ValueTextEquals("hmac");
                            if (!reader.Read())
                                throw Unexpected();
                            if (isHmac && reader.TokenType == JsonTokenType.String && !reader.ValueIsEscaped && !reader.HasValueSequence)
                            {
                                HashPrimitives.Zero(hmacField);
                                hmacField = reader.ValueSpan.ToArray();
                            }
                            else
                            {
                                reader.Skip();
                            }
                        }
                        if (reader.TokenType != JsonTokenType.EndObject)
                            throw Unexpected();
                    }
                    else
                    {
                        reader.Skip();
                    }
                }

                // The root object must be closed and nothing may follow it.
                if (reader.TokenType != JsonTokenType.EndObject || reader.CurrentDepth != 0 || reader.Read())
                    throw Unexpected();
            }
            catch (JsonException)
            {
                throw Unexpected();
            }

            if (hmacField == null)
                throw Unexpected();
            try
            {
                return DecodeHmacField(hmacField, expectedVersion);
            }
            finally
            {
                HashPrimitives.Zero(hmacField);
            }
        }

        private static byte[] DecodeHmacField(byte[] field, int expectedVersion)
        {
            ReadOnlySpan<byte> span = field;
            if (!span.StartsWith(HmacPrefix))
                throw Unexpected();
            span = span.Slice(HmacPrefix.Length);

            int colon = span.IndexOf((byte)':');
            if (colon < 1 || colon > 10 || span[0] == (byte)'0')
                throw Unexpected();
            long version = 0;
            for (int i = 0; i < colon; i++)
            {
                byte c = span[i];
                if (c < (byte)'0' || c > (byte)'9')
                    throw Unexpected();
                version = (version * 10) + (c - '0');
            }
            if (version != expectedVersion)
                throw new PepperUnavailableException("HashiCorp Vault answered with a different key version than requested.");

            ReadOnlySpan<byte> b64 = span.Slice(colon + 1);
            if (b64.Length != Base64.GetMaxEncodedToUtf8Length(HmacLength))
                throw Unexpected();
            var decoded = new byte[Base64.GetMaxDecodedFromUtf8Length(b64.Length)];
            try
            {
                OperationStatus status = Base64.DecodeFromUtf8(b64, decoded, out int consumed, out int written);
                if (status != OperationStatus.Done || consumed != b64.Length || written != HmacLength)
                    throw Unexpected();
                var result = new byte[HmacLength];
                Buffer.BlockCopy(decoded, 0, result, 0, HmacLength);
                return result;
            }
            finally
            {
                HashPrimitives.Zero(decoded);
            }
        }

        private static async Task<byte[]> ReadLimitedAsync(HttpContent content, CancellationToken ct)
        {
            long? declared = content.Headers.ContentLength;
            if (declared > MaxResponseBytes)
                throw new PepperUnavailableException("HashiCorp Vault returned an oversized response.");

            using (Stream stream = await content.ReadAsStreamAsync(ct).ConfigureAwait(false))
            {
                // One spare byte past the limit: a response of exactly MaxResponseBytes fits, and filling the spare
                // byte means there is more. (declared <= MaxResponseBytes was checked above.)
                var buffer = new byte[declared > 0 ? (int)declared.Value + 1 : 1024];
                int length = 0;
                while (true)
                {
                    if (length == buffer.Length)
                    {
                        if (length > MaxResponseBytes)
                        {
                            HashPrimitives.Zero(buffer);
                            throw new PepperUnavailableException("HashiCorp Vault returned an oversized response.");
                        }
                        var larger = new byte[Math.Min(buffer.Length * 2, MaxResponseBytes + 1)];
                        Buffer.BlockCopy(buffer, 0, larger, 0, length);
                        HashPrimitives.Zero(buffer);
                        buffer = larger;
                    }

                    int read = await stream.ReadAsync(buffer, length, buffer.Length - length, ct).ConfigureAwait(false);
                    if (read == 0)
                        break;
                    length += read;
                }

                var exact = new byte[length];
                Buffer.BlockCopy(buffer, 0, exact, 0, length);
                HashPrimitives.Zero(buffer);
                return exact;
            }
        }

        private static Uri BuildEndpoint(HashiCorpVaultPepperOptions options)
        {
            Uri? address = options.VaultAddress;
            if (address == null || !address.IsAbsoluteUri)
                throw new ArgumentException("VaultAddress must be an absolute URI.", nameof(options));
            if (address.Scheme != Uri.UriSchemeHttps && !(address.Scheme == Uri.UriSchemeHttp && options.AllowInsecureHttp))
                throw new ArgumentException("VaultAddress must use https (set AllowInsecureHttp only for local development).", nameof(options));
            if (address.Query.Length != 0 || address.Fragment.Length != 0 || address.UserInfo.Length != 0)
                throw new ArgumentException("VaultAddress must not contain user info, a query or a fragment.", nameof(options));

            string mount = (options.MountPath ?? string.Empty).Trim('/');
            string[] segments = mount.Split('/');
            if (mount.Length == 0)
                throw new ArgumentException("MountPath is required.", nameof(options));
            foreach (string segment in segments)
            {
                if (!IsValidPathSegment(segment))
                    throw new ArgumentException("MountPath segments may contain only letters, digits, '.', '_' and '-'.", nameof(options));
            }
            if (options.KeyName == null || !IsValidPathSegment(options.KeyName))
                throw new ArgumentException("KeyName is required and may contain only letters, digits, '.', '_' and '-'.", nameof(options));

            var path = new StringBuilder(address.AbsoluteUri.TrimEnd('/'));
            path.Append("/v1");
            foreach (string segment in segments)
                path.Append('/').Append(Uri.EscapeDataString(segment));
            path.Append("/hmac/").Append(Uri.EscapeDataString(options.KeyName)).Append("/sha2-256");
            return new Uri(path.ToString(), UriKind.Absolute);
        }

        private static bool IsValidPathSegment(string segment)
        {
            if (segment.Length == 0 || segment.Length > 128 || segment == "." || segment == "..")
                return false;
            foreach (char c in segment)
            {
                bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-';
                if (!ok)
                    return false;
            }
            return true;
        }

        private static bool IsValidHeaderValue(string value)
        {
            if (value.Length == 0 || value.Length > 8192)
                return false;
            foreach (char c in value)
            {
                if (c <= ' ' || c > '~')
                    return false;
            }
            return true;
        }

        private static PepperUnavailableException Unexpected() =>
            new PepperUnavailableException("HashiCorp Vault returned an unexpected Transit HMAC response.");
    }
}
