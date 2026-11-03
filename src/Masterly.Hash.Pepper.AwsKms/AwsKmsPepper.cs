using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Amazon.KeyManagementService;
using Amazon.KeyManagementService.Model;
using Amazon.Runtime;
using Masterly.Hash.Primitives;

namespace Masterly.Hash.Pepper.AwsKms
{
    /// <summary>
    /// Pepper computed by AWS KMS <c>GenerateMac</c> (<c>HMAC_SHA_256</c>) on an HMAC KMS key. The key never leaves
    /// KMS. The password-derived pepper input is sent to KMS over TLS for every hash and verify.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Pepper key ids are mapped to KMS keys by <see cref="AwsKmsPepperOptions.Keys"/>. HMAC KMS keys do not support
    /// automatic rotation. To rotate, create a new HMAC key, add it under a new pepper key id and make that id current.
    /// Hashes made with older ids keep verifying and are flagged for rehash.
    /// </para>
    /// <para>
    /// Every failure to obtain the MAC throws <see cref="PepperUnavailableException"/>: a KMS error, throttling,
    /// access denied, a disabled key, a network failure, a timeout or an unusable response. Messages never contain the input.
    /// </para>
    /// <para>
    /// <see cref="ApplyAsync"/> is the real implementation. <see cref="Apply"/> blocks on it (sync-over-async on a
    /// thread-pool thread, with <c>ConfigureAwait(false)</c> throughout); prefer the async hasher API with this pepper.
    /// </para>
    /// <para>Thread-safe. The KMS client is not disposed by this class.</para>
    /// </remarks>
    public sealed class AwsKmsPepper : IPasswordPepper
    {
        /// <summary>Length in bytes of an <c>HMAC_SHA_256</c> MAC.</summary>
        public const int MacLength = 32;

        /// <summary>Largest message KMS <c>GenerateMac</c> accepts, in bytes.</summary>
        public const int MaxInputBytes = 4096;


        private readonly IAmazonKeyManagementService _kms;
        private readonly Dictionary<string, string> _keys;
        private readonly List<string> _grantTokens;
        private readonly TimeSpan _timeout;

        /// <summary>Creates the pepper. Validates and copies <paramref name="options"/>; later changes to it have no effect.</summary>
        /// <param name="kms">KMS client, e.g. <c>new AmazonKeyManagementServiceClient()</c> or one resolved from DI. Not disposed by this class.</param>
        /// <param name="options">Key map, current key id and timeout.</param>
        /// <exception cref="ArgumentNullException"><paramref name="kms"/> or <paramref name="options"/> is null.</exception>
        /// <exception cref="ArgumentException">The options are invalid.</exception>
        public AwsKmsPepper(IAmazonKeyManagementService kms, AwsKmsPepperOptions options)
        {
            if (kms == null) throw new ArgumentNullException(nameof(kms));
            if (options == null) throw new ArgumentNullException(nameof(options));

            _keys = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (KeyValuePair<string, string> pair in options.Keys)
            {
                if (pair.Key == null || !HashPrimitives.IsValidKeyId(pair.Key))
                    throw new ArgumentException($"Pepper key id '{pair.Key}' must match ^[A-Za-z0-9-]{{1,32}}$.", nameof(options));
                if (!IsValidKmsKey(pair.Value))
                    throw new ArgumentException($"KMS key for pepper key id '{pair.Key}' must be a non-empty key ARN, key id or alias without whitespace.", nameof(options));
                _keys[pair.Key] = pair.Value;
            }

            if (options.CurrentKeyId == null || !_keys.ContainsKey(options.CurrentKeyId))
                throw new ArgumentException("CurrentKeyId is required and must be a key in Keys.", nameof(options));

            _grantTokens = new List<string>();
            foreach (string token in options.GrantTokens)
            {
                if (string.IsNullOrEmpty(token))
                    throw new ArgumentException("GrantTokens cannot contain null or empty entries.", nameof(options));
                _grantTokens.Add(token);
            }

            if (options.Timeout <= TimeSpan.Zero || options.Timeout > TimeSpan.FromMinutes(10))
                throw new ArgumentException("Timeout must be greater than zero and at most 10 minutes.", nameof(options));

            _kms = kms;
            _timeout = options.Timeout;
            CurrentKeyId = options.CurrentKeyId;
        }

        /// <inheritdoc />
        public string CurrentKeyId { get; }

        /// <inheritdoc />
        /// <remarks>True if <paramref name="keyId"/> is in the configured key map. Makes no network call.</remarks>
        public bool IsKnownKey(string keyId) => keyId != null && _keys.ContainsKey(keyId);

        /// <inheritdoc />
        /// <remarks>Blocks the calling thread on <see cref="ApplyAsync"/>. Prefer the hasher's async methods.</remarks>
        /// <exception cref="PepperUnavailableException">KMS could not compute the MAC.</exception>
        public byte[] Apply(string keyId, byte[] input)
        {
            if (input == null) throw new ArgumentNullException(nameof(input));
            return Task.Run(() => ApplyAsync(keyId, input, CancellationToken.None).AsTask()).GetAwaiter().GetResult();
        }

        /// <inheritdoc />
        /// <exception cref="ArgumentNullException"><paramref name="input"/> is null.</exception>
        /// <exception cref="ArgumentException"><paramref name="input"/> is empty or longer than <see cref="MaxInputBytes"/>.</exception>
        /// <exception cref="KeyNotFoundException"><paramref name="keyId"/> is not in the key map.</exception>
        /// <exception cref="PepperUnavailableException">KMS could not compute the MAC.</exception>
        /// <exception cref="OperationCanceledException"><paramref name="cancellationToken"/> was cancelled.</exception>
        public async ValueTask<byte[]> ApplyAsync(string keyId, byte[] input, CancellationToken cancellationToken = default)
        {
            if (input == null) throw new ArgumentNullException(nameof(input));
            if (keyId == null || !_keys.TryGetValue(keyId, out string? kmsKey))
                throw new KeyNotFoundException($"Unknown pepper key '{keyId}'.");
            if (input.Length == 0 || input.Length > MaxInputBytes)
                throw new ArgumentException(
                    $"KMS GenerateMac accepts 1 to {MaxInputBytes} bytes; keep PasswordHasherOptions.MaxPasswordBytes at or below {MaxInputBytes}.",
                    nameof(input));
            cancellationToken.ThrowIfCancellationRequested();

            var request = new GenerateMacRequest
            {
                KeyId = kmsKey,
                MacAlgorithm = MacAlgorithmSpec.HMAC_SHA_256,
                Message = new MemoryStream(input, 0, input.Length, writable: false, publiclyVisible: true),
            };
            if (_grantTokens.Count > 0)
                request.GrantTokens = new List<string>(_grantTokens);

            using (var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
            {
                timeout.CancelAfter(_timeout);
                GenerateMacResponse? response;
                try
                {
                    response = await _kms.GenerateMacAsync(request, timeout.Token).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
                {
                    throw new PepperUnavailableException("AWS KMS did not answer within the configured timeout.");
                }
                catch (AmazonServiceException ex)
                {
                    throw new PepperUnavailableException($"AWS KMS GenerateMac failed ({SafeCode(ex.ErrorCode)}, HTTP {(int)ex.StatusCode}).", ex);
                }
                catch (AmazonClientException ex)
                {
                    throw new PepperUnavailableException("AWS KMS GenerateMac failed on the client side (credentials, configuration or network).", ex);
                }
                catch (HttpRequestException ex)
                {
                    throw new PepperUnavailableException("AWS KMS could not be reached.", ex);
                }
                catch (IOException ex)
                {
                    throw new PepperUnavailableException("The connection to AWS KMS failed.", ex);
                }
                catch (TimeoutException ex)
                {
                    // AWSSDK.Core unwraps its own HttpClient timeout into a TimeoutException.
                    throw new PepperUnavailableException("AWS KMS did not answer within the SDK client timeout.", ex);
                }
                catch (Exception ex) when (!(ex is OperationCanceledException) && !(ex is PepperUnavailableException))
                {
                    // Any other SDK pipeline failure (e.g. a disposed client) still honours the documented contract.
                    throw new PepperUnavailableException("AWS KMS GenerateMac failed.", ex);
                }
                finally
                {
                    request.Message.Dispose();
                }

                return ExtractMac(response);
            }
        }

        private static byte[] ExtractMac(GenerateMacResponse? response)
        {
            MemoryStream? mac = response?.Mac;
            if (mac == null)
                throw new PepperUnavailableException("AWS KMS returned no MAC.");
            try
            {
                if (response!.MacAlgorithm != null && response.MacAlgorithm != MacAlgorithmSpec.HMAC_SHA_256)
                    throw new PepperUnavailableException("AWS KMS answered with a different MAC algorithm than requested.");
                if (mac.Length != MacLength)
                    throw new PepperUnavailableException("AWS KMS returned a MAC of unexpected length.");
                return mac.ToArray();
            }
            finally
            {
                if (mac.TryGetBuffer(out ArraySegment<byte> buffer) && buffer.Array != null)
                    Array.Clear(buffer.Array, buffer.Offset, buffer.Count);
                mac.Dispose();
            }
        }

        private static bool IsValidKmsKey(string? key)
        {
            if (key == null || key.Length == 0 || key.Length > 2048)
                return false;
            foreach (char c in key)
            {
                if (c <= ' ' || c > '~')
                    return false;
            }
            return true;
        }

        private static string SafeCode(string? code)
        {
            if (string.IsNullOrEmpty(code))
                return "unknown error";
            foreach (char c in code!)
            {
                bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-';
                if (!ok)
                    return "unknown error";
            }
            return code.Length > 64 ? code.Substring(0, 64) : code;
        }
    }
}
