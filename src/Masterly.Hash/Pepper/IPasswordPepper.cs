using System.Threading;
using System.Threading.Tasks;

namespace Masterly.Hash.Pepper
{
    /// <summary>
    /// A server-side secret mixed into every password before hashing, so a stolen database cannot be attacked
    /// offline without it. Each key has an id that is stored in the hash, which allows rotation:
    /// hashes made with an older key keep verifying and are flagged for rehash.
    /// </summary>
    /// <remarks>
    /// Implementations backed by a remote service (HashiCorp Vault, AWS KMS) should prefer the async
    /// <see cref="ApplyAsync"/>; the synchronous <see cref="Apply"/> may block.
    /// </remarks>
    public interface IPasswordPepper
    {
        /// <summary>Key id used for new hashes. Must match <c>^[A-Za-z0-9-]{1,32}$</c>.</summary>
        string CurrentKeyId { get; }

        /// <summary>True if hashes made with <paramref name="keyId"/> can still be verified.</summary>
        bool IsKnownKey(string keyId);

        /// <summary>Returns a keyed, deterministic transform of <paramref name="input"/> (typically HMAC-SHA256).</summary>
        byte[] Apply(string keyId, byte[] input);

        /// <summary>Async variant of <see cref="Apply"/>.</summary>
        ValueTask<byte[]> ApplyAsync(string keyId, byte[] input, CancellationToken cancellationToken = default);
    }
}
