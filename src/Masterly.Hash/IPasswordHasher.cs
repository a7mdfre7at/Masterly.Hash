using System.Threading;
using System.Threading.Tasks;

namespace Masterly.Hash
{
    /// <summary>Hashes and verifies passwords. <see cref="PasswordHasher"/> is the implementation.</summary>
    public interface IPasswordHasher
    {
        /// <summary>Hashes a password with the default profile and current pepper key.</summary>
        string Hash(string password);

        /// <summary>Hashes a password with a specific registered profile.</summary>
        string Hash(string password, HashProfile profile);

        /// <summary>Verifies a password against a stored hash. Never throws for a bad stored hash; see <see cref="PasswordVerificationResult.FailureReason"/>.</summary>
        PasswordVerificationResult Verify(string password, string storedHash);

        /// <summary>
        /// Like <see cref="Verify"/>, but when <paramref name="storedHash"/> is null (unknown user) it still spends the
        /// same time verifying against a dummy hash, so response timing does not reveal which accounts exist.
        /// </summary>
        PasswordVerificationResult VerifyOrDummy(string password, string? storedHash);

        /// <summary>Async <see cref="Hash(string)"/>; waits asynchronously for a slot and supports remote peppers.</summary>
        ValueTask<string> HashAsync(string password, CancellationToken cancellationToken = default);

        /// <summary>Async <see cref="Verify"/>.</summary>
        ValueTask<PasswordVerificationResult> VerifyAsync(string password, string storedHash, CancellationToken cancellationToken = default);

        /// <summary>Async <see cref="VerifyOrDummy"/>.</summary>
        ValueTask<PasswordVerificationResult> VerifyOrDummyAsync(string password, string? storedHash, CancellationToken cancellationToken = default);

        /// <summary>True if a successful login with this stored hash would produce a rehash. Does not verify.</summary>
        bool NeedsRehash(string storedHash);

        /// <summary>Describes a stored hash without verifying it.</summary>
        HashInfo Inspect(string storedHash);

        /// <summary>
        /// Onion-wraps a legacy hash offline: <c>Argon2id(legacyDigest)</c>. The wrapped hash verifies with the original
        /// password and is upgraded to a plain hash on the next login. Returns false if no registered format can wrap it.
        /// </summary>
        bool TryWrap(string legacyHash, out string wrappedHash);
    }
}
