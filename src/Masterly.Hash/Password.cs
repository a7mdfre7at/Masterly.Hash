using System.Threading;
using System.Threading.Tasks;

namespace Masterly.Hash
{
    /// <summary>
    /// The two-method API. Uses <see cref="PasswordHasher.Default"/>: Argon2id with <see cref="HashProfile.Server2026a"/>,
    /// no pepper, 1.x hashes accepted and upgraded.
    /// </summary>
    /// <example>
    /// <code>
    /// string stored = Password.Hash("hunter2");
    /// var result = Password.Verify("hunter2", stored);
    /// if (result.IsMatch &amp;&amp; result.Rehash is { } fresh)
    ///     user.PasswordHash = fresh;
    /// </code>
    /// </example>
    public static class Password
    {
        /// <summary>Hashes a password with the default profile.</summary>
        public static string Hash(string password) => PasswordHasher.Default.Hash(password);

        /// <summary>Hashes a password with a built-in profile, e.g. <see cref="HashProfile.Constrained2026a"/>.</summary>
        public static string Hash(string password, HashProfile profile) => PasswordHasher.Default.Hash(password, profile);

        /// <summary>Hashes a password with the default profile.</summary>
        public static string Hash(SensitiveString password) => PasswordHasher.Default.Hash(password.Reveal());

        /// <summary>Verifies a password. Check <see cref="PasswordVerificationResult.Rehash"/> to upgrade old hashes.</summary>
        public static PasswordVerificationResult Verify(string password, string storedHash) => PasswordHasher.Default.Verify(password, storedHash);

        /// <summary>Verifies a password.</summary>
        public static PasswordVerificationResult Verify(SensitiveString password, string storedHash) => PasswordHasher.Default.Verify(password.Reveal(), storedHash);

        /// <summary>Verifies a password, spending the same time when the user does not exist (<paramref name="storedHash"/> is null).</summary>
        public static PasswordVerificationResult VerifyOrDummy(string password, string? storedHash) => PasswordHasher.Default.VerifyOrDummy(password, storedHash);

        /// <summary>Async <see cref="Hash(string)"/>.</summary>
        public static ValueTask<string> HashAsync(string password, CancellationToken cancellationToken = default) =>
            PasswordHasher.Default.HashAsync(password, cancellationToken);

        /// <summary>Async <see cref="Verify(string, string)"/>.</summary>
        public static ValueTask<PasswordVerificationResult> VerifyAsync(string password, string storedHash, CancellationToken cancellationToken = default) =>
            PasswordHasher.Default.VerifyAsync(password, storedHash, cancellationToken);

        /// <summary>Async <see cref="VerifyOrDummy"/>.</summary>
        public static ValueTask<PasswordVerificationResult> VerifyOrDummyAsync(string password, string? storedHash, CancellationToken cancellationToken = default) =>
            PasswordHasher.Default.VerifyOrDummyAsync(password, storedHash, cancellationToken);

        /// <summary>True if a successful login would replace this stored hash.</summary>
        public static bool NeedsRehash(string storedHash) => PasswordHasher.Default.NeedsRehash(storedHash);

        /// <summary>Describes a stored hash without verifying it.</summary>
        public static HashInfo Inspect(string storedHash) => PasswordHasher.Default.Inspect(storedHash);
    }
}
