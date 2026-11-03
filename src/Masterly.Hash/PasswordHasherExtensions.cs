using System;
using System.Threading;
using System.Threading.Tasks;

namespace Masterly.Hash
{
    /// <summary><see cref="SensitiveString"/> overloads for <see cref="IPasswordHasher"/>.</summary>
    public static class PasswordHasherExtensions
    {
        /// <summary>Hashes a password.</summary>
        public static string Hash(this IPasswordHasher hasher, SensitiveString password) =>
            Checked(hasher).Hash(Reveal(password));

        /// <summary>Verifies a password.</summary>
        public static PasswordVerificationResult Verify(this IPasswordHasher hasher, SensitiveString password, string storedHash) =>
            Checked(hasher).Verify(Reveal(password), storedHash);

        /// <summary>Verifies a password with user-enumeration protection.</summary>
        public static PasswordVerificationResult VerifyOrDummy(this IPasswordHasher hasher, SensitiveString password, string? storedHash) =>
            Checked(hasher).VerifyOrDummy(Reveal(password), storedHash);

        /// <summary>Async hash.</summary>
        public static ValueTask<string> HashAsync(this IPasswordHasher hasher, SensitiveString password, CancellationToken cancellationToken = default) =>
            Checked(hasher).HashAsync(Reveal(password), cancellationToken);

        /// <summary>Async verify.</summary>
        public static ValueTask<PasswordVerificationResult> VerifyAsync(this IPasswordHasher hasher, SensitiveString password, string storedHash, CancellationToken cancellationToken = default) =>
            Checked(hasher).VerifyAsync(Reveal(password), storedHash, cancellationToken);

        /// <summary>Async verify with user-enumeration protection.</summary>
        public static ValueTask<PasswordVerificationResult> VerifyOrDummyAsync(this IPasswordHasher hasher, SensitiveString password, string? storedHash, CancellationToken cancellationToken = default) =>
            Checked(hasher).VerifyOrDummyAsync(Reveal(password), storedHash, cancellationToken);

        private static IPasswordHasher Checked(IPasswordHasher hasher) => hasher ?? throw new ArgumentNullException(nameof(hasher));

        private static string Reveal(SensitiveString password) =>
            (password ?? throw new ArgumentNullException(nameof(password))).Reveal();
    }
}
