using System;
using System.Globalization;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using IdentityVerificationResult = Microsoft.AspNetCore.Identity.PasswordVerificationResult;
using MasterlyHasher = Masterly.Hash.IPasswordHasher;
using MasterlyVerificationResult = Masterly.Hash.PasswordVerificationResult;

namespace Masterly.Hash.AspNetCore
{
    /// <summary>
    /// ASP.NET Core Identity <see cref="IPasswordHasher{TUser}"/> backed by a Masterly.Hash
    /// <see cref="Masterly.Hash.IPasswordHasher"/>. Register it with
    /// <c>services.AddIdentityCore&lt;TUser&gt;().AddMasterlyPasswordHasher()</c>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <see cref="UserManager{TUser}"/> re-hashes the password itself (by calling <see cref="HashPassword"/>) when
    /// verification returns <see cref="IdentityVerificationResult.SuccessRehashNeeded"/>, so the replacement hash that
    /// Masterly.Hash can compute during verification (<see cref="Masterly.Hash.PasswordVerificationResult.Rehash"/>) is ignored.
    /// Configure the hasher with <see cref="PasswordHasherOptions.ComputeRehashOnVerify"/> set to <c>false</c> (as
    /// <c>AddMasterlyPasswordHasher</c> does) so that hash is not computed for nothing.
    /// </para>
    /// <para>
    /// To keep existing users, the hasher must accept the hashes Identity wrote before the switch: register
    /// <see cref="Legacy.AspNetIdentityV3Format"/> and <see cref="Legacy.AspNetIdentityV2Format"/>
    /// (<see cref="AspNetIdentityPasswordHasherOptionsExtensions.AddAspNetIdentityFormats"/>; <c>AddMasterlyPasswordHasher</c>
    /// does this). They verify with <see cref="IdentityVerificationResult.SuccessRehashNeeded"/> and are replaced on the next login.
    /// </para>
    /// <para>
    /// <see cref="PasswordHasherBusyException"/> propagates when the hasher is at its concurrency limit; map it to HTTP 503
    /// with <c>services.AddMasterlyHashExceptionHandler()</c>.
    /// </para>
    /// <para>
    /// Passwords are length-checked before any normalization work, so an attacker-sized login value (for example a
    /// multi-megabyte form field of NFKC-expanding characters) is refused cheaply. A legacy hash that verifies but whose
    /// password cannot be re-hashed under <see cref="PasswordHasherOptions.MaxPasswordBytes"/> (legacy formats count raw
    /// UTF-8, new hashes count UTF-8 after NFKC) is reported as <see cref="IdentityVerificationResult.Success"/>, which
    /// keeps the still-valid legacy hash instead of making <see cref="UserManager{TUser}"/> re-hash and throw.
    /// </para>
    /// </remarks>
    /// <typeparam name="TUser">The Identity user type. The user is not used: Masterly hashes carry their own salt.</typeparam>
    public sealed class MasterlyIdentityPasswordHasher<TUser> : IPasswordHasher<TUser>
        where TUser : class
    {
        private readonly MasterlyHasher _hasher;
        private readonly int _maxPasswordBytes;

        /// <summary>
        /// Creates the adapter over <paramref name="hasher"/>, taking the password limit from the options the hasher was
        /// built from. This is the constructor dependency injection uses.
        /// </summary>
        /// <param name="hasher">The Masterly hasher.</param>
        /// <param name="options">The options <paramref name="hasher"/> was created with.</param>
        public MasterlyIdentityPasswordHasher(MasterlyHasher hasher, IOptions<PasswordHasherOptions> options)
            : this(hasher, (options ?? throw new ArgumentNullException(nameof(options))).Value.MaxPasswordBytes)
        {
        }

        /// <summary>Creates the adapter over <paramref name="hasher"/>.</summary>
        /// <param name="hasher">The Masterly hasher.</param>
        /// <param name="maxPasswordBytes">
        /// The <see cref="PasswordHasherOptions.MaxPasswordBytes"/> <paramref name="hasher"/> was created with (at least 1).
        /// </param>
        public MasterlyIdentityPasswordHasher(MasterlyHasher hasher, int maxPasswordBytes)
        {
            _hasher = hasher ?? throw new ArgumentNullException(nameof(hasher));
            if (maxPasswordBytes < 1)
                throw new ArgumentOutOfRangeException(nameof(maxPasswordBytes), maxPasswordBytes, "The limit must be positive.");
            _maxPasswordBytes = maxPasswordBytes;
        }

        /// <summary>Hashes <paramref name="password"/> with the hasher's default profile and current pepper key.</summary>
        /// <exception cref="ArgumentNullException"><paramref name="password"/> is null.</exception>
        /// <exception cref="ArgumentException">The password is empty or longer than <see cref="PasswordHasherOptions.MaxPasswordBytes"/>.</exception>
        /// <exception cref="PasswordHasherBusyException">The hasher is at its concurrency limit.</exception>
        public string HashPassword(TUser user, string password)
        {
            if (password == null) throw new ArgumentNullException(nameof(password));
            if (PasswordLength.ExceedsRawBound(password, _maxPasswordBytes))
                throw new ArgumentException("Password exceeds " + _maxPasswordBytes.ToString(CultureInfo.InvariantCulture) + " bytes.", nameof(password));
            return _hasher.Hash(password);
        }

        /// <summary>
        /// Verifies <paramref name="providedPassword"/> against <paramref name="hashedPassword"/>. A null, empty, malformed or
        /// unrecognised stored hash, or an over-long password, returns <see cref="IdentityVerificationResult.Failed"/> instead
        /// of throwing.
        /// </summary>
        /// <exception cref="ArgumentNullException"><paramref name="providedPassword"/> is null.</exception>
        /// <exception cref="PasswordHasherBusyException">The hasher is at its concurrency limit.</exception>
        public IdentityVerificationResult VerifyHashedPassword(TUser user, string hashedPassword, string providedPassword)
        {
            if (providedPassword == null) throw new ArgumentNullException(nameof(providedPassword));
            if (string.IsNullOrEmpty(hashedPassword))
                return IdentityVerificationResult.Failed;

            // Refuse attacker-sized input before the hasher normalizes it (NFKC can expand it 18x).
            if (PasswordLength.ExceedsRawBound(providedPassword, _maxPasswordBytes))
                return IdentityVerificationResult.Failed;

            MasterlyVerificationResult result = _hasher.Verify(providedPassword, hashedPassword);
            IdentityVerificationResult mapped = Map(result.Status);

            // UserManager answers SuccessRehashNeeded by calling HashPassword, which would throw for a password that
            // a legacy format accepted (raw UTF-8) but that is over the limit after NFKC: keep the legacy hash instead.
            if (mapped == IdentityVerificationResult.SuccessRehashNeeded &&
                PasswordLength.IsTooLongToHash(providedPassword, _maxPasswordBytes))
            {
                return IdentityVerificationResult.Success;
            }
            return mapped;
        }
        internal static IdentityVerificationResult Map(VerificationStatus status) => status switch
        {
            VerificationStatus.Success => IdentityVerificationResult.Success,
            VerificationStatus.SuccessRehashNeeded => IdentityVerificationResult.SuccessRehashNeeded,
            _ => IdentityVerificationResult.Failed,
        };
    }
}
