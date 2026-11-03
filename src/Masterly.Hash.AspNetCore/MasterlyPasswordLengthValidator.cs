using System;
using System.Globalization;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Masterly.Hash.AspNetCore
{
    /// <summary>
    /// Identity <see cref="IPasswordValidator{TUser}"/> that rejects passwords Masterly.Hash cannot hash: empty, or longer
    /// than <see cref="PasswordHasherOptions.MaxPasswordBytes"/> (UTF-8 after NFKC). Identity's own validator has no
    /// maximum, so without this one <see cref="UserManager{TUser}.CreateAsync(TUser, string)"/>, <c>AddPasswordAsync</c>,
    /// <c>ChangePasswordAsync</c> and <c>ResetPasswordAsync</c> would throw from <see cref="IPasswordHasher{TUser}.HashPassword"/>
    /// instead of returning a failed <see cref="IdentityResult"/>. <c>AddMasterlyPasswordHasher</c> registers it.
    /// </summary>
    /// <typeparam name="TUser">The Identity user type.</typeparam>
    public sealed class MasterlyPasswordLengthValidator<TUser> : IPasswordValidator<TUser>
        where TUser : class
    {
        /// <summary>The <see cref="IdentityError.Code"/> reported for an over-long password.</summary>
        public const string PasswordTooLongCode = "PasswordTooLong";

        /// <summary>The <see cref="IdentityError.Code"/> reported for an empty password.</summary>
        public const string PasswordRequiredCode = "PasswordRequired";

        /// <summary>Creates the validator with the limit configured for the registered hasher.</summary>
        [ActivatorUtilitiesConstructor]
        public MasterlyPasswordLengthValidator(IOptions<PasswordHasherOptions> options)
            : this((options ?? throw new ArgumentNullException(nameof(options))).Value.MaxPasswordBytes)
        {
        }

        /// <summary>Creates the validator with an explicit limit in UTF-8 bytes (at least 1).</summary>
        public MasterlyPasswordLengthValidator(int maxPasswordBytes)
        {
            if (maxPasswordBytes < 1)
                throw new ArgumentOutOfRangeException(nameof(maxPasswordBytes), maxPasswordBytes, "The limit must be positive.");
            MaxPasswordBytes = maxPasswordBytes;
        }

        /// <summary>Longest accepted password, in UTF-8 bytes after NFKC normalization.</summary>
        public int MaxPasswordBytes { get; }

        /// <inheritdoc />
        public Task<IdentityResult> ValidateAsync(UserManager<TUser> manager, TUser user, string? password)
        {
            if (password == null) throw new ArgumentNullException(nameof(password));

            if (password.Length == 0)
            {
                return Task.FromResult(IdentityResult.Failed(new IdentityError
                {
                    Code = PasswordRequiredCode,
                    Description = "A password is required.",
                }));
            }

            if (PasswordLength.IsTooLongToHash(password, MaxPasswordBytes))
            {
                return Task.FromResult(IdentityResult.Failed(new IdentityError
                {
                    Code = PasswordTooLongCode,
                    Description = "Passwords must be at most " + MaxPasswordBytes.ToString(CultureInfo.InvariantCulture) + " bytes long.",
                }));
            }

            return Task.FromResult(IdentityResult.Success);
        }
    }
}
