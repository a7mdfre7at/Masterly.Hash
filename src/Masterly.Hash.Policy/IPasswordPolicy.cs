using System.Threading;
using System.Threading.Tasks;

namespace Masterly.Hash.Policy
{
    /// <summary>Decides whether a new password is acceptable. <see cref="PasswordPolicy"/> is the implementation.</summary>
    public interface IPasswordPolicy
    {
        /// <summary>Checks a candidate password against every local rule (no breach lookup).</summary>
        PasswordPolicyResult Evaluate(string password, PasswordContext? context = null);

        /// <summary>Checks a candidate password against every local rule (no breach lookup).</summary>
        PasswordPolicyResult Evaluate(SensitiveString password, PasswordContext? context = null);

        /// <summary>Checks a candidate password against every rule, including the breached-password lookup if one is configured.</summary>
        ValueTask<PasswordPolicyResult> EvaluateAsync(string password, PasswordContext? context = null, CancellationToken cancellationToken = default);

        /// <summary>Checks a candidate password against every rule, including the breached-password lookup if one is configured.</summary>
        ValueTask<PasswordPolicyResult> EvaluateAsync(SensitiveString password, PasswordContext? context = null, CancellationToken cancellationToken = default);
    }
}
