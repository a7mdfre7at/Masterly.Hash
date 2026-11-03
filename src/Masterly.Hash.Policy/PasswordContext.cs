using System.Collections.Generic;

namespace Masterly.Hash.Policy
{
    /// <summary>
    /// Facts about the account and the service that a password must not be built from (NIST SP 800-63B rev. 4:
    /// "context-specific words, such as the name of the service, the username, and derivatives thereof").
    /// Every property is optional.
    /// </summary>
    public sealed class PasswordContext
    {
        /// <summary>The account's user name or login.</summary>
        public string? UserName { get; set; }

        /// <summary>The account's email address. The local part and the domain labels are checked separately.</summary>
        public string? Email { get; set; }

        /// <summary>The user's display or full name. Each name part is checked.</summary>
        public string? DisplayName { get; set; }

        /// <summary>The application or site name, e.g. <c>Contoso</c>. Usually better set once in <see cref="PasswordPolicyOptions.ContextWords"/>.</summary>
        public string? ApplicationName { get; set; }

        /// <summary>Other words specific to this user, such as a company name, city or pet's name.</summary>
        public IList<string> AdditionalWords { get; } = new List<string>();
    }
}
