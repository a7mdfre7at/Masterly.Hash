using System;

namespace Masterly.Hash.Pepper.HashiCorpVault
{
    /// <summary>
    /// HashiCorp Vault could not compute the pepper: it was unreachable, timed out, refused the request,
    /// or returned an unusable response. The message never contains the password, the pepper input or the token.
    /// </summary>
    /// <remarks>
    /// The password hasher does not catch this exception: a login attempted while Vault is down fails loudly
    /// instead of being reported as a wrong password. Treat it as a transient server error (HTTP 503).
    /// </remarks>
    public sealed class PepperUnavailableException : Exception
    {
        /// <summary>Creates the exception with a default message.</summary>
        public PepperUnavailableException()
            : base("The HashiCorp Vault pepper is unavailable.")
        {
        }

        /// <summary>Creates the exception with a message.</summary>
        public PepperUnavailableException(string message)
            : base(message)
        {
        }

        /// <summary>Creates the exception with a message and the underlying cause.</summary>
        public PepperUnavailableException(string message, Exception innerException)
            : base(message, innerException)
        {
        }
    }
}
