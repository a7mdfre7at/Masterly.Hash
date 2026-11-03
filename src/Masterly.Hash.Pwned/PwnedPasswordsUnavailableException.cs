using System;

namespace Masterly.Hash.Pwned
{
    /// <summary>
    /// The Pwned Passwords service could not answer (timeout, network error, non-success status, malformed or
    /// oversized response). Thrown only when <see cref="PwnedPasswordsOptions.FailureMode"/> is
    /// <see cref="PwnedPasswordsFailureMode.Throw"/>. The message never contains the password, its hash or the prefix.
    /// </summary>
    public sealed class PwnedPasswordsUnavailableException : Exception
    {
        /// <summary>Creates the exception.</summary>
        public PwnedPasswordsUnavailableException()
            : base("The Pwned Passwords service is unavailable.")
        {
        }

        /// <summary>Creates the exception with a message.</summary>
        public PwnedPasswordsUnavailableException(string message)
            : base(message)
        {
        }

        /// <summary>Creates the exception with a message and the underlying failure.</summary>
        public PwnedPasswordsUnavailableException(string message, Exception? innerException)
            : base(message, innerException)
        {
        }
    }
}
