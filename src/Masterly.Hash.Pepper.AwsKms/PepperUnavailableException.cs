using System;

namespace Masterly.Hash.Pepper.AwsKms
{
    /// <summary>
    /// AWS KMS could not compute the pepper. KMS may be unreachable or slow, the call may have been throttled or
    /// denied, the key may be disabled, or the response may be unusable. The message never contains the password
    /// or the pepper input.
    /// </summary>
    /// <remarks>
    /// The password hasher does not catch this exception, so a login attempted while KMS is unavailable fails loudly
    /// instead of being reported as a wrong password. Treat it as a transient server error (HTTP 503).
    /// </remarks>
    public sealed class PepperUnavailableException : Exception
    {
        /// <summary>Creates the exception with a default message.</summary>
        public PepperUnavailableException()
            : base("The AWS KMS pepper is unavailable.")
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
