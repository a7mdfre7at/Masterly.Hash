using System;

namespace Masterly.Hash.Testing
{
    /// <summary>
    /// Thrown by <see cref="MasterlyHashAssert"/> when an assertion fails. Every test framework (xUnit, NUnit, MSTest)
    /// reports an unhandled exception as a test failure. Messages never contain passwords or stored values.
    /// </summary>
    public sealed class MasterlyHashAssertionException : Exception
    {
        /// <summary>Creates the exception with a message.</summary>
        /// <param name="message">What was expected and what was found.</param>
        public MasterlyHashAssertionException(string message)
            : base(message)
        {
        }

        /// <summary>Creates the exception with a message and an inner exception.</summary>
        /// <param name="message">What was expected and what was found.</param>
        /// <param name="innerException">The underlying cause.</param>
        public MasterlyHashAssertionException(string message, Exception innerException)
            : base(message, innerException)
        {
        }
    }
}
