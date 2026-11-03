using System;

namespace Masterly.Hash
{
    /// <summary>
    /// Thrown when no hashing slot became free within <see cref="PasswordHasherOptions.ConcurrencyTimeout"/>.
    /// Map it to HTTP 503 so clients back off instead of piling on.
    /// </summary>
    public sealed class PasswordHasherBusyException : TimeoutException
    {
        /// <summary>Creates the exception.</summary>
        public PasswordHasherBusyException()
            : base("The password hasher is at its concurrency limit. Try again later.")
        {
        }
    }
}
