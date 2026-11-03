using System;

namespace Masterly.Hash.Pepper.AzureKeyVault
{
    /// <summary>
    /// The pepper keys could not be loaded from Azure Key Vault. Key Vault may be unreachable or slow, access may
    /// have been denied, the secret may be missing or disabled, or a secret value may be invalid. The message never
    /// contains key material.
    /// </summary>
    /// <remarks>
    /// Thrown by <see cref="AzureKeyVaultPepper.CreateAsync"/> and <see cref="AzureKeyVaultPepper.RefreshAsync"/>.
    /// Once keys are loaded, hashing and verifying never call Key Vault, so they never throw this exception.
    /// </remarks>
    public sealed class PepperUnavailableException : Exception
    {
        /// <summary>Creates the exception with a default message.</summary>
        public PepperUnavailableException()
            : base("The Azure Key Vault pepper is unavailable.")
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
