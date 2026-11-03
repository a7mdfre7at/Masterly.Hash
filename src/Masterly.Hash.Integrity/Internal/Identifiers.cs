using Masterly.Hash.Primitives;

namespace Masterly.Hash.Integrity.Internal
{
    /// <summary>Validation of algorithm names and key ids: the core package's id rules.</summary>
    internal static class Identifiers
    {
        /// <summary>Algorithm names follow the core's lowercase-id rule, <c>^[a-z0-9][a-z0-9-]{0,31}\z</c>.</summary>
        public static bool IsValidAlgorithmName(string? name) => name != null && HashPrimitives.IsValidFormatId(name);

        /// <summary>Key ids follow the core's pepper key id rule, <c>^[A-Za-z0-9-]{1,32}\z</c>.</summary>
        public static bool IsValidKeyId(string? keyId) => keyId != null && HashPrimitives.IsValidKeyId(keyId);
    }
}
