using Microsoft.CodeAnalysis;

namespace Masterly.Hash.Analyzers
{
    /// <summary>The diagnostic IDs reported by Masterly.Hash.Analyzers.</summary>
    public static class DiagnosticIds
    {
        /// <summary>Fast hash (MD5, SHA-1, SHA-2, SHA-3, HMAC) used on a password.</summary>
        public const string FastHashOnPassword = "MH0001";

        /// <summary>Non-constant-time comparison of a hash, MAC, token or other secret.</summary>
        public const string NonConstantTimeComparison = "MH0002";

        /// <summary>Hard-coded pepper or key.</summary>
        public const string HardCodedPepper = "MH0003";

        /// <summary>Password may be written to a log or the console.</summary>
        public const string PasswordLogged = "MH0004";

        /// <summary>Weak PBKDF2 parameters.</summary>
        public const string WeakPbkdf2 = "MH0005";

        /// <summary>Use of the obsolete Masterly.Hash 1.x API.</summary>
        public const string ObsoleteApi = "MH0006";
    }

    internal static class Descriptors
    {
        private const string Category = "Security";

        private static string HelpLink(string id) =>
            "https://github.com/a7mdfre7at/Masterly.Hash/blob/master/docs/analyzers/" + id + ".md";

        public static readonly DiagnosticDescriptor FastHashOnPassword = new DiagnosticDescriptor(
            DiagnosticIds.FastHashOnPassword,
            title: "Fast hash used on a password",
            messageFormat: "'{0}' is a fast hash and must not be used on the password '{1}'; use Masterly.Hash.Password.Hash",
            category: Category,
            defaultSeverity: DiagnosticSeverity.Warning,
            isEnabledByDefault: true,
            description: "MD5, SHA-1, SHA-2, SHA-3 and HMAC are designed to be fast, so a GPU can try billions of password guesses per second against them. Store passwords with a memory-hard password hash such as Argon2id (Masterly.Hash.Password.Hash).",
            helpLinkUri: HelpLink(DiagnosticIds.FastHashOnPassword));

        public static readonly DiagnosticDescriptor NonConstantTimeComparison = new DiagnosticDescriptor(
            DiagnosticIds.NonConstantTimeComparison,
            title: "Non-constant-time comparison of secrets",
            messageFormat: "'{0}' looks like a secret and is compared with '{1}', which returns early on the first difference; use CryptographicOperations.FixedTimeEquals",
            category: Category,
            defaultSeverity: DiagnosticSeverity.Warning,
            isEnabledByDefault: true,
            description: "Equality operators, string.Equals and SequenceEqual stop at the first mismatching element, so the time they take reveals how much of a hash, MAC or token an attacker guessed correctly. Compare secrets with CryptographicOperations.FixedTimeEquals.",
            helpLinkUri: HelpLink(DiagnosticIds.NonConstantTimeComparison));

        public static readonly DiagnosticDescriptor HardCodedPepper = new DiagnosticDescriptor(
            DiagnosticIds.HardCodedPepper,
            title: "Hard-coded pepper or key",
            messageFormat: "The {0} is hard-coded; load it from a secret store or configuration instead",
            category: Category,
            defaultSeverity: DiagnosticSeverity.Warning,
            isEnabledByDefault: true,
            description: "A pepper or signing key compiled into the binary is visible to anyone with the source, the binary or a decompiler, and cannot be rotated without a release. Load keys from a key vault, environment or protected configuration.",
            helpLinkUri: HelpLink(DiagnosticIds.HardCodedPepper));

        public static readonly DiagnosticDescriptor PasswordLogged = new DiagnosticDescriptor(
            DiagnosticIds.PasswordLogged,
            title: "Password may be logged",
            messageFormat: "'{0}' may be written to a log by '{1}'; never log passwords",
            category: Category,
            defaultSeverity: DiagnosticSeverity.Warning,
            isEnabledByDefault: true,
            description: "Logs are copied, shipped, indexed and retained far longer than credentials should live. Remove the password from the log statement, or log SensitiveString (which prints as ***) instead of its revealed value.",
            helpLinkUri: HelpLink(DiagnosticIds.PasswordLogged));

        public static readonly DiagnosticDescriptor WeakPbkdf2 = new DiagnosticDescriptor(
            DiagnosticIds.WeakPbkdf2,
            title: "Weak PBKDF2 parameters",
            messageFormat: "Weak PBKDF2 parameters: {0}",
            category: Category,
            defaultSeverity: DiagnosticSeverity.Warning,
            isEnabledByDefault: true,
            description: "PBKDF2 is only as strong as its iteration count and PRF. Constructors that omit the hash algorithm default to HMAC-SHA1, and those that omit the iteration count default to 1,000 iterations. Counts below 100,000 are reported; this is a floor, not a recommendation: OWASP recommends 600,000 iterations for PBKDF2-HMAC-SHA256 and 210,000 for PBKDF2-HMAC-SHA512. Prefer Masterly.Hash.Password.Hash.",
            helpLinkUri: HelpLink(DiagnosticIds.WeakPbkdf2));

        public static readonly DiagnosticDescriptor ObsoleteApi = new DiagnosticDescriptor(
            DiagnosticIds.ObsoleteApi,
            title: "Obsolete Masterly.Hash 1.x API",
            messageFormat: "'{0}' is the Masterly.Hash 1.x API, which produces fast single-pass hashes; use '{1}' instead",
            category: Category,
            defaultSeverity: DiagnosticSeverity.Info,
            isEnabledByDefault: true,
            description: "The 1.x API hashes with a single salted SHA-2 pass, which is not suitable for passwords. Password.Hash produces an Argon2id hash, and Password.Verify keeps accepting 1.x hashes and upgrades them on login.",
            helpLinkUri: HelpLink(DiagnosticIds.ObsoleteApi));
    }
}
