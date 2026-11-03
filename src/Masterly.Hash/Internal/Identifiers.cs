namespace Masterly.Hash.Internal
{
    /// <summary>
    /// The id rules of the <c>$mh$</c> format, checked character by character. (A <c>^...$</c> regex would also accept
    /// a trailing newline, because <c>$</c> matches before a final <c>\n</c> in .NET.)
    /// </summary>
    internal static class Identifiers
    {
        /// <summary>Profile and legacy format ids: <c>^[a-z0-9][a-z0-9-]{0,31}\z</c>.</summary>
        public static bool IsValidLowercaseId(string? id)
        {
            if (id == null || id.Length == 0 || id.Length > 32)
                return false;
            for (int i = 0; i < id.Length; i++)
            {
                char c = id[i];
                bool ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || (c == '-' && i > 0);
                if (!ok)
                    return false;
            }
            return true;
        }

        /// <summary>Pepper (and other) key ids: <c>^[A-Za-z0-9-]{1,32}\z</c>.</summary>
        public static bool IsValidKeyId(string? keyId)
        {
            if (keyId == null || keyId.Length == 0 || keyId.Length > 32)
                return false;
            foreach (char c in keyId)
            {
                bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-';
                if (!ok)
                    return false;
            }
            return true;
        }
    }
}
