using System.Collections.Generic;
using System.Collections.ObjectModel;

namespace Masterly.Hash.Legacy
{
    /// <summary>The legacy formats this package provides, with their default settings and cost caps.</summary>
    public static class LegacyFormats
    {
        /// <summary>
        /// Every format with default settings: bcrypt, wordpress-bcrypt, argon2-phc, phpass, django-pbkdf2, aspnet-identity-v3,
        /// aspnet-identity-v2, md5, sha1, sha256 and sha512. The syntaxes do not overlap, so the order only matters
        /// relative to formats registered elsewhere.
        /// </summary>
        public static IReadOnlyList<ILegacyHashFormat> All { get; } = new ReadOnlyCollection<ILegacyHashFormat>(new ILegacyHashFormat[]
        {
            BCryptFormat.Default,
            WordPressBcryptFormat.Default,
            ExternalArgon2Format.Default,
            PhpassFormat.Default,
            DjangoPbkdf2Format.Default,
            AspNetIdentityV3Format.Default,
            AspNetIdentityV2Format.Instance,
            UnsaltedDigestFormat.Md5,
            UnsaltedDigestFormat.Sha1,
            UnsaltedDigestFormat.Sha256,
            UnsaltedDigestFormat.Sha512,
        });
    }
}
