using System;
using System.Collections.Generic;
using Masterly.Hash.BlindIndex;

namespace Masterly.Hash.EntityFrameworkCore
{
    /// <summary>Settings for <see cref="MasterlyHashSaveChangesInterceptor"/>.</summary>
    public sealed class MasterlyHashInterceptorOptions
    {
        /// <summary>
        /// When false (the default), a value written to a hashed-password property is kept as-is only if it is a
        /// native Masterly hash (<c>$mh$...</c>) this hasher recognizes; anything else is treated as plaintext and
        /// hashed. When true, values recognized by a registered legacy format (for example a 1.x base64 hash) are
        /// also kept, which is useful for bulk imports of legacy hashes through EF.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Leave this off unless you need it: the 1.x format is plain base64, so a long base64-looking password typed by
        /// a user would be recognized as a legacy hash and stored unhashed.
        /// </para>
        /// <para>
        /// Either way, a legacy hash that is already stored in the row survives a re-save of the entity (for example
        /// <c>DbSet.Update</c> of a detached entity): for a modified entity the interceptor compares such a value with
        /// the database before treating it as plaintext.
        /// </para>
        /// </remarks>
        public bool AcceptLegacyHashes { get; set; }

        /// <summary>
        /// Normalizers by id, overriding the ones recorded by <c>HasBlindIndex</c>. The built-in normalizers have the
        /// ids <c>exact</c>, <c>trim</c>, <c>case-insensitive</c>, <c>email</c> and <c>phone</c>; a configured
        /// <c>EmailNormalizer</c> or <c>PhoneNormalizer</c> gets an id that encodes its settings (for example
        /// <c>email:strip-plus-tags</c> or <c>phone:cc=44</c>); any other normalizer is recorded under its type's full
        /// name.
        /// </summary>
        public IDictionary<string, IBlindIndexNormalizer> Normalizers { get; } = new Dictionary<string, IBlindIndexNormalizer>(StringComparer.Ordinal);
    }
}
