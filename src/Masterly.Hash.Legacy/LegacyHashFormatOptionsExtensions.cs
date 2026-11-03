using System;
using System.Collections.Generic;
using Masterly.Hash.Legacy;

namespace Masterly.Hash
{
    /// <summary>Registers the <c>Masterly.Hash.Legacy</c> formats on <see cref="PasswordHasherOptions"/>.</summary>
    public static class LegacyHashFormatOptionsExtensions
    {
        /// <summary>
        /// Adds legacy formats so the hasher can verify (and upgrade on login, or onion-wrap) hashes from other systems.
        /// </summary>
        /// <remarks>
        /// The formats are inserted ahead of the built-in Masterly.Hash 1.x format (<see cref="V1LegacyFormat"/>),
        /// whose plain base64 also matches hex digests and ASP.NET Identity hashes; this way
        /// <see cref="IPasswordHasher.Inspect"/> and <see cref="IPasswordHasher.TryWrap"/> pick the precise format.
        /// Adding a format instance that is already registered does nothing; adding a different instance with an
        /// id that is already registered (or twice in <paramref name="formats"/>) throws. The call is all-or-nothing:
        /// when it throws, <paramref name="options"/> is unchanged.
        /// </remarks>
        /// <returns>The same options, for chaining.</returns>
        public static PasswordHasherOptions AddLegacyFormats(this PasswordHasherOptions options, params ILegacyHashFormat[] formats)
        {
            if (options == null) throw new ArgumentNullException(nameof(options));
            if (formats == null) throw new ArgumentNullException(nameof(formats));

            var toAdd = new List<ILegacyHashFormat>(formats.Length);
            foreach (ILegacyHashFormat format in formats)
            {
                if (format == null)
                    throw new ArgumentException("Formats cannot contain null.", nameof(formats));

                ILegacyHashFormat? existing = FindById(options.LegacyFormats, format.Id) ?? FindById(toAdd, format.Id);
                if (existing == null)
                    toAdd.Add(format);
                else if (!ReferenceEquals(existing, format))
                    throw new ArgumentException($"A different legacy format with id '{format.Id}' is already registered.", nameof(formats));
            }

            Insert(options, toAdd);
            return options;
        }

        /// <summary>
        /// Adds every format in <see cref="LegacyFormats.All"/> with its default settings, skipping any whose id is
        /// already registered.
        /// </summary>
        /// <remarks>
        /// Formats registered earlier take precedence, so custom caps can be combined with the defaults:
        /// <c>options.AddLegacyFormats(new PhpassFormat(14)).AddAllLegacyFormats()</c> keeps the custom phpass format.
        /// </remarks>
        /// <returns>The same options, for chaining.</returns>
        public static PasswordHasherOptions AddAllLegacyFormats(this PasswordHasherOptions options)
        {
            if (options == null) throw new ArgumentNullException(nameof(options));

            var toAdd = new List<ILegacyHashFormat>(LegacyFormats.All.Count);
            foreach (ILegacyHashFormat format in LegacyFormats.All)
            {
                if (FindById(options.LegacyFormats, format.Id) == null)
                    toAdd.Add(format);
            }

            Insert(options, toAdd);
            return options;
        }

        private static ILegacyHashFormat? FindById(IList<ILegacyHashFormat> formats, string id)
        {
            foreach (ILegacyHashFormat existing in formats)
            {
                if (existing != null && string.Equals(existing.Id, id, StringComparison.Ordinal))
                    return existing;
            }
            return null;
        }

        private static void Insert(PasswordHasherOptions options, List<ILegacyHashFormat> formats)
        {
            foreach (ILegacyHashFormat format in formats)
                options.LegacyFormats.Insert(IndexOfV1(options), format);
        }

        private static int IndexOfV1(PasswordHasherOptions options)
        {
            for (int i = 0; i < options.LegacyFormats.Count; i++)
            {
                if (options.LegacyFormats[i] is V1LegacyFormat)
                    return i;
            }
            return options.LegacyFormats.Count;
        }
    }
}
