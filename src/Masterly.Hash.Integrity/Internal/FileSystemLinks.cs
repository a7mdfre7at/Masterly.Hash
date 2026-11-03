using System;
using System.IO;

namespace Masterly.Hash.Integrity.Internal
{
    internal enum LinkResolution
    {
        /// <summary>A reparse point that is not a symbolic link or junction.</summary>
        NotALink,

        /// <summary>The link (or a link in its chain) points nowhere, or the chain loops.</summary>
        Broken,

        /// <summary>The final target exists.</summary>
        Resolved,
    }

    /// <summary>Symbolic link and junction resolution through the .NET link APIs.</summary>
    internal static class FileSystemLinks
    {
        /// <summary>The link's own target text, or <see langword="null"/> when it has none.</summary>
        internal static string? GetLinkTarget(FileSystemInfo item)
        {
            return item.LinkTarget;
        }

        /// <summary>Follows the whole link chain of <paramref name="item"/>.</summary>
        internal static LinkResolution ResolveFinalTarget(FileSystemInfo item, out FileSystemInfo? target)
        {
            target = null;
            try
            {
                target = item.ResolveLinkTarget(returnFinalTarget: true);
            }
            catch (IOException)
            {
                // Too many levels of links (a loop in the chain) or an unreadable link.
                return LinkResolution.Broken;
            }

            if (target == null)
                return LinkResolution.NotALink;
            target.Refresh();
            return target.Exists ? LinkResolution.Resolved : LinkResolution.Broken;
        }

        /// <summary>Full path without trailing separators, for ancestor comparisons.</summary>
        internal static string Normalize(string path)
        {
            string full = Path.GetFullPath(path);
            return full.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        }

        /// <summary>
        /// True if <paramref name="ancestor"/> is <paramref name="path"/> or one of its parents. Case-insensitive on
        /// purpose: on a case-sensitive file system that can only report a loop that is not one, which records the
        /// link instead of following it.
        /// </summary>
        internal static bool IsAncestorOrSelf(string ancestor, string path) =>
            string.Equals(ancestor, path, StringComparison.OrdinalIgnoreCase) ||
            (path.Length > ancestor.Length &&
             path.StartsWith(ancestor, StringComparison.OrdinalIgnoreCase) &&
             (path[ancestor.Length] == Path.DirectorySeparatorChar || path[ancestor.Length] == Path.AltDirectorySeparatorChar));
    }
}
