using System.Collections.Generic;

namespace Masterly.Hash.Integrity
{
    /// <summary>Differences between an expected <see cref="DirectoryManifest"/> and the current state of a directory.</summary>
    public sealed class DirectoryManifestDiff
    {
        internal DirectoryManifestDiff(bool manifestIntact, IReadOnlyList<string> added, IReadOnlyList<string> removed, IReadOnlyList<string> modified)
        {
            ManifestIntact = manifestIntact;
            Added = added;
            Removed = removed;
            Modified = modified;
        }

        /// <summary>
        /// True if the expected manifest's algorithm is the one verification used, its Merkle root matches its own
        /// entries, and (when a trusted root was supplied) that root equals the trusted one. False means the manifest
        /// cannot be trusted: treat the whole directory as unverified. The lists may then be incomplete (they are
        /// empty when the manifest's algorithm could not be used at all).
        /// </summary>
        /// <remarks>
        /// For an unkeyed algorithm such as SHA-256, True without a trusted root only rules out accidental corruption
        /// and inconsistent edits: anyone can recompute the root, so an attacker who can rewrite the manifest can
        /// replace it with a consistent one. Pass a root kept out of the attacker's reach to
        /// <see cref="DirectoryManifest.VerifyAsync(string, DirectoryManifest, ContentHash, ContentHashAlgorithm, DirectoryManifestOptions, System.Threading.CancellationToken)"/>,
        /// or use a keyed algorithm.
        /// </remarks>
        public bool ManifestIntact { get; }

        /// <summary>Files and links present now but not in the manifest, ordinal order.</summary>
        public IReadOnlyList<string> Added { get; }

        /// <summary>Files and links in the manifest that are gone, ordinal order.</summary>
        public IReadOnlyList<string> Removed { get; }

        /// <summary>Entries whose contents, length or kind changed (or link target, for links), ordinal order.</summary>
        public IReadOnlyList<string> Modified { get; }

        /// <summary>True if the manifest is intact and nothing was added, removed or modified.</summary>
        public bool IsMatch => ManifestIntact && Added.Count == 0 && Removed.Count == 0 && Modified.Count == 0;

        /// <inheritdoc />
        public override string ToString() =>
            IsMatch
                ? "Match"
                : $"{(ManifestIntact ? string.Empty : "manifest tampered, ")}{Added.Count} added, {Removed.Count} removed, {Modified.Count} modified";
    }
}
