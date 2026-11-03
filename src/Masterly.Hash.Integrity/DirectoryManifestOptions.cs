using System;

namespace Masterly.Hash.Integrity
{
    /// <summary>Controls how <see cref="DirectoryManifest.CreateAsync(string, ContentHashAlgorithm, DirectoryManifestOptions, System.Threading.CancellationToken)"/> walks a directory.</summary>
    public sealed class DirectoryManifestOptions
    {
        /// <summary>
        /// Optional filter on the canonical relative path of each file or link; return <see langword="false"/> to
        /// leave it out. Directories are always walked. Anything filtered out is outside tamper detection.
        /// </summary>
        public Func<string, bool>? Filter { get; set; }

        /// <summary>
        /// When <see langword="false"/> (the default) symbolic links, junctions and other reparse points are not
        /// followed: each one is recorded as a <see cref="DirectoryManifestEntryKind.Link"/> entry holding the hash
        /// of its target text, so adding, removing or retargeting a link is reported, and the walk never reaches
        /// outside the root. When <see langword="true"/> links are followed and their targets hashed. A directory
        /// link that points back to one of its own ancestors, and a link whose target is missing, are recorded as
        /// link entries instead of being followed. Other repeated targets are hashed once per path, bounded by
        /// <see cref="MaxDepth"/> and <see cref="MaxEntries"/>.
        /// </summary>
        public bool FollowReparsePoints { get; set; }

        /// <summary>
        /// Deepest directory nesting walked below the root. Default 64. A non-empty directory deeper than this makes
        /// the walk fail with an <see cref="System.IO.IOException"/>, so nothing is silently left unverified.
        /// </summary>
        public int MaxDepth { get; set; } = 64;

        /// <summary>
        /// Most file system entries (files, links and directories) the walk visits before failing with an
        /// <see cref="System.IO.IOException"/>. Bounds the work an attacker can cause with links. Default 1,000,000.
        /// </summary>
        public int MaxEntries { get; set; } = 1_000_000;

        internal void Validate()
        {
            if (MaxDepth < 0)
                throw new ArgumentOutOfRangeException(nameof(MaxDepth), MaxDepth, "MaxDepth cannot be negative.");
            if (MaxEntries < 1)
                throw new ArgumentOutOfRangeException(nameof(MaxEntries), MaxEntries, "MaxEntries must be positive.");
        }
    }
}
