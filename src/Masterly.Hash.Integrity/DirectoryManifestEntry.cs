using System;

namespace Masterly.Hash.Integrity
{
    /// <summary>What a <see cref="DirectoryManifestEntry"/> describes.</summary>
    public enum DirectoryManifestEntryKind
    {
        /// <summary>A file; the entry holds the length and hash of its contents.</summary>
        File = 0,

        /// <summary>
        /// A symbolic link, junction or other reparse point recorded without being followed; the entry holds the
        /// length and hash of the UTF-8 link target text (empty when the platform cannot read the target).
        /// </summary>
        Link = 1,
    }

    /// <summary>One file or link in a <see cref="DirectoryManifest"/>: its relative path, length and content hash. Immutable.</summary>
    public sealed class DirectoryManifestEntry
    {
        /// <summary>Longest relative path accepted, in UTF-16 code units.</summary>
        public const int MaxPathLength = 4096;

        /// <summary>Creates an entry.</summary>
        /// <param name="path">
        /// Canonical relative path: <c>/</c> separators, no leading or trailing <c>/</c>, no empty, <c>.</c> or
        /// <c>..</c> segments, no backslashes, control characters or unpaired surrogates.
        /// </param>
        /// <param name="length">File length in bytes.</param>
        /// <param name="hash">Hash of the file's contents.</param>
        public DirectoryManifestEntry(string path, long length, ContentHash hash)
            : this(path, length, hash, DirectoryManifestEntryKind.File)
        {
        }

        /// <summary>Creates an entry of the given <paramref name="kind"/>.</summary>
        /// <param name="path">Canonical relative path (see the other constructor).</param>
        /// <param name="length">Length in bytes of the hashed content (file contents, or link target text).</param>
        /// <param name="hash">Hash of the file contents, or of the UTF-8 link target text.</param>
        /// <param name="kind">Whether the entry is a file or an unfollowed link.</param>
        public DirectoryManifestEntry(string path, long length, ContentHash hash, DirectoryManifestEntryKind kind)
        {
            if (kind != DirectoryManifestEntryKind.File && kind != DirectoryManifestEntryKind.Link)
                throw new ArgumentOutOfRangeException(nameof(kind), kind, "Unknown entry kind.");
            if (path == null) throw new ArgumentNullException(nameof(path));
            if (hash == null) throw new ArgumentNullException(nameof(hash));
            if (!IsCanonicalPath(path))
                throw new ArgumentException("Path must be a canonical relative path with '/' separators.", nameof(path));
            if (length < 0) throw new ArgumentOutOfRangeException(nameof(length), length, "Length cannot be negative.");
            Path = path;
            Length = length;
            Hash = hash;
            Kind = kind;
        }

        /// <summary>Relative path with <c>/</c> separators.</summary>
        public string Path { get; }

        /// <summary>Length in bytes of the hashed content (the file, or the link target text).</summary>
        public long Length { get; }

        /// <summary>Content hash (of the file, or of the link target text).</summary>
        public ContentHash Hash { get; }

        /// <summary>Whether this is a file or an unfollowed link.</summary>
        public DirectoryManifestEntryKind Kind { get; }

        /// <summary>True if <paramref name="path"/> is a canonical relative manifest path.</summary>
        public static bool IsCanonicalPath(string? path)
        {
            if (path == null || path.Length == 0 || path.Length > MaxPathLength)
                return false;
            if (path[0] == '/' || path[path.Length - 1] == '/')
                return false;

            int segmentStart = 0;
            for (int i = 0; i <= path.Length; i++)
            {
                if (i == path.Length || path[i] == '/')
                {
                    int length = i - segmentStart;
                    if (length == 0)
                        return false;
                    if (length == 1 && path[segmentStart] == '.')
                        return false;
                    if (length == 2 && path[segmentStart] == '.' && path[segmentStart + 1] == '.')
                        return false;
                    segmentStart = i + 1;
                    continue;
                }

                char c = path[i];
                if (c == '\\' || char.IsControl(c))
                    return false;
                if (char.IsHighSurrogate(c))
                {
                    if (i + 1 >= path.Length || !char.IsLowSurrogate(path[i + 1]))
                        return false;
                    i++;
                }
                else if (char.IsLowSurrogate(c))
                {
                    return false;
                }
            }
            return true;
        }

        /// <inheritdoc />
        public override string ToString() => Kind == DirectoryManifestEntryKind.Link ? Path + " (link) " + Hash : Path + " " + Hash;
    }
}
