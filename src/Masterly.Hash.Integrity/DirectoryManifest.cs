using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Masterly.Hash.Integrity.Internal;

namespace Masterly.Hash.Integrity
{
    /// <summary>
    /// A snapshot of a directory tree: every file's (and unfollowed link's) canonical relative path, length and
    /// content hash, sorted ordinally, plus an RFC 9162 Merkle root over the entries. Immutable.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Each Merkle leaf is <c>field(tag) || field(utf8(path)) || u64(length) || field(digest)</c> (8-byte big-endian
    /// lengths), where the tag is <c>masterly-manifest/v1</c> for files and <c>masterly-manifest/v1:link</c> for links.
    /// </para>
    /// <para>
    /// The root detects accidental corruption and inconsistent edits of the manifest. It does not stop deliberate
    /// rewriting when the algorithm is unkeyed: anyone can recompute it. Keep the <see cref="Root"/> somewhere the
    /// attacker cannot write and pass it to
    /// <see cref="VerifyAsync(string, DirectoryManifest, ContentHash, ContentHashAlgorithm, DirectoryManifestOptions, CancellationToken)"/>,
    /// or use a keyed algorithm.
    /// </para>
    /// <para>
    /// The walk fails closed: links are recorded rather than dropped, and a tree deeper than
    /// <see cref="DirectoryManifestOptions.MaxDepth"/> or larger than <see cref="DirectoryManifestOptions.MaxEntries"/>
    /// raises <see cref="IOException"/>. Zero-length files are recorded as empty without being opened, so FIFOs,
    /// sockets and device nodes (which report length 0 on Unix) cannot block or flood the walk.
    /// </para>
    /// <para>
    /// Verification never opens files by paths taken from the manifest; it walks the directory and compares, so a
    /// hostile manifest cannot cause reads outside the root.
    /// </para>
    /// </remarks>
    public sealed class DirectoryManifest
    {
        /// <summary>Value of the <c>format</c> property in the JSON form.</summary>
        public const string FormatId = "masterly-manifest/v1";

        private static readonly byte[] LeafTag = Encoding.ASCII.GetBytes(FormatId);
        private static readonly byte[] LinkLeafTag = Encoding.ASCII.GetBytes(FormatId + ":link");
        private static readonly UTF8Encoding StrictUtf8 = new UTF8Encoding(false, true);

        private readonly DirectoryManifestEntry[] _entries;

        private DirectoryManifest(string algorithm, string? keyId, DirectoryManifestEntry[] entries, ContentHash root)
        {
            Algorithm = algorithm;
            KeyId = keyId;
            _entries = entries;
            Root = root;
        }

        /// <summary>Algorithm name of every hash in the manifest, e.g. <c>sha256</c>.</summary>
        public string Algorithm { get; }

        /// <summary>Key id when the manifest uses a keyed algorithm; otherwise <see langword="null"/>.</summary>
        public string? KeyId { get; }

        /// <summary>Entries in ordinal path order.</summary>
        public IReadOnlyList<DirectoryManifestEntry> Entries => _entries;

        /// <summary>Merkle root over the entries, as recorded (check it with <see cref="IsIntact()"/>).</summary>
        public ContentHash Root { get; }

        /// <summary>
        /// Builds a manifest from entries (sorted here; duplicate paths are rejected). All hashes must come from
        /// <paramref name="algorithm"/>, which also hashes the Merkle tree.
        /// </summary>
        public static DirectoryManifest FromEntries(IEnumerable<DirectoryManifestEntry> entries, ContentHashAlgorithm algorithm)
        {
            if (entries == null) throw new ArgumentNullException(nameof(entries));
            if (algorithm == null) throw new ArgumentNullException(nameof(algorithm));
            var list = new List<DirectoryManifestEntry>();
            foreach (DirectoryManifestEntry entry in entries)
            {
                if (entry == null)
                    throw new ArgumentException("Entries cannot contain null.", nameof(entries));
                if (!entry.Hash.IsFrom(algorithm))
                    throw new ArgumentException($"Every entry must be hashed with {algorithm.Identifier}.", nameof(entries));
                list.Add(entry);
            }

            list.Sort((a, b) => string.CompareOrdinal(a.Path, b.Path));
            for (int i = 1; i < list.Count; i++)
            {
                if (string.Equals(list[i - 1].Path, list[i].Path, StringComparison.Ordinal))
                    throw new ArgumentException("Entries contain a duplicate path.", nameof(entries));
            }

            DirectoryManifestEntry[] array = list.ToArray();
            return new DirectoryManifest(algorithm.Name, algorithm.KeyId, array, ComputeRoot(array, algorithm));
        }

        /// <summary>SHA-256 manifest of every regular file under <paramref name="rootPath"/>.</summary>
        public static Task<DirectoryManifest> CreateAsync(string rootPath, CancellationToken cancellationToken = default) =>
            CreateAsync(rootPath, ContentHashAlgorithm.Sha256, null, cancellationToken);

        /// <summary>Manifest of the files under <paramref name="rootPath"/>, hashed with <paramref name="algorithm"/>.</summary>
        /// <exception cref="DirectoryNotFoundException">The root does not exist.</exception>
        public static Task<DirectoryManifest> CreateAsync(string rootPath, ContentHashAlgorithm algorithm, DirectoryManifestOptions? options = null, CancellationToken cancellationToken = default)
        {
            if (rootPath == null) throw new ArgumentNullException(nameof(rootPath));
            if (algorithm == null) throw new ArgumentNullException(nameof(algorithm));
            options ??= new DirectoryManifestOptions();
            options.Validate();
            var root = new DirectoryInfo(Path.GetFullPath(rootPath));
            if (!root.Exists)
                throw new DirectoryNotFoundException("The manifest root directory does not exist.");
            return CreateCoreAsync(root, algorithm, options, cancellationToken);
        }

        /// <summary>
        /// Rebuilds the manifest of <paramref name="rootPath"/> and compares it with <paramref name="expected"/>.
        /// The algorithm is resolved from the manifest, which works for unkeyed algorithms only (a keyed manifest
        /// yields <see cref="DirectoryManifestDiff.ManifestIntact"/> = <see langword="false"/>).
        /// </summary>
        public static Task<DirectoryManifestDiff> VerifyAsync(string rootPath, DirectoryManifest expected, CancellationToken cancellationToken = default) =>
            VerifyAsync(rootPath, expected, null, null, cancellationToken);

        /// <summary>
        /// Rebuilds the manifest of <paramref name="rootPath"/> with <paramref name="algorithm"/> (or the manifest's
        /// own unkeyed algorithm when <see langword="null"/>) and reports added, removed and modified entries.
        /// Use the same <paramref name="options"/> as when the manifest was created.
        /// </summary>
        /// <remarks>
        /// <paramref name="expected"/> is treated as untrusted: if its algorithm or key id differs from
        /// <paramref name="algorithm"/>, or it is keyed and no algorithm is given, the result has
        /// <see cref="DirectoryManifestDiff.ManifestIntact"/> = <see langword="false"/> instead of an exception.
        /// </remarks>
        /// <exception cref="IOException">The walk exceeded <see cref="DirectoryManifestOptions.MaxDepth"/> or <see cref="DirectoryManifestOptions.MaxEntries"/>, or a file could not be read.</exception>
        public static Task<DirectoryManifestDiff> VerifyAsync(string rootPath, DirectoryManifest expected, ContentHashAlgorithm? algorithm, DirectoryManifestOptions? options = null, CancellationToken cancellationToken = default)
        {
            if (rootPath == null) throw new ArgumentNullException(nameof(rootPath));
            if (expected == null) throw new ArgumentNullException(nameof(expected));
            return VerifyCoreAsync(rootPath, expected, algorithm, null, options, cancellationToken);
        }

        /// <summary>
        /// Like <see cref="VerifyAsync(string, DirectoryManifest, ContentHashAlgorithm, DirectoryManifestOptions, CancellationToken)"/>,
        /// but also requires <paramref name="expected"/>'s root to equal <paramref name="trustedRoot"/>, a copy kept
        /// where the attacker cannot write. This is what makes an unkeyed manifest resist deliberate rewriting.
        /// </summary>
        /// <exception cref="IOException">The walk exceeded <see cref="DirectoryManifestOptions.MaxDepth"/> or <see cref="DirectoryManifestOptions.MaxEntries"/>, or a file could not be read.</exception>
        public static Task<DirectoryManifestDiff> VerifyAsync(string rootPath, DirectoryManifest expected, ContentHash trustedRoot, ContentHashAlgorithm? algorithm, DirectoryManifestOptions? options, CancellationToken cancellationToken = default)
        {
            if (rootPath == null) throw new ArgumentNullException(nameof(rootPath));
            if (expected == null) throw new ArgumentNullException(nameof(expected));
            if (trustedRoot == null) throw new ArgumentNullException(nameof(trustedRoot));
            return VerifyCoreAsync(rootPath, expected, algorithm, trustedRoot, options, cancellationToken);
        }

        /// <summary>
        /// Compares two manifests. <see cref="DirectoryManifestDiff.ManifestIntact"/> reports whether
        /// <paramref name="expected"/> uses <paramref name="algorithm"/> (or its own unkeyed algorithm when
        /// <see langword="null"/>), shares <paramref name="actual"/>'s algorithm and still matches its own root.
        /// Never throws on mismatched algorithms; entries hashed differently are reported as modified.
        /// </summary>
        public static DirectoryManifestDiff Compare(DirectoryManifest expected, DirectoryManifest actual, ContentHashAlgorithm? algorithm = null)
        {
            if (expected == null) throw new ArgumentNullException(nameof(expected));
            if (actual == null) throw new ArgumentNullException(nameof(actual));
            return CompareCore(expected, actual, algorithm, null);
        }

        /// <summary>
        /// Like <see cref="Compare(DirectoryManifest, DirectoryManifest, ContentHashAlgorithm)"/>, but also requires
        /// <paramref name="expected"/>'s root to equal <paramref name="trustedRoot"/>.
        /// </summary>
        public static DirectoryManifestDiff Compare(DirectoryManifest expected, DirectoryManifest actual, ContentHashAlgorithm? algorithm, ContentHash trustedRoot)
        {
            if (expected == null) throw new ArgumentNullException(nameof(expected));
            if (actual == null) throw new ArgumentNullException(nameof(actual));
            if (trustedRoot == null) throw new ArgumentNullException(nameof(trustedRoot));
            return CompareCore(expected, actual, algorithm, trustedRoot);
        }

        /// <summary>True if <see cref="Root"/> matches the entries. Unkeyed manifests only (keyed ones return <see langword="false"/>).</summary>
        public bool IsIntact() => IsIntact(null);

        /// <summary>
        /// True if <see cref="Root"/> matches the entries under <paramref name="algorithm"/> (needed for keyed
        /// manifests). A manifest whose algorithm or key id differs from <paramref name="algorithm"/> is not intact.
        /// </summary>
        public bool IsIntact(ContentHashAlgorithm? algorithm)
        {
            if (!ContentHashAlgorithm.TryResolve(Algorithm, KeyId, algorithm, out ContentHashAlgorithm? resolved))
                return false;
            foreach (DirectoryManifestEntry entry in _entries)
            {
                if (!entry.Hash.IsFrom(resolved!))
                    return false;
            }
            return Root.IsFrom(resolved!) && ComputeRoot(_entries, resolved!).Equals(Root);
        }

        /// <summary>The Merkle tree over the entries, e.g. to prove that one file is part of the manifest.</summary>
        public MerkleTree ToMerkleTree(ContentHashAlgorithm? algorithm = null)
        {
            ContentHashAlgorithm resolved = ContentHashAlgorithm.Resolve(Algorithm, KeyId, algorithm, nameof(algorithm));
            return MerkleTree.Build(LeafData(_entries), resolved);
        }

        /// <summary>The Merkle leaf data for <paramref name="entry"/> (see the class remarks for the encoding).</summary>
        public static byte[] EncodeLeaf(DirectoryManifestEntry entry)
        {
            if (entry == null) throw new ArgumentNullException(nameof(entry));
            byte[] tag = entry.Kind == DirectoryManifestEntryKind.Link ? LinkLeafTag : LeafTag;
            byte[] path = StrictUtf8.GetBytes(entry.Path);
            byte[] digest = entry.Hash.DigestBytes;
            byte[] result = new byte[8 + tag.Length + 8 + path.Length + 8 + 8 + digest.Length];
            int offset = 0;
            offset = WriteField(result, offset, tag);
            offset = WriteField(result, offset, path);
            offset = WriteUInt64(result, offset, (ulong)entry.Length);
            WriteField(result, offset, digest);
            return result;
        }

        /// <summary>
        /// Serializes to JSON: <c>{"format", "algorithm", "root", "files": [{"path", "length", "hash"}]}</c>. Link
        /// entries also carry <c>"kind": "link"</c>.
        /// </summary>
        public string ToJson(bool indented = true)
        {
            using (var buffer = new MemoryStream())
            {
                using (var writer = new Utf8JsonWriter(buffer, new JsonWriterOptions { Indented = indented }))
                {
                    writer.WriteStartObject();
                    writer.WriteString("format", FormatId);
                    writer.WriteString("algorithm", KeyId == null ? Algorithm : Algorithm + ":" + KeyId);
                    writer.WriteString("root", Root.ToString());
                    writer.WriteStartArray("files");
                    foreach (DirectoryManifestEntry entry in _entries)
                    {
                        writer.WriteStartObject();
                        writer.WriteString("path", entry.Path);
                        writer.WriteNumber("length", entry.Length);
                        writer.WriteString("hash", entry.Hash.ToString());
                        if (entry.Kind == DirectoryManifestEntryKind.Link)
                            writer.WriteString("kind", "link");
                        writer.WriteEndObject();
                    }
                    writer.WriteEndArray();
                    writer.WriteEndObject();
                }
                return Encoding.UTF8.GetString(buffer.ToArray());
            }
        }

        /// <summary>
        /// Parses the JSON form strictly: known properties only, canonical paths in strictly ascending ordinal order,
        /// every hash from the same algorithm. The root is not checked here; call <see cref="IsIntact()"/>.
        /// </summary>
        /// <exception cref="FormatException">The JSON is not a valid manifest.</exception>
        public static DirectoryManifest FromJson(string json)
        {
            if (json == null) throw new ArgumentNullException(nameof(json));
            if (!TryFromJson(json, out DirectoryManifest? manifest))
                throw new FormatException("Not a valid directory manifest.");
            return manifest!;
        }

        /// <summary>Parses the JSON form strictly. Never throws.</summary>
        public static bool TryFromJson(string? json, out DirectoryManifest? manifest)
        {
            manifest = null;
            if (string.IsNullOrEmpty(json))
                return false;
            try
            {
                using (JsonDocument document = JsonDocument.Parse(json!, new JsonDocumentOptions { MaxDepth = 8 }))
                    return TryRead(document.RootElement, out manifest);
            }
            catch (JsonException)
            {
                return false;
            }
            catch (ArgumentException)
            {
                // Invalid UTF-16 (an unpaired surrogate) cannot be transcoded to JSON text.
                return false;
            }
            catch (InvalidOperationException)
            {
                // JsonElement.GetString on an escaped lone surrogate such as "\udc00".
                return false;
            }
        }

        /// <inheritdoc />
        public override string ToString() => $"{_entries.Length} files, root {Root}";

        private static bool TryRead(JsonElement root, out DirectoryManifest? manifest)
        {
            manifest = null;
            if (root.ValueKind != JsonValueKind.Object)
                return false;

            string? format = null, algorithm = null, rootHash = null;
            JsonElement files = default;
            bool hasFiles = false;
            foreach (JsonProperty property in root.EnumerateObject())
            {
                switch (property.Name)
                {
                    case "format" when format == null && property.Value.ValueKind == JsonValueKind.String:
                        format = property.Value.GetString();
                        break;
                    case "algorithm" when algorithm == null && property.Value.ValueKind == JsonValueKind.String:
                        algorithm = property.Value.GetString();
                        break;
                    case "root" when rootHash == null && property.Value.ValueKind == JsonValueKind.String:
                        rootHash = property.Value.GetString();
                        break;
                    case "files" when !hasFiles && property.Value.ValueKind == JsonValueKind.Array:
                        files = property.Value;
                        hasFiles = true;
                        break;
                    default:
                        return false;
                }
            }

            if (format != FormatId || algorithm == null || !hasFiles || !ContentHash.TryParse(rootHash, out ContentHash? parsedRoot))
                return false;
            string identity = parsedRoot!.KeyId == null ? parsedRoot.Algorithm : parsedRoot.Algorithm + ":" + parsedRoot.KeyId;
            if (!string.Equals(identity, algorithm, StringComparison.Ordinal))
                return false;

            var entries = new List<DirectoryManifestEntry>(files.GetArrayLength());
            string? previous = null;
            foreach (JsonElement file in files.EnumerateArray())
            {
                if (!TryReadEntry(file, out DirectoryManifestEntry? entry))
                    return false;
                if (entry!.Hash.Algorithm != parsedRoot.Algorithm || entry.Hash.KeyId != parsedRoot.KeyId)
                    return false;
                if (previous != null && string.CompareOrdinal(previous, entry.Path) >= 0)
                    return false;
                previous = entry.Path;
                entries.Add(entry);
            }

            manifest = new DirectoryManifest(parsedRoot.Algorithm, parsedRoot.KeyId, entries.ToArray(), parsedRoot);
            return true;
        }

        private static bool TryReadEntry(JsonElement file, out DirectoryManifestEntry? entry)
        {
            entry = null;
            if (file.ValueKind != JsonValueKind.Object)
                return false;

            string? path = null, hash = null;
            long length = -1;
            bool hasKind = false;
            foreach (JsonProperty property in file.EnumerateObject())
            {
                switch (property.Name)
                {
                    case "path" when path == null && property.Value.ValueKind == JsonValueKind.String:
                        path = property.Value.GetString();
                        break;
                    case "hash" when hash == null && property.Value.ValueKind == JsonValueKind.String:
                        hash = property.Value.GetString();
                        break;
                    case "kind" when !hasKind && property.Value.ValueKind == JsonValueKind.String && property.Value.ValueEquals("link"):
                        hasKind = true;
                        break;
                    case "length" when length < 0 && property.Value.ValueKind == JsonValueKind.Number:
                        if (!property.Value.TryGetInt64(out length) || length < 0)
                            return false;
                        break;
                    default:
                        return false;
                }
            }

            if (length < 0 || !DirectoryManifestEntry.IsCanonicalPath(path) || !ContentHash.TryParse(hash, out ContentHash? parsed))
                return false;
            entry = new DirectoryManifestEntry(path!, length, parsed!, hasKind ? DirectoryManifestEntryKind.Link : DirectoryManifestEntryKind.File);
            return true;
        }

        private static async Task<DirectoryManifestDiff> VerifyCoreAsync(string rootPath, DirectoryManifest expected, ContentHashAlgorithm? algorithm,
            ContentHash? trustedRoot, DirectoryManifestOptions? options, CancellationToken cancellationToken)
        {
            // Walk with the caller's algorithm when given, otherwise with the manifest's own unkeyed algorithm. A keyed
            // or unknown manifest algorithm with nothing to walk with cannot be checked at all.
            ContentHashAlgorithm? walk = algorithm;
            if (walk == null && !ContentHashAlgorithm.TryResolve(expected.Algorithm, expected.KeyId, null, out walk))
            {
                string[] none = Array.Empty<string>();
                return new DirectoryManifestDiff(false, none, none, none);
            }

            DirectoryManifest actual = await CreateAsync(rootPath, walk!, options, cancellationToken).ConfigureAwait(false);
            return CompareCore(expected, actual, walk, trustedRoot);
        }

        private static DirectoryManifestDiff CompareCore(DirectoryManifest expected, DirectoryManifest actual, ContentHashAlgorithm? algorithm, ContentHash? trustedRoot)
        {
            bool intact = expected.Algorithm == actual.Algorithm && expected.KeyId == actual.KeyId &&
                          expected.IsIntact(algorithm) &&
                          (trustedRoot == null || expected.Root.Equals(trustedRoot));

            var added = new List<string>();
            var removed = new List<string>();
            var modified = new List<string>();
            int i = 0, j = 0;
            while (i < expected._entries.Length || j < actual._entries.Length)
            {
                int order = i == expected._entries.Length ? 1
                    : j == actual._entries.Length ? -1
                    : string.CompareOrdinal(expected._entries[i].Path, actual._entries[j].Path);
                if (order < 0)
                {
                    removed.Add(expected._entries[i++].Path);
                }
                else if (order > 0)
                {
                    added.Add(actual._entries[j++].Path);
                }
                else
                {
                    DirectoryManifestEntry e = expected._entries[i++];
                    DirectoryManifestEntry a = actual._entries[j++];
                    bool sameHash = e.Hash.Equals(a.Hash);
                    if (!sameHash || e.Length != a.Length || e.Kind != a.Kind)
                        modified.Add(e.Path);
                }
            }

            return new DirectoryManifestDiff(intact, added.AsReadOnly(), removed.AsReadOnly(), modified.AsReadOnly());
        }

        private static async Task<DirectoryManifest> CreateCoreAsync(DirectoryInfo root, ContentHashAlgorithm algorithm, DirectoryManifestOptions options, CancellationToken cancellationToken)
        {
            string prefix = root.FullName;
            if (prefix.Length == 0 || (prefix[prefix.Length - 1] != Path.DirectorySeparatorChar && prefix[prefix.Length - 1] != Path.AltDirectorySeparatorChar))
                prefix += Path.DirectorySeparatorChar;

            FileSystemInfo? rootTarget = null;
            bool rootIsLink = (root.Attributes & FileAttributes.ReparsePoint) != 0 &&
                              FileSystemLinks.ResolveFinalTarget(root, out rootTarget) == LinkResolution.Resolved;
            string rootReal = FileSystemLinks.Normalize(rootIsLink ? rootTarget!.FullName : root.FullName);

            var entries = new List<DirectoryManifestEntry>();
            var pending = new Stack<PendingDirectory>();
            pending.Push(new PendingDirectory(root, 0, rootReal));
            long visited = 0;
            while (pending.Count > 0)
            {
                PendingDirectory current = pending.Pop();
                foreach (FileSystemInfo item in current.Directory.EnumerateFileSystemInfos())
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    if (++visited > options.MaxEntries)
                        throw new IOException("The directory tree has more entries than MaxEntries allows, so it cannot be fully verified.");

                    bool isReparsePoint = (item.Attributes & FileAttributes.ReparsePoint) != 0;
                    string realPath = Path.Combine(current.RealPath, item.Name);
                    FileSystemInfo? target = null;
                    if (isReparsePoint)
                    {
                        if (!options.FollowReparsePoints)
                        {
                            AddLink(entries, item, prefix, algorithm, options);
                            continue;
                        }

                        LinkResolution resolution = FileSystemLinks.ResolveFinalTarget(item, out target);
                        if (resolution == LinkResolution.Broken ||
                            (resolution == LinkResolution.Resolved && (item is DirectoryInfo) != (target is DirectoryInfo)))
                        {
                            AddLink(entries, item, prefix, algorithm, options);
                            continue;
                        }

                        if (resolution == LinkResolution.Resolved && item is DirectoryInfo)
                        {
                            string targetReal = FileSystemLinks.Normalize(target!.FullName);
                            if (FileSystemLinks.IsAncestorOrSelf(targetReal, realPath))
                            {
                                // Following would loop back into a directory that is already being walked.
                                AddLink(entries, item, prefix, algorithm, options);
                                continue;
                            }
                            realPath = targetReal;
                        }
                    }

                    if (item is DirectoryInfo directory)
                    {
                        if (current.Depth >= options.MaxDepth)
                        {
                            if (HasAnyEntry(directory))
                                throw new IOException("The directory tree is nested deeper than MaxDepth, so it cannot be fully verified.");
                            continue;
                        }
                        pending.Push(new PendingDirectory(directory, current.Depth + 1, realPath));
                        continue;
                    }

                    string relative = RelativePath(item, prefix);
                    if (options.Filter != null && !options.Filter(relative))
                        continue;

                    // Unix FIFOs, sockets and devices report length 0 and could block or never end if opened. A
                    // followed link uses its resolved target's length.
                    bool openIt = target is FileInfo targetFile ? targetFile.Length > 0
                        : isReparsePoint || ((FileInfo)item).Length > 0;
                    if (!openIt)
                    {
                        entries.Add(new DirectoryManifestEntry(relative, 0, ContentHasher.Compute(Array.Empty<byte>(), algorithm)));
                        continue;
                    }

                    using (FileStream stream = ContentHasher.OpenRead(item.FullName))
                    {
                        ContentHash hash = await ContentHasher.ComputeAsync(stream, algorithm, cancellationToken).ConfigureAwait(false);
                        entries.Add(new DirectoryManifestEntry(relative, stream.Position, hash));
                    }
                }
            }

            return FromEntries(entries, algorithm);
        }

        private static void AddLink(List<DirectoryManifestEntry> entries, FileSystemInfo item, string prefix, ContentHashAlgorithm algorithm, DirectoryManifestOptions options)
        {
            string relative = RelativePath(item, prefix);
            if (options.Filter != null && !options.Filter(relative))
                return;
            // Lenient UTF-8: a Unix link target need not be valid text; replacement characters still change the hash.
            byte[] target = Encoding.UTF8.GetBytes(FileSystemLinks.GetLinkTarget(item) ?? string.Empty);
            entries.Add(new DirectoryManifestEntry(relative, target.Length, ContentHasher.Compute(target, algorithm), DirectoryManifestEntryKind.Link));
        }

        private static string RelativePath(FileSystemInfo item, string prefix)
        {
            string full = item.FullName;
            if (!full.StartsWith(prefix, StringComparison.Ordinal))
                throw new IOException("A directory entry resolved outside the manifest root.");
            string relative = full.Substring(prefix.Length);
            if (Path.DirectorySeparatorChar != '\\' && relative.IndexOf('\\') >= 0)
                throw new IOException("A file or directory name contains a backslash, which manifests cannot represent.");
            relative = relative.Replace('\\', '/');
            if (!DirectoryManifestEntry.IsCanonicalPath(relative))
                throw new IOException("A file path cannot be represented in a manifest.");
            return relative;
        }

        private static bool HasAnyEntry(DirectoryInfo directory)
        {
            using (IEnumerator<FileSystemInfo> enumerator = directory.EnumerateFileSystemInfos().GetEnumerator())
                return enumerator.MoveNext();
        }

        private static ContentHash ComputeRoot(DirectoryManifestEntry[] entries, ContentHashAlgorithm algorithm) =>
            MerkleTree.Build(LeafData(entries), algorithm).RootHash;

        private static IEnumerable<byte[]> LeafData(DirectoryManifestEntry[] entries)
        {
            foreach (DirectoryManifestEntry entry in entries)
                yield return EncodeLeaf(entry);
        }

        private static int WriteField(byte[] target, int offset, byte[] value)
        {
            offset = WriteUInt64(target, offset, (ulong)value.Length);
            Buffer.BlockCopy(value, 0, target, offset, value.Length);
            return offset + value.Length;
        }

        private static int WriteUInt64(byte[] target, int offset, ulong value)
        {
            for (int i = 7; i >= 0; i--)
            {
                target[offset + i] = (byte)value;
                value >>= 8;
            }
            return offset + 8;
        }

        private readonly struct PendingDirectory
        {
            public PendingDirectory(DirectoryInfo directory, int depth, string realPath)
            {
                Directory = directory;
                Depth = depth;
                RealPath = realPath;
            }

            public DirectoryInfo Directory { get; }

            public int Depth { get; }

            /// <summary>Path with followed links replaced by their targets, for loop detection.</summary>
            public string RealPath { get; }
        }
    }
}
