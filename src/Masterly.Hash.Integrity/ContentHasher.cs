using System;
using System.Buffers;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Masterly.Hash.Primitives;

namespace Masterly.Hash.Integrity
{
    /// <summary>
    /// Computes and verifies <see cref="ContentHash"/> values for byte arrays, streams and files. Streams are read in
    /// pooled 64 KiB chunks, so memory use does not depend on the content size. Verification compares in constant time.
    /// </summary>
    public static class ContentHasher
    {
        /// <summary>Size of the pooled read buffer.</summary>
        public const int BufferSize = 64 * 1024;

        /// <summary>SHA-256 of <paramref name="data"/>.</summary>
        public static ContentHash Compute(byte[] data) => Compute(data, ContentHashAlgorithm.Sha256);

        /// <summary>Hash of <paramref name="data"/> with <paramref name="algorithm"/>.</summary>
        public static ContentHash Compute(byte[] data, ContentHashAlgorithm algorithm)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));
            if (algorithm == null) throw new ArgumentNullException(nameof(algorithm));
            using (ContentDigest digest = algorithm.CreateDigest())
            {
                digest.Append(data, 0, data.Length);
                return Finish(algorithm, digest);
            }
        }

        /// <summary>Hash of the rest of <paramref name="stream"/>, read synchronously. The stream is not closed.</summary>
        public static ContentHash Compute(Stream stream, ContentHashAlgorithm algorithm)
        {
            if (stream == null) throw new ArgumentNullException(nameof(stream));
            if (algorithm == null) throw new ArgumentNullException(nameof(algorithm));
            if (!stream.CanRead) throw new ArgumentException("Stream must be readable.", nameof(stream));

            byte[] buffer = ArrayPool<byte>.Shared.Rent(BufferSize);
            try
            {
                using (ContentDigest digest = algorithm.CreateDigest())
                {
                    int read;
                    while ((read = stream.Read(buffer, 0, BufferSize)) > 0)
                        digest.Append(buffer, 0, read);
                    return Finish(algorithm, digest);
                }
            }
            finally
            {
                // Content may be sensitive (it is often what an HMAC protects); never hand it to the next renter.
                ArrayPool<byte>.Shared.Return(buffer, clearArray: true);
            }
        }

        /// <summary>SHA-256 of the rest of <paramref name="stream"/>. The stream is not closed.</summary>
        public static Task<ContentHash> ComputeAsync(Stream stream, CancellationToken cancellationToken = default) =>
            ComputeAsync(stream, ContentHashAlgorithm.Sha256, cancellationToken);

        /// <summary>Hash of the rest of <paramref name="stream"/> with <paramref name="algorithm"/>. The stream is not closed.</summary>
        public static Task<ContentHash> ComputeAsync(Stream stream, ContentHashAlgorithm algorithm, CancellationToken cancellationToken = default)
        {
            if (stream == null) throw new ArgumentNullException(nameof(stream));
            if (algorithm == null) throw new ArgumentNullException(nameof(algorithm));
            if (!stream.CanRead) throw new ArgumentException("Stream must be readable.", nameof(stream));
            return ComputeCoreAsync(stream, algorithm, cancellationToken);
        }

        /// <summary>SHA-256 of a file.</summary>
        public static Task<ContentHash> ComputeFileAsync(string path, CancellationToken cancellationToken = default) =>
            ComputeFileAsync(path, ContentHashAlgorithm.Sha256, cancellationToken);

        /// <summary>Hash of a file with <paramref name="algorithm"/>.</summary>
        public static Task<ContentHash> ComputeFileAsync(string path, ContentHashAlgorithm algorithm, CancellationToken cancellationToken = default)
        {
            if (path == null) throw new ArgumentNullException(nameof(path));
            if (algorithm == null) throw new ArgumentNullException(nameof(algorithm));
            return ComputeFileCoreAsync(path, algorithm, cancellationToken);
        }

        /// <summary>
        /// True if <paramref name="data"/> hashes to <paramref name="expected"/>. The algorithm is resolved from the
        /// registry, so this overload only works for unkeyed hashes: a keyed <paramref name="expected"/> returns
        /// <see langword="false"/>.
        /// </summary>
        public static bool Verify(byte[] data, ContentHash expected) => Verify(data, expected, null);

        /// <summary>
        /// True if <paramref name="data"/> hashes to <paramref name="expected"/> under <paramref name="algorithm"/>
        /// (or the registered unkeyed algorithm when <see langword="null"/>).
        /// </summary>
        /// <remarks>
        /// <paramref name="expected"/> is treated as untrusted: if its name or key id differs from
        /// <paramref name="algorithm"/> (for example a stored value swapped from a keyed to a plain hash, or a record
        /// still tagged with a rotated key id), the result is <see langword="false"/> rather than an exception.
        /// Check <see cref="ContentHash.KeyId"/> first to pick the right key during rotation.
        /// </remarks>
        public static bool Verify(byte[] data, ContentHash expected, ContentHashAlgorithm? algorithm)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));
            if (expected == null) throw new ArgumentNullException(nameof(expected));
            if (!ContentHashAlgorithm.TryResolve(expected.Algorithm, expected.KeyId, algorithm, out ContentHashAlgorithm? resolved))
                return false;
            return Matches(Compute(data, resolved!), expected);
        }

        /// <summary>
        /// True if the rest of <paramref name="stream"/> hashes to <paramref name="expected"/>. Unkeyed hashes only;
        /// see the overload taking an algorithm for keyed ones.
        /// </summary>
        public static Task<bool> VerifyAsync(Stream stream, ContentHash expected, CancellationToken cancellationToken = default) =>
            VerifyAsync(stream, expected, null, cancellationToken);

        /// <summary>
        /// True if the rest of <paramref name="stream"/> hashes to <paramref name="expected"/> under
        /// <paramref name="algorithm"/> (or the registered unkeyed algorithm when <see langword="null"/>).
        /// The digests are compared in constant time. An algorithm identity mismatch with <paramref name="expected"/>
        /// returns <see langword="false"/> without reading the stream.
        /// </summary>
        public static Task<bool> VerifyAsync(Stream stream, ContentHash expected, ContentHashAlgorithm? algorithm, CancellationToken cancellationToken = default)
        {
            if (stream == null) throw new ArgumentNullException(nameof(stream));
            if (expected == null) throw new ArgumentNullException(nameof(expected));
            if (!stream.CanRead) throw new ArgumentException("Stream must be readable.", nameof(stream));
            if (!ContentHashAlgorithm.TryResolve(expected.Algorithm, expected.KeyId, algorithm, out ContentHashAlgorithm? resolved))
                return Task.FromResult(false);
            return VerifyCoreAsync(ComputeCoreAsync(stream, resolved!, cancellationToken), expected);
        }

        /// <summary>True if the file hashes to <paramref name="expected"/>. Unkeyed hashes only (keyed ones return <see langword="false"/>).</summary>
        public static Task<bool> VerifyFileAsync(string path, ContentHash expected, CancellationToken cancellationToken = default) =>
            VerifyFileAsync(path, expected, null, cancellationToken);

        /// <summary>
        /// True if the file hashes to <paramref name="expected"/> under <paramref name="algorithm"/>. An algorithm
        /// identity mismatch with <paramref name="expected"/> returns <see langword="false"/>.
        /// </summary>
        public static Task<bool> VerifyFileAsync(string path, ContentHash expected, ContentHashAlgorithm? algorithm, CancellationToken cancellationToken = default)
        {
            if (path == null) throw new ArgumentNullException(nameof(path));
            if (expected == null) throw new ArgumentNullException(nameof(expected));
            if (!ContentHashAlgorithm.TryResolve(expected.Algorithm, expected.KeyId, algorithm, out ContentHashAlgorithm? resolved))
                return Task.FromResult(false);
            return VerifyCoreAsync(ComputeFileCoreAsync(path, resolved!, cancellationToken), expected);
        }

        internal static FileStream OpenRead(string path) =>
            new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 1, FileOptions.Asynchronous | FileOptions.SequentialScan);

        private static async Task<ContentHash> ComputeFileCoreAsync(string path, ContentHashAlgorithm algorithm, CancellationToken cancellationToken)
        {
            using (FileStream stream = OpenRead(path))
                return await ComputeCoreAsync(stream, algorithm, cancellationToken).ConfigureAwait(false);
        }

        private static async Task<ContentHash> ComputeCoreAsync(Stream stream, ContentHashAlgorithm algorithm, CancellationToken cancellationToken)
        {
            byte[] buffer = ArrayPool<byte>.Shared.Rent(BufferSize);
            try
            {
                using (ContentDigest digest = algorithm.CreateDigest())
                {
                    int read;
                    while ((read = await stream.ReadAsync(buffer, 0, BufferSize, cancellationToken).ConfigureAwait(false)) > 0)
                        digest.Append(buffer, 0, read);
                    return Finish(algorithm, digest);
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer, clearArray: true);
            }
        }

        private static async Task<bool> VerifyCoreAsync(Task<ContentHash> actual, ContentHash expected) =>
            Matches(await actual.ConfigureAwait(false), expected);

        private static bool Matches(ContentHash actual, ContentHash expected) =>
            actual.Algorithm == expected.Algorithm && actual.KeyId == expected.KeyId &&
            HashPrimitives.FixedTimeEquals(actual.DigestBytes, expected.DigestBytes);

        private static ContentHash Finish(ContentHashAlgorithm algorithm, ContentDigest digest)
        {
            byte[] result = digest.GetHashAndReset();
            if (result.Length != algorithm.DigestLength)
                throw new InvalidOperationException($"Algorithm '{algorithm.Name}' produced a digest of the wrong length.");
            return ContentHash.FromOwned(algorithm, result);
        }
    }
}
