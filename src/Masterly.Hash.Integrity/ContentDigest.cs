using System;

namespace Masterly.Hash.Integrity
{
    /// <summary>
    /// An incremental hash computation created by <see cref="ContentHashAlgorithm.CreateDigest"/>. Not thread-safe.
    /// </summary>
    public abstract class ContentDigest : IDisposable
    {
        private bool _disposed;

        /// <summary>Feeds <paramref name="count"/> bytes of <paramref name="buffer"/>, starting at <paramref name="offset"/>.</summary>
        public void Append(byte[] buffer, int offset, int count)
        {
            if (buffer == null) throw new ArgumentNullException(nameof(buffer));
            if (offset < 0 || offset > buffer.Length) throw new ArgumentOutOfRangeException(nameof(offset));
            if (count < 0 || count > buffer.Length - offset) throw new ArgumentOutOfRangeException(nameof(count));
            ThrowIfDisposed();
            if (count > 0)
                AppendCore(buffer, offset, count);
        }

        /// <summary>Feeds all of <paramref name="data"/>.</summary>
        public void Append(byte[] data)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));
            Append(data, 0, data.Length);
        }

        /// <summary>Returns the digest of everything appended so far and resets the state for reuse.</summary>
        public byte[] GetHashAndReset()
        {
            ThrowIfDisposed();
            return GetHashAndResetCore();
        }

        /// <summary>Releases the underlying hash state.</summary>
        public void Dispose()
        {
            if (_disposed)
                return;
            _disposed = true;
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>Feeds bytes. Arguments are already validated and <paramref name="count"/> is positive.</summary>
        protected abstract void AppendCore(byte[] buffer, int offset, int count);

        /// <summary>Finishes the computation and resets the state.</summary>
        protected abstract byte[] GetHashAndResetCore();

        /// <summary>Releases resources held by the implementation.</summary>
        protected virtual void Dispose(bool disposing)
        {
        }

        private void ThrowIfDisposed()
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().Name);
        }
    }
}
