using System;

namespace Masterly.Hash.Integrity.Blake3
{
    /// <summary>
    /// BLAKE3 for Masterly.Hash.Integrity: <see cref="Blake3"/> (<c>blake3:&lt;hex&gt;</c>) and the keyed mode
    /// <see cref="Keyed"/> (<c>blake3-keyed:&lt;keyId&gt;:&lt;hex&gt;</c>), both with 32-byte output.
    /// </summary>
    /// <remarks>
    /// Call <see cref="Register"/> once at startup so that <see cref="ContentHash.Parse"/> and the
    /// <see cref="DirectoryManifest"/> JSON reader recognise BLAKE3 hashes before any BLAKE3 hash has been computed.
    /// Hashing uses the fully managed implementation in the <c>Blake3</c> NuGet package.
    /// </remarks>
    public static class Blake3Algorithms
    {
        /// <summary>Algorithm name of plain BLAKE3.</summary>
        public const string Name = "blake3";

        /// <summary>Algorithm name of keyed BLAKE3.</summary>
        public const string KeyedName = "blake3-keyed";

        /// <summary>Output length in bytes (the BLAKE3 default).</summary>
        public const int DigestLength = 32;

        /// <summary>Required key length for keyed BLAKE3.</summary>
        public const int KeyLength = 32;

        static Blake3Algorithms()
        {
            Blake3 = new Blake3Algorithm();
            ContentHashAlgorithm.Register(Blake3);
            ContentHashAlgorithm.RegisterKeyedFamily(KeyedName, DigestLength);
        }

        /// <summary>Plain BLAKE3 with a 32-byte digest.</summary>
        public static ContentHashAlgorithm Blake3 { get; }

        /// <summary>Makes <c>blake3</c> and <c>blake3-keyed</c> known to the parsers. Idempotent and thread-safe.</summary>
        public static void Register()
        {
            // Touching the property guarantees that the static constructor has run.
            _ = Blake3;
        }

        /// <summary>
        /// Keyed BLAKE3 (a MAC). Use it where an attacker who can write stored hashes must not be able to forge them.
        /// The key is copied; keep it out of the data store.
        /// </summary>
        /// <param name="keyId">Id recorded with every hash, <c>^[A-Za-z0-9-]{1,32}$</c>.</param>
        /// <param name="key">Exactly <see cref="KeyLength"/> secret bytes.</param>
        public static ContentHashAlgorithm Keyed(string keyId, byte[] key)
        {
            if (keyId == null) throw new ArgumentNullException(nameof(keyId));
            if (key == null) throw new ArgumentNullException(nameof(key));
            if (key.Length != KeyLength)
                throw new ArgumentException($"BLAKE3 keys must be exactly {KeyLength} bytes.", nameof(key));
            Register();
            return new Blake3KeyedAlgorithm(keyId, key);
        }

        private sealed class Blake3Algorithm : ContentHashAlgorithm
        {
            public Blake3Algorithm()
                : base(Blake3Algorithms.Name, Blake3Algorithms.DigestLength, null)
            {
            }

            public override ContentDigest CreateDigest() => new Blake3Digest(global::Blake3.Hasher.New());
        }

        private sealed class Blake3KeyedAlgorithm : ContentHashAlgorithm
        {
            private readonly byte[] _key;

            public Blake3KeyedAlgorithm(string keyId, byte[] key)
                : base(KeyedName, Blake3Algorithms.DigestLength, keyId)
            {
                _key = (byte[])key.Clone();
            }

            public override ContentDigest CreateDigest() => new Blake3Digest(global::Blake3.Hasher.NewKeyed(_key));
        }

        private sealed class Blake3Digest : ContentDigest
        {
            private readonly global::Blake3.Hasher _hasher;

            public Blake3Digest(global::Blake3.Hasher hasher)
            {
                _hasher = hasher;
            }

            protected override void AppendCore(byte[] buffer, int offset, int count) =>
                _hasher.Update(new ReadOnlySpan<byte>(buffer, offset, count));

            protected override byte[] GetHashAndResetCore()
            {
                byte[] result = new byte[Blake3Algorithms.DigestLength];
                _hasher.Finalize(result);
                _hasher.Reset();
                return result;
            }

            protected override void Dispose(bool disposing)
            {
                // Hasher.Dispose clears the internal state (which holds key material in keyed mode).
                if (disposing)
                    _hasher.Dispose();
            }
        }
    }
}
