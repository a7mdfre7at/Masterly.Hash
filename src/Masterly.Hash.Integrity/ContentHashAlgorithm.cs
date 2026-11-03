using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using Masterly.Hash.Integrity.Internal;

namespace Masterly.Hash.Integrity
{
    /// <summary>
    /// A hash function usable for content hashes, Merkle trees, hash chains and manifests.
    /// Built in: <see cref="Sha256"/>, <see cref="Sha384"/>, <see cref="Sha512"/> and keyed <see cref="HmacSha256"/>.
    /// Satellite packages (for example Masterly.Hash.Integrity.Blake3) add more through <see cref="Register"/>.
    /// </summary>
    /// <remarks>
    /// Equality is by identity (<see cref="Name"/>, <see cref="KeyId"/>, <see cref="DigestLength"/>), never by key
    /// material: two HMAC instances with the same key id compare equal even if their keys differ.
    /// </remarks>
    public abstract class ContentHashAlgorithm : IEquatable<ContentHashAlgorithm>
    {
        /// <summary>Minimum length of an HMAC key in bytes.</summary>
        public const int MinHmacKeyLength = 32;

        private static readonly object RegistryLock = new object();
        private static readonly Dictionary<string, Registration> Registry = new Dictionary<string, Registration>(StringComparer.Ordinal);

        static ContentHashAlgorithm()
        {
            Sha256 = new BclAlgorithm("sha256", HashAlgorithmName.SHA256, 32);
            Sha384 = new BclAlgorithm("sha384", HashAlgorithmName.SHA384, 48);
            Sha512 = new BclAlgorithm("sha512", HashAlgorithmName.SHA512, 64);
            Register(Sha256);
            Register(Sha384);
            Register(Sha512);
            RegisterFamily("hmac-sha256", 32);
        }

        /// <summary>Creates an algorithm descriptor.</summary>
        /// <param name="name">Lowercase name written into hash strings; must match <c>^[a-z0-9][a-z0-9-]{0,31}$</c>.</param>
        /// <param name="digestLength">Digest length in bytes, 16 to 128.</param>
        /// <param name="keyId">Key id for keyed algorithms (<c>^[A-Za-z0-9-]{1,32}$</c>); <see langword="null"/> for plain hashes.</param>
        protected ContentHashAlgorithm(string name, int digestLength, string? keyId)
        {
            if (!Identifiers.IsValidAlgorithmName(name))
                throw new ArgumentException("Algorithm name must match ^[a-z0-9][a-z0-9-]{0,31}$.", nameof(name));
            if (digestLength < 16 || digestLength > 128)
                throw new ArgumentOutOfRangeException(nameof(digestLength), digestLength, "Digest length must be between 16 and 128 bytes.");
            if (keyId != null && !Identifiers.IsValidKeyId(keyId))
                throw new ArgumentException("Key id must match ^[A-Za-z0-9-]{1,32}$.", nameof(keyId));
            Name = name;
            DigestLength = digestLength;
            KeyId = keyId;
        }

        /// <summary>SHA-256 (FIPS 180-4). The default everywhere in this package.</summary>
        public static ContentHashAlgorithm Sha256 { get; }

        /// <summary>SHA-384 (FIPS 180-4).</summary>
        public static ContentHashAlgorithm Sha384 { get; }

        /// <summary>SHA-512 (FIPS 180-4).</summary>
        public static ContentHashAlgorithm Sha512 { get; }

        /// <summary>Lowercase algorithm name, e.g. <c>sha256</c> or <c>hmac-sha256</c>.</summary>
        public string Name { get; }

        /// <summary>Digest length in bytes.</summary>
        public int DigestLength { get; }

        /// <summary>Key id of a keyed algorithm; <see langword="null"/> for plain hashes.</summary>
        public string? KeyId { get; }

        /// <summary>True if the algorithm needs a secret key (a MAC).</summary>
        public bool IsKeyed => KeyId != null;

        /// <summary><c>name</c> or <c>name:keyId</c>.</summary>
        public string Identifier => KeyId == null ? Name : Name + ":" + KeyId;

        /// <summary>Starts a new incremental computation. Dispose it when done.</summary>
        public abstract ContentDigest CreateDigest();

        /// <summary>
        /// HMAC-SHA256 (RFC 2104) keyed with <paramref name="key"/>. Use it when an attacker who can write the stored
        /// hashes must not be able to forge new ones. The key is copied; keep it out of the data store.
        /// </summary>
        /// <param name="keyId">Id recorded next to every hash so keys can be rotated; <c>^[A-Za-z0-9-]{1,32}$</c>.</param>
        /// <param name="key">Secret key, at least <see cref="MinHmacKeyLength"/> bytes.</param>
        public static ContentHashAlgorithm HmacSha256(string keyId, byte[] key)
        {
            if (keyId == null) throw new ArgumentNullException(nameof(keyId));
            if (key == null) throw new ArgumentNullException(nameof(key));
            if (key.Length < MinHmacKeyLength)
                throw new ArgumentException($"HMAC key must be at least {MinHmacKeyLength} bytes.", nameof(key));
            return new HmacAlgorithm("hmac-sha256", HashAlgorithmName.SHA256, 32, keyId, key);
        }

        /// <summary>
        /// Makes an algorithm name known to <see cref="ContentHash.Parse"/>. For an unkeyed algorithm the instance
        /// also becomes resolvable through <see cref="TryGet"/>; for a keyed one only the name family is registered.
        /// Registering the same identity twice is a no-op; a conflicting registration throws.
        /// </summary>
        public static void Register(ContentHashAlgorithm algorithm)
        {
            if (algorithm == null) throw new ArgumentNullException(nameof(algorithm));
            RegisterCore(algorithm.Name, algorithm.DigestLength, algorithm.IsKeyed, algorithm.IsKeyed ? null : algorithm);
        }

        /// <summary>
        /// Registers a keyed algorithm family by name, so hashes such as <c>name:keyId:hex</c> parse before any keyed
        /// instance exists.
        /// </summary>
        /// <param name="name">Algorithm name, <c>^[a-z0-9][a-z0-9-]{0,31}$</c>.</param>
        /// <param name="digestLength">Digest length in bytes, 16 to 128.</param>
        public static void RegisterKeyedFamily(string name, int digestLength) => RegisterFamily(name, digestLength);

        /// <summary>Resolves a registered unkeyed algorithm by name. Keyed algorithms need their key and are never returned.</summary>
        public static bool TryGet(string? name, out ContentHashAlgorithm? algorithm)
        {
            algorithm = null;
            if (name == null)
                return false;
            lock (RegistryLock)
            {
                if (Registry.TryGetValue(name, out Registration? registration) && registration.Instance != null)
                    algorithm = registration.Instance;
            }
            return algorithm != null;
        }

        /// <summary>True if <paramref name="name"/> has been registered (keyed or not).</summary>
        public static bool IsRegistered(string? name)
        {
            if (name == null)
                return false;
            lock (RegistryLock)
                return Registry.ContainsKey(name);
        }

        internal static bool TryGetRegistration(string name, out int digestLength, out bool isKeyed)
        {
            lock (RegistryLock)
            {
                if (Registry.TryGetValue(name, out Registration? registration))
                {
                    digestLength = registration.DigestLength;
                    isKeyed = registration.IsKeyed;
                    return true;
                }
            }
            digestLength = 0;
            isKeyed = false;
            return false;
        }

        /// <summary>
        /// Resolves the algorithm for a stored hash identity: <paramref name="algorithm"/> if given (it must match),
        /// otherwise the registered unkeyed algorithm.
        /// </summary>
        internal static ContentHashAlgorithm Resolve(string name, string? keyId, ContentHashAlgorithm? algorithm, string paramName)
        {
            string identity = keyId == null ? name : name + ":" + keyId;
            if (algorithm != null)
            {
                if (algorithm.Name != name || algorithm.KeyId != keyId)
                    throw new ArgumentException($"Algorithm '{algorithm.Identifier}' does not match '{identity}'.", paramName);
                return algorithm;
            }
            if (keyId != null)
                throw new ArgumentException($"'{identity}' is keyed; pass the algorithm with its key.", paramName);
            if (!TryGet(name, out ContentHashAlgorithm? resolved))
                throw new ArgumentException($"Algorithm '{name}' is not registered.", paramName);
            return resolved!;
        }

        /// <summary>
        /// Non-throwing <see cref="Resolve"/> for verification paths, where the identity comes from stored (untrusted)
        /// data: a mismatch, a keyed identity without an algorithm, or an unregistered name all yield false.
        /// </summary>
        internal static bool TryResolve(string name, string? keyId, ContentHashAlgorithm? algorithm, out ContentHashAlgorithm? resolved)
        {
            resolved = null;
            if (algorithm != null)
            {
                if (algorithm.Name != name || algorithm.KeyId != keyId)
                    return false;
                resolved = algorithm;
                return true;
            }
            return keyId == null && TryGet(name, out resolved);
        }

        private static void RegisterFamily(string name, int digestLength)
        {
            if (!Identifiers.IsValidAlgorithmName(name))
                throw new ArgumentException("Algorithm name must match ^[a-z0-9][a-z0-9-]{0,31}$.", nameof(name));
            if (digestLength < 16 || digestLength > 128)
                throw new ArgumentOutOfRangeException(nameof(digestLength), digestLength, "Digest length must be between 16 and 128 bytes.");
            RegisterCore(name, digestLength, true, null);
        }

        private static void RegisterCore(string name, int digestLength, bool isKeyed, ContentHashAlgorithm? instance)
        {
            lock (RegistryLock)
            {
                if (Registry.TryGetValue(name, out Registration? existing))
                {
                    bool same = existing.DigestLength == digestLength && existing.IsKeyed == isKeyed &&
                                (isKeyed || existing.Instance!.GetType() == instance!.GetType());
                    if (!same)
                        throw new InvalidOperationException($"A different algorithm named '{name}' is already registered.");
                    return;
                }

                Registry[name] = new Registration(digestLength, isKeyed, instance);
            }
        }

        /// <inheritdoc />
        public bool Equals(ContentHashAlgorithm? other) =>
            other != null && Name == other.Name && KeyId == other.KeyId && DigestLength == other.DigestLength;

        /// <inheritdoc />
        public override bool Equals(object? obj) => Equals(obj as ContentHashAlgorithm);

        /// <inheritdoc />
        public override int GetHashCode() => StringComparer.Ordinal.GetHashCode(Identifier);

        /// <summary>Same as <see cref="Identifier"/>. Never includes key material.</summary>
        public override string ToString() => Identifier;

        private sealed class Registration
        {
            public Registration(int digestLength, bool isKeyed, ContentHashAlgorithm? instance)
            {
                DigestLength = digestLength;
                IsKeyed = isKeyed;
                Instance = instance;
            }

            public int DigestLength { get; }

            public bool IsKeyed { get; }

            public ContentHashAlgorithm? Instance { get; }
        }

        private sealed class BclAlgorithm : ContentHashAlgorithm
        {
            private readonly HashAlgorithmName _hash;

            public BclAlgorithm(string name, HashAlgorithmName hash, int digestLength)
                : base(name, digestLength, null)
            {
                _hash = hash;
            }

            public override ContentDigest CreateDigest() => new IncrementalDigest(IncrementalHash.CreateHash(_hash));
        }

        private sealed class HmacAlgorithm : ContentHashAlgorithm
        {
            private readonly HashAlgorithmName _hash;
            private readonly byte[] _key;

            public HmacAlgorithm(string name, HashAlgorithmName hash, int digestLength, string keyId, byte[] key)
                : base(name, digestLength, keyId)
            {
                _hash = hash;
                _key = (byte[])key.Clone();
            }

            public override ContentDigest CreateDigest() => new IncrementalDigest(IncrementalHash.CreateHMAC(_hash, _key));
        }

        private sealed class IncrementalDigest : ContentDigest
        {
            private readonly IncrementalHash _hash;

            public IncrementalDigest(IncrementalHash hash)
            {
                _hash = hash;
            }

            protected override void AppendCore(byte[] buffer, int offset, int count) => _hash.AppendData(buffer, offset, count);

            protected override byte[] GetHashAndResetCore() => _hash.GetHashAndReset();

            protected override void Dispose(bool disposing)
            {
                if (disposing)
                    _hash.Dispose();
            }
        }
    }
}
