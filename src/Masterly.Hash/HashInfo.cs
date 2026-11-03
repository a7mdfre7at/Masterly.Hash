namespace Masterly.Hash
{
    /// <summary>What a stored hash is, without verifying it. Used for audits and migration planning.</summary>
    public sealed class HashInfo
    {
        /// <summary>The <see cref="Format"/> of hashes produced by Masterly.Hash 2.x.</summary>
        public const string NativeFormat = "mh";

        /// <summary>The <see cref="Format"/> of strings no configured format recognizes.</summary>
        public const string UnknownFormat = "unknown";

        /// <summary>Creates a description of a stored hash, for custom <see cref="IPasswordHasher"/> implementations and test fakes.</summary>
        public HashInfo(string format, bool isRecognized, string? profileId, HashProfile? profile, string? pepperKeyId, string? wrappedFormat, RehashReason rehashReason)
        {
            Format = format ?? throw new System.ArgumentNullException(nameof(format));
            IsRecognized = isRecognized;
            ProfileId = profileId;
            Profile = profile;
            PepperKeyId = pepperKeyId;
            WrappedFormat = wrappedFormat;
            RehashReason = rehashReason;
        }

        /// <summary><c>mh</c> for Masterly hashes, a legacy format id (e.g. <c>v1</c>, <c>bcrypt</c>), or <c>unknown</c>.</summary>
        public string Format { get; }

        /// <summary>True if this hasher can verify the hash.</summary>
        public bool IsRecognized { get; }

        /// <summary>Profile id from a Masterly hash.</summary>
        public string? ProfileId { get; }

        /// <summary>The registered profile, or null if the id is not in the allowlist.</summary>
        public HashProfile? Profile { get; }

        /// <summary>Pepper key id, if the hash is peppered.</summary>
        public string? PepperKeyId { get; }

        /// <summary>The legacy format inside an onion-wrapped hash.</summary>
        public string? WrappedFormat { get; }

        /// <summary>Why the hash would be rehashed on a successful login, or <see cref="Masterly.Hash.RehashReason.None"/>.</summary>
        public RehashReason RehashReason { get; }

        /// <summary>True for hashes produced by Masterly.Hash 2.x (<see cref="NativeFormat"/>).</summary>
        public bool IsNative => Format == NativeFormat;

        /// <summary>True if a successful login would replace this hash.</summary>
        public bool NeedsRehash => RehashReason != RehashReason.None;
    }
}
