namespace Masterly.Hash.Legacy
{
    /// <summary>
    /// A read-only hash format from another system (or from Masterly.Hash 1.x). The hasher can verify these
    /// hashes but never produces them; a successful verify always reports that a rehash is needed.
    /// </summary>
    /// <remarks>
    /// Formats that also implement onion wrapping let <see cref="PasswordHasher.TryWrap"/> upgrade a weak hash
    /// offline, without the password: <c>Argon2id(legacyDigest)</c>. The wrapped hash stores the format id and
    /// the per-hash parameters (salt, cost) needed to recompute the legacy digest at login.
    /// </remarks>
    public interface ILegacyHashFormat
    {
        /// <summary>Stable id written into wrapped hashes, e.g. <c>v1</c>, <c>bcrypt</c>. Must match <c>^[a-z0-9][a-z0-9-]{0,31}$</c>.</summary>
        string Id { get; }

        /// <summary>Cheap syntactic check: does <paramref name="storedHash"/> look like this format?</summary>
        bool CanHandle(string storedHash);

        /// <summary>Verifies <paramref name="password"/> against a stored hash in this format. Must use a constant-time comparison.</summary>
        bool Verify(string password, string storedHash);

        /// <summary>
        /// For onion wrapping: splits a stored hash into its secret digest and the public parameters needed to
        /// recompute it. Returns false if this format (or this particular hash) cannot be wrapped.
        /// </summary>
        bool TryExtractWrapInput(string storedHash, out byte[] digest, out byte[] parameter);

        /// <summary>
        /// For onion wrapping: recomputes the digest from the password and the parameter returned by
        /// <see cref="TryExtractWrapInput"/>. For the right password the result must equal that digest exactly.
        /// </summary>
        byte[] ComputeWrapInput(string password, byte[] parameter);
    }
}
