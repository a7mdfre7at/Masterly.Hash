using System.Collections.Generic;

namespace Masterly.Hash.Detection
{
    /// <summary>
    /// Produces the decoy passwords ("honeywords") stored next to a user's real password. The security of the
    /// scheme rests entirely on the decoys being hard to tell apart from the real password.
    /// </summary>
    /// <remarks>
    /// <see cref="HoneywordService"/> normalizes the real password (NFKC) before calling the generator, checks the
    /// returned set, and shuffles the real password in at a random position; generators do not need to shuffle.
    /// Implementations must use a cryptographically secure random source and must not log or retain the input.
    /// </remarks>
    public interface IHoneywordGenerator
    {
        /// <summary>
        /// Returns exactly <paramref name="count"/> non-empty decoys, distinct from each other and from
        /// <paramref name="realPassword"/>.
        /// </summary>
        /// <param name="realPassword">The user's real password, NFKC-normalized. Never empty.</param>
        /// <param name="count">How many decoys to produce (sweetword count minus one).</param>
        IReadOnlyList<string> GenerateDecoys(string realPassword, int count);
    }
}
