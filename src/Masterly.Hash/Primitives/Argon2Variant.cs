namespace Masterly.Hash.Primitives
{
    /// <summary>The Argon2 variant for <see cref="HashPrimitives.Argon2"/> (RFC 9106 type <c>y</c>).</summary>
    public enum Argon2Variant
    {
        /// <summary>Argon2d: data-dependent memory access. Fastest against GPUs, but exposed to side channels.</summary>
        Argon2d = 0,

        /// <summary>Argon2i: data-independent memory access.</summary>
        Argon2i = 1,

        /// <summary>Argon2id: Argon2i for the first half of the first pass, then Argon2d. The RFC 9106 recommendation.</summary>
        Argon2id = 2,
    }
}
