namespace Masterly.Hash.EntityFrameworkCore
{
    /// <summary>
    /// Names of the model annotations written by <see cref="MasterlyHashPropertyBuilderExtensions"/>. Every value is a
    /// string, bool or int, so the annotations round-trip through migration snapshots.
    /// </summary>
    public static class MasterlyHashAnnotationNames
    {
        /// <summary>Common prefix of every annotation.</summary>
        public const string Prefix = "Masterly:";

        /// <summary>On a password property: <c>true</c> if the interceptor hashes it.</summary>
        public const string HashedPassword = Prefix + "HashedPassword";

        /// <summary>On a blind-index source property: name of the property that receives the index.</summary>
        public const string BlindIndexProperty = Prefix + "BlindIndex:Property";

        /// <summary>On a blind-index source property: the index name used for domain separation.</summary>
        public const string BlindIndexName = Prefix + "BlindIndex:Name";

        /// <summary>On a blind-index source property: id of the normalizer.</summary>
        public const string BlindIndexNormalizer = Prefix + "BlindIndex:Normalizer";

        /// <summary>On a blind-index source property: index length in bits.</summary>
        public const string BlindIndexOutputBits = Prefix + "BlindIndex:OutputBits";
    }
}
