namespace Masterly.Hash.Pwned.Internal
{
    /// <summary>Singleton that owns the range cache shared by the transient typed clients.</summary>
    internal sealed class PwnedPasswordsCacheHolder
    {
        public PwnedPasswordsCacheHolder(RangeCache? cache)
        {
            Cache = cache;
        }

        public RangeCache? Cache { get; }
    }
}
