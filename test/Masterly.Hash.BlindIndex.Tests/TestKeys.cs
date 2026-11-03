using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Masterly.Hash.BlindIndex.Tests;

internal static class TestKeys
{
    /// <summary>The key 0x00, 0x01, ..., 0x1f used by the known-answer vectors.</summary>
    public static byte[] Sequential => Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();

    public static byte[] Derived(string id) => SHA256.HashData(Encoding.UTF8.GetBytes("blind-index-key-" + id));

    public static BlindIndexer Ring(string currentKeyId, params string[] keyIds)
    {
        var keys = new Dictionary<string, byte[]>();
        foreach (string id in keyIds)
            keys[id] = Derived(id);
        return new BlindIndexer(currentKeyId, keys);
    }

    public static BlindIndexer Single(string keyId = "k1") => new(keyId, Derived(keyId));

    public static BlindIndexOptions Bits(int bits, IBlindIndexNormalizer? normalizer = null) =>
        new() { OutputBits = bits, Normalizer = normalizer ?? BlindIndexNormalizers.Exact };
}
