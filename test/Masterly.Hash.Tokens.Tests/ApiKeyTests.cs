using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Masterly.Hash.Tokens.Tests;

public class ApiKeyTests
{
    [Fact]
    public void GeneratedKeyHasDocumentedFormat()
    {
        string key = ApiKey.Generate("mh_live");

        Assert.StartsWith("mh_live_", key);
        string tail = key.Substring("mh_live_".Length);
        Assert.Equal(Base62.GetEncodedLength(ApiKey.DefaultEntropyBytes) + ApiKey.ChecksumLength, tail.Length);
        Assert.Equal(43 + 6, tail.Length);
        Assert.True(Base62.IsBase62(tail));
        Assert.True(key.Length <= ApiKey.MaxLength);
    }

    [Fact]
    public void ChecksumIsBase62Crc32OfPrefixAndRandom()
    {
        string key = ApiKey.Generate("acme_test2", 16);
        string body = key.Substring(0, key.Length - ApiKey.ChecksumLength);
        uint crc = Crc32.Compute(Encoding.ASCII.GetBytes(body));
        byte[] be = { (byte)(crc >> 24), (byte)(crc >> 16), (byte)(crc >> 8), (byte)crc };

        Assert.Equal(Base62.Encode(be), key.Substring(key.Length - ApiKey.ChecksumLength));
    }

    [Fact]
    public void ChecksumMatchesHandComputedVector()
    {
        // 16 zero bytes encode to 22 '0' digits; the checksum is base62(CRC-32("mh_" + 22 zeros)).
        string body = "mh_" + new string('0', 22);
        uint crc = Crc32.Compute(body);
        string key = body + Base62.Encode(new[] { (byte)(crc >> 24), (byte)(crc >> 16), (byte)(crc >> 8), (byte)crc });

        Assert.True(ApiKey.TryParse(key, out ApiKeyParts? parts));
        Assert.Equal("mh", parts!.Prefix);
        Assert.Equal(16, parts.EntropyBytes);
        Assert.Equal(new string('0', 22), parts.RandomPart);
    }

    [Theory]
    [InlineData(16, 22)]
    [InlineData(24, 33)]
    [InlineData(32, 43)]
    [InlineData(64, 86)]
    public void EntropyControlsRandomLength(int bytes, int chars)
    {
        string key = ApiKey.Generate("mh", bytes);
        Assert.True(ApiKey.TryParse(key, out ApiKeyParts? parts));
        Assert.Equal(chars, parts!.RandomPart.Length);
        Assert.Equal(bytes, parts.EntropyBytes);
    }

    [Fact]
    public void KeysAreUnique()
    {
        var keys = new HashSet<string>();
        for (int i = 0; i < 2000; i++)
            Assert.True(keys.Add(ApiKey.Generate("mh_live")));
    }

    [Fact]
    public void GeneratedKeysAlwaysHaveValidChecksum()
    {
        for (int i = 0; i < 500; i++)
            Assert.True(ApiKey.HasValidChecksum(ApiKey.Generate("mh_live", 16 + i % 49)));
    }

    [Fact]
    public void TryParseReturnsParts()
    {
        string key = ApiKey.Generate("mh_live");
        Assert.True(ApiKey.TryParse(key, out ApiKeyParts? parts));
        Assert.Equal("mh_live", parts!.Prefix);
        Assert.Equal(key, parts.Prefix + "_" + parts.RandomPart + parts.Checksum);
        Assert.Equal(ApiKey.ChecksumLength, parts.Checksum.Length);
        Assert.Equal(32, parts.EntropyBytes);
    }

    [Fact]
    public void PartsToStringHidesRandomPart()
    {
        Assert.True(ApiKey.TryParse(ApiKey.Generate("mh_live"), out ApiKeyParts? parts));
        string text = parts!.ToString();
        Assert.DoesNotContain(parts.RandomPart, text);
        Assert.Equal("mh_live_***" + parts.Checksum, text);
    }

    [Fact]
    public void EverySingleCharacterSubstitutionIsDetected()
    {
        string key = ApiKey.Generate("mh_live");
        const string candidates = Base62.Alphabet + "_-";
        int checks = 0;
        for (int i = 0; i < key.Length; i++)
        {
            foreach (char c in candidates)
            {
                if (c == key[i])
                    continue;
                char[] chars = key.ToCharArray();
                chars[i] = c;
                Assert.False(ApiKey.HasValidChecksum(new string(chars)), $"position {i} -> '{c}'");
                checks++;
            }
        }
        Assert.True(checks > 3000);
    }

    [Fact]
    public void EveryAdjacentTranspositionIsDetected()
    {
        string key = ApiKey.Generate("mh_live");
        for (int i = 0; i + 1 < key.Length; i++)
        {
            if (key[i] == key[i + 1])
                continue;
            char[] chars = key.ToCharArray();
            (chars[i], chars[i + 1]) = (chars[i + 1], chars[i]);
            Assert.False(ApiKey.HasValidChecksum(new string(chars)), $"swap at {i}");
        }
    }

    [Fact]
    public void DeletionsInsertionsAndTruncationsAreDetected()
    {
        string key = ApiKey.Generate("mh_live");
        for (int i = 0; i < key.Length; i++)
        {
            Assert.False(ApiKey.HasValidChecksum(key.Remove(i, 1)), $"delete {i}");
            Assert.False(ApiKey.HasValidChecksum(key.Insert(i, "a")), $"insert {i}");
            Assert.False(ApiKey.HasValidChecksum(key.Substring(0, i)), $"truncate {i}");
        }
        Assert.False(ApiKey.HasValidChecksum(key + "0"));
        Assert.False(ApiKey.HasValidChecksum(" " + key));
        Assert.False(ApiKey.HasValidChecksum(key + "\n"));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("_")]
    [InlineData("mh_")]
    [InlineData("_abcdef")]
    [InlineData("mh_live")]
    [InlineData("mh_live_")]
    [InlineData("mh_live_short")]
    [InlineData("1mh_0000000000000000000000000000")]
    [InlineData("mh__0000000000000000000000000000")]
    [InlineData("mh-live_0000000000000000000000000000")]
    [InlineData("ghp_16C7e42F292c6912E7710c838347Ae178B4a")]
    [InlineData("mh_live_zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz")]
    [InlineData("mh_live_00000000000000000000000000000000000000000000000é")]
    public void GarbageIsRejectedWithoutThrowing(string? input)
    {
        Assert.False(ApiKey.HasValidChecksum(input));
        Assert.False(ApiKey.TryParse(input, out ApiKeyParts? parts));
        Assert.Null(parts);
    }

    [Fact]
    public void OversizedInputIsRejected()
    {
        Assert.False(ApiKey.HasValidChecksum(new string('a', 100_000)));
        Assert.False(ApiKey.HasValidChecksum("mh_" + new string('0', ApiKey.MaxLength)));
    }

    [Fact]
    public void RandomPartOutOfRangeForItsLengthIsRejected()
    {
        // 22 'z' digits exceed 2^128, so they do not decode to 16 bytes, even with a correct checksum.
        string body = "mh_" + new string('z', 22);
        uint crc = Crc32.Compute(body);
        string key = body + Base62.Encode(new[] { (byte)(crc >> 24), (byte)(crc >> 16), (byte)(crc >> 8), (byte)crc });
        Assert.False(ApiKey.HasValidChecksum(key));
    }

    [Fact]
    public void FuzzedInputNeverThrows()
    {
        var rng = new Random(1234);
        string key = ApiKey.Generate("mh_live");
        for (int i = 0; i < 5000; i++)
        {
            char[] chars = key.ToCharArray();
            int edits = rng.Next(1, 4);
            for (int e = 0; e < edits; e++)
                chars[rng.Next(chars.Length)] = (char)rng.Next(0, 0xFFFF);
            string mutated = new string(chars).Substring(0, rng.Next(chars.Length + 1));
            ApiKey.TryParse(mutated, out _);
        }
    }

    [Theory]
    [InlineData("mh", true)]
    [InlineData("mh_live", true)]
    [InlineData("acme_test2", true)]
    [InlineData("A", true)]
    [InlineData("a_b_c", true)]
    [InlineData("", false)]
    [InlineData(null, false)]
    [InlineData("_mh", false)]
    [InlineData("mh_", false)]
    [InlineData("mh__live", false)]
    [InlineData("2mh", false)]
    [InlineData("mh-live", false)]
    [InlineData("mh live", false)]
    [InlineData("mé", false)]
    [InlineData("abcdefghijabcdefghijabcdefghijab", true)]
    [InlineData("abcdefghijabcdefghijabcdefghijabc", false)]
    public void PrefixValidation(string? prefix, bool valid) => Assert.Equal(valid, ApiKey.IsValidPrefix(prefix));

    [Fact]
    public void GenerateValidatesArguments()
    {
        Assert.Throws<ArgumentNullException>(() => ApiKey.Generate(null!));
        Assert.Throws<ArgumentException>(() => ApiKey.Generate("bad-prefix"));
        Assert.Throws<ArgumentException>(() => ApiKey.Generate(""));
        Assert.Throws<ArgumentOutOfRangeException>(() => ApiKey.Generate("mh", ApiKey.MinEntropyBytes - 1));
        Assert.Throws<ArgumentOutOfRangeException>(() => ApiKey.Generate("mh", ApiKey.MaxEntropyBytes + 1));
        Assert.Throws<ArgumentNullException>(() => ApiKey.Generate((ApiKeyHasher)null!, "mh"));
    }

    [Fact]
    public void GenerateWithHasherReturnsVerifiableKey()
    {
        var hasher = new ApiKeyHasher(TestKeys.Ring("k1", "k1"));
        GeneratedApiKey created = ApiKey.Generate(hasher, "mh_live");

        Assert.Equal("mh_live", created.Prefix);
        Assert.True(ApiKey.HasValidChecksum(created.PlainText));
        Assert.StartsWith("k1:", created.LookupHash);
        Assert.Equal(hasher.ComputeLookupHash(created.PlainText), created.LookupHash);
        Assert.True(hasher.Verify(created.PlainText, created.LookupHash));
    }

    [Fact]
    public void GeneratedApiKeyNeverPrintsTheSecret()
    {
        var hasher = new ApiKeyHasher(TestKeys.Ring("k1", "k1"));
        GeneratedApiKey created = ApiKey.Generate(hasher, "mh_live");
        Assert.True(ApiKey.TryParse(created.PlainText, out ApiKeyParts? parts));

        Assert.Equal(created.Hint, created.ToString());
        Assert.StartsWith("mh_live_...", created.Hint);
        Assert.EndsWith(created.PlainText.Substring(created.PlainText.Length - 4), created.Hint);
        Assert.DoesNotContain(parts!.RandomPart, created.ToString());
        Assert.Throws<ArgumentNullException>(() => new GeneratedApiKey(null!, "p", "h"));
    }

    [Fact]
    public void GeneratorUsesConfiguredPrefixAndEntropy()
    {
        var hasher = new ApiKeyHasher(TestKeys.Ring("k1", "k1"));
        var generator = new ApiKeyGenerator(hasher, "mh_test", 24);

        Assert.Equal("mh_test", generator.Prefix);
        Assert.Equal(24, generator.EntropyBytes);
        Assert.Same(hasher, generator.Hasher);

        GeneratedApiKey[] keys = Enumerable.Range(0, 20).Select(_ => generator.Generate()).ToArray();
        Assert.All(keys, k =>
        {
            Assert.True(ApiKey.TryParse(k.PlainText, out ApiKeyParts? p));
            Assert.Equal("mh_test", p!.Prefix);
            Assert.Equal(24, p.EntropyBytes);
            Assert.True(hasher.Verify(k.PlainText, k.LookupHash));
        });
        Assert.Equal(20, keys.Select(k => k.LookupHash).Distinct().Count());
    }

    [Fact]
    public void GeneratorValidatesArguments()
    {
        var hasher = new ApiKeyHasher(TestKeys.Ring("k1", "k1"));
        Assert.Throws<ArgumentNullException>(() => new ApiKeyGenerator(null!, "mh"));
        Assert.Throws<ArgumentNullException>(() => new ApiKeyGenerator(hasher, null!));
        Assert.Throws<ArgumentException>(() => new ApiKeyGenerator(hasher, "mh_"));
        Assert.Throws<ArgumentOutOfRangeException>(() => new ApiKeyGenerator(hasher, "mh", 8));
    }
}
