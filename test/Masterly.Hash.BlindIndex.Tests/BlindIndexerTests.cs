using System;
using System.Collections.Generic;
using System.Linq;
using Masterly.Hash.BlindIndex.Normalizers;
using Masterly.Hash.Primitives;

namespace Masterly.Hash.BlindIndex.Tests;

public class BlindIndexerTests
{
    private readonly BlindIndexer _indexer = TestKeys.Single();

    // ---- determinism and format ----

    [Fact]
    public void Compute_is_deterministic_across_instances()
    {
        var other = new BlindIndexer("k1", TestKeys.Derived("k1"));
        Assert.Equal(_indexer.Compute("alice@example.com", "users.email"), _indexer.Compute("alice@example.com", "users.email"));
        Assert.Equal(_indexer.Compute("alice@example.com", "users.email"), other.Compute("alice@example.com", "users.email"));
    }

    [Fact]
    public void Output_is_key_id_colon_canonical_base64()
    {
        string index = _indexer.Compute("value", "t.c");
        string[] parts = index.Split(':');
        Assert.Equal(2, parts.Length);
        Assert.Equal("k1", parts[0]);
        Assert.True(HashPrimitives.TryFromB64(parts[1], out byte[] tag));
        Assert.Equal(8, tag.Length);
        Assert.True(BlindIndexer.TryGetKeyId(index, out string keyId));
        Assert.Equal("k1", keyId);
    }

    [Theory]
    [InlineData(16)]
    [InlineData(24)]
    [InlineData(32)]
    [InlineData(64)]
    [InlineData(128)]
    [InlineData(200)]
    [InlineData(256)]
    public void Truncation_length_matches_output_bits(int bits)
    {
        string index = _indexer.Compute("value", "t.c", TestKeys.Bits(bits));
        Assert.True(HashPrimitives.TryFromB64(index.Substring(3), out byte[] tag));
        Assert.Equal(bits / 8, tag.Length);
    }

    [Fact]
    public void Shorter_indexes_are_prefixes_of_the_full_mac()
    {
        HashPrimitives.TryFromB64(_indexer.Compute("v", "t.c", TestKeys.Bits(256)).Substring(3), out byte[] full);
        for (int bits = 16; bits <= 256; bits += 8)
        {
            HashPrimitives.TryFromB64(_indexer.Compute("v", "t.c", TestKeys.Bits(bits)).Substring(3), out byte[] tag);
            Assert.Equal(full.Take(bits / 8), tag);
        }
    }

    [Fact]
    public void Different_values_give_different_indexes()
    {
        var seen = new HashSet<string>();
        for (int i = 0; i < 1000; i++)
            Assert.True(seen.Add(_indexer.Compute("user" + i + "@example.com", "users.email")));
    }

    [Fact]
    public void Different_keys_give_unrelated_indexes()
    {
        string a = new BlindIndexer("k", TestKeys.Derived("a")).Compute("v", "t.c");
        string b = new BlindIndexer("k", TestKeys.Derived("b")).Compute("v", "t.c");
        Assert.NotEqual(a, b);
    }

    // ---- domain separation ----

    [Fact]
    public void Same_value_in_two_columns_gives_unrelated_indexes()
    {
        string a = _indexer.Compute("alice@example.com", "users.email");
        string b = _indexer.Compute("alice@example.com", "orders.email");
        Assert.NotEqual(a, b);
    }

    [Fact]
    public void Length_prefixing_prevents_name_value_boundary_shifts()
    {
        // Without length prefixes, ("ab", "c") and ("a", "bc") would hash the same bytes.
        Assert.NotEqual(_indexer.Compute("c", "ab"), _indexer.Compute("bc", "a"));
        Assert.NotEqual(_indexer.Compute("c", "a.b"), _indexer.Compute("b.c", "a"));
    }

    [Fact]
    public void Compound_parts_are_unambiguous()
    {
        string a = _indexer.ComputeCompound("t.c", "ab", "c");
        string b = _indexer.ComputeCompound("t.c", "a", "bc");
        string c = _indexer.ComputeCompound("t.c", "abc");
        string d = _indexer.ComputeCompound("t.c", "abc", "");
        string e = _indexer.ComputeCompound("t.c", "a\0", "bc");
        Assert.Equal(5, new HashSet<string> { a, b, c, d, e }.Count);
    }

    [Fact]
    public void Compound_part_order_matters()
    {
        Assert.NotEqual(_indexer.ComputeCompound("t.c", "smith", "1990"), _indexer.ComputeCompound("t.c", "1990", "smith"));
    }

    [Fact]
    public void Single_part_compound_differs_from_single_value_index()
    {
        Assert.NotEqual(_indexer.Compute("abc", "t.c"), _indexer.ComputeCompound("t.c", "abc"));
    }

    [Fact]
    public void Compound_normalizes_each_part()
    {
        var options = TestKeys.Bits(64, BlindIndexNormalizers.CaseInsensitive);
        Assert.Equal(_indexer.ComputeCompound("t.c", options, "SMITH", "John"), _indexer.ComputeCompound("t.c", options, "smith", "jOHN"));
    }

    [Fact]
    public void Compound_is_deterministic_and_respects_bits()
    {
        string a = _indexer.ComputeCompound("t.c", TestKeys.Bits(128), "x", "y");
        Assert.Equal(a, _indexer.ComputeCompound("t.c", TestKeys.Bits(128), "x", "y"));
        HashPrimitives.TryFromB64(a.Substring(3), out byte[] tag);
        Assert.Equal(16, tag.Length);
    }

    // ---- normalization through the indexer ----

    [Fact]
    public void Normalizer_is_applied_before_hashing()
    {
        var options = TestKeys.Bits(64, BlindIndexNormalizers.Email);
        Assert.Equal(_indexer.Compute(" Alice@Example.COM ", "users.email", options), _indexer.Compute("alice@example.com", "users.email", options));
        Assert.Equal(_indexer.Compute("alice@example.com", "users.email"), _indexer.Compute("alice@example.com", "users.email", options));
    }

    [Fact]
    public void Exact_normalizer_distinguishes_case()
    {
        Assert.NotEqual(_indexer.Compute("Alice", "t.c"), _indexer.Compute("alice", "t.c"));
    }

    [Fact]
    public void Custom_normalizer_is_used()
    {
        var options = new BlindIndexOptions { Normalizer = new DigitsOnly() };
        Assert.Equal(_indexer.Compute("a1b2", "t.c", options), _indexer.Compute("12", "t.c", options));
    }

    // ---- rotation ----

    [Fact]
    public void ComputeAll_returns_current_first_then_others()
    {
        BlindIndexer ring = TestKeys.Ring("2026", "2024", "2026", "2025");
        Assert.Equal(new[] { "2026", "2024", "2025" }, ring.KeyIds);

        IReadOnlyList<string> all = ring.ComputeAll("alice@example.com", "users.email");
        Assert.Equal(3, all.Count);
        Assert.Equal(ring.Compute("alice@example.com", "users.email"), all[0]);
        Assert.Equal(ring.ComputeWithKey("2024", "alice@example.com", "users.email"), all[1]);
        Assert.Equal(ring.ComputeWithKey("2025", "alice@example.com", "users.email"), all[2]);
        Assert.Equal(3, all.Distinct().Count());
    }

    [Fact]
    public void Rotation_scenario_finds_rows_indexed_under_old_key()
    {
        BlindIndexer before = TestKeys.Ring("old", "old");
        string storedRow = before.Compute("alice@example.com", "users.email");

        BlindIndexer during = TestKeys.Ring("new", "old", "new");
        Assert.Contains(storedRow, during.ComputeAll("alice@example.com", "users.email"));
        Assert.True(during.NeedsReindex(storedRow));
        Assert.True(during.Matches(storedRow, "alice@example.com", "users.email"));

        string reindexed = during.Compute("alice@example.com", "users.email");
        Assert.False(during.NeedsReindex(reindexed));
        Assert.StartsWith("new:", reindexed);

        BlindIndexer after = TestKeys.Ring("new", "new");
        Assert.Equal(reindexed, after.Compute("alice@example.com", "users.email"));
        Assert.False(after.Matches(storedRow, "alice@example.com", "users.email"));
    }

    [Fact]
    public void ComputeCompoundAll_covers_every_key()
    {
        BlindIndexer ring = TestKeys.Ring("b", "a", "b");
        IReadOnlyList<string> all = ring.ComputeCompoundAll("t.c", "x", "y");
        Assert.Equal(new[] { ring.ComputeCompound("t.c", "x", "y"), TestKeys.Ring("a", "a").ComputeCompound("t.c", "x", "y") }, all);
        Assert.Equal(all, ring.ComputeCompoundAll("t.c", (BlindIndexOptions?)null, "x", "y"));
    }

    [Fact]
    public void Index_does_not_depend_on_other_keys_in_ring()
    {
        Assert.Equal(TestKeys.Ring("a", "a").Compute("v", "t.c"), TestKeys.Ring("a", "a", "b", "c").Compute("v", "t.c"));
    }

    // ---- Matches / NeedsReindex / TryGetKeyId ----

    [Fact]
    public void Matches_true_for_correct_value_false_otherwise()
    {
        var options = TestKeys.Bits(32, BlindIndexNormalizers.Email);
        string stored = _indexer.Compute("alice@example.com", "users.email", options);
        Assert.True(_indexer.Matches(stored, "ALICE@example.com", "users.email", options));
        Assert.False(_indexer.Matches(stored, "bob@example.com", "users.email", options));
        Assert.False(_indexer.Matches(stored, "alice@example.com", "orders.email", options));
        Assert.False(_indexer.Matches(stored, "alice@example.com", "users.email", TestKeys.Bits(64, BlindIndexNormalizers.Email)));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(":")]
    [InlineData("k1")]
    [InlineData("k1:")]
    [InlineData(":AAAAAAAAAAA")]
    [InlineData("unknown:AAAAAAAAAAA")]
    [InlineData("k1:not base64!")]
    [InlineData("k1:AAAAAAAAAAA=")]
    [InlineData("k1:AAAAAAAAAAB")]
    [InlineData("k1:AA")]
    [InlineData("bad id:AAAAAAAAAAA")]
    [InlineData("k1:AAAAAAAAAAA:extra")]
    [InlineData("k1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    public void Malformed_stored_index_never_throws(string? stored)
    {
        Assert.False(_indexer.Matches(stored, "value", "t.c"));
        Assert.True(_indexer.NeedsReindex(stored));
    }

    [Fact]
    public void Oversized_stored_index_is_rejected_before_decoding()
    {
        // Longest well-formed index: 32-char key id + ':' + 43 chars (unpadded base64 of 32 bytes).
        BlindIndexer ring = TestKeys.Ring(new string('a', 32), new string('a', 32));
        string longest = ring.Compute("v", "t.c", TestKeys.Bits(256));
        Assert.Equal(76, longest.Length);
        Assert.True(BlindIndexer.TryGetKeyId(longest, out _));
        Assert.True(ring.Matches(longest, "v", "t.c", TestKeys.Bits(256)));

        string tooLong = longest + "A";
        Assert.False(BlindIndexer.TryGetKeyId(tooLong, out _));
        string huge = "k1:" + new string('A', 4_000_000);
        Assert.False(BlindIndexer.TryGetKeyId(huge, out string id));
        Assert.Equal(string.Empty, id);
        Assert.False(_indexer.Matches(huge, "value", "t.c"));
        Assert.True(_indexer.NeedsReindex(huge));
        Assert.False(BlindIndexer.TryGetKeyId(new string('a', 33) + ":AAAAAAAAAAA", out _));
    }

    [Fact]
    public void KeyIds_cannot_be_mutated_by_callers()
    {
        BlindIndexer ring = TestKeys.Ring("b", "a", "b");
        IReadOnlyList<string> ids = ring.KeyIds;
        Assert.False(ids is string[]);
        Assert.Throws<NotSupportedException>(() => ((IList<string>)ids)[0] = "zzz");
        Assert.Equal(new[] { "b", "a" }, ring.KeyIds);
        Assert.Equal(ring.Compute("v", "t.c"), ring.ComputeAll("v", "t.c")[0]);
    }

    [Fact]
    public void Wrong_tag_under_known_key_does_not_match()
    {
        Assert.False(_indexer.Matches("k1:AAAAAAAAAAA", "value", "t.c"));
        Assert.False(_indexer.NeedsReindex("k1:AAAAAAAAAAA"));
    }

    [Fact]
    public void NeedsReindex_false_only_for_current_key()
    {
        BlindIndexer ring = TestKeys.Ring("b", "a", "b");
        Assert.False(ring.NeedsReindex(ring.Compute("v", "t.c")));
        Assert.True(ring.NeedsReindex(ring.ComputeWithKey("a", "v", "t.c")));
    }

    [Fact]
    public void TryGetKeyId_reads_old_key_ids()
    {
        string stored = TestKeys.Ring("legacy-1", "legacy-1").Compute("v", "t.c");
        Assert.True(BlindIndexer.TryGetKeyId(stored, out string id));
        Assert.Equal("legacy-1", id);
        Assert.False(BlindIndexer.TryGetKeyId("garbage", out id));
        Assert.Equal(string.Empty, id);
    }

    // ---- key ring construction ----

    [Fact]
    public void Key_ring_copies_keys()
    {
        byte[] key = TestKeys.Derived("copy");
        var indexer = new BlindIndexer("k", key);
        string before = indexer.Compute("v", "t.c");
        Array.Clear(key);
        Assert.Equal(before, indexer.Compute("v", "t.c"));
    }

    [Fact]
    public void FromBase64_matches_raw_keys()
    {
        byte[] a = TestKeys.Derived("a");
        byte[] b = TestKeys.Derived("b");
        BlindIndexer fromB64 = BlindIndexer.FromBase64("b", new Dictionary<string, string>
        {
            ["a"] = Convert.ToBase64String(a),
            ["b"] = Convert.ToBase64String(b),
        });
        BlindIndexer raw = new("b", new Dictionary<string, byte[]> { ["a"] = a, ["b"] = b });
        Assert.Equal(raw.ComputeAll("v", "t.c"), fromB64.ComputeAll("v", "t.c"));
    }

    [Fact]
    public void GenerateKey_is_random_and_long_enough()
    {
        byte[] a = BlindIndexer.GenerateKey();
        byte[] b = BlindIndexer.GenerateKey();
        Assert.Equal(BlindIndexer.MinKeyLength, a.Length);
        Assert.NotEqual(a, b);
        _ = new BlindIndexer("k", a);
    }

    [Fact]
    public void Indexer_is_thread_safe()
    {
        BlindIndexer ring = TestKeys.Ring("b", "a", "b");
        string expected = ring.Compute("v", "t.c");
        var results = new string[2000];
        System.Threading.Tasks.Parallel.For(0, results.Length, i => results[i] = ring.Compute("v", "t.c"));
        Assert.All(results, r => Assert.Equal(expected, r));
    }

    [Fact]
    public void Implements_interface()
    {
        IBlindIndexer indexer = _indexer;
        Assert.Equal("k1", indexer.CurrentKeyId);
        Assert.Equal(_indexer.Compute("v", "t.c"), indexer.Compute("v", "t.c"));
    }

    private sealed class DigitsOnly : IBlindIndexNormalizer
    {
        public string Normalize(string value) => new(value.Where(char.IsAsciiDigit).ToArray());
    }
}
