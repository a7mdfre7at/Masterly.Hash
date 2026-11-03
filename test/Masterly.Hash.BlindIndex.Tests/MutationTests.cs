using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Masterly.Hash.BlindIndex.Normalizers;
using Masterly.Hash.Primitives;

namespace Masterly.Hash.BlindIndex.Tests;

/// <summary>
/// Precise assertions (exact boundaries, exception types, parameter names and messages, wire bytes) that pin behaviour
/// a looser test would let drift.
/// </summary>
public class MutationTests
{
    private readonly BlindIndexer _indexer = TestKeys.Single();

    // ---- BlindIndexMath ----

    [Fact]
    public void MinimumOutputBits_accepts_zero_distinct_values()
    {
        Assert.Equal(BlindIndexOptions.MinOutputBits, BlindIndexMath.MinimumOutputBits(0, 1.0));
    }

    [Fact]
    public void MinimumOutputBits_checks_distinct_values_before_the_target()
    {
        var ex = Assert.Throws<ArgumentOutOfRangeException>(() => BlindIndexMath.MinimumOutputBits(-1, 0));
        Assert.Equal("distinctValues", ex.ParamName);
    }

    [Fact]
    public void MinimumOutputBits_accepts_a_length_exactly_at_the_target()
    {
        // (65_537 - 1) / 2^16 == 1 exactly, and (2^24 + 1 - 1) / 2^24 == 1 exactly.
        Assert.Equal(1.0, BlindIndexMath.ExpectedFalsePositivesPerQuery(65_537, 16));
        Assert.Equal(16, BlindIndexMath.MinimumOutputBits(65_537, 1.0));
        Assert.Equal(24, BlindIndexMath.MinimumOutputBits((1L << 24) + 1, 1.0));
    }

    [Fact]
    public void Math_exception_messages()
    {
        var target = Assert.Throws<ArgumentOutOfRangeException>(() => BlindIndexMath.MinimumOutputBits(10, -1));
        Assert.Equal("maxFalsePositivesPerQuery", target.ParamName);
        Assert.StartsWith("Target must be a positive finite number.", target.Message);

        var bits = Assert.Throws<ArgumentOutOfRangeException>(() => BlindIndexMath.ExpectedCollidingPairs(10, 12));
        Assert.Equal("outputBits", bits.ParamName);
        Assert.Equal(12, bits.ActualValue);
        Assert.StartsWith("OutputBits must be a multiple of 8 from 16 to 256.", bits.Message);
    }

    // ---- BlindIndexOptions ----

    [Fact]
    public void Options_output_bits_exception_message()
    {
        var ex = Assert.Throws<ArgumentOutOfRangeException>(() => new BlindIndexOptions { OutputBits = 12 });
        Assert.Equal("value", ex.ParamName);
        Assert.Equal(12, ex.ActualValue);
        Assert.StartsWith("OutputBits must be a multiple of 8 from 16 to 256.", ex.Message);
    }

    // ---- BlindIndexer constructor ----

    [Fact]
    public void Null_current_key_id_in_a_ring_is_an_argument_exception_not_a_dictionary_error()
    {
        var keys = new Dictionary<string, byte[]> { ["k"] = TestKeys.Derived("k") };
        var ex = Assert.Throws<ArgumentException>(() => new BlindIndexer(null!, keys));
        Assert.Equal("currentKeyId", ex.ParamName);
        Assert.StartsWith("Key id must match ^[A-Za-z0-9-]{1,32}$.", ex.Message);
    }

    [Fact]
    public void Invalid_current_key_id_message()
    {
        var keys = new Dictionary<string, byte[]> { ["k"] = TestKeys.Derived("k") };
        var ex = Assert.Throws<ArgumentException>(() => new BlindIndexer("bad id", keys));
        Assert.Equal("currentKeyId", ex.ParamName);
        Assert.StartsWith("Key id must match ^[A-Za-z0-9-]{1,32}$.", ex.Message);
    }

    [Fact]
    public void Empty_key_id_is_rejected()
    {
        byte[] key = TestKeys.Derived("k");
        var current = Assert.Throws<ArgumentException>(() => new BlindIndexer("", key));
        Assert.Equal("currentKeyId", current.ParamName);

        var ring = Assert.Throws<ArgumentException>(() =>
            new BlindIndexer("k", new Dictionary<string, byte[]> { ["k"] = key, [""] = key }));
        Assert.Equal("keys", ring.ParamName);
        Assert.StartsWith("Every key id must match ^[A-Za-z0-9-]{1,32}$.", ring.Message);
    }

    [Fact]
    public void Short_key_and_missing_current_key_messages()
    {
        var shortKey = Assert.Throws<ArgumentException>(() => new BlindIndexer("k", new byte[31]));
        Assert.Equal("keys", shortKey.ParamName);
        Assert.StartsWith("Blind index key 'k' must be at least 32 bytes.", shortKey.Message);

        var missing = Assert.Throws<ArgumentException>(() =>
            new BlindIndexer("missing", new Dictionary<string, byte[]> { ["k"] = TestKeys.Derived("k") }));
        Assert.Equal("currentKeyId", missing.ParamName);
        Assert.StartsWith("Current key 'missing' is not in the key ring.", missing.Message);
    }

    [Fact]
    public void Null_key_id_for_the_single_key_constructor_names_keyId()
    {
        var ex = Assert.Throws<ArgumentNullException>(() => new BlindIndexer(null!, TestKeys.Derived("k")));
        Assert.Equal("keyId", ex.ParamName);
    }

    [Fact]
    public void Older_key_ids_are_sorted_ordinally_after_the_current_one()
    {
        var keys = new Dictionary<string, byte[]>
        {
            ["m"] = TestKeys.Derived("m"),
            ["z"] = TestKeys.Derived("z"),
            ["b"] = TestKeys.Derived("b"),
            ["a"] = TestKeys.Derived("a"),
            ["B"] = TestKeys.Derived("B"),
        };
        var ring = new BlindIndexer("m", keys);
        Assert.Equal(new[] { "m", "B", "a", "b", "z" }, ring.KeyIds);

        IReadOnlyList<string> all = ring.ComputeAll("v", "t.c");
        Assert.Equal(new[] { "m", "B", "a", "b", "z" }, all.Select(s => s.Split(':')[0]));
    }

    [Theory]
    [InlineData("A")]
    [InlineData("Z")]
    [InlineData("a")]
    [InlineData("z")]
    [InlineData("0")]
    [InlineData("9")]
    [InlineData("-")]
    public void Key_id_character_class_boundaries_are_accepted(string id)
    {
        var indexer = new BlindIndexer(id, TestKeys.Derived(id));
        string index = indexer.Compute("v", "t.c");
        Assert.StartsWith(id + ":", index);
        Assert.True(BlindIndexer.TryGetKeyId(index, out string parsed));
        Assert.Equal(id, parsed);
    }

    [Theory]
    [InlineData("@")]
    [InlineData("[")]
    [InlineData("`")]
    [InlineData("{")]
    [InlineData("/")]
    [InlineData(":")]
    [InlineData("_")]
    public void Key_id_characters_just_outside_the_class_are_rejected(string id)
    {
        var ex = Assert.Throws<ArgumentException>(() => new BlindIndexer(id, TestKeys.Derived("x")));
        Assert.Equal("currentKeyId", ex.ParamName);
    }

    // ---- index names ----

    [Theory]
    [InlineData("A")]
    [InlineData("Z")]
    [InlineData("a")]
    [InlineData("z")]
    [InlineData("0")]
    [InlineData("9")]
    [InlineData(".")]
    [InlineData("_")]
    [InlineData(":")]
    [InlineData("/")]
    [InlineData("-")]
    public void Index_name_character_class_boundaries_are_accepted(string name)
    {
        Assert.StartsWith("k1:", _indexer.Compute("v", name));
    }

    [Theory]
    [InlineData("@")]
    [InlineData("[")]
    [InlineData("`")]
    [InlineData("{")]
    [InlineData(";")]
    public void Index_name_characters_just_outside_the_class_are_rejected(string name)
    {
        var ex = Assert.Throws<ArgumentException>(() => _indexer.Compute("v", name));
        Assert.Equal("indexName", ex.ParamName);
        Assert.StartsWith("Index name must match ^[A-Za-z0-9._:/-]{1,128}$.", ex.Message);
    }

    // ---- argument order and messages ----

    [Fact]
    public void Null_key_id_for_ComputeWithKey_names_keyId()
    {
        var ex = Assert.Throws<ArgumentNullException>(() => _indexer.ComputeWithKey(null!, "v", "t.c"));
        Assert.Equal("keyId", ex.ParamName);
    }

    [Fact]
    public void Null_value_is_reported_before_the_index_name_is_validated()
    {
        var ex = Assert.Throws<ArgumentNullException>(() => _indexer.Compute(null!, "bad name"));
        Assert.Equal("value", ex.ParamName);

        ex = Assert.Throws<ArgumentNullException>(() => _indexer.Matches("k1:AAAAAAAAAAA", null!, "bad name"));
        Assert.Equal("value", ex.ParamName);
    }

    [Fact]
    public void Null_value_is_rejected_even_when_the_normalizer_accepts_null()
    {
        var options = new BlindIndexOptions { Normalizer = new ConstantNormalizer("x") };
        var ex = Assert.Throws<ArgumentNullException>(() => _indexer.Compute(null!, "t.c", options));
        Assert.Equal("value", ex.ParamName);
    }

    [Fact]
    public void Empty_after_normalization_message()
    {
        var ex = Assert.Throws<ArgumentException>(() => _indexer.Compute("   ", "t.c", TestKeys.Bits(64, BlindIndexNormalizers.Trim)));
        Assert.Equal("value", ex.ParamName);
        Assert.StartsWith("Value is empty after normalization.", ex.Message);
    }

    [Fact]
    public void Empty_compound_parts_are_reported_before_the_index_name_is_validated()
    {
        var ex = Assert.Throws<ArgumentException>(() => _indexer.ComputeCompound("bad name"));
        Assert.Equal("parts", ex.ParamName);
        Assert.StartsWith("A compound index needs at least one part.", ex.Message);

        ex = Assert.Throws<ArgumentException>(() => _indexer.ComputeCompound("t.c"));
        Assert.Equal("parts", ex.ParamName);
        Assert.StartsWith("A compound index needs at least one part.", ex.Message);
    }

    [Fact]
    public void Null_compound_part_names_parts()
    {
        var ex = Assert.Throws<ArgumentNullException>(() => _indexer.ComputeCompound("t.c", "a", null!));
        Assert.Equal("parts", ex.ParamName);
        Assert.StartsWith("Compound index parts cannot be null.", ex.Message);

        var options = new BlindIndexOptions { Normalizer = new ConstantNormalizer("x") };
        ex = Assert.Throws<ArgumentNullException>(() => _indexer.ComputeCompound("t.c", options, "a", null!));
        Assert.Equal("parts", ex.ParamName);
    }

    [Fact]
    public void All_empty_compound_parts_message()
    {
        var ex = Assert.Throws<ArgumentException>(() => _indexer.ComputeCompound("t.c", "", ""));
        Assert.Equal("parts", ex.ParamName);
        Assert.StartsWith("Every compound index part is empty after normalization.", ex.Message);
    }

    [Fact]
    public void Normalizer_returning_null_message_names_the_normalizer()
    {
        var options = new BlindIndexOptions { Normalizer = new NullReturningNormalizer() };
        var ex = Assert.Throws<InvalidOperationException>(() => _indexer.Compute("v", "t.c", options));
        Assert.Equal("Normalizer NullReturningNormalizer returned null.", ex.Message);
    }

    [Fact]
    public void Lone_surrogate_reaching_the_encoder_message()
    {
        // The exact normalizer passes the value through, so the strict UTF-8 encoder is what rejects it.
        var ex = Assert.Throws<ArgumentException>(() => _indexer.Compute("a\uD800", "t.c"));
        Assert.Equal("value", ex.ParamName);
        Assert.StartsWith("Value contains invalid UTF-16 (a lone surrogate).", ex.Message);

        ex = Assert.Throws<ArgumentException>(() => _indexer.ComputeCompound("t.c", "ok", "\uDC00"));
        Assert.Equal("parts", ex.ParamName);
        Assert.StartsWith("Value contains invalid UTF-16 (a lone surrogate).", ex.Message);
    }

    [Fact]
    public void Lone_surrogate_reaching_unicode_normalization_message()
    {
        var ex = Assert.Throws<ArgumentException>(() => BlindIndexNormalizers.CaseInsensitive.Normalize("a\uD800"));
        Assert.Equal("value", ex.ParamName);
        Assert.StartsWith("Value contains invalid UTF-16 (a lone surrogate).", ex.Message);

        ex = Assert.Throws<ArgumentException>(() => BlindIndexNormalizers.Email.Normalize("a\uD800@x.com"));
        Assert.Equal("value", ex.ParamName);
        Assert.StartsWith("Value contains invalid UTF-16 (a lone surrogate).", ex.Message);
    }

    // ---- stored index parsing ----

    [Fact]
    public void Stored_index_with_an_invalid_key_id_is_rejected()
    {
        string valid = _indexer.Compute("v", "t.c");
        string tag = valid.Substring(3);
        Assert.False(BlindIndexer.TryGetKeyId("k 1:" + tag, out string id));
        Assert.Equal(string.Empty, id);
        Assert.False(BlindIndexer.TryGetKeyId("k_1:" + tag, out _));
        Assert.True(_indexer.NeedsReindex("k 1:" + tag));
    }

    [Fact]
    public void Stored_index_with_invalid_base64_is_rejected()
    {
        Assert.False(BlindIndexer.TryGetKeyId("k1:!!!!!!!!!!!", out string id));
        Assert.Equal(string.Empty, id);
        Assert.False(_indexer.Matches("k1:!!!!!!!!!!!", "v", "t.c"));
        Assert.True(_indexer.NeedsReindex("k1:!!!!!!!!!!!"));
    }

    [Fact]
    public void Stored_tag_length_boundaries()
    {
        Assert.False(BlindIndexer.TryGetKeyId("k1:" + HashPrimitives.ToB64(new byte[1]), out _));
        Assert.True(BlindIndexer.TryGetKeyId("k1:" + HashPrimitives.ToB64(new byte[2]), out string id));
        Assert.Equal("k1", id);
        Assert.True(BlindIndexer.TryGetKeyId("k1:" + HashPrimitives.ToB64(new byte[32]), out _));
        Assert.False(BlindIndexer.TryGetKeyId("k1:" + HashPrimitives.ToB64(new byte[33]), out id));
        Assert.Equal(string.Empty, id);

        // The shortest valid index still round-trips through Matches.
        var bits16 = TestKeys.Bits(16);
        string shortest = _indexer.Compute("v", "t.c", bits16);
        Assert.True(_indexer.Matches(shortest, "v", "t.c", bits16));
        Assert.False(_indexer.NeedsReindex(shortest));
        Assert.False(_indexer.Matches("k1:" + HashPrimitives.ToB64(new byte[1]), "v", "t.c", TestKeys.Bits(16)));
    }

    // ---- length prefixes ----

    /// <summary>
    /// A value of 2^24 + 2^16 + 1 bytes makes every byte of its big-endian length prefix (01 01 00 01) significant,
    /// so a wrong shift in the prefix encoding changes the MAC.
    /// </summary>
    [Fact]
    public void Length_prefix_encodes_all_four_bytes_big_endian()
    {
        const int length = (1 << 24) + (1 << 16) + 1;
        string value = new('v', length);
        byte[] key = TestKeys.Derived("ref");
        var indexer = new BlindIndexer("ref", key);

        byte[] domain = Encoding.ASCII.GetBytes("masterly-blind-index/v1");
        byte[] name = Encoding.ASCII.GetBytes("t.c");
        byte[] message = new byte[domain.Length + 4 + name.Length + 4 + length];
        int offset = 0;
        domain.CopyTo(message, offset);
        offset += domain.Length;
        BinaryPrimitives.WriteUInt32BigEndian(message.AsSpan(offset), (uint)name.Length);
        offset += 4;
        name.CopyTo(message, offset);
        offset += name.Length;
        BinaryPrimitives.WriteUInt32BigEndian(message.AsSpan(offset), (uint)length);
        Assert.Equal(new byte[] { 0x01, 0x01, 0x00, 0x01 }, message.AsSpan(offset, 4).ToArray());
        offset += 4;
        message.AsSpan(offset).Fill((byte)'v');

        byte[] mac = HMACSHA256.HashData(key, message);
        string expected = "ref:" + Convert.ToBase64String(mac, 0, 8).TrimEnd('=');
        Assert.Equal(expected, indexer.Compute(value, "t.c"));
    }

    // ---- EmailNormalizer ----

    [Fact]
    public void Email_errors_have_a_fixed_message()
    {
        var normalizer = new EmailNormalizer(stripGmailDots: true);
        foreach (string bad in new[] { "@x.com", "a@", "a@.", "...@gmail.com" })
        {
            var ex = Assert.Throws<ArgumentException>(() => normalizer.Normalize(bad));
            Assert.Equal("value", ex.ParamName);
            Assert.StartsWith("Value is not an email address.", ex.Message);
        }
    }

    // ---- PhoneNormalizer ----

    [Theory]
    [InlineData("1")]
    [InlineData("10")]
    [InlineData("20")]
    [InlineData("100")]
    [InlineData("999")]
    public void Country_code_boundaries_are_accepted(string code)
    {
        var normalizer = new PhoneNormalizer(code);
        Assert.Equal(code, normalizer.DefaultCountryCode);
        Assert.Equal(code + "79", normalizer.Normalize("079"));
    }

    [Theory]
    [InlineData("")]
    [InlineData("0")]
    [InlineData("1000")]
    [InlineData("1/")]
    [InlineData("1:")]
    [InlineData("+1")]
    public void Invalid_country_codes_are_rejected(string code)
    {
        var ex = Assert.Throws<ArgumentException>(() => new PhoneNormalizer(code));
        Assert.Equal("defaultCountryCode", ex.ParamName);
        Assert.StartsWith("Country code must be 1 to 3 ASCII digits without a leading zero.", ex.Message);
    }

    [Theory]
    // The first "(0)" after a digit is the trunk group; one before any digit is not.
    [InlineData("+(0)44(0)20", "04420")]
    // A trailing trunk group: the loop must resume after the group without reading past the end.
    [InlineData("+44(0)", "44")]
    [InlineData("+44 (0)", "44")]
    // A "(0)" that is part of the "00" prefix area is kept.
    [InlineData("0(0)44 20", "4420")]
    [InlineData("00(0)44", "044")]
    [InlineData("00 44 (0)20", "4420")]
    // Incomplete or non-zero groups are not trunk groups and must not read past the end.
    [InlineData("+44 (", "44")]
    [InlineData("+44(  ", "44")]
    [InlineData("+44(0", "440")]
    [InlineData("+44(0 ", "440")]
    [InlineData("+44(1)", "441")]
    [InlineData("+44( 1 )20", "44120")]
    public void Phone_trunk_group_edge_cases(string input, string expected)
    {
        Assert.Equal(expected, BlindIndexNormalizers.Phone.Normalize(input));
    }

    private sealed class NullReturningNormalizer : IBlindIndexNormalizer
    {
        public string Normalize(string value) => null!;
    }

    private sealed class ConstantNormalizer(string result) : IBlindIndexNormalizer
    {
        public string Normalize(string value) => result;
    }
}
