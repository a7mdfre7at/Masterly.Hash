using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace Masterly.Hash.BlindIndex.Tests;

/// <summary>Invalid input must surface as <see cref="ArgumentException"/> (or a subclass), never a crypto exception, and never echo the value.</summary>
public class ValidationTests
{
    private readonly BlindIndexer _indexer = TestKeys.Single();

    private static void AssertArgument(Action action)
    {
        Exception ex = Record.Exception(action);
        Assert.NotNull(ex);
        Assert.IsAssignableFrom<ArgumentException>(ex);
        Assert.IsNotAssignableFrom<CryptographicException>(ex);
    }

    [Fact]
    public void Null_and_empty_values_throw()
    {
        AssertArgument(() => _indexer.Compute(null!, "t.c"));
        AssertArgument(() => _indexer.Compute("", "t.c"));
        AssertArgument(() => _indexer.ComputeAll(null!, "t.c"));
        AssertArgument(() => _indexer.ComputeAll("", "t.c"));
        AssertArgument(() => _indexer.Matches("k1:AAAAAAAAAAA", "", "t.c"));
    }

    [Fact]
    public void Value_empty_after_normalization_throws()
    {
        AssertArgument(() => _indexer.Compute("   ", "t.c", TestKeys.Bits(64, BlindIndexNormalizers.Trim)));
        AssertArgument(() => _indexer.Compute("call me", "t.c", TestKeys.Bits(64, BlindIndexNormalizers.Phone)));
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("users email")]
    [InlineData("users.email\n")]
    [InlineData("café")]
    [InlineData("a,b")]
    public void Invalid_index_names_throw(string name)
    {
        AssertArgument(() => _indexer.Compute("v", name));
        AssertArgument(() => _indexer.ComputeCompound(name, "v"));
    }

    [Fact]
    public void Index_name_length_is_capped()
    {
        _indexer.Compute("v", new string('a', BlindIndexer.MaxIndexNameLength));
        AssertArgument(() => _indexer.Compute("v", new string('a', BlindIndexer.MaxIndexNameLength + 1)));
        AssertArgument(() => _indexer.Compute("v", null!));
    }

    [Theory]
    [InlineData("users.email")]
    [InlineData("Users_Email-2")]
    [InlineData("db:schema/table.col")]
    public void Valid_index_names_are_accepted(string name)
    {
        Assert.NotNull(_indexer.Compute("v", name));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(8)]
    [InlineData(15)]
    [InlineData(17)]
    [InlineData(63)]
    [InlineData(264)]
    [InlineData(-8)]
    public void Invalid_output_bits_throw(int bits)
    {
        AssertArgument(() => new BlindIndexOptions { OutputBits = bits });
        Assert.False(BlindIndexOptions.IsValidOutputBits(bits));
    }

    [Fact]
    public void Null_normalizer_throws()
    {
        AssertArgument(() => new BlindIndexOptions { Normalizer = null! });
    }

    [Fact]
    public void Lone_surrogate_throws_argument_exception_without_lossy_collisions()
    {
        AssertArgument(() => _indexer.Compute("a\uD800", "t.c"));
        AssertArgument(() => _indexer.Compute("a\uDC00", "t.c"));
        AssertArgument(() => _indexer.Compute("a\uD800", "t.c", TestKeys.Bits(64, BlindIndexNormalizers.CaseInsensitive)));
        AssertArgument(() => _indexer.ComputeCompound("t.c", "ok", "\uD800"));
    }

    [Fact]
    public void Compound_part_errors_throw()
    {
        AssertArgument(() => _indexer.ComputeCompound("t.c", (string[])null!));
        AssertArgument(() => _indexer.ComputeCompound("t.c"));
        AssertArgument(() => _indexer.ComputeCompound("t.c", "a", null!));
        AssertArgument(() => _indexer.ComputeCompound("t.c", "", ""));
        AssertArgument(() => _indexer.ComputeCompoundAll("t.c", "", ""));
    }

    [Fact]
    public void Unknown_key_for_ComputeWithKey_throws_argument_exception()
    {
        AssertArgument(() => _indexer.ComputeWithKey("nope", "v", "t.c"));
        AssertArgument(() => _indexer.ComputeWithKey(null!, "v", "t.c"));
    }

    [Fact]
    public void Key_ring_validation()
    {
        byte[] good = TestKeys.Derived("x");
        AssertArgument(() => new BlindIndexer("k", new byte[31]));
        AssertArgument(() => new BlindIndexer("k", (byte[])null!));
        AssertArgument(() => new BlindIndexer(null!, good));
        AssertArgument(() => new BlindIndexer("bad id", good));
        AssertArgument(() => new BlindIndexer("k:1", good));
        AssertArgument(() => new BlindIndexer(new string('a', 33), good));
        AssertArgument(() => new BlindIndexer("missing", new Dictionary<string, byte[]> { ["k"] = good }));
        AssertArgument(() => new BlindIndexer("k", new Dictionary<string, byte[]> { ["k"] = good, ["bad id"] = good }));
        AssertArgument(() => new BlindIndexer("k", (IReadOnlyDictionary<string, byte[]>)null!));
    }

    [Fact]
    public void FromBase64_validation_does_not_leak_key_material()
    {
        const string secretish = "not*base64*at*all";
        Exception ex = Record.Exception(() => BlindIndexer.FromBase64("k", new Dictionary<string, string> { ["k"] = secretish }));
        Assert.IsAssignableFrom<ArgumentException>(ex);
        Assert.DoesNotContain(secretish, ex.Message);
        AssertArgument(() => BlindIndexer.FromBase64("k", new Dictionary<string, string> { ["k"] = null! }));
        AssertArgument(() => BlindIndexer.FromBase64("k", new Dictionary<string, string> { ["k"] = Convert.ToBase64String(new byte[16]) }));
        AssertArgument(() => BlindIndexer.FromBase64("k", null!));
    }

    [Fact]
    public void FromBase64_with_swapped_key_and_id_does_not_echo_the_secret()
    {
        // Config binding mistake: the secret is the dictionary key and the key id is the value.
        string secret = Convert.ToBase64String(TestKeys.Derived("swapped"));
        foreach (string? value in new[] { "prod-2026", null })
        {
            Exception? ex = Record.Exception(() => BlindIndexer.FromBase64("prod-2026", new Dictionary<string, string> { [secret] = value! }));
            Assert.IsAssignableFrom<ArgumentException>(ex);
            Assert.DoesNotContain(secret, ex!.Message);
            Assert.DoesNotContain(secret.Substring(0, 8), ex.Message);
        }
    }

    [Fact]
    public void Exception_messages_do_not_contain_the_value()
    {
        const string pii = "secret.person@example.com\uD800";
        Exception ex = Record.Exception(() => _indexer.Compute(pii, "t.c"));
        Assert.DoesNotContain("secret.person", ex!.Message);

        ex = Record.Exception(() => _indexer.Compute("secret.person-no-at-sign", "t.c", TestKeys.Bits(64, BlindIndexNormalizers.Email)));
        Assert.IsAssignableFrom<ArgumentException>(ex);
        Assert.DoesNotContain("secret.person", ex!.Message);
    }

    [Fact]
    public void Normalizer_returning_null_is_reported_as_invalid_operation()
    {
        var options = new BlindIndexOptions { Normalizer = new NullNormalizer() };
        Assert.Throws<InvalidOperationException>(() => _indexer.Compute("v", "t.c", options));
    }

    private sealed class NullNormalizer : IBlindIndexNormalizer
    {
        public string Normalize(string value) => null!;
    }
}
