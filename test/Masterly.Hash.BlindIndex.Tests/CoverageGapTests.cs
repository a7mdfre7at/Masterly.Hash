using System;
using System.Reflection;

namespace Masterly.Hash.BlindIndex.Tests;

/// <summary>Edge paths not reached by the scenario tests.</summary>
public class CoverageGapTests
{
    private readonly BlindIndexer _indexer = TestKeys.Single();

    [Fact]
    public void Unknown_key_with_an_invalid_id_is_not_echoed()
    {
        var ex = Assert.Throws<ArgumentException>(() => _indexer.ComputeWithKey("bad id!", "v", "t.c"));
        Assert.Equal("keyId", ex.ParamName);
        Assert.Contains("Key '?'", ex.Message);
        Assert.DoesNotContain("bad id!", ex.Message);

        ex = Assert.Throws<ArgumentException>(() => _indexer.ComputeWithKey("nope", "v", "t.c"));
        Assert.Contains("Key 'nope'", ex.Message);
    }

    // The property setters reject these values, so the indexer's own re-validation is a defensive guard; force the
    // backing fields to prove the guard still rejects options that bypassed the setters.
    [Fact]
    public void Options_with_invalid_output_bits_are_rejected_by_the_indexer()
    {
        var options = new BlindIndexOptions();
        SetField(options, "_outputBits", 12);

        var ex = Assert.Throws<ArgumentException>(() => _indexer.Compute("v", "t.c", options));
        Assert.Equal("options", ex.ParamName);
        Assert.StartsWith("OutputBits must be a multiple of 8 from 16 to 256.", ex.Message);
    }

    [Fact]
    public void Options_with_null_normalizer_are_rejected_by_the_indexer()
    {
        var options = new BlindIndexOptions();
        SetField(options, "_normalizer", null);

        var ex = Assert.Throws<ArgumentException>(() => _indexer.Compute("v", "t.c", options));
        Assert.Equal("options", ex.ParamName);
        Assert.StartsWith("Normalizer cannot be null.", ex.Message);
    }

    [Fact]
    public void Phone_normalizer_returns_empty_for_whitespace_only_input()
    {
        Assert.Equal("", BlindIndexNormalizers.Phone.Normalize("   "));
        Assert.Equal("", BlindIndexNormalizers.Phone.Normalize(""));
    }

    private static void SetField(object target, string name, object? value)
    {
        FieldInfo field = target.GetType().GetField(name, BindingFlags.Instance | BindingFlags.NonPublic)
            ?? throw new InvalidOperationException($"Field {name} not found.");
        field.SetValue(target, value);
    }
}
