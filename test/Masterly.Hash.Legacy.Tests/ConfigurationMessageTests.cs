using System;
using Masterly.Hash.Legacy;

namespace Masterly.Hash.Legacy.Tests;

/// <summary>
/// Configuration errors a developer sees at startup (constructor caps, <c>AddLegacyFormats</c>) and the
/// out-of-memory classification <see cref="ExternalArgon2Format.Verify"/> relies on: exact messages and exact
/// classifications, so a changed string or branch fails a test.
/// </summary>
public class ConfigurationMessageTests
{
    private static void AssertOutOfRange(Action construct, string paramName, int actualValue, string message)
    {
        var ex = Assert.Throws<ArgumentOutOfRangeException>(construct);
        Assert.Equal(paramName, ex.ParamName);
        Assert.Equal(actualValue, ex.ActualValue);
        // ArgumentOutOfRangeException.Message appends the parameter name and actual value; build the expected
        // text the same way so the comparison is exact on every runtime.
        Assert.Equal(new ArgumentOutOfRangeException(paramName, actualValue, message).Message, ex.Message);
        Assert.StartsWith(message, ex.Message, StringComparison.Ordinal);
    }

    private static void AssertArgument(Action call, string paramName, string message)
    {
        var ex = Assert.Throws<ArgumentException>(call);
        Assert.Equal(paramName, ex.ParamName);
        Assert.Equal(new ArgumentException(message, paramName).Message, ex.Message);
        Assert.StartsWith(message, ex.Message, StringComparison.Ordinal);
    }

    // ---------- constructor caps ----------

    [Fact]
    public void AspNetIdentityV3_max_iterations_error_message()
    {
        AssertOutOfRange(() => _ = new AspNetIdentityV3Format(0), "maxIterations", 0, "Max iterations must be positive.");
    }

    [Fact]
    public void Django_max_iterations_error_message()
    {
        AssertOutOfRange(() => _ = new DjangoPbkdf2Format(-1), "maxIterations", -1, "Max iterations must be positive.");
    }

    [Fact]
    public void BCrypt_max_cost_error_message()
    {
        AssertOutOfRange(() => _ = new BCryptFormat(3), "maxCost", 3, "Max cost must be between 4 and 31.");
        AssertOutOfRange(() => _ = new BCryptFormat(32), "maxCost", 32, "Max cost must be between 4 and 31.");
    }

    [Fact]
    public void WordPress_max_cost_error_message()
    {
        AssertOutOfRange(() => _ = new WordPressBcryptFormat(3), "maxCost", 3, "Max cost must be between 4 and 31.");
        AssertOutOfRange(() => _ = new WordPressBcryptFormat(32), "maxCost", 32, "Max cost must be between 4 and 31.");
    }

    [Fact]
    public void Phpass_max_cost_error_message()
    {
        AssertOutOfRange(() => _ = new PhpassFormat(6), "maxCostLog2", 6, "Max cost must be between 7 and 30.");
        AssertOutOfRange(() => _ = new PhpassFormat(31), "maxCostLog2", 31, "Max cost must be between 7 and 30.");
    }

    [Fact]
    public void Argon2_cap_error_messages()
    {
        AssertOutOfRange(() => _ = new ExternalArgon2Format(7, 1, 1), "maxMemoryKiB", 7, "Max memory must be between 8 and 1048576 KiB.");
        AssertOutOfRange(() => _ = new ExternalArgon2Format(1048577, 1, 1), "maxMemoryKiB", 1048577, "Max memory must be between 8 and 1048576 KiB.");
        AssertOutOfRange(() => _ = new ExternalArgon2Format(1024, 65, 1), "maxIterations", 65, "Max iterations must be between 1 and 64.");
        AssertOutOfRange(() => _ = new ExternalArgon2Format(1024, 0, 1), "maxIterations", 0, "Max iterations must be between 1 and 64.");
        AssertOutOfRange(() => _ = new ExternalArgon2Format(1024, 1, 17), "maxParallelism", 17, "Max parallelism must be between 1 and 16.");
        AssertOutOfRange(() => _ = new ExternalArgon2Format(1024, 1, 0), "maxParallelism", 0, "Max parallelism must be between 1 and 16.");
    }

    // ---------- AddLegacyFormats ----------

    [Fact]
    public void AddLegacyFormats_null_entry_error_message()
    {
        AssertArgument(() => new PasswordHasherOptions().AddLegacyFormats(BCryptFormat.Default, null!),
            "formats", "Formats cannot contain null.");
    }

    [Fact]
    public void AddLegacyFormats_duplicate_id_error_message_names_the_id()
    {
        var options = new PasswordHasherOptions().AddLegacyFormats(BCryptFormat.Default);
        AssertArgument(() => options.AddLegacyFormats(new BCryptFormat(12)),
            "formats", "A different legacy format with id 'bcrypt' is already registered.");

        // Duplicate inside one call reports the same way.
        AssertArgument(() => new PasswordHasherOptions().AddLegacyFormats(PhpassFormat.Default, new PhpassFormat(14)),
            "formats", "A different legacy format with id 'phpass' is already registered.");
    }

    // ---------- ExternalArgon2Format.IsOutOfMemory ----------

    [Fact]
    public void IsOutOfMemory_bare_out_of_memory_is_true()
    {
        Assert.True(ExternalArgon2Format.IsOutOfMemory(new OutOfMemoryException()));
        Assert.True(ExternalArgon2Format.IsOutOfMemory(new InsufficientMemoryException())); // derives from OOM
    }

    [Fact]
    public void IsOutOfMemory_other_exception_is_false()
    {
        Assert.False(ExternalArgon2Format.IsOutOfMemory(new InvalidOperationException()));
        Assert.False(ExternalArgon2Format.IsOutOfMemory(new ArgumentException()));
    }

    [Fact]
    public void IsOutOfMemory_empty_aggregate_is_false()
    {
        Assert.False(ExternalArgon2Format.IsOutOfMemory(new AggregateException()));
        Assert.False(ExternalArgon2Format.IsOutOfMemory(new AggregateException(new AggregateException())));
    }

    [Fact]
    public void IsOutOfMemory_aggregate_needs_every_inner_exception_to_be_out_of_memory()
    {
        Assert.True(ExternalArgon2Format.IsOutOfMemory(new AggregateException(new OutOfMemoryException())));
        Assert.True(ExternalArgon2Format.IsOutOfMemory(
            new AggregateException(new OutOfMemoryException(), new AggregateException(new OutOfMemoryException()))));

        // A non-OOM inner exception, first or last, makes the whole aggregate a real failure.
        Assert.False(ExternalArgon2Format.IsOutOfMemory(
            new AggregateException(new OutOfMemoryException(), new InvalidOperationException())));
        Assert.False(ExternalArgon2Format.IsOutOfMemory(
            new AggregateException(new InvalidOperationException(), new OutOfMemoryException())));
        Assert.False(ExternalArgon2Format.IsOutOfMemory(new AggregateException(new InvalidOperationException())));
    }
}
