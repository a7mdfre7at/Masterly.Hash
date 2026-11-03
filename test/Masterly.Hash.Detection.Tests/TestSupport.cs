using System;
using System.Collections.Generic;
using System.Threading;
using Masterly.Hash.Detection.Internal;
using Masterly.Hash.Primitives;

namespace Masterly.Hash.Detection.Tests;

internal static class TestSupport
{
    public static readonly HashProfile Fast = HashProfile.Argon2id("test", memoryKiB: 64, iterations: 1);

    public static PasswordHasher Hasher() =>
        new PasswordHasher(new PasswordHasherOptions { DefaultProfile = Fast, AllowWeakProfiles = true });

    public static HoneywordService Service(IHoneywordGenerator? generator = null, Action<HoneywordServiceOptions>? configure = null)
    {
        var options = new HoneywordServiceOptions();
        if (generator != null)
            options.Generator = generator;
        configure?.Invoke(options);
        return new HoneywordService(Hasher(), options);
    }

    /// <summary>Replaces the service's KDF with a counting wrapper around the real one.</summary>
    public static StrongBox Count(HoneywordService service)
    {
        var box = new StrongBox();
        service.Derive = (profile, input, salt) =>
        {
            Interlocked.Increment(ref box.Value);
            return HashPrimitives.DeriveKey(profile, input, salt);
        };
        return box;
    }

    /// <summary>Splits a $mhw$ string into (params, salt, tags) without the library's parser.</summary>
    public static (string Parameters, byte[] Salt, byte[][] Tags) Split(string stored)
    {
        Assert.StartsWith("$mhw$", stored);
        string[] parts = stored.Substring(5).Split('$');
        Assert.Equal(3, parts.Length);
        Assert.True(HashPrimitives.TryFromB64(parts[1], out byte[] salt));
        string[] encoded = parts[2].Split(',');
        var tags = new byte[encoded.Length][];
        for (int i = 0; i < encoded.Length; i++)
            Assert.True(HashPrimitives.TryFromB64(encoded[i], out tags[i]));
        return (parts[0], salt, tags);
    }

    public static CharClass[] Pattern(string value)
    {
        var result = new CharClass[value.Length];
        for (int i = 0; i < value.Length; i++)
            result[i] = CharClasses.Of(value[i]);
        return result;
    }

    public sealed class StrongBox
    {
        public int Value;
    }
}

/// <summary>Deterministic decoys "decoy-0", "decoy-1", ... so tests can log in with a known decoy.</summary>
internal sealed class FixedGenerator : IHoneywordGenerator
{
    private readonly Func<string, int, IReadOnlyList<string>>? _override;

    public FixedGenerator(Func<string, int, IReadOnlyList<string>>? @override = null) => _override = @override;

    public static string Decoy(int i) => "decoy-" + i;

    public IReadOnlyList<string> GenerateDecoys(string realPassword, int count)
    {
        if (_override != null)
            return _override(realPassword, count);
        var list = new List<string>(count);
        for (int i = 0; i < count; i++)
            list.Add(Decoy(i));
        return list;
    }
}

internal sealed class FakeClock
{
    public FakeClock(DateTimeOffset start) => Now = start;

    public DateTimeOffset Now { get; set; }

    public void Advance(TimeSpan by) => Now += by;

    public Func<DateTimeOffset> Func => () => Now;
}
