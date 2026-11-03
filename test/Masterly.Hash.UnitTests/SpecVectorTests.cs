using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using Masterly.Hash.Legacy;
using Masterly.Hash.Pepper;
using Masterly.Hash.Primitives;

namespace Masterly.Hash.UnitTests;

/// <summary>Keeps docs/spec/test-vectors.json (cross-checked against argon2-cffi and hashlib) in sync with the code.</summary>
public class SpecVectorTests
{
    public static IEnumerable<object[]> Vectors()
    {
        using JsonDocument doc = JsonDocument.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "test-vectors.json")));
        foreach (JsonElement v in doc.RootElement.GetProperty("vectors").EnumerateArray())
            yield return new object[] { v.GetProperty("name").GetString()! };
    }

    [Theory]
    [MemberData(nameof(Vectors))]
    public void SpecVector_Verifies_AndKdfMatches(string name)
    {
        using JsonDocument doc = JsonDocument.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "test-vectors.json")));
        JsonElement v = default;
        foreach (JsonElement e in doc.RootElement.GetProperty("vectors").EnumerateArray())
            if (e.GetProperty("name").GetString() == name) v = e;

        string password = v.GetProperty("password").GetString()!;
        string hash = v.GetProperty("hash").GetString()!;
        HashProfile profile = HashProfile.BuiltIn[0];
        Assert.True(HashProfile.TryGetBuiltIn(v.GetProperty("profile").GetString()!, out profile));

        byte[] tag = HashPrimitives.DeriveKey(profile, Convert.FromHexString(v.GetProperty("kdfInputHex").GetString()!), Convert.FromHexString(v.GetProperty("saltHex").GetString()!));
        Assert.Equal(v.GetProperty("tagHex").GetString(), Convert.ToHexString(tag).ToLowerInvariant());

        var options = new PasswordHasherOptions
        {
            Pepper = new HmacPepper("k1", new Dictionary<string, byte[]> { ["k1"] = Convert.FromHexString("404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f") }),
        };
        options.LegacyFormats[0] = new V1LegacyFormat(V1Algorithm.SHA256);
        var hasher = new PasswordHasher(options);
        Assert.True(hasher.Verify(password, hash).IsMatch, name);
        Assert.False(hasher.Verify(password + "x", hash).IsMatch, name);
    }
}
