using System;
using System.Security.Cryptography;
using System.Text;
using Masterly.Hash.Legacy;
using Masterly.Hash.Pepper;

namespace Masterly.Hash.UnitTests;

/// <summary>Fast hashers for tests. Production profiles are exercised separately.</summary>
internal static class TestHashers
{
    public static readonly HashProfile Fast = HashProfile.Argon2id("test-fast", memoryKiB: 64, iterations: 1);
    public static readonly HashProfile Fast2 = HashProfile.Argon2id("test-fast2", memoryKiB: 128, iterations: 1);

    public static PasswordHasher Create(Action<PasswordHasherOptions>? configure = null)
    {
        var options = new PasswordHasherOptions { DefaultProfile = Fast, AllowWeakProfiles = true };
        configure?.Invoke(options);
        return new PasswordHasher(options);
    }

    public static HmacPepper Pepper(string currentKeyId, params string[] keyIds)
    {
        var keys = new System.Collections.Generic.Dictionary<string, byte[]>();
        foreach (string id in keyIds)
            keys[id] = SHA256.HashData(Encoding.UTF8.GetBytes("pepper-key-" + id));
        return new HmacPepper(currentKeyId, keys);
    }

    /// <summary>Byte-for-byte copy of the Masterly.Hash 1.0.0 algorithm (git b71d95f..7cdefe2).</summary>
    public static string Original1x(string plainText, byte[] saltBytes, V1Algorithm hash)
    {
        byte[] plainData = Encoding.UTF8.GetBytes(plainText);
        byte[] plainDataWithSalt = new byte[plainData.Length + saltBytes.Length];
        for (int x = 0; x < plainData.Length; x++)
            plainDataWithSalt[x] = plainData[x];
        for (int n = 0; n < saltBytes.Length; n++)
            plainDataWithSalt[plainData.Length + n] = saltBytes[n];

        byte[] hashValue = hash switch
        {
            V1Algorithm.SHA256 => SHA256.HashData(plainDataWithSalt),
            V1Algorithm.SHA384 => SHA384.HashData(plainDataWithSalt),
            _ => SHA512.HashData(plainDataWithSalt),
        };

        byte[] result = new byte[hashValue.Length + saltBytes.Length];
        for (int x = 0; x < hashValue.Length; x++)
            result[x] = hashValue[x];
        for (int n = 0; n < saltBytes.Length; n++)
            result[hashValue.Length + n] = saltBytes[n];
        return Convert.ToBase64String(result);
    }
}
