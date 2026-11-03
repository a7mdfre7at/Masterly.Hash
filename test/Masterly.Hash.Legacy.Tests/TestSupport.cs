using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;
using Masterly.Hash.Legacy;

namespace Masterly.Hash.Legacy.Tests;

internal static class TestSupport
{
    /// <summary>Fast, deliberately weak profile so tests run quickly.</summary>
    public static readonly HashProfile Fast = HashProfile.Argon2id("test", 64, 1);

    public static PasswordHasher Hasher(params ILegacyHashFormat[] formats)
    {
        var options = new PasswordHasherOptions { DefaultProfile = Fast, AllowWeakProfiles = true };
        options.AddLegacyFormats(formats);
        return new PasswordHasher(options);
    }

    public static PasswordHasher AllFormats()
    {
        var options = new PasswordHasherOptions { DefaultProfile = Fast, AllowWeakProfiles = true };
        options.AddAllLegacyFormats();
        return new PasswordHasher(options);
    }

    public static ILegacyHashFormat Format(string id)
    {
        foreach (ILegacyHashFormat format in LegacyFormats.All)
        {
            if (format.Id == id)
                return format;
        }
        throw new ArgumentException("No format " + id);
    }

    /// <summary>ASP.NET Core Identity v3 layout, built by hand for edge cases Microsoft's hasher never emits.</summary>
    public static string IdentityV3(uint prf, uint iterations, byte[] salt, byte[] subkey, int? declaredSaltLength = null)
    {
        byte[] buffer = new byte[13 + salt.Length + subkey.Length];
        buffer[0] = 0x01;
        WriteBigEndian(buffer, 1, prf);
        WriteBigEndian(buffer, 5, iterations);
        WriteBigEndian(buffer, 9, (uint)(declaredSaltLength ?? salt.Length));
        Buffer.BlockCopy(salt, 0, buffer, 13, salt.Length);
        Buffer.BlockCopy(subkey, 0, buffer, 13 + salt.Length, subkey.Length);
        return Convert.ToBase64String(buffer);
    }

    private static void WriteBigEndian(byte[] buffer, int offset, uint value) =>
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(buffer.AsSpan(offset, 4), value);

    public static byte[] Bytes(int length, byte seed)
    {
        byte[] result = new byte[length];
        for (int i = 0; i < length; i++)
            result[i] = (byte)(seed + i);
        return result;
    }

    public static string Hex(byte[] bytes)
    {
        var sb = new StringBuilder(bytes.Length * 2);
        foreach (byte b in bytes)
            sb.Append(b.ToString("x2"));
        return sb.ToString();
    }

    public static string Upper(string value) => value.ToUpperInvariant();

    /// <summary>Runs <paramref name="action"/> and asserts it finished well within <paramref name="maxMs"/>.</summary>
    public static void AssertQuick(Action action, int maxMs = 1000)
    {
        var sw = Stopwatch.StartNew();
        action();
        sw.Stop();
        Assert.True(sw.ElapsedMilliseconds < maxMs, $"took {sw.ElapsedMilliseconds} ms");
    }

    /// <summary>Strings that no format may accept and none may throw on.</summary>
    public static IEnumerable<string> Garbage()
    {
        yield return "";
        yield return " ";
        yield return "$";
        yield return "$$$$$$";
        yield return "password";
        yield return "null";
        yield return "\0\0\0\0";
        yield return new string('a', 5000);
        yield return new string('$', 5000);
        yield return "$2b$";
        yield return "$2b$12$";
        yield return "$2b$12$short";
        yield return "$P$";
        yield return "$H$9";
        yield return "pbkdf2_sha256$";
        yield return "pbkdf2_sha256$$$";
        yield return "pbkdf2_sha256$abc$salt$hash";
        yield return "$argon2id$";
        yield return "$argon2id$v=19$m=,t=,p=$$";
        yield return "$mh$p=test$$";
        yield return "AQAAAA==";
        yield return "AA==";
        yield return "𐀀\uD800";
        yield return "5f4dcc3b5aa765d61d8327deb882cf9";   // 31 hex chars
        yield return "5f4dcc3b5aa765d61d8327deb882cf9g";  // non-hex
    }

    /// <summary>Random single-character edits, deletions, insertions and truncations of a valid hash.</summary>
    public static IEnumerable<string> Mutations(string valid, int count, int seed)
    {
        var random = new Random(seed);
        const string chars = "$./+=0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz,_-\0é";
        for (int n = 0; n < count; n++)
        {
            var sb = new StringBuilder(valid);
            int pos = random.Next(valid.Length);
            switch (random.Next(4))
            {
                case 0: sb[pos] = chars[random.Next(chars.Length)]; break;
                case 1: sb.Remove(pos, 1); break;
                case 2: sb.Insert(pos, chars[random.Next(chars.Length)]); break;
                default: sb.Length = pos; break;
            }
            yield return sb.ToString();
        }
    }
}
