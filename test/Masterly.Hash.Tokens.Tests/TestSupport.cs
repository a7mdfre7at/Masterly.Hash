using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Masterly.Hash.Tokens.Tests;

internal sealed class FakeClock
{
    public FakeClock(DateTimeOffset now) => Now = now;

    public DateTimeOffset Now { get; set; }

    public void Advance(TimeSpan by) => Now += by;

    public Func<DateTimeOffset> AsFunc() => () => Now;
}

internal static class TestKeys
{
    public static readonly DateTimeOffset T0 = new DateTimeOffset(2026, 11, 2, 12, 0, 0, TimeSpan.Zero);

    public static byte[] Key(string id) => SHA256.HashData(Encoding.UTF8.GetBytes("test-key-" + id));

    public static HmacKeyRing Ring(string currentKeyId, params string[] keyIds)
    {
        var keys = new Dictionary<string, byte[]>();
        foreach (string id in keyIds)
            keys[id] = Key(id);
        return new HmacKeyRing(currentKeyId, keys);
    }

    /// <summary>Subkey derivation input: 0xFF || ASCII(label).</summary>
    public static byte[] SubkeyInfo(string label)
    {
        byte[] labelBytes = Encoding.ASCII.GetBytes(label);
        byte[] info = new byte[labelBytes.Length + 1];
        info[0] = 0xFF;
        labelBytes.CopyTo(info, 1);
        return info;
    }

    public static string ToBase64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public static byte[] FromBase64Url(string value)
    {
        string s = value.Replace('-', '+').Replace('_', '/');
        return Convert.FromBase64String(s + new string('=', (4 - s.Length % 4) % 4));
    }
}
