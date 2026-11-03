using System;
using System.Collections.Generic;

namespace Masterly.Hash.PropertyTests.Support;

/// <summary>
/// Independent bit-level reference for canonical unpadded standard base64 (RFC 4648 §4, padding omitted as in the
/// PHC string format). Written without <see cref="Convert"/> so it shares no code with the implementation under test.
/// </summary>
internal static class Base64Reference
{
    private const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    /// <summary>
    /// Encodes without padding. Returns "" for an empty input.
    /// </summary>
    public static string Encode(byte[] bytes)
    {
        var chars = new List<char>((bytes.Length * 4 + 2) / 3);
        int buffer = 0, bits = 0;
        foreach (byte b in bytes)
        {
            buffer = (buffer << 8) | b;
            bits += 8;
            while (bits >= 6)
            {
                bits -= 6;
                chars.Add(Alphabet[(buffer >> bits) & 0x3F]);
            }
        }
        if (bits > 0)
            chars.Add(Alphabet[(buffer << (6 - bits)) & 0x3F]);
        return new string(chars.ToArray());
    }

    /// <summary>
    /// Decodes canonical unpadded base64. Rejects: the empty string (the library never stores an empty field),
    /// a length of 1 mod 4 (cannot encode whole bytes), any character outside the alphabet (padding and whitespace
    /// included), and non-zero unused trailing bits (non-canonical: two strings for one byte array).
    /// </summary>
    public static bool TryDecode(string value, out byte[] bytes)
    {
        bytes = Array.Empty<byte>();
        if (value.Length == 0 || value.Length % 4 == 1)
            return false;

        var output = new List<byte>(value.Length * 3 / 4);
        int buffer = 0, bits = 0;
        foreach (char c in value)
        {
            int v = Alphabet.IndexOf(c, StringComparison.Ordinal);
            if (v < 0)
                return false;
            buffer = ((buffer << 6) | v) & 0xFFFFFF;
            bits += 6;
            if (bits >= 8)
            {
                bits -= 8;
                output.Add((byte)((buffer >> bits) & 0xFF));
            }
        }

        // 2 chars leave 4 unused bits, 3 chars leave 2; they must be zero.
        if ((buffer & ((1 << bits) - 1)) != 0)
            return false;

        bytes = output.ToArray();
        return true;
    }
}
