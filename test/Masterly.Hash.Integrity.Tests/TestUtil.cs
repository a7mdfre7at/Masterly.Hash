using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Masterly.Hash.Integrity.Tests;

internal static class TestUtil
{
    public static byte[] Hex(string hex) => Convert.FromHexString(hex);

    public static string ToHex(byte[] bytes) => Convert.ToHexString(bytes).ToLowerInvariant();

    public static string ToHex(ReadOnlyMemory<byte> bytes) => ToHex(bytes.ToArray());

    public static byte[] Utf8(string value) => Encoding.UTF8.GetBytes(value);

    public static byte[] Key(string label) => SHA256.HashData(Utf8("integrity-test-key-" + label));

    public static ContentHashAlgorithm Hmac(string keyId, string label = "a") => ContentHashAlgorithm.HmacSha256(keyId, Key(label));

    public static byte[] Flip(byte[] value, int index = 0)
    {
        byte[] copy = (byte[])value.Clone();
        copy[index % copy.Length] ^= 0x01;
        return copy;
    }
}

/// <summary>A temp directory deleted on dispose.</summary>
internal sealed class TempDirectory : IDisposable
{
    public TempDirectory()
    {
        Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "mh-integrity-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path);
    }

    public string Path { get; }

    public string Write(string relative, string content) => Write(relative, Encoding.UTF8.GetBytes(content));

    public string Write(string relative, byte[] content)
    {
        string full = System.IO.Path.Combine(Path, relative.Replace('/', System.IO.Path.DirectorySeparatorChar));
        Directory.CreateDirectory(System.IO.Path.GetDirectoryName(full)!);
        File.WriteAllBytes(full, content);
        return full;
    }

    public void Delete(string relative) =>
        File.Delete(System.IO.Path.Combine(Path, relative.Replace('/', System.IO.Path.DirectorySeparatorChar)));

    public void Dispose()
    {
        try
        {
            Directory.Delete(Path, recursive: true);
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }
}

/// <summary>A non-seekable stream that returns at most <c>chunk</c> bytes per read.</summary>
internal sealed class TrickleStream : Stream
{
    private readonly byte[] _data;
    private readonly int _chunk;
    private int _position;

    public TrickleStream(byte[] data, int chunk)
    {
        _data = data;
        _chunk = chunk;
    }

    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
    public override void Flush() { }
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

    public override int Read(byte[] buffer, int offset, int count)
    {
        int n = Math.Min(Math.Min(count, _chunk), _data.Length - _position);
        Buffer.BlockCopy(_data, _position, buffer, offset, n);
        _position += n;
        return n;
    }
}
