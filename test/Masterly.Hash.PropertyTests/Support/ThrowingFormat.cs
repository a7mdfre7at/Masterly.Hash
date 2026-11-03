using System;
using System.Security.Cryptography;
using Masterly.Hash.Legacy;

namespace Masterly.Hash.PropertyTests.Support;

/// <summary>Members of <see cref="ILegacyHashFormat"/> that a <see cref="ThrowingFormat"/> can throw from.</summary>
[Flags]
public enum ThrowPoint
{
    None = 0,
    CanHandle = 1,
    Verify = 2,
    TryExtractWrapInput = 4,
    ComputeWrapInput = 8,
}

/// <summary>
/// A badly written third-party format: it claims every non-<c>$mh$</c> string, extracts a wrap input from all of
/// them, and throws <see cref="Exception"/> from the members in <see cref="ThrowFrom"/>. Members that do not throw
/// behave like a format that never matches (Verify false, ComputeWrapInput returns a digest no hash contains).
/// </summary>
public sealed class ThrowingFormat : ILegacyHashFormat
{
    public ThrowingFormat(ThrowPoint throwFrom, Func<Exception> exception)
    {
        ThrowFrom = throwFrom;
        Exception = exception;
    }

    public ThrowPoint ThrowFrom { get; }

    public Func<Exception> Exception { get; }

    public string Id => "boom";

    public bool CanHandle(string storedHash)
    {
        Throw(ThrowPoint.CanHandle);
        return !string.IsNullOrEmpty(storedHash);
    }

    public bool Verify(string password, string storedHash)
    {
        Throw(ThrowPoint.Verify);
        return false;
    }

    public bool TryExtractWrapInput(string storedHash, out byte[] digest, out byte[] parameter)
    {
        Throw(ThrowPoint.TryExtractWrapInput);
        digest = SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(storedHash ?? string.Empty));
        parameter = new byte[] { 1, 2, 3 };
        return !string.IsNullOrEmpty(storedHash);
    }

    public byte[] ComputeWrapInput(string password, byte[] parameter)
    {
        Throw(ThrowPoint.ComputeWrapInput);
        return new byte[32]; // never the SHA-256 of a stored hash
    }

    private void Throw(ThrowPoint point)
    {
        if ((ThrowFrom & point) != 0)
            throw Exception();
    }

    public override string ToString() => $"boom(throws {ThrowFrom}: {Exception().GetType().Name})";
}
