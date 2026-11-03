using System;
using System.Linq;
using Masterly.Hash.Legacy;

namespace Masterly.Hash.Testing.Tests;

/// <summary>
/// Pins the exact text of the <see cref="ArgumentException"/>s the testing helpers throw. These are public API errors a
/// developer reads in a failing test's output, so their wording (including the interpolated profile, salt length and
/// key id) is part of the observable contract.
/// </summary>
public class ArgumentMessageTests
{
    private const string Pw = "my-plaintext-password";
    private const string KeyIdRule = "Key id must match ^[A-Za-z0-9-]{1,32}$.";

    private static readonly byte[] Salt = Enumerable.Range(0, 16).Select(i => (byte)i).ToArray();

    private static void Rejects(string message, string paramName, Action action)
    {
        ArgumentException ex = Assert.Throws<ArgumentException>(action);
        Assert.Equal(paramName, ex.ParamName);
        Assert.Equal($"{message} (Parameter '{paramName}')", ex.Message);
    }

    [Fact]
    public void FakePepper_InvalidKeyId_HasExactMessage()
    {
        Rejects(KeyIdRule, "currentKeyId", () => new FakePepper("bad id"));
        Rejects(KeyIdRule, "otherKeyIds", () => new FakePepper("k1", new string('k', 33)));
        Rejects(KeyIdRule, "keyId", () => new FakePepper().AddKey(""));
        Rejects(KeyIdRule, "keyId", () => new FakePepper().RotateTo("a/b"));
    }

    [Fact]
    public void KnownHashesCreate_EmptyPassword_HasExactMessage()
    {
        Rejects("Password cannot be empty.", "password", () => KnownHashes.Create(FastPasswordHasher.Profile, "", Salt));
    }

    [Fact]
    public void KnownHashesCreate_WrongSaltLength_HasExactMessage()
    {
        Rejects("Salt must be 16 bytes for profile 'test-fast'.", "salt",
            () => KnownHashes.Create(FastPasswordHasher.Profile, Pw, new byte[15]));
    }

    [Fact]
    public void KnownHashesCreate_KeyIdWithoutPepper_HasExactMessage()
    {
        Rejects("A pepper key id requires a pepper.", "pepperKeyId",
            () => KnownHashes.Create(FastPasswordHasher.Profile, Pw, Salt, null, "k1"));
    }

    [Fact]
    public void KnownHashesCreate_InvalidKeyId_HasExactMessage()
    {
        Rejects("Pepper key id must match ^[A-Za-z0-9-]{1,32}$.", "pepperKeyId",
            () => KnownHashes.Create(FastPasswordHasher.Profile, Pw, Salt, new FakePepper(), "bad id"));
    }

    [Fact]
    public void KnownHashesCreate_UnknownKey_HasExactMessage()
    {
        Rejects("The pepper does not know key 'unknown'.", "pepperKeyId",
            () => KnownHashes.Create(FastPasswordHasher.Profile, Pw, Salt, new FakePepper(), "unknown"));
    }

    [Fact]
    public void KnownHashesCreateWrappedV1_WrongSaltLength_HasExactMessage()
    {
        Rejects("Salt must be 16 bytes for profile 'test-fast'.", "salt",
            () => KnownHashes.CreateWrappedV1(FastPasswordHasher.Profile, Pw, Salt, V1Algorithm.SHA512, new byte[8]));
    }

    [Fact]
    public void IsNotPlaintext_EmptyPassword_HasExactMessage()
    {
        Rejects("Password cannot be empty.", "password", () => MasterlyHashAssert.IsNotPlaintext("x", ""));
    }
}
