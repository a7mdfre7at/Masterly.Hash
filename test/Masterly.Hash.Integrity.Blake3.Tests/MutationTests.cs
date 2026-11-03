using System;
using System.Reflection;
using System.Text;

namespace Masterly.Hash.Integrity.Blake3.Tests;

public class MutationTests
{
    private static readonly byte[] Key = Encoding.ASCII.GetBytes("whats the Elvish word for friend");

    private static global::Blake3.Hasher GetHasher(ContentDigest digest)
    {
        FieldInfo? field = digest.GetType().GetField("_hasher", BindingFlags.Instance | BindingFlags.NonPublic);
        Assert.NotNull(field);
        return Assert.IsType<global::Blake3.Hasher>(field!.GetValue(digest));
    }

    [Fact]
    public void Dispose_DisposesUnderlyingHasher_Plain()
    {
        ContentDigest digest = Blake3Algorithms.Blake3.CreateDigest();
        global::Blake3.Hasher hasher = GetHasher(digest);
        hasher.Update(new byte[] { 1 }); // usable before dispose

        digest.Dispose();

        Assert.Throws<ObjectDisposedException>(() => hasher.Update(new byte[] { 1 }));
        Assert.Throws<ObjectDisposedException>(() => digest.GetHashAndReset());
    }

    [Fact]
    public void Dispose_DisposesUnderlyingHasher_Keyed()
    {
        ContentDigest digest = Blake3Algorithms.Keyed("k", Key).CreateDigest();
        global::Blake3.Hasher hasher = GetHasher(digest);
        hasher.Update(new byte[] { 1 });

        digest.Dispose();
        digest.Dispose(); // idempotent

        Assert.Throws<ObjectDisposedException>(() => hasher.Update(new byte[] { 1 }));
    }

    // The L40 / L57 Register() mutants are equivalent only because the explicit static constructor makes
    // the type "precise-init" (no beforefieldinit): any static method call, even an empty Register(), runs it.
    // Pin that invariant so a refactor that drops the static constructor is caught.
    [Fact]
    public void Blake3Algorithms_HasPreciseStaticInitialization()
    {
        Type type = typeof(Blake3Algorithms);
        Assert.False(type.Attributes.HasFlag(TypeAttributes.BeforeFieldInit));
        Assert.NotNull(type.TypeInitializer);
    }

    [Fact]
    public void Keyed_WrongLength_ReportsKeyParam_AndExactLengthAccepted()
    {
        Assert.Equal("key", Assert.Throws<ArgumentException>(() => Blake3Algorithms.Keyed("k", new byte[Blake3Algorithms.KeyLength - 1])).ParamName);
        ArgumentException tooLong = Assert.Throws<ArgumentException>(() => Blake3Algorithms.Keyed("k", new byte[Blake3Algorithms.KeyLength + 1]));
        Assert.Equal("key", tooLong.ParamName);
        Assert.StartsWith("BLAKE3 keys must be exactly 32 bytes.", tooLong.Message, StringComparison.Ordinal);
        Assert.Equal("key", Assert.Throws<ArgumentNullException>(() => Blake3Algorithms.Keyed("k", null!)).ParamName);
        Assert.Equal("keyId", Assert.Throws<ArgumentNullException>(() => Blake3Algorithms.Keyed(null!, Key)).ParamName);

        ContentHashAlgorithm mac = Blake3Algorithms.Keyed("k", new byte[Blake3Algorithms.KeyLength]);
        Assert.Equal(Blake3Algorithms.KeyedName, mac.Name);
        Assert.Equal(Blake3Algorithms.DigestLength, mac.DigestLength);
        Assert.Equal("k", mac.KeyId);
    }
}
