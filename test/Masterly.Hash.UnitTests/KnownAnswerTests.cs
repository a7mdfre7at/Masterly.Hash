using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Masterly.Hash.Internal;
using Masterly.Hash.Primitives;

namespace Masterly.Hash.UnitTests;

/// <summary>Reference vectors from the RFCs, plus differential checks between implementations.</summary>
public class KnownAnswerTests
{
    private static byte[] Hex(string hex) => Convert.FromHexString(hex.Replace(" ", ""));

    [Theory]
    // RFC 6070, PBKDF2-HMAC-SHA1
    [InlineData("SHA1", "password", "salt", 1, "0c60c80f961f0e71f3a9b524af6012062fe037a6")]
    [InlineData("SHA1", "password", "salt", 2, "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957")]
    [InlineData("SHA1", "password", "salt", 4096, "4b007901b765489abead49d926f721d065a429c1")]
    [InlineData("SHA1", "passwordPASSWORDpassword", "saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096, "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038")]
    // RFC 7914 §11, PBKDF2-HMAC-SHA256
    [InlineData("SHA256", "passwd", "salt", 1, "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783")]
    public void Pbkdf2_RfcVectors(string prf, string password, string salt, int iterations, string expectedHex)
    {
        byte[] expected = Hex(expectedHex);
        var alg = new HashAlgorithmName(prf);
        byte[] p = Encoding.UTF8.GetBytes(password), s = Encoding.UTF8.GetBytes(salt);

        Assert.Equal(expected, HashPrimitives.Pbkdf2(alg, p, s, iterations, expected.Length));
    }

    [Fact]
    public void Argon2id_Rfc9106Vector_ValidatesTheDependency()
    {
        // RFC 9106 §5.3
        using var argon2 = new Konscious.Security.Cryptography.Argon2id(Enumerable.Repeat((byte)1, 32).ToArray())
        {
            Salt = Enumerable.Repeat((byte)2, 16).ToArray(),
            KnownSecret = Enumerable.Repeat((byte)3, 8).ToArray(),
            AssociatedData = Enumerable.Repeat((byte)4, 12).ToArray(),
            MemorySize = 32,
            Iterations = 3,
            DegreeOfParallelism = 4,
        };

        Assert.Equal(Hex("0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"), argon2.GetBytes(32));
    }

    [Fact]
    public void Kdf_IsDeterministicForFixedSalt()
    {
        byte[] salt = new byte[16];
        byte[] a = Kdf.Derive(TestHashers.Fast, Encoding.UTF8.GetBytes("pw"), salt);
        byte[] b = Kdf.Derive(TestHashers.Fast, Encoding.UTF8.GetBytes("pw"), salt);
        Assert.Equal(a, b);
        Assert.Equal(32, a.Length);
    }

    [Fact]
    public void FixedTimeEquals_Behaves()
    {
        Assert.True(HashPrimitives.FixedTimeEquals(new byte[] { 1, 2 }, new byte[] { 1, 2 }));
        Assert.False(HashPrimitives.FixedTimeEquals(new byte[] { 1, 2 }, new byte[] { 1, 3 }));
        Assert.False(HashPrimitives.FixedTimeEquals(new byte[] { 1 }, new byte[] { 1, 2 }));
    }

    [Theory]
    [InlineData("", false)]
    [InlineData("A", false)]
    [InlineData("AA", true)]
    [InlineData("AB", false)]   // non-canonical trailing bits
    [InlineData("AA==", false)] // padding not allowed
    [InlineData("A A=", false)]
    [InlineData("-_", false)]   // url-safe alphabet not allowed
    public void B64_IsStrict(string value, bool ok)
    {
        Assert.Equal(ok, HashPrimitives.TryFromB64(value, out _));
    }
}
