using System;
using System.Security.Cryptography;
using System.Text;
using FsCheck.Xunit;
using Masterly.Hash.Primitives;
using Masterly.Hash.PropertyTests.Support;

namespace Masterly.Hash.PropertyTests;

/// <summary>
/// Differential tests of PBKDF2 against <see cref="Rfc2898DeriveBytes.Pbkdf2(byte[], byte[], int, HashAlgorithmName, int)"/>.
/// </summary>
[Properties(Arbitrary = new[] { typeof(Arbitraries) }, QuietOnSuccess = true)]
public class Pbkdf2DifferentialProperties
{
    [Property(MaxTest = 1000)]
    public void Public_Pbkdf2_matches_the_BCL(Pbkdf2Case c)
    {
        byte[] expected = Rfc2898DeriveBytes.Pbkdf2(c.Password, c.Salt, c.Iterations, c.Prf, c.Length);
        Assert.Equal(expected, HashPrimitives.Pbkdf2(c.Prf, c.Password, c.Salt, c.Iterations, c.Length));
    }

    [Property(MaxTest = 300)]
    public void DeriveKey_with_a_PBKDF2_profile_is_PBKDF2_HMAC_SHA512(Pbkdf2Case c)
    {
        if (c.Password.Length == 0 || c.Salt.Length < 8)
            return; // DeriveKey's documented preconditions
        int tagLength = Math.Clamp(c.Length, 16, 64);
        HashProfile profile = HashProfile.Pbkdf2Sha512("pbkdf2-" + c.Iterations, c.Iterations, tagLength: tagLength);

        byte[] expected = Rfc2898DeriveBytes.Pbkdf2(c.Password, c.Salt, c.Iterations, HashAlgorithmName.SHA512, tagLength);
        Assert.Equal(expected, HashPrimitives.DeriveKey(profile, c.Password, c.Salt));
    }

    /// <summary>RFC 6070 (PBKDF2-HMAC-SHA1) §2 and RFC 7914 (scrypt) §11 (PBKDF2-HMAC-SHA256) test vectors.</summary>
    [Theory]
    [InlineData("SHA1", "password", "salt", 1, "0c60c80f961f0e71f3a9b524af6012062fe037a6")]
    [InlineData("SHA1", "password", "salt", 2, "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957")]
    [InlineData("SHA1", "password", "salt", 4096, "4b007901b765489abead49d926f721d065a429c1")]
    [InlineData("SHA1", "passwordPASSWORDpassword", "saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096, "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038")]
    [InlineData("SHA1", "pass\0word", "sa\0lt", 4096, "56fa6aa75548099dcc37d7f03425e0c3")]
    [InlineData("SHA256", "passwd", "salt", 1, "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783")]
    [InlineData("SHA256", "Password", "NaCl", 80000, "4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d")]
    public void Known_answer_vectors(string prf, string password, string salt, int iterations, string expectedHex)
    {
        var name = new HashAlgorithmName(prf);
        byte[] p = Encoding.ASCII.GetBytes(password);
        byte[] s = Encoding.ASCII.GetBytes(salt);
        byte[] expected = Convert.FromHexString(expectedHex);

        Assert.Equal(expected, HashPrimitives.Pbkdf2(name, p, s, iterations, expected.Length));
    }

    [Property(MaxTest = 100)]
    public void Invalid_arguments_throw_argument_exceptions_only(Pbkdf2Case c)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => HashPrimitives.Pbkdf2(c.Prf, c.Password, c.Salt, 1 - c.Iterations, c.Length));
        Assert.Throws<ArgumentOutOfRangeException>(() => HashPrimitives.Pbkdf2(c.Prf, c.Password, c.Salt, c.Iterations, 1 - c.Length));
        Assert.Throws<ArgumentOutOfRangeException>(() => HashPrimitives.Pbkdf2(HashAlgorithmName.MD5, c.Password, c.Salt, c.Iterations, c.Length));
        Assert.Throws<ArgumentOutOfRangeException>(() => HashPrimitives.Pbkdf2(HashAlgorithmName.SHA384, c.Password, c.Salt, c.Iterations, c.Length));
        Assert.Throws<ArgumentNullException>(() => HashPrimitives.Pbkdf2(c.Prf, null!, c.Salt, c.Iterations, c.Length));
        Assert.Throws<ArgumentNullException>(() => HashPrimitives.Pbkdf2(c.Prf, c.Password, null!, c.Iterations, c.Length));
    }
}
