using Masterly.Hash.Analyzers.Internal;

namespace Masterly.Hash.Analyzers.Tests;

public class NameMatcherTests
{
    [Theory]
    [InlineData("userPassword", new[] { "user", "password" })]
    [InlineData("HTTPToken", new[] { "http", "token" })]
    [InlineData("pwd_2", new[] { "pwd" })]
    [InlineData("_apiKey", new[] { "api", "key" })]
    [InlineData("MAX_PASSWORD_LENGTH", new[] { "max", "password", "length" })]
    [InlineData("XMLHttpRequest", new[] { "xml", "http", "request" })]
    public void SplitWords_SplitsOnHumpsUnderscoresAndDigits(string name, string[] expected) =>
        Assert.Equal(expected, NameMatcher.SplitWords(name));

    [Theory]
    [InlineData("password")]
    [InlineData("Password")]
    [InlineData("PASSWORD")]
    [InlineData("newPassword")]
    [InlineData("PassWord")]
    [InlineData("passwd")]
    [InlineData("pwd")]
    [InlineData("userPwd")]
    [InlineData("passphrase")]
    [InlineData("pin")]
    [InlineData("PinCode")]
    [InlineData("password2")]
    [InlineData("confirm_password")]
    [InlineData("passwordBytes")]
    [InlineData("plainPassword")]
    public void Password_Matches(string name) => Assert.True(NameMatcher.Password.IsMatch(name));

    [Theory]
    [InlineData("passwordPolicy")]
    [InlineData("PasswordLength")]
    [InlineData("passwordHash")]
    [InlineData("hashedPassword_Hash")]
    [InlineData("passwordResetToken")]
    [InlineData("passwordSaltBytes")]
    [InlineData("passwordHashBytes")]
    [InlineData("storedPasswordHashBase64")]
    [InlineData("hashedPassword")]
    [InlineData("HashedPassword")]
    [InlineData("encryptedPassword")]
    [InlineData("saltedPasswordBytes")]
    [InlineData("maskedPin")]
    [InlineData("passwordPolicyName")]
    [InlineData("spinner")]
    [InlineData("pinned")]
    [InlineData("opinion")]
    [InlineData("compass")]
    [InlineData("passage")]
    [InlineData("")]
    [InlineData(null)]
    public void Password_DoesNotMatch(string? name) => Assert.False(NameMatcher.Password.IsMatch(name));

    [Theory]
    [InlineData("hash")]
    [InlineData("storedHash")]
    [InlineData("hashedPassword")]
    [InlineData("digest")]
    [InlineData("mac")]
    [InlineData("expectedHmac")]
    [InlineData("signature")]
    [InlineData("accessToken")]
    [InlineData("apiKey")]
    [InlineData("ApiKey")]
    [InlineData("clientSecret")]
    [InlineData("PasswordHash")]
    [InlineData("passwordHashBytes")]
    [InlineData("storedPasswordHashBase64")]
    public void Secret_Matches(string name) => Assert.True(NameMatcher.Secret.IsMatch(name));

    [Theory]
    [InlineData("hashAlgorithm")]
    [InlineData("tokenType")]
    [InlineData("macAddress")]
    [InlineData("macAddressBytes")]
    [InlineData("macAddressString")]
    [InlineData("hashAlgorithmName")]
    [InlineData("tokenTypeValue")]
    [InlineData("GetHashCode")]
    [InlineData("hashtag")]
    [InlineData("machine")]
    [InlineData("tokenizer")]
    [InlineData("apiKeyHeader")]
    [InlineData("secretName")]
    [InlineData("api")]
    public void Secret_DoesNotMatch(string name) => Assert.False(NameMatcher.Secret.IsMatch(name));

    [Theory]
    [InlineData("pepper")]
    [InlineData("Pepper")]
    [InlineData("hmacKey")]
    [InlineData("HmacKey")]
    [InlineData("secretKey")]
    [InlineData("SigningKey")]
    [InlineData("_signingKey")]
    [InlineData("jwtSigningKey")]
    public void Key_Matches(string name) => Assert.True(NameMatcher.Key.IsMatch(name));

    [Theory]
    [InlineData("pepperKeyId")]
    [InlineData("signingKeyName")]
    [InlineData("secretKeyPath")]
    [InlineData("peppermint")]
    [InlineData("key")]
    [InlineData("secret")]
    public void Key_DoesNotMatch(string name) => Assert.False(NameMatcher.Key.IsMatch(name));

    [Theory]
    [InlineData("_")]
    [InlineData("__")]
    [InlineData("_1")]
    public void NamesWithoutWords_DoNotMatch(string name)
    {
        Assert.Empty(NameMatcher.SplitWords(name));
        Assert.False(NameMatcher.Password.IsMatch(name));
        Assert.False(NameMatcher.Secret.IsMatch(name));
        Assert.False(NameMatcher.Key.IsMatch(name));
    }
}
