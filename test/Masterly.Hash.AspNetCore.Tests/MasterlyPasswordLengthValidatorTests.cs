using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using MasterlyOptions = Masterly.Hash.PasswordHasherOptions;

namespace Masterly.Hash.AspNetCore.Tests;

public class MasterlyPasswordLengthValidatorTests
{
    private const int Limit = 64;

    private static Task<IdentityResult> Validate(string? password, int limit = Limit) =>
        new MasterlyPasswordLengthValidator<TestUser>(limit).ValidateAsync(null!, new TestUser(), password);

    [Fact]
    public void Constructors_ValidateArguments()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new MasterlyPasswordLengthValidator<TestUser>(0));
        Assert.Throws<ArgumentNullException>(() => new MasterlyPasswordLengthValidator<TestUser>((IOptions<MasterlyOptions>)null!));
        Assert.Equal(512, new MasterlyPasswordLengthValidator<TestUser>(Options.Create(new MasterlyOptions { MaxPasswordBytes = 512 })).MaxPasswordBytes);
    }

    [Fact]
    public async Task NullPassword_Throws() =>
        await Assert.ThrowsAsync<ArgumentNullException>(() => Validate(null));

    [Fact]
    public async Task EmptyPassword_Fails()
    {
        IdentityResult result = await Validate("");
        Assert.False(result.Succeeded);
        Assert.Equal(MasterlyPasswordLengthValidator<TestUser>.PasswordRequiredCode, Assert.Single(result.Errors).Code);
    }

    [Theory]
    [InlineData(1, false)]
    [InlineData(Limit, false)]
    [InlineData(Limit + 1, true)]
    [InlineData(10_000_000, true)]
    public async Task AsciiLength_IsChecked(int length, bool tooLong)
    {
        IdentityResult result = await Validate(new string('a', length));
        Assert.Equal(!tooLong, result.Succeeded);
        if (tooLong)
        {
            IdentityError error = Assert.Single(result.Errors);
            Assert.Equal(MasterlyPasswordLengthValidator<TestUser>.PasswordTooLongCode, error.Code);
            Assert.Contains("64", error.Description, StringComparison.Ordinal);
            Assert.DoesNotContain("aaaa", error.Description, StringComparison.Ordinal);
        }
    }

    [Theory]
    [InlineData("ﷺ", false)]       // 33 bytes after NFKC
    [InlineData("ﷺﷺ", true)]  // 6 raw bytes, 66 after NFKC: the hasher would refuse it
    [InlineData("각각각각각각각각", false)] // 72 raw bytes, 24 after NFKC
    public async Task NonAscii_IsMeasuredLikeTheHasher(string password, bool tooLong)
    {
        IdentityResult result = await Validate(password);
        Assert.Equal(!tooLong, result.Succeeded);

        var hasher = new PasswordHasher(new MasterlyOptions { DefaultProfile = TestHashers.Fast, AllowWeakProfiles = true, MaxPasswordBytes = Limit });
        if (tooLong)
            Assert.Throws<ArgumentException>(() => hasher.Hash(password));
        else
            Assert.StartsWith("$mh$", hasher.Hash(password), StringComparison.Ordinal);
    }

    [Fact]
    public async Task HugeNfkcExpandingPassword_IsRejectedWithoutNormalizing()
    {
        string hostile = new('ﷺ', 4_000_000);

        long before = GC.GetAllocatedBytesForCurrentThread();
        IdentityResult result = await Validate(hostile, 1024);
        long allocated = GC.GetAllocatedBytesForCurrentThread() - before;

        Assert.False(result.Succeeded);
        Assert.True(allocated < 100_000, $"The validator allocated {allocated} bytes; it must reject from the length alone.");
    }
}
