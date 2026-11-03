using Masterly.Hash.PropertyTests.Support;

namespace Masterly.Hash.PropertyTests;

internal static class Assertions
{
    /// <summary>Reasons that mean "this stored hash cannot be used by this hasher" (as opposed to a wrong password).</summary>
    public static readonly VerificationFailureReason[] Unusable =
    {
        VerificationFailureReason.NoStoredHash,
        VerificationFailureReason.UnknownFormat,
        VerificationFailureReason.MalformedHash,
        VerificationFailureReason.UnknownProfile,
        VerificationFailureReason.UnknownPepperKey,
    };

    /// <summary>The invariants every <see cref="PasswordVerificationResult"/> must satisfy, whatever the input.</summary>
    public static void Consistent(PasswordVerificationResult result, string context)
    {
        Assert.NotNull(result);
        Assert.True(result.IsMatch == (result.Status != VerificationStatus.Failed), context);
        Assert.True(result.IsMatch == (result.FailureReason == VerificationFailureReason.None), $"{context}: {result}");
        Assert.True(result.NeedsRehash == (result.RehashReason != RehashReason.None), $"{context}: {result}");
        if (!result.NeedsRehash)
            Assert.Null(result.Rehash);
    }

    public static string Context(string password, string stored) =>
        $"password={Fixtures.Show(password)} stored={Fixtures.Show(stored)}";
}
