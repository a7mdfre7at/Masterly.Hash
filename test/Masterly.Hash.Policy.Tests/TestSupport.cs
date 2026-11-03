using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace Masterly.Hash.Policy.Tests;

internal static class Policies
{
    /// <summary>Fixed so year and date scoring does not drift with the calendar.</summary>
    public const int ReferenceYear = 2026;

    public static PasswordPolicy Create(Action<PasswordPolicyOptions>? configure = null, IBreachedPasswordChecker? checker = null)
    {
        var options = new PasswordPolicyOptions { ReferenceYear = ReferenceYear };
        configure?.Invoke(options);
        return new PasswordPolicy(options, checker);
    }

    /// <summary>Weak, fast hasher for the integration test only.</summary>
    public static PasswordHasher FastHasher() =>
        new PasswordHasher(new PasswordHasherOptions { DefaultProfile = HashProfile.Argon2id("test", 64, 1), AllowWeakProfiles = true });

    /// <summary>Every piece of text a result exposes.</summary>
    public static List<string> Texts(PasswordPolicyResult result)
    {
        var texts = new List<string> { result.ToString(), result.StrengthEstimate.ToString(), result.StrengthEstimate.Warning };
        foreach (PasswordViolation violation in result.Violations)
        {
            texts.Add(violation.Message);
            texts.Add(violation.ToString());
        }
        texts.AddRange(result.Suggestions);
        texts.AddRange(result.StrengthEstimate.Suggestions);
        foreach (PatternMatch match in result.StrengthEstimate.Sequence)
            texts.Add(match.ToString());
        if (result.BreachCheck != null)
            texts.Add(result.BreachCheck.ToString());
        return texts;
    }
}

/// <summary>Hand-written fake; records what it was asked.</summary>
internal sealed class FakeBreachChecker : IBreachedPasswordChecker
{
    private readonly Func<string, CancellationToken, ValueTask<BreachCheckResult>> _behaviour;

    public FakeBreachChecker(BreachCheckResult? result)
        : this((_, _) => new ValueTask<BreachCheckResult>(result!))
    {
    }

    public FakeBreachChecker(Func<string, CancellationToken, ValueTask<BreachCheckResult>> behaviour) => _behaviour = behaviour;

    public static FakeBreachChecker Throwing(Exception exception) => new((_, _) => throw exception);

    public List<string> Received { get; } = new();

    public int Calls => Received.Count;

    public ValueTask<BreachCheckResult> CheckAsync(string password, CancellationToken cancellationToken)
    {
        Received.Add(password);
        return _behaviour(password, cancellationToken);
    }
}
