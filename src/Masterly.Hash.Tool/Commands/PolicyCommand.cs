using System;
using System.CommandLine;
using System.Globalization;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Masterly.Hash.Policy;
using Masterly.Hash.Tool.IO;

namespace Masterly.Hash.Tool.Commands
{
    /// <summary>Settings for <see cref="PolicyCommand"/>.</summary>
    internal sealed class PolicySettings
    {
        public bool FromStdin { get; set; }
        public int? MinLength { get; set; }
        public bool Pwned { get; set; }
        public bool AllowUnavailable { get; set; }
        public string? UserName { get; set; }
        public string? Email { get; set; }
    }

    /// <summary>
    /// <c>policy [--min-length N] [--pwned]</c>: NIST SP 800-63B checks, strength score and crack times.
    /// Exit 0 acceptable, 1 rejected, 2 when <c>--pwned</c> was asked for but the breach check could not be done
    /// (unless <c>--allow-unavailable</c>).
    /// </summary>
    internal static class PolicyCommand
    {
        public static Command Create(ToolEnvironment environment)
        {
            Option<bool> stdin = CommandHelpers.StdinOption();
            var minLength = new Option<int?>("--min-length")
            {
                Description = "Minimum length in code points (8-128). Default 15, the NIST minimum for a single-factor password.",
                HelpName = "N",
            };
            var pwned = new Option<bool>("--pwned")
            {
                Description = "ONLINE: also look the password up in Have I Been Pwned. Only the first 5 hex characters of its SHA-1 hash are sent (k-anonymity).",
            };
            var allowUnavailable = new Option<bool>("--allow-unavailable")
            {
                Description = "With --pwned: if Have I Been Pwned cannot be reached, judge the password without it (exit 0/1) instead of failing with exit code 2.",
            };
            var userName = new Option<string?>("--user-name") { Description = "The account's user name; passwords containing it are rejected." };
            var email = new Option<string?>("--email") { Description = "The account's email address; passwords containing its parts are rejected." };

            var command = new Command("policy", "Check a password from a no-echo prompt or --stdin against the NIST SP 800-63B policy: score, crack-time estimates, violations and suggestions. Exit code 0 = acceptable, 1 = rejected, 2 = error (including --pwned when the breach check is unavailable).")
            {
                stdin, minLength, pwned, allowUnavailable, userName, email,
            };
            command.SetAction((parse, cancellationToken) => ExecuteAsync(
                environment,
                new PolicySettings
                {
                    FromStdin = parse.GetValue(stdin),
                    MinLength = parse.GetValue(minLength),
                    Pwned = parse.GetValue(pwned),
                    AllowUnavailable = parse.GetValue(allowUnavailable),
                    UserName = parse.GetValue(userName),
                    Email = parse.GetValue(email),
                },
                cancellationToken));
            return command;
        }

        public static async Task<int> ExecuteAsync(ToolEnvironment environment, PolicySettings settings, CancellationToken cancellationToken)
        {
            if (settings == null) throw new ArgumentNullException(nameof(settings));

            var options = new PasswordPolicyOptions();
            if (settings.AllowUnavailable && !settings.Pwned)
                throw new ToolException("--allow-unavailable only applies with --pwned.");
            if (settings.MinLength.HasValue)
            {
                int min = settings.MinLength.Value;
                if (min < PasswordPolicyOptions.MinimumAllowedMinLength || min > options.MaxLength)
                    throw new ToolException("--min-length must be between 8 (the NIST floor) and 128.");
                options.MinLength = min;
            }

            var context = new PasswordContext { UserName = settings.UserName, Email = settings.Email };
            string password = PasswordInput.Read(environment.Console, settings.FromStdin, confirm: false);

            PasswordPolicyResult result;
            if (settings.Pwned)
            {
                environment.Console.Error.WriteLine("policy: querying Have I Been Pwned (online; only a 5-character SHA-1 prefix is sent)...");
                IBreachedPasswordChecker checker = environment.BreachCheckerFactory();
                try
                {
                    var policy = new PasswordPolicy(options, checker);
                    result = await policy.EvaluateAsync(password, context, cancellationToken).ConfigureAwait(false);
                }
                finally
                {
                    (checker as IDisposable)?.Dispose();
                }
            }
            else
            {
                result = new PasswordPolicy(options).Evaluate(password, context);
            }

            Write(environment.Console.Out, result, settings.Pwned);

            // Fail closed: a breach check that was asked for but not done must not look like a clean result to a script.
            // (A password rejected on other grounds is still reported as rejected.)
            if (result.IsAcceptable && settings.Pwned && result.BreachCheck?.Status == BreachCheckStatus.Unavailable && !settings.AllowUnavailable)
            {
                environment.Console.Error.WriteLine("error: the Have I Been Pwned check was requested but is unavailable, so the password was not fully checked. " +
                    "Retry when online, or pass --allow-unavailable to accept the result without it.");
                return ExitCodes.Error;
            }
            return result.IsAcceptable ? ExitCodes.Success : ExitCodes.Failure;
        }

        private static void Write(TextWriter output, PasswordPolicyResult result, bool pwned)
        {
            StrengthEstimate estimate = result.StrengthEstimate;
            CrackTimeEstimates times = estimate.CrackTimes;

            output.WriteLine("Result:     " + (result.IsAcceptable ? "Acceptable" : "Rejected"));
            output.WriteLine(string.Format(CultureInfo.InvariantCulture, "Score:      {0}/4 (about 10^{1:0.0} guesses)", result.Score, estimate.GuessesLog10));
            output.WriteLine("Length:     " + CommandHelpers.Number(result.Length) + " code points");
            output.WriteLine("Crack time (estimates):");
            output.WriteLine("  online, rate-limited (100/hour):     " + times.OnlineThrottled.Display);
            output.WriteLine("  online, not rate-limited (10/s):     " + times.OnlineUnthrottled.Display);
            output.WriteLine("  offline, slow hash e.g. Argon2id (10^4/s): " + times.OfflineSlowHash.Display);
            output.WriteLine("  offline, fast hash e.g. SHA-1 (10^10/s):   " + times.OfflineFastHash.Display);
            if (estimate.Warning.Length > 0)
                output.WriteLine("Warning:    " + estimate.Warning);

            if (result.Violations.Count > 0)
            {
                output.WriteLine("Violations:");
                foreach (PasswordViolation violation in result.Violations)
                    output.WriteLine("  - " + violation.Code + ": " + violation.Message);
            }

            if (result.Suggestions.Count > 0)
            {
                output.WriteLine("Suggestions:");
                foreach (string suggestion in result.Suggestions)
                    output.WriteLine("  - " + suggestion);
            }

            if (!pwned)
            {
                output.WriteLine("Breach check: skipped (offline). Pass --pwned to query Have I Been Pwned.");
            }
            else
            {
                BreachCheckResult? breach = result.BreachCheck;
                string text = breach == null ? "not performed (the password was rejected on length)"
                    : breach.Status == BreachCheckStatus.Unavailable ? "unavailable (the service could not be reached; nothing is known)"
                    : breach.IsBreached ? "BREACHED: seen " + CommandHelpers.Number(breach.Occurrences) + " times in known breaches"
                    : "not found in known breaches";
                output.WriteLine("Breach check (online, Have I Been Pwned k-anonymity): " + text);
            }
        }
    }
}
