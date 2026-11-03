using System.CommandLine;
using System.IO;
using Masterly.Hash.Tool.IO;

namespace Masterly.Hash.Tool.Commands
{
    /// <summary><c>verify &lt;storedHash&gt; [--stdin]</c>: exit 0 match, 1 mismatch, 2 unusable hash or input.</summary>
    internal static class VerifyCommand
    {
        public static Command Create(ToolEnvironment environment)
        {
            var storedHash = new Argument<string>("storedHash")
            {
                Description = "The stored hash (Masterly or any supported legacy format). Quote it: it contains '$'.",
            };
            Option<bool> stdin = CommandHelpers.StdinOption();
            var command = new Command("verify", "Verify a password from a no-echo prompt or --stdin against a stored hash. Exit code 0 = match, 1 = mismatch, 2 = error.")
            {
                storedHash,
                stdin,
            };
            command.SetAction(parse => Execute(environment, parse.GetValue(storedHash) ?? string.Empty, parse.GetValue(stdin)));
            return command;
        }

        public static int Execute(ToolEnvironment environment, string storedHash, bool fromStdin)
        {
            PasswordHasher hasher = CommandHelpers.CreateHasher(environment);
            string password = PasswordInput.Read(environment.Console, fromStdin, confirm: false);
            PasswordVerificationResult result = hasher.Verify(password, storedHash);

            TextWriter output = environment.Console.Out;
            output.WriteLine("Status:         " + result.Status);
            output.WriteLine("Match:          " + CommandHelpers.YesNo(result.IsMatch));
            if (result.Status == VerificationStatus.Failed)
                output.WriteLine("Failure reason: " + result.FailureReason);
            if (result.NeedsRehash)
            {
                output.WriteLine("Rehash reason:  " + result.RehashReason);
                if (result.Rehash != null)
                    output.WriteLine("Rehash:         " + result.Rehash);
            }

            if (result.IsMatch)
                return ExitCodes.Success;
            return result.FailureReason == VerificationFailureReason.Mismatch ? ExitCodes.Failure : ExitCodes.Error;
        }
    }
}
