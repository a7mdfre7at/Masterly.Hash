using System;
using System.CommandLine;
using Masterly.Hash.Tool.IO;

namespace Masterly.Hash.Tool.Commands
{
    /// <summary><c>hash [--profile 2026a|2026c|2026f] [--stdin]</c>: prints a new hash.</summary>
    internal static class HashCommand
    {
        public static Command Create(ToolEnvironment environment)
        {
            Option<string?> profile = CommandHelpers.ProfileOption("Built-in profile for the new hash. Default: 2026a (Argon2id, 64 MiB, t=3).");
            Option<bool> stdin = CommandHelpers.StdinOption();
            var command = new Command("hash", "Hash a password from a no-echo prompt (asked twice) or --stdin, and print the hash.")
            {
                profile,
                stdin,
            };
            command.SetAction(parse => Execute(environment, parse.GetValue(profile), parse.GetValue(stdin)));
            return command;
        }

        public static int Execute(ToolEnvironment environment, string? profileId, bool fromStdin)
        {
            PasswordHasher hasher = CommandHelpers.CreateHasher(environment);
            HashProfile profile = profileId == null ? hasher.DefaultProfile : CommandHelpers.ResolveProfile(profileId);
            string password = PasswordInput.Read(environment.Console, fromStdin, confirm: true);

            string hash;
            try
            {
                hash = hasher.Hash(password, profile);
            }
            catch (ArgumentException ex)
            {
                // Core messages name limits, never the password.
                throw new ToolException("The password cannot be hashed: " + ex.Message);
            }

            environment.Console.Out.WriteLine(hash);
            return ExitCodes.Success;
        }
    }
}
