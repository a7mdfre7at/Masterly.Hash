using System;
using System.Collections.Generic;
using System.CommandLine;
using System.Linq;
using System.IO;
using Masterly.Hash.Legacy;

namespace Masterly.Hash.Tool.Commands
{
    /// <summary><c>inspect &lt;storedHash&gt;</c>: describes a stored hash without a password. Exit 0 recognized, 1 not.</summary>
    internal static class InspectCommand
    {
        public static Command Create(ToolEnvironment environment)
        {
            var storedHash = new Argument<string>("storedHash")
            {
                Description = "The stored hash to describe. Quote it: it contains '$'.",
            };
            Option<string?> pepperKeyIds = CommandHelpers.PepperKeyIdsOption();
            var command = new Command("inspect", "Describe a stored hash: format, profile, pepper key, onion-wrapping and whether a login would rehash it.")
            {
                storedHash,
                pepperKeyIds,
            };
            command.SetAction(parse => Execute(environment, parse.GetValue(storedHash) ?? string.Empty,
                ClassificationPepper.ParseKeyIds(parse.GetValue(pepperKeyIds))));
            return command;
        }

        public static int Execute(ToolEnvironment environment, string storedHash, IReadOnlyList<string>? pepperKeyIds = null)
        {
            PasswordHasher hasher = CommandHelpers.CreateHasher(environment, options => CommandHelpers.UseClassificationPepper(options, pepperKeyIds));
            HashInfo info = hasher.Inspect(storedHash);

            string profile = info.Profile != null ? info.Profile.ToString()
                : info.ProfileId != null ? info.ProfileId + " (not registered)"
                : "-";

            bool weak = false;
            if (info.IsRecognized && !string.Equals(info.Format, "mh", StringComparison.Ordinal))
                weak = HashAudit.IsWeak(info.Format, storedHash);

            TextWriter output = environment.Console.Out;
            output.WriteLine("Format:       " + info.Format);
            output.WriteLine("Recognized:   " + CommandHelpers.YesNo(info.IsRecognized));
            output.WriteLine("Profile:      " + profile);
            bool unknownKey = info.PepperKeyId != null && (pepperKeyIds == null || !pepperKeyIds.Contains(info.PepperKeyId));
            output.WriteLine("Pepper key:   " + (info.PepperKeyId == null ? "none"
                : unknownKey ? info.PepperKeyId + " (unknown; pass --pepper-key-ids " + info.PepperKeyId + " to classify it)"
                : info.PepperKeyId));
            output.WriteLine("Wrapped:      " + (info.WrappedFormat != null ? "yes (" + info.WrappedFormat + ")" : "no"));
            output.WriteLine("Needs rehash: " + (info.NeedsRehash ? "yes (" + info.RehashReason + ")" : "no"));
            output.WriteLine("Weak:         " + CommandHelpers.YesNo(weak));
            return info.IsRecognized ? ExitCodes.Success : ExitCodes.Failure;
        }
    }
}
