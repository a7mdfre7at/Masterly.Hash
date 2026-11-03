using System;
using System.Collections.Generic;
using System.CommandLine;
using System.Globalization;
using Masterly.Hash.Legacy;

namespace Masterly.Hash.Tool.Commands
{
    /// <summary>Options and helpers shared by several commands.</summary>
    internal static class CommandHelpers
    {
        public static readonly string[] BuiltInProfileIds = { "2026a", "2026c", "2026f" };

        public static Option<bool> StdinOption() =>
            new Option<bool>("--stdin")
            {
                Description = "Read the password from the first line of standard input instead of prompting.",
            };

        public static Option<string?> ProfileOption(string description)
        {
            var option = new Option<string?>("--profile")
            {
                Description = description,
                HelpName = "2026a|2026c|2026f",
            };
            option.AcceptOnlyFromAmong(BuiltInProfileIds);
            return option;
        }

        public static Option<string> DelimiterOption() =>
            new Option<string>("--delimiter")
            {
                Description = "CSV field delimiter: one character, or 'tab'.",
                DefaultValueFactory = _ => ",",
            };

        public static Option<bool> HeaderOption(string description) =>
            new Option<bool>("--header") { Description = description };

        /// <summary>
        /// <c>--pepper-key-ids k2,k1</c>: the pepper key ids the application knows (current first), so peppered hashes
        /// are classified rather than counted as unknown. Only ids are given; the keys themselves are never needed.
        /// </summary>
        public static Option<string?> PepperKeyIdsOption() =>
            new Option<string?>("--pepper-key-ids")
            {
                Description = "Comma-separated pepper key ids your application knows, current key first (e.g. k2,k1). " +
                    "Peppered hashes ($mh$p=...,k=ID$...) are then classified instead of reported as unknown. Only the ids are needed, never the keys.",
                HelpName = "IDS",
            };

        /// <summary>Registers a <see cref="ClassificationPepper"/> for <paramref name="keyIds"/>, if any.</summary>
        public static void UseClassificationPepper(PasswordHasherOptions options, IReadOnlyList<string>? keyIds)
        {
            if (keyIds != null && keyIds.Count > 0)
                options.Pepper = new ClassificationPepper(keyIds);
        }

        public static HashProfile ResolveProfile(string id)
        {
            switch (id)
            {
                case "2026a":
                    return HashProfile.Server2026a;
                case "2026c":
                    return HashProfile.Constrained2026a;
                case "2026f":
                    return HashProfile.Fips2026a;
                default:
                    throw new ToolException("Unknown profile; use 2026a, 2026c or 2026f.");
            }
        }

        /// <summary>A hasher from the environment's options with every legacy format registered.</summary>
        public static PasswordHasher CreateHasher(ToolEnvironment environment, Action<PasswordHasherOptions>? configure = null)
        {
            PasswordHasherOptions options = environment.HasherOptionsFactory();
            if (options == null)
                throw new InvalidOperationException("HasherOptionsFactory returned null.");
            options.AddAllLegacyFormats();
            configure?.Invoke(options);
            return new PasswordHasher(options);
        }

        public static string YesNo(bool value) => value ? "yes" : "no";

        public static string Number(long value) => value.ToString(CultureInfo.InvariantCulture);

        public static string Milliseconds(double value) => value.ToString("0.0", CultureInfo.InvariantCulture);
    }
}
