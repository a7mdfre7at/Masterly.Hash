using System;
using System.CommandLine;
using System.Globalization;
using System.IO;
using Masterly.Hash.Primitives;
using Masterly.Hash.Tokens;
using Masterly.Hash.Tool.IO;

namespace Masterly.Hash.Tool.Commands
{
    /// <summary>Settings for <see cref="ApiKeyCommand"/>.</summary>
    internal sealed class ApiKeySettings
    {
        public string Prefix { get; set; } = string.Empty;
        public string KeyId { get; set; } = ApiKeyCommand.DefaultKeyId;
        public string? KeyEnvironmentVariable { get; set; }
        public bool KeyFromStdin { get; set; }
        public int EntropyBytes { get; set; } = ApiKey.DefaultEntropyBytes;
    }

    /// <summary>
    /// <c>apikey generate --prefix mh_live [--key-env NAME | --key-stdin] [--key-id k1]</c>: prints a new API key and
    /// its lookup hash. The HMAC lookup key is never taken from a command-line argument.
    /// </summary>
    internal static class ApiKeyCommand
    {
        public const string DefaultKeyId = "k1";

        /// <summary>Longest base64 lookup key accepted from stdin or the environment.</summary>
        private const int MaxKeyChars = 1024;

        public static Command Create(ToolEnvironment environment)
        {
            var prefix = new Option<string>("--prefix")
            {
                Description = "Key prefix, e.g. mh_live: 1-32 ASCII letters, digits and single underscores, starting with a letter.",
                Required = true,
            };
            var keyId = new Option<string>("--key-id")
            {
                Description = "Id of the HMAC lookup key, stored in the lookup hash.",
                DefaultValueFactory = _ => DefaultKeyId,
            };
            var keyEnv = new Option<string?>("--key-env")
            {
                Description = "Read the base64 HMAC lookup key (32+ bytes) from this environment variable instead of generating one.",
                HelpName = "NAME",
            };
            var keyStdin = new Option<bool>("--key-stdin")
            {
                Description = "Read the base64 HMAC lookup key from the first line of standard input instead of generating one.",
            };
            var entropy = new Option<int>("--entropy-bytes")
            {
                Description = "Random bytes in the key (16-64).",
                DefaultValueFactory = _ => ApiKey.DefaultEntropyBytes,
                HelpName = "N",
            };

            var generate = new Command("generate", "Print a new API key and its lookup hash (HMAC-SHA256). Without --key-env or --key-stdin a new lookup key is generated and printed.")
            {
                prefix, keyId, keyEnv, keyStdin, entropy,
            };
            generate.SetAction(parse => Generate(environment, new ApiKeySettings
            {
                Prefix = parse.GetValue(prefix) ?? string.Empty,
                KeyId = parse.GetValue(keyId) ?? DefaultKeyId,
                KeyEnvironmentVariable = parse.GetValue(keyEnv),
                KeyFromStdin = parse.GetValue(keyStdin),
                EntropyBytes = parse.GetValue(entropy),
            }));
            return new Command("apikey", "API key utilities.") { generate };
        }

        public static int Generate(ToolEnvironment environment, ApiKeySettings settings)
        {
            if (settings == null) throw new ArgumentNullException(nameof(settings));
            if (!ApiKey.IsValidPrefix(settings.Prefix))
                throw new ToolException("--prefix must be 1-32 ASCII letters, digits and single underscores, start with a letter and not end with '_' (e.g. mh_live).");
            if (!HmacKeyRing.IsValidKeyId(settings.KeyId))
                throw new ToolException("--key-id must match ^[A-Za-z0-9-]{1,32}$.");
            if (settings.EntropyBytes < ApiKey.MinEntropyBytes || settings.EntropyBytes > ApiKey.MaxEntropyBytes)
                throw new ToolException(string.Format(CultureInfo.InvariantCulture,
                    "--entropy-bytes must be between {0} and {1}.", ApiKey.MinEntropyBytes, ApiKey.MaxEntropyBytes));
            if (settings.KeyEnvironmentVariable != null && settings.KeyFromStdin)
                throw new ToolException("Pass either --key-env or --key-stdin, not both.");

            string? source = null;
            byte[] key;
            if (settings.KeyEnvironmentVariable != null)
            {
                string? text = environment.GetEnvironmentVariable(settings.KeyEnvironmentVariable);
                if (string.IsNullOrWhiteSpace(text))
                    throw new ToolException("Environment variable " + settings.KeyEnvironmentVariable + " is not set.");
                key = DecodeKey(text!, "environment variable " + settings.KeyEnvironmentVariable);
                source = "from environment variable " + settings.KeyEnvironmentVariable;
            }
            else if (settings.KeyFromStdin)
            {
                PasswordInput.RequireRedirected(environment.Console, "--key-stdin", "use --key-env");
                string? text = LineReader.ReadLine(environment.Console.In, MaxKeyChars, "The lookup key on standard input is too long.");
                if (string.IsNullOrWhiteSpace(text))
                    throw new ToolException("No lookup key on standard input.");
                key = DecodeKey(text!, "standard input");
                source = "from standard input";
            }
            else
            {
                key = HmacKeyRing.GenerateKey();
            }

            HmacKeyRing ring;
            string? newKey = null;
            try
            {
                if (key.Length < HmacKeyRing.MinKeyLength)
                    throw new ToolException(string.Format(CultureInfo.InvariantCulture,
                        "The lookup key must be at least {0} bytes.", HmacKeyRing.MinKeyLength));
                ring = new HmacKeyRing(settings.KeyId, key);
                if (source == null)
                    newKey = Convert.ToBase64String(key);
            }
            finally
            {
                HashPrimitives.Zero(key);
            }

            GeneratedApiKey generated = ApiKey.Generate(new ApiKeyHasher(ring), settings.Prefix, settings.EntropyBytes);

            TextWriter output = environment.Console.Out;
            output.WriteLine("API key:       " + generated.PlainText);
            output.WriteLine("Lookup hash:   " + generated.LookupHash);
            output.WriteLine("Hint:          " + generated.Hint);
            output.WriteLine("Lookup key id: " + settings.KeyId);
            output.WriteLine("Lookup key:    " + (newKey ?? "(provided " + source + ")"));

            TextWriter notes = environment.Console.Error;
            notes.WriteLine("Give the API key to its owner once; store only the lookup hash (ideally in a unique index).");
            if (newKey != null)
                notes.WriteLine("The lookup key is new: keep it in a secret store, not the database. Every lookup hash depends on it.");
            return ExitCodes.Success;
        }

        private static byte[] DecodeKey(string text, string where)
        {
            try
            {
                return Convert.FromBase64String(text.Trim());
            }
            catch (FormatException)
            {
                throw new ToolException("The lookup key in " + where + " is not valid base64.");
            }
        }
    }
}
