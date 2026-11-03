using System;
using System.CommandLine;
using Masterly.Hash.Pepper;
using Masterly.Hash.Primitives;

namespace Masterly.Hash.Tool.Commands
{
    /// <summary><c>pepper generate</c>: prints a new base64 32-byte pepper key.</summary>
    internal static class PepperCommand
    {
        public static Command Create(ToolEnvironment environment)
        {
            var generate = new Command("generate", "Print a new random 32-byte pepper key, base64-encoded, for HmacPepper.");
            generate.SetAction(_ => Generate(environment));
            return new Command("pepper", "Pepper key utilities.") { generate };
        }

        public static int Generate(ToolEnvironment environment)
        {
            byte[] key = HmacPepper.GenerateKey();
            try
            {
                environment.Console.Out.WriteLine(Convert.ToBase64String(key));
            }
            finally
            {
                HashPrimitives.Zero(key);
            }
            environment.Console.Error.WriteLine("Keep this key in a secret store (environment, Key Vault, Vault), never in the database, and give it a key id, e.g. HmacPepper.FromBase64(\"k1\", ...).");
            return ExitCodes.Success;
        }
    }
}
