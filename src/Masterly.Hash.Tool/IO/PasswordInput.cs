using System.Text;
using Masterly.Hash.Primitives;

namespace Masterly.Hash.Tool.IO
{
    /// <summary>
    /// Gets a password from a no-echo prompt or the first line of standard input. There is deliberately no way to
    /// pass one as a command-line argument: arguments end up in shell history and process listings.
    /// </summary>
    internal static class PasswordInput
    {
        /// <summary>Longest password accepted from the prompt or standard input, in UTF-16 code units.</summary>
        public const int MaxPasswordChars = 4096;

        public const string TooLongMessage = "The password is longer than 4096 characters.";

        /// <summary>
        /// Reads a password. With <paramref name="fromStdin"/>, the first line of standard input (without its line
        /// break); otherwise a prompt, asked twice when <paramref name="confirm"/> is true.
        /// </summary>
        public static string Read(IToolConsole console, bool fromStdin, bool confirm)
        {
            string? password;
            if (fromStdin)
            {
                RequireRedirected(console, "--stdin");
                password = LineReader.ReadLine(console.In, MaxPasswordChars, TooLongMessage);
                if (password == null)
                    throw new ToolException("No password on standard input.");
            }
            else
            {
                if (console.IsInputRedirected)
                    throw new ToolException("Standard input is redirected, so there is no prompt; pass --stdin to read the password from it.");

                password = console.ReadSecret("Password: ");
                if (password == null)
                    throw new ToolException("No password entered.");
                if (password.Length > MaxPasswordChars)
                    throw new ToolException(TooLongMessage);
                if (confirm && password.Length > 0)
                {
                    string? again = console.ReadSecret("Confirm password: ");
                    if (again == null || !SecretEquals(password, again))
                        throw new ToolException("The passwords do not match.");
                }
            }

            if (password.Length == 0)
                throw new ToolException("The password is empty; empty passwords are never hashed and never match.");
            return password;
        }

        /// <summary>
        /// Refuses to read a secret from standard input when it is a terminal: the terminal's line mode would echo
        /// it as it is typed (into the scrollback and any session recording).
        /// </summary>
        public static void RequireRedirected(IToolConsole console, string option, string? alternative = null)
        {
            if (!console.IsInputRedirected)
                throw new ToolException(option + " expects piped input, but standard input is a terminal (typing there would echo the secret). " +
                    "Pipe the secret in, or " + (alternative ?? "omit " + option + " to use the no-echo prompt") + ".");
        }

        /// <summary>Constant-time comparison of two secrets; the temporary encodings are zeroed.</summary>
        public static bool SecretEquals(string left, string right)
        {
            byte[] a = Encoding.UTF8.GetBytes(left);
            byte[] b = Encoding.UTF8.GetBytes(right);
            try
            {
                return HashPrimitives.FixedTimeEquals(a, b);
            }
            finally
            {
                HashPrimitives.Zero(a);
                HashPrimitives.Zero(b);
            }
        }
    }
}
