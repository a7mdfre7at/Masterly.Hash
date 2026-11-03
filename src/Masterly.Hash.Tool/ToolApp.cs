using System;
using System.Collections.Generic;
using System.CommandLine;
using System.CommandLine.Invocation;
using System.IO;
using System.Reflection;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Masterly.Hash.Tool.Commands;

namespace Masterly.Hash.Tool
{
    /// <summary>
    /// The <c>masterly-hash</c> command line. <see cref="RunAsync"/> parses arguments, runs one command against a
    /// <see cref="ToolEnvironment"/> and returns the exit code, so the whole tool can run in-process.
    /// </summary>
    public static class ToolApp
    {
        /// <summary>The tool's command name.</summary>
        public const string CommandName = "masterly-hash";

        /// <summary>Commands that read a password; their argument errors are reported without echoing any token.</summary>
        private static readonly HashSet<string> PasswordCommands = new HashSet<string>(StringComparer.Ordinal) { "hash", "verify", "policy" };

        /// <summary>The tool version, e.g. <c>2.0.0</c>.</summary>
        public static string Version { get; } = ReadVersion();

        /// <summary>Parses <paramref name="args"/>, runs the command and returns its exit code (see <see cref="ExitCodes"/>).</summary>
        /// <remarks>Never throws for user errors: they are printed to <see cref="IToolConsole.Error"/> as <c>error: ...</c>.</remarks>
        public static async Task<int> RunAsync(IReadOnlyList<string> args, ToolEnvironment environment, CancellationToken cancellationToken = default)
        {
            if (args == null) throw new ArgumentNullException(nameof(args));
            if (environment == null) throw new ArgumentNullException(nameof(environment));

            TextWriter error = environment.Console.Error;
            RootCommand root = BuildRootCommand(environment);
            // No command needs response files, and '@token' expansion would echo a mistyped '@password' in its error.
            ParseResult parse = root.Parse(args, new ParserConfiguration { ResponseFileTokenReplacer = null });

            if (parse.Action is ParseErrorAction)
            {
                ReportParseErrors(parse, root, args, error);
                return ExitCodes.Error;
            }

            var configuration = new InvocationConfiguration
            {
                Output = environment.Console.Out,
                Error = error,
                EnableDefaultExceptionHandler = false,
            };

            try
            {
                return await parse.InvokeAsync(configuration, cancellationToken).ConfigureAwait(false);
            }
            catch (ToolException ex)
            {
                error.WriteLine("error: " + ex.Message);
                return ex.ExitCode;
            }
            catch (OperationCanceledException)
            {
                error.WriteLine("error: cancelled.");
                return ExitCodes.Cancelled;
            }
            catch (IOException ex)
            {
                error.WriteLine("error: " + ex.Message);
                return ExitCodes.Error;
            }
            catch (UnauthorizedAccessException ex)
            {
                error.WriteLine("error: " + ex.Message);
                return ExitCodes.Error;
            }
            catch (PasswordHasherBusyException ex)
            {
                error.WriteLine("error: " + ex.Message);
                return ExitCodes.Error;
            }
            catch (DecoderFallbackException)
            {
                // The exception message quotes the offending bytes, which may be part of a password: never print it.
                error.WriteLine("error: standard input is not valid UTF-8.");
                return ExitCodes.Error;
            }
        }

        internal static RootCommand BuildRootCommand(ToolEnvironment environment)
        {
            var root = new RootCommand(
                "masterly-hash: hash, verify, inspect, audit and migrate password hashes with Masterly.Hash. " +
                "Passwords are read from a no-echo prompt or --stdin, never from arguments.")
            {
                HashCommand.Create(environment),
                VerifyCommand.Create(environment),
                InspectCommand.Create(environment),
                AuditCommand.Create(environment),
                WrapCommand.Create(environment),
                BenchCommand.Create(environment),
                PolicyCommand.Create(environment),
                PepperCommand.Create(environment),
                ApiKeyCommand.Create(environment),
            };

            foreach (Option option in root.Options)
            {
                if (option is VersionOption version)
                    version.Action = new PrintVersionAction();
            }

            return root;
        }

        private static void ReportParseErrors(ParseResult parse, RootCommand root, IReadOnlyList<string> args, TextWriter error)
        {
            Command command = parse.CommandResult.Command;
            bool sensitive = command is RootCommand || PasswordCommands.Contains(command.Name);
            if (command is RootCommand && parse.UnmatchedTokens.Count > 0)
            {
                // A mistyped command may be followed by a password; echo neither.
                error.WriteLine("error: unrecognized command or argument (not echoed, in case it is a password).");
            }
            else if (sensitive && parse.UnmatchedTokens.Count > 0)
            {
                // The stray token may well be a password; do not echo it anywhere.
                error.WriteLine("error: unexpected argument. Passwords are never accepted on the command line (they would end up in " +
                    "shell history and process listings): type it at the prompt, or pipe it in with --stdin.");
            }
            else
            {
                IReadOnlyList<string> secrets = sensitive ? PossibleSecrets(root, args) : Array.Empty<string>();
                foreach (System.CommandLine.Parsing.ParseError parseError in parse.Errors)
                    error.WriteLine("error: " + Redact(parseError.Message, secrets));
            }

            string help = command is RootCommand ? CommandName + " --help" : CommandName + " " + CommandPath(command) + " --help";
            error.WriteLine("Run '" + help + "' for usage.");
        }

        /// <summary>
        /// Every argument that is not a command or option name (and the value part of <c>--option=value</c>), i.e.
        /// everything that could be a password typed in the wrong place.
        /// </summary>
        internal static IReadOnlyList<string> PossibleSecrets(RootCommand root, IReadOnlyList<string> args)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            CollectNames(root, names);

            var secrets = new List<string>();
            foreach (string arg in args)
            {
                if (string.IsNullOrEmpty(arg) || names.Contains(arg))
                    continue;
                secrets.Add(arg);
                if (arg.Length > 1 && arg[0] == '@')
                    secrets.Add(arg.Substring(1));
                int separator = arg.StartsWith("-", StringComparison.Ordinal) ? arg.IndexOfAny(new[] { '=', ':' }) : -1;
                if (separator > 0 && separator < arg.Length - 1)
                    secrets.Add(arg.Substring(separator + 1));
            }

            // Longest first, so a token is never left half-redacted by a shorter one inside it.
            secrets.Sort((a, b) => b.Length.CompareTo(a.Length));
            return secrets;
        }

        /// <summary>
        /// Replaces each quoted possible secret in <paramref name="message"/> with <c>'***'</c>. If one still appears
        /// unquoted, the whole message is replaced by a generic one.
        /// </summary>
        internal static string Redact(string message, IReadOnlyList<string> secrets)
        {
            if (secrets.Count == 0)
                return message;
            string redacted = message;
            foreach (string secret in secrets)
                redacted = redacted.Replace("'" + secret + "'", "'***'", StringComparison.Ordinal);
            foreach (string secret in secrets)
            {
                if (secret.Length >= 3 && redacted.Contains(secret, StringComparison.Ordinal))
                    return "invalid arguments (details withheld: an argument may be a password, which is never echoed).";
            }
            return redacted;
        }

        private static void CollectNames(Command command, HashSet<string> names)
        {
            names.Add(command.Name);
            foreach (string alias in command.Aliases)
                names.Add(alias);
            foreach (Option option in command.Options)
            {
                names.Add(option.Name);
                foreach (string alias in option.Aliases)
                    names.Add(alias);
            }
            foreach (Command sub in command.Subcommands)
                CollectNames(sub, names);
        }

        private static string CommandPath(Command command)
        {
            var names = new List<string>();
            for (Command? current = command; current != null && !(current is RootCommand); current = Parent(current))
                names.Insert(0, current.Name);
            return string.Join(" ", names);
        }

        private static Command? Parent(Command command)
        {
            foreach (Symbol parent in command.Parents)
            {
                if (parent is Command parentCommand)
                    return parentCommand;
            }
            return null;
        }

        private static string ReadVersion()
        {
            string? informational = typeof(ToolApp).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
            if (string.IsNullOrEmpty(informational))
                return typeof(ToolApp).Assembly.GetName().Version?.ToString() ?? "0.0.0";
            int plus = informational!.IndexOf('+');
            return plus >= 0 ? informational.Substring(0, plus) : informational;
        }

        /// <summary>Prints this tool's version rather than the entry assembly's (which differs when hosted in-process).</summary>
        private sealed class PrintVersionAction : SynchronousCommandLineAction
        {
            public override int Invoke(ParseResult parseResult)
            {
                parseResult.InvocationConfiguration.Output.WriteLine(Version);
                return ExitCodes.Success;
            }
        }
    }
}
