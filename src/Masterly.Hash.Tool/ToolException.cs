using System;

namespace Masterly.Hash.Tool
{
    /// <summary>
    /// A user-facing error: the message is printed as <c>error: ...</c> and the process exits with
    /// <see cref="ExitCode"/>. Messages never contain passwords or keys.
    /// </summary>
    internal sealed class ToolException : Exception
    {
        public ToolException(string message, int exitCode = ExitCodes.Error)
            : base(message)
        {
            ExitCode = exitCode;
        }

        public int ExitCode { get; }
    }
}
