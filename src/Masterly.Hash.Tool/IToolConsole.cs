using System.IO;

namespace Masterly.Hash.Tool
{
    /// <summary>
    /// The terminal the tool talks to. <see cref="SystemConsole"/> is the real one; tests supply a fake so every
    /// command can run in-process.
    /// </summary>
    public interface IToolConsole
    {
        /// <summary>Standard input: piped passwords (<c>--stdin</c>) and <c>audit -</c>.</summary>
        TextReader In { get; }

        /// <summary>Standard output: results only, so they can be piped.</summary>
        TextWriter Out { get; }

        /// <summary>Standard error: prompts, progress, warnings and errors.</summary>
        TextWriter Error { get; }

        /// <summary>True if standard input is a pipe or file rather than a terminal, so no prompt is possible.</summary>
        bool IsInputRedirected { get; }

        /// <summary>
        /// Shows <paramref name="prompt"/> and reads one line without echoing it. Returns null if nothing can be read
        /// (no terminal, end of input or the user cancelled).
        /// </summary>
        string? ReadSecret(string prompt);
    }
}
