using System;
using System.IO;

namespace Masterly.Hash.Tool.IO
{
    /// <summary>Reads one line with a hard length cap, so a huge input cannot exhaust memory.</summary>
    internal static class LineReader
    {
        /// <summary>
        /// Reads up to the next <c>\n</c> (a trailing <c>\r</c> is removed). Returns null at end of input.
        /// Throws <see cref="ToolException"/> with <paramref name="tooLongMessage"/> if the line exceeds
        /// <paramref name="maxChars"/>. Intermediate buffers are cleared, so this is safe for secrets.
        /// </summary>
        public static string? ReadLine(TextReader reader, int maxChars, string tooLongMessage)
        {
            if (reader == null) throw new ArgumentNullException(nameof(reader));

            char[] buffer = new char[Math.Min(maxChars + 1, 256)];
            int length = 0;
            bool any = false;
            try
            {
                while (true)
                {
                    int c = reader.Read();
                    if (c < 0)
                        break;
                    any = true;
                    if (c == '\n')
                        break;
                    // One extra slot for a trailing '\r', which is removed below.
                    if (length == maxChars + 1)
                        throw new ToolException(tooLongMessage);
                    if (length == buffer.Length)
                    {
                        char[] larger = new char[Math.Min(buffer.Length * 2, maxChars + 1)];
                        Array.Copy(buffer, larger, length);
                        Array.Clear(buffer, 0, buffer.Length);
                        buffer = larger;
                    }
                    buffer[length++] = (char)c;
                }

                if (!any)
                    return null;
                if (length > 0 && buffer[length - 1] == '\r')
                    length--;
                if (length > maxChars)
                    throw new ToolException(tooLongMessage);
                return new string(buffer, 0, length);
            }
            finally
            {
                Array.Clear(buffer, 0, buffer.Length);
            }
        }
    }
}
