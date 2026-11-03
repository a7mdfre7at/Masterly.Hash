using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;

namespace Masterly.Hash.Tool.IO
{
    /// <summary>One CSV field: its unquoted value and the exact text it was read from.</summary>
    internal readonly struct CsvField
    {
        public CsvField(string value, string raw)
        {
            Value = value;
            Raw = raw;
        }

        /// <summary>The value, with quotes removed and doubled quotes collapsed.</summary>
        public string Value { get; }

        /// <summary>The field exactly as it appeared in the input, so untouched columns are written back unchanged.</summary>
        public string Raw { get; }
    }

    /// <summary>One CSV record and the line break that ended it.</summary>
    internal sealed class CsvRecord
    {
        public CsvRecord(List<CsvField> fields, string terminator, long lineNumber, int length = 0)
        {
            Fields = fields;
            Terminator = terminator;
            LineNumber = lineNumber;
            Length = length;
        }

        /// <summary>Characters read for this record (used to bound how much is buffered at once).</summary>
        public int Length { get; }

        public List<CsvField> Fields { get; }

        /// <summary><c>\r\n</c>, <c>\n</c>, <c>\r</c>, or empty for a last line without a line break.</summary>
        public string Terminator { get; }

        /// <summary>1-based line on which the record starts.</summary>
        public long LineNumber { get; }

        /// <summary>True for an empty line.</summary>
        public bool IsBlank => Fields.Count == 1 && Fields[0].Raw.Length == 0;
    }

    /// <summary>
    /// Streaming RFC 4180 reader: quoted fields may contain the delimiter, doubled quotes and line breaks. Lenient
    /// about text after a closing quote. Each record is capped so an unterminated quote cannot exhaust memory.
    /// </summary>
    internal sealed class CsvRecordReader
    {
        /// <summary>Default cap on one record, in characters (1 Mi).</summary>
        public const int DefaultMaxRecordChars = 1024 * 1024;

        private readonly TextReader _reader;
        private readonly char _delimiter;
        private readonly int _maxRecordChars;
        private readonly char[] _buffer = new char[16 * 1024];
        private int _position;
        private int _length;
        private bool _endOfInput;
        private long _line = 1;

        public CsvRecordReader(TextReader reader, char delimiter, int maxRecordChars = DefaultMaxRecordChars)
        {
            _reader = reader ?? throw new ArgumentNullException(nameof(reader));
            if (delimiter == '"' || delimiter == '\r' || delimiter == '\n')
                throw new ArgumentException("The delimiter cannot be a quote or a line break.", nameof(delimiter));
            if (maxRecordChars < 1) throw new ArgumentOutOfRangeException(nameof(maxRecordChars));
            _delimiter = delimiter;
            _maxRecordChars = maxRecordChars;
        }

        /// <summary>1-based line the reader has reached (for error messages).</summary>
        public long Line => _line;

        /// <summary>Reads the next record, or returns null at end of input.</summary>
        public CsvRecord? Read()
        {
            if (Peek() < 0)
                return null;

            long startLine = _line;
            var fields = new List<CsvField>();
            var value = new StringBuilder();
            var raw = new StringBuilder();
            string terminator = string.Empty;
            bool inQuotes = false;
            bool fieldStart = true;
            int consumed = 0;

            while (true)
            {
                int c = Next();
                if (c < 0)
                {
                    if (inQuotes)
                        throw new ToolException(string.Format(CultureInfo.InvariantCulture,
                            "Unterminated quoted field in the record starting on line {0}.", startLine));
                    break;
                }

                if (++consumed > _maxRecordChars)
                    throw new ToolException(string.Format(CultureInfo.InvariantCulture,
                        "The record starting on line {0} is longer than {1} characters (unterminated quote?).", startLine, _maxRecordChars));

                char ch = (char)c;
                if (inQuotes)
                {
                    raw.Append(ch);
                    if (ch == '"')
                    {
                        if (Peek() == '"')
                        {
                            Next();
                            consumed++;
                            raw.Append('"');
                            value.Append('"');
                        }
                        else
                        {
                            inQuotes = false;
                        }
                    }
                    else
                    {
                        if (ch == '\n' || (ch == '\r' && Peek() != '\n'))
                            _line++;
                        value.Append(ch);
                    }
                    continue;
                }

                if (ch == _delimiter)
                {
                    fields.Add(new CsvField(value.ToString(), raw.ToString()));
                    value.Clear();
                    raw.Clear();
                    fieldStart = true;
                    continue;
                }

                if (ch == '\r')
                {
                    if (Peek() == '\n')
                    {
                        Next();
                        terminator = "\r\n";
                    }
                    else
                    {
                        terminator = "\r";
                    }
                    _line++;
                    break;
                }

                if (ch == '\n')
                {
                    terminator = "\n";
                    _line++;
                    break;
                }

                if (ch == '"' && fieldStart)
                {
                    inQuotes = true;
                    fieldStart = false;
                    raw.Append(ch);
                    continue;
                }

                fieldStart = false;
                raw.Append(ch);
                value.Append(ch);
            }

            fields.Add(new CsvField(value.ToString(), raw.ToString()));
            return new CsvRecord(fields, terminator, startLine, consumed);
        }

        private int Peek()
        {
            if (_position == _length)
            {
                if (_endOfInput)
                    return -1;
                _length = _reader.Read(_buffer, 0, _buffer.Length);
                _position = 0;
                if (_length <= 0)
                {
                    _length = 0;
                    _endOfInput = true;
                    return -1;
                }
            }
            return _buffer[_position];
        }

        private int Next()
        {
            int c = Peek();
            if (c >= 0)
                _position++;
            return c;
        }
    }

    /// <summary>CSV writing helpers.</summary>
    internal static class CsvFormat
    {
        /// <summary>Quotes a value if it contains the delimiter, a quote or a line break.</summary>
        public static string Quote(string value, char delimiter)
        {
            bool needsQuotes = false;
            foreach (char c in value)
            {
                if (c == delimiter || c == '"' || c == '\r' || c == '\n')
                {
                    needsQuotes = true;
                    break;
                }
            }
            return needsQuotes ? "\"" + value.Replace("\"", "\"\"") + "\"" : value;
        }

        /// <summary>
        /// Writes a record back exactly as read, except that the field at <paramref name="replaceIndex"/> becomes
        /// <paramref name="replacement"/> (quoted as needed) when it is not null.
        /// </summary>
        public static void Write(TextWriter writer, CsvRecord record, char delimiter, int replaceIndex, string? replacement)
        {
            for (int i = 0; i < record.Fields.Count; i++)
            {
                if (i > 0)
                    writer.Write(delimiter);
                writer.Write(i == replaceIndex && replacement != null ? Quote(replacement, delimiter) : record.Fields[i].Raw);
            }
            writer.Write(record.Terminator);
        }

        /// <summary>
        /// Parses a <c>--delimiter</c> value: one character, or <c>tab</c> / <c>\t</c>. Quotes and line breaks are refused.
        /// </summary>
        public static char ParseDelimiter(string? text)
        {
            if (text == null || text.Length == 0)
                return ',';
            if (text == "\\t" || string.Equals(text, "tab", StringComparison.OrdinalIgnoreCase))
                return '\t';
            if (text.Length != 1)
                throw new ToolException("--delimiter must be a single character (or 'tab').");
            char c = text[0];
            if (c == '"' || c == '\r' || c == '\n')
                throw new ToolException("--delimiter cannot be a quote or a line break.");
            return c;
        }
    }
}
