using System;
using System.Collections.Generic;
using System.CommandLine;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using Masterly.Hash.Legacy;
using Masterly.Hash.Tool.IO;

namespace Masterly.Hash.Tool.Commands
{
    /// <summary>
    /// <c>audit &lt;file|-&gt; [--column N] [--delimiter ,] [--header] [--format markdown|json]</c>: streams stored
    /// hashes into <see cref="HashAudit"/> and prints the report.
    /// </summary>
    internal static class AuditCommand
    {
        /// <summary>Longest line accepted in one-hash-per-line mode.</summary>
        public const int MaxLineChars = 64 * 1024;

        public static Command Create(ToolEnvironment environment)
        {
            var input = new Argument<string>("file")
            {
                Description = "File with one stored hash per line (or a CSV with --column); '-' reads standard input.",
            };
            var column = new Option<int?>("--column")
            {
                Description = "Read the hash from this 1-based CSV column instead of taking whole lines.",
                HelpName = "N",
            };
            Option<string> delimiter = CommandHelpers.DelimiterOption();
            Option<bool> header = CommandHelpers.HeaderOption("Skip the first line/record (a header row).");
            var format = new Option<string>("--format")
            {
                Description = "Report format.",
                DefaultValueFactory = _ => "markdown",
            };
            format.AcceptOnlyFromAmong("markdown", "json");
            Option<string?> pepperKeyIds = CommandHelpers.PepperKeyIdsOption();

            var command = new Command("audit", "Audit stored hashes (every legacy format is recognized): formats, profiles, weak, needs-rehash and duplicate counts. Reads one hash per line, or one CSV column.")
            {
                input,
                column,
                delimiter,
                header,
                format,
                pepperKeyIds,
            };
            command.SetAction(parse => Execute(
                environment,
                parse.GetValue(input) ?? "-",
                parse.GetValue(column),
                CsvFormat.ParseDelimiter(parse.GetValue(delimiter)),
                parse.GetValue(header),
                parse.GetValue(format) ?? "markdown",
                ClassificationPepper.ParseKeyIds(parse.GetValue(pepperKeyIds))));
            return command;
        }

        public static int Execute(ToolEnvironment environment, string input, int? column, char delimiter, bool header, string format,
            IReadOnlyList<string>? pepperKeyIds = null)
        {
            if (column.HasValue && column.Value < 1)
                throw new ToolException("--column is 1-based and must be at least 1.");

            PasswordHasher hasher = CommandHelpers.CreateHasher(environment, options => CommandHelpers.UseClassificationPepper(options, pepperKeyIds));
            var stats = new SourceStats();
            HashAuditReport report;

            if (input == "-")
            {
                report = HashAudit.Audit(hasher, CountUnknownPepperKeys(hasher, pepperKeyIds, Values(environment.Console.In, column, delimiter, header, stats), stats));
            }
            else
            {
                if (!File.Exists(input))
                    throw new ToolException("Input file not found: " + input);
                using (var reader = new StreamReader(input, Encoding.UTF8, detectEncodingFromByteOrderMarks: true, bufferSize: 64 * 1024))
                    report = HashAudit.Audit(hasher, CountUnknownPepperKeys(hasher, pepperKeyIds, Values(reader, column, delimiter, header, stats), stats));
            }

            if (stats.UnknownPepperKey > 0)
            {
                environment.Console.Error.WriteLine(string.Format(CultureInfo.InvariantCulture,
                    "warning: {0} Masterly hash(es) are peppered with a key id this audit does not know, so they are counted as unknown. " +
                    "Pass --pepper-key-ids (current key first, e.g. k2,k1) to classify them; the keys themselves are not needed.", stats.UnknownPepperKey));
            }

            if (stats.MissingColumn > 0)
            {
                environment.Console.Error.WriteLine(string.Format(CultureInfo.InvariantCulture,
                    "warning: {0} record(s) have no column {1}; they are counted as unknown.", stats.MissingColumn, column));
            }

            environment.Console.Out.Write(string.Equals(format, "json", StringComparison.Ordinal) ? ToJson(report) + "\n" : report.ToMarkdown());
            return ExitCodes.Success;
        }

        private static IEnumerable<string?> Values(TextReader reader, int? column, char delimiter, bool header, SourceStats stats)
        {
            if (column == null)
            {
                bool first = true;
                string? line;
                while ((line = LineReader.ReadLine(reader, MaxLineChars, "A line is longer than 65536 characters; is this the right file?")) != null)
                {
                    if (first && header)
                    {
                        first = false;
                        continue;
                    }
                    first = false;
                    string value = line.Trim();
                    if (value.Length > 0)
                        yield return value;
                }
                yield break;
            }

            int index = column.Value - 1;
            var csv = new CsvRecordReader(reader, delimiter);
            bool firstRecord = true;
            CsvRecord? record;
            while ((record = csv.Read()) != null)
            {
                if (firstRecord && header)
                {
                    firstRecord = false;
                    continue;
                }
                firstRecord = false;
                if (record.IsBlank)
                    continue;
                if (index >= record.Fields.Count)
                {
                    stats.MissingColumn++;
                    yield return null;
                    continue;
                }
                yield return record.Fields[index].Value.Trim();
            }
        }

        /// <summary>Passes values through, counting well-formed Masterly hashes whose pepper key id is not known.</summary>
        private static IEnumerable<string?> CountUnknownPepperKeys(PasswordHasher hasher, IReadOnlyList<string>? pepperKeyIds, IEnumerable<string?> values, SourceStats stats)
        {
            foreach (string? value in values)
            {
                if (value != null && value.StartsWith("$mh$", StringComparison.Ordinal))
                {
                    HashInfo info = hasher.Inspect(value);
                    if (info.PepperKeyId != null && (pepperKeyIds == null || !pepperKeyIds.Contains(info.PepperKeyId)))
                        stats.UnknownPepperKey++;
                }
                yield return value;
            }
        }

        /// <summary>The report as indented JSON. Keys are format and profile ids, never stored hashes.</summary>
        internal static string ToJson(HashAuditReport report)
        {
            using (var stream = new MemoryStream())
            {
                using (var json = new Utf8JsonWriter(stream, new JsonWriterOptions { Indented = true }))
                {
                    json.WriteStartObject();
                    json.WriteNumber("total", report.Total);
                    json.WriteNumber("recognized", report.Recognized);
                    json.WriteNumber("unknown", report.Unknown);
                    json.WriteNumber("needsRehash", report.NeedsRehash);
                    json.WriteNumber("weak", report.Weak);
                    json.WriteNumber("wrapped", report.Wrapped);
                    json.WriteNumber("duplicates", report.Duplicates);
                    json.WriteStartObject("percent");
                    json.WriteNumber("recognized", Math.Round(report.RecognizedPercent, 2));
                    json.WriteNumber("unknown", Math.Round(report.UnknownPercent, 2));
                    json.WriteNumber("needsRehash", Math.Round(report.NeedsRehashPercent, 2));
                    json.WriteNumber("weak", Math.Round(report.WeakPercent, 2));
                    json.WriteNumber("wrapped", Math.Round(report.WrappedPercent, 2));
                    json.WriteNumber("duplicates", Math.Round(report.DuplicatePercent, 2));
                    json.WriteEndObject();
                    WriteCounts(json, "byFormat", report.ByFormat);
                    WriteCounts(json, "byProfile", report.ByProfile);
                    WriteCounts(json, "weakByFormat", report.WeakByFormat);
                    json.WriteEndObject();
                }
                return Encoding.UTF8.GetString(stream.ToArray());
            }
        }

        private static void WriteCounts(Utf8JsonWriter json, string name, IReadOnlyDictionary<string, long> counts)
        {
            var keys = new List<string>(counts.Keys);
            keys.Sort(StringComparer.Ordinal);
            json.WriteStartObject(name);
            foreach (string key in keys)
                json.WriteNumber(key, counts[key]);
            json.WriteEndObject();
        }

        private sealed class SourceStats
        {
            public long MissingColumn;
            public long UnknownPepperKey;
        }
    }
}
