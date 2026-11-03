using System;
using System.Collections.Generic;
using System.CommandLine;
using System.Globalization;
using System.IO;
using System.Runtime.ExceptionServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Masterly.Hash.Legacy;
using Masterly.Hash.Primitives;
using Masterly.Hash.Tool.IO;

namespace Masterly.Hash.Tool.Commands
{
    /// <summary>Settings for <see cref="WrapCommand"/>.</summary>
    internal sealed class WrapSettings
    {
        public string Input { get; set; } = string.Empty;
        public string Output { get; set; } = string.Empty;
        /// <summary>1-based column holding the stored hash.</summary>
        public int Column { get; set; }
        public char Delimiter { get; set; } = ',';
        public bool Header { get; set; }
        public V1Algorithm? V1Algorithm { get; set; }
        public string? ProfileId { get; set; }
        public bool WeakOnly { get; set; }
        public bool Force { get; set; }
        public int Parallelism { get; set; } = WrapCommand.DefaultParallelism;
        /// <summary>Pepper key ids known to the application, so peppered Masterly hashes count as already current.</summary>
        public IReadOnlyList<string>? PepperKeyIds { get; set; }
    }

    /// <summary>
    /// <c>wrap &lt;input.csv&gt; &lt;output.csv&gt; --column N [--v1-algorithm SHA512]</c>: onion-wraps legacy hashes in
    /// one CSV column, streaming. Every other byte of the (UTF-8) file is copied unchanged.
    /// </summary>
    internal static class WrapCommand
    {
        public const int MaxParallelism = 64;

        /// <summary>Each Argon2id hash allocates the profile's memory (64 MiB for 2026a), so the default is capped at 8.</summary>
        public static readonly int DefaultParallelism = Math.Max(1, Math.Min(Environment.ProcessorCount, 8));

        private const int ProgressEvery = 10_000;

        /// <summary>
        /// A batch is also cut when its records reach this many characters, so a file of huge records cannot make a
        /// batch of <c>Parallelism * 16</c> records exhaust memory before any hashing starts.
        /// </summary>
        internal const int MaxBatchChars = 4 * 1024 * 1024;

        private const string OutOfMemoryMessage = "Out of memory while hashing: each Argon2id hash needs the profile's memory (64 MiB for 2026a). " +
            "Try a lower --parallelism, or --profile 2026c.";

        public static Command Create(ToolEnvironment environment)
        {
            var input = new Argument<string>("input.csv") { Description = "CSV export of the password table." };
            var output = new Argument<string>("output.csv") { Description = "Where to write the CSV with wrapped hashes. Written to a temporary file and renamed on success." };
            var column = new Option<int>("--column")
            {
                Description = "1-based column that holds the stored hash.",
                HelpName = "N",
                Required = true,
            };
            Option<string> delimiter = CommandHelpers.DelimiterOption();
            Option<bool> header = CommandHelpers.HeaderOption("The first record is a header row; copy it unchanged.");
            var v1 = new Option<string?>("--v1-algorithm")
            {
                Description = "Digest of Masterly.Hash 1.x hashes in this file. 1.x did not record it, so v1 hashes are only wrapped when it is given.",
                HelpName = "SHA256|SHA384|SHA512",
            };
            v1.AcceptOnlyFromAmong("SHA256", "SHA384", "SHA512");
            Option<string?> profile = CommandHelpers.ProfileOption("Profile for the wrapping hash. Default: 2026a.");
            var weakOnly = new Option<bool>("--weak-only") { Description = "Only wrap weak hashes (unsalted digests, 1.x, phpass, low-cost bcrypt/PBKDF2); copy the rest unchanged." };
            var force = new Option<bool>("--force") { Description = "Overwrite the output file if it exists." };
            var parallelism = new Option<int>("--parallelism")
            {
                Description = "Hashes computed at once. Each Argon2id hash uses the profile's memory (64 MiB for 2026a).",
                DefaultValueFactory = _ => DefaultParallelism,
                HelpName = "N",
            };
            Option<string?> pepperKeyIds = CommandHelpers.PepperKeyIdsOption();

            var command = new Command("wrap", "Onion-wrap legacy hashes in one CSV column (Argon2id over the legacy digest), streaming. Other columns are kept; wrapped hashes verify with the original passwords and upgrade on the next login.")
            {
                input, output, column, delimiter, header, v1, profile, weakOnly, force, parallelism, pepperKeyIds,
            };
            command.SetAction((parse, cancellationToken) => Task.FromResult(Execute(
                environment,
                new WrapSettings
                {
                    Input = parse.GetValue(input) ?? string.Empty,
                    Output = parse.GetValue(output) ?? string.Empty,
                    Column = parse.GetValue(column),
                    Delimiter = CsvFormat.ParseDelimiter(parse.GetValue(delimiter)),
                    Header = parse.GetValue(header),
                    V1Algorithm = ParseV1(parse.GetValue(v1)),
                    ProfileId = parse.GetValue(profile),
                    WeakOnly = parse.GetValue(weakOnly),
                    Force = parse.GetValue(force),
                    Parallelism = parse.GetValue(parallelism),
                    PepperKeyIds = ClassificationPepper.ParseKeyIds(parse.GetValue(pepperKeyIds)),
                },
                cancellationToken)));
            return command;
        }

        public static int Execute(ToolEnvironment environment, WrapSettings settings, CancellationToken cancellationToken)
        {
            if (settings == null) throw new ArgumentNullException(nameof(settings));
            if (settings.Column < 1)
                throw new ToolException("--column is 1-based and must be at least 1.");
            if (settings.Parallelism < 1 || settings.Parallelism > MaxParallelism)
                throw new ToolException("--parallelism must be between 1 and 64.");
            if (!File.Exists(settings.Input))
                throw new ToolException("Input file not found: " + settings.Input);

            string inputPath = Path.GetFullPath(settings.Input);
            string outputPath = Path.GetFullPath(settings.Output);
            if (string.Equals(inputPath, outputPath, StringComparison.OrdinalIgnoreCase))
                throw new ToolException("The output file must differ from the input file.");
            if (File.Exists(outputPath) && !settings.Force)
                throw new ToolException("The output file already exists; pass --force to overwrite it: " + settings.Output);
            if (Directory.Exists(outputPath))
                throw new ToolException("The output path is a directory: " + settings.Output);

            HashProfile? profile = settings.ProfileId == null ? null : CommandHelpers.ResolveProfile(settings.ProfileId);
            // The wrapping hasher has no pepper (the tool never holds one); a second hasher that knows the pepper key
            // ids only classifies, so peppered Masterly hashes are recognized as current rather than skipped.
            Action<PasswordHasherOptions> configure = options =>
            {
                if (profile != null)
                    options.DefaultProfile = profile;
                options.MaxConcurrency = settings.Parallelism;
                if (settings.V1Algorithm.HasValue)
                {
                    // Replace by id: the host's options factory may already have registered its own v1 format.
                    var restricted = new V1LegacyFormat(settings.V1Algorithm.Value);
                    int index = -1;
                    for (int i = 0; i < options.LegacyFormats.Count && index < 0; i++)
                    {
                        if (options.LegacyFormats[i]?.Id == restricted.Id)
                            index = i;
                    }
                    if (index >= 0)
                        options.LegacyFormats[index] = restricted;
                    else
                        options.LegacyFormats.Add(restricted);
                }
            };
            PasswordHasher hasher = CommandHelpers.CreateHasher(environment, configure);
            PasswordHasher classifier = settings.PepperKeyIds == null || settings.PepperKeyIds.Count == 0
                ? hasher
                : CommandHelpers.CreateHasher(environment, options =>
                {
                    configure(options);
                    CommandHelpers.UseClassificationPepper(options, settings.PepperKeyIds);
                });

            string directory = Path.GetDirectoryName(outputPath) ?? ".";
            string tempPath = Path.Combine(directory,
                "." + Path.GetFileName(outputPath) + "." + HexSuffix() + ".tmp");
            var counts = new WrapCounts();
            bool bom = ReadUtf8Bom(inputPath);
            try
            {
                // Strict UTF-8: a lenient decoder would silently turn non-UTF-8 bytes (e.g. a Windows-1252 e-acute) in
                // other columns into U+FFFD, corrupting the table that is meant to be re-imported.
                var encoding = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);
                using (var reader = new StreamReader(inputPath, encoding, detectEncodingFromByteOrderMarks: false, bufferSize: 64 * 1024))
                using (FileStream file = CreatePrivateFile(tempPath))
                using (var writer = new StreamWriter(file, new UTF8Encoding(bom), bufferSize: 64 * 1024))
                {
                    var csv = new CsvRecordReader(reader, settings.Delimiter);
                    try
                    {
                        if (bom)
                            SkipBom(reader);
                        Run(environment, classifier, hasher, settings, csv, writer, counts, cancellationToken);
                    }
                    catch (DecoderFallbackException)
                    {
                        // The exception text quotes the bytes; say only where.
                        throw new ToolException(string.Format(CultureInfo.InvariantCulture,
                            "The input is not valid UTF-8 (the first invalid bytes are at or after line {0}). wrap copies other columns " +
                            "unchanged and will not guess an encoding: convert the file to UTF-8 first (e.g. iconv -f WINDOWS-1252 -t UTF-8).", csv.Line));
                    }
                }
                File.Move(tempPath, outputPath, overwrite: true);
            }
            catch
            {
                TryDelete(tempPath);
                throw;
            }

            Report(environment.Console.Out, counts, settings.Output);
            return ExitCodes.Success;
        }

        private static void Run(
            ToolEnvironment environment, PasswordHasher classifier, PasswordHasher hasher, WrapSettings settings, CsvRecordReader reader,
            TextWriter writer, WrapCounts counts, CancellationToken cancellationToken)
        {
            int index = settings.Column - 1;
            int batchSize = settings.Parallelism * 16;
            var batch = new List<CsvRecord>(batchSize);
            var results = new RowResult[batchSize];
            var parallel = new ParallelOptions { MaxDegreeOfParallelism = settings.Parallelism, CancellationToken = cancellationToken };
            bool first = true;
            long nextProgress = ProgressEvery;

            while (true)
            {
                batch.Clear();
                long batchChars = 0;
                CsvRecord? record;
                while (batch.Count < batchSize && batchChars < MaxBatchChars && (record = reader.Read()) != null)
                {
                    if (first && settings.Header)
                    {
                        // Header rows go straight through; they are not hashes.
                        CsvFormat.Write(writer, record, settings.Delimiter, -1, null);
                        first = false;
                        continue;
                    }
                    first = false;
                    batch.Add(record);
                    batchChars += record.Length;
                }

                if (batch.Count == 0)
                    break;

                ProcessBatch(batch.Count, results, parallel, i => Process(classifier, hasher, batch[i], index, settings.WeakOnly));

                for (int i = 0; i < batch.Count; i++)
                {
                    RowResult result = results[i];
                    counts.Add(result);
                    CsvFormat.Write(writer, batch[i], settings.Delimiter, index, result.Wrapped);
                    results[i] = default;
                }

                if (counts.Rows >= nextProgress)
                {
                    environment.Console.Error.WriteLine("wrap: " + CommandHelpers.Number(counts.Rows) + " rows processed");
                    nextProgress = (counts.Rows / ProgressEvery + 1) * ProgressEvery;
                }
            }
        }

        /// <summary>
        /// Runs <paramref name="process"/> for each index in parallel. Worker exceptions arrive wrapped in an
        /// <see cref="AggregateException"/>; the first is rethrown as itself so the tool's error handling applies, and
        /// running out of memory becomes a clear error.
        /// </summary>
        internal static void ProcessBatch(int count, RowResult[] results, ParallelOptions parallel, Func<int, RowResult> process)
        {
            try
            {
                Parallel.For(0, count, parallel, i => results[i] = process(i));
            }
            catch (AggregateException ex)
            {
                AggregateException flat = ex.Flatten();
                foreach (Exception inner in flat.InnerExceptions)
                {
                    if (inner is OutOfMemoryException)
                        throw new ToolException(OutOfMemoryMessage);
                }
                if (flat.InnerExceptions.Count > 0)
                    ExceptionDispatchInfo.Capture(flat.InnerExceptions[0]).Throw();
                throw;
            }
            catch (OutOfMemoryException)
            {
                throw new ToolException(OutOfMemoryMessage);
            }
        }

        internal static RowResult Process(PasswordHasher hasher, CsvRecord record, int index, bool weakOnly) =>
            Process(hasher, hasher, record, index, weakOnly);

        /// <summary>
        /// Decides what to do with one record: <paramref name="classifier"/> inspects the hash (it may know pepper key
        /// ids), <paramref name="hasher"/> wraps it.
        /// </summary>
        internal static RowResult Process(PasswordHasher classifier, PasswordHasher hasher, CsvRecord record, int index, bool weakOnly)
        {
            if (record.IsBlank)
                return new RowResult(RowOutcome.Blank, null, null);
            if (index >= record.Fields.Count)
                return RowResult.Skip("missing column");

            string value = record.Fields[index].Value.Trim();
            if (value.Length == 0)
                return RowResult.Skip("empty");

            HashInfo info = classifier.Inspect(value);
            if (string.Equals(info.Format, "mh", StringComparison.Ordinal))
            {
                if (info.IsRecognized)
                    return new RowResult(RowOutcome.AlreadyCurrent, null, null);
                if (info.PepperKeyId != null && classifier.Inspect(WithoutPepperKey(value)).IsRecognized)
                    return RowResult.Skip("mh (unknown pepper key; pass --pepper-key-ids)");
                return RowResult.Skip("mh (malformed or unregistered profile)");
            }
            if (!info.IsRecognized)
                return RowResult.Skip("unknown format");
            if (weakOnly && !HashAudit.IsWeak(info.Format, value))
                return RowResult.Skip(info.Format + " (not weak)");
            if (hasher.TryWrap(value, out string wrapped))
                return new RowResult(RowOutcome.Wrapped, info.Format, wrapped);
            return RowResult.Skip(string.Equals(info.Format, "v1", StringComparison.Ordinal)
                ? "v1 (pass --v1-algorithm to wrap 1.x hashes)"
                : info.Format + " (cannot be wrapped)");
        }

        private static void Report(TextWriter output, WrapCounts counts, string outputName)
        {
            output.WriteLine("Rows:            " + CommandHelpers.Number(counts.Rows));
            output.WriteLine("Wrapped:         " + CommandHelpers.Number(counts.Wrapped));
            output.WriteLine("Already current: " + CommandHelpers.Number(counts.AlreadyCurrent));
            output.WriteLine("Skipped:         " + CommandHelpers.Number(counts.Skipped));
            WriteBreakdown(output, "Wrapped by format:", counts.WrappedByFormat);
            WriteBreakdown(output, "Skipped by reason:", counts.SkippedByReason);
            output.WriteLine("Output:          " + outputName);
        }

        private static void WriteBreakdown(TextWriter output, string title, Dictionary<string, long> counts)
        {
            if (counts.Count == 0)
                return;
            output.WriteLine(title);
            var keys = new List<string>(counts.Keys);
            keys.Sort(StringComparer.Ordinal);
            foreach (string key in keys)
                output.WriteLine("  " + key + ": " + CommandHelpers.Number(counts[key]));
        }

        private static V1Algorithm? ParseV1(string? value)
        {
            switch (value)
            {
                case null:
                    return null;
                case "SHA256":
                    return V1Algorithm.SHA256;
                case "SHA384":
                    return V1Algorithm.SHA384;
                case "SHA512":
                    return V1Algorithm.SHA512;
                default:
                    throw new ToolException("--v1-algorithm must be SHA256, SHA384 or SHA512.");
            }
        }

        /// <summary>True if the file starts with a UTF-8 BOM. UTF-16 and UTF-32 files are refused.</summary>
        private static bool ReadUtf8Bom(string path)
        {
            using (FileStream stream = File.OpenRead(path))
            {
                var bytes = new byte[4];
                int read = 0;
                while (read < 4)
                {
                    int n = stream.Read(bytes, read, 4 - read);
                    if (n <= 0)
                        break;
                    read += n;
                }
                bool utf16 = read >= 2 && ((bytes[0] == 0xFF && bytes[1] == 0xFE) || (bytes[0] == 0xFE && bytes[1] == 0xFF));
                bool utf32Be = read == 4 && bytes[0] == 0 && bytes[1] == 0 && bytes[2] == 0xFE && bytes[3] == 0xFF;
                if (utf16 || utf32Be)
                    throw new ToolException("The input is UTF-16 or UTF-32; wrap only reads UTF-8. Convert it first (e.g. iconv -f UTF-16 -t UTF-8).");
                return read >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF;
            }
        }

        /// <summary>Consumes the U+FEFF the BOM decodes to (the writer emits the BOM again).</summary>
        private static void SkipBom(StreamReader reader)
        {
            if (reader.Peek() == 0xFEFF)
                reader.Read();
        }

        /// <summary>
        /// Creates the output file readable and writable by the owner only (0600) on Unix: it holds the whole password
        /// table. On Windows it inherits the directory's ACL, like any new file.
        /// </summary>
        private static FileStream CreatePrivateFile(string path)
        {
            var options = new FileStreamOptions
            {
                Mode = FileMode.CreateNew,
                Access = FileAccess.Write,
                Share = FileShare.None,
            };
            if (!OperatingSystem.IsWindows())
                options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
            return new FileStream(path, options);
        }

        /// <summary>The hash with its <c>,k=ID</c> parameter removed, to tell "unknown pepper key" from "malformed".</summary>
        private static string WithoutPepperKey(string value)
        {
            int start = value.IndexOf(",k=", StringComparison.Ordinal);
            if (start < 0)
                return value;
            int end = start + 3;
            while (end < value.Length && value[end] != ',' && value[end] != '$')
                end++;
            return value.Substring(0, start) + value.Substring(end);
        }

        private static string HexSuffix()
        {
            byte[] bytes = HashPrimitives.RandomBytes(4);
            var sb = new StringBuilder(8);
            foreach (byte b in bytes)
                sb.Append(b.ToString("x2", CultureInfo.InvariantCulture));
            return sb.ToString();
        }

        private static void TryDelete(string path)
        {
            try
            {
                if (File.Exists(path))
                    File.Delete(path);
            }
            catch (IOException)
            {
                // Best effort; the original error matters more.
            }
            catch (UnauthorizedAccessException)
            {
                // Best effort.
            }
        }

        internal enum RowOutcome
        {
            Blank,
            Wrapped,
            AlreadyCurrent,
            Skipped,
        }

        internal readonly struct RowResult
        {
            public RowResult(RowOutcome outcome, string? detail, string? wrapped)
            {
                Outcome = outcome;
                Detail = detail;
                Wrapped = wrapped;
            }

            public RowOutcome Outcome { get; }

            /// <summary>The legacy format of a wrapped row, or why a row was skipped.</summary>
            public string? Detail { get; }

            /// <summary>The wrapped hash, for <see cref="RowOutcome.Wrapped"/>.</summary>
            public string? Wrapped { get; }

            public static RowResult Skip(string reason) => new RowResult(RowOutcome.Skipped, reason, null);
        }

        private sealed class WrapCounts
        {
            public long Rows;
            public long Wrapped;
            public long AlreadyCurrent;
            public long Skipped;
            public readonly Dictionary<string, long> WrappedByFormat = new Dictionary<string, long>(StringComparer.Ordinal);
            public readonly Dictionary<string, long> SkippedByReason = new Dictionary<string, long>(StringComparer.Ordinal);

            public void Add(RowResult result)
            {
                switch (result.Outcome)
                {
                    case RowOutcome.Blank:
                        return;
                    case RowOutcome.Wrapped:
                        Wrapped++;
                        Increment(WrappedByFormat, result.Detail ?? "?");
                        break;
                    case RowOutcome.AlreadyCurrent:
                        AlreadyCurrent++;
                        break;
                    default:
                        Skipped++;
                        Increment(SkippedByReason, result.Detail ?? "?");
                        break;
                }
                Rows++;
            }

            private static void Increment(Dictionary<string, long> counts, string key)
            {
                counts.TryGetValue(key, out long count);
                counts[key] = count + 1;
            }
        }
    }
}
