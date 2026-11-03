using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.Text;

namespace Masterly.Hash.Legacy
{
    /// <summary>Result of <see cref="HashAudit.Audit"/>. Immutable.</summary>
    public sealed class HashAuditReport
    {
        internal HashAuditReport(
            long total, long recognized, long unknown, long needsRehash, long weak, long wrapped, long duplicates,
            Dictionary<string, long> byFormat, Dictionary<string, long> byProfile, Dictionary<string, long> weakByFormat)
        {
            Total = total;
            Recognized = recognized;
            Unknown = unknown;
            NeedsRehash = needsRehash;
            Weak = weak;
            Wrapped = wrapped;
            Duplicates = duplicates;
            ByFormat = new ReadOnlyDictionary<string, long>(new Dictionary<string, long>(byFormat, StringComparer.Ordinal));
            ByProfile = new ReadOnlyDictionary<string, long>(new Dictionary<string, long>(byProfile, StringComparer.Ordinal));
            WeakByFormat = new ReadOnlyDictionary<string, long>(new Dictionary<string, long>(weakByFormat, StringComparer.Ordinal));
        }

        /// <summary>Number of values audited, including null and empty ones.</summary>
        public long Total { get; }

        /// <summary>Values the hasher can verify.</summary>
        public long Recognized { get; }

        /// <summary>Values the hasher cannot verify: unknown formats, malformed hashes, unregistered profiles or pepper keys.</summary>
        public long Unknown { get; }

        /// <summary>Recognized values that a successful login would replace (legacy, wrapped, outdated profile or pepper key).</summary>
        public long NeedsRehash { get; }

        /// <summary>
        /// Recognized values in a weak format: unsalted MD5/SHA-1/SHA-256/SHA-512, Masterly.Hash 1.x, phpass,
        /// ASP.NET Identity v2, bcrypt below cost 10 and PBKDF2 below 100,000 iterations. Candidates for
        /// <see cref="IPasswordHasher.TryWrap"/>. Onion-wrapped hashes are not weak.
        /// </summary>
        public long Weak { get; }

        /// <summary>Onion-wrapped Masterly hashes (protected, but still upgraded on the next login).</summary>
        public long Wrapped { get; }

        /// <summary>
        /// Non-empty values identical to an earlier value. Salted hashes practically never repeat, so a non-zero
        /// count usually means unsalted digests (same password, same hash) or copied rows.
        /// </summary>
        public long Duplicates { get; }

        /// <summary>
        /// Counts by <see cref="HashInfo.Format"/>: <c>mh</c> for Masterly hashes (including malformed ones), a legacy
        /// format id, or <c>unknown</c>. The counts add up to <see cref="Total"/>.
        /// </summary>
        public IReadOnlyDictionary<string, long> ByFormat { get; }

        /// <summary>Masterly hashes counted by profile id, including ids that are not registered with the hasher.</summary>
        public IReadOnlyDictionary<string, long> ByProfile { get; }

        /// <summary>The <see cref="Weak"/> values counted by format id.</summary>
        public IReadOnlyDictionary<string, long> WeakByFormat { get; }

        /// <summary>Percentage of <see cref="Recognized"/> values.</summary>
        public double RecognizedPercent => Percent(Recognized);

        /// <summary>Percentage of <see cref="Unknown"/> values.</summary>
        public double UnknownPercent => Percent(Unknown);

        /// <summary>Percentage of <see cref="NeedsRehash"/> values.</summary>
        public double NeedsRehashPercent => Percent(NeedsRehash);

        /// <summary>Percentage of <see cref="Weak"/> values.</summary>
        public double WeakPercent => Percent(Weak);

        /// <summary>Percentage of <see cref="Wrapped"/> values.</summary>
        public double WrappedPercent => Percent(Wrapped);

        /// <summary>Percentage of <see cref="Duplicates"/>.</summary>
        public double DuplicatePercent => Percent(Duplicates);

        /// <summary><paramref name="count"/> as a percentage (0..100) of <see cref="Total"/>; 0 for an empty audit.</summary>
        public double Percent(long count) => Total == 0 ? 0 : 100.0 * count / Total;

        /// <summary>A Markdown summary: a totals table, then counts by format and by profile.</summary>
        public string ToMarkdown()
        {
            var sb = new StringBuilder();
            sb.Append("## Password hash audit\n\n");
            sb.Append("| Metric | Count | Share |\n");
            sb.Append("|---|---:|---:|\n");
            Row(sb, "Total", Total);
            Row(sb, "Recognized", Recognized);
            Row(sb, "Unknown", Unknown);
            Row(sb, "Needs rehash", NeedsRehash);
            Row(sb, "Weak", Weak);
            Row(sb, "Onion-wrapped", Wrapped);
            Row(sb, "Duplicates", Duplicates);

            sb.Append("\n### By format\n\n");
            sb.Append("| Format | Count | Share | Weak |\n");
            sb.Append("|---|---:|---:|---:|\n");
            foreach (KeyValuePair<string, long> entry in Sorted(ByFormat))
            {
                WeakByFormat.TryGetValue(entry.Key, out long weak);
                sb.Append("| ").Append(Escape(entry.Key))
                  .Append(" | ").Append(entry.Value.ToString(CultureInfo.InvariantCulture))
                  .Append(" | ").Append(FormatPercent(entry.Value))
                  .Append(" | ").Append(weak.ToString(CultureInfo.InvariantCulture))
                  .Append(" |\n");
            }

            if (ByProfile.Count > 0)
            {
                sb.Append("\n### By profile\n\n");
                sb.Append("| Profile | Count | Share |\n");
                sb.Append("|---|---:|---:|\n");
                foreach (KeyValuePair<string, long> entry in Sorted(ByProfile))
                    Row(sb, entry.Key, entry.Value);
            }

            return sb.ToString();
        }

        /// <inheritdoc />
        public override string ToString() =>
            string.Format(CultureInfo.InvariantCulture,
                "{0} hashes: {1} recognized, {2} unknown, {3} need rehash, {4} weak, {5} duplicates",
                Total, Recognized, Unknown, NeedsRehash, Weak, Duplicates);

        private void Row(StringBuilder sb, string label, long count) =>
            sb.Append("| ").Append(Escape(label))
              .Append(" | ").Append(count.ToString(CultureInfo.InvariantCulture))
              .Append(" | ").Append(FormatPercent(count))
              .Append(" |\n");

        private string FormatPercent(long count) => Percent(count).ToString("0.0", CultureInfo.InvariantCulture) + "%";

        private static List<KeyValuePair<string, long>> Sorted(IReadOnlyDictionary<string, long> counts)
        {
            var list = new List<KeyValuePair<string, long>>(counts);
            list.Sort((a, b) =>
            {
                int byCount = b.Value.CompareTo(a.Value);
                return byCount != 0 ? byCount : string.CompareOrdinal(a.Key, b.Key);
            });
            return list;
        }

        /// <summary>Keeps a cell on one line and inside its column whatever a custom hasher reports as a format.</summary>
        private static string Escape(string value)
        {
            var sb = new StringBuilder(value.Length);
            foreach (char c in value)
            {
                if (c == '|' || c == '\\' || c == '`')
                    sb.Append('\\').Append(c);
                else if (c < 0x20 || c == 0x7F)
                    sb.Append(' ');
                else
                    sb.Append(c);
            }
            return sb.ToString();
        }
    }
}
