using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using Masterly.Hash.BlindIndex;
using Masterly.Hash.EntityFrameworkCore.Internal;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.ChangeTracking;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.EntityFrameworkCore.Metadata;

namespace Masterly.Hash.EntityFrameworkCore
{
    /// <summary>
    /// Hashes <see cref="MasterlyHashPropertyBuilderExtensions.IsHashedPassword{TProperty}"/> properties and computes
    /// <see cref="MasterlyHashPropertyBuilderExtensions.HasBlindIndex{TProperty}"/> indexes just before
    /// <c>SaveChanges</c>/<c>SaveChangesAsync</c> writes to the database.
    /// </summary>
    /// <remarks>
    /// <para>
    /// For every added entity, and every modified entity whose annotated property is modified, the interceptor:
    /// </para>
    /// <list type="bullet">
    /// <item><description>writes the blind index of the source property's current value into the index property
    /// (null when the value is null, empty, or empty after normalization). This also runs when only the index property
    /// is modified, so a value written directly to the index is replaced by the one derived from the source;</description></item>
    /// <item><description>replaces a plaintext password with its hash, in the entity itself, so the plaintext does not
    /// remain in the entity after the save. A value that already is a recognized Masterly hash is left untouched; a value
    /// that looks like a Masterly hash (<c>$mh$</c>) but is not recognized (unknown profile or pepper key) fails the save
    /// rather than being hashed a second time.</description></item>
    /// </list>
    /// <para>
    /// A modified entity cannot tell a re-saved stored value from a new assignment (<c>DbSet.Update</c> on a detached
    /// entity marks every property modified). So when the value of a modified password property is a legacy hash (and
    /// <see cref="MasterlyHashInterceptorOptions.AcceptLegacyHashes"/> is off) or an unrecognized <c>$mh$</c> value, the
    /// interceptor reads the row (<c>GetDatabaseValues</c>). A value equal to the stored one is kept unchanged; otherwise
    /// a legacy-looking value is hashed and an unrecognized <c>$mh$</c> value fails the save. Plaintext and recognized
    /// Masterly hashes never cause this extra query.
    /// </para>
    /// <para>
    /// The synchronous <c>SaveChanges</c> uses <see cref="IPasswordHasher.Hash(string)"/>; the asynchronous one uses
    /// <see cref="IPasswordHasher.HashAsync"/>, which supports remote peppers. Thread-safe; register one instance per
    /// application. Errors never include the value being hashed or indexed.
    /// </para>
    /// </remarks>
    public sealed class MasterlyHashSaveChangesInterceptor : SaveChangesInterceptor
    {
        private const string NativeFormat = "mh";
        private const string NativePrefix = "$mh$";

        private readonly ConditionalWeakTable<IEntityType, EntityPlan> _plans = new ConditionalWeakTable<IEntityType, EntityPlan>();
        private readonly ConditionalWeakTable<IEntityType, EntityPlan>.CreateValueCallback _buildPlan;
        private readonly IReadOnlyDictionary<string, IBlindIndexNormalizer> _normalizers;
        private readonly bool _acceptLegacyHashes;

        /// <summary>Creates the interceptor.</summary>
        /// <param name="hasher">Hashes password properties.</param>
        /// <param name="indexer">Computes blind indexes; required only if the model uses <c>HasBlindIndex</c>.</param>
        /// <param name="options">Optional settings; copied, so later changes have no effect.</param>
        public MasterlyHashSaveChangesInterceptor(IPasswordHasher hasher, IBlindIndexer? indexer = null, MasterlyHashInterceptorOptions? options = null)
        {
            Hasher = hasher ?? throw new ArgumentNullException(nameof(hasher));
            Indexer = indexer;
            options ??= new MasterlyHashInterceptorOptions();
            _acceptLegacyHashes = options.AcceptLegacyHashes;

            var normalizers = new Dictionary<string, IBlindIndexNormalizer>(StringComparer.Ordinal);
            foreach (KeyValuePair<string, IBlindIndexNormalizer> pair in options.Normalizers)
            {
                if (pair.Value == null)
                    throw new ArgumentException($"Normalizer '{pair.Key}' is null.", nameof(options));
                normalizers[pair.Key] = pair.Value;
            }
            _normalizers = normalizers;
            _buildPlan = type => EntityPlan.Build(type, _normalizers);
        }

        /// <summary>The hasher used for password properties (and by <c>VerifyAndUpgradeAsync</c>).</summary>
        public IPasswordHasher Hasher { get; }

        /// <summary>The blind indexer, or null if none was configured.</summary>
        public IBlindIndexer? Indexer { get; }

        /// <inheritdoc />
        public override InterceptionResult<int> SavingChanges(DbContextEventData eventData, InterceptionResult<int> result)
        {
            if (eventData == null) throw new ArgumentNullException(nameof(eventData));
            if (eventData.Context != null)
            {
                foreach (WorkItem item in Collect(eventData.Context))
                {
                    ApplyIndexes(item);
                    PropertyValues? databaseValues = null;
                    bool fetched = false;
                    foreach (IProperty property in item.Plan.Passwords)
                    {
                        PropertyEntry entry = item.Entry.Property(property);
                        ValueKind kind = Classify(item.Entry, entry, out string value);
                        if (kind == ValueKind.Keep)
                            continue;
                        if (kind != ValueKind.Plaintext && item.Entry.State == EntityState.Modified)
                        {
                            if (!fetched)
                            {
                                databaseValues = item.Entry.GetDatabaseValues();
                                fetched = true;
                            }
                            if (IsStoredValue(databaseValues, property, value))
                                continue;
                        }
                        if (kind == ValueKind.UnrecognizedNative)
                            throw Unrecognized(item.Entry, property);
                        entry.CurrentValue = HashOrThrow(item.Entry, property, value);
                    }
                }
            }
            return result;
        }

        /// <inheritdoc />
        public override async ValueTask<InterceptionResult<int>> SavingChangesAsync(DbContextEventData eventData, InterceptionResult<int> result, CancellationToken cancellationToken = default)
        {
            if (eventData == null) throw new ArgumentNullException(nameof(eventData));
            if (eventData.Context != null)
            {
                foreach (WorkItem item in Collect(eventData.Context))
                {
                    ApplyIndexes(item);
                    PropertyValues? databaseValues = null;
                    bool fetched = false;
                    foreach (IProperty property in item.Plan.Passwords)
                    {
                        PropertyEntry entry = item.Entry.Property(property);
                        ValueKind kind = Classify(item.Entry, entry, out string value);
                        if (kind == ValueKind.Keep)
                            continue;
                        if (kind != ValueKind.Plaintext && item.Entry.State == EntityState.Modified)
                        {
                            if (!fetched)
                            {
                                databaseValues = await item.Entry.GetDatabaseValuesAsync(cancellationToken).ConfigureAwait(false);
                                fetched = true;
                            }
                            if (IsStoredValue(databaseValues, property, value))
                                continue;
                        }
                        if (kind == ValueKind.UnrecognizedNative)
                            throw Unrecognized(item.Entry, property);
                        entry.CurrentValue = await HashOrThrowAsync(item.Entry, property, value, cancellationToken).ConfigureAwait(false);
                    }
                }
            }
            return result;
        }

        /// <summary>The resolved blind index whose index property is <paramref name="indexPropertyName"/>, or null.</summary>
        internal BlindIndexMapping? FindIndexByTarget(IEntityType entityType, string indexPropertyName)
        {
            foreach (BlindIndexMapping mapping in GetPlan(entityType).Indexes)
            {
                if (string.Equals(mapping.Index.Name, indexPropertyName, StringComparison.Ordinal))
                    return mapping;
            }
            return null;
        }

        internal EntityPlan GetPlan(IEntityType entityType) =>
            _plans.GetValue(entityType, _buildPlan);

        private List<WorkItem> Collect(DbContext context)
        {
            // Entries() runs DetectChanges when AutoDetectChangesEnabled is on (the default).
            var work = new List<WorkItem>();
            foreach (EntityEntry entry in context.ChangeTracker.Entries())
            {
                if (entry.State != EntityState.Added && entry.State != EntityState.Modified)
                    continue;
                EntityPlan plan = GetPlan(entry.Metadata);
                if (!plan.IsEmpty)
                    work.Add(new WorkItem(entry, plan));
            }
            return work;
        }

        private static bool IsDirty(EntityEntry entry, PropertyEntry property) =>
            entry.State == EntityState.Added || property.IsModified;

        private void ApplyIndexes(WorkItem item)
        {
            foreach (BlindIndexMapping mapping in item.Plan.Indexes)
            {
                // The index is derived data: a direct write to it (mass assignment, a copied row) is replaced by the
                // value computed from the source, so a row can never carry another row's index.
                PropertyEntry source = item.Entry.Property(mapping.Source);
                PropertyEntry target = item.Entry.Property(mapping.Index);
                if (!IsDirty(item.Entry, source) && !target.IsModified)
                    continue;

                string? value = source.CurrentValue as string;
                string? index = null;
                if (!string.IsNullOrEmpty(value))
                {
                    IBlindIndexer indexer = Indexer ?? throw new InvalidOperationException(
                        $"'{item.Entry.Metadata.DisplayName()}.{mapping.Source.Name}' has a blind index but no IBlindIndexer was passed to UseMasterlyHash.");
                    index = ComputeIndex(indexer, mapping, value, item.Entry.Metadata);
                }

                if (!string.Equals(target.CurrentValue as string, index, StringComparison.Ordinal))
                    target.CurrentValue = index;
            }
        }

        private static string? ComputeIndex(IBlindIndexer indexer, BlindIndexMapping mapping, string value, IEntityType entityType)
        {
            try
            {
                string? normalized = mapping.Options.Normalizer.Normalize(value);
                if (string.IsNullOrEmpty(normalized))
                    return null;
                return indexer.Compute(value, mapping.IndexName, mapping.Options);
            }
            catch (ArgumentException ex)
            {
                // The inner message never contains the value (normalizer and indexer contract).
                throw new InvalidOperationException(
                    $"Cannot compute blind index '{mapping.IndexName}' for '{entityType.DisplayName()}.{mapping.Source.Name}'. See the inner exception.", ex);
            }
        }

        private ValueKind Classify(EntityEntry entry, PropertyEntry propertyEntry, out string value)
        {
            value = string.Empty;
            if (!IsDirty(entry, propertyEntry) || propertyEntry.CurrentValue is not string current)
                return ValueKind.Keep;

            value = current;
            HashInfo info = Hasher.Inspect(current);
            if (info.IsRecognized)
            {
                if (string.Equals(info.Format, NativeFormat, StringComparison.Ordinal) || _acceptLegacyHashes)
                    return ValueKind.Keep;
                return ValueKind.LegacyHash;
            }
            return current.StartsWith(NativePrefix, StringComparison.Ordinal) ? ValueKind.UnrecognizedNative : ValueKind.Plaintext;
        }

        // A Modified entry cannot tell a re-saved stored value from a new assignment: DbSet.Update and State = Modified
        // mark every property modified, with originals equal to currents. For values that look like hashes the database
        // decides: the value it already holds is kept, never hashed as if it were a password (which would turn a stored
        // legacy hash into a working password and lock the user out).
        private static bool IsStoredValue(PropertyValues? databaseValues, IProperty property, string value) =>
            databaseValues != null && string.Equals(databaseValues[property] as string, value, StringComparison.Ordinal);

        private static InvalidOperationException Unrecognized(EntityEntry entry, IProperty property) =>
            new InvalidOperationException(
                $"The value of '{entry.Metadata.DisplayName()}.{property.Name}' is a Masterly hash that this hasher does not recognize "
                + "(malformed, or an unregistered profile or pepper key). It was not hashed again; register the profile or pepper key, or assign a plaintext password.");

        private string HashOrThrow(EntityEntry entry, IProperty property, string plaintext)
        {
            try
            {
                return Hasher.Hash(plaintext);
            }
            catch (ArgumentException ex)
            {
                throw HashFailure(entry, property, ex);
            }
        }

        private async ValueTask<string> HashOrThrowAsync(EntityEntry entry, IProperty property, string plaintext, CancellationToken cancellationToken)
        {
            try
            {
                return await Hasher.HashAsync(plaintext, cancellationToken).ConfigureAwait(false);
            }
            catch (ArgumentException ex)
            {
                throw HashFailure(entry, property, ex);
            }
        }

        // The hasher's messages ("Password cannot be empty.", "Password exceeds N bytes.") never contain the password.
        private static InvalidOperationException HashFailure(EntityEntry entry, IProperty property, ArgumentException ex) =>
            new InvalidOperationException($"Cannot hash the value of '{entry.Metadata.DisplayName()}.{property.Name}': {ex.Message}", ex);

        private enum ValueKind
        {
            /// <summary>Not a candidate (unchanged or null), or a hash to store as-is.</summary>
            Keep,

            /// <summary>Plaintext: hash it.</summary>
            Plaintext,

            /// <summary>Recognized by a legacy format while legacy hashes are not accepted.</summary>
            LegacyHash,

            /// <summary>Starts with <c>$mh$</c> but this hasher does not recognize it.</summary>
            UnrecognizedNative,
        }

        private readonly struct WorkItem
        {
            public WorkItem(EntityEntry entry, EntityPlan plan)
            {
                Entry = entry;
                Plan = plan;
            }

            public EntityEntry Entry { get; }

            public EntityPlan Plan { get; }
        }
    }
}
