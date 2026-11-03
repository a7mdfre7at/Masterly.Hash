using System;
using System.Collections.Generic;
using Masterly.Hash.BlindIndex;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata;

namespace Masterly.Hash.EntityFrameworkCore.Internal
{
    /// <summary>A blind index resolved against the model: source, target and options.</summary>
    internal sealed class BlindIndexMapping
    {
        public BlindIndexMapping(IProperty source, IProperty index, string indexName, BlindIndexOptions options)
        {
            Source = source;
            Index = index;
            IndexName = indexName;
            Options = options;
        }

        public IProperty Source { get; }

        public IProperty Index { get; }

        public string IndexName { get; }

        public BlindIndexOptions Options { get; }
    }

    /// <summary>The annotated properties of one entity type, resolved once per model.</summary>
    internal sealed class EntityPlan
    {
        public static readonly EntityPlan Empty = new EntityPlan(Array.Empty<IProperty>(), Array.Empty<BlindIndexMapping>());

        public EntityPlan(IReadOnlyList<IProperty> passwords, IReadOnlyList<BlindIndexMapping> indexes)
        {
            Passwords = passwords;
            Indexes = indexes;
        }

        public IReadOnlyList<IProperty> Passwords { get; }

        public IReadOnlyList<BlindIndexMapping> Indexes { get; }

        public bool IsEmpty => Passwords.Count == 0 && Indexes.Count == 0;

        public static EntityPlan Build(IEntityType entityType, IReadOnlyDictionary<string, IBlindIndexNormalizer> normalizers)
        {
            var passwords = new List<IProperty>();
            var indexes = new List<BlindIndexMapping>();
            foreach (IProperty property in entityType.GetProperties())
            {
                if (property.FindAnnotation(MasterlyHashAnnotationNames.HashedPassword)?.Value is true)
                {
                    RequireString(entityType, property);
                    passwords.Add(property);
                }

                if (property.FindAnnotation(MasterlyHashAnnotationNames.BlindIndexProperty)?.Value is string indexPropertyName)
                    indexes.Add(BuildIndex(entityType, property, indexPropertyName, normalizers));
            }

            var targets = new HashSet<IProperty>();
            foreach (BlindIndexMapping mapping in indexes)
            {
                if (!targets.Add(mapping.Index))
                    throw new InvalidOperationException(
                        $"Two blind indexes on '{entityType.DisplayName()}' write to the same property '{mapping.Index.Name}'.");
                if (passwords.Contains(mapping.Index) || passwords.Contains(mapping.Source))
                    throw new InvalidOperationException(
                        $"Blind index '{mapping.IndexName}' on '{entityType.DisplayName()}' cannot read from or write to a hashed-password property.");
            }

            return passwords.Count == 0 && indexes.Count == 0 ? Empty : new EntityPlan(passwords, indexes);
        }

        private static BlindIndexMapping BuildIndex(IEntityType entityType, IProperty source, string indexPropertyName, IReadOnlyDictionary<string, IBlindIndexNormalizer> normalizers)
        {
            RequireString(entityType, source);
            string indexName = source.FindAnnotation(MasterlyHashAnnotationNames.BlindIndexName)?.Value as string
                ?? throw new InvalidOperationException($"Blind index on '{entityType.DisplayName()}.{source.Name}' has no index name annotation.");
            string normalizerId = source.FindAnnotation(MasterlyHashAnnotationNames.BlindIndexNormalizer)?.Value as string ?? "exact";
            int outputBits = source.FindAnnotation(MasterlyHashAnnotationNames.BlindIndexOutputBits)?.Value is int bits
                ? bits
                : BlindIndexOptions.DefaultOutputBits;

            IProperty index = entityType.FindProperty(indexPropertyName)
                ?? throw new InvalidOperationException(
                    $"Blind index '{indexName}' on '{entityType.DisplayName()}.{source.Name}' targets property '{indexPropertyName}', which does not exist on the entity type.");
            RequireString(entityType, index);
            if (index.IsPrimaryKey())
                throw new InvalidOperationException($"Blind index '{indexName}' cannot be written to the primary key '{entityType.DisplayName()}.{index.Name}'.");

            if (!NormalizerRegistry.TryResolve(normalizerId, normalizers, out IBlindIndexNormalizer normalizer))
                throw new InvalidOperationException(
                    $"Blind index '{indexName}' uses normalizer '{normalizerId}', which is not registered. Add it to MasterlyHashInterceptorOptions.Normalizers.");

            var options = new BlindIndexOptions { OutputBits = outputBits, Normalizer = normalizer };
            return new BlindIndexMapping(source, index, indexName, options);
        }

        private static void RequireString(IEntityType entityType, IProperty property)
        {
            if (property.ClrType != typeof(string))
                throw new InvalidOperationException($"'{entityType.DisplayName()}.{property.Name}' must be a string property.");
        }
    }
}
