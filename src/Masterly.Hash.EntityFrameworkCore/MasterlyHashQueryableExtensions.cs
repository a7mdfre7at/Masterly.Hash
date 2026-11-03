using System;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
using Masterly.Hash.BlindIndex;
using Masterly.Hash.EntityFrameworkCore.Internal;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Metadata;

namespace Masterly.Hash.EntityFrameworkCore
{
    /// <summary>Blind-index equality lookups that stay correct during key rotation.</summary>
    /// <remarks>
    /// The value is indexed under every key in the ring (<see cref="IBlindIndexer.ComputeAll"/>) and the query becomes
    /// <c>WHERE idx = @p0 OR idx = @p1 ...</c>, which is an <c>IN</c> over the candidates: rows written under an older
    /// key are still found. Each candidate is a SQL parameter (no literals in the SQL text, a stable plan cache, and no
    /// dependency on JSON/array support of the provider or SQL Server compatibility level). A blind index can have false
    /// positives by design, so compare the decrypted value of each returned row when that matters.
    /// </remarks>
    public static class MasterlyHashQueryableExtensions
    {
        /// <summary>
        /// Filters to rows whose <paramref name="indexProperty"/> holds the index of <paramref name="value"/> under any
        /// key of <paramref name="indexer"/>. Pass the same <paramref name="options"/> (normalizer, output bits) the index
        /// was written with. An empty value, or one that is empty after normalization, matches nothing.
        /// </summary>
        /// <exception cref="ArgumentException">The index name is invalid or the value cannot be indexed.</exception>
        public static IQueryable<TEntity> WhereBlindIndex<TEntity>(
            this IQueryable<TEntity> source,
            Expression<Func<TEntity, string?>> indexProperty,
            IBlindIndexer indexer,
            string indexName,
            string value,
            BlindIndexOptions? options = null)
        {
            if (source == null) throw new ArgumentNullException(nameof(source));
            if (indexProperty == null) throw new ArgumentNullException(nameof(indexProperty));
            if (indexer == null) throw new ArgumentNullException(nameof(indexer));
            if (indexName == null) throw new ArgumentNullException(nameof(indexName));
            if (value == null) throw new ArgumentNullException(nameof(value));

            IBlindIndexNormalizer normalizer = options?.Normalizer ?? BlindIndexNormalizers.Exact;
            if (value.Length == 0 || normalizer.Normalize(value).Length == 0)
                return source.Where(MatchNothing<TEntity>());
            return source.Where(BuildPredicate(indexProperty, indexer.ComputeAll(value, indexName, options)));
        }

        /// <summary>
        /// Filters to rows whose <paramref name="indexProperty"/> matches <paramref name="value"/>, using the index name,
        /// normalizer and output length configured with <c>HasBlindIndex</c> and the indexer passed to
        /// <c>UseMasterlyHash</c>. An empty value, or one that is empty after normalization, matches nothing (such rows
        /// store null). A value the normalizer rejects (e.g. not an email address) throws <see cref="ArgumentException"/>.
        /// </summary>
        /// <exception cref="InvalidOperationException">No <c>HasBlindIndex</c> writes to the property, or the context has no indexer.</exception>
        public static IQueryable<TEntity> WhereBlindIndex<TEntity>(
            this DbSet<TEntity> source,
            Expression<Func<TEntity, string?>> indexProperty,
            string value)
            where TEntity : class
        {
            if (source == null) throw new ArgumentNullException(nameof(source));
            if (indexProperty == null) throw new ArgumentNullException(nameof(indexProperty));
            if (value == null) throw new ArgumentNullException(nameof(value));

            DbContext context = source.GetService<ICurrentDbContext>().Context;
            IReadOnlyList<string> candidates = Candidates(context, source.EntityType, indexProperty, value);
            return candidates.Count == 0
                ? source.Where(MatchNothing<TEntity>())
                : source.Where(BuildPredicate(indexProperty, candidates));
        }

        /// <summary>
        /// The index of <paramref name="value"/> under every key in the ring (current first), as configured for
        /// <paramref name="indexProperty"/>; empty if the value is empty or empty after normalization. Useful for raw SQL.
        /// </summary>
        /// <exception cref="InvalidOperationException">The entity type is not in the model, no <c>HasBlindIndex</c> writes to the property, or the context has no indexer.</exception>
        public static IReadOnlyList<string> GetBlindIndexCandidates<TEntity>(
            this DbContext context,
            Expression<Func<TEntity, string?>> indexProperty,
            string value)
            where TEntity : class
        {
            if (context == null) throw new ArgumentNullException(nameof(context));
            if (indexProperty == null) throw new ArgumentNullException(nameof(indexProperty));
            if (value == null) throw new ArgumentNullException(nameof(value));

            IEntityType entityType = context.Model.FindEntityType(typeof(TEntity))
                ?? throw new InvalidOperationException($"'{typeof(TEntity).Name}' is not an entity type of this context.");
            return Candidates(context, entityType, indexProperty, value);
        }

        private static IReadOnlyList<string> Candidates<TEntity>(DbContext context, IEntityType entityType, Expression<Func<TEntity, string?>> indexProperty, string value)
        {
            string name = ContextServices.GetPropertyName(indexProperty, nameof(indexProperty));
            MasterlyHashSaveChangesInterceptor interceptor = ContextServices.RequireInterceptor(context);
            BlindIndexMapping mapping = interceptor.FindIndexByTarget(entityType, name)
                ?? throw new InvalidOperationException($"No HasBlindIndex on '{entityType.DisplayName()}' writes to property '{name}'.");
            IBlindIndexer indexer = interceptor.Indexer
                ?? throw new InvalidOperationException("No IBlindIndexer was passed to UseMasterlyHash.");

            if (value.Length == 0 || mapping.Options.Normalizer.Normalize(value).Length == 0)
                return Array.Empty<string>();
            return indexer.ComputeAll(value, mapping.IndexName, mapping.Options);
        }

        private static Expression<Func<TEntity, bool>> MatchNothing<TEntity>() => _ => false;

        internal static Expression<Func<TEntity, bool>> BuildPredicate<TEntity>(Expression<Func<TEntity, string?>> indexProperty, IReadOnlyList<string> candidates)
        {
            Expression? body = null;
            foreach (string candidate in candidates)
            {
                // Member access on a closure-like object, so EF Core sends each candidate as a parameter.
                Expression parameter = Expression.Property(Expression.Constant(new Candidate(candidate)), nameof(Candidate.Value));
                Expression equal = Expression.Equal(indexProperty.Body, parameter);
                body = body == null ? equal : Expression.OrElse(body, equal);
            }
            return Expression.Lambda<Func<TEntity, bool>>(body ?? Expression.Constant(false), indexProperty.Parameters);
        }

        private sealed class Candidate
        {
            public Candidate(string value) => Value = value;

            public string Value { get; }
        }
    }
}
