using System;
using Masterly.Hash.BlindIndex;
using Microsoft.EntityFrameworkCore;

namespace Masterly.Hash.EntityFrameworkCore
{
    /// <summary>Registers <see cref="MasterlyHashSaveChangesInterceptor"/> on a context.</summary>
    public static class MasterlyHashDbContextOptionsBuilderExtensions
    {
        /// <summary>
        /// Adds a <see cref="MasterlyHashSaveChangesInterceptor"/> that hashes <c>IsHashedPassword</c> properties and
        /// maintains <c>HasBlindIndex</c> indexes on save.
        /// </summary>
        /// <param name="optionsBuilder">The options builder.</param>
        /// <param name="hasher">The password hasher, typically the application's singleton.</param>
        /// <param name="indexer">The blind indexer; required only if the model uses <c>HasBlindIndex</c>.</param>
        /// <param name="configure">Optional interceptor settings.</param>
        public static DbContextOptionsBuilder UseMasterlyHash(
            this DbContextOptionsBuilder optionsBuilder,
            IPasswordHasher hasher,
            IBlindIndexer? indexer = null,
            Action<MasterlyHashInterceptorOptions>? configure = null)
        {
            if (optionsBuilder == null) throw new ArgumentNullException(nameof(optionsBuilder));
            if (hasher == null) throw new ArgumentNullException(nameof(hasher));

            var options = new MasterlyHashInterceptorOptions();
            configure?.Invoke(options);
            return optionsBuilder.AddInterceptors(new MasterlyHashSaveChangesInterceptor(hasher, indexer, options));
        }

        /// <inheritdoc cref="UseMasterlyHash(DbContextOptionsBuilder, IPasswordHasher, IBlindIndexer?, Action{MasterlyHashInterceptorOptions}?)"/>
        public static DbContextOptionsBuilder<TContext> UseMasterlyHash<TContext>(
            this DbContextOptionsBuilder<TContext> optionsBuilder,
            IPasswordHasher hasher,
            IBlindIndexer? indexer = null,
            Action<MasterlyHashInterceptorOptions>? configure = null)
            where TContext : DbContext
        {
            UseMasterlyHash((DbContextOptionsBuilder)optionsBuilder, hasher, indexer, configure);
            return optionsBuilder;
        }
    }
}
