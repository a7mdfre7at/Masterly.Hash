using System;
using System.Linq.Expressions;
using System.Threading;
using System.Threading.Tasks;
using Masterly.Hash.EntityFrameworkCore.Internal;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.ChangeTracking;

namespace Masterly.Hash.EntityFrameworkCore
{
    /// <summary>Login-time helpers that verify a password and transparently upgrade an outdated stored hash.</summary>
    public static class MasterlyHashDbContextExtensions
    {
        /// <summary>
        /// Verifies <paramref name="password"/> against the hash in <paramref name="passwordProperty"/> using the hasher
        /// passed to <c>UseMasterlyHash</c>. If it matches and the hash is outdated (legacy 1.x format, older profile or
        /// pepper key), writes the fresh hash to the property and saves.
        /// </summary>
        /// <inheritdoc cref="VerifyAndUpgradeAsync{TEntity}(DbContext, IPasswordHasher, TEntity, Expression{Func{TEntity, string}}, string, CancellationToken)" path="/param|/returns|/remarks"/>
        /// <exception cref="InvalidOperationException">The context has no <see cref="MasterlyHashSaveChangesInterceptor"/>.</exception>
        public static Task<PasswordVerificationResult> VerifyAndUpgradeAsync<TEntity>(
            this DbContext context,
            TEntity entity,
            Expression<Func<TEntity, string?>> passwordProperty,
            string password,
            CancellationToken cancellationToken = default)
            where TEntity : class
        {
            if (context == null) throw new ArgumentNullException(nameof(context));
            return VerifyAndUpgradeAsync(context, ContextServices.RequireInterceptor(context).Hasher, entity, passwordProperty, password, cancellationToken);
        }

        /// <summary>
        /// Verifies <paramref name="password"/> against the hash in <paramref name="passwordProperty"/>. If it matches and
        /// the hash is outdated, writes the fresh hash (<see cref="PasswordVerificationResult.Rehash"/>) to the property
        /// and saves.
        /// </summary>
        /// <param name="context">The context tracking (or able to attach) <paramref name="entity"/>.</param>
        /// <param name="hasher">The password hasher.</param>
        /// <param name="entity">The user entity, tracked or detached (for example loaded with <c>AsNoTracking</c>).</param>
        /// <param name="passwordProperty">Selects the stored hash, e.g. <c>u =&gt; u.PasswordHash</c>.</param>
        /// <param name="password">The password the user typed.</param>
        /// <param name="cancellationToken">Cancels the verification and the save.</param>
        /// <returns>The verification result. Use <see cref="PasswordVerificationResult.IsMatch"/> to decide the login.</returns>
        /// <remarks>
        /// <para>
        /// A null stored hash is verified against a dummy hash (<see cref="IPasswordHasher.VerifyOrDummyAsync"/>) so the
        /// response time does not reveal accounts without a password. Never throws for a bad stored hash.
        /// </para>
        /// <para>
        /// The upgrade calls <c>SaveChangesAsync</c>, which also saves any other pending changes of the context. It is
        /// skipped when the entity is added or deleted, the password property already has an unsaved change, the row
        /// no longer holds the hash that was verified (re-read just before the save, so a password reset that committed
        /// meanwhile is not overwritten), or the entity is detached and another instance with the same key is tracked.
        /// A detached entity is attached for the save and detached again.
        /// </para>
        /// <para>
        /// The re-read leaves a small window between the read and the <c>UPDATE</c>. Make the password column (or a row
        /// version) a concurrency token to close it. If the save fails with a <see cref="DbUpdateException"/> (including
        /// <see cref="DbUpdateConcurrencyException"/>) that concerns this entity alone, the property is restored and the
        /// result is returned: the login still succeeds and the upgrade is retried next time. Any other failure of
        /// <c>SaveChangesAsync</c> (a connection error, a failing pending change of another entity, cancellation) is
        /// rethrown after the property is restored.
        /// </para>
        /// </remarks>
        public static async Task<PasswordVerificationResult> VerifyAndUpgradeAsync<TEntity>(
            this DbContext context,
            IPasswordHasher hasher,
            TEntity entity,
            Expression<Func<TEntity, string?>> passwordProperty,
            string password,
            CancellationToken cancellationToken = default)
            where TEntity : class
        {
            if (context == null) throw new ArgumentNullException(nameof(context));
            if (hasher == null) throw new ArgumentNullException(nameof(hasher));
            if (entity == null) throw new ArgumentNullException(nameof(entity));
            if (passwordProperty == null) throw new ArgumentNullException(nameof(passwordProperty));
            if (password == null) throw new ArgumentNullException(nameof(password));

            EntityEntry<TEntity> entry = context.Entry(entity);
            PropertyEntry<TEntity, string?> property = entry.Property(passwordProperty);
            string? stored = property.CurrentValue;

            PasswordVerificationResult result = await hasher.VerifyOrDummyAsync(password, stored, cancellationToken).ConfigureAwait(false);
            if (!result.NeedsRehash || stored == null)
                return result;
            if (entry.State == EntityState.Added || entry.State == EntityState.Deleted || property.IsModified)
                return result;

            string rehash = result.Rehash ?? await hasher.HashAsync(password, cancellationToken).ConfigureAwait(false);

            // Re-read the stored hash just before writing: if it changed since the entity was loaded (a password reset
            // committed while the slow verification ran), the upgrade would overwrite it with the old password's hash.
            // This narrows the race to the gap between this read and the UPDATE; a concurrency token closes it.
            PropertyValues? current = await entry.GetDatabaseValuesAsync(cancellationToken).ConfigureAwait(false);
            if (current == null || !string.Equals(current[property.Metadata] as string, stored, StringComparison.Ordinal))
                return result;

            bool wasDetached = entry.State == EntityState.Detached;
            if (wasDetached)
            {
                try
                {
                    entry.State = EntityState.Unchanged;
                }
                catch (InvalidOperationException)
                {
                    // Another instance with the same key is already tracked. The upgrade is opportunistic: skip it
                    // rather than turn a successful login into an exception.
                    if (entry.State != EntityState.Detached)
                        entry.State = EntityState.Detached;
                    return result;
                }
            }
            try
            {
                property.CurrentValue = rehash;
                await context.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (DbUpdateException ex) when (OnlyEntity(ex, entity))
            {
                Restore(property, stored);
            }
            catch
            {
                Restore(property, stored);
                throw;
            }
            finally
            {
                if (wasDetached)
                    entry.State = EntityState.Detached;
            }
            return result;
        }

        private static void Restore(PropertyEntry property, string stored)
        {
            property.CurrentValue = stored;
            property.IsModified = false;
        }

        private static bool OnlyEntity(DbUpdateException ex, object entity)
        {
            if (ex.Entries.Count == 0)
                return false;
            foreach (EntityEntry failed in ex.Entries)
            {
                if (!ReferenceEquals(failed.Entity, entity))
                    return false;
            }
            return true;
        }
    }
}
