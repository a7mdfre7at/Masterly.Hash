using System;
using Masterly.Hash.BlindIndex;
using Masterly.Hash.EntityFrameworkCore.Internal;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Masterly.Hash.EntityFrameworkCore
{
    /// <summary>Model-building extensions that mark properties for <see cref="MasterlyHashSaveChangesInterceptor"/>.</summary>
    public static class MasterlyHashPropertyBuilderExtensions
    {
        /// <summary>
        /// Marks a string property as a password column. On <c>SaveChanges</c>, the interceptor replaces a plaintext value
        /// with its hash, in the entity itself, whenever the entity is added or this property is modified. Values that
        /// already are hashes the hasher recognizes are left untouched.
        /// </summary>
        /// <remarks>
        /// This is deliberately not a value converter: a converter would leave the plaintext in the entity after
        /// <c>SaveChanges</c> and would also hash query parameters (<c>Where(u =&gt; u.Password == input)</c>), which
        /// can never match a salted hash. Requires <see cref="MasterlyHashDbContextOptionsBuilderExtensions.UseMasterlyHash(Microsoft.EntityFrameworkCore.DbContextOptionsBuilder, IPasswordHasher, IBlindIndexer?, Action{MasterlyHashInterceptorOptions}?)"/>.
        /// </remarks>
        /// <typeparam name="TProperty">Must be <see cref="string"/> (nullable or not).</typeparam>
        /// <exception cref="ArgumentException">The property is not a string, or it is the source of a blind index.</exception>
        public static PropertyBuilder<TProperty> IsHashedPassword<TProperty>(this PropertyBuilder<TProperty> propertyBuilder)
        {
            if (propertyBuilder == null) throw new ArgumentNullException(nameof(propertyBuilder));
            EnsureString<TProperty>(propertyBuilder, nameof(IsHashedPassword));
            if (propertyBuilder.Metadata.FindAnnotation(MasterlyHashAnnotationNames.BlindIndexProperty) != null)
                throw new ArgumentException(
                    $"Property '{propertyBuilder.Metadata.Name}' is the source of a blind index and cannot also be a hashed password: an index of a password would allow offline guessing.",
                    nameof(propertyBuilder));

            propertyBuilder.HasAnnotation(MasterlyHashAnnotationNames.HashedPassword, true);
            return propertyBuilder;
        }

        /// <summary>
        /// Maintains a blind index of this (source) property in another string property of the same entity. On
        /// <c>SaveChanges</c>, whenever the entity is added or this property is modified, the interceptor sets
        /// <paramref name="indexPropertyName"/> to the current-key index of the value, or to null if the value is null
        /// or empty after normalization. Query it with
        /// <see cref="MasterlyHashQueryableExtensions.WhereBlindIndex{TEntity}(Microsoft.EntityFrameworkCore.DbSet{TEntity}, System.Linq.Expressions.Expression{Func{TEntity, string}}, string)"/>.
        /// </summary>
        /// <typeparam name="TProperty">Must be <see cref="string"/> (nullable or not).</typeparam>
        /// <param name="propertyBuilder">The source property, typically an encrypted column (the entity holds plaintext).</param>
        /// <param name="indexPropertyName">The string property that stores the index. Give it a database index.</param>
        /// <param name="indexName">Domain-separation name, e.g. <c>users.email</c>. Never change it for existing data.</param>
        /// <param name="normalizer">Normalizer applied before hashing; defaults to <see cref="BlindIndexNormalizers.Exact"/>.</param>
        /// <param name="outputBits">Index length in bits (multiple of 8 from 16 to 256); see <see cref="BlindIndexOptions.OutputBits"/>.</param>
        /// <remarks>
        /// The model stores only the normalizer's id, so the annotation survives migration snapshots. The built-in
        /// normalizers, including configured <c>EmailNormalizer</c> and <c>PhoneNormalizer</c> instances, get ids that
        /// encode their settings. Any other normalizer is identified by its type's full name: one model cannot use two
        /// differently configured instances of such a type (reuse one instance, or override <c>Equals</c>), and two
        /// models in one process that do so must map the id explicitly in
        /// <see cref="MasterlyHashInterceptorOptions.Normalizers"/>.
        /// </remarks>
        /// <exception cref="ArgumentException">An argument is invalid, the property is not a string, it is a hashed
        /// password, or the model already uses a differently configured instance of the same custom normalizer type.</exception>
        public static PropertyBuilder<TProperty> HasBlindIndex<TProperty>(
            this PropertyBuilder<TProperty> propertyBuilder,
            string indexPropertyName,
            string indexName,
            IBlindIndexNormalizer? normalizer = null,
            int outputBits = BlindIndexOptions.DefaultOutputBits)
        {
            if (propertyBuilder == null) throw new ArgumentNullException(nameof(propertyBuilder));
            if (indexPropertyName == null) throw new ArgumentNullException(nameof(indexPropertyName));
            if (indexName == null) throw new ArgumentNullException(nameof(indexName));
            EnsureString<TProperty>(propertyBuilder, nameof(HasBlindIndex));

            string sourceName = propertyBuilder.Metadata.Name;
            if (indexPropertyName.Trim().Length == 0)
                throw new ArgumentException("Index property name cannot be empty.", nameof(indexPropertyName));
            if (string.Equals(indexPropertyName, sourceName, StringComparison.Ordinal))
                throw new ArgumentException("The index property must differ from the source property.", nameof(indexPropertyName));
            if (!IsValidIndexName(indexName))
                throw new ArgumentException("Index name must match ^[A-Za-z0-9._:/-]{1,128}$.", nameof(indexName));
            if (!BlindIndexOptions.IsValidOutputBits(outputBits))
                throw new ArgumentOutOfRangeException(nameof(outputBits), outputBits, "OutputBits must be a multiple of 8 from 16 to 256.");
            if (propertyBuilder.Metadata.FindAnnotation(MasterlyHashAnnotationNames.HashedPassword)?.Value is true)
                throw new ArgumentException(
                    $"Property '{sourceName}' is a hashed password and cannot be the source of a blind index: an index of a password would allow offline guessing.",
                    nameof(propertyBuilder));

            string normalizerId = NormalizerRegistry.Register(normalizer ?? BlindIndexNormalizers.Exact, propertyBuilder.Metadata.DeclaringType.Model);
            propertyBuilder.HasAnnotation(MasterlyHashAnnotationNames.BlindIndexProperty, indexPropertyName);
            propertyBuilder.HasAnnotation(MasterlyHashAnnotationNames.BlindIndexName, indexName);
            propertyBuilder.HasAnnotation(MasterlyHashAnnotationNames.BlindIndexNormalizer, normalizerId);
            propertyBuilder.HasAnnotation(MasterlyHashAnnotationNames.BlindIndexOutputBits, outputBits);
            return propertyBuilder;
        }

        private static void EnsureString<TProperty>(PropertyBuilder<TProperty> propertyBuilder, string method)
        {
            if (typeof(TProperty) != typeof(string))
                throw new ArgumentException($"{method} requires a string property; '{propertyBuilder.Metadata.Name}' is {typeof(TProperty).Name}.", nameof(propertyBuilder));
        }

        internal static bool IsValidIndexName(string indexName)
        {
            if (indexName.Length < 1 || indexName.Length > BlindIndexer.MaxIndexNameLength)
                return false;
            foreach (char c in indexName)
            {
                bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
                    || c == '.' || c == '_' || c == ':' || c == '/' || c == '-';
                if (!ok)
                    return false;
            }
            return true;
        }
    }
}
