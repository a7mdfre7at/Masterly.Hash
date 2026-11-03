using System;
using System.Linq;
using System.Linq.Expressions;
using System.Reflection;
using System.Reflection.Emit;
using System.Threading;
using System.Threading.Tasks;
using Masterly.Hash.BlindIndex;
using Masterly.Hash.EntityFrameworkCore.Internal;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.EntityFrameworkCore.Infrastructure;

// EF's analyzer treats every *.Internal namespace as EF internals; NormalizerRegistry and ContextServices are this
// package's own internal types.
#pragma warning disable EF1001

namespace Masterly.Hash.EntityFrameworkCore.Tests;

/// <summary>Model configuration errors, context wiring and the rarer interceptor and query paths.</summary>
public class CoverageGapTests
{
    private const string Plain = "correct horse battery staple";

    private readonly PasswordHasher _hasher = TestHashers.Create();

    // ---- a context whose model is built by the test -----------------------------------------------------------

    public sealed class Tag
    {
        public string Code { get; set; } = "";

        public string? Name { get; set; }
    }

    /// <summary>A context whose model is configured per test; <see cref="Key"/> keeps each model separately cached.</summary>
    public sealed class ConfigurableContext : DbContext
    {
        private readonly Action<ModelBuilder> _configure;

        public ConfigurableContext(DbContextOptions<ConfigurableContext> options, string key, Action<ModelBuilder> configure)
            : base(options)
        {
            Key = key;
            _configure = configure;
        }

        public string Key { get; }

        protected override void OnModelCreating(ModelBuilder modelBuilder) => _configure(modelBuilder);
    }

    private sealed class KeyedModelCacheKeyFactory : IModelCacheKeyFactory
    {
        public object Create(DbContext context, bool designTime) =>
            (context.GetType(), (context as ConfigurableContext)?.Key, designTime);
    }

    private ConfigurableContext Configure(SqliteDb db, Action<ModelBuilder> configure, IBlindIndexer? indexer = null,
        Action<MasterlyHashInterceptorOptions>? options = null, [System.Runtime.CompilerServices.CallerMemberName] string key = "")
    {
        DbContextOptions<ConfigurableContext> built = new DbContextOptionsBuilder<ConfigurableContext>()
            .UseSqlite(db.Connection)
            .UseMasterlyHash(_hasher, indexer ?? TestKeys.Kat(), options)
            .ReplaceService<IModelCacheKeyFactory, KeyedModelCacheKeyFactory>()
            .Options;
        var context = new ConfigurableContext(built, key, configure);
        context.Database.EnsureCreated();
        return context;
    }

    private static string SaveError(ConfigurableContext context, object entity)
    {
        context.Add(entity);
        return Assert.Throws<InvalidOperationException>(() => context.SaveChanges()).Message;
    }

    // ---- EntityPlan configuration errors ------------------------------------------------------------------------

    [Fact]
    public void Two_blind_indexes_writing_the_same_property_are_rejected()
    {
        using var db = new SqliteDb();
        using ConfigurableContext context = Configure(db, b => b.Entity<User>(e =>
        {
            e.Property(u => u.Email).HasBlindIndex(nameof(User.EmailIndex), "users.email");
            e.Property(u => u.Phone).HasBlindIndex(nameof(User.EmailIndex), "users.phone");
        }));

        Assert.Equal("Two blind indexes on 'User' write to the same property 'EmailIndex'.",
            SaveError(context, new User { UserName = "a", Email = "a@b.c" }));
    }

    [Fact]
    public void Blind_index_writing_to_a_hashed_password_is_rejected()
    {
        using var db = new SqliteDb();
        using ConfigurableContext context = Configure(db, b => b.Entity<User>(e =>
        {
            e.Property(u => u.PasswordHash).IsHashedPassword();
            e.Property(u => u.Email).HasBlindIndex(nameof(User.PasswordHash), "users.email");
        }));

        Assert.Equal("Blind index 'users.email' on 'User' cannot read from or write to a hashed-password property.",
            SaveError(context, new User { UserName = "a", Email = "a@b.c", PasswordHash = Plain }));
        Assert.Empty(db.Column("SELECT PasswordHash FROM \"User\""));
    }

    [Fact]
    public void Blind_index_reading_a_hashed_password_from_raw_annotations_is_rejected()
    {
        // HasBlindIndex refuses this combination; a hand-edited model (e.g. a migration snapshot) must not slip through.
        using var db = new SqliteDb();
        using ConfigurableContext context = Configure(db, b => b.Entity<User>(e =>
            e.Property(u => u.PasswordHash).IsHashedPassword()
                .HasAnnotation(MasterlyHashAnnotationNames.BlindIndexProperty, nameof(User.EmailIndex))
                .HasAnnotation(MasterlyHashAnnotationNames.BlindIndexName, "users.pw")));

        Assert.Equal("Blind index 'users.pw' on 'User' cannot read from or write to a hashed-password property.",
            SaveError(context, new User { UserName = "a", PasswordHash = Plain }));
    }

    [Fact]
    public void Blind_index_writing_to_the_primary_key_is_rejected()
    {
        using var db = new SqliteDb();
        using ConfigurableContext context = Configure(db, b => b.Entity<Tag>(e =>
        {
            e.HasKey(t => t.Code);
            e.Property(t => t.Name).HasBlindIndex(nameof(Tag.Code), "tags.name");
        }));

        Assert.Equal("Blind index 'tags.name' cannot be written to the primary key 'Tag.Code'.",
            SaveError(context, new Tag { Code = "c1", Name = "n" }));
    }

    [Fact]
    public void Unregistered_normalizer_id_is_rejected_unless_mapped_in_options()
    {
        Action<ModelBuilder> model = b => b.Entity<User>().Property(u => u.Email)
            .HasAnnotation(MasterlyHashAnnotationNames.BlindIndexProperty, nameof(User.EmailIndex))
            .HasAnnotation(MasterlyHashAnnotationNames.BlindIndexName, "users.email")
            .HasAnnotation(MasterlyHashAnnotationNames.BlindIndexNormalizer, "no-such-normalizer");

        using (var db = new SqliteDb())
        using (ConfigurableContext context = Configure(db, model, key: "unregistered-normalizer"))
        {
            Assert.Equal("Blind index 'users.email' uses normalizer 'no-such-normalizer', which is not registered. Add it to MasterlyHashInterceptorOptions.Normalizers.",
                SaveError(context, new User { UserName = "a", Email = "a@b.c" }));
        }

        // A null mapping is refused up front rather than treated as "not registered".
        using (var db = new SqliteDb())
        {
            var ex = Assert.Throws<ArgumentException>(() =>
                Configure(db, model, options: o => o.Normalizers["no-such-normalizer"] = null!, key: "unregistered-normalizer"));
            Assert.StartsWith("Normalizer 'no-such-normalizer' is null.", ex.Message);
        }

        BlindIndexer indexer = TestKeys.Kat();
        using (var db = new SqliteDb())
        using (ConfigurableContext context = Configure(db, model, indexer, o => o.Normalizers["no-such-normalizer"] = BlindIndexNormalizers.Trim, key: "unregistered-normalizer"))
        {
            var user = new User { UserName = "a", Email = "  a@b.c " };
            context.Add(user);
            context.SaveChanges();
            Assert.Equal(indexer.Compute("  a@b.c ", "users.email", new BlindIndexOptions { Normalizer = BlindIndexNormalizers.Trim }), user.EmailIndex);
        }
    }

    [Fact]
    public void Raw_annotations_without_normalizer_or_output_bits_use_the_defaults()
    {
        BlindIndexer indexer = TestKeys.Kat();
        using var db = new SqliteDb();
        using ConfigurableContext context = Configure(db, b => b.Entity<User>().Property(u => u.Email)
            .HasAnnotation(MasterlyHashAnnotationNames.BlindIndexProperty, nameof(User.EmailIndex))
            .HasAnnotation(MasterlyHashAnnotationNames.BlindIndexName, "users.email")
            .HasAnnotation(MasterlyHashAnnotationNames.BlindIndexOutputBits, "not-a-number"), indexer);

        var user = new User { UserName = "a", Email = "A@B.c" };
        context.Add(user);
        context.SaveChanges();

        Assert.Equal(indexer.Compute("A@B.c", "users.email"), user.EmailIndex);
    }

    [Fact]
    public void Raw_blind_index_annotation_without_a_name_is_rejected()
    {
        using var db = new SqliteDb();
        using ConfigurableContext context = Configure(db, b => b.Entity<User>().Property(u => u.Email)
            .HasAnnotation(MasterlyHashAnnotationNames.BlindIndexProperty, nameof(User.EmailIndex)));

        Assert.Equal("Blind index on 'User.Email' has no index name annotation.",
            SaveError(context, new User { UserName = "a", Email = "a@b.c" }));
    }

    [Fact]
    public void Hashed_password_annotation_on_a_non_string_property_is_rejected()
    {
        using var db = new SqliteDb();
        using ConfigurableContext context = Configure(db, b => b.Entity<User>().Property(u => u.Id)
            .HasAnnotation(MasterlyHashAnnotationNames.HashedPassword, true));

        Assert.Equal("'User.Id' must be a string property.", SaveError(context, new User { UserName = "a" }));
    }

    [Fact]
    public void Blind_index_targeting_a_non_string_property_is_rejected()
    {
        using var db = new SqliteDb();
        using ConfigurableContext context = Configure(db, b => b.Entity<User>().Property(u => u.Email)
            .HasBlindIndex(nameof(User.Id), "users.email"));

        Assert.Equal("'User.Id' must be a string property.", SaveError(context, new User { UserName = "a", Email = "a@b.c" }));
    }

    // ---- NormalizerRegistry -----------------------------------------------------------------------------------

    [Fact]
    public void Builtin_trim_and_case_insensitive_normalizers_round_trip_by_id()
    {
        object model = new object();

        Assert.Equal("trim", NormalizerRegistry.Register(BlindIndexNormalizers.Trim, model));
        Assert.Equal("case-insensitive", NormalizerRegistry.Register(BlindIndexNormalizers.CaseInsensitive, model));

        var none = new System.Collections.Generic.Dictionary<string, IBlindIndexNormalizer>();
        Assert.True(NormalizerRegistry.TryResolve("trim", none, out IBlindIndexNormalizer trim));
        Assert.Same(BlindIndexNormalizers.Trim, trim);
        Assert.True(NormalizerRegistry.TryResolve("case-insensitive", none, out IBlindIndexNormalizer ci));
        Assert.Same(BlindIndexNormalizers.CaseInsensitive, ci);
    }

    [Fact]
    public void Two_normalizer_types_with_the_same_full_name_conflict_in_one_model()
    {
        // Custom normalizers are identified by full type name; types from two assemblies can share it.
        IBlindIndexNormalizer first = EmitNormalizer("first");
        IBlindIndexNormalizer second = EmitNormalizer("second");
        Assert.Equal(first.GetType().FullName, second.GetType().FullName);
        Assert.NotEqual(first.GetType(), second.GetType());
        object model = new object();

        Assert.Equal("Cov.SameNameNormalizer", NormalizerRegistry.Register(first, model));
        var ex = Assert.Throws<ArgumentException>(() => NormalizerRegistry.Register(second, model));

        Assert.Equal("normalizer", ex.ParamName);
        Assert.Contains("another instance of normalizer type 'Cov.SameNameNormalizer'", ex.Message);
        Assert.Equal("x", first.Normalize("x"));
    }

    /// <summary>A fieldless <c>Cov.SameNameNormalizer</c> (identity normalizer) in a new dynamic assembly.</summary>
    private static IBlindIndexNormalizer EmitNormalizer(string assemblySuffix)
    {
        AssemblyBuilder assembly = AssemblyBuilder.DefineDynamicAssembly(new AssemblyName("CovNormalizers." + assemblySuffix), AssemblyBuilderAccess.Run);
        ModuleBuilder module = assembly.DefineDynamicModule("main");
        TypeBuilder type = module.DefineType("Cov.SameNameNormalizer", TypeAttributes.Public | TypeAttributes.Sealed | TypeAttributes.Class);
        type.AddInterfaceImplementation(typeof(IBlindIndexNormalizer));
        type.DefineDefaultConstructor(MethodAttributes.Public);
        MethodBuilder normalize = type.DefineMethod(nameof(IBlindIndexNormalizer.Normalize),
            MethodAttributes.Public | MethodAttributes.Virtual | MethodAttributes.Final | MethodAttributes.HideBySig | MethodAttributes.NewSlot,
            typeof(string), new[] { typeof(string) });
        ILGenerator il = normalize.GetILGenerator();
        il.Emit(OpCodes.Ldarg_1);
        il.Emit(OpCodes.Ret);
        type.DefineMethodOverride(normalize, typeof(IBlindIndexNormalizer).GetMethod(nameof(IBlindIndexNormalizer.Normalize))!);
        return (IBlindIndexNormalizer)Activator.CreateInstance(type.CreateType())!;
    }

    // ---- ContextServices ------------------------------------------------------------------------------------

    private sealed class NoOpInterceptor : SaveChangesInterceptor
    {
    }

    /// <summary>Fails every save with a <see cref="DbUpdateException"/> that names no entries (e.g. a lost connection).</summary>
    private sealed class FailingSaveInterceptor : SaveChangesInterceptor
    {
        public override InterceptionResult<int> SavingChanges(DbContextEventData eventData, InterceptionResult<int> result) =>
            throw new DbUpdateException("The database is unavailable.");

        public override ValueTask<InterceptionResult<int>> SavingChangesAsync(DbContextEventData eventData, InterceptionResult<int> result, CancellationToken cancellationToken = default) =>
            throw new DbUpdateException("The database is unavailable.");
    }

    [Fact]
    public async Task Context_with_only_other_interceptors_has_no_masterly_interceptor()
    {
        using var db = new SqliteDb();
        TestDbContext context = db.Create<TestDbContext>(o => new TestDbContext(
            new DbContextOptionsBuilder<TestDbContext>(o).AddInterceptors(new NoOpInterceptor()).Options), hasher: null);
        await using (context)
        {
            Assert.Null(ContextServices.FindInterceptor(context));
            var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
                context.VerifyAndUpgradeAsync(new User(), u => u.PasswordHash, Plain));
            Assert.Equal("No MasterlyHashSaveChangesInterceptor is registered on this context. Call UseMasterlyHash when configuring it.", ex.Message);
        }
    }

    private sealed class Holder
    {
        public string Field = "";

        public int Number { get; set; }
    }

    private static T Identity<T>(T value) => value;

    [Fact]
    public void GetPropertyName_unwraps_conversions_and_accepts_fields()
    {
        Assert.Equal("Number", ContextServices.GetPropertyName((Expression<Func<Holder, object>>)(h => h.Number), "p"));
        Assert.Equal("Number", ContextServices.GetPropertyName((Expression<Func<Holder, long>>)(h => checked((long)h.Number)), "p"));
        Assert.Equal("Number", ContextServices.GetPropertyName((Expression<Func<Holder, object>>)(h => (object)(long)h.Number), "p"));
        Assert.Equal("Field", ContextServices.GetPropertyName((Expression<Func<Holder, string>>)(h => h.Field), "p"));
        Assert.Equal("Email", ContextServices.GetPropertyName((Expression<Func<User, string>>)(u => EF.Property<string>(u, "Email")), "p"));
    }

    [Fact]
    public void GetPropertyName_rejects_anything_but_a_direct_property()
    {
        var other = new User();
        string name = "Email";
        LambdaExpression[] invalid =
        {
            (Expression<Func<Holder, int>>)(h => -h.Number),
            (Expression<Func<User, int>>)(u => u.UserName.Length),
            (Expression<Func<User, string>>)(u => string.Empty),
            (Expression<Func<User, string>>)(u => u.UserName.Trim()),
            (Expression<Func<User, string>>)(u => Identity(u.UserName)),
            (Expression<Func<User, string>>)(u => EF.Property<string>(other, "Email")),
            (Expression<Func<User, string>>)(u => EF.Property<string>(u, name)),
        };

        foreach (LambdaExpression selector in invalid)
        {
            var ex = Assert.Throws<ArgumentException>(() => ContextServices.GetPropertyName(selector, "selector"));
            Assert.Equal("selector", ex.ParamName);
        }
    }

    // ---- MasterlyHashDbContextExtensions ----------------------------------------------------------------------

    [Fact]
    public async Task Upgrade_save_failing_without_entries_is_rethrown_and_the_property_restored()
    {
        string v1 = TestHashers.V1Sha512(Plain, new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 });
        using var db = new SqliteDb();
        using (TestDbContext seed = db.Context(_hasher))
        {
            seed.Users.Add(new User { UserName = "alice", PasswordHash = "placeholder-password" });
            seed.SaveChanges();
        }
        db.Execute("UPDATE Users SET PasswordHash = $h", ("$h", v1));

        TestDbContext context = db.Create<TestDbContext>(o => new TestDbContext(
            new DbContextOptionsBuilder<TestDbContext>(o).AddInterceptors(new FailingSaveInterceptor()).Options), _hasher);
        await using (context)
        {
            User user = await context.Users.SingleAsync();

            var ex = await Assert.ThrowsAsync<DbUpdateException>(() => context.VerifyAndUpgradeAsync(user, u => u.PasswordHash, Plain));

            Assert.Equal("The database is unavailable.", ex.Message);
            Assert.Equal(v1, user.PasswordHash);
            Assert.False(context.Entry(user).Property(u => u.PasswordHash).IsModified);
            Assert.Equal(v1, db.Scalar("SELECT PasswordHash FROM Users"));
        }
    }

    [Fact]
    public async Task Explicit_hasher_overload_rejects_a_null_context()
    {
        await Assert.ThrowsAsync<ArgumentNullException>(() =>
            ((DbContext)null!).VerifyAndUpgradeAsync(_hasher, new User(), u => u.PasswordHash, Plain));
    }

    [Fact]
    public void HasBlindIndex_rejects_a_null_builder()
    {
        Assert.Throws<ArgumentNullException>(() => MasterlyHashPropertyBuilderExtensions.HasBlindIndex<string>(null!, "EmailIndex", "users.email"));
    }

    // ---- queries ------------------------------------------------------------------------------------------------

    [Fact]
    public void Query_helpers_reject_null_arguments_and_unknown_entity_types()
    {
        BlindIndexer indexer = TestKeys.Kat();
        using var db = new SqliteDb();
        using TestDbContext context = db.Context(_hasher, indexer);

        Assert.Throws<ArgumentNullException>(() => ((IQueryable<User>)null!).WhereBlindIndex(u => u.EmailIndex, indexer, "users.email", "x"));
        Assert.Throws<ArgumentNullException>(() => ((DbSet<User>)null!).WhereBlindIndex(u => u.EmailIndex, "x"));
        Assert.Throws<ArgumentNullException>(() => context.Users.WhereBlindIndex(null!, "x"));
        Assert.Throws<ArgumentNullException>(() => ((DbContext)null!).GetBlindIndexCandidates<User>(u => u.EmailIndex, "x"));
        Assert.Throws<ArgumentNullException>(() => context.GetBlindIndexCandidates<User>(null!, "x"));
        Assert.Throws<ArgumentNullException>(() => context.GetBlindIndexCandidates<User>(u => u.EmailIndex, null!));

        var ex = Assert.Throws<InvalidOperationException>(() => context.GetBlindIndexCandidates<Tag>(t => t.Name, "x"));
        Assert.Equal("'Tag' is not an entity type of this context.", ex.Message);
    }

    [Fact]
    public void Predicate_without_candidates_matches_nothing()
    {
        Expression<Func<User, bool>> predicate = MasterlyHashQueryableExtensions.BuildPredicate<User>(u => u.EmailIndex, Array.Empty<string>());

        Func<User, bool> compiled = predicate.Compile();
        Assert.False(compiled(new User { EmailIndex = null }));
        Assert.False(compiled(new User { EmailIndex = "anything" }));
    }

    // ---- interceptor --------------------------------------------------------------------------------------------

    [Fact]
    public async Task Async_interceptor_rejects_null_event_data()
    {
        await Assert.ThrowsAsync<ArgumentNullException>(() =>
            new MasterlyHashSaveChangesInterceptor(_hasher).SavingChangesAsync(null!, default).AsTask());
    }

    [Fact]
    public async Task Async_save_of_an_unrecognized_masterly_hash_fails_instead_of_double_hashing()
    {
        using var db = new SqliteDb();
        await using TestDbContext context = db.Context(_hasher);
        var user = new User { UserName = "alice", PasswordHash = "$mh$garbage" };
        context.Users.Add(user);

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => context.SaveChangesAsync());

        Assert.StartsWith("The value of 'User.PasswordHash' is a Masterly hash that this hasher does not recognize", ex.Message);
        Assert.Equal("$mh$garbage", user.PasswordHash);
        Assert.Empty(db.Column("SELECT PasswordHash FROM Users"));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Update_of_a_row_deleted_meanwhile_does_not_treat_the_value_as_stored(bool async)
    {
        // The stored-value check finds no row, so an unrecognized hash is reported instead of being kept.
        using var db = new SqliteDb();
        int id;
        using (TestDbContext seed = db.Context(_hasher))
        {
            var u = new User { UserName = "alice", PasswordHash = Plain };
            seed.Users.Add(u);
            seed.SaveChanges();
            id = u.Id;
        }
        db.Execute("DELETE FROM Users");

        await using TestDbContext context = db.Context(_hasher);
        context.Users.Update(new User { Id = id, UserName = "alice", PasswordHash = "$mh$garbage" });

        InvalidOperationException ex = async
            ? await Assert.ThrowsAsync<InvalidOperationException>(() => context.SaveChangesAsync())
            : Assert.Throws<InvalidOperationException>(() => context.SaveChanges());

        Assert.Contains("does not recognize", ex.Message);
    }
}
