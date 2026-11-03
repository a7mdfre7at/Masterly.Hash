using System;
using System.Collections.Generic;
using System.Data.Common;
using System.Linq;
using System.Linq.Expressions;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using Masterly.Hash.BlindIndex;
using Masterly.Hash.BlindIndex.Normalizers;
using Masterly.Hash.EntityFrameworkCore.Internal;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Metadata;

// EF's analyzer treats every *.Internal namespace as EF internals; EntityPlan, NormalizerRegistry and ContextServices
// are this package's own internal types.
#pragma warning disable EF1001

namespace Masterly.Hash.EntityFrameworkCore.Tests;

/// <summary>
/// Tests that pin exact behaviour (boundaries, messages, query counts, ConfigureAwait) so that a changed line fails a
/// test. Models are built inside each test (fresh <see cref="ModelBuilder"/> or a keyed context) so that a test never
/// depends on a model another test happened to build first.
/// </summary>
public class MutationTests
{
    private const string Plain = "correct horse battery staple";

    private static readonly byte[] V1Salt = { 9, 8, 7, 6, 5, 4, 3, 2 };

    private readonly PasswordHasher _hasher = TestHashers.Create();

    private static readonly Dictionary<string, IBlindIndexNormalizer> NoOverrides = new(StringComparer.Ordinal);

    // ---- infrastructure ----------------------------------------------------------------------------------------

    /// <summary>An awaitable that never completes synchronously and resumes on the thread pool, ignoring any context.</summary>
    private readonly struct ForceAsync : INotifyCompletion
    {
        public ForceAsync GetAwaiter() => this;

        public bool IsCompleted => false;

        public void OnCompleted(Action continuation) => ThreadPool.QueueUserWorkItem(_ => continuation());

        public void GetResult()
        {
        }
    }

    /// <summary>
    /// Counts continuations of this package's async methods posted to it (what <c>ConfigureAwait(true)</c> does) and
    /// runs every posted continuation on the pool. EF Core's own <c>DbContext.SaveChangesAsync</c> captures the context
    /// once; only continuations whose state machine belongs to Masterly.Hash.EntityFrameworkCore are counted.
    /// </summary>
    private sealed class CountingSynchronizationContext : SynchronizationContext
    {
        private const string LibraryPrefix = "Masterly.Hash.EntityFrameworkCore.MasterlyHash";

        private int _posts;

        public int Posts => Volatile.Read(ref _posts);

        public override void Post(SendOrPostCallback d, object? state)
        {
            if (Describe(d.Target).Contains(LibraryPrefix, StringComparison.Ordinal) || Describe(state).Contains(LibraryPrefix, StringComparison.Ordinal))
                Interlocked.Increment(ref _posts);
            ThreadPool.QueueUserWorkItem(_ => d(state));
        }

        /// <summary>Type names of the object and, one level deep, of its fields and delegate targets.</summary>
        private static string Describe(object? value)
        {
            if (value == null)
                return "";
            var names = new List<string> { value.GetType().FullName ?? "" };
            if (value is Delegate del && del.Target != null)
                names.Add(del.Target.GetType().FullName ?? "");
            foreach (System.Reflection.FieldInfo field in value.GetType().GetFields(System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.NonPublic))
            {
                object? fieldValue = field.GetValue(value);
                if (fieldValue == null)
                    continue;
                names.Add(fieldValue.GetType().FullName ?? "");
                if (fieldValue is Delegate inner && inner.Target != null)
                    names.Add(inner.Target.GetType().FullName ?? "");
            }
            return string.Join("|", names);
        }

        public override SynchronizationContext CreateCopy() => this;
    }

    /// <summary>
    /// Starts <paramref name="action"/> with a <see cref="CountingSynchronizationContext"/> as the current context and
    /// returns its result with the number of continuations that were posted back to that context.
    /// </summary>
    private static async Task<(T Result, int Posts)> RunCapturingPosts<T>(Func<Task<T>> action)
    {
        var context = new CountingSynchronizationContext();
        SynchronizationContext? previous = SynchronizationContext.Current;
        SynchronizationContext.SetSynchronizationContext(context);
        Task<T> task;
        try
        {
            task = action();
        }
        finally
        {
            SynchronizationContext.SetSynchronizationContext(previous);
        }
        T result = await task;
        return (result, context.Posts);
    }

    /// <summary>A hasher that delegates to a real one, counts calls and can make its async methods truly asynchronous.</summary>
    private sealed class ScriptedHasher : IPasswordHasher
    {
        private readonly PasswordHasher _inner;
        private int _calls;
        private int _forced;

        public ScriptedHasher(PasswordHasher inner) => _inner = inner;

        public bool AsyncVerify { get; set; }

        public bool AsyncHash { get; set; }

        /// <summary>Calls to Hash*/Verify* (not Inspect/NeedsRehash).</summary>
        public int Calls => Volatile.Read(ref _calls);

        /// <summary>How many times an async method really completed asynchronously.</summary>
        public int Forced => Volatile.Read(ref _forced);

        public string Hash(string password)
        {
            Interlocked.Increment(ref _calls);
            return _inner.Hash(password);
        }

        public string Hash(string password, HashProfile profile)
        {
            Interlocked.Increment(ref _calls);
            return _inner.Hash(password, profile);
        }

        public PasswordVerificationResult Verify(string password, string storedHash)
        {
            Interlocked.Increment(ref _calls);
            return _inner.Verify(password, storedHash);
        }

        public PasswordVerificationResult VerifyOrDummy(string password, string? storedHash)
        {
            Interlocked.Increment(ref _calls);
            return _inner.VerifyOrDummy(password, storedHash);
        }

        public async ValueTask<string> HashAsync(string password, CancellationToken cancellationToken = default)
        {
            Interlocked.Increment(ref _calls);
            if (AsyncHash)
            {
                await new ForceAsync();
                Interlocked.Increment(ref _forced);
            }
            return _inner.Hash(password);
        }

        public async ValueTask<PasswordVerificationResult> VerifyAsync(string password, string storedHash, CancellationToken cancellationToken = default)
        {
            Interlocked.Increment(ref _calls);
            if (AsyncVerify)
            {
                await new ForceAsync();
                Interlocked.Increment(ref _forced);
            }
            return _inner.Verify(password, storedHash);
        }

        public async ValueTask<PasswordVerificationResult> VerifyOrDummyAsync(string password, string? storedHash, CancellationToken cancellationToken = default)
        {
            Interlocked.Increment(ref _calls);
            if (AsyncVerify)
            {
                await new ForceAsync();
                Interlocked.Increment(ref _forced);
            }
            return _inner.VerifyOrDummy(password, storedHash);
        }

        public bool NeedsRehash(string storedHash) => _inner.NeedsRehash(storedHash);

        public HashInfo Inspect(string storedHash) => _inner.Inspect(storedHash);

        public bool TryWrap(string legacyHash, out string wrappedHash) => _inner.TryWrap(legacyHash, out wrappedHash);
    }

    /// <summary>Records every command and can make async reader executions truly asynchronous.</summary>
    private sealed class CommandRecorder : DbCommandInterceptor
    {
        private readonly List<string> _commands = new();
        private int _forced;

        public bool ForceAsync { get; set; }

        /// <summary>Makes only commands that are not a SELECT (the UPDATE of a save) truly asynchronous.</summary>
        public bool ForceAsyncWrites { get; set; }

        public int Forced => Volatile.Read(ref _forced);

        /// <summary>The synchronization context that was current when a write was forced asynchronous.</summary>
        public SynchronizationContext? WriteContext { get; private set; }

        /// <summary>Text of the commands that <see cref="ForceAsyncWrites"/> made asynchronous.</summary>
        public List<string> ForcedWrites { get; } = new();

        private void NoteForcedWrite(DbCommand command)
        {
            lock (ForcedWrites)
                ForcedWrites.Add(command.CommandText);
            WriteContext = SynchronizationContext.Current;
        }

        public IReadOnlyList<string> Commands
        {
            get
            {
                lock (_commands)
                    return _commands.ToArray();
            }
        }

        public int Selects => Commands.Count(c => c.TrimStart().StartsWith("SELECT", StringComparison.OrdinalIgnoreCase));

        public void Clear()
        {
            lock (_commands)
                _commands.Clear();
        }

        private void Record(DbCommand command)
        {
            lock (_commands)
                _commands.Add(command.CommandText);
        }

        public override InterceptionResult<DbDataReader> ReaderExecuting(DbCommand command, CommandEventData eventData, InterceptionResult<DbDataReader> result)
        {
            Record(command);
            return result;
        }

        public override async ValueTask<InterceptionResult<DbDataReader>> ReaderExecutingAsync(DbCommand command, CommandEventData eventData, InterceptionResult<DbDataReader> result, CancellationToken cancellationToken = default)
        {
            Record(command);
            if (ForceAsync || (ForceAsyncWrites && !IsSelect(command)))
            {
                if (ForceAsyncWrites)
                    NoteForcedWrite(command);
                await new MutationTests.ForceAsync();
                Interlocked.Increment(ref _forced);
            }
            return result;
        }

        private static bool IsSelect(DbCommand command) =>
            command.CommandText.TrimStart().StartsWith("SELECT", StringComparison.OrdinalIgnoreCase);

        public override InterceptionResult<int> NonQueryExecuting(DbCommand command, CommandEventData eventData, InterceptionResult<int> result)
        {
            Record(command);
            return result;
        }

        public override async ValueTask<InterceptionResult<int>> NonQueryExecutingAsync(DbCommand command, CommandEventData eventData, InterceptionResult<int> result, CancellationToken cancellationToken = default)
        {
            Record(command);
            if (ForceAsyncWrites)
            {
                NoteForcedWrite(command);
                await new MutationTests.ForceAsync();
                Interlocked.Increment(ref _forced);
            }
            return result;
        }

        public override InterceptionResult<object> ScalarExecuting(DbCommand command, CommandEventData eventData, InterceptionResult<object> result)
        {
            Record(command);
            return result;
        }

        public override ValueTask<InterceptionResult<object>> ScalarExecutingAsync(DbCommand command, CommandEventData eventData, InterceptionResult<object> result, CancellationToken cancellationToken = default)
        {
            Record(command);
            return new ValueTask<InterceptionResult<object>>(result);
        }
    }

    /// <summary>A context whose model is configured per test; <see cref="Key"/> keeps each model separately cached.</summary>
    public sealed class KeyedContext : DbContext
    {
        private readonly Action<ModelBuilder> _configure;

        public KeyedContext(DbContextOptions<KeyedContext> options, string key, Action<ModelBuilder> configure)
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
            (context.GetType(), (context as KeyedContext)?.Key, designTime);
    }

    private KeyedContext Keyed(SqliteDb db, Action<ModelBuilder> configure, IInterceptor? extra = null, [CallerMemberName] string key = "")
    {
        DbContextOptionsBuilder<KeyedContext> builder = new DbContextOptionsBuilder<KeyedContext>()
            .UseSqlite(db.Connection)
            .UseMasterlyHash(_hasher, TestKeys.Kat())
            .ReplaceService<IModelCacheKeyFactory, KeyedModelCacheKeyFactory>();
        if (extra != null)
            builder.AddInterceptors(extra);
        var context = new KeyedContext(builder.Options, "mutation-" + key, configure);
        context.Database.EnsureCreated();
        return context;
    }

    private static TestDbContext WithInterceptor(SqliteDb db, IInterceptor extra, IPasswordHasher? hasher) =>
        db.Create<TestDbContext>(o => new TestDbContext(new DbContextOptionsBuilder<TestDbContext>(o).AddInterceptors(extra).Options), hasher);

    private int SeedV1(SqliteDb db, string v1)
    {
        using TestDbContext seed = db.Context(_hasher);
        var u = new User { UserName = "alice", PasswordHash = "placeholder-password" };
        seed.Users.Add(u);
        seed.SaveChanges();
        db.Execute("UPDATE Users SET PasswordHash = $h", ("$h", v1));
        return u.Id;
    }

    private static void AssertArgument<TException>(Action action, string paramName, string messageStart)
        where TException : ArgumentException
    {
        TException ex = Assert.Throws<TException>(action);
        Assert.Equal(paramName, ex.ParamName);
        Assert.StartsWith(messageStart, ex.Message, StringComparison.Ordinal);
    }

    // ---- EntityPlan ----------------------------------------------------------------------------------------------

    [Fact]
    public void Plan_is_empty_only_without_passwords_and_indexes()
    {
        var builder = new ModelBuilder();
        builder.Entity<User>(e =>
        {
            e.Property(u => u.PasswordHash).IsHashedPassword();
            e.Property(u => u.Email).HasBlindIndex(nameof(User.EmailIndex), "users.email");
        });
        IReadOnlyEntityType user = builder.Model.FindEntityType(typeof(User))!;
        IProperty password = (IProperty)user.FindProperty(nameof(User.PasswordHash))!;
        IProperty email = (IProperty)user.FindProperty(nameof(User.Email))!;
        IProperty emailIndex = (IProperty)user.FindProperty(nameof(User.EmailIndex))!;
        var mapping = new BlindIndexMapping(email, emailIndex, "users.email", new BlindIndexOptions());

        Assert.True(EntityPlan.Empty.IsEmpty);
        Assert.True(new EntityPlan(Array.Empty<IProperty>(), Array.Empty<BlindIndexMapping>()).IsEmpty);
        Assert.False(new EntityPlan(new[] { password }, Array.Empty<BlindIndexMapping>()).IsEmpty);
        Assert.False(new EntityPlan(Array.Empty<IProperty>(), new[] { mapping }).IsEmpty);
        Assert.False(new EntityPlan(new[] { password }, new[] { mapping }).IsEmpty);
    }

    [Fact]
    public void Plan_of_a_type_without_annotations_is_the_shared_empty_plan()
    {
        using var db = new SqliteDb();
        using OwnedDbContext context = db.Create<OwnedDbContext>(o => new OwnedDbContext(o), _hasher, TestKeys.Kat());
        MasterlyHashSaveChangesInterceptor interceptor = ContextServices.FindInterceptor(context)!;

        EntityPlan member = interceptor.GetPlan(context.Model.FindEntityType(typeof(Member))!);
        Assert.Same(EntityPlan.Empty, member);

        EntityPlan credentials = interceptor.GetPlan(context.Model.FindEntityType(typeof(Credentials))!);
        Assert.NotSame(EntityPlan.Empty, credentials);
        Assert.Equal(nameof(Credentials.PasswordHash), Assert.Single(credentials.Passwords).Name);
        Assert.Equal("members.recovery_email", Assert.Single(credentials.Indexes).IndexName);
    }

    [Fact]
    public void Password_only_entity_is_hashed()
    {
        using var db = new SqliteDb();
        using ConcurrencyDbContext context = db.Create<ConcurrencyDbContext>(o => new ConcurrencyDbContext(o), _hasher);
        MasterlyHashSaveChangesInterceptor interceptor = ContextServices.FindInterceptor(context)!;
        EntityPlan plan = interceptor.GetPlan(context.Model.FindEntityType(typeof(Account))!);
        Assert.False(plan.IsEmpty);
        Assert.Single(plan.Passwords);
        Assert.Empty(plan.Indexes);

        var account = new Account { PasswordHash = Plain };
        context.Accounts.Add(account);
        context.SaveChanges();

        Assert.StartsWith("$mh$p=test$", account.PasswordHash);
        Assert.True(_hasher.Verify(Plain, db.Scalar("SELECT PasswordHash FROM Accounts")!).IsMatch);
    }

    [Fact]
    public void Blind_index_reading_a_non_string_property_is_rejected()
    {
        using var db = new SqliteDb();
        using KeyedContext context = Keyed(db, b => b.Entity<User>().Property(u => u.Id)
            .HasAnnotation(MasterlyHashAnnotationNames.BlindIndexProperty, nameof(User.EmailIndex))
            .HasAnnotation(MasterlyHashAnnotationNames.BlindIndexName, "users.id"));
        context.Add(new User { UserName = "a" });

        var ex = Assert.Throws<InvalidOperationException>(() => context.SaveChanges());
        Assert.Equal("'User.Id' must be a string property.", ex.Message);
        Assert.Empty(db.Column("SELECT UserName FROM \"User\""));
    }

    // ---- NormalizerRegistry --------------------------------------------------------------------------------------

    [Fact]
    public void Phone_normalizer_without_country_code_has_the_plain_phone_id()
    {
        Assert.Equal("phone", NormalizerRegistry.Register(BlindIndexNormalizers.Phone, new object()));
        Assert.Equal("phone", NormalizerRegistry.Register(new PhoneNormalizer(), new object()));
        Assert.Equal("phone:cc=44", NormalizerRegistry.Register(new PhoneNormalizer("44"), new object()));
        Assert.Equal("exact", NormalizerRegistry.Register(BlindIndexNormalizers.Exact, new object()));
        Assert.Equal("email", NormalizerRegistry.Register(BlindIndexNormalizers.Email, new object()));
    }

    [Theory]
    [InlineData("1")]
    [InlineData("9")]
    [InlineData("10")]
    [InlineData("19")]
    [InlineData("90")]
    [InlineData("123")]
    [InlineData("999")]
    public void Country_code_ids_resolve_at_every_digit_and_length_boundary(string code)
    {
        Assert.True(NormalizerRegistry.TryResolve("phone:cc=" + code, NoOverrides, out IBlindIndexNormalizer resolved));
        Assert.Equal(code, Assert.IsType<PhoneNormalizer>(resolved).DefaultCountryCode);
    }

    [Theory]
    [InlineData("1234")]
    [InlineData("0")]
    [InlineData("01")]
    [InlineData("1/")]
    [InlineData("1:")]
    [InlineData("/")]
    [InlineData(":")]
    public void Country_code_ids_outside_the_boundaries_do_not_resolve(string code)
    {
        Assert.False(NormalizerRegistry.TryResolve("phone:cc=" + code, NoOverrides, out IBlindIndexNormalizer fallback));
        Assert.Same(BlindIndexNormalizers.Exact, fallback);
    }

    [Fact]
    public void Null_override_falls_back_to_the_built_in_normalizer()
    {
        var overrides = new Dictionary<string, IBlindIndexNormalizer>(StringComparer.Ordinal) { ["trim"] = null! };

        Assert.True(NormalizerRegistry.TryResolve("trim", overrides, out IBlindIndexNormalizer resolved));
        Assert.Same(BlindIndexNormalizers.Trim, resolved);
    }

    [Fact]
    public void Non_null_override_wins_over_the_built_in_normalizer()
    {
        var overrides = new Dictionary<string, IBlindIndexNormalizer>(StringComparer.Ordinal) { ["trim"] = BlindIndexNormalizers.CaseInsensitive };

        Assert.True(NormalizerRegistry.TryResolve("trim", overrides, out IBlindIndexNormalizer resolved));
        Assert.Same(BlindIndexNormalizers.CaseInsensitive, resolved);
    }

    private sealed class StatefulNormalizer : IBlindIndexNormalizer
    {
        private readonly string _suffix;

        public StatefulNormalizer(string suffix) => _suffix = suffix;

        public string Normalize(string value) => value + _suffix;
    }

    [Fact]
    public void Conflicting_custom_normalizer_message_is_exact()
    {
        object model = new object();
        string id = typeof(StatefulNormalizer).FullName!;
        Assert.Equal(id, NormalizerRegistry.Register(new StatefulNormalizer("a"), model));

        var ex = Assert.Throws<ArgumentException>(() => NormalizerRegistry.Register(new StatefulNormalizer("b"), model));

        Assert.Equal("normalizer", ex.ParamName);
        Assert.StartsWith(
            $"This model already uses another instance of normalizer type '{id}'. Custom normalizers are identified by type, so two "
            + "differently configured instances would share one id. Reuse one instance, use a separate type per configuration, "
            + "or override Equals so that equally configured instances compare equal.",
            ex.Message, StringComparison.Ordinal);
    }

    // ---- ContextServices -----------------------------------------------------------------------------------------

    [Fact]
    public void Invalid_selector_message_is_exact()
    {
        AssertArgument<ArgumentException>(
            () => ContextServices.GetPropertyName((Expression<Func<User, int>>)(u => u.UserName.Length), "selector"),
            "selector",
            "The expression must select a property of the entity, e.g. u => u.EmailIndex.");
    }

    // ---- UseMasterlyHash -----------------------------------------------------------------------------------------

    [Fact]
    public void UseMasterlyHash_rejects_a_null_hasher_before_running_configure()
    {
        bool configured = false;
        var builder = new DbContextOptionsBuilder();

        var ex = Assert.Throws<ArgumentNullException>(() => builder.UseMasterlyHash(null!, null, _ => configured = true));

        Assert.Equal("hasher", ex.ParamName);
        Assert.False(configured);
        Assert.Null(builder.Options.FindExtension<CoreOptionsExtension>()?.Interceptors);
    }

    // ---- property builder extensions -----------------------------------------------------------------------------

    [Fact]
    public void Builder_error_messages_are_exact()
    {
        var entity = new ModelBuilder().Entity<User>();

        AssertArgument<ArgumentException>(() => entity.Property(u => u.Id).IsHashedPassword(),
            "propertyBuilder", "IsHashedPassword requires a string property; 'Id' is Int32.");
        AssertArgument<ArgumentException>(() => entity.Property(u => u.Id).HasBlindIndex("EmailIndex", "users.id"),
            "propertyBuilder", "HasBlindIndex requires a string property; 'Id' is Int32.");
        AssertArgument<ArgumentException>(() => entity.Property(u => u.Email).HasBlindIndex(" ", "users.email"),
            "indexPropertyName", "Index property name cannot be empty.");
        AssertArgument<ArgumentException>(() => entity.Property(u => u.Email).HasBlindIndex("Email", "users.email"),
            "indexPropertyName", "The index property must differ from the source property.");
        AssertArgument<ArgumentException>(() => entity.Property(u => u.Email).HasBlindIndex("EmailIndex", "users email"),
            "indexName", "Index name must match ^[A-Za-z0-9._:/-]{1,128}$.");
        var range = Assert.Throws<ArgumentOutOfRangeException>(() => entity.Property(u => u.Email).HasBlindIndex("EmailIndex", "users.email", outputBits: 12));
        Assert.Equal("outputBits", range.ParamName);
        Assert.Equal(12, range.ActualValue);
        Assert.StartsWith("OutputBits must be a multiple of 8 from 16 to 256.", range.Message, StringComparison.Ordinal);

        entity.Property(u => u.PasswordHash).IsHashedPassword();
        AssertArgument<ArgumentException>(() => entity.Property(u => u.PasswordHash).HasBlindIndex("EmailIndex", "users.pw"),
            "propertyBuilder",
            "Property 'PasswordHash' is a hashed password and cannot be the source of a blind index: an index of a password would allow offline guessing.");

        entity.Property(u => u.Nickname).HasBlindIndex("EmailIndex", "users.nick");
        AssertArgument<ArgumentException>(() => entity.Property(u => u.Nickname).IsHashedPassword(),
            "propertyBuilder",
            "Property 'Nickname' is the source of a blind index and cannot also be a hashed password: an index of a password would allow offline guessing.");
    }

    [Fact]
    public void HasBlindIndex_records_every_annotation_including_output_bits()
    {
        var entity = new ModelBuilder().Entity<User>();
        entity.Property(u => u.Email).HasBlindIndex(nameof(User.EmailIndex), "users.email", BlindIndexNormalizers.Trim, outputBits: 32);
        entity.Property(u => u.Phone).HasBlindIndex(nameof(User.PhoneIndex), "users.phone");

        var email = entity.Metadata.FindProperty(nameof(User.Email))!;
        Assert.Equal(nameof(User.EmailIndex), email[MasterlyHashAnnotationNames.BlindIndexProperty]);
        Assert.Equal("users.email", email[MasterlyHashAnnotationNames.BlindIndexName]);
        Assert.Equal("trim", email[MasterlyHashAnnotationNames.BlindIndexNormalizer]);
        Assert.Equal(32, email[MasterlyHashAnnotationNames.BlindIndexOutputBits]);

        var phone = entity.Metadata.FindProperty(nameof(User.Phone))!;
        Assert.Equal("exact", phone[MasterlyHashAnnotationNames.BlindIndexNormalizer]);
        Assert.Equal(BlindIndexOptions.DefaultOutputBits, phone[MasterlyHashAnnotationNames.BlindIndexOutputBits]);
    }

    [Fact]
    public void Output_bits_reach_the_stored_index()
    {
        BlindIndexer indexer = TestKeys.Kat();
        using var db = new SqliteDb();
        DbContextOptions<KeyedContext> options = new DbContextOptionsBuilder<KeyedContext>()
            .UseSqlite(db.Connection)
            .UseMasterlyHash(_hasher, indexer)
            .ReplaceService<IModelCacheKeyFactory, KeyedModelCacheKeyFactory>()
            .Options;
        using var context = new KeyedContext(options, "mutation-output-bits",
            b => b.Entity<User>().Property(u => u.Email).HasBlindIndex(nameof(User.EmailIndex), "users.email", outputBits: 16));
        context.Database.EnsureCreated();

        var user = new User { UserName = "a", Email = "a@b.c" };
        context.Add(user);
        context.SaveChanges();

        Assert.Equal(indexer.Compute("a@b.c", "users.email", new BlindIndexOptions { OutputBits = 16 }), user.EmailIndex);
        Assert.NotEqual(indexer.Compute("a@b.c", "users.email"), user.EmailIndex);
    }

    [Theory]
    [InlineData("a")]
    [InlineData("A")]
    [InlineData("Z")]
    [InlineData("z")]
    [InlineData("0")]
    [InlineData("9")]
    [InlineData("M")]
    [InlineData("m")]
    [InlineData("5")]
    [InlineData(".")]
    [InlineData("_")]
    [InlineData(":")]
    [InlineData("/")]
    [InlineData("-")]
    [InlineData("AZaz09._:/-")]
    public void Index_name_accepts_every_boundary_character(string name)
    {
        Assert.True(MasterlyHashPropertyBuilderExtensions.IsValidIndexName(name));
    }

    [Theory]
    [InlineData("")]
    [InlineData("@")] // 'A' - 1
    [InlineData("[")] // 'Z' + 1
    [InlineData("`")] // 'a' - 1
    [InlineData("{")] // 'z' + 1
    [InlineData(" ")]
    [InlineData("a b")]
    [InlineData("é")]
    public void Index_name_rejects_characters_outside_the_alphabet(string name)
    {
        Assert.False(MasterlyHashPropertyBuilderExtensions.IsValidIndexName(name));
    }

    [Fact]
    public void Index_name_length_limit_is_inclusive()
    {
        Assert.True(MasterlyHashPropertyBuilderExtensions.IsValidIndexName(new string('a', BlindIndexer.MaxIndexNameLength)));
        Assert.False(MasterlyHashPropertyBuilderExtensions.IsValidIndexName(new string('a', BlindIndexer.MaxIndexNameLength + 1)));
        Assert.True(MasterlyHashPropertyBuilderExtensions.IsValidIndexName("ab"));
    }

    // ---- queries -------------------------------------------------------------------------------------------------

    [Fact]
    public void Explicit_query_checks_arguments_in_order()
    {
        BlindIndexer indexer = TestKeys.Kat();
        IQueryable<User> source = Array.Empty<User>().AsQueryable();

        Assert.Equal("source", Assert.Throws<ArgumentNullException>(() =>
            ((IQueryable<User>)null!).WhereBlindIndex(null!, indexer, "users.email", "x")).ParamName);
        Assert.Equal("source", Assert.Throws<ArgumentNullException>(() =>
            ((IQueryable<User>)null!).WhereBlindIndex(u => u.EmailIndex, indexer, "bad name!", "x")).ParamName);
        Assert.Equal("indexName", Assert.Throws<ArgumentNullException>(() =>
            source.WhereBlindIndex(u => u.EmailIndex, indexer, null!, null!)).ParamName);
        Assert.Equal("indexName", Assert.Throws<ArgumentNullException>(() =>
            source.WhereBlindIndex(u => u.EmailIndex, indexer, null!, "x")).ParamName);
    }

    [Fact]
    public void Explicit_query_applies_the_options_normalizer_to_detect_empty_values()
    {
        BlindIndexer indexer = TestKeys.Kat();
        var options = new BlindIndexOptions { Normalizer = BlindIndexNormalizers.Trim };
        var users = new[]
        {
            new User { UserName = "null-index", EmailIndex = null },
            new User { UserName = "indexed", EmailIndex = indexer.Compute("x", "users.email", options) },
        }.AsQueryable();

        Assert.Empty(users.WhereBlindIndex(u => u.EmailIndex, indexer, "users.email", "   ", options).ToList());
        Assert.Equal("indexed", users.WhereBlindIndex(u => u.EmailIndex, indexer, "users.email", "  x ", options).Single().UserName);
    }

    [Fact]
    public void Model_driven_query_error_messages_are_exact()
    {
        using var db = new SqliteDb();
        using TestDbContext context = db.Context(_hasher, TestKeys.Kat());
        var unmapped = Assert.Throws<InvalidOperationException>(() => context.Users.WhereBlindIndex(u => u.Nickname, "x"));
        Assert.Equal("No HasBlindIndex on 'User' writes to property 'Nickname'.", unmapped.Message);

        using TestDbContext noIndexer = db.Context(_hasher);
        var missing = Assert.Throws<InvalidOperationException>(() => noIndexer.GetBlindIndexCandidates<User>(u => u.EmailIndex, "x"));
        Assert.Equal("No IBlindIndexer was passed to UseMasterlyHash.", missing.Message);
    }

    // ---- interceptor ---------------------------------------------------------------------------------------------

    [Fact]
    public void Unrecognized_hash_message_is_exact()
    {
        using var db = new SqliteDb();
        using TestDbContext context = db.Context(_hasher);
        context.Users.Add(new User { UserName = "alice", PasswordHash = "$mh$garbage" });

        var ex = Assert.Throws<InvalidOperationException>(() => context.SaveChanges());

        Assert.Equal(
            "The value of 'User.PasswordHash' is a Masterly hash that this hasher does not recognize "
            + "(malformed, or an unregistered profile or pepper key). It was not hashed again; register the profile or pepper key, or assign a plaintext password.",
            ex.Message);
    }

    // Plaintext already stored in the row (e.g. imported before the interceptor existed) is hashed when the property
    // is marked modified: only hash-looking values are compared with the database.
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Modified_plaintext_equal_to_the_stored_value_is_still_hashed(bool async)
    {
        const string stored = "a plaintext password from an old import";
        using var db = new SqliteDb();
        using (TestDbContext seed = db.Create<TestDbContext>(o => new TestDbContext(o), hasher: null))
        {
            seed.Users.Add(new User { UserName = "alice", PasswordHash = stored });
            seed.SaveChanges();
        }
        Assert.Equal(stored, db.Scalar("SELECT PasswordHash FROM Users"));

        var recorder = new CommandRecorder();
        await using TestDbContext context = WithInterceptor(db, recorder, _hasher);
        User user = await context.Users.SingleAsync();
        context.Entry(user).Property(u => u.PasswordHash).IsModified = true;
        recorder.Clear();

        if (async)
            await context.SaveChangesAsync();
        else
            context.SaveChanges();

        Assert.True(_hasher.Verify(stored, db.Scalar("SELECT PasswordHash FROM Users")!).IsMatch);
        Assert.Equal(0, recorder.Selects);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Row_is_read_once_per_entity_for_several_legacy_password_properties(bool async)
    {
        string v1a = TestHashers.V1Sha512(Plain, V1Salt);
        string v1b = TestHashers.V1Sha512("another password", V1Salt);
        Action<ModelBuilder> model = b => b.Entity<User>(e =>
        {
            e.Property(u => u.PasswordHash).IsHashedPassword();
            e.Property(u => u.Nickname).IsHashedPassword();
        });

        using var db = new SqliteDb();
        int id;
        using (KeyedContext seed = Keyed(db, model))
        {
            var u = new User { UserName = "alice", PasswordHash = "placeholder-1", Nickname = "placeholder-2" };
            seed.Add(u);
            seed.SaveChanges();
            id = u.Id;
        }
        db.Execute("UPDATE \"User\" SET PasswordHash = $a, Nickname = $b", ("$a", v1a), ("$b", v1b));

        var recorder = new CommandRecorder();
        await using KeyedContext context = Keyed(db, model, recorder);
        context.Update(new User { Id = id, UserName = "alice", PasswordHash = v1a, Nickname = v1b });
        recorder.Clear();

        if (async)
            await context.SaveChangesAsync();
        else
            context.SaveChanges();

        Assert.Equal(1, recorder.Selects);
        Assert.Equal(v1a, db.Scalar("SELECT PasswordHash FROM \"User\""));
        Assert.Equal(v1b, db.Scalar("SELECT Nickname FROM \"User\""));
    }

    [Fact]
    public void Unchanged_entities_are_not_planned()
    {
        // The type's configuration is invalid, but no Added or Modified entity of it is saved, so it is never planned.
        using var db = new SqliteDb();
        using KeyedContext context = Keyed(db, b => b.Entity<User>().Property(u => u.Id)
            .HasAnnotation(MasterlyHashAnnotationNames.HashedPassword, true));
        context.Attach(new User { Id = 1, UserName = "a" });

        Assert.Equal(0, context.SaveChanges());
        Assert.Equal(EntityState.Unchanged, context.Entry(context.ChangeTracker.Entries<User>().Single().Entity).State);
    }

    [Fact]
    public void Deleted_entities_are_not_planned()
    {
        // Deleting an entity of a type whose configuration is invalid works: only Added and Modified entities are planned.
        Action<ModelBuilder> model = b => b.Entity<User>().Property(u => u.Id)
            .HasAnnotation(MasterlyHashAnnotationNames.HashedPassword, true);
        using var db = new SqliteDb();
        using KeyedContext context = Keyed(db, model);
        db.Execute("INSERT INTO \"User\" (Id, UserName) VALUES (7, 'a')");
        context.Attach(new User { Id = 7, UserName = "a" });
        context.Remove(context.ChangeTracker.Entries<User>().Single().Entity);

        Assert.Equal(1, context.SaveChanges());
        Assert.Empty(db.Column("SELECT UserName FROM \"User\""));
    }

    // ---- ConfigureAwait(false) -----------------------------------------------------------------------------------
    // Each test makes exactly one await incomplete while a capturing SynchronizationContext is current, so a
    // ConfigureAwait(true) at that await would post its continuation back to the context.

    [Fact]
    public async Task Async_hashing_in_the_interceptor_does_not_capture_the_context()
    {
        var hasher = new ScriptedHasher(_hasher) { AsyncHash = true };
        using var db = new SqliteDb();
        await using TestDbContext context = db.Context(hasher);
        var user = new User { UserName = "alice", PasswordHash = Plain };
        context.Users.Add(user);

        (int saved, int posts) = await RunCapturingPosts(() => context.SaveChangesAsync());

        Assert.Equal(1, saved);
        Assert.Equal(1, hasher.Forced);
        Assert.Equal(0, posts);
        Assert.True(_hasher.Verify(Plain, db.Scalar("SELECT PasswordHash FROM Users")!).IsMatch);
    }

    [Fact]
    public async Task Async_database_read_in_the_interceptor_does_not_capture_the_context()
    {
        string v1 = TestHashers.V1Sha512(Plain, V1Salt);
        using var db = new SqliteDb();
        int id = SeedV1(db, v1);

        var recorder = new CommandRecorder();
        await using TestDbContext context = WithInterceptor(db, recorder, _hasher);
        context.Users.Update(new User { Id = id, UserName = "alice", PasswordHash = v1 });
        recorder.Clear();
        recorder.ForceAsync = true;

        (int saved, int posts) = await RunCapturingPosts(() => context.SaveChangesAsync());

        Assert.Equal(1, saved);
        Assert.True(recorder.Forced >= 1);
        Assert.Equal(1, recorder.Selects);
        Assert.Equal(0, posts);
        Assert.Equal(v1, db.Scalar("SELECT PasswordHash FROM Users"));
    }

    [Fact]
    public async Task Async_verification_in_upgrade_does_not_capture_the_context()
    {
        using var db = new SqliteDb();
        SeedV1(db, _hasher.Hash(Plain));
        var hasher = new ScriptedHasher(_hasher) { AsyncVerify = true };

        await using TestDbContext context = db.Create<TestDbContext>(o => new TestDbContext(o), hasher: null);
        User user = await context.Users.SingleAsync();

        (PasswordVerificationResult result, int posts) = await RunCapturingPosts(() => context.VerifyAndUpgradeAsync(hasher, user, u => u.PasswordHash, Plain));

        Assert.Equal(VerificationStatus.Success, result.Status);
        Assert.Equal(1, hasher.Forced);
        Assert.Equal(0, posts);
    }

    [Fact]
    public async Task Async_rehash_in_upgrade_does_not_capture_the_context()
    {
        string v1 = TestHashers.V1Sha512(Plain, V1Salt);
        using var db = new SqliteDb();
        SeedV1(db, v1);
        var hasher = new ScriptedHasher(TestHashers.Create(o => o.ComputeRehashOnVerify = false)) { AsyncHash = true };

        await using TestDbContext context = db.Create<TestDbContext>(o => new TestDbContext(o), hasher: null);
        User user = await context.Users.SingleAsync();

        (PasswordVerificationResult result, int posts) = await RunCapturingPosts(() => context.VerifyAndUpgradeAsync(hasher, user, u => u.PasswordHash, Plain));

        Assert.True(result.NeedsRehash);
        Assert.Null(result.Rehash);
        Assert.Equal(1, hasher.Forced);
        Assert.Equal(0, posts);
        Assert.True(_hasher.Verify(Plain, db.Scalar("SELECT PasswordHash FROM Users")!).IsMatch);
    }

    [Fact]
    public async Task Async_database_read_in_upgrade_does_not_capture_the_context()
    {
        string v1 = TestHashers.V1Sha512(Plain, V1Salt);
        using var db = new SqliteDb();
        SeedV1(db, v1);
        var hasher = new ScriptedHasher(_hasher);

        var recorder = new CommandRecorder();
        await using TestDbContext context = WithInterceptor(db, recorder, hasher: null);
        User user = await context.Users.SingleAsync();
        recorder.Clear();
        recorder.ForceAsync = true;

        (PasswordVerificationResult result, int posts) = await RunCapturingPosts(() => context.VerifyAndUpgradeAsync(hasher, user, u => u.PasswordHash, Plain));

        Assert.True(result.NeedsRehash);
        Assert.NotNull(result.Rehash);
        Assert.Equal(0, hasher.Forced);
        Assert.True(recorder.Forced >= 1);
        Assert.Equal(0, posts);
        Assert.Equal(result.Rehash, db.Scalar("SELECT PasswordHash FROM Users"));
    }

    // The verification, the rehash and the re-read of the stored hash all complete synchronously here; only the
    // UPDATE of SaveChangesAsync is made asynchronous, so a ConfigureAwait(true) on the save would post back.
    [Fact]
    public async Task Async_save_in_upgrade_does_not_capture_the_context()
    {
        string v1 = TestHashers.V1Sha512(Plain, V1Salt);
        using var db = new SqliteDb();
        SeedV1(db, v1);
        var hasher = new ScriptedHasher(_hasher);

        var recorder = new CommandRecorder();
        await using TestDbContext context = WithInterceptor(db, recorder, hasher: null);
        User user = await context.Users.SingleAsync();
        recorder.Clear();
        recorder.ForceAsyncWrites = true;

        (PasswordVerificationResult result, int posts) = await RunCapturingPosts(() => context.VerifyAndUpgradeAsync(hasher, user, u => u.PasswordHash, Plain));

        Assert.True(result.NeedsRehash);
        Assert.NotNull(result.Rehash);
        Assert.Equal(0, hasher.Forced);
        Assert.Equal(1, recorder.Forced);
        Assert.Equal(1, recorder.Selects);
        // The one asynchronous command is the UPDATE of the save, and the counting context was still current when it
        // was issued, so the library's await of SaveChangesAsync is the one that would capture it.
        string write = Assert.Single(recorder.ForcedWrites);
        Assert.StartsWith("UPDATE", write.TrimStart(), StringComparison.OrdinalIgnoreCase);
        Assert.IsType<CountingSynchronizationContext>(recorder.WriteContext);
        Assert.Equal(2, recorder.Commands.Count);
        Assert.Equal(0, posts);
        Assert.Equal(result.Rehash, db.Scalar("SELECT PasswordHash FROM Users"));
        Assert.Equal(result.Rehash, user.PasswordHash);
        Assert.Equal(EntityState.Unchanged, context.Entry(user).State);
    }

    // ---- VerifyAndUpgradeAsync -----------------------------------------------------------------------------------

    [Fact]
    public async Task Upgrade_stores_the_rehash_computed_by_verification()
    {
        string v1 = TestHashers.V1Sha512(Plain, V1Salt);
        using var db = new SqliteDb();
        SeedV1(db, v1);
        var hasher = new ScriptedHasher(_hasher);

        await using TestDbContext context = db.Context(hasher);
        User user = await context.Users.SingleAsync();
        PasswordVerificationResult result = await context.VerifyAndUpgradeAsync(user, u => u.PasswordHash, Plain);

        Assert.NotNull(result.Rehash);
        Assert.Equal(result.Rehash, user.PasswordHash);
        Assert.Equal(result.Rehash, db.Scalar("SELECT PasswordHash FROM Users"));
        // Only the verification ran: the precomputed rehash was used instead of hashing again.
        Assert.Equal(1, hasher.Calls);
    }

    [Fact]
    public async Task Upgrade_of_a_deleted_entity_is_skipped_and_the_row_kept()
    {
        string v1 = TestHashers.V1Sha512(Plain, V1Salt);
        using var db = new SqliteDb();
        SeedV1(db, v1);

        var recorder = new CommandRecorder();
        await using TestDbContext context = WithInterceptor(db, recorder, _hasher);
        User user = await context.Users.SingleAsync();
        context.Users.Remove(user);
        recorder.Clear();

        PasswordVerificationResult result = await context.VerifyAndUpgradeAsync(user, u => u.PasswordHash, Plain);

        Assert.True(result.NeedsRehash);
        Assert.Equal(EntityState.Deleted, context.Entry(user).State);
        Assert.Equal(v1, user.PasswordHash);
        Assert.Empty(recorder.Commands);
        Assert.Equal(v1, db.Scalar("SELECT PasswordHash FROM Users"));
    }

    [Fact]
    public async Task Upgrade_of_an_added_entity_is_skipped_without_querying()
    {
        string v1 = TestHashers.V1Sha512(Plain, V1Salt);
        using var db = new SqliteDb();
        var recorder = new CommandRecorder();
        await using TestDbContext context = WithInterceptor(db, recorder, _hasher);
        var user = new User { UserName = "bob", PasswordHash = v1 };
        context.Users.Add(user);
        recorder.Clear();

        PasswordVerificationResult result = await context.VerifyAndUpgradeAsync(user, u => u.PasswordHash, Plain);

        Assert.True(result.NeedsRehash);
        Assert.Equal(EntityState.Added, context.Entry(user).State);
        Assert.Equal(v1, user.PasswordHash);
        Assert.Empty(recorder.Commands);
    }

    [Fact]
    public async Task Upgrade_validates_arguments_before_touching_the_context_or_hasher()
    {
        using var db = new SqliteDb();
        await using TestDbContext context = db.Context(_hasher);
        var hasher = new ScriptedHasher(_hasher);
        var user = new User { UserName = "alice", PasswordHash = _hasher.Hash(Plain) };

        Assert.Equal("entity", (await Assert.ThrowsAsync<ArgumentNullException>(() =>
            context.VerifyAndUpgradeAsync<User>(hasher, null!, u => u.PasswordHash, Plain))).ParamName);
        Assert.Equal("passwordProperty", (await Assert.ThrowsAsync<ArgumentNullException>(() =>
            context.VerifyAndUpgradeAsync(hasher, user, null!, Plain))).ParamName);
        Assert.Equal("password", (await Assert.ThrowsAsync<ArgumentNullException>(() =>
            context.VerifyAndUpgradeAsync(hasher, user, u => u.PasswordHash, null!))).ParamName);
        Assert.Equal("hasher", (await Assert.ThrowsAsync<ArgumentNullException>(() =>
            context.VerifyAndUpgradeAsync(null!, user, u => u.PasswordHash, Plain))).ParamName);

        Assert.Equal(0, hasher.Calls);
        Assert.Equal(EntityState.Detached, context.Entry(user).State);
    }

    // With several null arguments the first one in declaration order is reported. context.Entry(null) would report
    // "entity" too, so only a call with a later null argument as well shows that the entity guard runs first.
    [Fact]
    public async Task Upgrade_reports_the_first_null_argument_in_declaration_order()
    {
        using var db = new SqliteDb();
        await using TestDbContext context = db.Context(_hasher);
        var hasher = new ScriptedHasher(_hasher);
        var user = new User { UserName = "alice", PasswordHash = _hasher.Hash(Plain) };

        Assert.Equal("entity", (await Assert.ThrowsAsync<ArgumentNullException>(() =>
            context.VerifyAndUpgradeAsync<User>(hasher, null!, null!, Plain))).ParamName);
        Assert.Equal("entity", (await Assert.ThrowsAsync<ArgumentNullException>(() =>
            context.VerifyAndUpgradeAsync<User>(hasher, null!, u => u.PasswordHash, null!))).ParamName);
        Assert.Equal("passwordProperty", (await Assert.ThrowsAsync<ArgumentNullException>(() =>
            context.VerifyAndUpgradeAsync(hasher, user, null!, null!))).ParamName);

        Assert.Equal(0, hasher.Calls);
        Assert.Equal(EntityState.Detached, context.Entry(user).State);
    }

    // An empty value matches nothing through the shared `_ => false` predicate, not through a predicate built from
    // the selector with no candidates (same SQL, but a different expression tree).
    [Fact]
    public void Model_driven_query_for_an_empty_value_uses_the_match_nothing_predicate()
    {
        using var db = new SqliteDb();
        using TestDbContext context = db.Context(_hasher, TestKeys.Kat());
        context.Users.Add(new User { UserName = "no-email" });
        context.SaveChanges();
        Expression<Func<User, string?>> selector = u => u.EmailIndex;

        IQueryable<User> query = context.Users.WhereBlindIndex(selector, "");

        var where = Assert.IsAssignableFrom<MethodCallExpression>(query.Expression);
        Assert.Equal(nameof(Queryable.Where), where.Method.Name);
        var predicate = Assert.IsAssignableFrom<LambdaExpression>(Assert.IsAssignableFrom<UnaryExpression>(where.Arguments[1]).Operand);
        Assert.Equal(false, Assert.IsAssignableFrom<ConstantExpression>(predicate.Body).Value);
        ParameterExpression parameter = Assert.Single(predicate.Parameters);
        Assert.NotSame(selector.Parameters[0], parameter);
        Assert.Equal("_", parameter.Name);
        Assert.Empty(query.ToList());
    }
}
