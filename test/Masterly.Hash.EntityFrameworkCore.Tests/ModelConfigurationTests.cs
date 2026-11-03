using System;
using System.Linq;
using Masterly.Hash.BlindIndex;
using Masterly.Hash.BlindIndex.Normalizers;
using Masterly.Hash.EntityFrameworkCore.Internal;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Metadata;
using Microsoft.EntityFrameworkCore.Migrations.Design;
using Microsoft.Extensions.DependencyInjection;

namespace Masterly.Hash.EntityFrameworkCore.Tests;

public class ModelConfigurationTests
{
    private readonly PasswordHasher _hasher = TestHashers.Create();

    [Fact]
    public void Annotations_hold_only_scaffoldable_values()
    {
        using var db = new SqliteDb();
        using TestDbContext context = db.Context(_hasher, TestKeys.Kat());
        IEntityType user = context.Model.FindEntityType(typeof(User))!;

        Assert.Equal(true, user.FindProperty(nameof(User.PasswordHash))!.FindAnnotation(MasterlyHashAnnotationNames.HashedPassword)!.Value);
        IProperty email = user.FindProperty(nameof(User.Email))!;
        Assert.Equal("EmailIndex", email[MasterlyHashAnnotationNames.BlindIndexProperty]);
        Assert.Equal("users.email", email[MasterlyHashAnnotationNames.BlindIndexName]);
        Assert.Equal("email", email[MasterlyHashAnnotationNames.BlindIndexNormalizer]);
        Assert.Equal(64, email[MasterlyHashAnnotationNames.BlindIndexOutputBits]);

        foreach (IProperty property in user.GetProperties())
        {
            foreach (IAnnotation annotation in property.GetAnnotations().Where(a => a.Name.StartsWith(MasterlyHashAnnotationNames.Prefix, StringComparison.Ordinal)))
                Assert.True(annotation.Value is string or bool or int, annotation.Name);
        }
    }

    [Fact]
    public void Migration_snapshot_can_be_generated()
    {
        using var db = new SqliteDb();
        using TestDbContext context = db.Context(_hasher, TestKeys.Kat());

        var services = new ServiceCollection();
        services.AddEntityFrameworkDesignTimeServices();
        services.AddDbContextDesignTimeServices(context);
#pragma warning disable EF1001 // The provider's design-time services are what `dotnet ef` loads; only the class lives in an Internal namespace.
        new Microsoft.EntityFrameworkCore.Sqlite.Design.Internal.SqliteDesignTimeServices().ConfigureDesignTimeServices(services);
#pragma warning restore EF1001
        using ServiceProvider provider = services.BuildServiceProvider();
        IMigrationsCodeGenerator generator = provider.GetRequiredService<IMigrationsCodeGeneratorSelector>().Select(language: null);

        IModel designModel = context.GetService<IDesignTimeModel>().Model;
        string snapshot = generator.GenerateSnapshot("Test.Migrations", typeof(TestDbContext), "TestSnapshot", designModel);

        Assert.Contains("\"Masterly:HashedPassword\", true", snapshot);
        Assert.Contains("\"Masterly:BlindIndex:Normalizer\", \"email\"", snapshot);
        Assert.Contains("\"Masterly:BlindIndex:OutputBits\", 32", snapshot);
    }

    [Fact]
    public void Builder_rejects_invalid_configuration()
    {
        var builder = new ModelBuilder();
        var entity = builder.Entity<User>();

        Assert.Throws<ArgumentNullException>(() => MasterlyHashPropertyBuilderExtensions.IsHashedPassword<string>(null!));
        Assert.Throws<ArgumentException>(() => entity.Property(u => u.Id).IsHashedPassword());
        Assert.Throws<ArgumentException>(() => entity.Property(u => u.Id).HasBlindIndex("EmailIndex", "users.id"));
        Assert.Throws<ArgumentNullException>(() => entity.Property(u => u.Email).HasBlindIndex(null!, "users.email"));
        Assert.Throws<ArgumentNullException>(() => entity.Property(u => u.Email).HasBlindIndex("EmailIndex", null!));
        Assert.Throws<ArgumentException>(() => entity.Property(u => u.Email).HasBlindIndex(" ", "users.email"));
        Assert.Throws<ArgumentException>(() => entity.Property(u => u.Email).HasBlindIndex("Email", "users.email"));
        Assert.Throws<ArgumentException>(() => entity.Property(u => u.Email).HasBlindIndex("EmailIndex", "users email"));
        Assert.Throws<ArgumentException>(() => entity.Property(u => u.Email).HasBlindIndex("EmailIndex", new string('a', 129)));
        Assert.Throws<ArgumentOutOfRangeException>(() => entity.Property(u => u.Email).HasBlindIndex("EmailIndex", "users.email", outputBits: 12));

        // A password must never also feed a blind index, in either order.
        entity.Property(u => u.PasswordHash).IsHashedPassword();
        Assert.Throws<ArgumentException>(() => entity.Property(u => u.PasswordHash).HasBlindIndex("EmailIndex", "users.pw"));
        entity.Property(u => u.Nickname).HasBlindIndex("EmailIndex", "users.nick");
        Assert.Throws<ArgumentException>(() => entity.Property(u => u.Nickname).IsHashedPassword());
    }

    [Fact]
    public void Missing_index_property_fails_the_save_with_a_clear_message()
    {
        using var db = new SqliteDb();
        using BadTargetContext context = db.Create<BadTargetContext>(o => new BadTargetContext(o), _hasher, TestKeys.Kat());
        context.Add(new User { UserName = "x", Email = "a@b.c" });

        var ex = Assert.Throws<InvalidOperationException>(() => context.SaveChanges());
        Assert.Contains("DoesNotExist", ex.Message);
    }

    [Fact]
    public void Custom_normalizer_is_resolved_by_type_name_and_can_be_overridden()
    {
        BlindIndexer indexer = TestKeys.Ring("k1", "k1");
        using var db = new SqliteDb();
        using (CustomNormalizerContext context = db.Create<CustomNormalizerContext>(o => new CustomNormalizerContext(o), _hasher, indexer))
        {
            var user = new User { UserName = "x", Email = "abc" };
            context.Add(user);
            context.SaveChanges();
            Assert.Equal(indexer.Compute("cba", "users.email"), user.EmailIndex);
            Assert.Equal(typeof(ReverseNormalizer).FullName, context.Model.FindEntityType(typeof(User))!.FindProperty("Email")![MasterlyHashAnnotationNames.BlindIndexNormalizer]);
        }

        using (CustomNormalizerContext context = db.Create<CustomNormalizerContext>(o => new CustomNormalizerContext(o), _hasher, indexer,
            o => o.Normalizers[typeof(ReverseNormalizer).FullName!] = BlindIndexNormalizers.Exact))
        {
            var user = new User { UserName = "y", Email = "abc" };
            context.Add(user);
            context.SaveChanges();
            Assert.Equal(indexer.Compute("abc", "users.email"), user.EmailIndex);
        }
    }

    // Regression: every non-singleton normalizer was keyed by type name, so EmailNormalizer(stripPlusTags: true) and
    // EmailNormalizer() collapsed onto one id and one of the two indexes silently used the other's settings.
    [Fact]
    public void Differently_configured_builtin_normalizers_keep_their_own_settings()
    {
        BlindIndexer indexer = TestKeys.Ring("k1", "k1");
        using var db = new SqliteDb();
        using ConfiguredNormalizersContext context = db.Create<ConfiguredNormalizersContext>(o => new ConfiguredNormalizersContext(o), _hasher, indexer);

        IEntityType user = context.Model.FindEntityType(typeof(User))!;
        IEntityType contact = context.Model.FindEntityType(typeof(Contact))!;
        Assert.Equal("email:strip-plus-tags", user.FindProperty(nameof(User.Email))![MasterlyHashAnnotationNames.BlindIndexNormalizer]);
        Assert.Equal("phone:cc=44", user.FindProperty(nameof(User.Phone))![MasterlyHashAnnotationNames.BlindIndexNormalizer]);
        Assert.Equal("email", contact.FindProperty(nameof(Contact.Email))![MasterlyHashAnnotationNames.BlindIndexNormalizer]);
        Assert.Equal("phone:cc=1", contact.FindProperty(nameof(Contact.Phone))![MasterlyHashAnnotationNames.BlindIndexNormalizer]);

        var u = new User { UserName = "bob", Email = "bob+promo@x.io", Phone = "020 7946 0958" };
        var c = new Contact { Email = "bob+promo@x.io", Phone = "020 7946 0958" };
        context.Add(u);
        context.Add(c);
        context.SaveChanges();

        Assert.Equal(indexer.Compute("bob@x.io", "users.email", new BlindIndexOptions { Normalizer = BlindIndexNormalizers.Email }), u.EmailIndex);
        Assert.Equal(indexer.Compute("bob+promo@x.io", "contacts.email", new BlindIndexOptions { Normalizer = BlindIndexNormalizers.Email }), c.EmailIndex);
        Assert.Equal(indexer.Compute("+44 20 7946 0958", "users.phone", new BlindIndexOptions { Normalizer = BlindIndexNormalizers.Phone }), u.PhoneIndex);
        Assert.Equal(indexer.Compute("+1 207 946 0958", "contacts.phone", new BlindIndexOptions { Normalizer = BlindIndexNormalizers.Phone }), c.PhoneIndex);
        Assert.Equal("bob", context.Set<User>().WhereBlindIndex(x => x.EmailIndex, "bob@x.io").Single().UserName);
    }
#pragma warning disable EF1001 // EF's analyzer treats every *.Internal namespace as EF internals; NormalizerRegistry is this package's own internal type.

    [Theory]
    [InlineData("email", false, false)]
    [InlineData("email:strip-plus-tags", true, false)]
    [InlineData("email:strip-gmail-dots", false, true)]
    [InlineData("email:strip-plus-tags,strip-gmail-dots", true, true)]
    public void Email_normalizer_ids_round_trip(string id, bool plus, bool dots)
    {
        Assert.Equal(id, NormalizerRegistry.Register(new EmailNormalizer(plus, dots), new object()));
        Assert.True(NormalizerRegistry.TryResolve(id, new System.Collections.Generic.Dictionary<string, IBlindIndexNormalizer>(), out IBlindIndexNormalizer resolved));
        var email = Assert.IsType<EmailNormalizer>(resolved);
        Assert.Equal(plus, email.StripPlusTags);
        Assert.Equal(dots, email.StripGmailDots);
    }

    [Theory]
    [InlineData("email:")]
    [InlineData("email:strip-gmail-dots,strip-plus-tags")]
    [InlineData("email:strip-plus-tags,strip-plus-tags")]
    [InlineData("email:unknown")]
    [InlineData("phone:cc=")]
    [InlineData("phone:cc=0")]
    [InlineData("phone:cc=1234")]
    [InlineData("phone:cc=4a")]
    public void Malformed_configured_ids_do_not_resolve(string id)
    {
        Assert.False(NormalizerRegistry.TryResolve(id, new System.Collections.Generic.Dictionary<string, IBlindIndexNormalizer>(), out _));
    }
#pragma warning restore EF1001

    [Fact]
    public void Conflicting_custom_normalizer_instances_in_one_model_are_rejected()
    {
        var builder = new ModelBuilder();
        var entity = builder.Entity<User>();
        entity.Property(u => u.Email).HasBlindIndex(nameof(User.EmailIndex), "users.email", new SuffixNormalizer("a"));
        var ex = Assert.Throws<ArgumentException>(() =>
            entity.Property(u => u.Phone).HasBlindIndex(nameof(User.PhoneIndex), "users.phone", new SuffixNormalizer("b")));
        Assert.Contains(typeof(SuffixNormalizer).FullName!, ex.Message);

        // Interchangeable instances are fine: equal by Equals, or of a type without instance state.
        var other = new ModelBuilder().Entity<User>();
        other.Property(u => u.Email).HasBlindIndex(nameof(User.EmailIndex), "users.email", new EqualSuffixNormalizer("a"));
        other.Property(u => u.Phone).HasBlindIndex(nameof(User.PhoneIndex), "users.phone", new EqualSuffixNormalizer("a"));
        other.Property(u => u.Nickname).HasBlindIndex(nameof(User.UserName), "users.nick", new ReverseNormalizer());
        other.Property(u => u.PasswordHash).HasBlindIndex("Unused", "users.pw", new ReverseNormalizer());

        // A separate model (another context, or the design-time model) may reconfigure the type.
        new ModelBuilder().Entity<User>().Property(u => u.Email).HasBlindIndex(nameof(User.EmailIndex), "users.email", new SuffixNormalizer("b"));
    }

    [Fact]
    public void Generic_options_builder_overload_returns_typed_builder()
    {
        var builder = new DbContextOptionsBuilder<TestDbContext>();
        DbContextOptionsBuilder<TestDbContext> returned = builder.UseMasterlyHash(_hasher);
        Assert.Same(builder, returned);
        Assert.Throws<ArgumentNullException>(() => builder.UseMasterlyHash(null!));
        Assert.Throws<ArgumentNullException>(() => ((DbContextOptionsBuilder)null!).UseMasterlyHash(_hasher));

        CoreOptionsExtension core = builder.Options.FindExtension<CoreOptionsExtension>()!;
        var interceptor = Assert.IsType<MasterlyHashSaveChangesInterceptor>(Assert.Single(core.Interceptors!));
        Assert.Same(_hasher, interceptor.Hasher);
        Assert.Null(interceptor.Indexer);
    }

    [Fact]
    public void Owned_type_properties_are_processed()
    {
        BlindIndexer indexer = TestKeys.Kat();
        using var db = new SqliteDb();
        using (OwnedDbContext context = db.Create<OwnedDbContext>(o => new OwnedDbContext(o), _hasher, indexer))
        {
            var member = new Member { Credentials = new Credentials { PasswordHash = "owned secret", RecoveryEmail = "Alice@Example.com" } };
            context.Members.Add(member);
            context.SaveChanges();

            Assert.True(_hasher.Verify("owned secret", member.Credentials.PasswordHash!).IsMatch);
            Assert.Equal(indexer.Compute("alice@example.com", "members.recovery_email"), member.Credentials.RecoveryEmailIndex);
        }

        using (OwnedDbContext context = db.Create<OwnedDbContext>(o => new OwnedDbContext(o), _hasher, indexer))
        {
            Member member = context.Members.Single();
            member.Credentials.PasswordHash = "changed secret";
            context.SaveChanges();
            Assert.True(_hasher.Verify("changed secret", db.Scalar("SELECT Credentials_PasswordHash FROM Members")!).IsMatch);
        }
    }

    private sealed class ReverseNormalizer : IBlindIndexNormalizer
    {
        public string Normalize(string value) => new(value.Reverse().ToArray());
    }

    /// <summary>A configurable custom normalizer with reference equality.</summary>
    private sealed class SuffixNormalizer : IBlindIndexNormalizer
    {
        private readonly string _suffix;

        public SuffixNormalizer(string suffix) => _suffix = suffix;

        public string Normalize(string value) => value + _suffix;
    }

    /// <summary>A configurable custom normalizer with value equality.</summary>
    private sealed record EqualSuffixNormalizer(string Suffix) : IBlindIndexNormalizer
    {
        public string Normalize(string value) => value + Suffix;
    }

    public sealed class Contact
    {
        public int Id { get; set; }

        public string? Email { get; set; }

        public string? EmailIndex { get; set; }

        public string? Phone { get; set; }

        public string? PhoneIndex { get; set; }
    }

    /// <summary>Two entity types using differently configured instances of the built-in Email and Phone normalizers.</summary>
    public sealed class ConfiguredNormalizersContext : DbContext
    {
        public ConfiguredNormalizersContext(DbContextOptions<ConfiguredNormalizersContext> options) : base(options)
        {
        }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<User>(e =>
            {
                e.Property(u => u.Email).HasBlindIndex(nameof(User.EmailIndex), "users.email", new EmailNormalizer(stripPlusTags: true));
                e.Property(u => u.Phone).HasBlindIndex(nameof(User.PhoneIndex), "users.phone", new PhoneNormalizer("44"));
            });
            modelBuilder.Entity<Contact>(e =>
            {
                e.Property(c => c.Email).HasBlindIndex(nameof(Contact.EmailIndex), "contacts.email", new EmailNormalizer());
                e.Property(c => c.Phone).HasBlindIndex(nameof(Contact.PhoneIndex), "contacts.phone", new PhoneNormalizer("1"));
            });
        }
    }

    public sealed class BadTargetContext : DbContext
    {
        public BadTargetContext(DbContextOptions<BadTargetContext> options) : base(options)
        {
        }

        protected override void OnModelCreating(ModelBuilder modelBuilder) =>
            modelBuilder.Entity<User>().Property(u => u.Email).HasBlindIndex("DoesNotExist", "users.email");
    }

    public sealed class CustomNormalizerContext : DbContext
    {
        public CustomNormalizerContext(DbContextOptions<CustomNormalizerContext> options) : base(options)
        {
        }

        protected override void OnModelCreating(ModelBuilder modelBuilder) =>
            modelBuilder.Entity<User>().Property(u => u.Email).HasBlindIndex(nameof(User.EmailIndex), "users.email", new ReverseNormalizer());
    }
}
