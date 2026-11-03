import React from 'react';
import clsx from 'clsx';
import Link from '@docusaurus/Link';
import useBaseUrl from '@docusaurus/useBaseUrl';
import useDocusaurusContext from '@docusaurus/useDocusaurusContext';
import Layout from '@theme/Layout';
import Heading from '@theme/Heading';
import CodeBlock from '@theme/CodeBlock';
import Tabs from '@theme/Tabs';
import TabItem from '@theme/TabItem';
import Icon from '@site/src/components/home/Icon';
import CopyCommand from '@site/src/components/home/CopyCommand';
import VerifyDemo from '@site/src/components/home/VerifyDemo';
import styles from './index.module.css';

// Every sample below uses public APIs from src/ (Masterly.Hash, .DependencyInjection, .AspNetCore,
// .EntityFrameworkCore and .Legacy), as shown in each package's README.
const integrations = [
  {
    value: 'core',
    label: 'Core',
    caption: 'No setup. The static Password class uses a shared hasher with the 2026a Argon2id profile.',
    to: '/docs/quick-start',
    code: `using Masterly.Hash;

// Registration or password change
string stored = Password.Hash(password);           // $mh$p=2026a$<salt>$<tag>

// Login
PasswordVerificationResult result = Password.Verify(password, user.PasswordHash);
if (result.IsMatch && result.Rehash is { } fresh)
{
    user.PasswordHash = fresh;                      // only when the stored hash is outdated
}`,
  },
  {
    value: 'di',
    label: 'Dependency injection',
    caption: 'One validated singleton, bound from configuration, with a pepper and the legacy formats you need.',
    to: '/docs/dependency-injection',
    code: `builder.Services.AddMasterlyHash(builder.Configuration.GetSection("MasterlyHash"))
    .Configure(options => options.AddAllLegacyFormats())
    .WithPepper(HmacPepper.FromBase64("k2", pepperKeys));

public sealed class LoginService(IPasswordHasher hasher)
{
    public async Task<bool> CheckAsync(User? user, string password, CancellationToken cancellationToken)
    {
        // Same cost whether or not the user exists.
        PasswordVerificationResult result =
            await hasher.VerifyOrDummyAsync(password, user?.PasswordHash, cancellationToken);
        return result.IsMatch;
    }
}`,
  },
  {
    value: 'identity',
    label: 'ASP.NET Core Identity',
    caption: 'Replaces Identity’s hasher. Existing v2 and v3 Identity hashes keep verifying and upgrade on login.',
    to: '/docs/aspnetcore-identity',
    code: `builder.Services
    .AddIdentityCore<AppUser>()
    .AddEntityFrameworkStores<AppDbContext>()
    .AddMasterlyPasswordHasher();

// A busy hasher becomes 503 with Retry-After instead of a queue that eats memory.
builder.Services.AddProblemDetails();
builder.Services.AddMasterlyHashExceptionHandler();

WebApplication app = builder.Build();
app.UseExceptionHandler();`,
  },
  {
    value: 'ef',
    label: 'EF Core',
    caption: 'Mark the column once. SaveChanges writes the hash into the entity; VerifyAndUpgradeAsync saves upgrades.',
    to: '/docs/entity-framework-core',
    code: `modelBuilder.Entity<User>().Property(u => u.PasswordHash).IsHashedPassword();

builder.Services.AddDbContext<AppDbContext>((services, options) => options
    .UseSqlServer(connectionString)
    .UseMasterlyHash(services.GetRequiredService<IPasswordHasher>()));

// Sign-up: assign the plaintext; it holds the hash after SaveChangesAsync.
db.Users.Add(new User { PasswordHash = password });
await db.SaveChangesAsync(cancellationToken);

// Login: verify, and store the new hash when the old one is outdated.
PasswordVerificationResult result =
    await db.VerifyAndUpgradeAsync(user, u => u.PasswordHash, password, cancellationToken);`,
  },
];

// The RehashReason values a successful Verify can report (src/Masterly.Hash/PasswordVerificationResult.cs).
const rehashReasons = [
  {reason: 'LegacyFormat', detail: '1.x, bcrypt, Identity…'},
  {reason: 'Wrapped', detail: 'wrapped offline'},
  {reason: 'OutdatedProfile', detail: '2026c, default 2026a'},
  {reason: 'OutdatedPepperKey', detail: 'k1, current k2'},
];

const features = [
  {
    icon: 'upgrade',
    title: 'Upgrade on login',
    text: 'Old formats, older profiles and retired pepper keys all verify. The result carries a fresh hash under the current settings, so the table upgrades itself as users sign in.',
    to: '/docs/upgrade-on-login',
    size: 'wide',
    visual: 'reasons',
  },
  {
    icon: 'gauge',
    title: 'Dated profiles, not knobs',
    text: 'A stored hash names a profile such as 2026a. Costs come from a compiled-in allowlist, never from the row.',
    to: '/docs/profiles',
  },
  {
    icon: 'key',
    title: 'Peppers with rotation',
    text: 'HMAC-SHA256 under a key kept outside the database. Old key ids keep verifying and trigger a rehash.',
    to: '/docs/peppers',
  },
  {
    icon: 'cpu',
    title: 'Safe under load',
    text: 'A concurrency gate bounds memory under a login flood, and a 1024-byte input cap stops oversized passwords.',
    to: '/docs/limits-and-concurrency',
  },
  {
    icon: 'userX',
    title: 'No user enumeration',
    text: 'VerifyOrDummy spends the same work on an unknown user name as on a real account.',
    to: '/docs/user-enumeration',
  },
  {
    icon: 'vault',
    title: 'Keys that never leave the vault',
    text: 'Compute the pepper in HashiCorp Vault Transit or AWS KMS, or load rotating keys from Azure Key Vault.',
    to: '/docs/hashicorp-vault',
  },
  {
    icon: 'layers',
    title: 'Onion wrapping',
    text: 'Upgrade every weak hash in the table today, offline, without anyone’s password. The wrapped hash verifies with the original password and is replaced on the next login.',
    to: '/docs/onion-wrapping',
    size: 'wide',
    visual: 'wrap',
  },
  {
    icon: 'scale',
    title: 'NIST password policy',
    text: 'SP 800-63B rev. 4 rules: 15 characters minimum by default, common-password and context-word checks, a strength score.',
    to: '/docs/password-policy',
  },
  {
    icon: 'shieldAlert',
    title: 'Breached-password check',
    text: 'Have I Been Pwned with k-anonymity: only five hex characters of a SHA-1 hash leave your server.',
    to: '/docs/breach-checking',
  },
  {
    icon: 'code',
    title: 'Analyzers with code fixes',
    text: 'Six Roslyn rules catch fast hashes on passwords, non-constant-time comparisons and hard-coded peppers.',
    to: '/docs/analyzers',
  },
  {
    icon: 'ticket',
    title: 'API keys and tokens',
    text: 'API keys with a checksum and an indexable lookup hash. Signed, expiring, purpose-bound tokens.',
    to: '/docs/api-keys-and-tokens',
  },
  {
    icon: 'search',
    title: 'Blind indexes',
    text: 'Search encrypted PII columns by an HMAC index that keeps matching during key rotation.',
    to: '/docs/blind-indexes',
  },
  {
    icon: 'network',
    title: 'Tamper evidence',
    text: 'Content hashes, RFC 9162 Merkle trees with proofs, hash chains and directory manifests.',
    to: '/docs/merkle-trees-and-hash-chains',
  },
  {
    icon: 'alert',
    title: 'Attack detection',
    text: 'Honeywords, honey accounts and credential-stuffing detection for the login path.',
    to: '/docs/attack-detection',
  },
  {
    icon: 'terminal',
    title: 'Command-line tool',
    text: 'hash, verify, inspect, audit, wrap and bench from masterly-hash, streaming over CSV exports.',
    to: '/docs/command-line-tool',
  },
  {
    icon: 'flask',
    title: 'Test helpers',
    text: 'A fast hasher for unit tests, a recording decorator, a fake pepper and MasterlyHashAssert.',
    to: '/docs/testing',
  },
];

// LegacyFormats.All in src/Masterly.Hash.Legacy, plus the 1.x format built into the core package.
const legacyFormats = [
  {id: 'v1', name: 'Masterly.Hash 1.x', sample: 'base64(SHA-2 ‖ salt)', builtIn: true},
  {id: 'bcrypt', name: 'bcrypt', sample: '$2a$ $2b$ $2y$'},
  {id: 'wordpress-bcrypt', name: 'WordPress 6.8+', sample: '$wp$2y$'},
  {id: 'phpass', name: 'phpass', sample: '$P$ $H$'},
  {id: 'django-pbkdf2', name: 'Django', sample: 'pbkdf2_sha256$'},
  {id: 'aspnet-identity-v3', name: 'ASP.NET Core Identity', sample: 'AQAAAA…'},
  {id: 'aspnet-identity-v2', name: 'ASP.NET Identity 2', sample: 'AA…'},
  {id: 'argon2-phc', name: 'Argon2 (PHC)', sample: '$argon2id$v=19$'},
  {id: 'md5', name: 'MD5', sample: 'hex, unsalted'},
  {id: 'sha1', name: 'SHA-1', sample: 'hex, unsalted'},
  {id: 'sha256', name: 'SHA-256', sample: 'hex, unsalted'},
  {id: 'sha512', name: 'SHA-512', sample: 'hex, unsalted'},
];

function Hero() {
  const {siteConfig} = useDocusaurusContext();
  const version = siteConfig.customFields.packageVersion;
  return (
    <header className={styles.hero}>
      <div className={styles.heroBackdrop} aria-hidden="true" />
      <div className={clsx('container', styles.heroGrid)}>
        <div className={styles.heroCopy}>
          <Link className={styles.eyebrow} to="/docs/upgrading-from-1x">
            <span className={styles.eyebrowVersion}>v{version}</span>
            <span>Open source · MIT · .NET 8</span>
            <Icon name="arrowRight" size={14} />
          </Link>
          <Heading as="h1" className={styles.heroTitle}>
            Password hashing <span className={styles.heroLine}>
              you <span className={styles.heroAccent}>can’t get wrong.</span>
            </span>
          </Heading>
          <p className={styles.heroLead}>
            It takes two methods and the defaults are safe: Argon2id, a fresh salt and a constant-time check. Every hash
            you already have, from 1.x, bcrypt, Identity or Django, upgrades itself the next time its user logs in.
          </p>
          <div className={styles.heroActions}>
            <Link className={clsx('button button--primary button--lg', styles.primaryButton)} to="/docs/quick-start">
              Get started
              <Icon name="arrowRight" size={18} />
            </Link>
            <Link className={clsx('button button--lg', styles.secondaryButton)} to="/docs/overview">
              Read the docs
            </Link>
          </div>
          <CopyCommand command="dotnet add package Masterly.Hash" className={styles.heroInstall} />
        </div>
        <div className={styles.heroDemo}>
          <VerifyDemo />
        </div>
      </div>
    </header>
  );
}

function Stats() {
  // Counted from src/: 18 package folders sharing <Version> in Directory.Build.props; PasswordHasherOptions defaults;
  // 11 formats in LegacyFormats.All plus the built-in 1.x format.
  const stats = [
    {value: '18', label: 'packages, one shared version'},
    {value: '2026a', label: 'default profile: Argon2id, 64 MiB, t=3'},
    {value: '1024 bytes', label: 'input cap, checked before any hashing'},
    {value: '12', label: 'legacy formats verified and upgraded'},
  ];
  return (
    <section className={styles.stats} aria-label="At a glance">
      <div className={clsx('container', styles.statsGrid)}>
        {stats.map((stat) => (
          <div key={stat.label} className={styles.stat}>
            <div className={styles.statValue}>{stat.value}</div>
            <div className={styles.statLabel}>{stat.label}</div>
          </div>
        ))}
      </div>
    </section>
  );
}

function SectionHeader({eyebrow, title, children}) {
  return (
    <div className={styles.sectionHeader}>
      <div className={styles.sectionEyebrow}>{eyebrow}</div>
      <Heading as="h2" className={styles.sectionTitle}>
        {title}
      </Heading>
      {children && <p className={styles.sectionLead}>{children}</p>}
    </div>
  );
}

function TwoMethods() {
  return (
    <section className={styles.section}>
      <div className="container">
        <SectionHeader eyebrow="Use" title="Two methods, wherever your passwords live">
          Hash on registration, verify on login, save the rehash when there is one. The same two calls work on their
          own, through dependency injection, inside ASP.NET Core Identity and from Entity Framework Core.
        </SectionHeader>
        <div className={styles.tabsCard}>
          <Tabs groupId="integration" className={styles.tabs}>
            {integrations.map((item) => (
              <TabItem key={item.value} value={item.value} label={item.label}>
                <p className={styles.tabCaption}>
                  {item.caption}{' '}
                  <Link to={item.to} className={styles.inlineLink}>
                    Learn more
                    <Icon name="arrowRight" size={14} />
                  </Link>
                </p>
                <CodeBlock language="csharp">{item.code}</CodeBlock>
              </TabItem>
            ))}
          </Tabs>
        </div>
      </div>
    </section>
  );
}

function ReasonsVisual() {
  return (
    <ul className={styles.reasons} aria-label="Rehash reasons">
      {rehashReasons.map((item) => (
        <li key={item.reason} className={styles.reason}>
          <code className={styles.reasonName}>RehashReason.{item.reason}</code>
          <span className={styles.reasonDetail}>{item.detail}</span>
        </li>
      ))}
    </ul>
  );
}

function WrapVisual() {
  return (
    <div className={styles.wrap} aria-label="Onion wrapping example">
      <div className={styles.wrapRow}>
        <span className={styles.wrapLabel}>Before</span>
        <code className={clsx(styles.wrapValue, styles.wrapWeak)}>5f4dcc3b5aa765d61d8327deb882cf99</code>
        <span className={styles.wrapNote}>unsalted MD5</span>
      </div>
      <div className={styles.wrapArrow} aria-hidden="true">
        <code>hasher.TryWrap(stored, out string wrapped)</code>
      </div>
      <div className={styles.wrapRow}>
        <span className={styles.wrapLabel}>After</span>
        <code className={clsx(styles.wrapValue, styles.wrapStrong)}>$mh$p=2026a,w=md5$…</code>
        <span className={styles.wrapNote}>Argon2id over the MD5 digest</span>
      </div>
    </div>
  );
}

function Features() {
  return (
    <section className={clsx(styles.section, styles.sectionAlt)}>
      <div className="container">
        <SectionHeader eyebrow="Capabilities" title="Everything around the hash, too">
          Start with the two methods. Add a pepper, legacy formats, Identity, a password policy or attack detection when
          you need them, without changing how you hash and verify.
        </SectionHeader>
        <div className={styles.bento}>
          {features.map((feature) => (
            <Link
              key={feature.title}
              to={feature.to}
              className={clsx(styles.featureCard, feature.size === 'wide' && styles.featureWide)}>
              <div className={styles.featureBody}>
                <span className={styles.featureIcon}>
                  <Icon name={feature.icon} size={20} />
                </span>
                <Heading as="h3" className={styles.featureTitle}>
                  {feature.title}
                </Heading>
                <p className={styles.featureText}>{feature.text}</p>
                <span className={styles.featureMore}>
                  Read the guide
                  <Icon name="arrowRight" size={14} />
                </span>
              </div>
              {feature.visual === 'reasons' && <ReasonsVisual />}
              {feature.visual === 'wrap' && <WrapVisual />}
            </Link>
          ))}
        </div>
      </div>
    </section>
  );
}

function Migration() {
  return (
    <section className={styles.section}>
      <div className={clsx('container', styles.migration)}>
        <div className={styles.migrationCopy}>
          <div className={styles.sectionEyebrow}>Migrate</div>
          <Heading as="h2" className={clsx(styles.sectionTitle, styles.migrationTitle)}>
            Every hash you already have
          </Heading>
          <p className={styles.sectionLead}>
            Register the formats your table holds and your users keep logging in. Each successful login replaces the old
            hash with an Argon2id one. Accounts that never log in can be onion-wrapped offline, and an audit tells you
            what the table holds before you start.
          </p>
          <div className={styles.migrationActions}>
            <Link className={clsx('button', styles.secondaryButton)} to="/docs/legacy-formats">
              Supported formats
              <Icon name="arrowRight" size={16} />
            </Link>
            <Link className={styles.inlineLink} to="/docs/auditing-hash-tables">
              Audit a hash table
              <Icon name="arrowRight" size={14} />
            </Link>
          </div>
        </div>
        <ul className={styles.formats} aria-label="Supported legacy formats">
          {legacyFormats.map((format) => (
            <li key={format.id} className={styles.format}>
              <span className={styles.formatName}>
                {format.name}
                {format.builtIn && <span className={styles.formatBadge}>built in</span>}
              </span>
              <code className={styles.formatSample}>{format.sample}</code>
              <span className={styles.formatId}>{format.id}</span>
            </li>
          ))}
        </ul>
      </div>
    </section>
  );
}

function CallToAction() {
  return (
    <section className={styles.cta}>
      <div className={clsx('container', styles.ctaInner)}>
        <img className={styles.ctaMark} src={useBaseUrl('/img/logo.svg')} alt="" width="64" height="64" />
        <img
          className={clsx(styles.ctaMark, styles.ctaMarkDark)}
          src={useBaseUrl('/img/logo-dark.svg')}
          alt=""
          width="64"
          height="64"
        />
        <Heading as="h2" className={styles.ctaTitle}>
          Hash your first password in two minutes.
        </Heading>
        <p className={styles.ctaText}>The Quick Start installs the package, hashes a password and verifies it.</p>
        <div className={styles.heroActions}>
          <Link className={clsx('button button--primary button--lg', styles.primaryButton)} to="/docs/quick-start">
            Open the Quick Start
            <Icon name="arrowRight" size={18} />
          </Link>
          <Link className={clsx('button button--lg', styles.secondaryButton)} to="/docs/examples">
            See real-world examples
          </Link>
        </div>
      </div>
    </section>
  );
}

export default function Home() {
  return (
    <Layout description="Password hashing for .NET that you can't get wrong: Argon2id by default, dated profiles, upgrade on login, peppers with rotation and migration from bcrypt, Identity, Django and more.">
      <Hero />
      <main>
        <Stats />
        <TwoMethods />
        <Features />
        <Migration />
        <CallToAction />
      </main>
    </Layout>
  );
}
