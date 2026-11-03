// @ts-check

/**
 * A sidebar category whose label links to a generated overview page of cards (one per page, using each
 * page's front-matter description).
 * @param {string} label
 * @param {string} slug
 * @param {string} description
 * @param {string[]} items
 * @param {boolean} [collapsed]
 * @returns {import('@docusaurus/plugin-content-docs').SidebarItemCategory}
 */
function section(label, slug, description, items, collapsed = false) {
  return {
    type: 'category',
    label,
    collapsed,
    link: {type: 'generated-index', slug: `/category/${slug}`, title: label, description},
    items,
  };
}

/** @type {import('@docusaurus/plugin-content-docs').SidebarsConfig} */
const sidebars = {
  docs: [
    section(
      'Getting Started',
      'getting-started',
      'Install the packages, hash your first password and learn how the pieces fit.',
      ['overview', 'installation', 'quick-start', 'how-it-works'],
    ),
    section(
      'Password Hashing',
      'password-hashing',
      'Hash and verify passwords, choose profiles, add a pepper and stay safe under load.',
      ['hashing-and-verifying', 'profiles', 'upgrade-on-login', 'peppers', 'limits-and-concurrency', 'user-enumeration'],
    ),
    section(
      'Migrating Existing Hashes',
      'migration',
      'Verify bcrypt, Identity, Django, phpass and raw digests, wrap weak hashes offline and upgrade from 1.x.',
      ['legacy-formats', 'onion-wrapping', 'auditing-hash-tables', 'upgrading-from-1x'],
    ),
    section(
      'Integrations',
      'integrations',
      'Dependency injection, ASP.NET Core Identity, Entity Framework Core and telemetry.',
      ['dependency-injection', 'aspnetcore-identity', 'entity-framework-core', 'observability'],
    ),
    section(
      'Key Management',
      'key-management',
      'Keep the pepper key inside HashiCorp Vault, AWS KMS or Azure Key Vault.',
      ['hashicorp-vault', 'aws-kms', 'azure-key-vault'],
    ),
    section(
      'Password Policy',
      'password-policy',
      'NIST SP 800-63B rules, strength estimation and breached-password checks.',
      ['password-policy', 'strength-estimation', 'breach-checking'],
    ),
    section(
      'Beyond Passwords',
      'beyond-passwords',
      'API keys and signed tokens, blind indexes, tamper evidence and attack detection.',
      ['api-keys-and-tokens', 'blind-indexes', 'integrity', 'merkle-trees-and-hash-chains', 'attack-detection'],
    ),
    section(
      'Tooling',
      'tooling',
      'Roslyn analyzers, the command-line tool, test helpers and performance.',
      ['analyzers', 'command-line-tool', 'testing', 'performance'],
    ),
    'examples',
    section(
      'Reference',
      'reference',
      'The public API of every package, the $mh$ format specification and the threat model.',
      ['api-reference', 'hash-format', 'threat-model'],
    ),
  ],
};

export default sidebars;
