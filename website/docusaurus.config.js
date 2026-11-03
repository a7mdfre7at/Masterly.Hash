// @ts-check
// Docusaurus configuration for the Masterly.Hash documentation site.
// See: https://docusaurus.io/docs/api/docusaurus-config

import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {themes as prismThemes} from 'prism-react-renderer';

const repositoryUrl = 'https://github.com/a7mdfre7at/Masterly.Hash';
const nugetUrl = 'https://www.nuget.org/packages/Masterly.Hash';
const socialImageUrl = 'img/social-card.png';

// The package version has one source of truth: <Version> in the root Directory.Build.props.
const siteDirectory = path.dirname(fileURLToPath(import.meta.url));
const buildProps = fs.readFileSync(path.join(siteDirectory, '..', 'Directory.Build.props'), 'utf8');
const versionMatch = /<Version>([^<]+)<\/Version>/.exec(buildProps);
if (!versionMatch) {
  throw new Error('Directory.Build.props has no <Version> element.');
}
const packageVersion = versionMatch[1].trim();
const majorMinor = packageVersion.split('.').slice(0, 2).join('.');

// The docs are versioned per minor release. Once `npm run docusaurus docs:version <major.minor>` has frozen a release,
// versions.json exists: website/docs becomes the unreleased "Next" line (served at /docs/next) and the first entry of
// versions.json, the latest release, owns /docs. Until the first snapshot exists, website/docs is the current release
// and is served at /docs with no "unreleased" banner.
const hasVersionSnapshots = fs.existsSync(path.join(siteDirectory, 'versions.json'));
const docsVersioning = hasVersionSnapshots
  ? {
      versions: {
        current: {label: 'Next', path: 'next', banner: 'unreleased'},
      },
    }
  : {
      lastVersion: 'current',
      versions: {
        current: {label: majorMinor, banner: 'none'},
      },
    };

/** @type {import('@docusaurus/types').Config} */
const config = {
  title: 'Masterly.Hash',
  tagline: 'Password hashing you can’t get wrong.',
  favicon: 'img/favicon.svg',

  future: {
    v4: true,
  },

  url: 'https://a7mdfre7at.github.io',
  baseUrl: '/Masterly.Hash/',
  organizationName: 'a7mdfre7at',
  projectName: 'Masterly.Hash',
  trailingSlash: false,

  onBrokenLinks: 'throw',
  onBrokenAnchors: 'throw',

  customFields: {
    packageVersion,
    repositoryUrl,
    nugetUrl,
  },

  markdown: {
    // .md files are plain CommonMark, so C# generics such as IPasswordHasher<TUser> need no escaping.
    format: 'detect',
    hooks: {
      onBrokenMarkdownLinks: 'throw',
    },
  },

  headTags: [
    {tagName: 'link', attributes: {rel: 'preconnect', href: 'https://fonts.googleapis.com'}},
    {tagName: 'link', attributes: {rel: 'preconnect', href: 'https://fonts.gstatic.com', crossorigin: 'anonymous'}},
  ],

  stylesheets: [
    'https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&family=Space+Grotesk:wght@500;600;700&display=swap',
  ],

  i18n: {
    defaultLocale: 'en',
    locales: ['en'],
  },

  presets: [
    [
      'classic',
      /** @type {import('@docusaurus/preset-classic').Options} */
      ({
        docs: {
          sidebarPath: './sidebars.js',
          editUrl: `${repositoryUrl}/tree/master/website/`,
          showLastUpdateTime: true,
          ...docsVersioning,
        },
        blog: false,
        theme: {
          customCss: './src/css/custom.css',
        },
      }),
    ],
  ],

  themes: [
    [
      '@easyops-cn/docusaurus-search-local',
      /** @type {import('@easyops-cn/docusaurus-search-local').PluginOptions} */
      ({
        hashed: true,
        indexBlog: false,
        docsRouteBasePath: '/docs',
        highlightSearchTermsOnTargetPage: true,
        explicitSearchResultPath: true,
        searchResultLimits: 10,
        searchBarShortcutHint: true,
      }),
    ],
  ],

  themeConfig:
    /** @type {import('@docusaurus/preset-classic').ThemeConfig} */
    ({
      image: socialImageUrl,
      metadata: [
        {
          name: 'keywords',
          content:
            '.NET, C#, password hashing, Argon2id, PBKDF2, bcrypt migration, pepper, ASP.NET Core Identity, OWASP, NIST SP 800-63B',
        },
      ],
      colorMode: {
        defaultMode: 'dark',
        respectPrefersColorScheme: true,
      },
      announcementBar: {
        id: `release-${majorMinor}`,
        content: `<strong>${packageVersion} is out.</strong> Argon2id by default, dated profiles and upgrade on login. <a href="/Masterly.Hash/docs/upgrading-from-1x">Upgrading from 1.x →</a>`,
        isCloseable: true,
      },
      docs: {
        sidebar: {
          hideable: true,
          autoCollapseCategories: false,
        },
      },
      tableOfContents: {
        minHeadingLevel: 2,
        maxHeadingLevel: 3,
      },
      navbar: {
        title: 'Masterly.Hash',
        hideOnScroll: false,
        logo: {
          alt: '',
          src: 'img/logo.svg',
          srcDark: 'img/logo-dark.svg',
          width: 32,
          height: 32,
        },
        items: [
          {type: 'docSidebar', sidebarId: 'docs', position: 'left', label: 'Docs'},
          {to: '/docs/examples', label: 'Examples', position: 'left'},
          {to: '/docs/api-reference', label: 'API', position: 'left'},
          // A static page, outside the React router; the pathname:// protocol keeps the link checker away from it.
          {to: 'pathname:///playground/', label: 'Playground', position: 'left', target: '_self'},
          {
            type: 'docsVersionDropdown',
            position: 'right',
            dropdownActiveClassDisabled: true,
            dropdownItemsAfter: [
              {type: 'html', value: '<hr class="dropdown-separator">'},
              {href: `${repositoryUrl}/blob/master/CHANGELOG.md`, label: 'Changelog'},
            ],
          },
          {
            type: 'html',
            position: 'right',
            value: `<a class="navbar-version" href="${repositoryUrl}/blob/master/CHANGELOG.md" title="Changelog">v${packageVersion}</a>`,
          },
          {
            href: nugetUrl,
            position: 'right',
            className: 'navbar-icon-link navbar-icon-link--nuget',
            'aria-label': 'NuGet package',
          },
          {
            href: repositoryUrl,
            position: 'right',
            className: 'navbar-icon-link navbar-icon-link--github',
            'aria-label': 'GitHub repository',
          },
        ],
      },
      footer: {
        style: 'dark',
        links: [
          {
            title: 'Learn',
            items: [
              {label: 'Quick Start', to: '/docs/quick-start'},
              {label: 'Hashing and Verifying', to: '/docs/hashing-and-verifying'},
              {label: 'Migrating Existing Hashes', to: '/docs/legacy-formats'},
              {label: 'Real-World Examples', to: '/docs/examples'},
            ],
          },
          {
            title: 'Reference',
            items: [
              {label: 'API Reference', to: '/docs/api-reference'},
              {label: 'Hash Format', to: '/docs/hash-format'},
              {label: 'Threat Model', to: '/docs/threat-model'},
              {label: 'Upgrading from 1.x', to: '/docs/upgrading-from-1x'},
            ],
          },
          {
            title: 'Project',
            items: [
              {label: 'GitHub', href: repositoryUrl},
              {label: 'Issues', href: `${repositoryUrl}/issues`},
              {label: 'Security policy', href: `${repositoryUrl}/blob/master/SECURITY.md`},
              {label: 'Changelog', href: `${repositoryUrl}/blob/master/CHANGELOG.md`},
              {label: 'NuGet', href: 'https://www.nuget.org/packages?q=Masterly.Hash'},
            ],
          },
        ],
        copyright: `MIT licensed · © 2021-${new Date().getFullYear()} Ahmad Omar Al-Freihat`,
      },
      prism: {
        theme: prismThemes.oneLight,
        darkTheme: prismThemes.oneDark,
        additionalLanguages: ['csharp', 'bash', 'json', 'powershell'],
      },
    }),
};

export default config;
