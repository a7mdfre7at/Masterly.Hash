import React from 'react';
import clsx from 'clsx';
import Link from '@docusaurus/Link';
import {
  filterDocCardListItems,
  useCurrentSidebarSiblings,
  useDocById,
} from '@docusaurus/plugin-content-docs/client';
import Icon from '@site/src/components/home/Icon';
import styles from './styles.module.css';

// Ejected from @docusaurus/theme-classic (marked safe to swizzle). Renders the cards on generated category pages
// with the site's icon set and full page descriptions instead of emoji and truncated text.
const iconByDocId = {
  'overview': 'layers',
  'installation': 'box',
  'quick-start': 'zap',
  'how-it-works': 'tree',
  'hashing-and-verifying': 'lock',
  'profiles': 'gauge',
  'upgrade-on-login': 'upgrade',
  'peppers': 'key',
  'limits-and-concurrency': 'cpu',
  'user-enumeration': 'userX',
  'legacy-formats': 'shuffle',
  'onion-wrapping': 'layers',
  'auditing-hash-tables': 'search',
  'upgrading-from-1x': 'upgrade',
  'dependency-injection': 'plug',
  'aspnetcore-identity': 'shieldCheck',
  'entity-framework-core': 'database',
  'observability': 'activity',
  'hashicorp-vault': 'vault',
  'aws-kms': 'cloud',
  'azure-key-vault': 'cloud',
  'password-policy': 'scale',
  'strength-estimation': 'gauge',
  'breach-checking': 'shieldAlert',
  'api-keys-and-tokens': 'ticket',
  'blind-indexes': 'search',
  'integrity': 'fileCheck',
  'merkle-trees-and-hash-chains': 'network',
  'attack-detection': 'alert',
  'analyzers': 'code',
  'command-line-tool': 'terminal',
  'testing': 'flask',
  'performance': 'clock',
  'examples': 'braces',
  'api-reference': 'book',
  'hash-format': 'fileCode',
  'threat-model': 'shield',
};

function CardBody({icon, title, description}) {
  return (
    <>
      <span className={styles.icon}>
        <Icon name={icon} size={18} />
      </span>
      <span className={styles.title}>
        {title}
        <Icon name="arrowRight" size={14} className={styles.arrow} />
      </span>
      {description && <span className={styles.description}>{description}</span>}
    </>
  );
}

function DocLinkCard({item}) {
  const doc = useDocById(item.docId ?? undefined);
  const description = item.description ?? doc?.description;
  return (
    <Link to={item.href} className={styles.card}>
      <CardBody icon={iconByDocId[item.docId] ?? 'braces'} title={item.label} description={description} />
    </Link>
  );
}

function CategoryCard({item}) {
  const href = item.href ?? item.items?.find((child) => child.href)?.href;
  if (!href) {
    return null;
  }
  const count = item.items?.length ?? 0;
  return (
    <Link to={href} className={styles.card}>
      <CardBody
        icon="layers"
        title={item.label}
        description={item.description ?? `${count} ${count === 1 ? 'page' : 'pages'}`}
      />
    </Link>
  );
}

function DocCardListForCurrentSidebarCategory({className}) {
  const items = useCurrentSidebarSiblings();
  return <DocCardList items={items} className={className} />;
}

/**
 * A grid of linked cards, one per sidebar item.
 */
export default function DocCardList(props) {
  const {items, className} = props;
  if (!items) {
    return <DocCardListForCurrentSidebarCategory {...props} />;
  }
  const filteredItems = filterDocCardListItems(items);
  return (
    <ul className={clsx(styles.grid, className)}>
      {filteredItems.map((item, index) => (
        <li key={index} className={styles.item}>
          {item.type === 'category' ? <CategoryCard item={item} /> : <DocLinkCard item={item} />}
        </li>
      ))}
    </ul>
  );
}
