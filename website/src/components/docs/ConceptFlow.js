import React from 'react';
import Link from '@docusaurus/Link';
import useVersionedDocLink from './useVersionedDocLink';
import styles from './ConceptFlow.module.css';

// Every API named below is public in src/Masterly.Hash (or the integration package the wrapper row names).
const stages = [
  {
    step: '1',
    title: 'Hash',
    text: 'Registration and password changes call Hash. The default is Argon2id with a fresh 16-byte salt.',
    apis: ['Password.Hash', 'hasher.HashAsync', 'HashProfile.Server2026a'],
    to: '/docs/hashing-and-verifying',
  },
  {
    step: '2',
    title: 'Store',
    text: 'The result is one string. It names a dated profile and never carries cost parameters.',
    apis: ['$mh$p=2026a$…', 'Password.Inspect', 'HashInfo.ProfileId'],
    to: '/docs/hash-format',
  },
  {
    step: '3',
    title: 'Verify',
    text: 'Login calls Verify. The comparison is constant-time and a bad stored value never throws.',
    apis: ['Password.Verify', 'result.IsMatch', 'Password.VerifyOrDummy'],
    to: '/docs/hashing-and-verifying',
  },
  {
    step: '4',
    title: 'Rehash',
    text: 'When the stored hash is outdated, the result carries its replacement. Save it and you are done.',
    apis: ['result.Rehash', 'result.RehashReason', 'Password.NeedsRehash'],
    to: '/docs/upgrade-on-login',
  },
];

const wrappers = [
  {api: '.WithPepper(...)', text: 'add a secret key', to: '/docs/peppers'},
  {api: '.AddAllLegacyFormats()', text: 'accept old hashes', to: '/docs/legacy-formats'},
  {api: 'TryWrap(...)', text: 'upgrade offline', to: '/docs/onion-wrapping'},
  {api: 'MaxConcurrency', text: 'bound memory', to: '/docs/limits-and-concurrency'},
  {api: 'VerifyOrDummy(...)', text: 'hide unknown users', to: '/docs/user-enumeration'},
];

// Long member names such as Password.VerifyOrDummy may wrap only after a dot, never mid-word.
function withBreaksAfterDots(api) {
  return api.split(/(?<=\.)/).map((part, index) => (
    <React.Fragment key={index}>
      {index > 0 && <wbr />}
      {part}
    </React.Fragment>
  ));
}

/**
 * The life of a stored password (hash, store, verify, rehash), plus the options that apply to every stage.
 */
export default function ConceptFlow() {
  const versionedLink = useVersionedDocLink();
  return (
    <div className={styles.flow}>
      <ol className={styles.stages}>
        {stages.map((stage) => (
          <li key={stage.title} className={styles.stage}>
            <Link to={versionedLink(stage.to)} className={styles.stageLink}>
              <span className={styles.step} aria-hidden="true">
                {stage.step}
              </span>
              <span className={styles.title}>{stage.title}</span>
              <span className={styles.text}>{stage.text}</span>
              <span className={styles.apis}>
                {stage.apis.map((api) => (
                  <code key={api}>{withBreaksAfterDots(api)}</code>
                ))}
              </span>
            </Link>
          </li>
        ))}
      </ol>
      <div className={styles.wrappers}>
        <span className={styles.wrappersLabel}>Applies to every stage</span>
        <ul className={styles.wrapperList}>
          {wrappers.map((wrapper) => (
            <li key={wrapper.api}>
              <Link to={versionedLink(wrapper.to)} className={styles.wrapper}>
                <code>{wrapper.api}</code>
                <span>{wrapper.text}</span>
              </Link>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}
