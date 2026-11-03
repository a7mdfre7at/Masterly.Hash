import React, {useCallback, useEffect, useRef, useState} from 'react';
import clsx from 'clsx';
import CodeBlock from '@theme/CodeBlock';
import Icon from './Icon';
import styles from './VerifyDemo.module.css';

// Every stored hash and output value below is real: each was produced by Masterly.Hash 2.0.0 (with
// Masterly.Hash.Legacy for bcrypt) for the password "hunter2", then verified with PasswordHasher.Verify.
const scenarios = [
  {
    id: 'bcrypt',
    label: 'bcrypt',
    comment: '// "$2a$10$MFlDm3A4HKAdz8JrHEMP…"  bcrypt, cost 10',
    format: 'bcrypt',
    reason: 'LegacyFormat',
    rehash: '$mh$p=2026a$Jtw/9PKwFVyXp/mSCI9nrA$7FpZjNOdorbVEO+GRKfdZQnMjsuU4IclrGXTYdx8Hjc',
  },
  {
    id: 'v1',
    label: '1.x',
    comment: '// "TOI1CxDHLb2qZFFLH2A7HYpA…"  Masterly.Hash 1.x, SHA-512',
    format: 'v1',
    reason: 'LegacyFormat',
    rehash: '$mh$p=2026a$+IjltXpuHWLnQddnoTzy6g$xh6gH1KCqLAWnpvKtpKpFL0Knou5/BfaB/KLnDi6/pY',
  },
  {
    id: 'profile',
    label: '2026c',
    comment: '// "$mh$p=2026c$nPOf5tFUsQQY…"  an older, lighter profile',
    format: 'mh, profile 2026c',
    reason: 'OutdatedProfile',
    rehash: '$mh$p=2026a$gnlj9E3ypIBCWBBFgAq56g$fH529joWzfxLlqRx2XKiAo0/GeEAYe3MzTh95FRR9wU',
  },
];

function codeFor(scenario) {
  return `PasswordHasher hasher = new(
    new PasswordHasherOptions().AddAllLegacyFormats());

string stored = user.PasswordHash;
${scenario.comment}

PasswordVerificationResult result = hasher.Verify(password, stored);
if (result.IsMatch && result.Rehash is { } fresh)
{
    user.PasswordHash = fresh;   // upgraded for good
    await db.SaveChangesAsync(cancellationToken);
}`;
}

const finalStep = 5;
const stepDelayMs = 520;

function prefersReducedMotion() {
  return typeof window !== 'undefined' && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
}

/** Colours the `$` delimiters of a $mh$ string in the brand colour, as BRAND.md specifies for the format line. */
function FormatLine({value}) {
  return value.split(/(\$)/).map((part, index) =>
    part === '$' ? (
      <span key={index} className={styles.delimiter}>
        $
      </span>
    ) : (
      <React.Fragment key={index}>{part}</React.Fragment>
    ),
  );
}

/**
 * A code window that verifies an outdated stored hash and reveals the verification result field by field, ending
 * with the fresh Argon2id hash. Every row is rendered from the start, so the animation never shifts the layout.
 */
export default function VerifyDemo() {
  const [scenarioIndex, setScenarioIndex] = useState(0);
  const [step, setStep] = useState(0);
  const [running, setRunning] = useState(false);
  const container = useRef(null);
  const started = useRef(false);
  const scenario = scenarios[scenarioIndex];

  const run = useCallback(() => {
    if (prefersReducedMotion()) {
      setStep(finalStep);
      return;
    }
    setStep(0);
    setRunning(true);
  }, []);

  useEffect(() => {
    if (!running) {
      return undefined;
    }
    if (step >= finalStep) {
      setRunning(false);
      return undefined;
    }
    const timer = setTimeout(() => setStep((current) => current + 1), stepDelayMs);
    return () => clearTimeout(timer);
  }, [running, step]);

  useEffect(() => {
    const element = container.current;
    if (!element || typeof IntersectionObserver === 'undefined') {
      run();
      return undefined;
    }
    const observer = new IntersectionObserver(
      (entries) => {
        if (entries.some((entry) => entry.isIntersecting) && !started.current) {
          started.current = true;
          run();
          observer.disconnect();
        }
      },
      {threshold: 0.4},
    );
    observer.observe(element);
    return () => observer.disconnect();
  }, [run]);

  function choose(index) {
    setScenarioIndex(index);
    run();
  }

  const done = step >= finalStep;
  const rows = [
    {key: 'format', label: 'hasher.Inspect(stored).Format', value: scenario.format, tone: 'neutral'},
    {key: 'match', label: 'result.IsMatch', value: 'true', tone: 'pass'},
    {key: 'status', label: 'result.Status', value: 'SuccessRehashNeeded', tone: 'pass'},
    {key: 'reason', label: 'result.RehashReason', value: scenario.reason, tone: 'warn'},
  ];

  return (
    <div className={styles.window} ref={container}>
      <div className={styles.titleBar}>
        <span className={styles.dots} aria-hidden="true">
          <span />
          <span />
          <span />
        </span>
        <span className={styles.fileName}>Login.cs</span>
        <div className={styles.scenarios} role="group" aria-label="Stored hash">
          {scenarios.map((item, index) => (
            <button
              key={item.id}
              type="button"
              className={clsx(styles.scenario, index === scenarioIndex && styles.scenarioActive)}
              aria-pressed={index === scenarioIndex}
              onClick={() => choose(index)}>
              {item.label}
            </button>
          ))}
        </div>
        <button type="button" className={styles.runButton} onClick={run} disabled={running}>
          <Icon name={done ? 'replay' : 'play'} size={14} />
          <span>{done ? 'Run again' : running ? 'Running' : 'Run'}</span>
        </button>
      </div>

      <CodeBlock language="csharp" className={styles.code}>
        {codeFor(scenario)}
      </CodeBlock>

      <div className={styles.console}>
        <div className={styles.consoleHeader}>
          <span>Output</span>
          <span className={styles.status} role="status" aria-live="polite">
            {done ? (
              <>
                <span className={styles.statusPass}>Verified</span> · outdated hash replaced
              </>
            ) : (
              'Verifying…'
            )}
          </span>
        </div>
        <dl className={styles.fields}>
          {rows.map((row, index) => {
            const resolved = step > index;
            const active = running && step === index;
            return (
              <div key={row.key} className={styles.field}>
                <dt className={styles.fieldName}>{row.label}</dt>
                <dd className={styles.fieldValue}>
                  {resolved ? (
                    <span className={clsx(styles.value, styles[row.tone])}>{row.value}</span>
                  ) : (
                    <span className={clsx(styles.placeholder, active && styles.pulsing)}>…</span>
                  )}
                </dd>
              </div>
            );
          })}
          <div className={clsx(styles.field, styles.rehashField)}>
            <dt className={styles.fieldName}>result.Rehash</dt>
            <dd className={styles.fieldValue}>
              <span className={clsx(styles.rehash, step >= finalStep && styles.rehashVisible)}>
                {step >= finalStep ? (
                  <FormatLine value={scenario.rehash} />
                ) : (
                  <span className={clsx(styles.placeholder, running && step === finalStep - 1 && styles.pulsing)}>…</span>
                )}
              </span>
            </dd>
          </div>
        </dl>
      </div>
    </div>
  );
}
