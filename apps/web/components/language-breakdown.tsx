import type { Assessment } from '@/lib/types';
import styles from './language-breakdown.module.css';

const colors: Record<string, string> = {
  TypeScript: '#3178c6',
  JavaScript: '#f1e05a',
  Python: '#3572a5',
  MDX: '#fcb32c',
  CSS: '#663399',
  HTML: '#e34c26',
  Astro: '#ff5a03',
  Dockerfile: '#384d54',
  Shell: '#71a94e',
  SCSS: '#c6538c',
  Sass: '#a53b70',
  Vue: '#41b883',
  Svelte: '#ff3e00',
  Go: '#00add8',
  Rust: '#c87845',
  Java: '#b07219',
  PHP: '#4f5d95',
  Ruby: '#a82b32',
  'C#': '#239120',
  'C++': '#ed5e96',
  C: '#555f67',
  Kotlin: '#8a54ed',
  Swift: '#e64e35',
  Dart: '#00b4ab',
  SQL: '#b84592',
  Scala: '#c92d39',
  R: '#2065b9',
};
const otherColors = ['#607b9b', '#a26795', '#74883f', '#bb6f43'];
const formatPercent = new Intl.NumberFormat('en', { style: 'percent', maximumFractionDigits: 1 });

export function LanguageBreakdown({
  languages,
  detected,
}: {
  languages: Assessment['source_languages'];
  detected: string[];
}) {
  const measured = (languages ?? []).filter(({ bytes }) => Number.isFinite(bytes) && bytes > 0);
  const total = measured.reduce((sum, { bytes }) => sum + bytes, 0);
  const entries = measured.length ? measured : detected.map((name) => ({ name, bytes: 0 }));
  const items = entries.map((entry, index) => ({
    ...entry,
    color: colors[entry.name] ?? otherColors[index % otherColors.length],
  }));
  if (!items.length && languages == null) return null;

  return (
    <section className={styles.languages} aria-label="Source languages">
      <h4>Languages</h4>
      {total > 0 ? (
        <div className={styles.bar} aria-hidden="true">
          {items.map(({ name, bytes, color }) => (
            <span key={name} style={{ flexGrow: bytes, backgroundColor: color }} />
          ))}
        </div>
      ) : null}
      {items.length > 0 && (
        <ul
          className={styles.legend}
          aria-label={total > 0 ? 'Language percentages' : 'Detected languages'}
        >
          {items.map(({ name, bytes, color }) => (
            <li key={name}>
              <span className={styles.dot} style={{ backgroundColor: color }} aria-hidden="true" />
              <strong>{name}</strong>
              {total > 0 && (
                <span className={styles.percent}>
                  {bytes / total < 0.001 ? '<0.1%' : formatPercent.format(bytes / total)}
                </span>
              )}
            </li>
          ))}
        </ul>
      )}
      <p className={styles.note}>
        {total > 0
          ? 'Share of recognized source bytes, grouped by file extension.'
          : languages == null
            ? 'This assessment has language names only. New scans record proportions.'
            : 'No recognized source files with measurable size.'}
      </p>
    </section>
  );
}
