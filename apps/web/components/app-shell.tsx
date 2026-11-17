import type { ReactNode } from 'react';
import styles from './app-shell.module.css';

export function AppShell({ children }: { children: ReactNode }) {
  return (
    <main className={styles.shell}>
      <aside className={styles.rail} aria-label="Sapphire navigation">
        <div className={styles.brandMark} aria-hidden="true">
          S
        </div>
        <span className={styles.railLabel}>SAPPHIRE</span>
        <div className={styles.railLine} />
        <div className={`${styles.railIcon} ${styles.active}`} aria-label="Assessments">
          ◫
        </div>
        <div className={styles.railIcon} aria-hidden="true">
          ⌘
        </div>
        <span className={styles.railBottom}>LOCAL</span>
      </aside>

      <section className={styles.workspace}>
        <header className={styles.topbar}>
          <div className={styles.crumb}>
            Workspace <span>/</span> Assessments
          </div>
          <div className={styles.localBadge}>
            <i aria-hidden="true" /> Local environment
          </div>
        </header>
        <div className={styles.content}>{children}</div>
      </section>
    </main>
  );
}
