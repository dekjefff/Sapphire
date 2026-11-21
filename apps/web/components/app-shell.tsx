import type { ReactNode } from 'react';
import styles from './app-shell.module.css';

type AppShellProps = {
  account: ReactNode;
  children: ReactNode;
  navigation: ReactNode;
};

export function AppShell({ account, children, navigation }: AppShellProps) {
  return (
    <div className={styles.shell}>
      <header className={styles.topbar}>
        <span className="sapphire-brand">Sapphire</span>
        {account}
      </header>
      <aside className={styles.navigation}>{navigation}</aside>
      <main className={styles.workspace}>{children}</main>
    </div>
  );
}
