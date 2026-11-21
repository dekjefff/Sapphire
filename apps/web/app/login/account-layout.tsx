import type { ComponentPropsWithoutRef, ReactNode } from 'react';
import styles from './page.module.css';

export function AccountLayout({ title, children }: { title: string; children: ReactNode }) {
  return (
    <main className={styles.page}>
      <div className={styles.artwork} aria-hidden="true" />
      <section className={styles.panel} aria-labelledby="account-title">
        <div className={styles.brand}>Sapphire</div>
        <h1 id="account-title">{title}</h1>
        {children}
      </section>
    </main>
  );
}

export function Field({
  label,
  name,
  ...props
}: ComponentPropsWithoutRef<'input'> & { label: string; name: string }) {
  return (
    <label className={styles.field}>
      {label}
      <input name={name} required {...props} />
    </label>
  );
}
