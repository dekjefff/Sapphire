'use client';

import { useEffect, useId, useRef, useState } from 'react';
import styles from './account-menu.module.css';

export function AccountMenu({
  name,
  signOutAction,
}: {
  name: string;
  signOutAction: () => Promise<void>;
}) {
  const [open, setOpen] = useState(false);
  const root = useRef<HTMLDivElement>(null);
  const trigger = useRef<HTMLButtonElement>(null);
  const panelId = useId();
  const initials = name
    .split(/\s+/)
    .slice(0, 2)
    .map((word) => Array.from(word)[0])
    .join('')
    .toUpperCase();

  useEffect(() => {
    if (!open) return;

    function closeOutside(event: PointerEvent) {
      if (event.target instanceof Node && !root.current?.contains(event.target)) setOpen(false);
    }

    function closeWithEscape(event: KeyboardEvent) {
      if (event.key !== 'Escape') return;
      setOpen(false);
      if (root.current?.contains(document.activeElement)) trigger.current?.focus();
    }

    document.addEventListener('pointerdown', closeOutside);
    document.addEventListener('keydown', closeWithEscape);
    return () => {
      document.removeEventListener('pointerdown', closeOutside);
      document.removeEventListener('keydown', closeWithEscape);
    };
  }, [open]);

  return (
    <div
      ref={root}
      className={styles.account}
      onBlur={(event) => {
        if (event.relatedTarget && !event.currentTarget.contains(event.relatedTarget))
          setOpen(false);
      }}
    >
      <button
        ref={trigger}
        className={styles.avatar}
        type="button"
        aria-label="Account menu"
        aria-expanded={open}
        aria-controls={panelId}
        onClick={() => setOpen((current) => !current)}
      >
        <span aria-hidden="true">{initials}</span>
      </button>
      <div id={panelId} className={styles.panel} hidden={!open}>
        <p className={styles.name}>{name}</p>
        <form className={styles.actions} action={signOutAction}>
          <button className="sapphire-primary-button" type="submit">
            Sign out
          </button>
        </form>
      </div>
    </div>
  );
}
