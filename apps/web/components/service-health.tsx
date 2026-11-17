import type { HealthResponse } from '@/lib/types';
import styles from './service-health.module.css';

const serviceNames: Record<string, string> = {
  api: 'Control API',
  postgres: 'PostgreSQL',
  redis: 'Redis queue',
};

export function ServiceHealth({ health }: { health: HealthResponse | null }) {
  const services = health?.services ?? {
    api: 'unavailable',
    postgres: 'unavailable',
    redis: 'unavailable',
  };
  const healthy = health?.status === 'ok';

  return (
    <section className={styles.panel} aria-labelledby="service-health-title">
      <div className={styles.heading}>
        <div>
          <h2 id="service-health-title">Service health</h2>
          <p>Local services connected to this workspace</p>
        </div>
        <span className={`${styles.summary} ${healthy ? styles.good : styles.bad}`}>
          <i aria-hidden="true" />
          {healthy ? 'All systems operational' : 'Service connection issue'}
        </span>
      </div>
      <div className={styles.grid}>
        {Object.entries(services).map(([name, status]) => (
          <div className={styles.service} key={name}>
            <div className={styles.dot} data-state={status} aria-hidden="true" />
            <div>
              <strong>{serviceNames[name] ?? name}</strong>
              <small>{status}</small>
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}
