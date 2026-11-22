import { createHash, randomBytes, randomUUID, scrypt, timingSafeEqual } from 'node:crypto';
import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

type Account = { id: string; email: string; name: string };
type StoredAccount = Account & { password_salt: string; password_hash: string };

let database: DatabaseSync | undefined;

function accounts() {
  if (!database) {
    const path = process.env.SAPPHIRE_AUTH_DB_PATH ?? '.sapphire-auth/accounts.sqlite';
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    const db = new DatabaseSync(path);
    db.exec(`
      PRAGMA busy_timeout = 5000;
      CREATE TABLE IF NOT EXISTS accounts (
        id TEXT PRIMARY KEY,
        email TEXT NOT NULL UNIQUE,
        name TEXT NOT NULL,
        password_salt TEXT NOT NULL,
        password_hash TEXT NOT NULL,
        setup_digest TEXT NOT NULL UNIQUE
      );
    `);
    database = db;
  }
  return database;
}

const loginAttempts = new Map<string, number>();
let loginWindowEnds = 0;
let totalLoginAttempts = 0;

function allowLoginAttempt(email: string) {
  const now = Date.now();
  if (now >= loginWindowEnds) {
    loginAttempts.clear();
    loginWindowEnds = now + 60_000;
    totalLoginAttempts = 0;
  }
  const attempts = loginAttempts.get(email) ?? 0;
  if (attempts >= 10 || totalLoginAttempts >= 120) return false;
  loginAttempts.set(email, attempts + 1);
  totalLoginAttempts += 1;
  return true;
}

function normalizeEmail(value: unknown) {
  if (typeof value !== 'string' || value.length > 254) return null;
  const email = value.trim().toLowerCase();
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ? email : null;
}

function passwordKey(password: string, salt: string): Promise<Buffer> {
  return new Promise((done, fail) =>
    scrypt(password, salt, 64, { N: 32768, r: 8, p: 3, maxmem: 64 * 1024 * 1024 }, (error, key) => {
      if (error) fail(error);
      else done(key);
    }),
  );
}

function setupDigest() {
  const code = process.env.SAPPHIRE_AUTH_SETUP_CODE;
  return code && code.length >= 32 ? digest(code) : null;
}

function digest(code: string) {
  return createHash('sha256').update(code).digest();
}

function codeUsed(code: Buffer) {
  return accounts()
    .prepare('SELECT 1 FROM accounts WHERE setup_digest = ?')
    .get(code.toString('hex'));
}

export function canRegisterAccount() {
  const code = setupDigest();
  return Boolean(code && !codeUsed(code));
}

export async function registerAccount(form: FormData) {
  const email = normalizeEmail(form.get('email'));
  const first = form.get('firstName');
  const last = form.get('lastName');
  const password = form.get('password');
  const code = form.get('setupCode');
  if (
    !email ||
    typeof first !== 'string' ||
    !first.trim() ||
    first.length > 80 ||
    typeof last !== 'string' ||
    !last.trim() ||
    last.length > 80 ||
    typeof password !== 'string' ||
    password.length < 12 ||
    password.length > 128 ||
    password !== form.get('confirmPassword')
  ) {
    return 'fields';
  }

  const expected = setupDigest();
  if (
    !expected ||
    typeof code !== 'string' ||
    code.length > 128 ||
    !timingSafeEqual(expected, digest(code)) ||
    codeUsed(expected)
  ) {
    return 'setup';
  }

  const salt = randomBytes(16).toString('hex');
  const key = await passwordKey(password, salt);
  const result = accounts()
    .prepare(
      `
    INSERT INTO accounts (id, email, name, password_salt, password_hash, setup_digest)
    VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT DO NOTHING
  `,
    )
    .run(
      randomUUID(),
      email,
      first.trim() + ' ' + last.trim(),
      salt,
      key.toString('hex'),
      expected.toString('hex'),
    );
  return result.changes === 1 ? 'created' : 'setup';
}

export async function verifyAccount(
  emailValue: unknown,
  password: unknown,
): Promise<Account | null> {
  const email = normalizeEmail(emailValue);
  if (
    !email ||
    typeof password !== 'string' ||
    !password ||
    password.length > 128 ||
    !allowLoginAttempt(email)
  )
    return null;

  const account = accounts()
    .prepare('SELECT id, email, name, password_salt, password_hash FROM accounts WHERE email = ?')
    .get(email) as StoredAccount | undefined;
  const key = await passwordKey(
    password,
    account?.password_salt ?? '00000000000000000000000000000000',
  );
  if (!account || !timingSafeEqual(key, Buffer.from(account.password_hash, 'hex'))) return null;
  loginAttempts.delete(email);
  return { id: account.id, email: account.email, name: account.name };
}
