import assert from 'node:assert/strict';
import type { Server } from 'node:http';
import { after, before, test } from 'node:test';
import { DatabaseSync } from 'node:sqlite';

process.env.DATABASE_URL = 'file:./test.db';
process.env.JWT_ACCESS_SECRET = 'test-access-secret-with-at-least-thirty-two-characters';
process.env.JWT_REFRESH_SECRET = 'test-refresh-secret-with-at-least-thirty-two-characters';

let createApp: typeof import('../src/app').createApp;
let prisma: typeof import('../src/prisma').prisma;
let server: Server;
let baseUrl: string;

before(async () => {
  ({ createApp } = await import('../src/app'));
  ({ prisma } = await import('../src/prisma'));
  const database = new DatabaseSync('prisma/test.db');
  database.exec(`
    PRAGMA foreign_keys = ON;
    CREATE TABLE IF NOT EXISTS User (id TEXT PRIMARY KEY NOT NULL, name TEXT NOT NULL, email TEXT NOT NULL UNIQUE, passwordHash TEXT NOT NULL, createdAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS Session (id TEXT PRIMARY KEY NOT NULL, userId TEXT NOT NULL, tokenId TEXT NOT NULL UNIQUE, expiresAt DATETIME NOT NULL, revokedAt DATETIME, createdAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY (userId) REFERENCES User(id) ON DELETE CASCADE ON UPDATE CASCADE);
    CREATE INDEX IF NOT EXISTS Session_userId_idx ON Session(userId);
    CREATE INDEX IF NOT EXISTS Session_expiresAt_idx ON Session(expiresAt);
  `);
  database.close();
  await prisma.session.deleteMany();
  await prisma.user.deleteMany();
  server = createApp().listen(0);
  await new Promise<void>((resolve) => server.once('listening', resolve));
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('No test port');
  baseUrl = `http://127.0.0.1:${address.port}`;
});

after(async () => {
  if (server) await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  if (prisma) await prisma.$disconnect();
});

async function request(path: string, init: RequestInit = {}) {
  return fetch(`${baseUrl}${path}`, { ...init, headers: { 'content-type': 'application/json', ...init.headers } });
}

test('complete authentication lifecycle revokes both tokens on logout', async () => {
  const register = await request('/auth/register', { method: 'POST', body: JSON.stringify({ name: 'Ana Silva', email: 'ANA@EXAMPLE.COM', password: 'StrongPassword123' }) });
  assert.equal(register.status, 201);
  const registeredUser = await register.json() as { id: string; name: string; email: string };
  assert.ok(registeredUser.id.length > 0);
  assert.equal(registeredUser.name, 'Ana Silva');
  assert.equal(registeredUser.email, 'ana@example.com');

  const invalidLogin = await request('/auth/login', { method: 'POST', body: JSON.stringify({ email: 'ana@example.com', password: 'wrong' }) });
  assert.equal(invalidLogin.status, 401);

  const login = await request('/auth/login', { method: 'POST', body: JSON.stringify({ email: 'ana@example.com', password: 'StrongPassword123' }) });
  assert.equal(login.status, 200);
  const tokens = await login.json() as { accessToken: string; refreshToken: string };

  const profile = await request('/users/me', { headers: { authorization: `Bearer ${tokens.accessToken}` } });
  assert.equal(profile.status, 200);
  assert.equal((await profile.json() as { email: string }).email, 'ana@example.com');

  const refresh = await request('/auth/refresh', { method: 'POST', body: JSON.stringify({ refreshToken: tokens.refreshToken }) });
  assert.equal(refresh.status, 200);

  const logout = await request('/auth/logout', { method: 'POST', headers: { authorization: `Bearer ${tokens.accessToken}` } });
  assert.equal(logout.status, 204);

  assert.equal((await request('/users/me', { headers: { authorization: `Bearer ${tokens.accessToken}` } })).status, 401);
  assert.equal((await request('/auth/refresh', { method: 'POST', body: JSON.stringify({ refreshToken: tokens.refreshToken }) })).status, 401);
});

test('publishes the complete OpenAPI description', async () => {
  const response = await request('/openapi.json');
  assert.equal(response.status, 200);
  const document = await response.json() as { paths: Record<string, unknown> };
  assert.ok(document.paths['/auth/login']);
  assert.ok(document.paths['/users/me']);
});
