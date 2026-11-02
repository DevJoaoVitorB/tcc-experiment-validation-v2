import { beforeEach, describe, expect, it, vi } from 'vitest';
import request from 'supertest';

const users = new Map<string, any>(); const sessions = new Map<string, any>(); let id = 0;
vi.mock('../src/prisma.js', () => ({ prisma: {
  user: { create: vi.fn(async ({ data }) => { if (users.has(data.email)) { const e: any = new Error(); e.code = 'P2002'; throw e; } const user = { id: `u${++id}`, ...data }; users.set(user.email, user); return user; }), findUnique: vi.fn(async ({ where }) => where.email ? users.get(where.email) ?? null : [...users.values()].find(u => u.id === where.id) ?? null) },
  session: { create: vi.fn(async ({ data }) => { const s = { id: `s${++id}`, ...data, revokedAt: null }; sessions.set(s.id, s); return s; }), findUnique: vi.fn(async ({ where }) => sessions.get(where.id) ?? null), update: vi.fn(async ({ where, data }) => { const s = sessions.get(where.id); Object.assign(s, data); return s; }) }
} }));
import { app } from '../src/app.js';
beforeEach(() => { users.clear(); sessions.clear(); id = 0; });
describe('authentication flow', () => {
  it('registers, authenticates, returns own profile, refreshes and revokes a session', async () => {
    const created = await request(app).post('/auth/register').send({ name: 'Ana', email: 'ANA@example.com', password: 'secret123' });
    expect(created.status).toBe(201); expect(created.body.email).toBe('ana@example.com'); expect(created.body.passwordHash).toBeUndefined();
    const login = await request(app).post('/auth/login').send({ email: 'ana@example.com', password: 'secret123' });
    expect(login.status).toBe(200);
    expect((await request(app).get('/users/me').set('Authorization', `Bearer ${login.body.accessToken}`)).body.name).toBe('Ana');
    expect((await request(app).post('/auth/refresh').send({ refreshToken: login.body.refreshToken })).body.accessToken).toBeTruthy();
    expect((await request(app).post('/auth/logout').set('Authorization', `Bearer ${login.body.accessToken}`)).status).toBe(204);
    expect((await request(app).get('/users/me').set('Authorization', `Bearer ${login.body.accessToken}`)).status).toBe(401);
  });
});
