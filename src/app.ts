import express from 'express';
import bcrypt from 'bcryptjs';
import { z } from 'zod';
import { prisma } from './prisma.js';
import { config } from './config.js';
import { requireAuth, signAccess, signRefresh, verifyRefresh } from './auth.js';
import { openapi } from './openapi.js';

const registerSchema = z.object({ name: z.string().trim().min(1).max(100), email: z.string().trim().email().max(320), password: z.string().min(8).max(128) });
const loginSchema = z.object({ email: z.string().trim().email(), password: z.string().min(1) });
const refreshSchema = z.object({ refreshToken: z.string().min(1) });
const publicUser = (user: { id: string; name: string; email: string }) => ({ id: user.id, name: user.name, email: user.email });
const validationError = (res: express.Response, error: z.ZodError) => res.status(400).json({ error: 'Invalid request data', details: error.flatten().fieldErrors });

export const app = express();
app.use(express.json());
app.get('/openapi.json', (_req, res) => res.json(openapi));

app.post('/auth/register', async (req, res, next) => {
  const parsed = registerSchema.safeParse(req.body);
  if (!parsed.success) return validationError(res, parsed.error);
  const { name, password } = parsed.data;
  const email = parsed.data.email.toLowerCase();
  try {
    const user = await prisma.user.create({ data: { name, email, passwordHash: await bcrypt.hash(password, 12) } });
    return res.status(201).json(publicUser(user));
  } catch (error: any) {
    if (error.code === 'P2002') return res.status(409).json({ error: 'Email already registered' });
    next(error);
  }
});

app.post('/auth/login', async (req, res, next) => {
  const parsed = loginSchema.safeParse(req.body);
  if (!parsed.success) return validationError(res, parsed.error);
  try {
    const user = await prisma.user.findUnique({ where: { email: parsed.data.email.toLowerCase() } });
    if (!user || !(await bcrypt.compare(parsed.data.password, user.passwordHash))) return res.status(401).json({ error: 'Invalid email or password' });
    const session = await prisma.session.create({ data: { userId: user.id, expiresAt: new Date(Date.now() + config.refreshTtlMs) } });
    return res.json({ accessToken: signAccess(user.id, session.id), refreshToken: signRefresh(user.id, session.id) });
  } catch (error) { next(error); }
});

app.post('/auth/refresh', async (req, res) => {
  const parsed = refreshSchema.safeParse(req.body);
  if (!parsed.success) return validationError(res, parsed.error);
  try {
    const claims = verifyRefresh(parsed.data.refreshToken);
    const session = await prisma.session.findUnique({ where: { id: claims.sid } });
    if (!session || session.userId !== claims.sub || session.revokedAt || session.expiresAt <= new Date()) throw new Error('Unavailable session');
    return res.json({ accessToken: signAccess(claims.sub, claims.sid) });
  } catch { return res.status(401).json({ error: 'Invalid or expired refresh token' }); }
});

app.post('/auth/logout', requireAuth, async (req, res, next) => {
  try {
    await prisma.session.update({ where: { id: req.auth!.sid }, data: { revokedAt: new Date() } });
    return res.status(204).send();
  } catch (error) { next(error); }
});

app.get('/users/me', requireAuth, async (req, res, next) => {
  try {
    const user = await prisma.user.findUnique({ where: { id: req.auth!.sub } });
    if (!user) return res.status(401).json({ error: 'User no longer exists' });
    return res.json(publicUser(user));
  } catch (error) { next(error); }
});

app.use((_req, res) => res.status(404).json({ error: 'Route not found' }));
app.use((error: unknown, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
  console.error(error);
  res.status(500).json({ error: 'Internal server error' });
});
