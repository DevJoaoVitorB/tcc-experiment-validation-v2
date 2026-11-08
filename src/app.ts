import express from 'express';
import { z } from 'zod';
import { createSessionTokens, hashPassword, passwordMatches, refreshAccessToken, revokeSession } from './auth';
import { errorHandler, createRateLimiter, notFound, requireAuth } from './middleware';
import { openapi } from './openapi';
import { prisma } from './prisma';
import type { AuthenticatedRequest } from './types';

const email = z.string().trim().email().max(254).transform((value) => value.toLowerCase());
const password = z.string().min(12).max(128).refine((value) => /[a-z]/.test(value) && /[A-Z]/.test(value) && /\d/.test(value), 'weak password');
const registrationSchema = z.object({ name: z.string().trim().min(2).max(100), email, password }).strict();
const loginSchema = z.object({ email, password: z.string().min(1).max(128) }).strict();
const refreshSchema = z.object({ refreshToken: z.string().min(1).max(4096) }).strict();

const userView = (user: { id: string; name: string; email: string }) => ({ id: user.id, name: user.name, email: user.email });
const isUniqueConstraintError = (error: unknown): error is { code: string } =>
  typeof error === 'object' && error !== null && 'code' in error && (error as { code?: unknown }).code === 'P2002';

export function createApp() {
  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', false);
  app.use(express.json({ limit: '16kb', type: 'application/json' }));

  app.get('/openapi.json', (_req, res) => res.status(200).json(openapi));
  const authRateLimit = createRateLimiter(10, 15 * 60 * 1000);

  app.post('/auth/register', authRateLimit, async (req, res, next) => {
    try {
      const input = registrationSchema.parse(req.body);
      const user = await prisma.user.create({ data: { name: input.name, email: input.email, passwordHash: await hashPassword(input.password) } });
      res.status(201).json(userView(user));
    } catch (error) {
      if (isUniqueConstraintError(error)) {
        res.status(409).json({ error: 'EMAIL_ALREADY_REGISTERED', message: 'Unable to create user with the supplied data.' });
        return;
      }
      next(error);
    }
  });

  app.post('/auth/login', authRateLimit, async (req, res, next) => {
    try {
      const input = loginSchema.parse(req.body);
      const user = await prisma.user.findUnique({ where: { email: input.email } });
      const valid = user ? await passwordMatches(input.password, user.passwordHash) : false;
      if (!user || !valid) {
        res.status(401).json({ error: 'INVALID_CREDENTIALS', message: 'Invalid email or password.' });
        return;
      }
      res.status(200).json(await createSessionTokens(user.id));
    } catch (error) { next(error); }
  });

  app.post('/auth/refresh', async (req, res, next) => {
    try {
      const input = refreshSchema.parse(req.body);
      res.status(200).json(await refreshAccessToken(input.refreshToken));
    } catch (error) {
      if (error instanceof z.ZodError) return next(error);
      res.status(401).json({ error: 'INVALID_REFRESH_TOKEN', message: 'Refresh token is invalid or expired.' });
    }
  });

  app.post('/auth/logout', requireAuth, async (req: AuthenticatedRequest, res, next) => {
    try {
      await revokeSession(req.auth!.sessionId, req.auth!.userId);
      res.status(204).send();
    } catch (error) { next(error); }
  });

  app.get('/users/me', requireAuth, async (req: AuthenticatedRequest, res, next) => {
    try {
      const user = await prisma.user.findUnique({ where: { id: req.auth!.userId }, select: { id: true, name: true, email: true } });
      if (!user) {
        res.status(401).json({ error: 'UNAUTHORIZED', message: 'Authentication is invalid or expired.' });
        return;
      }
      res.status(200).json(userView(user));
    } catch (error) { next(error); }
  });

  app.use(notFound);
  app.use(errorHandler);
  return app;
}
