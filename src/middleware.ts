import type { NextFunction, Request, Response } from 'express';
import { ZodError } from 'zod';
import { authenticateAccessToken } from './auth';
import type { AuthenticatedRequest } from './types';

export async function requireAuth(req: AuthenticatedRequest, res: Response, next: NextFunction) {
  const header = req.header('authorization');
  const match = header?.match(/^Bearer (.+)$/i);
  if (!match) {
    res.status(401).json({ error: 'UNAUTHORIZED', message: 'Authentication is required.' });
    return;
  }
  try {
    req.auth = await authenticateAccessToken(match[1]);
    next();
  } catch {
    res.status(401).json({ error: 'UNAUTHORIZED', message: 'Authentication is invalid or expired.' });
  }
}

export function notFound(_req: Request, res: Response) {
  res.status(404).json({ error: 'NOT_FOUND', message: 'Resource not found.' });
}

export function errorHandler(error: unknown, _req: Request, res: Response, _next: NextFunction) {
  if (error instanceof ZodError) {
    res.status(400).json({ error: 'VALIDATION_ERROR', message: 'Request data is invalid.' });
    return;
  }
  if (error instanceof SyntaxError && 'body' in error) {
    res.status(400).json({ error: 'INVALID_JSON', message: 'Request body must be valid JSON.' });
    return;
  }
  res.status(500).json({ error: 'INTERNAL_ERROR', message: 'An unexpected error occurred.' });
}

export function createRateLimiter(limit: number, windowMs: number) {
  const attempts = new Map<string, { count: number; resetAt: number }>();
  return (req: Request, res: Response, next: NextFunction) => {
    const key = req.ip || 'unknown';
    const now = Date.now();
    const current = attempts.get(key);
    const state = !current || current.resetAt <= now ? { count: 0, resetAt: now + windowMs } : current;
    state.count += 1;
    attempts.set(key, state);
    if (state.count > limit) {
      res.status(429).json({ error: 'TOO_MANY_REQUESTS', message: 'Too many attempts. Try again later.' });
      return;
    }
    next();
  };
}
