import type { NextFunction, Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import { config } from './config.js';
import { prisma } from './prisma.js';

export type TokenClaims = { sub: string; sid: string; type: 'access' | 'refresh' };

export function signAccess(userId: string, sessionId: string) {
  return jwt.sign({ sub: userId, sid: sessionId, type: 'access' }, config.accessSecret, { expiresIn: config.accessTtl });
}
export function signRefresh(userId: string, sessionId: string) {
  return jwt.sign({ sub: userId, sid: sessionId, type: 'refresh' }, config.refreshSecret, { expiresIn: config.refreshTtl });
}
export function verifyRefresh(token: string): TokenClaims {
  const payload = jwt.verify(token, config.refreshSecret) as TokenClaims;
  if (payload.type !== 'refresh' || !payload.sub || !payload.sid) throw new Error('Invalid token');
  return payload;
}

declare global { namespace Express { interface Request { auth?: TokenClaims } } }
export async function requireAuth(req: Request, res: Response, next: NextFunction) {
  const header = req.header('authorization');
  if (!header?.startsWith('Bearer ')) return res.status(401).json({ error: 'Authentication required' });
  try {
    const payload = jwt.verify(header.slice(7), config.accessSecret) as TokenClaims;
    if (payload.type !== 'access' || !payload.sub || !payload.sid) throw new Error('Invalid token');
    const session = await prisma.session.findUnique({ where: { id: payload.sid } });
    if (!session || session.userId !== payload.sub || session.revokedAt || session.expiresAt <= new Date()) throw new Error('Session unavailable');
    req.auth = payload;
    next();
  } catch { return res.status(401).json({ error: 'Invalid or expired access token' }); }
}
