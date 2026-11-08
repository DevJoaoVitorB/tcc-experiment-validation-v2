import bcrypt from 'bcryptjs';
import jwt, { type JwtPayload } from 'jsonwebtoken';
import { randomUUID } from 'node:crypto';
import { config } from './config';
import { prisma } from './prisma';

type TokenPayload = JwtPayload & { sub: string; sid: string; kind: 'access' | 'refresh' };

const passwordRounds = 12;
const refreshLifetimeMs = 7 * 24 * 60 * 60 * 1000;

export async function hashPassword(password: string) {
  return bcrypt.hash(password, passwordRounds);
}

export async function passwordMatches(password: string, passwordHash: string) {
  return bcrypt.compare(password, passwordHash);
}

function signToken(userId: string, sessionId: string, kind: 'access' | 'refresh') {
  return jwt.sign(
    { sid: sessionId, kind },
    kind === 'access' ? config.accessSecret : config.refreshSecret,
    { subject: userId, expiresIn: kind === 'access' ? config.accessExpiresIn : config.refreshExpiresIn }
  );
}

function decodeToken(token: string, kind: 'access' | 'refresh'): TokenPayload {
  const payload = jwt.verify(token, kind === 'access' ? config.accessSecret : config.refreshSecret);
  if (typeof payload === 'string' || payload.kind !== kind || typeof payload.sub !== 'string' || typeof payload.sid !== 'string') {
    throw new Error('Invalid token');
  }
  return payload as TokenPayload;
}

export async function createSessionTokens(userId: string) {
  const sessionId = randomUUID();
  await prisma.session.create({
    data: { id: sessionId, tokenId: randomUUID(), userId, expiresAt: new Date(Date.now() + refreshLifetimeMs) }
  });
  return { accessToken: signToken(userId, sessionId, 'access'), refreshToken: signToken(userId, sessionId, 'refresh') };
}

export async function authenticateAccessToken(token: string) {
  const payload = decodeToken(token, 'access');
  const session = await prisma.session.findUnique({ where: { id: payload.sid } });
  if (!session || session.userId !== payload.sub || session.revokedAt || session.expiresAt <= new Date()) {
    throw new Error('Invalid session');
  }
  return { userId: payload.sub, sessionId: payload.sid };
}

export async function refreshAccessToken(token: string) {
  const payload = decodeToken(token, 'refresh');
  const session = await prisma.session.findUnique({ where: { id: payload.sid } });
  if (!session || session.userId !== payload.sub || session.revokedAt || session.expiresAt <= new Date()) {
    throw new Error('Invalid session');
  }
  return { accessToken: signToken(payload.sub, payload.sid, 'access') };
}

export async function revokeSession(sessionId: string, userId: string) {
  await prisma.session.updateMany({ where: { id: sessionId, userId, revokedAt: null }, data: { revokedAt: new Date() } });
}
