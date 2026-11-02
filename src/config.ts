import 'dotenv/config';

export const config = {
  port: Number(process.env.PORT ?? 3000),
  accessSecret: process.env.JWT_ACCESS_SECRET ?? 'development-access-secret-change-me',
  refreshSecret: process.env.JWT_REFRESH_SECRET ?? 'development-refresh-secret-change-me',
  accessTtl: 15 * 60,
  refreshTtl: 7 * 24 * 60 * 60,
  refreshTtlMs: 7 * 24 * 60 * 60 * 1000,
};
