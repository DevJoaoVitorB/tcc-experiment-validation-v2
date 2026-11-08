import 'dotenv/config';

function requiredSecret(name: string): string {
  const value = process.env[name];
  if (!value || value.length < 32) {
    throw new Error(`${name} must be configured with at least 32 characters`);
  }
  return value;
}

export const config = {
  port: Number(process.env.PORT ?? 3000),
  nodeEnv: process.env.NODE_ENV ?? 'development',
  accessSecret: requiredSecret('JWT_ACCESS_SECRET'),
  refreshSecret: requiredSecret('JWT_REFRESH_SECRET'),
  accessExpiresIn: '15m' as const,
  refreshExpiresIn: '7d' as const
};

if (!Number.isInteger(config.port) || config.port < 1 || config.port > 65535) {
  throw new Error('PORT must be a valid TCP port');
}
