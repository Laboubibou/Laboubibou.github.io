import dotenv from 'dotenv';
dotenv.config();

export const config = {
  port: parseInt(process.env.PORT || '3000', 10),
  jwtAccessSecret: process.env.JWT_ACCESS_SECRET || 'dev_access_secret_change_me',
  jwtRefreshSecret: process.env.JWT_REFRESH_SECRET || 'dev_refresh_secret_change_me',
  accessTokenTtlSec: parseInt(process.env.ACCESS_TOKEN_TTL_SEC || '900', 10),
  refreshTokenTtlSec: parseInt(process.env.REFRESH_TOKEN_TTL_SEC || '2592000', 10),
  dbPath: process.env.DB_PATH || '/workspace/data/auth.db',
  appBaseUrl: process.env.APP_BASE_URL || 'http://localhost:3000',
  smtp: {
    host: process.env.SMTP_HOST,
    port: process.env.SMTP_PORT ? parseInt(process.env.SMTP_PORT, 10) : undefined,
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
    from: process.env.MAIL_FROM || 'no-reply@example.test',
    jsonTransport: process.env.SMTP_JSON === '1' || !process.env.SMTP_HOST
  }
};