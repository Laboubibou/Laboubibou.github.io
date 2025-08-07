## Advanced Authentication Server

Features:
- Email/password auth with bcrypt
- Email verification
- MFA (TOTP) with QR code
- JWT access + refresh with rotation
- Sessions management and revocation
- Password reset flow
- Rate limiting, Helmet, CORS
- Email notifications (console by default)

### Quickstart

1. Install dependencies:

```bash
npm install
```

2. Copy env and run:

```bash
cp .env.example .env
npm run dev
```

3. Use the API under `http://localhost:3000/api`.

- POST `/api/auth/register` { email, password }
- GET `/api/auth/verify-email?token=...`
- POST `/api/auth/login` { email, password, totp? }
- POST `/api/auth/enable-mfa` { userId }
- POST `/api/auth/confirm-mfa` { userId, totp }
- POST `/api/auth/request-password-reset` { email }
- GET `/api/auth/reset-password?token=...`
- POST `/api/auth/reset-password` { token, newPassword }
- POST `/api/auth/refresh` { refreshToken }
- POST `/api/auth/logout` { refreshToken }
- GET `/api/auth/sessions?userId=...`
- POST `/api/auth/sessions/revoke` { userId, sessionId }

Emails are logged to console if `SMTP_JSON=1`.