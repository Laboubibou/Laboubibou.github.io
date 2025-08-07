import express from 'express';
import bcrypt from 'bcrypt';
import crypto from 'crypto';
import speakeasy from 'speakeasy';
import QRCode from 'qrcode';
import { all, get, run, addAuditLog } from './db.js';
import { config } from './config.js';
import { createAccessToken, createRefreshToken, verifyRefreshToken } from './middleware/auth.js';
import { sendEmail, buildVerificationEmail, buildPasswordResetEmail, buildNewLoginNotification } from './email.js';

export const router = express.Router();

function nowIso() { return new Date().toISOString(); }
function plusSecondsIso(seconds) { return new Date(Date.now() + seconds * 1000).toISOString(); }

function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

function getClientIp(req) {
  return req.headers['x-forwarded-for']?.toString().split(',')[0]?.trim() || req.socket.remoteAddress || null;
}

router.post('/register', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'missing_fields' });
  const existing = get('SELECT id FROM users WHERE email = @email', { email: email.toLowerCase() });
  if (existing) return res.status(409).json({ error: 'email_in_use' });
  const passwordHash = await bcrypt.hash(password, 12);
  const info = run('INSERT INTO users (email, password_hash) VALUES (@email, @hash)', { email: email.toLowerCase(), hash: passwordHash });
  const userId = info.lastInsertRowid;
  addAuditLog(userId, 'register', getClientIp(req), req.headers['user-agent'], null);
  // Send verification email
  const token = crypto.randomUUID().replace(/-/g, '') + crypto.randomBytes(16).toString('hex');
  const expiresAt = plusSecondsIso(60 * 60 * 24);
  run(`INSERT INTO email_verification_tokens (user_id, token, expires_at) VALUES (@userId, @token, @exp)`, { userId, token, exp: expiresAt });
  const link = `${config.appBaseUrl}/api/auth/verify-email?token=${token}`;
  await sendEmail(email, 'Vérification de votre email', buildVerificationEmail(link));
  return res.json({ ok: true });
});

router.get('/verify-email', (req, res) => {
  const token = req.query.token?.toString();
  if (!token) return res.status(400).send('Token manquant');
  const row = get('SELECT * FROM email_verification_tokens WHERE token = @token', { token });
  if (!row) return res.status(400).send('Token invalide');
  if (new Date(row.expires_at) < new Date()) return res.status(400).send('Token expiré');
  run('UPDATE users SET email_verified = 1, updated_at = datetime("now") WHERE id = @id', { id: row.user_id });
  run('DELETE FROM email_verification_tokens WHERE id = @id', { id: row.id });
  addAuditLog(row.user_id, 'email_verified', null, null, null);
  return res.send('Email vérifié. Vous pouvez fermer cette page.');
});

router.post('/login', async (req, res) => {
  const { email, password, totp } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'missing_fields' });
  const user = get('SELECT * FROM users WHERE email = @email', { email: email.toLowerCase() });
  if (!user) {
    addAuditLog(null, 'login_failed', getClientIp(req), req.headers['user-agent'], { email });
    return res.status(401).json({ error: 'invalid_credentials' });
  }
  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) {
    addAuditLog(user.id, 'login_failed', getClientIp(req), req.headers['user-agent'], null);
    return res.status(401).json({ error: 'invalid_credentials' });
  }
  if (!user.email_verified) {
    return res.status(403).json({ error: 'email_not_verified' });
  }
  if (user.mfa_enabled) {
    if (!totp) {
      return res.status(401).json({ error: 'mfa_required' });
    }
    const verified = speakeasy.totp.verify({
      secret: user.mfa_secret,
      encoding: 'base32',
      token: String(totp),
      window: 1
    });
    if (!verified) return res.status(401).json({ error: 'invalid_totp' });
  }

  const accessToken = createAccessToken({ sub: user.id, email: user.email });
  const refreshToken = createRefreshToken({ sub: user.id, email: user.email });
  // persist refresh token hash as a session
  const refreshHash = hashToken(refreshToken);
  const expiresAt = plusSecondsIso(config.refreshTokenTtlSec);
  run(`INSERT INTO sessions (user_id, refresh_token_hash, user_agent, ip_address, expires_at)
       VALUES (@uid, @hash, @ua, @ip, @exp)`,
    { uid: user.id, hash: refreshHash, ua: req.headers['user-agent'], ip: getClientIp(req), exp: expiresAt }
  );

  addAuditLog(user.id, 'login_success', getClientIp(req), req.headers['user-agent'], null);
  // Send new login notification
  await sendEmail(user.email, 'Nouvelle connexion', buildNewLoginNotification(nowIso(), getClientIp(req), req.headers['user-agent']));

  return res.json({ accessToken, refreshToken });
});

router.post('/enable-mfa', (req, res) => {
  const { userId } = req.body; // For demo; in real apps require auth
  if (!userId) return res.status(400).json({ error: 'missing_user_id' });
  const user = get('SELECT * FROM users WHERE id = @id', { id: userId });
  if (!user) return res.status(404).json({ error: 'user_not_found' });
  const secret = speakeasy.generateSecret({ name: 'AdvancedAuthApp' });
  const otpauthUrl = secret.otpauth_url;
  const secretBase32 = secret.base32;
  run('UPDATE users SET mfa_secret = @sec, updated_at = datetime("now") WHERE id = @id', { sec: secretBase32, id: userId });
  QRCode.toDataURL(otpauthUrl, (err, dataUrl) => {
    if (err) return res.status(500).json({ error: 'qrcode_error' });
    return res.json({ otpauthUrl, qrImageDataUrl: dataUrl, secret: secretBase32 });
  });
});

router.post('/confirm-mfa', (req, res) => {
  const { userId, totp } = req.body; // For demo; in real apps require auth
  if (!userId || !totp) return res.status(400).json({ error: 'missing_fields' });
  const user = get('SELECT * FROM users WHERE id = @id', { id: userId });
  if (!user || !user.mfa_secret) return res.status(400).json({ error: 'mfa_not_initialized' });
  const ok = speakeasy.totp.verify({ secret: user.mfa_secret, encoding: 'base32', token: String(totp), window: 1 });
  if (!ok) return res.status(400).json({ error: 'invalid_totp' });
  run('UPDATE users SET mfa_enabled = 1, updated_at = datetime("now") WHERE id = @id', { id: userId });
  addAuditLog(userId, 'mfa_enabled', null, null, null);
  return res.json({ ok: true });
});

router.post('/request-password-reset', (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'missing_email' });
  const user = get('SELECT * FROM users WHERE email = @email', { email: email.toLowerCase() });
  if (user) {
    const token = crypto.randomUUID().replace(/-/g, '') + crypto.randomBytes(16).toString('hex');
    const expiresAt = plusSecondsIso(60 * 60);
    run('INSERT INTO password_reset_tokens (user_id, token, expires_at) VALUES (@uid, @token, @exp)', { uid: user.id, token, exp: expiresAt });
    const link = `${config.appBaseUrl}/api/auth/reset-password?token=${token}`;
    sendEmail(user.email, 'Réinitialisation du mot de passe', buildPasswordResetEmail(link));
    addAuditLog(user.id, 'password_reset_requested', getClientIp(req), req.headers['user-agent'], null);
  }
  return res.json({ ok: true });
});

router.get('/reset-password', (req, res) => {
  const token = req.query.token?.toString();
  if (!token) return res.status(400).send('Token manquant');
  const row = get('SELECT * FROM password_reset_tokens WHERE token = @token', { token });
  if (!row) return res.status(400).send('Token invalide');
  if (new Date(row.expires_at) < new Date()) return res.status(400).send('Token expiré');
  return res.send('Token valide. Faites un POST /api/auth/reset-password avec token et newPassword.');
});

router.post('/reset-password', async (req, res) => {
  const { token, newPassword } = req.body;
  if (!token || !newPassword) return res.status(400).json({ error: 'missing_fields' });
  const row = get('SELECT * FROM password_reset_tokens WHERE token = @token', { token });
  if (!row) return res.status(400).json({ error: 'invalid_token' });
  if (new Date(row.expires_at) < new Date()) return res.status(400).json({ error: 'expired_token' });
  if (row.used) return res.status(400).json({ error: 'token_used' });
  const passwordHash = await bcrypt.hash(newPassword, 12);
  run('UPDATE users SET password_hash = @hash, updated_at = datetime("now") WHERE id = @id', { hash: passwordHash, id: row.user_id });
  run('UPDATE password_reset_tokens SET used = 1 WHERE id = @id', { id: row.id });
  addAuditLog(row.user_id, 'password_reset_success', null, null, null);
  return res.json({ ok: true });
});

router.post('/refresh', (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken) return res.status(400).json({ error: 'missing_refresh_token' });
  let payload;
  try {
    payload = verifyRefreshToken(refreshToken);
  } catch (e) {
    return res.status(401).json({ error: 'invalid_refresh_token' });
  }
  const hash = hashToken(refreshToken);
  const session = get('SELECT * FROM sessions WHERE refresh_token_hash = @hash', { hash });
  if (!session || session.revoked) return res.status(401).json({ error: 'invalid_session' });
  if (new Date(session.expires_at) < new Date()) return res.status(401).json({ error: 'session_expired' });

  // rotate refresh token
  const newRefreshToken = createRefreshToken({ sub: payload.sub, email: payload.email });
  const newHash = hashToken(newRefreshToken);
  const newExpires = plusSecondsIso(config.refreshTokenTtlSec);
  run('UPDATE sessions SET refresh_token_hash = @hash, last_used_at = datetime("now"), expires_at = @exp WHERE id = @id', { hash: newHash, exp: newExpires, id: session.id });
  addAuditLog(payload.sub, 'refresh_rotated', null, null, null);

  const accessToken = createAccessToken({ sub: payload.sub, email: payload.email });
  return res.json({ accessToken, refreshToken: newRefreshToken });
});

router.post('/logout', (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken) return res.status(400).json({ error: 'missing_refresh_token' });
  const hash = hashToken(refreshToken);
  const session = get('SELECT * FROM sessions WHERE refresh_token_hash = @hash', { hash });
  if (session) {
    run('UPDATE sessions SET revoked = 1 WHERE id = @id', { id: session.id });
    addAuditLog(session.user_id, 'logout', null, null, null);
  }
  return res.json({ ok: true });
});

router.get('/sessions', (req, res) => {
  const userId = parseInt(req.query.userId, 10);
  if (!userId) return res.status(400).json({ error: 'missing_user_id' });
  const sessions = all('SELECT id, user_agent, ip_address, created_at, last_used_at, expires_at, revoked FROM sessions WHERE user_id = @uid ORDER BY created_at DESC', { uid: userId });
  return res.json({ sessions });
});

router.post('/sessions/revoke', (req, res) => {
  const { userId, sessionId } = req.body;
  if (!userId || !sessionId) return res.status(400).json({ error: 'missing_fields' });
  const session = get('SELECT * FROM sessions WHERE id = @id AND user_id = @uid', { id: sessionId, uid: userId });
  if (!session) return res.status(404).json({ error: 'session_not_found' });
  run('UPDATE sessions SET revoked = 1 WHERE id = @id', { id: sessionId });
  addAuditLog(userId, 'session_revoked', null, null, { sessionId });
  return res.json({ ok: true });
});