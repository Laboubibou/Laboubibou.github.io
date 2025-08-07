import nodemailer from 'nodemailer';
import { config } from './config.js';

let transporter;
if (config.smtp.jsonTransport) {
  transporter = nodemailer.createTransport({ jsonTransport: true });
} else {
  transporter = nodemailer.createTransport({
    host: config.smtp.host,
    port: config.smtp.port,
    secure: config.smtp.port === 465,
    auth: config.smtp.user ? { user: config.smtp.user, pass: config.smtp.pass } : undefined
  });
}

export async function sendEmail(to, subject, html) {
  const info = await transporter.sendMail({
    from: config.smtp.from,
    to,
    subject,
    html
  });
  return info;
}

export function buildVerificationEmail(link) {
  return `
    <p>Merci de confirmer votre adresse email.</p>
    <p><a href="${link}">Vérifier mon email</a></p>
    <p>Si vous n'êtes pas à l'origine de cette action, ignorez cet email.</p>
  `;
}

export function buildPasswordResetEmail(link) {
  return `
    <p>Vous avez demandé à réinitialiser votre mot de passe.</p>
    <p><a href="${link}">Réinitialiser le mot de passe</a></p>
    <p>Ce lien expirera sous 60 minutes.</p>
  `;
}

export function buildNewLoginNotification(dateIso, ip, ua) {
  return `
    <p>Nouvelle connexion détectée le ${new Date(dateIso).toLocaleString()}.</p>
    <p>IP: ${ip || 'inconnue'}</p>
    <p>Agent: ${ua || 'inconnu'}</p>
    <p>Si ce n'était pas vous, changez votre mot de passe et révoquez les sessions.</p>
  `;
}