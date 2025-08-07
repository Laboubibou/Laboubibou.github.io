import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import { config } from './config.js';
import { router as authRouter } from './authRoutes.js';
import { authLimiter } from './middleware/auth.js';
import './db.js';

const app = express();
app.use(helmet());
app.use(cors({ origin: '*', credentials: false }));
app.use(express.json());

app.get('/', (req, res) => {
  res.sendFile('index.html', { root: '/workspace' });
});
app.get('/auth', (req, res) => {
  res.sendFile('auth.html', { root: '/workspace' });
});

app.get('/api/health', (req, res) => res.json({ ok: true }));
app.use('/api/auth', authLimiter, authRouter);

// Simple demo leaderboard API (mock)
app.get('/api/leaderboard', (req, res) => {
  res.json({
    points: [
      { rank: 1, player: 'NovaRider', platform: 'PC', event: 'Urban Freestyle', discipline: 'bike', score: 98450, date: '2025-06-28' },
      { rank: 2, player: 'Shiro', platform: 'PlayStation', event: 'Urban Freestyle', discipline: 'bike', score: 96120, date: '2025-06-21' },
      { rank: 3, player: 'Lynx', platform: 'Xbox', event: 'Urban Freestyle', discipline: 'bike', score: 94410, date: '2025-06-20' },
    ],
    time: [
      { rank: 1, player: 'NovaRider', platform: 'PC', event: 'Redwood Sprint', discipline: 'bike', timeMs: 112340, date: '2025-06-22' },
      { rank: 2, player: 'Shiro', platform: 'PlayStation', event: 'Redwood Sprint', discipline: 'bike', timeMs: 113280, date: '2025-06-24' },
      { rank: 3, player: 'Lynx', platform: 'Xbox', event: 'Redwood Sprint', discipline: 'bike', timeMs: 113990, date: '2025-06-26' },
    ],
  });
});

app.listen(config.port, () => {
  // eslint-disable-next-line no-console
  console.log(`Auth server listening on http://localhost:${config.port}`);
});