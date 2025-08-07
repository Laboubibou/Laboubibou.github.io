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

app.get('/api/health', (req, res) => res.json({ ok: true }));
app.use('/api/auth', authLimiter, authRouter);

app.listen(config.port, () => {
  // eslint-disable-next-line no-console
  console.log(`Auth server listening on http://localhost:${config.port}`);
});