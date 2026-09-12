require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const path = require('path');
const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at BIGINT NOT NULL
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS game_state (
      user_id INTEGER PRIMARY KEY REFERENCES users(id),
      state_json TEXT NOT NULL,
      updated_at BIGINT NOT NULL
    );
  `);
}

const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '1mb' }));
app.use(session({
  secret: process.env.SESSION_SECRET || 'change-me-in-production',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    maxAge: 1000 * 60 * 60 * 24 * 30,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax'
  }
}));
app.use(express.static(path.join(__dirname, 'public')));

function requireAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'Не авторизован' });
  next();
}

function defaultState() {
  return {
    month: 1, dayInMonth: 1, totalDayCounter: 1, level: 0,
    lifetime: { calls: 0, meetingsBooked: 0, dealsClosed: 0, volume: 0, bestBookingMessages: null, bestStreak: 0 },
    currentStreak: 0, monthVolume: 0, prevMonthVolume: 0, newDealsBonusPool: 0,
    monthPlan: 400000, calendar: [], todaysLeads: []
  };
}

const USERNAME_RE = /^[a-zA-Zа-яА-ЯёЁ0-9_\- ]{2,32}$/;

// --- Auth ---

app.post('/api/register', async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: 'Укажи имя и пароль' });
    if (!USERNAME_RE.test(username)) return res.status(400).json({ error: 'Имя: 2-32 символа (буквы, цифры, пробел, дефис)' });
    if (String(password).length < 6) return res.status(400).json({ error: 'Пароль минимум 6 символов' });

    const existing = await pool.query('SELECT id FROM users WHERE username = $1', [username]);
    if (existing.rows.length) return res.status(409).json({ error: 'Это имя уже занято' });

    const hash = await bcrypt.hash(password, 10);
    const inserted = await pool.query(
      'INSERT INTO users (username, password_hash, created_at) VALUES ($1, $2, $3) RETURNING id',
      [username, hash, Date.now()]
    );
    const userId = inserted.rows[0].id;
    await pool.query(
      'INSERT INTO game_state (user_id, state_json, updated_at) VALUES ($1, $2, $3)',
      [userId, JSON.stringify(defaultState()), Date.now()]
    );

    req.session.userId = userId;
    req.session.username = username;
    res.json({ username });
  } catch (err) {
    console.error('Ошибка регистрации:', err);
    res.status(500).json({ error: 'Ошибка сервера при регистрации' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body || {};
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username || '']);
    const user = result.rows[0];
    if (!user) return res.status(401).json({ error: 'Неверное имя или пароль' });
    const ok = await bcrypt.compare(password || '', user.password_hash);
    if (!ok) return res.status(401).json({ error: 'Неверное имя или пароль' });
    req.session.userId = user.id;
    req.session.username = user.username;
    res.json({ username: user.username });
  } catch (err) {
    console.error('Ошибка входа:', err);
    res.status(500).json({ error: 'Ошибка сервера при входе' });
  }
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get('/api/me', (req, res) => {
  if (!req.session.userId) return res.json({ user: null });
  res.json({ user: { username: req.session.username } });
});

// --- Game state ---

app.get('/api/state', requireAuth, async (req, res) => {
  try {
    const result = await pool.query('SELECT state_json FROM game_state WHERE user_id = $1', [req.session.userId]);
    const row = result.rows[0];
    res.json({ state: row ? JSON.parse(row.state_json) : defaultState() });
  } catch (err) {
    console.error('Ошибка чтения прогресса:', err);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

app.post('/api/state', requireAuth, async (req, res) => {
  try {
    const { state } = req.body || {};
    if (!state) return res.status(400).json({ error: 'Нет данных состояния' });
    await pool.query(`
      INSERT INTO game_state (user_id, state_json, updated_at) VALUES ($1, $2, $3)
      ON CONFLICT (user_id) DO UPDATE SET state_json = EXCLUDED.state_json, updated_at = EXCLUDED.updated_at
    `, [req.session.userId, JSON.stringify(state), Date.now()]);
    res.json({ ok: true });
  } catch (err) {
    console.error('Ошибка сохранения прогресса:', err);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// --- Leaderboard (публичный, чтобы вся команда видела рейтинг) ---

app.get('/api/leaderboard', async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT u.username as username, g.state_json as state_json
      FROM game_state g JOIN users u ON u.id = g.user_id
    `);
    const entries = result.rows.map(r => {
      try {
        const s = JSON.parse(r.state_json);
        return {
          nickname: r.username,
          volume: (s.lifetime && s.lifetime.volume) || 0,
          deals: (s.lifetime && s.lifetime.dealsClosed) || 0,
          calls: (s.lifetime && s.lifetime.calls) || 0,
          bestStreak: (s.lifetime && s.lifetime.bestStreak) || 0,
          bestBookingMessages: s.lifetime ? s.lifetime.bestBookingMessages : null,
          level: s.level || 0
        };
      } catch (e) { return null; }
    }).filter(Boolean);
    res.json({ entries });
  } catch (err) {
    console.error('Ошибка чтения лидерборда:', err);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// --- Прокси к Claude API (ключ хранится только на сервере) ---

app.post('/api/chat', requireAuth, async (req, res) => {
  if (!process.env.ANTHROPIC_API_KEY) {
    return res.status(500).json({ error: 'ANTHROPIC_API_KEY не настроен на сервере. Добавь его в переменные окружения.' });
  }
  const { system, messages, max_tokens } = req.body || {};
  if (!Array.isArray(messages)) return res.status(400).json({ error: 'Нет сообщений' });
  try {
    const r = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': process.env.ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify({
        model: 'claude-sonnet-5',
        max_tokens: max_tokens || 1000,
        system,
        messages
      })
    });
    const data = await r.json();
    if (!r.ok) return res.status(r.status).json(data);
    res.json(data);
  } catch (err) {
    console.error('Ошибка обращения к Claude API:', err);
    res.status(500).json({ error: 'Ошибка обращения к ИИ' });
  }
});

app.get('/api/health', (req, res) => res.json({ ok: true }));

const PORT = process.env.PORT || 3000;
initDb()
  .then(() => {
    app.listen(PORT, () => console.log(`Сервер «Первая встреча» запущен на порту ${PORT}`));
  })
  .catch(err => {
    console.error('Не удалось инициализировать базу данных:', err);
    process.exit(1);
  });
