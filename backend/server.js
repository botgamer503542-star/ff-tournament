// language: JavaScript (Node.js), file: server.js, target: Render Web Service
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { pool, initDb } = require('./db');

const JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
if (!JWT_SECRET || !ADMIN_PASSWORD) {
  console.warn('WARNING: JWT_SECRET বা ADMIN_PASSWORD Environment-এ সেট করা নেই');
}

const app = express();
app.use(cors());
app.use(express.json({ limit: '100kb' }));

// async রাউটের ত্রুটি ধরে রাখে, যাতে সার্ভার বন্ধ না হয়
const wrap = fn => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch(err => {
    console.error(err);
    if (!res.headersSent) res.status(500).json({ error: 'সার্ভারে সমস্যা হয়েছে' });
  });

function bearer(req) {
  const h = req.headers.authorization || '';
  return h.startsWith('Bearer ') ? h.slice(7) : '';
}

// ---------- মিডলওয়্যার ----------

function requireAdmin(req, res, next) {
  try {
    const p = jwt.verify(bearer(req), JWT_SECRET);
    if (p.role !== 'admin') throw new Error('not admin');
    next();
  } catch {
    res.status(401).json({ error: 'অনুমতি নেই, আবার অ্যাডমিন লগইন করুন' });
  }
}

const requireUser = wrap(async (req, res, next) => {
  let p;
  try {
    p = jwt.verify(bearer(req), JWT_SECRET);
  } catch {
    return res.status(401).json({ error: 'লগইনের মেয়াদ শেষ, আবার লগইন করুন' });
  }
  const { rows } = await pool.query('SELECT id, is_banned FROM users WHERE id = $1', [p.userId]);
  if (!rows.length) return res.status(401).json({ error: 'অনুমতি নেই, আবার লগইন করুন' });
  if (rows[0].is_banned) return res.status(403).json({ error: 'আপনাকে ব্যান করা হয়েছে' });
  req.userId = rows[0].id;
  next();
});

// ---------- হেলথ চেক ----------

app.get('/api/health', (req, res) => res.send('ok'));

// ---------- ইউজার রাউট ----------

app.post('/api/register', wrap(async (req, res) => {
  const name = String(req.body.name || '').trim();
  const ff_id = String(req.body.ff_id || '').trim();
  const phone = String(req.body.phone || '').trim();
  const password = String(req.body.password || '');
  if (!name || !ff_id || !phone || password.length < 4) {
    return res.status(400).json({ error: 'সব তথ্য দিন (পাসওয়ার্ড কমপক্ষে ৪ অক্ষর)' });
  }
  const exists = await pool.query('SELECT 1 FROM users WHERE phone = $1', [phone]);
  if (exists.rowCount) {
    return res.status(409).json({ error: 'এই ফোন নম্বরে আগে থেকেই অ্যাকাউন্ট আছে' });
  }
  const hash = await bcrypt.hash(password, 10);
  const { rows } = await pool.query(
    `INSERT INTO users (name, ff_id, phone, password_hash)
     VALUES ($1, $2, $3, $4) RETURNING id, name, ff_id, phone`,
    [name, ff_id, phone, hash]
  );
  res.json(rows[0]);
}));

app.post('/api/login', wrap(async (req, res) => {
  const phone = String(req.body.phone || '').trim();
  const password = String(req.body.password || '');
  const { rows } = await pool.query('SELECT * FROM users WHERE phone = $1', [phone]);
  if (!rows.length || !(await bcrypt.compare(password, rows[0].password_hash))) {
    return res.status(401).json({ error: 'ভুল ফোন নম্বর বা পাসওয়ার্ড' });
  }
  if (rows[0].is_banned) return res.status(403).json({ error: 'আপনাকে ব্যান করা হয়েছে' });
  const token = jwt.sign({ userId: rows[0].id }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, user: { id: rows[0].id, name: rows[0].name } });
}));

app.get('/api/settings', wrap(async (req, res) => {
  const { rows } = await pool.query('SELECT key, value FROM settings');
  res.json(Object.fromEntries(rows.map(r => [r.key, r.value])));
}));

app.get('/api/tournaments', requireUser, wrap(async (req, res) => {
  const { rows } = await pool.query(
    `SELECT * FROM tournaments WHERE status <> 'hidden'
     ORDER BY starts_at NULLS LAST, id DESC`
  );
  res.json(rows);
}));

app.post('/api/tournaments/:id/join', requireUser, wrap(async (req, res) => {
  const tid = Number(req.params.id);
  const t = await pool.query('SELECT status FROM tournaments WHERE id = $1', [tid]);
  if (!t.rows.length) return res.status(404).json({ error: 'টুর্নামেন্ট পাওয়া যায়নি' });
  if (t.rows[0].status !== 'open') {
    return res.status(400).json({ error: 'এই টুর্নামেন্টে এখন জয়েন করা যাবে না' });
  }
  const r = await pool.query(
    'INSERT INTO registrations (user_id, tournament_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
    [req.userId, tid]
  );
  if (!r.rowCount) return res.status(400).json({ error: 'আগে থেকেই জয়েন করা আছে' });
  res.json({ ok: true });
}));

// ---------- অ্যাডমিন রাউট ----------

app.post('/api/admin/login', (req, res) => {
  if (!ADMIN_PASSWORD || req.body.password !== ADMIN_PASSWORD) {
    return res.status(401).json({ error: 'ভুল পাসওয়ার্ড' });
  }
  const token = jwt.sign({ role: 'admin' }, JWT_SECRET, { expiresIn: '12h' });
  res.json({ token });
});

app.get('/api/admin/users', requireAdmin, wrap(async (req, res) => {
  const { rows } = await pool.query(
    'SELECT id, name, ff_id, phone, is_banned, created_at FROM users ORDER BY id DESC'
  );
  res.json(rows);
}));

app.post('/api/admin/ban/:userId', requireAdmin, wrap(async (req, res) => {
  const r = await pool.query('UPDATE users SET is_banned = TRUE WHERE id = $1', [Number(req.params.userId)]);
  if (!r.rowCount) return res.status(404).json({ error: 'ইউজার পাওয়া যায়নি' });
  res.json({ ok: true });
}));

app.post('/api/admin/unban/:userId', requireAdmin, wrap(async (req, res) => {
  const r = await pool.query('UPDATE users SET is_banned = FALSE WHERE id = $1', [Number(req.params.userId)]);
  if (!r.rowCount) return res.status(404).json({ error: 'ইউজার পাওয়া যায়নি' });
  res.json({ ok: true });
}));

function tournamentBody(b) {
  return {
    name: String(b.name || '').trim(),
    starts_at: b.starts_at || null,
    entry_fee: Math.max(0, parseInt(b.entry_fee, 10) || 0),
    prize: String(b.prize || ''),
    status: ['open', 'closed', 'hidden'].includes(b.status) ? b.status : 'open',
  };
}

app.get('/api/admin/tournaments', requireAdmin, wrap(async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM tournaments ORDER BY id DESC');
  res.json(rows);
}));

app.post('/api/admin/tournaments', requireAdmin, wrap(async (req, res) => {
  const t = tournamentBody(req.body);
  if (!t.name) return res.status(400).json({ error: 'টুর্নামেন্টের নাম দিন' });
  const { rows } = await pool.query(
    `INSERT INTO tournaments (name, starts_at, entry_fee, prize, status)
     VALUES ($1, $2, $3, $4, $5) RETURNING *`,
    [t.name, t.starts_at, t.entry_fee, t.prize, t.status]
  );
  res.json(rows[0]);
}));

app.put('/api/admin/tournaments/:id', requireAdmin, wrap(async (req, res) => {
  const t = tournamentBody(req.body);
  if (!t.name) return res.status(400).json({ error: 'টুর্নামেন্টের নাম দিন' });
  const { rows } = await pool.query(
    `UPDATE tournaments SET name=$1, starts_at=$2, entry_fee=$3, prize=$4, status=$5
     WHERE id=$6 RETURNING *`,
    [t.name, t.starts_at, t.entry_fee, t.prize, t.status, Number(req.params.id)]
  );
  if (!rows.length) return res.status(404).json({ error: 'টুর্নামেন্ট পাওয়া যায়নি' });
  res.json(rows[0]);
}));

app.delete('/api/admin/tournaments/:id', requireAdmin, wrap(async (req, res) => {
  await pool.query('DELETE FROM tournaments WHERE id = $1', [Number(req.params.id)]);
  res.json({ ok: true });
}));

app.put('/api/admin/settings', requireAdmin, wrap(async (req, res) => {
  for (const [key, value] of Object.entries(req.body || {})) {
    if (!/^[a-z_]{1,50}$/.test(key)) continue;
    await pool.query(
      `INSERT INTO settings (key, value) VALUES ($1, $2)
       ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`,
      [key, String(value)]
    );
  }
  res.json({ ok: true });
}));

// ---------- চালু করা ----------

const PORT = process.env.PORT || 3000;
initDb()
  .then(() => app.listen(PORT, () => console.log(`Server চালু: ${PORT}`)))
  .catch(err => {
    console.error('ডেটাবেস শুরু করা যায়নি:', err);
    process.exit(1);
  });
