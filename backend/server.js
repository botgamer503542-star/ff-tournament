// language: JavaScript (Node.js), file: server.js, target: Render Web Service
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { pool, initDb } = require('./db');

const app = express();
app.use(cors());
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;

// ---------- মিডলওয়্যার ----------

function requireAdmin(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : '';
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    if (payload.role !== 'admin') throw new Error('not admin');
    next();
  } catch {
    res.status(401).json({ error: 'অনুমতি নেই' });
  }
}

async function requireUser(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : '';
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const { rows } = await pool.query(
      'SELECT id, is_banned FROM users WHERE id = $1',
      [payload.userId]
    );
    if (!rows.length) return res.status(401).json({ error: 'অনুমতি নেই' });
    if (rows[0].is_banned) return res.status(403).json({ error: 'আপনাকে ব্যান করা হয়েছে' });
    req.userId = rows[0].id;
    next();
  } catch {
    res.status(401).json({ error: 'অনুমতি নেই' });
  }
}

// ---------- হেলথ চেক ----------

app.get('/api/health', (req, res) => res.send('ok'));

// ---------- ইউজার রাউট ----------

app.post('/api/register', async (req, res) => {
  const { name, ff_id, phone, password } = req.body;
  if (!name || !ff_id || !phone || !password) {
    return res.status(400).json({ error: 'সব তথ্য দিন' });
  }
  try {
    const hash = await bcrypt.hash(password, 10);
    const { rows } = await pool.query(
      `INSERT INTO users (name, ff_id, phone, password_hash)
       VALUES ($1, $2, $3, $4) RETURNING id, name, ff_id, phone`,
      [name, ff_id, phone, hash]
    );
    res.json(rows[0]);
  } catch (e) {
    res.status(500).json({ error: 'রেজিস্ট্রেশন ব্যর্থ' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { phone, password } = req.body;
    const { rows } = await pool.query('SELECT * FROM users WHERE phone = $1', [phone]);
    if (!rows.length) return res.status(401).json({ error: 'ভুল তথ্য' });
    const ok = await bcrypt.compare(password, rows[0].password_hash);
    if (!ok) return res.status(401).json({ error: 'ভুল তথ্য' });
    if (rows[0].is_banned) return res.status(403).json({ error: 'আপনাকে ব্যান করা হয়েছে' });
    const token = jwt.sign({ userId: rows[0].id }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, user: { id: rows[0].id, name: rows[0].name } });
  } catch {
    res.status(500).json({ error: 'লগইন ব্যর্থ' });
  }
});

app.get('/api/settings', async (req, res) => {
  const { rows } = await pool.query('SELECT key, value FROM settings');
  const out = {};
  rows.forEach(r => (out[r.key] = r.value));
  res.json(out);
});

app.get('/api/tournaments', requireUser, async (req, res) => {
  const { rows } = await pool.query(
    'SELECT * FROM tournaments WHERE status != $1 ORDER BY starts_at',
    ['hidden']
  );
  res.json(rows);
});

app.post('/api/tournaments/:id/join', requireUser, async (req, res) => {
  try {
    await pool.query(
      'INSERT INTO registrations (user_id, tournament_id) VALUES ($1, $2)',
      [req.userId, req.params.id]
    );
    res.json({ ok: true });
  } catch {
    res.status(400).json({ error: 'আগে থেকেই জয়েন করা আছে' });
  }
});

// ---------- অ্যাডমিন রাউট ----------

app.post('/api/admin/login', (req, res) => {
  if (req.body.password !== ADMIN_PASSWORD) {
    return res.status(401).json({ error: 'ভুল পাসওয়ার্ড' });
  }
  const token = jwt.sign({ role: 'admin' }, JWT_SECRET, { expiresIn: '12h' });
  res.json({ token });
});

app.get('/api/admin/users', requireAdmin, async (req, res) => {
  const { rows } = await pool.query(
    'SELECT id, name, ff_id, phone, is_banned, created_at FROM users ORDER BY id DESC'
  );
  res.json(rows);
});

app.post('/api/admin/ban/:userId', requireAdmin, async (req, res) => {
  await pool.query('UPDATE users SET is_banned = TRUE WHERE id = $1', [req.params.userId]);
  res.json({ ok: true });
});

app.post('/api/admin/unban/:userId', requireAdmin, async (req, res) => {
  await pool.query('UPDATE users SET is_banned = FALSE WHERE id = $1', [req.params.userId]);
  res.json({ ok: true });
});

app.post('/api/admin/tournaments', requireAdmin, async (req, res) => {
  const { name, starts_at, entry_fee, prize, status } = req.body;
  const { rows } = await pool.query(
    `INSERT INTO tournaments (name, starts_at, entry_fee, prize, status)
     VALUES ($1, $2, $3, $4, $5) RETURNING *`,
    [name, starts_at || null, entry_fee || 0, prize || '', status || 'open']
  );
  res.json(rows[0]);
});

app.put('/api/admin/tournaments/:id', requireAdmin, async (req, res) => {
  const { name, starts_at, entry_fee, prize, status } = req.body;
  const { rows } = await pool.query(
    `UPDATE tournaments SET name=$1, starts_at=$2, entry_fee=$3, prize=$4, status=$5
     WHERE id=$6 RETURNING *`,
    [name, starts_at || null, entry_fee || 0, prize || '', status || 'open', req.params.id]
  );
  res.json(rows[0]);
});

app.delete('/api/admin/tournaments/:id', requireAdmin, async (req, res) => {
  await pool.query('DELETE FROM tournaments WHERE id = $1', [req.params.id]);
  res.json({ ok: true });
});

app.put('/api/admin/settings', requireAdmin, async (req, res) => {
  for (const [key, value] of Object.entries(req.body)) {
    await pool.query(
      `INSERT INTO settings (key, value) VALUES ($1, $2)
       ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`,
      [key, String(value)]
    );
  }
  res.json({ ok: true });
});

// ---------- চালু করা ----------

const PORT = process.env.PORT || 3000;
initDb().then(() => {
  app.listen(PORT, () => console.log(`Server চালু: ${PORT}`));
});
