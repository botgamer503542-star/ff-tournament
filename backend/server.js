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

const METHODS = ['bkash', 'nagad', 'rocket'];
const PHONE_RE = /^01\d{9}$/;

const app = express();
app.use(cors());
app.use(express.json({ limit: '200kb' }));

const wrap = fn => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch(err => {
    console.error(err);
    if (!res.headersSent) res.status(500).json({ error: 'সার্ভারে সমস্যা হয়েছে' });
  });

function bearer(req) {
  const h = req.headers.authorization || '';
  return h.startsWith('Bearer ') ? h.slice(7) : '';
}

function toInt(v, fallback = 0) {
  const n = parseInt(v, 10);
  return Number.isFinite(n) ? n : fallback;
}

async function ensureWallet(client, uid) {
  await client.query(
    'INSERT INTO wallets (user_id, balance) VALUES ($1, 0) ON CONFLICT (user_id) DO NOTHING',
    [uid]
  );
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
  await pool.query(
    'INSERT INTO wallets (user_id, balance) VALUES ($1, 0) ON CONFLICT (user_id) DO NOTHING',
    [rows[0].id]
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

app.get('/api/categories', wrap(async (req, res) => {
  const { rows } = await pool.query('SELECT id, name, slug FROM categories ORDER BY sort_order, id');
  res.json(rows);
}));

app.get('/api/wallet', requireUser, wrap(async (req, res) => {
  const { rows } = await pool.query('SELECT balance FROM wallets WHERE user_id = $1', [req.userId]);
  res.json({ balance: rows[0] ? rows[0].balance : 0 });
}));

app.get('/api/wallet/history', requireUser, wrap(async (req, res) => {
  const deposits = await pool.query(
    `SELECT id, method, amount, trx_id, status, created_at FROM deposits
     WHERE user_id = $1 ORDER BY id DESC LIMIT 30`, [req.userId]);
  const withdrawals = await pool.query(
    `SELECT id, method, amount, account_number, status, created_at FROM withdrawals
     WHERE user_id = $1 ORDER BY id DESC LIMIT 30`, [req.userId]);
  const transactions = await pool.query(
    `SELECT type, amount, note, created_at FROM transactions
     WHERE user_id = $1 ORDER BY id DESC LIMIT 40`, [req.userId]);
  res.json({ deposits: deposits.rows, withdrawals: withdrawals.rows, transactions: transactions.rows });
}));

app.post('/api/deposits', requireUser, wrap(async (req, res) => {
  const method = String(req.body.method || '');
  const amount = toInt(req.body.amount);
  const sender = String(req.body.sender_number || '').replace(/\s/g, '');
  const trx = String(req.body.trx_id || '').trim().toUpperCase();
  if (!METHODS.includes(method)) return res.status(400).json({ error: 'সঠিক মাধ্যম বাছুন' });
  if (amount < 20 || amount > 100000) return res.status(400).json({ error: 'ডিপোজিট ৳২০ থেকে ৳১,০০,০০০ এর মধ্যে হতে হবে' });
  if (!PHONE_RE.test(sender)) return res.status(400).json({ error: 'যে নম্বর থেকে পাঠিয়েছেন তা সঠিক দিন (01XXXXXXXXX)' });
  if (!/^[A-Z0-9]{6,30}$/.test(trx)) return res.status(400).json({ error: 'সঠিক Transaction ID দিন' });
  try {
    await pool.query(
      `INSERT INTO deposits (user_id, method, amount, sender_number, trx_id)
       VALUES ($1, $2, $3, $4, $5)`,
      [req.userId, method, amount, sender, trx]
    );
  } catch (e) {
    if (e.code === '23505') return res.status(409).json({ error: 'এই Transaction ID আগে জমা দেওয়া হয়েছে' });
    throw e;
  }
  res.json({ ok: true, message: 'ডিপোজিট অনুরোধ জমা হয়েছে। অ্যাডমিন যাচাই করে ব্যালেন্সে যোগ করবে।' });
}));

app.post('/api/withdrawals', requireUser, wrap(async (req, res) => {
  const method = String(req.body.method || '');
  const amount = toInt(req.body.amount);
  const account = String(req.body.account_number || '').replace(/\s/g, '');
  if (!METHODS.includes(method)) return res.status(400).json({ error: 'সঠিক মাধ্যম বাছুন' });
  if (amount < 50 || amount > 100000) return res.status(400).json({ error: 'উইথড্রয়াল ৳৫০ থেকে ৳১,০০,০০০ এর মধ্যে হতে হবে' });
  if (!PHONE_RE.test(account)) return res.status(400).json({ error: 'সঠিক মোবাইল নম্বর দিন (01XXXXXXXXX)' });

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await ensureWallet(client, req.userId);
    const w = await client.query('SELECT balance FROM wallets WHERE user_id = $1 FOR UPDATE', [req.userId]);
    if (w.rows[0].balance < amount) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'ব্যালেন্স যথেষ্ট নয়' });
    }
    const pend = await client.query(
      `SELECT COUNT(*)::int AS n FROM withdrawals WHERE user_id = $1 AND status = 'pending'`, [req.userId]);
    if (pend.rows[0].n >= 3) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'একসাথে সর্বোচ্চ ৩টি উইথড্রয়াল অপেক্ষমাণ থাকতে পারে' });
    }
    await client.query(
      'UPDATE wallets SET balance = balance - $1, updated_at = NOW() WHERE user_id = $2',
      [amount, req.userId]);
    await client.query(
      `INSERT INTO withdrawals (user_id, method, amount, account_number) VALUES ($1,$2,$3,$4)`,
      [req.userId, method, amount, account]);
    await client.query(
      `INSERT INTO transactions (user_id, type, amount, note) VALUES ($1, 'withdraw', $2, $3)`,
      [req.userId, -amount, `${method} উইথড্রয়াল`]);
    await client.query('COMMIT');
    res.json({ ok: true, message: 'উইথড্রয়াল অনুরোধ জমা হয়েছে। অ্যাডমিন পাঠানোর পর জানানো হবে।' });
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}));

// ---------- টুর্নামেন্ট (ইউজার) ----------

const TOURNAMENT_SELECT = `
  SELECT t.id, t.name, t.category_id, c.name AS category_name, c.slug AS category_slug,
         t.match_type, t.map_name, t.max_slots, t.per_kill, t.entry_fee, t.prize,
         t.starts_at, t.status, t.image_url,
         (SELECT COUNT(*)::int FROM registrations r WHERE r.tournament_id = t.id) AS joined,
         EXISTS (SELECT 1 FROM registrations r WHERE r.tournament_id = t.id AND r.user_id = $1) AS is_joined,
         t.room_released
  FROM tournaments t
  LEFT JOIN categories c ON c.id = t.category_id
`;

function publicTournament(r) {
  return {
    id: r.id, name: r.name, category_id: r.category_id,
    category_name: r.category_name, category_slug: r.category_slug,
    match_type: r.match_type, map_name: r.map_name, max_slots: r.max_slots,
    per_kill: r.per_kill, entry_fee: r.entry_fee, prize: r.prize,
    starts_at: r.starts_at, status: r.status, image_url: r.image_url,
    joined: r.joined, available: Math.max(0, r.max_slots - r.joined),
    is_joined: r.is_joined,
  };
}

app.get('/api/tournaments', requireUser, wrap(async (req, res) => {
  const params = [req.userId];
  let where = `WHERE t.status <> 'hidden'`;
  if (req.query.category) {
    params.push(String(req.query.category));
    where += ` AND c.slug = $${params.length}`;
  }
  const { rows } = await pool.query(
    `${TOURNAMENT_SELECT} ${where} ORDER BY t.starts_at NULLS LAST, t.id DESC`, params);
  res.json(rows.map(publicTournament));
}));

app.get('/api/tournaments/:id', requireUser, wrap(async (req, res) => {
  const { rows } = await pool.query(
    `${TOURNAMENT_SELECT} WHERE t.id = $2 AND t.status <> 'hidden'`,
    [req.userId, Number(req.params.id)]);
  if (!rows.length) return res.status(404).json({ error: 'টুর্নামেন্ট পাওয়া যায়নি' });
  const t = rows[0];
  const out = publicTournament(t);
  if (t.is_joined && t.room_released) {
    const r = await pool.query('SELECT room_id, room_password FROM tournaments WHERE id = $1', [t.id]);
    out.room_id = r.rows[0].room_id;
    out.room_password = r.rows[0].room_password;
  }
  res.json(out);
}));

// জয়েন: Free Fire আইডির নাম নেয়, ব্যালেন্স কাটে, সব এক লেনদেনে
app.post('/api/tournaments/:id/join', requireUser, wrap(async (req, res) => {
  const tid = Number(req.params.id);
  const ffName = String(req.body.ff_name || '').trim().slice(0, 30);
  if (ffName.length < 2) return res.status(400).json({ error: 'আপনার Free Fire আইডির নাম দিন' });

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const t = await client.query(
      'SELECT id, status, max_slots, entry_fee, name FROM tournaments WHERE id = $1 FOR UPDATE', [tid]);
    if (!t.rows.length) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'টুর্নামেন্ট পাওয়া যায়নি' });
    }
    const tour = t.rows[0];
    if (tour.status !== 'open') {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'এই টুর্নামেন্টে এখন জয়েন করা যাবে না' });
    }

    const dup = await client.query(
      'SELECT 1 FROM registrations WHERE user_id = $1 AND tournament_id = $2', [req.userId, tid]);
    if (dup.rowCount) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'আগে থেকেই জয়েন করা আছে' });
    }

    const cnt = await client.query(
      'SELECT COUNT(*)::int AS n FROM registrations WHERE tournament_id = $1', [tid]);
    if (cnt.rows[0].n >= tour.max_slots) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'স্লট পূর্ণ হয়ে গেছে' });
    }

    const fee = toInt(tour.entry_fee);
    if (fee > 0) {
      await ensureWallet(client, req.userId);
      const w = await client.query('SELECT balance FROM wallets WHERE user_id = $1 FOR UPDATE', [req.userId]);
      if (w.rows[0].balance < fee) {
        await client.query('ROLLBACK');
        return res.status(400).json({ error: `পর্যাপ্ত ব্যালেন্স নেই। এন্ট্রি ফি ৳${fee}` });
      }
      await client.query(
        'UPDATE wallets SET balance = balance - $1, updated_at = NOW() WHERE user_id = $2',
        [fee, req.userId]);
      await client.query(
        `INSERT INTO transactions (user_id, type, amount, note) VALUES ($1,'entry',$2,$3)`,
        [req.userId, -fee, tour.name]);
    }

    await client.query(
      'INSERT INTO registrations (user_id, tournament_id, ff_name) VALUES ($1, $2, $3)',
      [req.userId, tid, ffName]);
    await client.query('COMMIT');
    res.json({ ok: true, message: fee > 0 ? `জয়েন সফল! ৳${fee} কাটা হয়েছে` : 'জয়েন সফল!' });
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}));

app.get('/api/my-matches', requireUser, wrap(async (req, res) => {
  const { rows } = await pool.query(
    `SELECT t.id, t.name, c.name AS category_name, t.map_name, t.starts_at, t.status,
            t.room_released, t.room_id, t.room_password, t.prize, t.per_kill, r.ff_name
     FROM registrations r
     JOIN tournaments t ON t.id = r.tournament_id
     LEFT JOIN categories c ON c.id = t.category_id
     WHERE r.user_id = $1
     ORDER BY t.starts_at DESC NULLS LAST`, [req.userId]);
  res.json(rows.map(r => ({
    id: r.id, name: r.name, category_name: r.category_name, map_name: r.map_name,
    starts_at: r.starts_at, status: r.status, prize: r.prize, per_kill: r.per_kill,
    ff_name: r.ff_name,
    room_id: r.room_released ? r.room_id : null,
    room_password: r.room_released ? r.room_password : null,
  })));
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
    `SELECT u.id, u.name, u.ff_id, u.phone, u.is_banned, u.created_at,
            COALESCE(w.balance, 0) AS balance
     FROM users u LEFT JOIN wallets w ON w.user_id = u.id
     ORDER BY u.id DESC`);
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

app.post('/api/admin/users/:userId/balance', requireAdmin, wrap(async (req, res) => {
  const uid = Number(req.params.userId);
  const amount = toInt(req.body.amount);
  if (!amount) return res.status(400).json({ error: 'সঠিক পরিমাণ দিন' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const u = await client.query('SELECT 1 FROM users WHERE id = $1', [uid]);
    if (!u.rowCount) { await client.query('ROLLBACK'); return res.status(404).json({ error: 'ইউজার পাওয়া যায়নি' }); }
    await ensureWallet(client, uid);
    const cur = await client.query('SELECT balance FROM wallets WHERE user_id = $1 FOR UPDATE', [uid]);
    if (cur.rows[0].balance + amount < 0) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'ব্যালেন্স ঋণাত্মক হতে পারবে না' });
    }
    await client.query(
      'UPDATE wallets SET balance = balance + $1, updated_at = NOW() WHERE user_id = $2', [amount, uid]);
    await client.query(
      `INSERT INTO transactions (user_id, type, amount, note) VALUES ($1,$2,$3,$4)`,
      [uid, amount > 0 ? 'deposit' : 'adjust', amount, String(req.body.note || 'অ্যাডমিন সমন্বয়').slice(0, 100)]);
    await client.query('COMMIT');
    res.json({ ok: true });
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}));

// ---- ডিপোজিট যাচাই ----

app.get('/api/admin/deposits', requireAdmin, wrap(async (req, res) => {
  const st = ['pending', 'approved', 'rejected'].includes(req.query.status) ? req.query.status : 'pending';
  const { rows } = await pool.query(
    `SELECT d.*, u.name, u.phone, u.ff_id
     FROM deposits d JOIN users u ON u.id = d.user_id
     WHERE d.status = $1 ORDER BY d.created_at DESC LIMIT 200`, [st]);
  res.json(rows);
}));

app.post('/api/admin/deposits/:id/approve', requireAdmin, wrap(async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const d = await client.query(
      `UPDATE deposits SET status = 'approved', reviewed_at = NOW()
       WHERE id = $1 AND status = 'pending' RETURNING user_id, amount, method, trx_id`,
      [Number(req.params.id)]);
    if (!d.rows.length) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'অনুরোধটি পাওয়া যায়নি বা আগেই যাচাই হয়েছে' });
    }
    const { user_id, amount, method, trx_id } = d.rows[0];
    await ensureWallet(client, user_id);
    await client.query(
      'UPDATE wallets SET balance = balance + $1, updated_at = NOW() WHERE user_id = $2', [amount, user_id]);
    await client.query(
      `INSERT INTO transactions (user_id, type, amount, note) VALUES ($1,'deposit',$2,$3)`,
      [user_id, amount, `${method} ডিপোজিট (${trx_id})`]);
    await client.query('COMMIT');
    res.json({ ok: true });
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}));

app.post('/api/admin/deposits/:id/reject', requireAdmin, wrap(async (req, res) => {
  const r = await pool.query(
    `UPDATE deposits SET status = 'rejected', reviewed_at = NOW() WHERE id = $1 AND status = 'pending'`,
    [Number(req.params.id)]);
  if (!r.rowCount) return res.status(400).json({ error: 'অনুরোধটি পাওয়া যায়নি বা আগেই যাচাই হয়েছে' });
  res.json({ ok: true });
}));

// ---- উইথড্রয়াল পরিশোধ ----

app.get('/api/admin/withdrawals', requireAdmin, wrap(async (req, res) => {
  const st = ['pending', 'paid', 'rejected'].includes(req.query.status) ? req.query.status : 'pending';
  const { rows } = await pool.query(
    `SELECT w.*, u.name, u.phone, u.ff_id
     FROM withdrawals w JOIN users u ON u.id = w.user_id
     WHERE w.status = $1 ORDER BY w.created_at DESC LIMIT 200`, [st]);
  res.json(rows);
}));

app.post('/api/admin/withdrawals/:id/paid', requireAdmin, wrap(async (req, res) => {
  const r = await pool.query(
    `UPDATE withdrawals SET status = 'paid', reviewed_at = NOW() WHERE id = $1 AND status = 'pending'`,
    [Number(req.params.id)]);
  if (!r.rowCount) return res.status(400).json({ error: 'অনুরোধটি পাওয়া যায়নি বা আগেই যাচাই হয়েছে' });
  res.json({ ok: true });
}));

app.post('/api/admin/withdrawals/:id/reject', requireAdmin, wrap(async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const w = await client.query(
      `UPDATE withdrawals SET status = 'rejected', reviewed_at = NOW()
       WHERE id = $1 AND status = 'pending' RETURNING user_id, amount, method`,
      [Number(req.params.id)]);
    if (!w.rows.length) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'অনুরোধটি পাওয়া যায়নি বা আগেই যাচাই হয়েছে' });
    }
    const { user_id, amount, method } = w.rows[0];
    await ensureWallet(client, user_id);
    await client.query(
      'UPDATE wallets SET balance = balance + $1, updated_at = NOW() WHERE user_id = $2', [amount, user_id]);
    await client.query(
      `INSERT INTO transactions (user_id, type, amount, note) VALUES ($1,'adjust',$2,$3)`,
      [user_id, amount, `${method} উইথড্রয়াল বাতিল, টাকা ফেরত`]);
    await client.query('COMMIT');
    res.json({ ok: true });
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}));

// ---- ক্যাটাগরি ও টুর্নামেন্ট (অ্যাডমিন) ----

app.get('/api/admin/categories', requireAdmin, wrap(async (req, res) => {
  const { rows } = await pool.query('SELECT id, name, slug FROM categories ORDER BY sort_order, id');
  res.json(rows);
}));

function tournamentBody(b) {
  const category = toInt(b.category_id, 0);
  return {
    name: String(b.name || '').trim(),
    category_id: category || null,
    match_type: String(b.match_type || 'BR').slice(0, 30),
    map_name: String(b.map_name || 'Bermuda').slice(0, 40),
    max_slots: Math.max(1, toInt(b.max_slots, 48)),
    per_kill: Math.max(0, toInt(b.per_kill, 0)),
    starts_at: b.starts_at || null,
    entry_fee: Math.max(0, toInt(b.entry_fee, 0)),
    prize: String(b.prize || '').slice(0, 100),
    image_url: b.image_url ? String(b.image_url).slice(0, 500) : null,
    status: ['open', 'closed', 'hidden'].includes(b.status) ? b.status : 'open',
  };
}

app.get('/api/admin/tournaments', requireAdmin, wrap(async (req, res) => {
  const { rows } = await pool.query(
    `SELECT t.*, (SELECT COUNT(*)::int FROM registrations r WHERE r.tournament_id = t.id) AS joined
     FROM tournaments t ORDER BY t.id DESC`);
  res.json(rows);
}));

app.post('/api/admin/tournaments', requireAdmin, wrap(async (req, res) => {
  const t = tournamentBody(req.body);
  if (!t.name) return res.status(400).json({ error: 'টুর্নামেন্টের নাম দিন' });
  const { rows } = await pool.query(
    `INSERT INTO tournaments
       (name, category_id, match_type, map_name, max_slots, per_kill, starts_at, entry_fee, prize, image_url, status)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING *`,
    [t.name, t.category_id, t.match_type, t.map_name, t.max_slots, t.per_kill,
     t.starts_at, t.entry_fee, t.prize, t.image_url, t.status]);
  res.json(rows[0]);
}));

app.put('/api/admin/tournaments/:id', requireAdmin, wrap(async (req, res) => {
  const t = tournamentBody(req.body);
  if (!t.name) return res.status(400).json({ error: 'টুর্নামেন্টের নাম দিন' });
  const { rows } = await pool.query(
    `UPDATE tournaments SET name=$1, category_id=$2, match_type=$3, map_name=$4, max_slots=$5,
       per_kill=$6, starts_at=$7, entry_fee=$8, prize=$9, image_url=$10, status=$11
     WHERE id=$12 RETURNING *`,
    [t.name, t.category_id, t.match_type, t.map_name, t.max_slots, t.per_kill,
     t.starts_at, t.entry_fee, t.prize, t.image_url, t.status, Number(req.params.id)]);
  if (!rows.length) return res.status(404).json({ error: 'টুর্নামেন্ট পাওয়া যায়নি' });
  res.json(rows[0]);
}));

app.put('/api/admin/tournaments/:id/room', requireAdmin, wrap(async (req, res) => {
  const release = req.body.release === true;
  const { rows } = await pool.query(
    `UPDATE tournaments SET room_id = $1, room_password = $2, room_released = $3
     WHERE id = $4 RETURNING id, room_released`,
    [
      req.body.room_id ? String(req.body.room_id).slice(0, 50) : null,
      req.body.room_password ? String(req.body.room_password).slice(0, 50) : null,
      release,
      Number(req.params.id),
    ]);
  if (!rows.length) return res.status(404).json({ error: 'টুর্নামেন্ট পাওয়া যায়নি' });
  res.json({ ok: true, room_released: rows[0].room_released });
}));

app.delete('/api/admin/tournaments/:id', requireAdmin, wrap(async (req, res) => {
  await pool.query('DELETE FROM tournaments WHERE id = $1', [Number(req.params.id)]);
  res.json({ ok: true });
}));

// সেটিংস: সংখ্যাযুক্ত নামও গ্রহণ করে (যেমন banner_cs_2v2, banner_1v1)
app.put('/api/admin/settings', requireAdmin, wrap(async (req, res) => {
  for (const [key, value] of Object.entries(req.body || {})) {
    if (!/^[a-z0-9_]{1,50}$/.test(key)) continue;
    await pool.query(
      `INSERT INTO settings (key, value) VALUES ($1, $2)
       ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`,
      [key, String(value).slice(0, 500)]);
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
