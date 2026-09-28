const express = require('express');
const session = require('express-session');
const PgSession = require('connect-pg-simple')(session);
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const { Pool } = require('pg');

const app = express();
const port = process.env.PORT || 3000;
const CRON_SECRET = process.env.CRON_SECRET || '';
const SESSION_SECRET = process.env.SESSION_SECRET || 'change-me-please';

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// ---------------------------------------------------------------
// Database initialization
// ---------------------------------------------------------------
async function initDb() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS notifications (
        id SERIAL PRIMARY KEY,
        phone VARCHAR(50),
        app VARCHAR(255),
        title TEXT,
        body TEXT,
        device_id INTEGER,
        timestamp TIMESTAMPTZ DEFAULT NOW(),
        raw_payload JSONB
      )
    `);
    await pool.query(`ALTER TABLE notifications ADD COLUMN IF NOT EXISTS phone VARCHAR(50)`);
    await pool.query(`ALTER TABLE notifications ADD COLUMN IF NOT EXISTS device_id INTEGER`);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        created_at TIMESTAMPTZ DEFAULT NOW()
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS devices (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        name VARCHAR(100) NOT NULL,
        phone_number VARCHAR(50),
        token VARCHAR(64) UNIQUE NOT NULL,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        last_seen_at TIMESTAMPTZ
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS "session" (
        "sid" varchar NOT NULL COLLATE "default",
        "sess" json NOT NULL,
        "expire" timestamp(6) NOT NULL,
        CONSTRAINT "session_pkey" PRIMARY KEY ("sid") NOT DEFERRABLE INITIALLY IMMEDIATE
      );
      CREATE INDEX IF NOT EXISTS "IDX_session_expire" ON "session" ("expire");
    `);

    console.log('Database tables initialized.');
  } catch (err) {
    console.error('Error initializing database:', err);
  }
}
initDb();

// ---------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------
app.set('trust proxy', 1);

app.use(session({
  store: new PgSession({ pool: pool, tableName: 'session', createTableIfMissing: true }),
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: true,
    maxAge: 30 * 24 * 60 * 60 * 1000
  }
}));

// ---------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------
function generateToken() {
  return crypto.randomBytes(24).toString('base64url');
}

function escapeHtml(str) {
  return String(str == null ? '' : str)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#039;');
}

function requireAuth(req, res, next) {
  if (req.session && req.session.userId) return next();
  if (req.path.startsWith('/api/') || req.path === '/webhook' || req.path.startsWith('/webhook/')) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  res.redirect('/login');
}

// ---------------------------------------------------------------
// SSE
// ---------------------------------------------------------------
const sseClients = new Set();

app.get('/api/stream', requireAuth, (req, res) => {
  res.set({
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
    'X-Accel-Buffering': 'no'
  });
  res.flushHeaders();
  res.write('event: hello\ndata: {"ok":true}\n\n');
  sseClients.add(res);
  console.log('SSE client connected. Total:', sseClients.size);

  const ping = setInterval(() => { try { res.write(': ping\n\n'); } catch (e) {} }, 25000);
  req.on('close', () => { clearInterval(ping); sseClients.delete(res); console.log('SSE client disconnected. Total:', sseClients.size); });
});

function broadcast(event, data) {
  const payload = 'event: ' + event + '\ndata: ' + JSON.stringify(data) + '\n\n';
  for (const client of sseClients) {
    try { client.write(payload); } catch (e) { sseClients.delete(client); }
  }
}

// ---------------------------------------------------------------
// Webhook
// ---------------------------------------------------------------
app.post('/webhook/:token', async (req, res) => {
  try {
    const token = req.params.token;
    const deviceResult = await pool.query('SELECT id, user_id FROM devices WHERE token = $1', [token]);
    if (deviceResult.rowCount === 0) {
      return res.status(404).json({ error: 'Unknown device token' });
    }
    const device = deviceResult.rows[0];

    const payload = req.body;
    console.log('=== INCOMING WEBHOOK ===');
    console.log('Device:', device.id, 'Body:', JSON.stringify(payload, null, 2));
    console.log('========================');

    const inserted = await pool.query(
      'INSERT INTO notifications (phone, app, title, body, device_id, raw_payload) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, phone, app, title, body, device_id, timestamp',
      [
        payload.phone || null,
        payload.app || null,
        payload.title || null,
        payload.body || null,
        device.id,
        JSON.stringify(payload)
      ]
    );

    await pool.query('UPDATE devices SET last_seen_at = NOW() WHERE id = $1', [device.id]);

    broadcast('notification', inserted.rows[0]);
    res.status(200).send('OK');
  } catch (err) {
    console.error('Error processing webhook:', err);
    res.status(500).send('Internal Server Error');
  }
});

// ---------------------------------------------------------------
// Auth routes
// ---------------------------------------------------------------
app.get('/signup', (req, res) => {
  if (req.session && req.session.userId) return res.redirect('/');
  res.send(renderAuthPage('signup', null));
});

app.post('/signup', async (req, res) => {
  const { email, password, confirm } = req.body;
  try {
    if (!email || !password) return res.status(400).send(renderAuthPage('signup', 'Email and password are required.'));
    if (password !== confirm) return res.status(400).send(renderAuthPage('signup', 'Passwords do not match.'));
    if (password.length < 8) return res.status(400).send(renderAuthPage('signup', 'Password must be at least 8 characters.'));

    const existing = await pool.query('SELECT id FROM users WHERE email = $1', [email.toLowerCase()]);
    if (existing.rowCount > 0) return res.status(400).send(renderAuthPage('signup', 'That email is already registered.'));

    const hash = await bcrypt.hash(password, 12);
    const inserted = await pool.query(
      'INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id, email',
      [email.toLowerCase(), hash]
    );

    req.session.userId = inserted.rows[0].id;
    req.session.email = inserted.rows[0].email;
    res.redirect('/devices');
  } catch (err) {
    console.error('Signup error:', err);
    res.status(500).send(renderAuthPage('signup', 'Something went wrong. Try again.'));
  }
});

app.get('/login', (req, res) => {
  if (req.session && req.session.userId) return res.redirect('/');
  res.send(renderAuthPage('login', null));
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    if (!email || !password) return res.status(400).send(renderAuthPage('login', 'Enter your email and password.'));

    const result = await pool.query('SELECT id, email, password_hash FROM users WHERE email = $1', [email.toLowerCase()]);
    if (result.rowCount === 0) return res.status(401).send(renderAuthPage('login', 'Invalid email or password.'));

    const user = result.rows[0];
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).send(renderAuthPage('login', 'Invalid email or password.'));

    req.session.userId = user.id;
    req.session.email = user.email;
    res.redirect('/');
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).send(renderAuthPage('login', 'Something went wrong. Try again.'));
  }
});

app.get('/logout', (req, res) => req.session.destroy(() => res.redirect('/login')));
app.post('/logout', (req, res) => req.session.destroy(() => res.redirect('/login')));

// ---------------------------------------------------------------
// Devices API
// ---------------------------------------------------------------
app.get('/api/devices', requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, name, phone_number, token, created_at, last_seen_at FROM devices WHERE user_id = $1 ORDER BY created_at DESC',
      [req.session.userId]
    );
    res.json({ devices: result.rows });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/devices', requireAuth, async (req, res) => {
  try {
    const { name, phone_number } = req.body;
    if (!name || !name.trim()) return res.status(400).json({ error: 'Device name is required.' });

    const token = generateToken();
    const result = await pool.query(
      'INSERT INTO devices (user_id, name, phone_number, token) VALUES ($1, $2, $3, $4) RETURNING id, name, phone_number, token, created_at, last_seen_at',
      [req.session.userId, name.trim(), (phone_number || '').trim() || null, token]
    );
    res.json({ device: result.rows[0] });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.patch('/api/devices/:id', requireAuth, async (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    const { name, phone_number } = req.body;
    const check = await pool.query('SELECT id FROM devices WHERE id = $1 AND user_id = $2', [id, req.session.userId]);
    if (check.rowCount === 0) return res.status(404).json({ error: 'Not found' });

    const result = await pool.query(
      'UPDATE devices SET name = COALESCE($1, name), phone_number = COALESCE($2, phone_number) WHERE id = $3 RETURNING id, name, phone_number, token, created_at, last_seen_at',
      [name ? name.trim() : null, phone_number !== undefined ? ((phone_number || '').trim() || null) : null, id]
    );
    res.json({ device: result.rows[0] });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/devices/:id/rotate', requireAuth, async (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    const check = await pool.query('SELECT id FROM devices WHERE id = $1 AND user_id = $2', [id, req.session.userId]);
    if (check.rowCount === 0) return res.status(404).json({ error: 'Not found' });

    const newToken = generateToken();
    const result = await pool.query(
      'UPDATE devices SET token = $1 WHERE id = $2 RETURNING id, name, phone_number, token, created_at, last_seen_at',
      [newToken, id]
    );
    res.json({ device: result.rows[0] });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/devices/:id', requireAuth, async (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    const check = await pool.query('SELECT id FROM devices WHERE id = $1 AND user_id = $2', [id, req.session.userId]);
    if (check.rowCount === 0) return res.status(404).json({ error: 'Not found' });

    await pool.query('DELETE FROM devices WHERE id = $1', [id]);
    res.json({ deleted: 1 });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ---------------------------------------------------------------
// Protected API
// ---------------------------------------------------------------
app.get('/count', requireAuth, async (req, res) => {
  try {
    const total = await pool.query('SELECT COUNT(*) FROM notifications');
    const latest = await pool.query('SELECT id, phone, app, title, body, device_id, timestamp FROM notifications ORDER BY id DESC LIMIT 10');
    res.json({ total: parseInt(total.rows[0].count, 10), latest: latest.rows });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/notifications', requireAuth, async (req, res) => {
  try {
    const { app: appFilter, q, device_id } = req.query;
    let query = 'SELECT id, phone, app, title, body, device_id, timestamp FROM notifications';
    const conditions = [];
    const values = [];

    if (appFilter) { values.push(appFilter); conditions.push('app = $' + values.length); }
    if (device_id) { values.push(parseInt(device_id, 10)); conditions.push('device_id = $' + values.length); }
    if (q) { values.push('%' + q + '%'); conditions.push('(title ILIKE $' + values.length + ' OR body ILIKE $' + values.length + ')'); }
    if (conditions.length) query += ' WHERE ' + conditions.join(' AND ');
    query += ' ORDER BY timestamp DESC LIMIT 200';

    const result = await pool.query(query, values);
    res.json({ notifications: result.rows });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/apps', requireAuth, async (req, res) => {
  try {
    const result = await pool.query('SELECT DISTINCT app FROM notifications WHERE app IS NOT NULL ORDER BY app');
    res.json({ apps: result.rows.map(r => r.app) });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/notifications/:id', requireAuth, async (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (isNaN(id)) return res.status(400).json({ error: 'Invalid id' });
    const result = await pool.query('DELETE FROM notifications WHERE id = $1', [id]);
    broadcast('deleted', { id });
    res.json({ deleted: result.rowCount });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/notifications', requireAuth, async (req, res) => {
  try {
    const result = await pool.query('DELETE FROM notifications');
    broadcast('cleared', {});
    res.json({ deleted: result.rowCount });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/prune', async (req, res) => {
  if (CRON_SECRET && req.query.secret !== CRON_SECRET) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const days = parseInt(req.query.days, 10) || 7;
    const result = await pool.query("DELETE FROM notifications WHERE timestamp < NOW() - ($1 || ' days')::interval", [days]);
    broadcast('cleared', {});
    res.json({ deleted: result.rowCount, olderThanDays: days });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ---------------------------------------------------------------
// Pages
// ---------------------------------------------------------------
app.get('/', requireAuth, (req, res) => res.send(renderDashboard(req.session.email || 'user')));
app.get('/devices', requireAuth, (req, res) => res.send(renderDevicesPage(req.session.email || 'user')));

// ===============================================================
// SVG ICON SET
// ===============================================================
const ICONS = {
  search: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>',
  refresh: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/></svg>',
  plus: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>',
  sun: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M6.34 17.66l-1.41 1.41M19.07 4.93l-1.41 1.41"/></svg>',
  moon: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>',
  bell: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/></svg>',
  clock: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>',
  zap: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>',
  smartphone: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="5" y="2" width="14" height="20" rx="2" ry="2"/><line x1="12" y1="18" x2="12.01" y2="18"/></svg>',
  whatsapp: '<svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor" xmlns="http://www.w3.org/2000/svg"><path d="M17.472 14.382c-.297-.149-1.758-.867-2.03-.967-.273-.099-.471-.148-.67.15-.197.297-.767.966-.94 1.164-.173.199-.347.223-.644.075-.297-.15-1.255-.463-2.39-1.475-.883-.788-1.48-1.761-1.653-2.059-.173-.297-.018-.458.13-.606.134-.133.298-.347.446-.52.149-.174.198-.298.298-.497.099-.198.05-.371-.025-.52-.075-.149-.669-1.612-.916-2.207-.242-.579-.487-.5-.669-.51-.173-.008-.371-.01-.57-.01-.198 0-.52.074-.792.372-.272.297-1.04 1.016-1.04 2.479 0 1.462 1.065 2.875 1.213 3.074.149.198 2.096 3.2 5.077 4.487.709.306 1.262.489 1.694.625.712.227 1.36.195 1.871.118.571-.085 1.758-.719 2.006-1.413.248-.694.248-1.289.173-1.413-.074-.124-.272-.198-.57-.347m-5.421 7.403h-.004a9.87 9.87 0 01-5.031-1.378l-.361-.214-3.741.982.998-3.648-.235-.374a9.86 9.86 0 01-1.51-5.26c.001-5.45 4.436-9.884 9.888-9.884 2.64 0 5.122 1.03 6.988 2.898a9.825 9.825 0 012.893 6.994c-.003 5.45-4.437 9.884-9.885 9.884m8.413-18.297A11.815 11.815 0 0012.05 0C5.495 0 .16 5.335.157 11.892c0 2.096.547 4.142 1.588 5.945L.057 24l6.305-1.654a11.882 11.882 0 005.683 1.448h.005c6.554 0 11.89-5.335 11.893-11.893a11.821 11.821 0 00-3.48-8.413Z"/></svg>',
  logout: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>'
};

// ===============================================================
// SHARED STYLES
// ===============================================================
const BASE_STYLES = `
  :root, [data-theme="dark"] {
    --bg: #0b0d14;
    --bg-2: #0f121b;
    --card: #151925;
    --card-hover: #1b2030;
    --text: #eef1f8;
    --muted: #8b93a7;
    --accent: #6c8cff;
    --accent-2: #8c5cff;
    --accent-glow: rgba(108, 140, 255, 0.35);
    --danger: #ef4444;
    --success: #22c55e;
    --warning: #f59e0b;
    --border: #232838;
    --border-strong: #2f3548;
    --shadow: 0 8px 32px rgba(0,0,0,0.45);
    --shadow-sm: 0 2px 8px rgba(0,0,0,0.35);
    --input-bg: #0d1017;
    --pill-bg: #2a2f42;
  }
  [data-theme="light"] {
    --bg: #f4f6fb;
    --bg-2: #eef1f8;
    --card: #ffffff;
    --card-hover: #f8fafc;
    --text: #0f172a;
    --muted: #64748b;
    --accent: #4f6bff;
    --accent-2: #7c3aed;
    --accent-glow: rgba(79, 107, 255, 0.25);
    --danger: #dc2626;
    --success: #16a34a;
    --warning: #d97706;
    --border: #e2e8f0;
    --border-strong: #cbd5e1;
    --shadow: 0 8px 32px rgba(15,23,42,0.08);
    --shadow-sm: 0 2px 8px rgba(15,23,42,0.06);
    --input-bg: #ffffff;
    --pill-bg: #e2e8f0;
  }
  * { box-sizing: border-box; }
  html, body { margin: 0; padding: 0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Inter", "Segoe UI", Roboto, sans-serif;
    background: var(--bg);
    color: var(--text);
    min-height: 100vh;
    transition: background 0.25s ease, color 0.25s ease;
    -webkit-font-smoothing: antialiased;
  }
  a { color: var(--accent); }
  ::-webkit-scrollbar { width: 10px; height: 10px; }
  ::-webkit-scrollbar-track { background: transparent; }
  ::-webkit-scrollbar-thumb { background: var(--border-strong); border-radius: 5px; }
  ::-webkit-scrollbar-thumb:hover { background: var(--muted); }

  .theme-toggle {
    background: var(--card);
    border: 1px solid var(--border);
    color: var(--text);
    width: 36px;
    height: 36px;
    border-radius: 10px;
    cursor: pointer;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    padding: 0;
    transition: border-color 0.15s, background 0.15s, transform 0.1s;
  }
  .theme-toggle svg { display: block; }
  .theme-toggle:hover { border-color: var(--accent); transform: scale(1.05); }
  .theme-toggle:active { transform: scale(0.95); }
`;

const NAV_STYLES = `
  header.site-header {
    position: sticky;
    top: 0;
    z-index: 50;
    background: color-mix(in srgb, var(--bg) 88%, transparent);
    backdrop-filter: blur(14px);
    -webkit-backdrop-filter: blur(14px);
    border-bottom: 1px solid var(--border);
    padding: 14px 24px;
  }
  .header-inner {
    max-width: 1180px;
    margin: 0 auto;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 16px;
    flex-wrap: wrap;
  }
  .brand {
    display: flex;
    align-items: center;
    gap: 10px;
    font-weight: 700;
    font-size: 1.08em;
    letter-spacing: -0.01em;
  }
  .brand .logo {
    width: 28px; height: 28px;
    border-radius: 8px;
    background: linear-gradient(135deg, var(--accent), var(--accent-2));
    display: flex; align-items: center; justify-content: center;
    color: white; font-size: 0.9em; font-weight: 800;
    box-shadow: 0 4px 12px var(--accent-glow);
  }
  .brand .dot {
    width: 8px; height: 8px;
    border-radius: 50%;
    background: var(--success);
    box-shadow: 0 0 10px var(--success);
    animation: pulse 2s infinite;
    margin-left: -4px;
  }
  @keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: 0.35; } }
  .nav { display: flex; gap: 4px; }
  .nav-link {
    color: var(--muted);
    text-decoration: none;
    padding: 7px 14px;
    border-radius: 9px;
    font-size: 0.9em;
    font-weight: 500;
    transition: background 0.15s, color 0.15s;
  }
  .nav-link:hover { color: var(--text); background: var(--card); }
  .nav-link.active {
    color: var(--text);
    background: color-mix(in srgb, var(--accent) 18%, transparent);
  }
  .right-info {
    display: flex;
    align-items: center;
    gap: 10px;
    font-size: 0.85em;
    color: var(--muted);
  }
  .user-email { color: var(--text); font-weight: 500; }
  .logout {
    color: var(--muted);
    text-decoration: none;
    border: 1px solid var(--border);
    padding: 6px 12px;
    border-radius: 9px;
    transition: border-color 0.15s, color 0.15s;
    font-size: 0.95em;
    display: inline-flex;
    align-items: center;
    gap: 6px;
  }
  .logout svg { display: block; }
  .logout:hover { border-color: var(--danger); color: var(--danger); }
`;

const FOOTER_STYLES = `
  footer.site-footer {
    margin-top: 48px;
    padding: 28px 24px 36px;
    border-top: 1px solid var(--border);
    color: var(--muted);
    font-size: 0.82em;
    text-align: center;
    line-height: 1.7;
  }
  footer.site-footer .whatsapp-link {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    background: rgba(37,211,102,0.12);
    color: #25D366;
    padding: 8px 16px;
    border-radius: 999px;
    font-weight: 600;
    margin-bottom: 10px;
    text-decoration: none;
    transition: background 0.15s, transform 0.1s;
  }
  footer.site-footer .whatsapp-link:hover {
    background: rgba(37,211,102,0.22);
    transform: translateY(-1px);
  }
  footer.site-footer .whatsapp-link svg { display: block; }
  footer.site-footer .credit { margin-top: 4px; color: var(--muted); }
  footer.site-footer .credit strong { color: var(--text); font-weight: 600; }
  footer.site-footer .version {
    display: inline-block;
    font-size: 0.85em;
    color: var(--muted);
    border: 1px solid var(--border);
    padding: 2px 10px;
    border-radius: 999px;
    margin-top: 8px;
  }
`;

const FOOTER_HTML = `
  <footer class="site-footer">
    <div>
      <a class="whatsapp-link" href="https://wa.me/254745361106" target="_blank" rel="noopener">
        ${ICONS.whatsapp}
        WhatsApp: 0745 361 106
      </a>
    </div>
    <div class="credit">
      Created by <strong>Gitau Computer Solutions</strong> and <strong>Gitau Tech Labs</strong>
    </div>
    <div class="version">Version 1.0</div>
  </footer>
`;

// Theme bootstrap — must run before paint to avoid flash
const THEME_BOOTSTRAP = `
  (function() {
    try {
      var saved = localStorage.getItem('theme');
      var theme = saved || (window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark');
      document.documentElement.setAttribute('data-theme', theme);
    } catch (e) {
      document.documentElement.setAttribute('data-theme', 'dark');
    }
  })();
`;

// Theme toggle wiring
const THEME_TOGGLE_SCRIPT = `
  function setupThemeToggle() {
    var btn = document.getElementById('theme-toggle');
    if (!btn) return;
    var SUN_SVG = ${JSON.stringify(ICONS.sun)};
    var MOON_SVG = ${JSON.stringify(ICONS.moon)};
    function updateIcon() {
      var theme = document.documentElement.getAttribute('data-theme');
      btn.innerHTML = theme === 'light' ? MOON_SVG : SUN_SVG;
      btn.title = theme === 'light' ? 'Switch to dark mode' : 'Switch to light mode';
    }
    btn.addEventListener('click', function() {
      var current = document.documentElement.getAttribute('data-theme');
      var next = current === 'light' ? 'dark' : 'light';
      document.documentElement.setAttribute('data-theme', next);
      try { localStorage.setItem('theme', next); } catch (e) {}
      updateIcon();
    });
    updateIcon();
  }
`;

// ===============================================================
// AUTH PAGE
// ===============================================================
function renderAuthPage(mode, error) {
  const isSignup = mode === 'signup';
  const title = isSignup ? 'Create your account' : 'Welcome back';
  const sub = isSignup ? 'Sign up to start tracking your devices' : 'Sign in to view your dashboard';
  const submitLabel = isSignup ? 'Create account' : 'Sign in';
  const switchText = isSignup ? 'Already have an account?' : "Don't have an account?";
  const switchLink = isSignup ? '/login' : '/signup';
  const switchLabel = isSignup ? 'Sign in' : 'Create one';

  return `<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${title} — Notification Dashboard</title>
<script>${THEME_BOOTSTRAP}</script>
<style>
  ${BASE_STYLES}
  ${FOOTER_STYLES}
  body {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    padding: 20px;
    background:
      radial-gradient(circle at 20% 0%, color-mix(in srgb, var(--accent) 12%, transparent), transparent 40%),
      radial-gradient(circle at 80% 100%, color-mix(in srgb, var(--accent-2) 10%, transparent), transparent 40%),
      var(--bg);
  }
  .top-bar {
    position: fixed;
    top: 16px;
    right: 16px;
    z-index: 10;
  }
  .auth-card {
    width: 100%;
    max-width: 420px;
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 18px;
    padding: 36px 32px;
    box-shadow: var(--shadow);
    margin: auto 0;
  }
  .logo-badge {
    width: 52px; height: 52px;
    border-radius: 14px;
    background: linear-gradient(135deg, var(--accent), var(--accent-2));
    display: flex; align-items: center; justify-content: center;
    color: white; font-size: 1.4em; font-weight: 800;
    box-shadow: 0 8px 24px var(--accent-glow);
    margin-bottom: 18px;
  }
  .auth-card h1 {
    margin: 0 0 6px 0;
    font-size: 1.55em;
    font-weight: 700;
    letter-spacing: -0.02em;
  }
  .subtitle {
    color: var(--muted);
    font-size: 0.92em;
    margin-bottom: 26px;
  }
  label {
    display: block;
    font-size: 0.82em;
    font-weight: 600;
    color: var(--muted);
    margin-bottom: 8px;
    margin-top: 16px;
    letter-spacing: 0.02em;
  }
  input {
    width: 100%;
    padding: 12px 14px;
    border-radius: 11px;
    border: 1px solid var(--border);
    background: var(--input-bg);
    color: var(--text);
    font-size: 0.95em;
    outline: none;
    transition: border-color 0.15s, box-shadow 0.15s;
    font-family: inherit;
  }
  input:focus {
    border-color: var(--accent);
    box-shadow: 0 0 0 3px var(--accent-glow);
  }
  button.submit {
    width: 100%;
    margin-top: 26px;
    padding: 13px;
    background: linear-gradient(135deg, var(--accent), var(--accent-2));
    color: white;
    border: none;
    border-radius: 11px;
    font-size: 1em;
    font-weight: 600;
    cursor: pointer;
    transition: transform 0.1s, box-shadow 0.15s;
    box-shadow: 0 6px 20px var(--accent-glow);
    font-family: inherit;
  }
  button.submit:hover { transform: translateY(-1px); box-shadow: 0 8px 26px var(--accent-glow); }
  button.submit:active { transform: translateY(0); }
  .error {
    background: color-mix(in srgb, var(--danger) 15%, transparent);
    color: var(--danger);
    border: 1px solid color-mix(in srgb, var(--danger) 40%, transparent);
    padding: 11px 14px;
    border-radius: 10px;
    font-size: 0.88em;
    margin-bottom: 18px;
  }
  .switch {
    text-align: center;
    margin-top: 22px;
    font-size: 0.9em;
    color: var(--muted);
  }
  .switch a { color: var(--accent); text-decoration: none; font-weight: 600; }
  .switch a:hover { text-decoration: underline; }
</style>
</head>
<body>
  <div class="top-bar">
    <button class="theme-toggle" id="theme-toggle" aria-label="Toggle theme"></button>
  </div>

  <form class="auth-card" method="POST" action="${isSignup ? '/signup' : '/login'}">
    <div class="logo-badge">N</div>
    <h1>${title}</h1>
    <div class="subtitle">${sub}</div>
    ${error ? '<div class="error">' + escapeHtml(error) + '</div>' : ''}

    <label for="email">Email</label>
    <input type="email" id="email" name="email" required autocomplete="email" autofocus placeholder="you@example.com">

    <label for="password">Password</label>
    <input type="password" id="password" name="password" required
      autocomplete="${isSignup ? 'new-password' : 'current-password'}"
      minlength="${isSignup ? '8' : '1'}"
      placeholder="${isSignup ? 'At least 8 characters' : 'Your password'}">

    ${isSignup ? `
    <label for="confirm">Confirm password</label>
    <input type="password" id="confirm" name="confirm" required autocomplete="new-password" minlength="8" placeholder="Repeat password">
    ` : ''}

    <button class="submit" type="submit">${submitLabel}</button>
    <div class="switch">${switchText} <a href="${switchLink}">${switchLabel}</a></div>
  </form>

  ${FOOTER_HTML}

<script>
  ${THEME_TOGGLE_SCRIPT}
  setupThemeToggle();
</script>
</body>
</html>`;
}

// ===============================================================
// NAV BAR
// ===============================================================
function navBar(email, active) {
  const cls = (path) => active === path ? 'nav-link active' : 'nav-link';
  return `
  <header class="site-header">
    <div class="header-inner">
      <div class="brand">
        <div class="logo">N</div>
        <div class="dot"></div>
        Notification Dashboard
      </div>
      <nav class="nav">
        <a class="${cls('dashboard')}" href="/">Dashboard</a>
        <a class="${cls('devices')}" href="/devices">Devices</a>
      </nav>
      <div class="right-info">
        <span class="user-email">${escapeHtml(email)}</span>
        <button class="theme-toggle" id="theme-toggle" aria-label="Toggle theme"></button>
        <a class="logout" href="/logout">${ICONS.logout} Sign out</a>
      </div>
    </div>
  </header>`;
}

// ===============================================================
// DEVICES PAGE
// ===============================================================
function renderDevicesPage(email) {
  return `<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>My Devices — Notification Dashboard</title>
<script>${THEME_BOOTSTRAP}</script>
<style>
  ${BASE_STYLES}
  ${NAV_STYLES}
  ${FOOTER_STYLES}
  main { max-width: 1180px; margin: 0 auto; padding: 32px 24px; }
  .page-head { margin-bottom: 28px; }
  .page-head h1 { margin: 0 0 6px 0; font-size: 1.6em; letter-spacing: -0.02em; }
  .page-head .subtitle { color: var(--muted); font-size: 0.95em; }

  .create-card {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 16px;
    padding: 22px 24px;
    margin-bottom: 28px;
    box-shadow: var(--shadow-sm);
  }
  .section-title {
    margin: 0 0 16px 0;
    font-size: 1.05em;
    font-weight: 600;
    display: flex;
    align-items: center;
    gap: 10px;
  }
  .section-icon {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 28px;
    height: 28px;
    border-radius: 8px;
    background: linear-gradient(135deg, var(--accent), var(--accent-2));
    color: white;
    box-shadow: 0 4px 12px var(--accent-glow);
  }
  .section-icon svg { display: block; }
  .form-row { display: flex; gap: 10px; flex-wrap: wrap; }
  .form-row input {
    flex: 1;
    min-width: 180px;
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 11px;
    padding: 11px 14px;
    color: var(--text);
    font-size: 0.95em;
    outline: none;
    transition: border-color 0.15s, box-shadow 0.15s;
    font-family: inherit;
  }
  .form-row input:focus {
    border-color: var(--accent);
    box-shadow: 0 0 0 3px var(--accent-glow);
  }
  .form-row button {
    background: linear-gradient(135deg, var(--accent), var(--accent-2));
    color: white;
    border: none;
    border-radius: 11px;
    padding: 11px 20px;
    font-size: 0.95em;
    font-weight: 600;
    cursor: pointer;
    box-shadow: 0 4px 16px var(--accent-glow);
    transition: transform 0.1s;
    font-family: inherit;
  }
  .form-row button:hover { transform: translateY(-1px); }
  .form-row button:active { transform: translateY(0); }

  .devices { display: flex; flex-direction: column; gap: 16px; }
  .device {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 16px;
    padding: 20px 22px;
    box-shadow: var(--shadow-sm);
    transition: border-color 0.15s;
  }
  .device:hover { border-color: var(--border-strong); }
  .device-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    flex-wrap: wrap;
    margin-bottom: 12px;
  }
  .device-name { font-size: 1.12em; font-weight: 600; display: flex; align-items: center; gap: 10px; }
  .device-meta { color: var(--muted); font-size: 0.83em; margin-top: 4px; }
  .badge {
    display: inline-block;
    font-size: 0.68em;
    font-weight: 700;
    padding: 3px 9px;
    border-radius: 999px;
    letter-spacing: 0.5px;
  }
  .badge.online { background: color-mix(in srgb, var(--success) 18%, transparent); color: var(--success); }
  .badge.offline { background: color-mix(in srgb, var(--muted) 18%, transparent); color: var(--muted); }
  .url-row { display: flex; gap: 8px; align-items: stretch; margin-top: 12px; flex-wrap: wrap; }
  .url-box {
    flex: 1;
    min-width: 220px;
    background: var(--input-bg);
    border: 1px solid var(--border);
    border-radius: 11px;
    padding: 11px 14px;
    font-family: ui-monospace, Menlo, Consolas, monospace;
    font-size: 0.82em;
    color: var(--accent);
    word-break: break-all;
  }
  .btn {
    background: transparent;
    border: 1px solid var(--border);
    border-radius: 11px;
    padding: 9px 14px;
    color: var(--text);
    font-size: 0.85em;
    font-weight: 500;
    cursor: pointer;
    transition: border-color 0.15s, color 0.15s, background 0.15s;
    white-space: nowrap;
    font-family: inherit;
  }
  .btn:hover { border-color: var(--accent); color: var(--accent); background: color-mix(in srgb, var(--accent) 8%, transparent); }
  .btn.danger:hover { border-color: var(--danger); color: var(--danger); background: color-mix(in srgb, var(--danger) 8%, transparent); }
  .device-actions { display: flex; gap: 8px; margin-top: 14px; flex-wrap: wrap; }
  .empty {
    text-align: center;
    padding: 60px 20px;
    color: var(--muted);
    background: var(--card);
    border-radius: 16px;
    border: 1px dashed var(--border);
  }
  .toast {
    position: fixed;
    bottom: 24px;
    left: 50%;
    transform: translateX(-50%) translateY(20px);
    background: var(--card);
    border: 1px solid var(--border);
    color: var(--text);
    padding: 13px 22px;
    border-radius: 11px;
    box-shadow: var(--shadow);
    opacity: 0;
    transition: opacity 0.25s, transform 0.25s;
    pointer-events: none;
    font-size: 0.9em;
    z-index: 100;
  }
  .toast.show { opacity: 1; transform: translateX(-50%) translateY(0); }
  .toast.error { border-color: var(--danger); color: var(--danger); }
</style>
</head>
<body>
${navBar(email, 'devices')}
<main>
  <div class="page-head">
    <h1>My Devices</h1>
    <div class="subtitle">Each device gets its own webhook URL. Paste it into the Notifikator app on that phone.</div>
  </div>

  <div class="create-card">
    <h2 class="section-title">
      <span class="section-icon">${ICONS.plus}</span>
      Add a new device
    </h2>
    <div class="form-row">
      <input type="text" id="new-name" placeholder="Device name (e.g. My Pixel)" maxlength="100">
      <input type="text" id="new-phone" placeholder="Phone number (optional)" maxlength="50">
      <button id="create-btn">Generate URL</button>
    </div>
  </div>

  <div class="devices" id="devices"></div>
</main>
${FOOTER_HTML}
<div class="toast" id="toast"></div>

<script>
  ${THEME_TOGGLE_SCRIPT}
  setupThemeToggle();

  const toast = document.getElementById('toast');
  let toastTimer = null;
  function showToast(msg, isError) {
    toast.textContent = msg;
    toast.className = 'toast show' + (isError ? ' error' : '');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { toast.className = 'toast' + (isError ? ' error' : ''); }, 2200);
  }

  function escapeHtml(s) {
    return String(s == null ? '' : s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#039;');
  }

  function timeAgo(iso) {
    if (!iso) return 'Never seen';
    const diff = Date.now() - new Date(iso).getTime();
    const m = Math.floor(diff / 60000);
    if (m < 1) return 'just now';
    if (m < 60) return m + ' min ago';
    const h = Math.floor(m / 60);
    if (h < 24) return h + ' hr ago';
    const d = Math.floor(h / 24);
    return d + ' day' + (d === 1 ? '' : 's') + ' ago';
  }

  function webhookUrl(token) { return window.location.origin + '/webhook/' + token; }

  async function copyText(text, label) {
    try { await navigator.clipboard.writeText(text); showToast(label + ' copied'); }
    catch (e) {
      const ta = document.createElement('textarea');
      ta.value = text;
      document.body.appendChild(ta); ta.select();
      try { document.execCommand('copy'); showToast(label + ' copied'); }
      catch (err) { showToast('Copy failed', true); }
      document.body.removeChild(ta);
    }
  }

  async function loadDevices() {
    const r = await fetch('/api/devices');
    if (r.status === 401) return location.href = '/login';
    const d = await r.json();
    renderDevices(d.devices);
  }

  function renderDevices(devices) {
    const container = document.getElementById('devices');
    if (!devices.length) {
      container.innerHTML = '<div class="empty">No devices yet. Add one above to generate a webhook URL.</div>';
      return;
    }
    container.innerHTML = devices.map(dev => {
      const online = dev.last_seen_at && (Date.now() - new Date(dev.last_seen_at).getTime()) < 5 * 60 * 1000;
      const url = webhookUrl(dev.token);
      return (
        '<div class="device" data-id="' + dev.id + '">' +
          '<div class="device-head">' +
            '<div>' +
              '<div class="device-name">' + escapeHtml(dev.name) +
                '<span class="badge ' + (online ? 'online' : 'offline') + '">' + (online ? 'ONLINE' : 'IDLE') + '</span>' +
              '</div>' +
              '<div class="device-meta">' +
                (dev.phone_number ? escapeHtml(dev.phone_number) + ' · ' : '') +
                'Last seen: ' + timeAgo(dev.last_seen_at) +
              '</div>' +
            '</div>' +
          '</div>' +
          '<div class="url-row">' +
            '<div class="url-box">' + escapeHtml(url) + '</div>' +
            '<button class="btn" data-action="copy-url" data-token="' + escapeHtml(dev.token) + '">Copy URL</button>' +
            '<button class="btn" data-action="copy-token" data-token="' + escapeHtml(dev.token) + '">Copy token</button>' +
          '</div>' +
          '<div class="device-actions">' +
            '<button class="btn" data-action="rename" data-id="' + dev.id + '" data-name="' + escapeHtml(dev.name) + '" data-phone="' + escapeHtml(dev.phone_number || '') + '">Rename</button>' +
            '<button class="btn" data-action="rotate" data-id="' + dev.id + '">Rotate token</button>' +
            '<button class="btn danger" data-action="delete" data-id="' + dev.id + '" data-name="' + escapeHtml(dev.name) + '">Delete</button>' +
          '</div>' +
        '</div>'
      );
    }).join('');
  }

  document.getElementById('create-btn').addEventListener('click', async () => {
    const name = document.getElementById('new-name').value.trim();
    const phone_number = document.getElementById('new-phone').value.trim();
    if (!name) return showToast('Device name is required', true);

    const r = await fetch('/api/devices', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, phone_number })
    });
    const d = await r.json();
    if (!r.ok) return showToast(d.error || 'Failed', true);

    document.getElementById('new-name').value = '';
    document.getElementById('new-phone').value = '';
    showToast('Device created — URL ready');
    loadDevices();
  });

  document.getElementById('devices').addEventListener('click', async (ev) => {
    const btn = ev.target.closest('button[data-action]');
    if (!btn) return;
    const action = btn.getAttribute('data-action');

    if (action === 'copy-url') {
      copyText(webhookUrl(btn.getAttribute('data-token')), 'Webhook URL');
    } else if (action === 'copy-token') {
      copyText(btn.getAttribute('data-token'), 'Token');
    } else if (action === 'rename') {
      const id = btn.getAttribute('data-id');
      const currentName = btn.getAttribute('data-name');
      const currentPhone = btn.getAttribute('data-phone');
      const newName = prompt('New device name:', currentName);
      if (newName === null) return;
      const newPhone = prompt('Phone number (optional):', currentPhone);
      if (newPhone === null) return;
      const r = await fetch('/api/devices/' + id, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: newName, phone_number: newPhone })
      });
      if (!r.ok) { const d = await r.json(); return showToast(d.error || 'Failed', true); }
      showToast('Device updated');
      loadDevices();
    } else if (action === 'rotate') {
      if (!confirm('Rotate token? The old webhook URL will stop working immediately.')) return;
      const id = btn.getAttribute('data-id');
      const r = await fetch('/api/devices/' + id + '/rotate', { method: 'POST' });
      if (!r.ok) { const d = await r.json(); return showToast(d.error || 'Failed', true); }
      showToast('Token rotated — update Notifikator');
      loadDevices();
    } else if (action === 'delete') {
      const id = btn.getAttribute('data-id');
      const name = btn.getAttribute('data-name');
      if (!confirm('Delete device "' + name + '"? Its notifications will remain but lose the device link.')) return;
      const r = await fetch('/api/devices/' + id, { method: 'DELETE' });
      if (!r.ok) { const d = await r.json(); return showToast(d.error || 'Failed', true); }
      showToast('Device deleted');
      loadDevices();
    }
  });

  loadDevices();
  setInterval(loadDevices, 30000);
</script>
</body>
</html>`;
}

// ===============================================================
// DASHBOARD PAGE
// ===============================================================
function renderDashboard(email) {
  return `<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Dashboard — Notification Tracker</title>
<script>${THEME_BOOTSTRAP}</script>
<style>
  ${BASE_STYLES}
  ${NAV_STYLES}
  ${FOOTER_STYLES}
  main { max-width: 1180px; margin: 0 auto; padding: 32px 24px; }

  .stats {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 16px;
    margin-bottom: 28px;
  }
  .stat {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 16px;
    padding: 20px 22px;
    box-shadow: var(--shadow-sm);
    position: relative;
    overflow: hidden;
    transition: transform 0.15s, border-color 0.15s;
  }
  .stat:hover { transform: translateY(-2px); border-color: var(--border-strong); }
  .stat::before {
    content: "";
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 3px;
    background: linear-gradient(90deg, var(--accent), var(--accent-2));
  }
  .stat-label {
    color: var(--muted);
    font-size: 0.72em;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    margin-bottom: 8px;
    display: flex;
    align-items: center;
    gap: 7px;
  }
  .stat-icon {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 22px;
    height: 22px;
    border-radius: 6px;
    background: color-mix(in srgb, var(--accent) 15%, transparent);
    color: var(--accent);
  }
  .stat-icon svg { width: 13px; height: 13px; display: block; }
  .stat-value {
    font-size: 1.85em;
    font-weight: 700;
    letter-spacing: -0.02em;
    line-height: 1.1;
  }
  .stat-value.small { font-size: 1.15em; }

  .toolbar {
    display: flex;
    gap: 10px;
    flex-wrap: wrap;
    margin-bottom: 20px;
    align-items: center;
  }
  .toolbar input, .toolbar select {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 11px;
    padding: 11px 14px;
    color: var(--text);
    font-size: 0.92em;
    outline: none;
    transition: border-color 0.15s, box-shadow 0.15s;
    font-family: inherit;
  }
  .toolbar input:focus, .toolbar select:focus {
    border-color: var(--accent);
    box-shadow: 0 0 0 3px var(--accent-glow);
  }
  .toolbar button {
    background: linear-gradient(135deg, var(--accent), var(--accent-2));
    color: white;
    border: none;
    border-radius: 11px;
    padding: 11px 18px;
    font-size: 0.92em;
    font-weight: 600;
    cursor: pointer;
    box-shadow: 0 4px 16px var(--accent-glow);
    transition: transform 0.1s;
    font-family: inherit;
  }
  .toolbar button:hover { transform: translateY(-1px); }
  .toolbar button.danger {
    background: transparent;
    color: var(--danger);
    border: 1px solid var(--border);
    box-shadow: none;
  }
  .toolbar button.danger:hover { border-color: var(--danger); background: color-mix(in srgb, var(--danger) 8%, transparent); }

  .search-wrap { position: relative; flex: 1; min-width: 200px; display: flex; }
  .search-wrap input { flex: 1; padding-left: 38px; min-width: 0; }
  .search-icon {
    position: absolute;
    left: 13px;
    top: 50%;
    transform: translateY(-50%);
    color: var(--muted);
    pointer-events: none;
    display: flex;
    align-items: center;
  }
  .search-icon svg { display: block; }

  .toolbar button.icon-btn {
    display: inline-flex;
    align-items: center;
    gap: 8px;
  }
  .toolbar button.icon-btn svg { display: block; }

  .bulk-bar {
    display: none;
    align-items: center;
    gap: 12px;
    background: color-mix(in srgb, var(--accent) 10%, var(--card));
    border: 1px solid color-mix(in srgb, var(--accent) 40%, transparent);
    border-radius: 12px;
    padding: 12px 18px;
    margin-bottom: 16px;
    font-size: 0.9em;
    font-weight: 500;
  }
  .bulk-bar.active { display: flex; }
  .bulk-bar button {
    background: var(--danger);
    color: white;
    border: none;
    border-radius: 9px;
    padding: 7px 14px;
    font-weight: 600;
    cursor: pointer;
    font-size: 0.88em;
    font-family: inherit;
  }
  .bulk-bar button.secondary {
    background: transparent;
    border: 1px solid var(--border);
    color: var(--text);
  }

  #notifications { display: flex; flex-direction: column; gap: 12px; }
  .notification {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 14px;
    padding: 16px 48px 16px 54px;
    position: relative;
    box-shadow: var(--shadow-sm);
    transition: background 0.15s, transform 0.1s, opacity 0.3s, border-color 0.15s;
  }
  .notification:hover {
    background: var(--card-hover);
    transform: translateY(-1px);
    border-color: var(--border-strong);
  }
  .notification.deleting { opacity: 0.25; transform: scale(0.98); }
  .notification::before {
    content: "";
    position: absolute;
    left: 0; top: 14px; bottom: 14px;
    width: 4px;
    border-radius: 4px;
    background: var(--bar-color, var(--accent));
  }
  .checkbox-wrap { position: absolute; left: 18px; top: 18px; }
  .checkbox-wrap input {
    width: 18px; height: 18px;
    accent-color: var(--accent);
    cursor: pointer;
  }
  .delete-btn {
    position: absolute;
    top: 12px; right: 12px;
    width: 28px; height: 28px;
    border-radius: 50%;
    border: none;
    background: transparent;
    color: var(--muted);
    font-size: 1.15em;
    line-height: 1;
    cursor: pointer;
    display: flex; align-items: center; justify-content: center;
    transition: background 0.15s, color 0.15s;
    font-family: inherit;
  }
  .delete-btn:hover {
    background: color-mix(in srgb, var(--danger) 15%, transparent);
    color: var(--danger);
  }
  .row1 {
    display: flex;
    align-items: center;
    gap: 8px;
    flex-wrap: wrap;
    margin-bottom: 8px;
  }
  .app-pill {
    font-size: 0.72em;
    font-weight: 700;
    padding: 4px 10px;
    border-radius: 999px;
    background: var(--pill-color, var(--pill-bg));
    color: #fff;
    letter-spacing: 0.3px;
  }
  .phone-pill {
    font-size: 0.72em;
    font-weight: 600;
    padding: 4px 10px;
    border-radius: 999px;
    background: color-mix(in srgb, var(--accent) 15%, transparent);
    color: var(--accent);
  }
  .device-pill {
    font-size: 0.72em;
    font-weight: 600;
    padding: 4px 10px;
    border-radius: 999px;
    background: color-mix(in srgb, var(--success) 15%, transparent);
    color: var(--success);
  }
  .time {
    margin-left: auto;
    font-size: 0.76em;
    color: var(--muted);
    white-space: nowrap;
    font-variant-numeric: tabular-nums;
  }
  .title { font-weight: 600; font-size: 1.02em; margin-bottom: 4px; word-wrap: break-word; }
  .body { color: var(--muted); font-size: 0.94em; line-height: 1.5; white-space: pre-wrap; word-wrap: break-word; }
  .empty {
    text-align: center;
    padding: 80px 20px;
    color: var(--muted);
    background: var(--card);
    border-radius: 16px;
    border: 1px dashed var(--border);
  }
  .toast {
    position: fixed;
    bottom: 24px;
    left: 50%;
    transform: translateX(-50%) translateY(20px);
    background: var(--card);
    border: 1px solid var(--border);
    color: var(--text);
    padding: 13px 22px;
    border-radius: 11px;
    box-shadow: var(--shadow);
    opacity: 0;
    transition: opacity 0.25s, transform 0.25s;
    pointer-events: none;
    font-size: 0.9em;
    z-index: 100;
    display: flex;
    align-items: center;
  }
  .toast.show { opacity: 1; transform: translateX(-50%) translateY(0); pointer-events: auto; }
  .toast.error { border-color: var(--danger); color: var(--danger); }
  @media (max-width: 600px) {
    main { padding: 20px 16px; }
    header.site-header { padding: 12px 16px; }
    .time { width: 100%; margin-left: 0; }
    .stat-value { font-size: 1.5em; }
  }
</style>
</head>
<body>
${navBar(email, 'dashboard')}
<main>
  <div class="stats">
    <div class="stat">
      <div class="stat-label"><span class="stat-icon">${ICONS.bell}</span> Total notifications</div>
      <div class="stat-value" id="stat-total">0</div>
    </div>
    <div class="stat">
      <div class="stat-label"><span class="stat-icon">${ICONS.clock}</span> Last hour</div>
      <div class="stat-value" id="stat-hour">0</div>
    </div>
    <div class="stat">
      <div class="stat-label"><span class="stat-icon">${ICONS.zap}</span> Top app</div>
      <div class="stat-value small" id="stat-top">—</div>
    </div>
    <div class="stat">
      <div class="stat-label"><span class="stat-icon">${ICONS.smartphone}</span> Devices</div>
      <div class="stat-value small" id="stat-devices">0</div>
    </div>
  </div>

  <div class="toolbar">
    <div class="search-wrap">
      <span class="search-icon">${ICONS.search}</span>
      <input type="text" id="search" placeholder="Search title or body...">
    </div>
    <select id="app-filter"><option value="">All apps</option></select>
    <select id="device-filter"><option value="">All devices</option></select>
    <button id="refresh-btn" class="icon-btn">${ICONS.refresh}<span>Refresh</span></button>
    <button id="clear-btn" class="danger">Clear all</button>
  </div>

  <div class="bulk-bar" id="bulk-bar">
    <span id="bulk-count">0 selected</span>
    <button id="bulk-delete">Delete selected</button>
    <button id="bulk-clear" class="secondary">Clear selection</button>
  </div>

  <div id="notifications"></div>
</main>
${FOOTER_HTML}
<div class="toast" id="toast"></div>

<script>
  ${THEME_TOGGLE_SCRIPT}
  setupThemeToggle();

  const APP_COLORS = {
    'com.whatsapp':'#25D366','com.whatsapp.w4b':'#25D366','com.google.android.apps.messaging':'#4285F4','com.android.mms':'#4285F4','com.samsung.android.messaging':'#4285F4','com.facebook.katana':'#1877F2','com.facebook.orca':'#0084FF','com.instagram.android':'#E1306C','com.twitter.android':'#1DA1F2','org.telegram.messenger':'#229ED9','com.google.android.gm':'#EA4335','com.google.android.apps.photos':'#FBBC04','com.android.systemui':'#6B7280','com.google.android.dialer':'#34A853','com.google.android.apps.maps':'#34A853','com.spotify.music':'#1DB954','com.netflix.mediaclient':'#E50914','com.google.android.youtube':'#FF0000','com.discord':'#5865F2','org.mozilla.firefox':'#FF7139','com.android.chrome':'#4285F4'
  };
  const DEFAULT_COLOR = '#6c8cff';
  const colorFor = a => APP_COLORS[a] || DEFAULT_COLOR;
  const shortApp = a => { if (!a) return 'unknown'; const p = a.split('.'); return p[p.length-1] || a; };
  const escapeHtml = s => String(s == null ? '' : s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#039;');
  const formatTime = iso => new Date(iso).toLocaleString('en-GB', { timeZone:'Africa/Nairobi', year:'numeric', month:'short', day:'2-digit', hour:'2-digit', minute:'2-digit', second:'2-digit', hour12:false }) + ' EAT';

  const toast = document.getElementById('toast');
  let toastTimer = null;
  function showToast(msg, isError) {
    toast.textContent = msg;
    toast.className = 'toast show' + (isError ? ' error' : '');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { toast.className = 'toast' + (isError ? ' error' : ''); }, 2200);
  }
  function showUndoToast(msg, onUndo) {
    toast.innerHTML = '';
    const t = document.createElement('span'); t.textContent = msg;
    const b = document.createElement('button');
    b.textContent = 'Undo';
    b.style.cssText = 'margin-left:14px;background:transparent;border:1px solid var(--accent);color:var(--accent);padding:5px 12px;border-radius:7px;cursor:pointer;font-weight:600;font-family:inherit;';
    b.onclick = () => { onUndo(); toast.className = 'toast'; };
    toast.appendChild(t); toast.appendChild(b);
    toast.className = 'toast show';
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { toast.className = 'toast'; }, 5000);
  }

  let allItems = [];
  let devicesById = {};
  const selectedIds = new Set();

  function updateBulkBar() {
    const bar = document.getElementById('bulk-bar');
    const c = document.getElementById('bulk-count');
    if (selectedIds.size > 0) { bar.classList.add('active'); c.textContent = selectedIds.size + ' selected'; }
    else bar.classList.remove('active');
  }

  function renderList(items) {
    const c = document.getElementById('notifications');
    if (!items.length) {
      c.innerHTML = '<div class="empty">No notifications match your filters.<br><span style="font-size:0.9em;opacity:0.7;margin-top:8px;display:inline-block;">Send a test from Notifikator to get started.</span></div>';
      return;
    }
    c.innerHTML = items.map(n => {
      const color = colorFor(n.app);
      const checked = selectedIds.has(String(n.id));
      const dev = devicesById[n.device_id];
      const deviceName = dev ? dev.name : null;
      return '<div class="notification" data-id="' + n.id + '" style="--bar-color:' + color + ';">' +
        '<div class="checkbox-wrap"><input type="checkbox" class="select-cb" data-id="' + n.id + '"' + (checked ? ' checked' : '') + '></div>' +
        '<button class="delete-btn" title="Delete" data-id="' + n.id + '">×</button>' +
        '<div class="row1">' +
          '<span class="app-pill" style="--pill-color:' + color + ';">' + escapeHtml(shortApp(n.app)) + '</span>' +
          (deviceName ? '<span class="device-pill">' + escapeHtml(deviceName) + '</span>' : '') +
          '<span class="phone-pill">' + escapeHtml(n.phone || 'Unknown') + '</span>' +
          '<span class="time">' + formatTime(n.timestamp) + '</span>' +
        '</div>' +
        (n.title ? '<div class="title">' + escapeHtml(n.title) + '</div>' : '') +
        (n.body  ? '<div class="body">'  + escapeHtml(n.body)  + '</div>' : '') +
      '</div>';
    }).join('');
  }

  function renderStats(items) {
    const total = items.length;
    const hour = items.filter(n => new Date(n.timestamp).getTime() > Date.now() - 3600000).length;
    const counts = {};
    items.forEach(n => { counts[n.app] = (counts[n.app] || 0) + 1; });
    const top = Object.keys(counts).sort((a,b) => counts[b]-counts[a])[0];
    document.getElementById('stat-total').textContent = total;
    document.getElementById('stat-hour').textContent = hour;
    document.getElementById('stat-top').textContent = top ? shortApp(top) + ' (' + counts[top] + ')' : '—';
    document.getElementById('stat-devices').textContent = Object.keys(devicesById).length;
  }

  async function loadDevices() {
    const r = await fetch('/api/devices');
    if (r.status === 401) return location.href = '/login';
    const d = await r.json();
    devicesById = {};
    d.devices.forEach(x => { devicesById[x.id] = x; });

    const sel = document.getElementById('device-filter');
    const cur = sel.value;
    sel.innerHTML = '<option value="">All devices</option>';
    d.devices.forEach(x => {
      const o = document.createElement('option');
      o.value = String(x.id);
      o.textContent = x.name;
      sel.appendChild(o);
    });
    sel.value = cur;
    document.getElementById('stat-devices').textContent = d.devices.length;
  }

  async function loadApps() {
    const r = await fetch('/api/apps');
    if (r.status === 401) return location.href = '/login';
    const d = await r.json();
    const sel = document.getElementById('app-filter');
    const cur = sel.value;
    sel.innerHTML = '<option value="">All apps</option>';
    d.apps.forEach(a => { const o = document.createElement('option'); o.value = a; o.textContent = shortApp(a); sel.appendChild(o); });
    sel.value = cur;
  }

  async function loadNotifications() {
    try {
      const r = await fetch('/api/notifications');
      if (r.status === 401) return location.href = '/login';
      const d = await r.json();
      allItems = d.notifications || [];
      applyFilters();
    } catch (e) {}
  }

  function applyFilters() {
    const q = document.getElementById('search').value.trim().toLowerCase();
    const app = document.getElementById('app-filter').value;
    const device = document.getElementById('device-filter').value;
    const f = allItems.filter(n => {
      if (app && n.app !== app) return false;
      if (device && String(n.device_id) !== String(device)) return false;
      if (q) { const h = ((n.title||'')+' '+(n.body||'')).toLowerCase(); if (!h.includes(q)) return false; }
      return true;
    });
    renderStats(f);
    renderList(f);
    updateBulkBar();
  }

  document.getElementById('notifications').addEventListener('click', ev => {
    const btn = ev.target.closest('.delete-btn');
    if (!btn) return;
    const id = btn.getAttribute('data-id');
    const item = allItems.find(n => String(n.id) === String(id));
    if (!item) return;
    allItems = allItems.filter(n => String(n.id) !== String(id));
    applyFilters();
    const timer = setTimeout(async () => {
      try { await fetch('/api/notifications/' + id, { method: 'DELETE' }); }
      catch (e) { showToast('Delete failed', true); }
    }, 5000);
    showUndoToast('Notification deleted', () => {
      clearTimeout(timer);
      allItems.push(item);
      allItems.sort((a,b) => new Date(b.timestamp) - new Date(a.timestamp));
      applyFilters();
      showToast('Restored');
    });
  });

  document.getElementById('notifications').addEventListener('change', ev => {
    const cb = ev.target.closest('.select-cb');
    if (!cb) return;
    const id = cb.getAttribute('data-id');
    if (cb.checked) selectedIds.add(String(id)); else selectedIds.delete(String(id));
    updateBulkBar();
  });

  document.getElementById('bulk-clear').addEventListener('click', () => { selectedIds.clear(); applyFilters(); });
  document.getElementById('bulk-delete').addEventListener('click', () => {
    if (selectedIds.size === 0) return;
    const ids = Array.from(selectedIds);
    if (!confirm('Delete ' + ids.length + ' notification(s)?')) return;
    allItems = allItems.filter(n => !selectedIds.has(String(n.id)));
    applyFilters();
    selectedIds.clear();
    updateBulkBar();
    Promise.all(ids.map(id => fetch('/api/notifications/' + id, { method: 'DELETE' }).catch(() => null)))
      .then(() => showToast('Deleted ' + ids.length + ' notification(s)'));
  });

  document.getElementById('clear-btn').addEventListener('click', async () => {
    if (!confirm('Delete ALL notifications? This cannot be undone.')) return;
    const r = await fetch('/api/notifications', { method: 'DELETE' });
    const d = await r.json();
    if (r.ok) { allItems = []; selectedIds.clear(); applyFilters(); showToast('Cleared ' + d.deleted); }
  });

  document.getElementById('search').addEventListener('input', applyFilters);
  document.getElementById('app-filter').addEventListener('change', applyFilters);
  document.getElementById('device-filter').addEventListener('change', applyFilters);
  document.getElementById('refresh-btn').addEventListener('click', () => { loadApps(); loadDevices(); loadNotifications(); });

  const source = new EventSource('/api/stream');
  source.addEventListener('hello', () => {});
  source.addEventListener('notification', ev => {
    const n = JSON.parse(ev.data);
    if (!allItems.some(x => x.id === n.id)) {
      allItems.unshift(n);
      applyFilters();
      const dev = devicesById[n.device_id];
      showToast('New: ' + shortApp(n.app) + (dev ? ' on ' + dev.name : ''));
    }
  });
  source.addEventListener('deleted', ev => {
    const { id } = JSON.parse(ev.data);
    allItems = allItems.filter(n => n.id !== id);
    applyFilters();
  });
  source.addEventListener('cleared', () => { allItems = []; applyFilters(); });
  source.onerror = () => {};

  (async () => {
    await loadDevices();
    await loadApps();
    await loadNotifications();
  })();
</script>
</body>
</html>`;
}

// ---------------------------------------------------------------
// Start
// ---------------------------------------------------------------
app.listen(port, function() {
  console.log('Server running on port ' + port);
});
