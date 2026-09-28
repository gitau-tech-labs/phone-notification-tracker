const express = require('express');
const session = require('express-session');
const PgSession = require('connect-pg-simple')(session);
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const path = require('path');

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
        timestamp TIMESTAMPTZ DEFAULT NOW(),
        raw_payload JSONB
      )
    `);
    await pool.query(`
      ALTER TABLE notifications ADD COLUMN IF NOT EXISTS phone VARCHAR(50)
    `);
    // Users table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        created_at TIMESTAMPTZ DEFAULT NOW()
      )
    `);
    // Session store (created by connect-pg-simple automatically, but let's be safe)
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
app.set('trust proxy', 1); // needed for secure cookies behind Render's proxy

app.use(session({
  store: new PgSession({
    pool: pool,
    tableName: 'session',
    createTableIfMissing: true
  }),
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: true, // Render serves HTTPS
    maxAge: 30 * 24 * 60 * 60 * 1000 // 30 days
  }
}));

// ---------------------------------------------------------------
// Auth middleware
// ---------------------------------------------------------------
function requireAuth(req, res, next) {
  if (req.session && req.session.userId) {
    return next();
  }
  // For API/JSON requests, return 401; for browser, redirect to /login
  if (req.path.startsWith('/api/') || req.path === '/webhook') {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  res.redirect('/login');
}

// ---------------------------------------------------------------
// SSE (still public-ish? No — we'll protect it)
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

  const ping = setInterval(() => {
    try { res.write(': ping\n\n'); } catch (e) {}
  }, 25000);

  req.on('close', () => {
    clearInterval(ping);
    sseClients.delete(res);
    console.log('SSE client disconnected. Total:', sseClients.size);
  });
});

function broadcast(event, data) {
  const payload = 'event: ' + event + '\ndata: ' + JSON.stringify(data) + '\n\n';
  for (const client of sseClients) {
    try { client.write(payload); } catch (e) { sseClients.delete(client); }
  }
}

// ---------------------------------------------------------------
// Webhook (public — Notifikator has to reach it)
// We protect it with a shared token so randoms can't spam it.
// ---------------------------------------------------------------
const WEBHOOK_TOKEN = process.env.WEBHOOK_TOKEN || '';

app.post('/webhook', async (req, res) => {
  try {
    if (WEBHOOK_TOKEN && req.query.token !== WEBHOOK_TOKEN) {
      return res.status(401).json({ error: 'Unauthorized' });
    }
    const payload = req.body;
    console.log('=== INCOMING WEBHOOK ===');
    console.log('Raw body:', JSON.stringify(payload, null, 2));
    console.log('========================');

    const inserted = await pool.query(
      'INSERT INTO notifications (phone, app, title, body, raw_payload) VALUES ($1, $2, $3, $4, $5) RETURNING id, phone, app, title, body, timestamp',
      [
        payload.phone || null,
        payload.app || null,
        payload.title || null,
        payload.body || null,
        JSON.stringify(payload)
      ]
    );

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
    res.redirect('/');
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

app.post('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

// ---------------------------------------------------------------
// Protected API routes
// ---------------------------------------------------------------
app.get('/count', requireAuth, async (req, res) => {
  try {
    const total = await pool.query('SELECT COUNT(*) FROM notifications');
    const latest = await pool.query(
      'SELECT id, phone, app, title, body, timestamp FROM notifications ORDER BY id DESC LIMIT 10'
    );
    res.json({ total: parseInt(total.rows[0].count, 10), latest: latest.rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/notifications', requireAuth, async (req, res) => {
  try {
    const { app: appFilter, q } = req.query;
    let query = 'SELECT id, phone, app, title, body, timestamp FROM notifications';
    const conditions = [];
    const values = [];

    if (appFilter) {
      values.push(appFilter);
      conditions.push('app = $' + values.length);
    }
    if (q) {
      values.push('%' + q + '%');
      conditions.push('(title ILIKE $' + values.length + ' OR body ILIKE $' + values.length + ')');
    }
    if (conditions.length) query += ' WHERE ' + conditions.join(' AND ');
    query += ' ORDER BY timestamp DESC LIMIT 200';

    const result = await pool.query(query, values);
    res.json({ notifications: result.rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/apps', requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT DISTINCT app FROM notifications WHERE app IS NOT NULL ORDER BY app'
    );
    res.json({ apps: result.rows.map(r => r.app) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/notifications/:id', requireAuth, async (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (isNaN(id)) return res.status(400).json({ error: 'Invalid id' });
    const result = await pool.query('DELETE FROM notifications WHERE id = $1', [id]);
    broadcast('deleted', { id });
    res.json({ deleted: result.rowCount });
  } catch (err) {
    console.error('Error deleting notification:', err);
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/notifications', requireAuth, async (req, res) => {
  try {
    const result = await pool.query('DELETE FROM notifications');
    broadcast('cleared', {});
    res.json({ deleted: result.rowCount });
  } catch (err) {
    console.error('Error clearing notifications:', err);
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/prune', async (req, res) => {
  if (CRON_SECRET && req.query.secret !== CRON_SECRET) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  try {
    const days = parseInt(req.query.days, 10) || 7;
    const result = await pool.query(
      "DELETE FROM notifications WHERE timestamp < NOW() - ($1 || ' days')::interval",
      [days]
    );
    console.log('Pruned ' + result.rowCount + ' notifications older than ' + days + ' days');
    broadcast('cleared', {});
    res.json({ deleted: result.rowCount, olderThanDays: days });
  } catch (err) {
    console.error('Error pruning notifications:', err);
    res.status(500).json({ error: err.message });
  }
});

// ---------------------------------------------------------------
// Dashboard (protected)
// ---------------------------------------------------------------
app.get('/', requireAuth, async (req, res) => {
  res.send(renderDashboard(req.session.email || 'user'));
});

// ---------------------------------------------------------------
// Auth pages
// ---------------------------------------------------------------
function renderAuthPage(mode, error) {
  const isSignup = mode === 'signup';
  const title = isSignup ? 'Create account' : 'Sign in';
  const submitLabel = isSignup ? 'Create account' : 'Sign in';
  const switchText = isSignup ? 'Already have an account?' : 'Need an account?';
  const switchLink = isSignup ? '/login' : '/signup';
  const switchLabel = isSignup ? 'Sign in' : 'Sign up';

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${title}</title>
<style>
  :root {
    --bg: #0f1117; --card: #171a23; --text: #e6e8ef;
    --muted: #8b93a7; --accent: #6c8cff; --danger: #ef4444; --border: #262a38;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center;
    background: var(--bg); color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    padding: 20px;
  }
  .card {
    width: 100%; max-width: 400px; background: var(--card);
    border: 1px solid var(--border); border-radius: 14px; padding: 32px 28px;
    box-shadow: 0 10px 40px rgba(0,0,0,0.5);
  }
  h1 { margin: 0 0 4px 0; font-size: 1.4em; }
  .subtitle { color: var(--muted); font-size: 0.9em; margin-bottom: 24px; }
  label { display: block; font-size: 0.85em; color: var(--muted); margin-bottom: 6px; margin-top: 14px; }
  input {
    width: 100%; padding: 11px 14px; border-radius: 10px;
    border: 1px solid var(--border); background: #0d1017; color: var(--text);
    font-size: 0.95em; outline: none; transition: border-color 0.15s;
  }
  input:focus { border-color: var(--accent); }
  button {
    width: 100%; margin-top: 22px; padding: 12px;
    background: var(--accent); color: white; border: none; border-radius: 10px;
    font-size: 1em; font-weight: 600; cursor: pointer;
  }
  button:hover { filter: brightness(1.1); }
  .error {
    background: rgba(239,68,68,0.12); color: #fecaca; border: 1px solid rgba(239,68,68,0.4);
    padding: 10px 14px; border-radius: 8px; font-size: 0.88em; margin-bottom: 18px;
  }
  .switch { text-align: center; margin-top: 20px; font-size: 0.9em; color: var(--muted); }
  .switch a { color: var(--accent); text-decoration: none; font-weight: 600; }
  .switch a:hover { text-decoration: underline; }
</style>
</head>
<body>
  <form class="card" method="POST" action="${isSignup ? '/signup' : '/login'}">
    <h1>${title}</h1>
    <div class="subtitle">Notification Dashboard</div>
    ${error ? '<div class="error">' + error + '</div>' : ''}
    <label for="email">Email</label>
    <input type="email" id="email" name="email" required autocomplete="email" autofocus>
    <label for="password">Password</label>
    <input type="password" id="password" name="password" required autocomplete="${isSignup ? 'new-password' : 'current-password'}" minlength="${isSignup ? '8' : '1'}">
    ${isSignup ? `
    <label for="confirm">Confirm password</label>
    <input type="password" id="confirm" name="confirm" required autocomplete="new-password" minlength="8">
    ` : ''}
    <button type="submit">${submitLabel}</button>
    <div class="switch">${switchText} <a href="${switchLink}">${switchLabel}</a></div>
  </form>
</body>
</html>`;
}

// ---------------------------------------------------------------
// Dashboard HTML
// ---------------------------------------------------------------
function renderDashboard(email) {
  // Reuse the same dashboard as before, just add a user bar at the top
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Notification Dashboard</title>
<style>
  :root {
    --bg: #0f1117; --card: #171a23; --card-hover: #1e2230; --text: #e6e8ef;
    --muted: #8b93a7; --accent: #6c8cff; --danger: #ef4444; --border: #262a38;
    --shadow: 0 4px 20px rgba(0,0,0,0.35);
  }
  * { box-sizing: border-box; }
  body { margin: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: var(--bg); color: var(--text); min-height: 100vh; }
  header { position: sticky; top: 0; z-index: 10; background: rgba(15,17,23,0.85); backdrop-filter: blur(10px); border-bottom: 1px solid var(--border); padding: 16px 24px; }
  .header-inner { max-width: 1100px; margin: 0 auto; display: flex; align-items: center; justify-content: space-between; gap: 16px; flex-wrap: wrap; }
  .brand { display: flex; align-items: center; gap: 10px; font-weight: 700; font-size: 1.15em; }
  .dot { width: 10px; height: 10px; border-radius: 50%; background: #22c55e; box-shadow: 0 0 12px #22c55e; animation: pulse 2s infinite; }
  @keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: 0.4; } }
  .right-info { display: flex; align-items: center; gap: 14px; font-size: 0.85em; color: var(--muted); }
  .user-email { color: var(--text); font-weight: 500; }
  .logout { color: var(--muted); text-decoration: none; border: 1px solid var(--border); padding: 5px 10px; border-radius: 8px; transition: border-color 0.15s, color 0.15s; }
  .logout:hover { border-color: var(--danger); color: var(--danger); }
  main { max-width: 1100px; margin: 0 auto; padding: 24px; }
  .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; margin-bottom: 20px; }
  .stat { background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 16px; box-shadow: var(--shadow); }
  .stat-label { color: var(--muted); font-size: 0.78em; text-transform: uppercase; letter-spacing: 0.6px; margin-bottom: 6px; }
  .stat-value { font-size: 1.6em; font-weight: 700; }
  .toolbar { display: flex; gap: 10px; flex-wrap: wrap; margin-bottom: 20px; }
  .toolbar input, .toolbar select { background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 10px 14px; color: var(--text); font-size: 0.95em; outline: none; transition: border-color 0.15s; }
  .toolbar input { flex: 1; min-width: 200px; }
  .toolbar input:focus, .toolbar select:focus { border-color: var(--accent); }
  .toolbar button { background: var(--accent); color: white; border: none; border-radius: 10px; padding: 10px 16px; font-size: 0.95em; font-weight: 600; cursor: pointer; }
  .toolbar button:hover { filter: brightness(1.1); }
  .toolbar button.danger { background: var(--danger); }
  .bulk-bar { display: none; align-items: center; gap: 12px; background: #1e2230; border: 1px solid var(--accent); border-radius: 10px; padding: 10px 16px; margin-bottom: 12px; font-size: 0.9em; }
  .bulk-bar.active { display: flex; }
  .bulk-bar button { background: var(--danger); color: white; border: none; border-radius: 8px; padding: 6px 12px; font-weight: 600; cursor: pointer; font-size: 0.9em; }
  .bulk-bar button.secondary { background: transparent; border: 1px solid var(--border); color: var(--text); }
  #notifications { display: flex; flex-direction: column; gap: 12px; }
  .notification { background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 14px 44px 14px 52px; position: relative; box-shadow: var(--shadow); transition: background 0.15s, transform 0.1s, opacity 0.3s; }
  .notification:hover { background: var(--card-hover); transform: translateY(-1px); }
  .notification.deleting { opacity: 0.3; transform: scale(0.98); }
  .notification::before { content: ""; position: absolute; left: 0; top: 12px; bottom: 12px; width: 4px; border-radius: 4px; background: var(--bar-color, var(--accent)); }
  .checkbox-wrap { position: absolute; left: 16px; top: 16px; }
  .checkbox-wrap input { width: 18px; height: 18px; accent-color: var(--accent); cursor: pointer; }
  .delete-btn { position: absolute; top: 10px; right: 10px; width: 26px; height: 26px; border-radius: 50%; border: none; background: transparent; color: var(--muted); font-size: 1.1em; line-height: 1; cursor: pointer; display: flex; align-items: center; justify-content: center; transition: background 0.15s, color 0.15s; }
  .delete-btn:hover { background: rgba(239,68,68,0.15); color: var(--danger); }
  .row1 { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; margin-bottom: 6px; }
  .app-pill { font-size: 0.75em; font-weight: 700; padding: 3px 10px; border-radius: 999px; background: var(--pill-color, #2a2f42); color: #fff; letter-spacing: 0.3px; }
  .phone-pill { font-size: 0.75em; font-weight: 600; padding: 3px 10px; border-radius: 999px; background: rgba(108,140,255,0.15); color: #a8bcff; }
  .time { margin-left: auto; font-size: 0.78em; color: var(--muted); white-space: nowrap; }
  .title { font-weight: 600; font-size: 1.02em; margin-bottom: 4px; word-wrap: break-word; }
  .body { color: #c4c9d8; font-size: 0.95em; line-height: 1.45; white-space: pre-wrap; word-wrap: break-word; }
  .empty { text-align: center; padding: 60px 20px; color: var(--muted); background: var(--card); border-radius: 12px; border: 1px dashed var(--border); }
  .toast { position: fixed; bottom: 24px; left: 50%; transform: translateX(-50%) translateY(20px); background: #1e2230; border: 1px solid var(--border); color: var(--text); padding: 12px 20px; border-radius: 10px; box-shadow: var(--shadow); opacity: 0; transition: opacity 0.25s, transform 0.25s; pointer-events: none; font-size: 0.9em; z-index: 100; display: flex; align-items: center; }
  .toast.show { opacity: 1; transform: translateX(-50%) translateY(0); pointer-events: auto; }
  .toast.error { border-color: var(--danger); color: #fecaca; }
  @media (max-width: 600px) { main { padding: 16px; } header { padding: 12px 16px; } .time { width: 100%; margin-left: 0; } }
</style>
</head>
<body>
<header>
  <div class="header-inner">
    <div class="brand"><div class="dot"></div> Notification Dashboard</div>
    <div class="right-info">
      <span id="status">Connecting...</span>
      <span class="user-email">${escapeHtml(email)}</span>
      <a class="logout" href="/logout">Sign out</a>
    </div>
  </div>
</header>

<main>
  <div class="stats">
    <div class="stat"><div class="stat-label">Total</div><div class="stat-value" id="stat-total">0</div></div>
    <div class="stat"><div class="stat-label">Last hour</div><div class="stat-value" id="stat-hour">0</div></div>
    <div class="stat"><div class="stat-label">Top app</div><div class="stat-value" id="stat-top" style="font-size:1em;">—</div></div>
  </div>

  <div class="toolbar">
    <input type="text" id="search" placeholder="Search title or body...">
    <select id="app-filter"><option value="">All apps</option></select>
    <button id="refresh-btn">Refresh</button>
    <button id="clear-btn" class="danger">Clear all</button>
  </div>

  <div class="bulk-bar" id="bulk-bar">
    <span id="bulk-count">0 selected</span>
    <button id="bulk-delete">Delete selected</button>
    <button id="bulk-clear" class="secondary">Clear selection</button>
  </div>

  <div id="notifications"></div>
</main>

<div class="toast" id="toast"></div>

<script>
  const APP_COLORS = {
    'com.whatsapp': '#25D366', 'com.whatsapp.w4b': '#25D366',
    'com.google.android.apps.messaging': '#4285F4', 'com.android.mms': '#4285F4',
    'com.samsung.android.messaging': '#4285F4',
    'com.facebook.katana': '#1877F2', 'com.facebook.orca': '#0084FF',
    'com.instagram.android': '#E1306C', 'com.twitter.android': '#1DA1F2',
    'org.telegram.messenger': '#229ED9', 'com.google.android.gm': '#EA4335',
    'com.google.android.apps.photos': '#FBBC04', 'com.android.systemui': '#6B7280',
    'com.google.android.dialer': '#34A853', 'com.google.android.apps.maps': '#34A853',
    'com.spotify.music': '#1DB954', 'com.netflix.mediaclient': '#E50914',
    'com.google.android.youtube': '#FF0000', 'com.discord': '#5865F2',
    'org.mozilla.firefox': '#FF7139', 'com.android.chrome': '#4285F4'
  };
  const DEFAULT_COLOR = '#6c8cff';
  const colorFor = app => APP_COLORS[app] || DEFAULT_COLOR;
  const shortApp = app => { if (!app) return 'unknown'; const p = app.split('.'); return p[p.length-1] || app; };
  const escapeHtml = s => String(s == null ? '' : s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#039;');
  const formatTime = iso => new Date(iso).toLocaleString('en-GB', { timeZone: 'Africa/Nairobi', year:'numeric', month:'short', day:'2-digit', hour:'2-digit', minute:'2-digit', second:'2-digit', hour12:false }) + ' EAT';

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
    b.style.cssText = 'margin-left:14px;background:transparent;border:1px solid var(--accent);color:var(--accent);padding:4px 10px;border-radius:6px;cursor:pointer;font-weight:600;';
    b.onclick = () => { onUndo(); toast.className = 'toast'; };
    toast.appendChild(t); toast.appendChild(b);
    toast.className = 'toast show';
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { toast.className = 'toast'; }, 5000);
  }

  let allItems = [];
  const selectedIds = new Set();

  function updateBulkBar() {
    const bar = document.getElementById('bulk-bar');
    const c = document.getElementById('bulk-count');
    if (selectedIds.size > 0) { bar.classList.add('active'); c.textContent = selectedIds.size + ' selected'; }
    else bar.classList.remove('active');
  }

  function renderList(items) {
    const c = document.getElementById('notifications');
    if (!items.length) { c.innerHTML = '<div class="empty">No notifications match your filters.</div>'; return; }
    c.innerHTML = items.map(n => {
      const color = colorFor(n.app);
      const checked = selectedIds.has(String(n.id));
      return '<div class="notification" data-id="' + n.id + '" style="--bar-color:' + color + ';">' +
        '<div class="checkbox-wrap"><input type="checkbox" class="select-cb" data-id="' + n.id + '"' + (checked ? ' checked' : '') + '></div>' +
        '<button class="delete-btn" title="Delete" data-id="' + n.id + '">×</button>' +
        '<div class="row1">' +
          '<span class="app-pill" style="--pill-color:' + color + ';">' + escapeHtml(shortApp(n.app)) + '</span>' +
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
  }

  async function loadApps() {
    try {
      const r = await fetch('/api/apps');
      if (r.status === 401) return location.href = '/login';
      const d = await r.json();
      const sel = document.getElementById('app-filter');
      const cur = sel.value;
      sel.innerHTML = '<option value="">All apps</option>';
      d.apps.forEach(a => { const o = document.createElement('option'); o.value = a; o.textContent = shortApp(a); sel.appendChild(o); });
      sel.value = cur;
    } catch (e) {}
  }

  async function loadNotifications() {
    try {
      const r = await fetch('/api/notifications');
      if (r.status === 401) return location.href = '/login';
      const d = await r.json();
      allItems = d.notifications || [];
      applyFilters();
    } catch (e) { document.getElementById('status').textContent = 'Connection error'; }
  }

  function applyFilters() {
    const q = document.getElementById('search').value.trim().toLowerCase();
    const app = document.getElementById('app-filter').value;
    const f = allItems.filter(n => {
      if (app && n.app !== app) return false;
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
  document.getElementById('refresh-btn').addEventListener('click', () => { loadApps(); loadNotifications(); });

  const source = new EventSource('/api/stream');
  source.addEventListener('hello', () => { document.getElementById('status').textContent = 'Live — connected'; });
  source.addEventListener('notification', ev => {
    const n = JSON.parse(ev.data);
    if (!allItems.some(x => x.id === n.id)) { allItems.unshift(n); applyFilters(); showToast('New: ' + shortApp(n.app)); }
  });
  source.addEventListener('deleted', ev => {
    const { id } = JSON.parse(ev.data);
    allItems = allItems.filter(n => n.id !== id);
    applyFilters();
  });
  source.addEventListener('cleared', () => { allItems = []; applyFilters(); });
  source.onerror = () => { document.getElementById('status').textContent = 'Reconnecting...'; };

  loadApps();
  loadNotifications();
</script>
</body>
</html>`;
}

// ---------------------------------------------------------------
// HTML escape helper (server-side, used inside renderDashboard)
// ---------------------------------------------------------------
function escapeHtml(str) {
  return String(str == null ? '' : str)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#039;');
}

// ---------------------------------------------------------------
// Start
// ---------------------------------------------------------------
app.listen(port, function() {
  console.log('Server running on port ' + port);
});
