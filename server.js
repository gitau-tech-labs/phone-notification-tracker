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
  return crypto.randomBytes(24).toString('base64url'); // 32 chars, URL-safe
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
// Webhook — token in URL identifies the device
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
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
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
  } catch (err) {
    console.error('Error creating device:', err);
    res.status(500).json({ error: err.message });
  }
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
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
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
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/devices/:id', requireAuth, async (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    const check = await pool.query('SELECT id FROM devices WHERE id = $1 AND user_id = $2', [id, req.session.userId]);
    if (check.rowCount === 0) return res.status(404).json({ error: 'Not found' });

    await pool.query('DELETE FROM devices WHERE id = $1', [id]);
    res.json({ deleted: 1 });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ---------------------------------------------------------------
// Protected API routes
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

// ---------------------------------------------------------------
// Render: Auth page
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
  :root { --bg:#0f1117; --card:#171a23; --text:#e6e8ef; --muted:#8b93a7; --accent:#6c8cff; --danger:#ef4444; --border:#262a38; }
  * { box-sizing: border-box; }
  body { margin:0; min-height:100vh; display:flex; align-items:center; justify-content:center; background:var(--bg); color:var(--text); font-family:-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; padding:20px; }
  .card { width:100%; max-width:400px; background:var(--card); border:1px solid var(--border); border-radius:14px; padding:32px 28px; box-shadow:0 10px 40px rgba(0,0,0,0.5); }
  h1 { margin:0 0 4px 0; font-size:1.4em; }
  .subtitle { color:var(--muted); font-size:0.9em; margin-bottom:24px; }
  label { display:block; font-size:0.85em; color:var(--muted); margin-bottom:6px; margin-top:14px; }
  input { width:100%; padding:11px 14px; border-radius:10px; border:1px solid var(--border); background:#0d1017; color:var(--text); font-size:0.95em; outline:none; transition:border-color 0.15s; }
  input:focus { border-color:var(--accent); }
  button { width:100%; margin-top:22px; padding:12px; background:var(--accent); color:white; border:none; border-radius:10px; font-size:1em; font-weight:600; cursor:pointer; }
  button:hover { filter:brightness(1.1); }
  .error { background:rgba(239,68,68,0.12); color:#fecaca; border:1px solid rgba(239,68,68,0.4); padding:10px 14px; border-radius:8px; font-size:0.88em; margin-bottom:18px; }
  .switch { text-align:center; margin-top:20px; font-size:0.9em; color:var(--muted); }
  .switch a { color:var(--accent); text-decoration:none; font-weight:600; }
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
    ${isSignup ? '<label for="confirm">Confirm password</label><input type="password" id="confirm" name="confirm" required autocomplete="new-password" minlength="8">' : ''}
    <button type="submit">${submitLabel}</button>
    <div class="switch">${switchText} <a href="${switchLink}">${switchLabel}</a></div>
  </form>
</body>
</html>`;
}

// ---------------------------------------------------------------
// Render: Shared nav bar
// ---------------------------------------------------------------
function navBar(email, active) {
  const cls = (path) => active === path ? 'nav-link active' : 'nav-link';
  return `
  <header>
    <div class="header-inner">
      <div class="brand"><div class="dot"></div> Notification Dashboard</div>
      <nav class="nav">
        <a class="${cls('dashboard')}" href="/">Dashboard</a>
        <a class="${cls('devices')}" href="/devices">Devices</a>
      </nav>
      <div class="right-info">
        <span class="user-email">${escapeHtml(email)}</span>
        <a class="logout" href="/logout">Sign out</a>
      </div>
    </div>
  </header>`;
}

const NAV_STYLES = `
  header { position:sticky; top:0; z-index:10; background:rgba(15,17,23,0.85); backdrop-filter:blur(10px); border-bottom:1px solid var(--border); padding:16px 24px; }
  .header-inner { max-width:1100px; margin:0 auto; display:flex; align-items:center; justify-content:space-between; gap:16px; flex-wrap:wrap; }
  .brand { display:flex; align-items:center; gap:10px; font-weight:700; font-size:1.15em; }
  .dot { width:10px; height:10px; border-radius:50%; background:#22c55e; box-shadow:0 0 12px #22c55e; animation:pulse 2s infinite; }
  @keyframes pulse { 0%,100% { opacity:1; } 50% { opacity:0.4; } }
  .nav { display:flex; gap:6px; }
  .nav-link { color:var(--muted); text-decoration:none; padding:6px 12px; border-radius:8px; font-size:0.9em; font-weight:500; transition:background 0.15s, color 0.15s; }
  .nav-link:hover { color:var(--text); background:rgba(255,255,255,0.05); }
  .nav-link.active { color:var(--text); background:rgba(108,140,255,0.15); }
  .right-info { display:flex; align-items:center; gap:14px; font-size:0.85em; color:var(--muted); }
  .user-email { color:var(--text); font-weight:500; }
  .logout { color:var(--muted); text-decoration:none; border:1px solid var(--border); padding:5px 10px; border-radius:8px; transition:border-color 0.15s, color 0.15s; }
  .logout:hover { border-color:var(--danger); color:var(--danger); }
`;

// ---------------------------------------------------------------
// Render: Devices page
// ---------------------------------------------------------------
function renderDevicesPage(email) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>My Devices</title>
<style>
  :root { --bg:#0f1117; --card:#171a23; --card-hover:#1e2230; --text:#e6e8ef; --muted:#8b93a7; --accent:#6c8cff; --danger:#ef4444; --border:#262a38; --shadow:0 4px 20px rgba(0,0,0,0.35); }
  * { box-sizing: border-box; }
  body { margin:0; font-family:-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background:var(--bg); color:var(--text); min-height:100vh; }
  ${NAV_STYLES}
  main { max-width:1100px; margin:0 auto; padding:24px; }
  h1 { margin:0 0 6px 0; font-size:1.4em; }
  .subtitle { color:var(--muted); font-size:0.9em; margin-bottom:24px; }
  .create-card { background:var(--card); border:1px solid var(--border); border-radius:12px; padding:20px; margin-bottom:24px; box-shadow:var(--shadow); }
  .create-card h2 { margin:0 0 14px 0; font-size:1.05em; }
  .form-row { display:flex; gap:10px; flex-wrap:wrap; }
  .form-row input { flex:1; min-width:180px; background:#0d1017; border:1px solid var(--border); border-radius:10px; padding:10px 14px; color:var(--text); font-size:0.95em; outline:none; transition:border-color 0.15s; }
  .form-row input:focus { border-color:var(--accent); }
  .form-row button { background:var(--accent); color:white; border:none; border-radius:10px; padding:10px 18px; font-size:0.95em; font-weight:600; cursor:pointer; }
  .form-row button:hover { filter:brightness(1.1); }
  .devices { display:flex; flex-direction:column; gap:14px; }
  .device { background:var(--card); border:1px solid var(--border); border-radius:12px; padding:18px 20px; box-shadow:var(--shadow); }
  .device-head { display:flex; align-items:center; justify-content:space-between; gap:12px; flex-wrap:wrap; margin-bottom:10px; }
  .device-name { font-size:1.1em; font-weight:600; }
  .device-meta { color:var(--muted); font-size:0.82em; margin-top:2px; }
  .badge { display:inline-block; font-size:0.7em; font-weight:700; padding:2px 8px; border-radius:999px; margin-left:8px; letter-spacing:0.3px; }
  .badge.online { background:rgba(34,197,94,0.15); color:#22c55e; }
  .badge.offline { background:rgba(139,147,167,0.15); color:var(--muted); }
  .url-row { display:flex; gap:8px; align-items:stretch; margin-top:12px; }
  .url-box { flex:1; background:#0d1017; border:1px solid var(--border); border-radius:10px; padding:10px 14px; font-family:ui-monospace,Menlo,Consolas,monospace; font-size:0.82em; color:#a8bcff; word-break:break-all; }
  .btn { background:transparent; border:1px solid var(--border); border-radius:10px; padding:8px 14px; color:var(--text); font-size:0.85em; font-weight:500; cursor:pointer; transition:border-color 0.15s, color 0.15s; white-space:nowrap; }
  .btn:hover { border-color:var(--accent); color:var(--accent); }
  .btn.danger:hover { border-color:var(--danger); color:var(--danger); }
  .device-actions { display:flex; gap:8px; margin-top:12px; flex-wrap:wrap; }
  .empty { text-align:center; padding:60px 20px; color:var(--muted); background:var(--card); border-radius:12px; border:1px dashed var(--border); }
  .toast { position:fixed; bottom:24px; left:50%; transform:translateX(-50%) translateY(20px); background:#1e2230; border:1px solid var(--border); color:var(--text); padding:12px 20px; border-radius:10px; box-shadow:var(--shadow); opacity:0; transition:opacity 0.25s, transform 0.25s; pointer-events:none; font-size:0.9em; z-index:100; }
  .toast.show { opacity:1; transform:translateX(-50%) translateY(0); }
  .toast.error { border-color:var(--danger); color:#fecaca; }
</style>
</head>
<body>
${navBar(email, 'devices')}
<main>
  <h1>My Devices</h1>
  <div class="subtitle">Each device gets its own webhook URL. Paste it into the Notifikator app on that phone.</div>

  <div class="create-card">
    <h2>Add a new device</h2>
    <div class="form-row">
      <input type="text" id="new-name" placeholder="Device name (e.g. My Pixel)" maxlength="100">
      <input type="text" id="new-phone" placeholder="Phone number (optional)" maxlength="50">
      <button id="create-btn">Generate URL</button>
    </div>
  </div>

  <div class="devices" id="devices"></div>
</main>
<div class="toast" id="toast"></div>

<script>
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

  function webhookUrl(token) {
    return window.location.origin + '/webhook/' + token;
  }

  async function copyText(text, label) {
    try {
      await navigator.clipboard.writeText(text);
      showToast(label + ' copied');
    } catch (e) {
      // Fallback
      const ta = document.createElement('textarea');
      ta.value = text;
      document.body.appendChild(ta);
      ta.select();
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

// ---------------------------------------------------------------
// Render: Dashboard
// ---------------------------------------------------------------
function renderDashboard(email) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Notification Dashboard</title>
<style>
  :root { --bg:#0f1117; --card:#171a23; --card-hover:#1e2230; --text:#e6e8ef; --muted:#8b93a7; --accent:#6c8cff; --danger:#ef4444; --border:#262a38; --shadow:0 4px 20px rgba(0,0,0,0.35); }
  * { box-sizing: border-box; }
  body { margin:0; font-family:-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background:var(--bg); color:var(--text); min-height:100vh; }
  ${NAV_STYLES}
  main { max-width:1100px; margin:0 auto; padding:24px; }
  .stats { display:grid; grid-template-columns:repeat(auto-fit, minmax(180px, 1fr)); gap:12px; margin-bottom:20px; }
  .stat { background:var(--card); border:1px solid var(--border); border-radius:12px; padding:16px; box-shadow:var(--shadow); }
  .stat-label { color:var(--muted); font-size:0.78em; text-transform:uppercase; letter-spacing:0.6px; margin-bottom:6px; }
  .stat-value { font-size:1.6em; font-weight:700; }
  .toolbar { display:flex; gap:10px; flex-wrap:wrap; margin-bottom:20px; }
  .toolbar input, .toolbar select { background:var(--card); border:1px solid var(--border); border-radius:10px; padding:10px 14px; color:var(--text); font-size:0.95em; outline:none; transition:border-color 0.15s; }
  .toolbar input { flex:1; min-width:200px; }
  .toolbar input:focus, .toolbar select:focus { border-color:var(--accent); }
  .toolbar button { background:var(--accent); color:white; border:none; border-radius:10px; padding:10px 16px; font-size:0.95em; font-weight:600; cursor:pointer; }
  .toolbar button:hover { filter:brightness(1.1); }
  .toolbar button.danger { background:var(--danger); }
  .bulk-bar { display:none; align-items:center; gap:12px; background:#1e2230; border:1px solid var(--accent); border-radius:10px; padding:10px 16px; margin-bottom:12px; font-size:0.9em; }
  .bulk-bar.active { display:flex; }
  .bulk-bar button { background:var(--danger); color:white; border:none; border-radius:8px; padding:6px 12px; font-weight:600; cursor:pointer; font-size:0.9em; }
  .bulk-bar button.secondary { background:transparent; border:1px solid var(--border); color:var(--text); }
  #notifications { display:flex; flex-direction:column; gap:12px; }
  .notification { background:var(--card); border:1px solid var(--border); border-radius:12px; padding:14px 44px 14px 52px; position:relative; box-shadow:var(--shadow); transition:background 0.15s, transform 0.1s, opacity 0.3s; }
  .notification:hover { background:var(--card-hover); transform:translateY(-1px); }
  .notification.deleting { opacity:0.3; transform:scale(0.98); }
  .notification::before { content:""; position:absolute; left:0; top:12px; bottom:12px; width:4px; border-radius:4px; background:var(--bar-color, var(--accent)); }
  .checkbox-wrap { position:absolute; left:16px; top:16px; }
  .checkbox-wrap input { width:18px; height:18px; accent-color:var(--accent); cursor:pointer; }
  .delete-btn { position:absolute; top:10px; right:10px; width:26px; height:26px; border-radius:50%; border:none; background:transparent; color:var(--muted); font-size:1.1em; line-height:1; cursor:pointer; display:flex; align-items:center; justify-content:center; transition:background 0.15s, color 0.15s; }
  .delete-btn:hover { background:rgba(239,68,68,0.15); color:var(--danger); }
  .row1 { display:flex; align-items:center; gap:10px; flex-wrap:wrap; margin-bottom:6px; }
  .app-pill { font-size:0.75em; font-weight:700; padding:3px 10px; border-radius:999px; background:var(--pill-color, #2a2f42); color:#fff; letter-spacing:0.3px; }
  .phone-pill { font-size:0.75em; font-weight:600; padding:3px 10px; border-radius:999px; background:rgba(108,140,255,0.15); color:#a8bcff; }
  .device-pill { font-size:0.75em; font-weight:600; padding:3px 10px; border-radius:999px; background:rgba(34,197,94,0.15); color:#22c55e; }
  .time { margin-left:auto; font-size:0.78em; color:var(--muted); white-space:nowrap; }
  .title { font-weight:600; font-size:1.02em; margin-bottom:4px; word-wrap:break-word; }
  .body { color:#c4c9d8; font-size:0.95em; line-height:1.45; white-space:pre-wrap; word-wrap:break-word; }
  .empty { text-align:center; padding:60px 20px; color:var(--muted); background:var(--card); border-radius:12px; border:1px dashed var(--border); }
  .toast { position:fixed; bottom:24px; left:50%; transform:translateX(-50%) translateY(20px); background:#1e2230; border:1px solid var(--border); color:var(--text); padding:12px 20px; border-radius:10px; box-shadow:var(--shadow); opacity:0; transition:opacity 0.25s, transform 0.25s; pointer-events:none; font-size:0.9em; z-index:100; display:flex; align-items:center; }
  .toast.show { opacity:1; transform:translateX(-50%) translateY(0); pointer-events:auto; }
  .toast.error { border-color:var(--danger); color:#fecaca; }
  @media (max-width:600px) { main { padding:16px; } header { padding:12px 16px; } .time { width:100%; margin-left:0; } }
</style>
</head>
<body>
${navBar(email, 'dashboard')}
<main>
  <div class="stats">
    <div class="stat"><div class="stat-label">Total</div><div class="stat-value" id="stat-total">0</div></div>
    <div class="stat"><div class="stat-label">Last hour</div><div class="stat-value" id="stat-hour">0</div></div>
    <div class="stat"><div class="stat-label">Top app</div><div class="stat-value" id="stat-top" style="font-size:1em;">—</div></div>
  </div>

  <div class="toolbar">
    <input type="text" id="search" placeholder="Search title or body...">
    <select id="app-filter"><option value="">All apps</option></select>
    <select id="device-filter"><option value="">All devices</option></select>
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
    b.style.cssText = 'margin-left:14px;background:transparent;border:1px solid var(--accent);color:var(--accent);padding:4px 10px;border-radius:6px;cursor:pointer;font-weight:600;';
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
    if (!items.length) { c.innerHTML = '<div class="empty">No notifications match your filters.</div>'; return; }
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
      document.getElementById('status') && (document.getElementById('status').textContent = 'Live — connected');
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
  source.addEventListener('hello', () => { document.getElementById('status') && (document.getElementById('status').textContent = 'Live — connected'); });
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
  source.onerror = () => { const s = document.getElementById('status'); if (s) s.textContent = 'Reconnecting...'; };

  (async () => {
    await loadDevices();
    await loadApps();
    await loadNotifications();
  })();
</script>
</body>
</html>`;
}

app.listen(port, function() {
  console.log('Server running on port ' + port);
});
