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

app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// ---------------------------------------------------------------
// Database
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
        shelf_id INTEGER,
        notes TEXT,
        hash VARCHAR(64),
        timestamp TIMESTAMPTZ DEFAULT NOW(),
        raw_payload JSONB
      )
    `);
    await pool.query(`ALTER TABLE notifications ADD COLUMN IF NOT EXISTS phone VARCHAR(50)`);
    await pool.query(`ALTER TABLE notifications ADD COLUMN IF NOT EXISTS device_id INTEGER`);
    await pool.query(`ALTER TABLE notifications ADD COLUMN IF NOT EXISTS shelf_id INTEGER`);
    await pool.query(`ALTER TABLE notifications ADD COLUMN IF NOT EXISTS notes TEXT`);
    await pool.query(`ALTER TABLE notifications ADD COLUMN IF NOT EXISTS hash VARCHAR(64)`);

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
      CREATE TABLE IF NOT EXISTS shelves (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        name VARCHAR(100) NOT NULL,
        color VARCHAR(20) DEFAULT '#6c8cff',
        position INTEGER DEFAULT 0,
        created_at TIMESTAMPTZ DEFAULT NOW()
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS tags (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        name VARCHAR(50) NOT NULL,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        UNIQUE (user_id, name)
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS notification_tags (
        notification_id INTEGER NOT NULL REFERENCES notifications(id) ON DELETE CASCADE,
        tag_id INTEGER NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
        PRIMARY KEY (notification_id, tag_id)
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
  cookie: { httpOnly: true, sameSite: 'lax', secure: true, maxAge: 30 * 24 * 60 * 60 * 1000 }
}));

// ---------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------
function generateToken() {
  return crypto.randomBytes(24).toString('base64url');
}

function sha256Hex(str) {
  return crypto.createHash('sha256').update(String(str)).digest('hex');
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

  const ping = setInterval(() => { try { res.write(': ping\n\n'); } catch (e) {} }, 25000);
  req.on('close', () => { clearInterval(ping); sseClients.delete(res); });
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
    if (deviceResult.rowCount === 0) return res.status(404).json({ error: 'Unknown device token' });
    const device = deviceResult.rows[0];

    const payload = req.body;
    const hash = sha256Hex(JSON.stringify(payload));

    const inserted = await pool.query(
      `INSERT INTO notifications (phone, app, title, body, device_id, hash, raw_payload)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       RETURNING id, phone, app, title, body, device_id, shelf_id, notes, hash, timestamp`,
      [
        payload.phone || null,
        payload.app || null,
        payload.title || null,
        payload.body || null,
        device.id,
        hash,
        JSON.stringify(payload)
      ]
    );

    await pool.query('UPDATE devices SET last_seen_at = NOW() WHERE id = $1', [device.id]);

    const row = inserted.rows[0];
    row.tags = [];
    broadcast('notification', row);
    res.status(200).send('OK');
  } catch (err) {
    console.error('Webhook error:', err);
    res.status(500).send('Internal Server Error');
  }
});

// ---------------------------------------------------------------
// Auth
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
// Shelves API
// ---------------------------------------------------------------
app.get('/api/shelves', requireAuth, async (req, res) => {
  try {
    const shelves = await pool.query(
      'SELECT id, name, color, position, created_at FROM shelves WHERE user_id = $1 ORDER BY position ASC, id ASC',
      [req.session.userId]
    );
    res.json({ shelves: shelves.rows });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/shelves', requireAuth, async (req, res) => {
  try {
    const { name, color } = req.body;
    if (!name || !name.trim()) return res.status(400).json({ error: 'Shelf name is required.' });
    const maxPos = await pool.query('SELECT COALESCE(MAX(position), 0) AS m FROM shelves WHERE user_id = $1', [req.session.userId]);
    const result = await pool.query(
      'INSERT INTO shelves (user_id, name, color, position) VALUES ($1, $2, $3, $4) RETURNING id, name, color, position, created_at',
      [req.session.userId, name.trim(), (color || '#6c8cff'), maxPos.rows[0].m + 1]
    );
    broadcast('shelves-changed', {});
    res.json({ shelf: result.rows[0] });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.patch('/api/shelves/:id', requireAuth, async (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    const { name, color, position } = req.body;
    const check = await pool.query('SELECT id FROM shelves WHERE id = $1 AND user_id = $2', [id, req.session.userId]);
    if (check.rowCount === 0) return res.status(404).json({ error: 'Not found' });
    const result = await pool.query(
      'UPDATE shelves SET name = COALESCE($1, name), color = COALESCE($2, color), position = COALESCE($3, position) WHERE id = $4 RETURNING id, name, color, position, created_at',
      [name ? name.trim() : null, color || null, (position !== undefined ? position : null), id]
    );
    broadcast('shelves-changed', {});
    res.json({ shelf: result.rows[0] });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/shelves/:id', requireAuth, async (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    const check = await pool.query('SELECT id FROM shelves WHERE id = $1 AND user_id = $2', [id, req.session.userId]);
    if (check.rowCount === 0) return res.status(404).json({ error: 'Not found' });
    await pool.query('UPDATE notifications SET shelf_id = NULL WHERE shelf_id = $1', [id]);
    await pool.query('DELETE FROM shelves WHERE id = $1', [id]);
    broadcast('shelves-changed', {});
    broadcast('notifications-changed', {});
    res.json({ deleted: 1 });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ---------------------------------------------------------------
// Notifications API
// ---------------------------------------------------------------
function normaliseNotificationRow(row) {
  // Ensure tags is always an array (Postgres json_agg may return a string in some driver configs)
  if (typeof row.tags === 'string') {
    try { row.tags = JSON.parse(row.tags); } catch (e) { row.tags = []; }
  }
  if (!Array.isArray(row.tags)) row.tags = [];
  return row;
}

app.get('/api/notifications', requireAuth, async (req, res) => {
  try {
    const { app: appFilter, q, device_id, shelf } = req.query;
    let query = `
      SELECT n.id, n.phone, n.app, n.title, n.body, n.device_id, n.shelf_id, n.notes, n.hash, n.timestamp,
             COALESCE(json_agg(json_build_object('id', t.id, 'name', t.name)) FILTER (WHERE t.id IS NOT NULL), '[]'::json) AS tags
      FROM notifications n
      LEFT JOIN notification_tags nt ON nt.notification_id = n.id
      LEFT JOIN tags t ON t.id = nt.tag_id
    `;
    const conditions = [];
    const values = [];

    if (appFilter) { values.push(appFilter); conditions.push('n.app = $' + values.length); }
    if (device_id) { values.push(parseInt(device_id, 10)); conditions.push('n.device_id = $' + values.length); }
    if (shelf === '__unsorted__') conditions.push('n.shelf_id IS NULL');
    else if (shelf) { values.push(parseInt(shelf, 10)); conditions.push('n.shelf_id = $' + values.length); }
    if (q) { values.push('%' + q + '%'); conditions.push('(n.title ILIKE $' + values.length + ' OR n.body ILIKE $' + values.length + ')'); }
    if (conditions.length) query += ' WHERE ' + conditions.join(' AND ');
    query += ' GROUP BY n.id ORDER BY n.timestamp DESC LIMIT 300';

    const result = await pool.query(query, values);
    res.json({ notifications: result.rows.map(normaliseNotificationRow) });
  } catch (err) {
    console.error('notifications list error:', err);
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/apps', requireAuth, async (req, res) => {
  try {
    const result = await pool.query('SELECT DISTINCT app FROM notifications WHERE app IS NOT NULL ORDER BY app');
    res.json({ apps: result.rows.map(r => r.app) });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.patch('/api/notifications/:id', requireAuth, async (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    const { shelf_id, notes } = req.body;
    const updates = [];
    const values = [];
    if (shelf_id !== undefined) {
      values.push(shelf_id === null ? null : parseInt(shelf_id, 10));
      updates.push('shelf_id = $' + values.length);
    }
    if (notes !== undefined) {
      values.push(notes);
      updates.push('notes = $' + values.length);
    }
    if (!updates.length) return res.status(400).json({ error: 'Nothing to update' });
    values.push(id);
    const result = await pool.query(
      'UPDATE notifications SET ' + updates.join(', ') + ' WHERE id = $' + values.length +
      ' RETURNING id, phone, app, title, body, device_id, shelf_id, notes, hash, timestamp',
      values
    );
    broadcast('notifications-changed', {});
    res.json({ notification: result.rows[0] });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/notifications/bulk-shelf', requireAuth, async (req, res) => {
  try {
    const { ids, shelf_id } = req.body;
    if (!Array.isArray(ids) || !ids.length) return res.status(400).json({ error: 'ids array required' });
    const shelfVal = shelf_id === null ? null : parseInt(shelf_id, 10);
    await pool.query('UPDATE notifications SET shelf_id = $1 WHERE id = ANY($2::int[])', [shelfVal, ids]);
    broadcast('notifications-changed', {});
    res.json({ updated: ids.length });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/notifications/:id', requireAuth, async (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
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

// ---------------------------------------------------------------
// Tags
// ---------------------------------------------------------------
app.get('/api/tags', requireAuth, async (req, res) => {
  try {
    const result = await pool.query('SELECT id, name FROM tags WHERE user_id = $1 ORDER BY name', [req.session.userId]);
    res.json({ tags: result.rows });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/notifications/:id/tags', requireAuth, async (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    const name = (req.body.name || '').trim().toLowerCase();
    if (!name) return res.status(400).json({ error: 'Tag name required' });

    const exists = await pool.query('SELECT id FROM notifications WHERE id = $1', [id]);
    if (exists.rowCount === 0) return res.status(404).json({ error: 'Notification not found' });

    const tag = await pool.query(
      'INSERT INTO tags (user_id, name) VALUES ($1, $2) ON CONFLICT (user_id, name) DO UPDATE SET name = EXCLUDED.name RETURNING id, name',
      [req.session.userId, name]
    );
    await pool.query(
      'INSERT INTO notification_tags (notification_id, tag_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
      [id, tag.rows[0].id]
    );
    broadcast('notifications-changed', {});
    res.json({ tag: tag.rows[0] });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/notifications/:id/tags/:tagId', requireAuth, async (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    const tagId = parseInt(req.params.tagId, 10);
    await pool.query('DELETE FROM notification_tags WHERE notification_id = $1 AND tag_id = $2', [id, tagId]);
    broadcast('notifications-changed', {});
    res.json({ removed: 1 });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ---------------------------------------------------------------
// Export
// ---------------------------------------------------------------
app.get('/api/export', requireAuth, async (req, res) => {
  try {
    const { shelf } = req.query;
    let query = `
      SELECT n.id, n.phone, n.app, n.title, n.body, n.device_id, n.shelf_id, n.notes, n.hash, n.timestamp,
             d.name AS device_name,
             COALESCE(json_agg(json_build_object('id', t.id, 'name', t.name)) FILTER (WHERE t.id IS NOT NULL), '[]'::json) AS tags
      FROM notifications n
      LEFT JOIN devices d ON d.id = n.device_id
      LEFT JOIN notification_tags nt ON nt.notification_id = n.id
      LEFT JOIN tags t ON t.id = nt.tag_id
    `;
    const values = [];
    if (shelf === '__unsorted__') query += ' WHERE n.shelf_id IS NULL';
    else if (shelf) { values.push(parseInt(shelf, 10)); query += ' WHERE n.shelf_id = $1'; }
    query += ' GROUP BY n.id, d.name ORDER BY n.timestamp DESC LIMIT 2000';

    const result = await pool.query(query, values);
    const rows = result.rows.map(normaliseNotificationRow);
    const payload = JSON.stringify(rows);
    const exportHash = sha256Hex(payload);

    const exportObj = {
      exported_at: new Date().toISOString(),
      exported_by: req.session.email || 'user',
      shelf_filter: shelf || 'all',
      count: rows.length,
      export_sha256: exportHash,
      notifications: rows
    };

    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', 'attachment; filename="shelf-export-' + Date.now() + '.json"');
    res.send(JSON.stringify(exportObj, null, 2));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ---------------------------------------------------------------
// Prune
// ---------------------------------------------------------------
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
// ICONS
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
  shelf: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 3h16a1 1 0 0 1 1 1v6H3V4a1 1 0 0 1 1-1z"/><path d="M3 14h18v6a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1v-6z"/></svg>',
  tag: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20.59 13.41l-7.17 7.17a2 2 0 0 1-2.83 0L2 12V2h10l8.59 8.59a2 2 0 0 1 0 2.82z"/><line x1="7" y1="7" x2="7.01" y2="7"/></svg>',
  download: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>',
  note: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>',
  whatsapp: '<svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor" xmlns="http://www.w3.org/2000/svg"><path d="M17.472 14.382c-.297-.149-1.758-.867-2.03-.967-.273-.099-.471-.148-.67.15-.197.297-.767.966-.94 1.164-.173.199-.347.223-.644.075-.297-.15-1.255-.463-2.39-1.475-.883-.788-1.48-1.761-1.653-2.059-.173-.297-.018-.458.13-.606.134-.133.298-.347.446-.52.149-.174.198-.298.298-.497.099-.198.05-.371-.025-.52-.075-.149-.669-1.612-.916-2.207-.242-.579-.487-.5-.669-.51-.173-.008-.371-.01-.57-.01-.198 0-.52.074-.792.372-.272.297-1.04 1.016-1.04 2.479 0 1.462 1.065 2.875 1.213 3.074.149.198 2.096 3.2 5.077 4.487.709.306 1.262.489 1.694.625.712.227 1.36.195 1.871.118.571-.085 1.758-.719 2.006-1.413.248-.694.248-1.289.173-1.413-.074-.124-.272-.198-.57-.347m-5.421 7.403h-.004a9.87 9.87 0 01-5.031-1.378l-.361-.214-3.741.982.998-3.648-.235-.374a9.86 9.86 0 01-1.51-5.26c.001-5.45 4.436-9.884 9.888-9.884 2.64 0 5.122 1.03 6.988 2.898a9.825 9.825 0 012.893 6.994c-.003 5.45-4.437 9.884-9.885 9.884m8.413-18.297A11.815 11.815 0 0012.05 0C5.495 0 .16 5.335.157 11.892c0 2.096.547 4.142 1.588 5.945L.057 24l6.305-1.654a11.882 11.882 0 005.683 1.448h.005c6.554 0 11.89-5.335 11.893-11.893a11.821 11.821 0 00-3.48-8.413Z"/></svg>',
  logout: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>',
  trash: '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>',
  edit: '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>'
};

// ===============================================================
// STYLES
// ===============================================================
const BASE_STYLES = `
  :root, [data-theme="dark"] {
    --bg: #0b0d14; --bg-2: #0f121b; --card: #151925; --card-hover: #1b2030;
    --text: #eef1f8; --muted: #8b93a7; --accent: #6c8cff; --accent-2: #8c5cff;
    --accent-glow: rgba(108, 140, 255, 0.35); --danger: #ef4444; --success: #22c55e;
    --warning: #f59e0b; --border: #232838; --border-strong: #2f3548;
    --shadow: 0 8px 32px rgba(0,0,0,0.45); --shadow-sm: 0 2px 8px rgba(0,0,0,0.35);
    --input-bg: #0d1017; --pill-bg: #2a2f42;
  }
  [data-theme="light"] {
    --bg: #f4f6fb; --bg-2: #eef1f8; --card: #ffffff; --card-hover: #f8fafc;
    --text: #0f172a; --muted: #64748b; --accent: #4f6bff; --accent-2: #7c3aed;
    --accent-glow: rgba(79, 107, 255, 0.25); --danger: #dc2626; --success: #16a34a;
    --warning: #d97706; --border: #e2e8f0; --border-strong: #cbd5e1;
    --shadow: 0 8px 32px rgba(15,23,42,0.08); --shadow-sm: 0 2px 8px rgba(15,23,42,0.06);
    --input-bg: #ffffff; --pill-bg: #e2e8f0;
  }
  * { box-sizing: border-box; }
  html, body { margin: 0; padding: 0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Inter", "Segoe UI", Roboto, sans-serif;
    background: var(--bg); color: var(--text); min-height: 100vh;
    transition: background 0.25s ease, color 0.25s ease;
    -webkit-font-smoothing: antialiased;
  }
  a { color: var(--accent); }
  ::-webkit-scrollbar { width: 10px; height: 10px; }
  ::-webkit-scrollbar-track { background: transparent; }
  ::-webkit-scrollbar-thumb { background: var(--border-strong); border-radius: 5px; }
  ::-webkit-scrollbar-thumb:hover { background: var(--muted); }
  .theme-toggle {
    background: var(--card); border: 1px solid var(--border); color: var(--text);
    width: 36px; height: 36px; border-radius: 10px; cursor: pointer;
    display: inline-flex; align-items: center; justify-content: center; padding: 0;
    transition: border-color 0.15s, background 0.15s, transform 0.1s;
  }
  .theme-toggle svg { display: block; }
  .theme-toggle:hover { border-color: var(--accent); transform: scale(1.05); }
`;

const NAV_STYLES = `
  header.site-header {
    position: sticky; top: 0; z-index: 50;
    background: color-mix(in srgb, var(--bg) 88%, transparent);
    backdrop-filter: blur(14px); -webkit-backdrop-filter: blur(14px);
    border-bottom: 1px solid var(--border); padding: 14px 24px;
  }
  .header-inner {
    max-width: 1400px; margin: 0 auto;
    display: flex; align-items: center; justify-content: space-between;
    gap: 16px; flex-wrap: wrap;
  }
  .brand { display: flex; align-items: center; gap: 10px; font-weight: 700; font-size: 1.08em; letter-spacing: -0.01em; }
  .brand .logo {
    width: 28px; height: 28px; border-radius: 8px;
    background: linear-gradient(135deg, var(--accent), var(--accent-2));
    display: flex; align-items: center; justify-content: center;
    color: white; font-size: 0.9em; font-weight: 800;
    box-shadow: 0 4px 12px var(--accent-glow);
  }
  .brand .dot {
    width: 8px; height: 8px; border-radius: 50%;
    background: var(--success); box-shadow: 0 0 10px var(--success);
    animation: pulse 2s infinite; margin-left: -4px;
  }
  @keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: 0.35; } }
  .nav { display: flex; gap: 4px; }
  .nav-link {
    color: var(--muted); text-decoration: none; padding: 7px 14px;
    border-radius: 9px; font-size: 0.9em; font-weight: 500;
    transition: background 0.15s, color 0.15s;
  }
  .nav-link:hover { color: var(--text); background: var(--card); }
  .nav-link.active { color: var(--text); background: color-mix(in srgb, var(--accent) 18%, transparent); }
  .right-info { display: flex; align-items: center; gap: 10px; font-size: 0.85em; color: var(--muted); }
  .user-email { color: var(--text); font-weight: 500; }
  .logout {
    color: var(--muted); text-decoration: none; border: 1px solid var(--border);
    padding: 6px 12px; border-radius: 9px;
    transition: border-color 0.15s, color 0.15s; font-size: 0.95em;
    display: inline-flex; align-items: center; gap: 6px;
  }
  .logout svg { display: block; }
  .logout:hover { border-color: var(--danger); color: var(--danger); }
`;

const FOOTER_STYLES = `
  footer.site-footer {
    margin-top: 40px; padding: 28px 24px 36px;
    border-top: 1px solid var(--border); color: var(--muted);
    font-size: 0.82em; text-align: center; line-height: 1.7;
  }
  footer.site-footer .whatsapp-link {
    display: inline-flex; align-items: center; gap: 8px;
    background: rgba(37,211,102,0.12); color: #25D366;
    padding: 8px 16px; border-radius: 999px; font-weight: 600;
    margin-bottom: 10px; text-decoration: none;
    transition: background 0.15s, transform 0.1s;
  }
  footer.site-footer .whatsapp-link:hover { background: rgba(37,211,102,0.22); transform: translateY(-1px); }
  footer.site-footer .whatsapp-link svg { display: block; }
  footer.site-footer .credit { margin-top: 4px; }
  footer.site-footer .credit strong { color: var(--text); font-weight: 600; }
  footer.site-footer .version {
    display: inline-block; font-size: 0.85em; color: var(--muted);
    border: 1px solid var(--border); padding: 2px 10px;
    border-radius: 999px; margin-top: 8px;
  }
`;

const FOOTER_HTML = `
  <footer class="site-footer">
    <div>
      <a class="whatsapp-link" href="https://wa.me/254745361106" target="_blank" rel="noopener">
        ${ICONS.whatsapp} WhatsApp: 0745 361 106
      </a>
    </div>
    <div class="credit">Created by <strong>Gitau Computer Solutions</strong> and <strong>Gitau Tech Labs</strong></div>
    <div class="version">Version 1.0</div>
  </footer>
`;

const THEME_BOOTSTRAP = `
  (function() {
    try {
      var saved = localStorage.getItem('theme');
      var theme = saved || (window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark');
      document.documentElement.setAttribute('data-theme', theme);
    } catch (e) { document.documentElement.setAttribute('data-theme', 'dark'); }
  })();
`;

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
  const sub = isSignup ? 'Sign up to start organizing your shelves' : 'Sign in to view your dashboard';
  const submitLabel = isSignup ? 'Create account' : 'Sign in';
  const switchText = isSignup ? 'Already have an account?' : "Don't have an account?";
  const switchLink = isSignup ? '/login' : '/signup';
  const switchLabel = isSignup ? 'Sign in' : 'Create one';

  return `<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${title} — Notification Shelves</title>
<script>${THEME_BOOTSTRAP}</script>
<style>
  ${BASE_STYLES}
  ${FOOTER_STYLES}
  body {
    display: flex; flex-direction: column; align-items: center; justify-content: center; padding: 20px;
    background:
      radial-gradient(circle at 20% 0%, color-mix(in srgb, var(--accent) 12%, transparent), transparent 40%),
      radial-gradient(circle at 80% 100%, color-mix(in srgb, var(--accent-2) 10%, transparent), transparent 40%),
      var(--bg);
  }
  .top-bar { position: fixed; top: 16px; right: 16px; z-index: 10; }
  .auth-card {
    width: 100%; max-width: 420px; background: var(--card);
    border: 1px solid var(--border); border-radius: 18px;
    padding: 36px 32px; box-shadow: var(--shadow); margin: auto 0;
  }
  .logo-badge {
    width: 52px; height: 52px; border-radius: 14px;
    background: linear-gradient(135deg, var(--accent), var(--accent-2));
    display: flex; align-items: center; justify-content: center;
    color: white; font-size: 1.4em; font-weight: 800;
    box-shadow: 0 8px 24px var(--accent-glow); margin-bottom: 18px;
  }
  .auth-card h1 { margin: 0 0 6px 0; font-size: 1.55em; font-weight: 700; letter-spacing: -0.02em; }
  .subtitle { color: var(--muted); font-size: 0.92em; margin-bottom: 26px; }
  label { display: block; font-size: 0.82em; font-weight: 600; color: var(--muted); margin-bottom: 8px; margin-top: 16px; letter-spacing: 0.02em; }
  input {
    width: 100%; padding: 12px 14px; border-radius: 11px;
    border: 1px solid var(--border); background: var(--input-bg);
    color: var(--text); font-size: 0.95em; outline: none;
    transition: border-color 0.15s, box-shadow 0.15s; font-family: inherit;
  }
  input:focus { border-color: var(--accent); box-shadow: 0 0 0 3px var(--accent-glow); }
  button.submit {
    width: 100%; margin-top: 26px; padding: 13px;
    background: linear-gradient(135deg, var(--accent), var(--accent-2));
    color: white; border: none; border-radius: 11px;
    font-size: 1em; font-weight: 600; cursor: pointer;
    transition: transform 0.1s, box-shadow 0.15s;
    box-shadow: 0 6px 20px var(--accent-glow); font-family: inherit;
  }
  button.submit:hover { transform: translateY(-1px); box-shadow: 0 8px 26px var(--accent-glow); }
  .error {
    background: color-mix(in srgb, var(--danger) 15%, transparent);
    color: var(--danger);
    border: 1px solid color-mix(in srgb, var(--danger) 40%, transparent);
    padding: 11px 14px; border-radius: 10px; font-size: 0.88em; margin-bottom: 18px;
  }
  .switch { text-align: center; margin-top: 22px; font-size: 0.9em; color: var(--muted); }
  .switch a { color: var(--accent); text-decoration: none; font-weight: 600; }
</style>
</head>
<body>
  <div class="top-bar"><button class="theme-toggle" id="theme-toggle" aria-label="Toggle theme"></button></div>
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
    ${isSignup ? '<label for="confirm">Confirm password</label><input type="password" id="confirm" name="confirm" required autocomplete="new-password" minlength="8" placeholder="Repeat password">' : ''}
    <button class="submit" type="submit">${submitLabel}</button>
    <div class="switch">${switchText} <a href="${switchLink}">${switchLabel}</a></div>
  </form>
  ${FOOTER_HTML}
<script>${THEME_TOGGLE_SCRIPT} setupThemeToggle();</script>
</body>
</html>`;
}

// ===============================================================
// NAV
// ===============================================================
function navBar(email, active) {
  const cls = (path) => active === path ? 'nav-link active' : 'nav-link';
  return `
  <header class="site-header">
    <div class="header-inner">
      <div class="brand"><div class="logo">N</div><div class="dot"></div>Notification Shelves</div>
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
<title>My Devices — Notification Shelves</title>
<script>${THEME_BOOTSTRAP}</script>
<style>
  ${BASE_STYLES} ${NAV_STYLES} ${FOOTER_STYLES}
  main { max-width: 1180px; margin: 0 auto; padding: 32px 24px; }
  .page-head { margin-bottom: 28px; }
  .page-head h1 { margin: 0 0 6px 0; font-size: 1.6em; letter-spacing: -0.02em; }
  .page-head .subtitle { color: var(--muted); font-size: 0.95em; }
  .create-card { background: var(--card); border: 1px solid var(--border); border-radius: 16px; padding: 22px 24px; margin-bottom: 28px; box-shadow: var(--shadow-sm); }
  .section-title { margin: 0 0 16px 0; font-size: 1.05em; font-weight: 600; display: flex; align-items: center; gap: 10px; }
  .section-icon { display: inline-flex; align-items: center; justify-content: center; width: 28px; height: 28px; border-radius: 8px; background: linear-gradient(135deg, var(--accent), var(--accent-2)); color: white; box-shadow: 0 4px 12px var(--accent-glow); }
  .section-icon svg { display: block; }
  .form-row { display: flex; gap: 10px; flex-wrap: wrap; }
  .form-row input { flex: 1; min-width: 180px; background: var(--input-bg); border: 1px solid var(--border); border-radius: 11px; padding: 11px 14px; color: var(--text); font-size: 0.95em; outline: none; font-family: inherit; transition: border-color 0.15s, box-shadow 0.15s; }
  .form-row input:focus { border-color: var(--accent); box-shadow: 0 0 0 3px var(--accent-glow); }
  .form-row button { background: linear-gradient(135deg, var(--accent), var(--accent-2)); color: white; border: none; border-radius: 11px; padding: 11px 20px; font-size: 0.95em; font-weight: 600; cursor: pointer; box-shadow: 0 4px 16px var(--accent-glow); font-family: inherit; }
  .devices { display: flex; flex-direction: column; gap: 16px; }
  .device { background: var(--card); border: 1px solid var(--border); border-radius: 16px; padding: 20px 22px; box-shadow: var(--shadow-sm); }
  .device-head { display: flex; align-items: center; justify-content: space-between; gap: 12px; flex-wrap: wrap; margin-bottom: 12px; }
  .device-name { font-size: 1.12em; font-weight: 600; display: flex; align-items: center; gap: 10px; }
  .device-meta { color: var(--muted); font-size: 0.83em; margin-top: 4px; }
  .badge { display: inline-block; font-size: 0.68em; font-weight: 700; padding: 3px 9px; border-radius: 999px; letter-spacing: 0.5px; }
  .badge.online { background: color-mix(in srgb, var(--success) 18%, transparent); color: var(--success); }
  .badge.offline { background: color-mix(in srgb, var(--muted) 18%, transparent); color: var(--muted); }
  .url-row { display: flex; gap: 8px; align-items: stretch; margin-top: 12px; flex-wrap: wrap; }
  .url-box { flex: 1; min-width: 220px; background: var(--input-bg); border: 1px solid var(--border); border-radius: 11px; padding: 11px 14px; font-family: ui-monospace, Menlo, Consolas, monospace; font-size: 0.82em; color: var(--accent); word-break: break-all; }
  .btn { background: transparent; border: 1px solid var(--border); border-radius: 11px; padding: 9px 14px; color: var(--text); font-size: 0.85em; font-weight: 500; cursor: pointer; transition: border-color 0.15s, color 0.15s, background 0.15s; white-space: nowrap; font-family: inherit; }
  .btn:hover { border-color: var(--accent); color: var(--accent); background: color-mix(in srgb, var(--accent) 8%, transparent); }
  .btn.danger:hover { border-color: var(--danger); color: var(--danger); background: color-mix(in srgb, var(--danger) 8%, transparent); }
  .device-actions { display: flex; gap: 8px; margin-top: 14px; flex-wrap: wrap; }
  .empty { text-align: center; padding: 60px 20px; color: var(--muted); background: var(--card); border-radius: 16px; border: 1px dashed var(--border); }
  .toast { position: fixed; bottom: 24px; left: 50%; transform: translateX(-50%) translateY(20px); background: var(--card); border: 1px solid var(--border); color: var(--text); padding: 13px 22px; border-radius: 11px; box-shadow: var(--shadow); opacity: 0; transition: opacity 0.25s, transform 0.25s; pointer-events: none; font-size: 0.9em; z-index: 100; }
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
    <h2 class="section-title"><span class="section-icon">${ICONS.plus}</span>Add a new device</h2>
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
  ${THEME_TOGGLE_SCRIPT} setupThemeToggle();
  var toast = document.getElementById('toast');
  var toastTimer = null;
  function showToast(msg, isError) {
    toast.textContent = msg;
    toast.className = 'toast show' + (isError ? ' error' : '');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(function() { toast.className = 'toast' + (isError ? ' error' : ''); }, 2200);
  }
  function escapeHtml(s) { return String(s == null ? '' : s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#039;'); }
  function timeAgo(iso) {
    if (!iso) return 'Never seen';
    var diff = Date.now() - new Date(iso).getTime();
    var m = Math.floor(diff / 60000);
    if (m < 1) return 'just now';
    if (m < 60) return m + ' min ago';
    var h = Math.floor(m / 60);
    if (h < 24) return h + ' hr ago';
    var d = Math.floor(h / 24);
    return d + ' day' + (d === 1 ? '' : 's') + ' ago';
  }
  function webhookUrl(token) { return window.location.origin + '/webhook/' + token; }
  async function copyText(text, label) {
    try { await navigator.clipboard.writeText(text); showToast(label + ' copied'); }
    catch (e) {
      var ta = document.createElement('textarea'); ta.value = text;
      document.body.appendChild(ta); ta.select();
      try { document.execCommand('copy'); showToast(label + ' copied'); }
      catch (err) { showToast('Copy failed', true); }
      document.body.removeChild(ta);
    }
  }
  async function loadDevices() {
    var r = await fetch('/api/devices');
    if (r.status === 401) { location.href = '/login'; return; }
    var d = await r.json();
    renderDevices(d.devices);
  }
  function renderDevices(devices) {
    var c = document.getElementById('devices');
    if (!devices.length) { c.innerHTML = '<div class="empty">No devices yet. Add one above to generate a webhook URL.</div>'; return; }
    c.innerHTML = devices.map(function(dev) {
      var online = dev.last_seen_at && (Date.now() - new Date(dev.last_seen_at).getTime()) < 5 * 60 * 1000;
      var url = webhookUrl(dev.token);
      return '<div class="device" data-id="' + dev.id + '">' +
        '<div class="device-head"><div>' +
          '<div class="device-name">' + escapeHtml(dev.name) + '<span class="badge ' + (online ? 'online' : 'offline') + '">' + (online ? 'ONLINE' : 'IDLE') + '</span></div>' +
          '<div class="device-meta">' + (dev.phone_number ? escapeHtml(dev.phone_number) + ' · ' : '') + 'Last seen: ' + timeAgo(dev.last_seen_at) + '</div>' +
        '</div></div>' +
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
      '</div>';
    }).join('');
  }
  document.getElementById('create-btn').addEventListener('click', async function() {
    var name = document.getElementById('new-name').value.trim();
    var phone_number = document.getElementById('new-phone').value.trim();
    if (!name) { showToast('Device name is required', true); return; }
    var r = await fetch('/api/devices', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name: name, phone_number: phone_number }) });
    var d = await r.json();
    if (!r.ok) { showToast(d.error || 'Failed', true); return; }
    document.getElementById('new-name').value = '';
    document.getElementById('new-phone').value = '';
    showToast('Device created');
    loadDevices();
  });
  document.getElementById('devices').addEventListener('click', async function(ev) {
    var btn = ev.target.closest('button[data-action]');
    if (!btn) return;
    var action = btn.getAttribute('data-action');
    if (action === 'copy-url') copyText(webhookUrl(btn.getAttribute('data-token')), 'Webhook URL');
    else if (action === 'copy-token') copyText(btn.getAttribute('data-token'), 'Token');
    else if (action === 'rename') {
      var id = btn.getAttribute('data-id');
      var n = prompt('New device name:', btn.getAttribute('data-name'));
      if (n === null) return;
      var p = prompt('Phone number (optional):', btn.getAttribute('data-phone'));
      if (p === null) return;
      var r = await fetch('/api/devices/' + id, { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name: n, phone_number: p }) });
      if (!r.ok) { var d = await r.json(); showToast(d.error || 'Failed', true); return; }
      showToast('Device updated'); loadDevices();
    } else if (action === 'rotate') {
      if (!confirm('Rotate token? The old webhook URL will stop working immediately.')) return;
      var id2 = btn.getAttribute('data-id');
      var r2 = await fetch('/api/devices/' + id2 + '/rotate', { method: 'POST' });
      if (!r2.ok) { var d2 = await r2.json(); showToast(d2.error || 'Failed', true); return; }
      showToast('Token rotated'); loadDevices();
    } else if (action === 'delete') {
      var id3 = btn.getAttribute('data-id');
      if (!confirm('Delete device "' + btn.getAttribute('data-name') + '"?')) return;
      var r3 = await fetch('/api/devices/' + id3, { method: 'DELETE' });
      if (!r3.ok) { var d3 = await r3.json(); showToast(d3.error || 'Failed', true); return; }
      showToast('Device deleted'); loadDevices();
    }
  });
  loadDevices();
  setInterval(loadDevices, 30000);
</script>
</body>
</html>`;
}

// ===============================================================
// DASHBOARD
// ===============================================================
function renderDashboard(email) {
  return `<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Dashboard — Notification Shelves</title>
<script>${THEME_BOOTSTRAP}</script>
<style>
  ${BASE_STYLES} ${NAV_STYLES} ${FOOTER_STYLES}
  .layout { max-width: 1400px; margin: 0 auto; display: grid; grid-template-columns: 260px 1fr; gap: 24px; padding: 24px; }
  @media (max-width: 900px) { .layout { grid-template-columns: 1fr; padding: 16px; } .sidebar { position: static !important; } }

  .sidebar { position: sticky; top: 84px; align-self: start; background: var(--card); border: 1px solid var(--border); border-radius: 16px; padding: 16px; box-shadow: var(--shadow-sm); }
  .sidebar-title { font-size: 0.72em; text-transform: uppercase; letter-spacing: 0.08em; color: var(--muted); font-weight: 700; margin-bottom: 10px; padding: 0 6px; }
  .shelf-list { display: flex; flex-direction: column; gap: 2px; margin-bottom: 14px; }
  .shelf-item { display: flex; align-items: center; gap: 10px; padding: 8px 10px; border-radius: 9px; cursor: pointer; color: var(--muted); font-size: 0.9em; font-weight: 500; transition: background 0.15s, color 0.15s; position: relative; }
  .shelf-item:hover { background: var(--card-hover); color: var(--text); }
  .shelf-item.active { background: color-mix(in srgb, var(--accent) 18%, transparent); color: var(--text); }
  .shelf-item .shelf-dot { width: 10px; height: 10px; border-radius: 3px; flex: 0 0 auto; }
  .shelf-item .shelf-count { margin-left: auto; font-size: 0.78em; color: var(--muted); background: color-mix(in srgb, var(--muted) 15%, transparent); padding: 1px 7px; border-radius: 999px; }
  .shelf-item.active .shelf-count { color: var(--text); background: color-mix(in srgb, var(--accent) 30%, transparent); }
  .shelf-item .shelf-actions { display: none; gap: 4px; margin-left: 6px; }
  .shelf-item:hover .shelf-actions { display: flex; }
  .shelf-actions button { background: transparent; border: none; cursor: pointer; color: var(--muted); padding: 2px; border-radius: 4px; display: flex; align-items: center; }
  .shelf-actions button:hover { color: var(--danger); }
  .shelf-actions button.edit:hover { color: var(--accent); }
  .new-shelf-btn { width: 100%; padding: 10px; background: transparent; border: 1px dashed var(--border); color: var(--muted); border-radius: 10px; cursor: pointer; font-size: 0.88em; font-weight: 500; font-family: inherit; display: flex; align-items: center; justify-content: center; gap: 8px; transition: border-color 0.15s, color 0.15s; }
  .new-shelf-btn:hover { border-color: var(--accent); color: var(--accent); }
  .new-shelf-btn svg { display: block; }

  .main-col { min-width: 0; }
  .head-row { display: flex; align-items: center; justify-content: space-between; gap: 12px; margin-bottom: 18px; flex-wrap: wrap; }
  .page-title { margin: 0; font-size: 1.4em; letter-spacing: -0.02em; }
  .page-sub { color: var(--muted); font-size: 0.9em; margin-top: 4px; }
  .head-actions { display: flex; gap: 8px; }
  .export-btn { background: transparent; border: 1px solid var(--border); color: var(--text); border-radius: 11px; padding: 9px 14px; cursor: pointer; font-weight: 600; font-size: 0.88em; font-family: inherit; display: inline-flex; align-items: center; gap: 6px; }
  .export-btn:hover { border-color: var(--accent); color: var(--accent); }
  .export-btn svg { display: block; }

  .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; margin-bottom: 20px; }
  .stat { background: var(--card); border: 1px solid var(--border); border-radius: 14px; padding: 16px 18px; box-shadow: var(--shadow-sm); position: relative; overflow: hidden; }
  .stat::before { content: ""; position: absolute; top: 0; left: 0; right: 0; height: 3px; background: linear-gradient(90deg, var(--accent), var(--accent-2)); }
  .stat-label { color: var(--muted); font-size: 0.7em; font-weight: 600; text-transform: uppercase; letter-spacing: 0.08em; margin-bottom: 6px; display: flex; align-items: center; gap: 6px; }
  .stat-icon { display: inline-flex; align-items: center; justify-content: center; width: 20px; height: 20px; border-radius: 5px; background: color-mix(in srgb, var(--accent) 15%, transparent); color: var(--accent); }
  .stat-icon svg { width: 12px; height: 12px; display: block; }
  .stat-value { font-size: 1.6em; font-weight: 700; letter-spacing: -0.02em; }
  .stat-value.small { font-size: 1.05em; }

  .toolbar { display: flex; gap: 10px; flex-wrap: wrap; margin-bottom: 20px; align-items: center; }
  .toolbar input, .toolbar select { background: var(--card); border: 1px solid var(--border); border-radius: 11px; padding: 10px 13px; color: var(--text); font-size: 0.9em; outline: none; font-family: inherit; transition: border-color 0.15s, box-shadow 0.15s; }
  .toolbar input:focus, .toolbar select:focus { border-color: var(--accent); box-shadow: 0 0 0 3px var(--accent-glow); }
  .toolbar button { background: linear-gradient(135deg, var(--accent), var(--accent-2)); color: white; border: none; border-radius: 11px; padding: 10px 16px; font-size: 0.9em; font-weight: 600; cursor: pointer; font-family: inherit; box-shadow: 0 4px 16px var(--accent-glow); display: inline-flex; align-items: center; gap: 6px; }
  .toolbar button svg { display: block; }
  .toolbar button.ghost { background: transparent; color: var(--text); border: 1px solid var(--border); box-shadow: none; }
  .toolbar button.ghost:hover { border-color: var(--accent); color: var(--accent); }
  .toolbar button.danger { background: transparent; color: var(--danger); border: 1px solid var(--border); box-shadow: none; }
  .toolbar button.danger:hover { border-color: var(--danger); background: color-mix(in srgb, var(--danger) 8%, transparent); }

  .search-wrap { position: relative; flex: 1; min-width: 200px; display: flex; }
  .search-wrap input { flex: 1; padding-left: 38px; min-width: 0; }
  .search-icon { position: absolute; left: 13px; top: 50%; transform: translateY(-50%); color: var(--muted); pointer-events: none; display: flex; align-items: center; }
  .search-icon svg { display: block; }

  .bulk-bar { display: none; align-items: center; gap: 12px; flex-wrap: wrap; background: color-mix(in srgb, var(--accent) 10%, var(--card)); border: 1px solid color-mix(in srgb, var(--accent) 40%, transparent); border-radius: 12px; padding: 12px 18px; margin-bottom: 16px; font-size: 0.9em; font-weight: 500; }
  .bulk-bar.active { display: flex; }
  .bulk-bar button { background: var(--danger); color: white; border: none; border-radius: 9px; padding: 7px 14px; font-weight: 600; cursor: pointer; font-size: 0.88em; font-family: inherit; }
  .bulk-bar button.secondary { background: transparent; border: 1px solid var(--border); color: var(--text); }
  .bulk-bar select { background: var(--card); border: 1px solid var(--border); color: var(--text); border-radius: 9px; padding: 7px 10px; font-size: 0.88em; font-family: inherit; }

  #notifications { display: flex; flex-direction: column; gap: 12px; }
  .notification { background: var(--card); border: 1px solid var(--border); border-radius: 14px; padding: 16px 48px 16px 54px; position: relative; box-shadow: var(--shadow-sm); transition: background 0.15s, transform 0.1s, opacity 0.3s, border-color 0.15s; }
  .notification:hover { background: var(--card-hover); transform: translateY(-1px); border-color: var(--border-strong); }
  .notification.deleting { opacity: 0.25; transform: scale(0.98); }
  .notification::before { content: ""; position: absolute; left: 0; top: 14px; bottom: 14px; width: 4px; border-radius: 4px; background: var(--bar-color, var(--accent)); }
  .checkbox-wrap { position: absolute; left: 18px; top: 18px; }
  .checkbox-wrap input { width: 18px; height: 18px; accent-color: var(--accent); cursor: pointer; }
  .delete-btn { position: absolute; top: 12px; right: 12px; width: 28px; height: 28px; border-radius: 50%; border: none; background: transparent; color: var(--muted); font-size: 1.15em; line-height: 1; cursor: pointer; display: flex; align-items: center; justify-content: center; transition: background 0.15s, color 0.15s; font-family: inherit; }
  .delete-btn:hover { background: color-mix(in srgb, var(--danger) 15%, transparent); color: var(--danger); }
  .row1 { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; margin-bottom: 8px; }
  .app-pill { font-size: 0.72em; font-weight: 700; padding: 4px 10px; border-radius: 999px; background: var(--pill-color, var(--pill-bg)); color: #fff; letter-spacing: 0.3px; }
  .phone-pill, .shelf-pill, .device-pill { font-size: 0.72em; font-weight: 600; padding: 4px 10px; border-radius: 999px; }
  .phone-pill { background: color-mix(in srgb, var(--accent) 15%, transparent); color: var(--accent); }
  .device-pill { background: color-mix(in srgb, var(--success) 15%, transparent); color: var(--success); }
  .shelf-pill { background: color-mix(in srgb, var(--shelf-color, #6c8cff) 20%, transparent); color: var(--shelf-color, #6c8cff); border: 1px solid color-mix(in srgb, var(--shelf-color, #6c8cff) 40%, transparent); }
  .tag-chip { display: inline-flex; align-items: center; gap: 4px; font-size: 0.7em; font-weight: 600; padding: 3px 8px; border-radius: 999px; background: color-mix(in srgb, var(--muted) 15%, transparent); color: var(--muted); cursor: pointer; }
  .tag-chip:hover { background: color-mix(in srgb, var(--danger) 20%, transparent); color: var(--danger); }
  .time { margin-left: auto; font-size: 0.76em; color: var(--muted); white-space: nowrap; font-variant-numeric: tabular-nums; }
  .title { font-weight: 600; font-size: 1.02em; margin-bottom: 4px; word-wrap: break-word; }
  .body { color: var(--muted); font-size: 0.94em; line-height: 1.5; white-space: pre-wrap; word-wrap: break-word; }
  .notes { margin-top: 10px; padding: 9px 12px; font-size: 0.88em; background: color-mix(in srgb, var(--warning) 12%, transparent); border-left: 3px solid var(--warning); border-radius: 6px; color: var(--text); white-space: pre-wrap; word-wrap: break-word; }
  .hash { font-family: ui-monospace, Menlo, Consolas, monospace; font-size: 0.72em; color: var(--muted); opacity: 0.7; margin-top: 8px; word-break: break-all; }
  .card-tools { display: flex; gap: 6px; margin-top: 10px; flex-wrap: wrap; }
  .card-tools button { background: transparent; border: 1px solid var(--border); color: var(--muted); border-radius: 8px; padding: 4px 10px; font-size: 0.78em; font-weight: 500; cursor: pointer; font-family: inherit; display: inline-flex; align-items: center; gap: 5px; }
  .card-tools button:hover { border-color: var(--accent); color: var(--accent); }
  .card-tools button svg { display: block; }
  .empty { text-align: center; padding: 80px 20px; color: var(--muted); background: var(--card); border-radius: 16px; border: 1px dashed var(--border); }
  .toast { position: fixed; bottom: 24px; left: 50%; transform: translateX(-50%) translateY(20px); background: var(--card); border: 1px solid var(--border); color: var(--text); padding: 13px 22px; border-radius: 11px; box-shadow: var(--shadow); opacity: 0; transition: opacity 0.25s, transform 0.25s; pointer-events: none; font-size: 0.9em; z-index: 100; display: flex; align-items: center; }
  .toast.show { opacity: 1; transform: translateX(-50%) translateY(0); pointer-events: auto; }
  .toast.error { border-color: var(--danger); color: var(--danger); }
</style>
</head>
<body>
${navBar(email, 'dashboard')}
<div class="layout">
  <aside class="sidebar">
    <div class="sidebar-title">Shelves</div>
    <div class="shelf-list" id="shelf-list"></div>
    <button class="new-shelf-btn" id="new-shelf-btn">${ICONS.plus} New shelf</button>
  </aside>

  <section class="main-col">
    <div class="head-row">
      <div>
        <h1 class="page-title" id="page-title">All notifications</h1>
        <div class="page-sub" id="page-sub">Everything captured across all shelves</div>
      </div>
      <div class="head-actions">
        <button class="export-btn" id="export-btn">${ICONS.download} Export</button>
      </div>
    </div>

    <div class="stats">
      <div class="stat"><div class="stat-label"><span class="stat-icon">${ICONS.bell}</span> Total</div><div class="stat-value" id="stat-total">0</div></div>
      <div class="stat"><div class="stat-label"><span class="stat-icon">${ICONS.clock}</span> Last hour</div><div class="stat-value" id="stat-hour">0</div></div>
      <div class="stat"><div class="stat-label"><span class="stat-icon">${ICONS.shelf}</span> Shelves</div><div class="stat-value small" id="stat-shelves">0</div></div>
      <div class="stat"><div class="stat-label"><span class="stat-icon">${ICONS.smartphone}</span> Devices</div><div class="stat-value small" id="stat-devices">0</div></div>
    </div>

    <div class="toolbar">
      <div class="search-wrap"><span class="search-icon">${ICONS.search}</span><input type="text" id="search" placeholder="Search title or body..."></div>
      <select id="app-filter"><option value="">All apps</option></select>
      <select id="device-filter"><option value="">All devices</option></select>
      <button id="refresh-btn" class="ghost">${ICONS.refresh} Refresh</button>
      <button id="clear-btn" class="danger">Clear all</button>
    </div>

    <div class="bulk-bar" id="bulk-bar">
      <span id="bulk-count">0 selected</span>
      <select id="bulk-shelf-select"><option value="">Move to shelf…</option></select>
      <button id="bulk-move">Move</button>
      <button id="bulk-delete">Delete</button>
      <button id="bulk-clear" class="secondary">Cancel</button>
    </div>

    <div id="notifications"></div>
  </section>
</div>
${FOOTER_HTML}
<div class="toast" id="toast"></div>

<script>
  ${THEME_TOGGLE_SCRIPT} setupThemeToggle();

  var APP_COLORS = {
    'com.whatsapp':'#25D366','com.whatsapp.w4b':'#25D366','com.google.android.apps.messaging':'#4285F4','com.android.mms':'#4285F4','com.samsung.android.messaging':'#4285F4','com.facebook.katana':'#1877F2','com.facebook.orca':'#0084FF','com.instagram.android':'#E1306C','com.twitter.android':'#1DA1F2','org.telegram.messenger':'#229ED9','com.google.android.gm':'#EA4335','com.google.android.apps.photos':'#FBBC04','com.android.systemui':'#6B7280','com.google.android.dialer':'#34A853','com.google.android.apps.maps':'#34A853','com.spotify.music':'#1DB954','com.netflix.mediaclient':'#E50914','com.google.android.youtube':'#FF0000','com.discord':'#5865F2','com.android.chrome':'#4285F4'
  };
  var DEFAULT_COLOR = '#6c8cff';
  function colorFor(a) { return APP_COLORS[a] || DEFAULT_COLOR; }
  function shortApp(a) { if (!a) return 'unknown'; var p = a.split('.'); return p[p.length-1] || a; }
  function escapeHtml(s) { return String(s == null ? '' : s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#039;'); }
  function formatTime(iso) {
    return new Date(iso).toLocaleString('en-GB', { timeZone:'Africa/Nairobi', year:'numeric', month:'short', day:'2-digit', hour:'2-digit', minute:'2-digit', second:'2-digit', hour12:false }) + ' EAT';
  }

  var toast = document.getElementById('toast');
  var toastTimer = null;
  function showToast(msg, isError) {
    toast.textContent = msg;
    toast.className = 'toast show' + (isError ? ' error' : '');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(function() { toast.className = 'toast' + (isError ? ' error' : ''); }, 2200);
  }
  function showUndoToast(msg, onUndo) {
    toast.innerHTML = '';
    var t = document.createElement('span'); t.textContent = msg;
    var b = document.createElement('button');
    b.textContent = 'Undo';
    b.style.cssText = 'margin-left:14px;background:transparent;border:1px solid var(--accent);color:var(--accent);padding:5px 12px;border-radius:7px;cursor:pointer;font-weight:600;font-family:inherit;';
    b.onclick = function() { onUndo(); toast.className = 'toast'; };
    toast.appendChild(t); toast.appendChild(b);
    toast.className = 'toast show';
    clearTimeout(toastTimer);
    toastTimer = setTimeout(function() { toast.className = 'toast'; }, 5000);
  }

  var allItems = [];
  var shelves = [];
  var shelvesById = {};
  var devicesById = {};
  var activeShelf = '';
  var selectedIds = new Set();

  function updateBulkBar() {
    var bar = document.getElementById('bulk-bar');
    var c = document.getElementById('bulk-count');
    if (selectedIds.size > 0) { bar.classList.add('active'); c.textContent = selectedIds.size + ' selected'; }
    else bar.classList.remove('active');
  }

  function renderShelfList() {
    var list = document.getElementById('shelf-list');
    var counts = {};
    var unsortedCount = 0;
    allItems.forEach(function(n) {
      if (n.shelf_id === null || n.shelf_id === undefined) unsortedCount++;
      else counts[n.shelf_id] = (counts[n.shelf_id] || 0) + 1;
    });

    var html = '';
    html += '<div class="shelf-item ' + (activeShelf === '' ? 'active' : '') + '" data-shelf="">' +
      '<span class="shelf-dot" style="background:var(--accent);"></span>All' +
      '<span class="shelf-count">' + allItems.length + '</span></div>';
    html += '<div class="shelf-item ' + (activeShelf === '__unsorted__' ? 'active' : '') + '" data-shelf="__unsorted__">' +
      '<span class="shelf-dot" style="background:var(--muted);"></span>Unsorted' +
      '<span class="shelf-count">' + unsortedCount + '</span></div>';

    shelves.forEach(function(s) {
      var c = counts[s.id] || 0;
      var active = String(activeShelf) === String(s.id) ? 'active' : '';
      html += '<div class="shelf-item ' + active + '" data-shelf="' + s.id + '">' +
        '<span class="shelf-dot" style="background:' + escapeHtml(s.color) + ';"></span>' +
        escapeHtml(s.name) +
        '<span class="shelf-count">' + c + '</span>' +
        '<span class="shelf-actions">' +
          '<button class="edit" data-shelf-action="edit" data-id="' + s.id + '" title="Edit">${ICONS.edit}</button>' +
          '<button data-shelf-action="delete" data-id="' + s.id + '" data-name="' + escapeHtml(s.name) + '" title="Delete">${ICONS.trash}</button>' +
        '</span>' +
      '</div>';
    });
    list.innerHTML = html;

    var sel = document.getElementById('bulk-shelf-select');
    var cur = sel.value;
    sel.innerHTML = '<option value="">Move to shelf…</option>' +
      '<option value="__unsorted__">Unsorted</option>' +
      shelves.map(function(s) { return '<option value="' + s.id + '">' + escapeHtml(s.name) + '</option>'; }).join('');
    sel.value = cur;

    document.getElementById('stat-shelves').textContent = shelves.length;
  }

  function renderList(items) {
    var c = document.getElementById('notifications');
    if (!items.length) {
      c.innerHTML = '<div class="empty">No notifications match your filters.<br><span style="font-size:0.9em;opacity:0.7;margin-top:8px;display:inline-block;">Send a test from Notifikator to get started.</span></div>';
      return;
    }
    var parts = [];
    items.forEach(function(n) {
      try {
        var color = colorFor(n.app);
        var checked = selectedIds.has(String(n.id));
        var dev = devicesById[n.device_id];
        var shelf = shelvesById[n.shelf_id];
        var tags = Array.isArray(n.tags) ? n.tags : [];
        parts.push(
          '<div class="notification" data-id="' + n.id + '" style="--bar-color:' + color + ';">' +
            '<div class="checkbox-wrap"><input type="checkbox" class="select-cb" data-id="' + n.id + '"' + (checked ? ' checked' : '') + '></div>' +
            '<button class="delete-btn" title="Delete" data-id="' + n.id + '">×</button>' +
            '<div class="row1">' +
              '<span class="app-pill" style="--pill-color:' + color + ';">' + escapeHtml(shortApp(n.app)) + '</span>' +
              (shelf ? '<span class="shelf-pill" style="--shelf-color:' + escapeHtml(shelf.color) + ';">' + escapeHtml(shelf.name) + '</span>' : '') +
              (dev ? '<span class="device-pill">' + escapeHtml(dev.name) + '</span>' : '') +
              '<span class="phone-pill">' + escapeHtml(n.phone || 'Unknown') + '</span>' +
              tags.map(function(t) {
                return '<span class="tag-chip" data-tag-id="' + t.id + '" data-notif-id="' + n.id + '" title="Remove tag">' + escapeHtml(t.name) + ' ×</span>';
              }).join('') +
              '<span class="time">' + formatTime(n.timestamp) + '</span>' +
            '</div>' +
            (n.title ? '<div class="title">' + escapeHtml(n.title) + '</div>' : '') +
            (n.body ? '<div class="body">' + escapeHtml(n.body) + '</div>' : '') +
            (n.notes ? '<div class="notes">' + escapeHtml(n.notes) + '</div>' : '') +
            '<div class="card-tools">' +
              '<button data-tool="tag" data-id="' + n.id + '">${ICONS.tag} Tag</button>' +
              '<button data-tool="notes" data-id="' + n.id + '">${ICONS.note} ' + (n.notes ? 'Edit note' : 'Note') + '</button>' +
            '</div>' +
            (n.hash ? '<div class="hash">sha256:' + n.hash.substring(0, 32) + '…</div>' : '') +
          '</div>'
        );
      } catch (e) {
        console.error('Failed to render notification', n, e);
      }
    });
    c.innerHTML = parts.join('');
  }

  function renderStats(items) {
    var total = items.length;
    var hour = items.filter(function(n) { return new Date(n.timestamp).getTime() > Date.now() - 3600000; }).length;
    document.getElementById('stat-total').textContent = total;
    document.getElementById('stat-hour').textContent = hour;
    document.getElementById('stat-devices').textContent = Object.keys(devicesById).length;
  }

  async function loadShelves() {
    var r = await fetch('/api/shelves');
    if (r.status === 401) { location.href = '/login'; return; }
    var d = await r.json();
    shelves = d.shelves || [];
    shelvesById = {};
    shelves.forEach(function(s) { shelvesById[s.id] = s; });
    renderShelfList();
  }

  async function loadDevices() {
    var r = await fetch('/api/devices');
    if (r.status === 401) { location.href = '/login'; return; }
    var d = await r.json();
    devicesById = {};
    d.devices.forEach(function(x) { devicesById[x.id] = x; });
    var sel = document.getElementById('device-filter');
    var cur = sel.value;
    sel.innerHTML = '<option value="">All devices</option>';
    d.devices.forEach(function(x) {
      var o = document.createElement('option');
      o.value = String(x.id);
      o.textContent = x.name;
      sel.appendChild(o);
    });
    sel.value = cur;
  }

  async function loadApps() {
    var r = await fetch('/api/apps');
    if (r.status === 401) { location.href = '/login'; return; }
    var d = await r.json();
    var sel = document.getElementById('app-filter');
    var cur = sel.value;
    sel.innerHTML = '<option value="">All apps</option>';
    d.apps.forEach(function(a) {
      var o = document.createElement('option');
      o.value = a;
      o.textContent = shortApp(a);
      sel.appendChild(o);
    });
    sel.value = cur;
  }

  async function loadNotifications() {
    try {
      var r = await fetch('/api/notifications');
      if (r.status === 401) { location.href = '/login'; return; }
      var d = await r.json();
      if (d.error) { console.error('API error:', d.error); showToast('Load error: ' + d.error, true); return; }
      allItems = d.notifications || [];
      applyFilters();
    } catch (e) {
      console.error('loadNotifications failed', e);
    }
  }

  function applyFilters() {
    var q = document.getElementById('search').value.trim().toLowerCase();
    var app = document.getElementById('app-filter').value;
    var device = document.getElementById('device-filter').value;

    renderShelfList();
    renderStats(allItems);

    var f = allItems.filter(function(n) {
      if (activeShelf === '__unsorted__') { if (n.shelf_id !== null && n.shelf_id !== undefined) return false; }
      else if (activeShelf !== '') { if (String(n.shelf_id) !== String(activeShelf)) return false; }
      if (app && n.app !== app) return false;
      if (device && String(n.device_id) !== String(device)) return false;
      if (q) {
        var h = ((n.title || '') + ' ' + (n.body || '') + ' ' + (n.notes || '')).toLowerCase();
        if (h.indexOf(q) === -1) return false;
      }
      return true;
    });
    renderList(f);
    updateBulkBar();

    var titleEl = document.getElementById('page-title');
    var subEl = document.getElementById('page-sub');
    if (activeShelf === '') { titleEl.textContent = 'All notifications'; subEl.textContent = 'Everything captured across all shelves'; }
    else if (activeShelf === '__unsorted__') { titleEl.textContent = 'Unsorted'; subEl.textContent = 'Notifications not yet placed on a shelf'; }
    else {
      var s = shelvesById[activeShelf];
      titleEl.textContent = s ? s.name : 'Shelf';
      subEl.textContent = 'Notifications assigned to this shelf';
    }
  }

  document.getElementById('shelf-list').addEventListener('click', async function(ev) {
    var action = ev.target.closest('button[data-shelf-action]');
    if (action) {
      ev.stopPropagation();
      var id = parseInt(action.getAttribute('data-id'), 10);
      if (action.getAttribute('data-shelf-action') === 'delete') {
        if (!confirm('Delete this shelf? Notifications inside will move to Unsorted.')) return;
        var r = await fetch('/api/shelves/' + id, { method: 'DELETE' });
        if (r.ok) { showToast('Shelf deleted'); if (String(activeShelf) === String(id)) activeShelf = ''; await loadShelves(); await loadNotifications(); }
      } else if (action.getAttribute('data-shelf-action') === 'edit') {
        var s = shelvesById[id];
        if (!s) return;
        var name = prompt('Shelf name:', s.name);
        if (name === null) return;
        var color = prompt('Color (hex):', s.color);
        if (color === null) return;
        var r2 = await fetch('/api/shelves/' + id, { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name: name, color: color }) });
        if (r2.ok) { showToast('Shelf updated'); await loadShelves(); }
      }
      return;
    }
    var item = ev.target.closest('.shelf-item');
    if (!item) return;
    activeShelf = item.getAttribute('data-shelf');
    applyFilters();
  });

  document.getElementById('new-shelf-btn').addEventListener('click', async function() {
    var name = prompt('Shelf name:');
    if (!name || !name.trim()) return;
    var color = prompt('Color (hex, optional):', '#6c8cff');
    var r = await fetch('/api/shelves', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name: name.trim(), color: color || '#6c8cff' }) });
    if (!r.ok) { var d = await r.json(); showToast(d.error || 'Failed', true); return; }
    showToast('Shelf created');
    await loadShelves();
  });

  document.getElementById('bulk-move').addEventListener('click', async function() {
    if (!selectedIds.size) return;
    var val = document.getElementById('bulk-shelf-select').value;
    if (!val) { showToast('Pick a shelf first', true); return; }
    var shelf_id = val === '__unsorted__' ? null : parseInt(val, 10);
    var ids = Array.from(selectedIds).map(function(x) { return parseInt(x, 10); });
    var r = await fetch('/api/notifications/bulk-shelf', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ids: ids, shelf_id: shelf_id }) });
    if (!r.ok) { var d = await r.json(); showToast(d.error || 'Failed', true); return; }
    showToast('Moved ' + ids.length + ' notification(s)');
    selectedIds.clear();
    await loadNotifications();
  });

  document.getElementById('notifications').addEventListener('click', async function(ev) {
    var del = ev.target.closest('.delete-btn');
    if (del) {
      var id = del.getAttribute('data-id');
      var item = allItems.find(function(n) { return String(n.id) === String(id); });
      if (!item) return;
      allItems = allItems.filter(function(n) { return String(n.id) !== String(id); });
      applyFilters();
      var timer = setTimeout(async function() {
        try { await fetch('/api/notifications/' + id, { method: 'DELETE' }); } catch (e) {}
      }, 5000);
      showUndoToast('Notification deleted', function() {
        clearTimeout(timer);
        allItems.push(item);
        allItems.sort(function(a,b) { return new Date(b.timestamp) - new Date(a.timestamp); });
        applyFilters();
        showToast('Restored');
      });
      return;
    }
    var tagChip = ev.target.closest('.tag-chip');
    if (tagChip) {
      var tagId = tagChip.getAttribute('data-tag-id');
      var notifId = tagChip.getAttribute('data-notif-id');
      var r = await fetch('/api/notifications/' + notifId + '/tags/' + tagId, { method: 'DELETE' });
      if (r.ok) { showToast('Tag removed'); await loadNotifications(); }
      return;
    }
    var tool = ev.target.closest('button[data-tool]');
    if (tool) {
      var id2 = tool.getAttribute('data-id');
      var item2 = allItems.find(function(n) { return String(n.id) === String(id2); });
      if (!item2) return;
      if (tool.getAttribute('data-tool') === 'tag') {
        var name = prompt('Add tag (lowercase, one word):');
        if (!name || !name.trim()) return;
        var r2 = await fetch('/api/notifications/' + id2 + '/tags', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name: name.trim() }) });
        if (r2.ok) { showToast('Tag added'); await loadNotifications(); }
        else { var d2 = await r2.json(); showToast(d2.error || 'Failed', true); }
      } else if (tool.getAttribute('data-tool') === 'notes') {
        var current = item2.notes || '';
        var notes = prompt('Note for this notification:', current);
        if (notes === null) return;
        var r3 = await fetch('/api/notifications/' + id2, { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ notes: notes }) });
        if (r3.ok) { showToast('Note saved'); await loadNotifications(); }
      }
      return;
    }
  });

  document.getElementById('notifications').addEventListener('change', function(ev) {
    var cb = ev.target.closest('.select-cb');
    if (!cb) return;
    var id = cb.getAttribute('data-id');
    if (cb.checked) selectedIds.add(String(id));
    else selectedIds.delete(String(id));
    updateBulkBar();
  });

  document.getElementById('bulk-clear').addEventListener('click', function() { selectedIds.clear(); applyFilters(); });
  document.getElementById('bulk-delete').addEventListener('click', function() {
    if (!selectedIds.size) return;
    var ids = Array.from(selectedIds);
    if (!confirm('Delete ' + ids.length + ' notification(s)?')) return;
    allItems = allItems.filter(function(n) { return !selectedIds.has(String(n.id)); });
    applyFilters();
    selectedIds.clear();
    updateBulkBar();
    Promise.all(ids.map(function(id) {
      return fetch('/api/notifications/' + id, { method: 'DELETE' }).catch(function() { return null; });
    })).then(function() { showToast('Deleted ' + ids.length + ' notification(s)'); });
  });

  document.getElementById('clear-btn').addEventListener('click', async function() {
    if (!confirm('Delete ALL notifications? This cannot be undone.')) return;
    var r = await fetch('/api/notifications', { method: 'DELETE' });
    var d = await r.json();
    if (r.ok) { allItems = []; selectedIds.clear(); applyFilters(); showToast('Cleared ' + d.deleted); }
  });

  document.getElementById('search').addEventListener('input', applyFilters);
  document.getElementById('app-filter').addEventListener('change', applyFilters);
  document.getElementById('device-filter').addEventListener('change', applyFilters);
  document.getElementById('refresh-btn').addEventListener('click', function() {
    loadShelves(); loadDevices(); loadApps(); loadNotifications();
  });
  document.getElementById('export-btn').addEventListener('click', function() {
    var params = new URLSearchParams();
    if (activeShelf === '__unsorted__') params.set('shelf', '__unsorted__');
    else if (activeShelf !== '') params.set('shelf', activeShelf);
    window.location.href = '/api/export' + (params.toString() ? '?' + params.toString() : '');
  });

  var source = new EventSource('/api/stream');
  source.addEventListener('notification', function(ev) {
    var n = JSON.parse(ev.data);
    if (!allItems.some(function(x) { return x.id === n.id; })) {
      n.tags = [];
      allItems.unshift(n);
      applyFilters();
      var dev = devicesById[n.device_id];
      showToast('New: ' + shortApp(n.app) + (dev ? ' on ' + dev.name : ''));
    }
  });
  source.addEventListener('deleted', function(ev) {
    var payload = JSON.parse(ev.data);
    allItems = allItems.filter(function(n) { return n.id !== payload.id; });
    applyFilters();
  });
  source.addEventListener('cleared', function() { allItems = []; applyFilters(); });
  source.addEventListener('notifications-changed', function() { loadNotifications(); });
  source.addEventListener('shelves-changed', function() { loadShelves(); });

  (async function() {
    await loadShelves();
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
