const express = require('express');
const { Pool } = require('pg');
const app = express();
const port = process.env.PORT || 3000;

app.use(express.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

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
    console.log('Database table initialized.');
  } catch (err) {
    console.error('Error initializing database:', err);
  }
}
initDb();

app.post('/webhook', async (req, res) => {
  try {
    const payload = req.body;

    console.log('=== INCOMING WEBHOOK ===');
    console.log('Raw body:', JSON.stringify(payload, null, 2));
    console.log('========================');

    await pool.query(
      'INSERT INTO notifications (phone, app, title, body, raw_payload) VALUES ($1, $2, $3, $4, $5)',
      [
        payload.phone || null,
        payload.app || null,
        payload.title || null,
        payload.body || null,
        JSON.stringify(payload)
      ]
    );

    res.status(200).send('OK');
  } catch (err) {
    console.error('Error processing webhook:', err);
    res.status(500).send('Internal Server Error');
  }
});

app.get('/count', async (req, res) => {
  try {
    const total = await pool.query('SELECT COUNT(*) FROM notifications');
    const latest = await pool.query(
      'SELECT id, phone, app, title, body, timestamp FROM notifications ORDER BY id DESC LIMIT 10'
    );
    res.json({
      total: parseInt(total.rows[0].count, 10),
      latest: latest.rows
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Simple JSON API used by the dashboard's live refresh
app.get('/api/notifications', async (req, res) => {
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
    if (conditions.length) {
      query += ' WHERE ' + conditions.join(' AND ');
    }
    query += ' ORDER BY timestamp DESC LIMIT 200';

    const result = await pool.query(query, values);
    res.json({ notifications: result.rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Distinct list of apps, for the filter dropdown
app.get('/api/apps', async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT DISTINCT app FROM notifications WHERE app IS NOT NULL ORDER BY app'
    );
    res.json({ apps: result.rows.map(r => r.app) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/', async (req, res) => {
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Notification Dashboard</title>
<style>
  :root {
    --bg: #0f1117;
    --card: #171a23;
    --card-hover: #1e2230;
    --text: #e6e8ef;
    --muted: #8b93a7;
    --accent: #6c8cff;
    --border: #262a38;
    --shadow: 0 4px 20px rgba(0,0,0,0.35);
  }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    background: var(--bg);
    color: var(--text);
    min-height: 100vh;
  }
  header {
    position: sticky;
    top: 0;
    z-index: 10;
    background: rgba(15,17,23,0.85);
    backdrop-filter: blur(10px);
    border-bottom: 1px solid var(--border);
    padding: 16px 24px;
  }
  .header-inner {
    max-width: 1100px;
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
    font-size: 1.15em;
    letter-spacing: 0.2px;
  }
  .dot {
    width: 10px;
    height: 10px;
    border-radius: 50%;
    background: #22c55e;
    box-shadow: 0 0 12px #22c55e;
    animation: pulse 2s infinite;
  }
  @keyframes pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.4; }
  }
  .status {
    color: var(--muted);
    font-size: 0.85em;
    font-weight: 500;
  }
  main {
    max-width: 1100px;
    margin: 0 auto;
    padding: 24px;
  }
  .stats {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 12px;
    margin-bottom: 20px;
  }
  .stat {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 16px;
    box-shadow: var(--shadow);
  }
  .stat-label {
    color: var(--muted);
    font-size: 0.78em;
    text-transform: uppercase;
    letter-spacing: 0.6px;
    margin-bottom: 6px;
  }
  .stat-value {
    font-size: 1.6em;
    font-weight: 700;
  }
  .toolbar {
    display: flex;
    gap: 10px;
    flex-wrap: wrap;
    margin-bottom: 20px;
  }
  .toolbar input,
  .toolbar select {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 10px 14px;
    color: var(--text);
    font-size: 0.95em;
    outline: none;
    transition: border-color 0.15s;
  }
  .toolbar input { flex: 1; min-width: 200px; }
  .toolbar input:focus,
  .toolbar select:focus { border-color: var(--accent); }
  .toolbar button {
    background: var(--accent);
    color: white;
    border: none;
    border-radius: 10px;
    padding: 10px 16px;
    font-size: 0.95em;
    font-weight: 600;
    cursor: pointer;
  }
  .toolbar button:hover { filter: brightness(1.1); }
  #notifications {
    display: flex;
    flex-direction: column;
    gap: 12px;
  }
  .notification {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 14px 16px 14px 20px;
    position: relative;
    box-shadow: var(--shadow);
    transition: background 0.15s, transform 0.1s;
  }
  .notification:hover {
    background: var(--card-hover);
    transform: translateY(-1px);
  }
  .notification::before {
    content: "";
    position: absolute;
    left: 0;
    top: 12px;
    bottom: 12px;
    width: 4px;
    border-radius: 4px;
    background: var(--bar-color, var(--accent));
  }
  .row1 {
    display: flex;
    align-items: center;
    gap: 10px;
    flex-wrap: wrap;
    margin-bottom: 6px;
  }
  .app-pill {
    font-size: 0.75em;
    font-weight: 700;
    padding: 3px 10px;
    border-radius: 999px;
    background: var(--pill-color, #2a2f42);
    color: #fff;
    letter-spacing: 0.3px;
  }
  .phone-pill {
    font-size: 0.75em;
    font-weight: 600;
    padding: 3px 10px;
    border-radius: 999px;
    background: rgba(108,140,255,0.15);
    color: #a8bcff;
  }
  .time {
    margin-left: auto;
    font-size: 0.78em;
    color: var(--muted);
    white-space: nowrap;
  }
  .title {
    font-weight: 600;
    font-size: 1.02em;
    margin-bottom: 4px;
    word-wrap: break-word;
  }
  .body {
    color: #c4c9d8;
    font-size: 0.95em;
    line-height: 1.45;
    white-space: pre-wrap;
    word-wrap: break-word;
  }
  .empty {
    text-align: center;
    padding: 60px 20px;
    color: var(--muted);
    background: var(--card);
    border-radius: 12px;
    border: 1px dashed var(--border);
  }
  @media (max-width: 600px) {
    main { padding: 16px; }
    header { padding: 12px 16px; }
    .time { width: 100%; margin-left: 0; }
  }
</style>
</head>
<body>
<header>
  <div class="header-inner">
    <div class="brand">
      <div class="dot"></div>
      Notification Dashboard
    </div>
    <div class="status" id="status">Connecting...</div>
  </div>
</header>

<main>
  <div class="stats">
    <div class="stat">
      <div class="stat-label">Total</div>
      <div class="stat-value" id="stat-total">0</div>
    </div>
    <div class="stat">
      <div class="stat-label">Last hour</div>
      <div class="stat-value" id="stat-hour">0</div>
    </div>
    <div class="stat">
      <div class="stat-label">Top app</div>
      <div class="stat-value" id="stat-top" style="font-size:1em;">—</div>
    </div>
  </div>

  <div class="toolbar">
    <input type="text" id="search" placeholder="Search title or body...">
    <select id="app-filter">
      <option value="">All apps</option>
    </select>
    <button id="refresh-btn">Refresh</button>
  </div>

  <div id="notifications"></div>
</main>

<script>
  const APP_COLORS = {
    'com.whatsapp':                    '#25D366',
    'com.whatsapp.w4b':                '#25D366',
    'com.google.android.apps.messaging': '#4285F4',
    'com.android.mms':                 '#4285F4',
    'com.samsung.android.messaging':   '#4285F4',
    'com.facebook.katana':             '#1877F2',
    'com.facebook.orca':               '#0084FF',
    'com.instagram.android':           '#E1306C',
    'com.twitter.android':             '#1DA1F2',
    'org.telegram.messenger':          '#229ED9',
    'com.google.android.gm':           '#EA4335',
    'com.google.android.apps.photos':  '#FBBC04',
    'com.android.systemui':            '#6B7280',
    'com.google.android.dialer':       '#34A853',
    'com.google.android.apps.maps':    '#34A853',
    'com.spotify.music':               '#1DB954',
    'com.netflix.mediaclient':         '#E50914',
    'com.google.android.youtube':      '#FF0000',
    'com.discord':                     '#5865F2',
    'org.mozilla.firefox':             '#FF7139',
    'com.android.chrome':              '#4285F4'
  };
  const DEFAULT_COLOR = '#6c8cff';

  function colorFor(app) {
    return APP_COLORS[app] || DEFAULT_COLOR;
  }

  function shortApp(app) {
    if (!app) return 'unknown';
    const parts = app.split('.');
    return parts[parts.length - 1] || app;
  }

  function escapeHtml(str) {
    return String(str == null ? '' : str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  function formatTime(iso) {
    return new Date(iso).toLocaleString('en-GB', {
      timeZone: 'Africa/Nairobi',
      year: 'numeric',
      month: 'short',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: false
    }) + ' EAT';
  }

  function renderList(items) {
    const container = document.getElementById('notifications');
    if (!items.length) {
      container.innerHTML = '<div class="empty">No notifications match your filters.</div>';
      return;
    }
    container.innerHTML = items.map(n => {
      const color = colorFor(n.app);
      return (
        '<div class="notification" style="--bar-color:' + color + ';">' +
          '<div class="row1">' +
            '<span class="app-pill" style="--pill-color:' + color + ';">' + escapeHtml(shortApp(n.app)) + '</span>' +
            '<span class="phone-pill">' + escapeHtml(n.phone || 'Unknown') + '</span>' +
            '<span class="time">' + formatTime(n.timestamp) + '</span>' +
          '</div>' +
          (n.title ? '<div class="title">' + escapeHtml(n.title) + '</div>' : '') +
          (n.body  ? '<div class="body">'  + escapeHtml(n.body)  + '</div>' : '') +
        '</div>'
      );
    }).join('');
  }

  function renderStats(items) {
    const total = items.length;
    const oneHourAgo = Date.now() - 60 * 60 * 1000;
    const hourCount = items.filter(n => new Date(n.timestamp).getTime() > oneHourAgo).length;
    const counts = {};
    items.forEach(n => { counts[n.app] = (counts[n.app] || 0) + 1; });
    const top = Object.keys(counts).sort((a, b) => counts[b] - counts[a])[0];

    document.getElementById('stat-total').textContent = total;
    document.getElementById('stat-hour').textContent = hourCount;
    document.getElementById('stat-top').textContent = top ? shortApp(top) + ' (' + counts[top] + ')' : '—';
  }

  async function loadApps() {
    try {
      const res = await fetch('/api/apps');
      const data = await res.json();
      const select = document.getElementById('app-filter');
      data.apps.forEach(app => {
        const opt = document.createElement('option');
        opt.value = app;
        opt.textContent = shortApp(app);
        select.appendChild(opt);
      });
    } catch (e) {
      console.error('Failed to load apps', e);
    }
  }

  let allItems = [];

  async function loadNotifications() {
    try {
      const res = await fetch('/api/notifications');
      const data = await res.json();
      allItems = data.notifications || [];
      applyFilters();
      document.getElementById('status').textContent =
        'Live — updated ' + new Date().toLocaleTimeString('en-GB', { hour12: false });
    } catch (e) {
      console.error(e);
      document.getElementById('status').textContent = 'Connection error';
    }
  }

  function applyFilters() {
    const q = document.getElementById('search').value.trim().toLowerCase();
    const app = document.getElementById('app-filter').value;

    const filtered = allItems.filter(n => {
      if (app && n.app !== app) return false;
      if (q) {
        const hay = ((n.title || '') + ' ' + (n.body || '')).toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });

    renderStats(filtered);
    renderList(filtered);
  }

  document.getElementById('search').addEventListener('input', applyFilters);
  document.getElementById('app-filter').addEventListener('change', applyFilters);
  document.getElementById('refresh-btn').addEventListener('click', loadNotifications);

  // Initial load + auto refresh every 20s
  loadApps();
  loadNotifications();
  setInterval(loadNotifications, 20000);
</script>
</body>
</html>`);
});

app.listen(port, function() {
  console.log('Server running on port ' + port);
});
