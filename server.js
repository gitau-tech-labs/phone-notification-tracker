const express = require('express');
const { Pool } = require('pg');
const app = express();
const port = process.env.PORT || 3000;

app.use(express.json());

// PostgreSQL connection pool
// Render provides DATABASE_URL automatically for the linked database
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
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
    // Ensure the phone column exists even if the table was created earlier
    await pool.query(`
      ALTER TABLE notifications ADD COLUMN IF NOT EXISTS phone VARCHAR(50)
    `);
    console.log('Database table initialized.');
  } catch (err) {
    console.error('Error initializing database:', err);
  }
}
initDb();

// ---------------------------------------------------------------
// Webhook — receives notifications from Notifikator
// ---------------------------------------------------------------
app.post('/webhook', async (req, res) => {
  try {
    const payload = req.body;

    // --- DEBUG LOGGING ---
    console.log('=== INCOMING WEBHOOK ===');
    console.log('Raw body:', JSON.stringify(payload, null, 2));
    console.log('phone  :', payload.phone);
    console.log('app    :', payload.app);
    console.log('title  :', payload.title);
    console.log('body   :', payload.body);
    console.log('========================');
    // --- END DEBUG LOGGING ---

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

// ---------------------------------------------------------------
// Debug endpoint — quick view of database contents
// ---------------------------------------------------------------
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

// ---------------------------------------------------------------
// Dashboard — colorful cards, phone number shown where available
// ---------------------------------------------------------------
app.get('/', async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM notifications ORDER BY timestamp DESC LIMIT 200'
    );

    // Per-app background colors
    const appColors = {
      'com.whatsapp':                        '#d4f7dc', // soft green
      'com.whatsapp.w4b':                    '#d4f7dc', // WhatsApp Business
      'com.google.android.apps.messaging':   '#d6e6ff', // Google Messages
      'com.android.mms':                     '#d6e6ff', // SMS
      'com.samsung.android.messaging':       '#d6e6ff',
      'com.facebook.katana':                 '#d9e6f7', // Facebook
      'com.facebook.orca':                   '#d9e6f7', // Messenger
      'com.instagram.android':               '#f9dff0', // Instagram
      'com.twitter.android':                 '#d9edf7', // X / Twitter
      'org.telegram.messenger':              '#d6ecf7', // Telegram
      'com.google.android.gm':               '#fde2e2', // Gmail
      'com.google.android.apps.photos':      '#fde9d9', // Photos
      'com.android.systemui':                '#e8e8e8', // System
      'com.google.android.dialer':           '#f9f0d4', // Phone calls
      'com.google.android.apps.maps':        '#e6f7e0', // Maps
      'com.spotify.music':                   '#d9f7d4', // Spotify
      'com.netflix.mediaclient':             '#f9d4d4', // Netflix
      'com.google.android.youtube':          '#fde2e2', // YouTube
      'com.discord':                         '#e0e0f7', // Discord
      'org.mozilla.firefox':                 '#ffe0cc', // Firefox
      'com.android.chrome':                  '#d9e6f7', // Chrome
    };
    const defaultColor = '#f1f1f1';

    let html = `
      <!DOCTYPE html>
      <html>
      <head>
        <title>Phone Notifications</title>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style>
          body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
            padding: 20px;
            background: #f4f4f4;
            color: #222;
            max-width: 800px;
            margin: 0 auto;
          }
          h1 { color: #333; margin-bottom: 4px; }
          .subtitle { color: #777; margin-bottom: 20px; font-size: 0.95em; }
          .notification {
            padding: 14px 16px;
            margin-bottom: 10px;
            border-radius: 10px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.08);
            border-left: 4px solid rgba(0,0,0,0.15);
          }
          .app { font-weight: bold; font-size: 0.95em; color: #333; margin-bottom: 2px; }
          .phone { font-size: 0.85em; color: #555; margin-bottom: 6px; }
          .title { font-weight: 600; margin-top: 4px; }
          .body { margin-top: 2px; white-space: pre-wrap; word-wrap: break-word; }
          .time { font-size: 0.78em; color: #777; margin-top: 8px; }
          .empty { background: white; padding: 20px; border-radius: 8px; text-align: center; color: #777; }
        </style>
      </head>
      <body>
        <h1>Recent Notifications</h1>
        <div class="subtitle">
          ${result.rows.length} notification${result.rows.length === 1 ? '' : 's'} shown
        </div>
    `;

    if (result.rows.length === 0) {
      html += '<div class="empty">No notifications received yet.</div>';
    } else {
      result.rows.forEach(row => {
        const bg = appColors[row.app] || defaultColor;
        const phone = row.phone ? row.phone : 'Unknown';
        const title = row.title || '(no title)';
        const body = row.body || '(no body)';
        const time = new Date(row.timestamp).toLocaleString();

        html += `
          <div class="notification" style="background:${bg};">
            <div class="app">${escapeHtml(row.app || 'unknown app')}</div>
            <div class="phone">📱 ${escapeHtml(phone)}</div>
            <div class="title">${escapeHtml(title)}</div>
            <div class="body">${escapeHtml(body)}</div>
            <div class="time">${time}</div>
          </div>
        `;
      });
    }

    html += `
      <script>
        // Refresh the page every 30 seconds to show new notifications
        setTimeout(() => location.reload(), 30000);
      </script>
      </body>
      </html>
    `;

    res.send(html);
  } catch (err) {
    console.error('Error fetching notifications:', err);
    res.status(500).send('Error loading notifications');
  }
});

// ---------------------------------------------------------------
// Simple HTML escaping helper
// ---------------------------------------------------------------
function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// ---------------------------------------------------------------
// Start the server
// ---------------------------------------------------------------
app.listen(port, () => {
  console.log(\`Server running on port \${port}\`);
});
