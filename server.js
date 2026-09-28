const express = require('express');
const { Pool } = require('pg');
const app = express();
const port = process.env.PORT || 3000;

app.use(express.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

async function initDb() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS notifications (
        id SERIAL PRIMARY KEY,
        app VARCHAR(255),
        title TEXT,
        body TEXT,
        timestamp TIMESTAMPTZ DEFAULT NOW(),
        raw_payload JSONB
      )
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
    await pool.query(
      'INSERT INTO notifications (app, title, body, raw_payload) VALUES ($1, $2, $3, $4)',
      [payload.app, payload.title, payload.body, JSON.stringify(payload)]
    );
    console.log('Received notification:', payload);
    res.status(200).send('OK');
  } catch (err) {
    console.error('Error processing webhook:', err);
    res.status(500).send('Internal Server Error');
  }
});

app.get('/', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM notifications ORDER BY timestamp DESC LIMIT 100');

    let html = `
      <!DOCTYPE html>
      <html>
      <head>
        <title>Phone Notifications</title>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style>
          body { font-family: sans-serif; padding: 20px; background: #f4f4f4; }
          h1 { color: #333; }
          .notification { background: white; padding: 15px; margin-bottom: 10px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
          .app { font-weight: bold; color: #007bff; }
          .time { font-size: 0.8em; color: #888; }
        </style>
      </head>
      <body>
        <h1>Recent Notifications</h1>
    `;

    if (result.rows.length === 0) {
      html += '<p>No notifications received yet.</p>';
    } else {
      result.rows.forEach(row => {
        html += `
          <div class="notification">
            <div class="app">${row.app}</div>
            <div><strong>${row.title || ''}</strong></div>
            <div>${row.body || ''}</div>
            <div class="time">${new Date(row.timestamp).toLocaleString()}</div>
          </div>
        `;
      });
    }

    html += `
      <script>
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

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
