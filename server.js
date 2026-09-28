app.post('/webhook', async (req, res) => {
  try {
    const payload = req.body;

    // --- DEBUG LOGGING START ---
    console.log('=== INCOMING WEBHOOK ===');
    console.log('Raw body:', JSON.stringify(payload, null, 2));
    console.log('app    :', payload.app);
    console.log('title  :', payload.title);
    console.log('body   :', payload.body);
    console.log('========================');
    // --- DEBUG LOGGING END ---

    await pool.query(
      'INSERT INTO notifications (app, title, body, raw_payload) VALUES ($1, $2, $3, $4)',
      [payload.app, payload.title, payload.body, JSON.stringify(payload)]
    );

    res.status(200).send('OK');
  } catch (err) {
    console.error('Error processing webhook:', err);
    res.status(500).send('Internal Server Error');
  }
});

// Debug endpoint — shows the total count of notifications in the DB
app.get('/count', async (req, res) => {
  try {
    const result = await pool.query('SELECT COUNT(*) FROM notifications');
    const latest = await pool.query('SELECT * FROM notifications ORDER BY id DESC LIMIT 5');
    res.json({
      total: result.rows[0].count,
      latest: latest.rows
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
