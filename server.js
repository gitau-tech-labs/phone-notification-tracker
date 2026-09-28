app.get('/', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM notifications ORDER BY timestamp DESC LIMIT 200');

    // Map of package names to pleasant background colors
    const appColors = {
      'com.whatsapp':            '#d4f7dc', // soft green
      'com.whatsapp.w4b':        '#d4f7dc', // WhatsApp Business
      'com.google.android.apps.messaging': '#d6e6ff', // soft blue
      'com.android.mms':         '#d6e6ff',
      'com.samsung.android.messaging': '#d6e6ff',
      'com.facebook.katana':     '#d9e6f7', // Facebook
      'com.facebook.orca':       '#d9e6f7', // Messenger
      'com.instagram.android':   '#f9dff0', // Instagram pink
      'com.twitter.android':     '#d9edf7', // Twitter/X
      'org.telegram.messenger':  '#d6ecf7', // Telegram
      'com.google.android.gm':   '#fde2e2', // Gmail red-ish
      'com.google.android.apps.photos': '#fde9d9',
      'com.android.systemui':    '#e8e8e8', // System grey
      'com.google.android.dialer':'#f9f0d4', // Phone calls
    };

    const defaultColor = '#f1f1f1';

    let html = `
      <!DOCTYPE html>
      <html>
      <head>
        <title>Phone Notifications</title>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style>
          body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; padding: 20px; background: #f4f4f4; color: #222; }
          h1 { color: #333; margin-bottom: 4px; }
          .subtitle { color: #777; margin-bottom: 20px; font-size: 0.95em; }
          .notification { padding: 14px 16px; margin-bottom: 10px; border-radius: 10px; box-shadow: 0 2px 4px rgba(0,0,0,0.08); border-left: 4px solid rgba(0,0,0,0.15); }
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
        <div class="subtitle">${result.rows.length} notification${result.rows.length === 1 ? '' : 's'} shown</div>
    `;

    if (result.rows.length === 0) {
      html += '<div class="empty">No notifications received yet.</div>';
    } else {
      result.rows.forEach(row => {
        const bg = appColors[row.app] || defaultColor;
        const phone = row.phone ? row.phone : 'Unknown';
        const title = row.title || '(no title)';
        const body  = row.body || '(no body)';
        const time  = new Date(row.timestamp).toLocaleString();

        html += `
          <div class="notification" style="background:${bg};">
            <div class="app">${row.app || 'unknown app'}</div>
            <div class="phone">📱 ${phone}</div>
            <div class="title">${title}</div>
            <div class="body">${body}</div>
            <div class="time">${time}</div>
          </div>
        `;
      });
    }

    html += `
      <script>
        // Refresh every 30 seconds to show new notifications
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
