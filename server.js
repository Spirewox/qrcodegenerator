const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

// Load .env file if it exists
const envPath = path.join(__dirname, '.env');
if (fs.existsSync(envPath)) {
  fs.readFileSync(envPath, 'utf8').split('\n').forEach(line => {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) return;
    const [key, ...rest] = trimmed.split('=');
    const val = rest.join('=').trim();
    if (key && val && !process.env[key.trim()]) process.env[key.trim()] = val;
  });
}
const Database = require('better-sqlite3');
const QRCode = require('qrcode');
const uuidv4 = () => crypto.randomUUID();
const sharp = require('sharp');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');

const app = express();
const PORT = process.env.PORT || 3000;
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;

// JWT secret — persist across restarts (use volume if available)
const SECRET_DIR = fs.existsSync('/data') ? '/data' : __dirname;
const SECRET_FILE = path.join(SECRET_DIR, '.jwt-secret');
let JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  try { JWT_SECRET = fs.readFileSync(SECRET_FILE, 'utf8').trim(); } catch {
    JWT_SECRET = crypto.randomBytes(32).toString('hex');
    fs.writeFileSync(SECRET_FILE, JWT_SECRET);
  }
}

// Multer — store uploaded logos in memory
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 2 * 1024 * 1024 } });

// Database setup — use persistent volume on Railway, local dir otherwise
const DATA_DIR = fs.existsSync('/data') ? '/data' : __dirname;
const db = new Database(path.join(DATA_DIR, 'qrcodes.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS reset_tokens (
    token TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TEXT NOT NULL,
    used INTEGER DEFAULT 0
  );

  CREATE TABLE IF NOT EXISTS qrcodes (
    id TEXT PRIMARY KEY,
    user_id TEXT,
    label TEXT NOT NULL,
    target_url TEXT NOT NULL,
    qr_data_url TEXT NOT NULL,
    color TEXT DEFAULT '#000000',
    bg_color TEXT DEFAULT '#ffffff',
    created_at TEXT DEFAULT (datetime('now')),
    is_active INTEGER DEFAULT 1,
    logo_data TEXT,
    logo_size INTEGER DEFAULT 20
  );

  CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    qr_id TEXT NOT NULL REFERENCES qrcodes(id) ON DELETE CASCADE,
    scanned_at TEXT DEFAULT (datetime('now')),
    ip TEXT,
    user_agent TEXT,
    referer TEXT
  );

  CREATE INDEX IF NOT EXISTS idx_scans_qr_id ON scans(qr_id);
  CREATE INDEX IF NOT EXISTS idx_scans_scanned_at ON scans(scanned_at);
`);

// Migrations for existing databases
try { db.exec(`ALTER TABLE qrcodes ADD COLUMN logo_data TEXT`); } catch {}
try { db.exec(`ALTER TABLE qrcodes ADD COLUMN logo_size INTEGER DEFAULT 20`); } catch {}
try { db.exec(`ALTER TABLE qrcodes ADD COLUMN user_id TEXT`); } catch {}

// --- Prepared statements ---
const stmts = {
  // Auth
  insertUser: db.prepare(`INSERT INTO users (id, name, email, password_hash) VALUES (?, ?, ?, ?)`),
  getUserByEmail: db.prepare(`SELECT * FROM users WHERE email = ?`),
  getUserById: db.prepare(`SELECT id, name, email, created_at FROM users WHERE id = ?`),
  updateUserPassword: db.prepare(`UPDATE users SET password_hash = ? WHERE id = ?`),
  insertResetToken: db.prepare(`INSERT INTO reset_tokens (token, user_id, expires_at) VALUES (?, ?, ?)`),
  getResetToken: db.prepare(`SELECT * FROM reset_tokens WHERE token = ? AND used = 0`),
  markTokenUsed: db.prepare(`UPDATE reset_tokens SET used = 1 WHERE token = ?`),

  // QR (scoped to user)
  insertQR: db.prepare(`INSERT INTO qrcodes (id, user_id, label, target_url, qr_data_url, color, bg_color, logo_data, logo_size) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`),
  getAllQR: db.prepare(`SELECT q.*, (SELECT COUNT(*) FROM scans WHERE qr_id = q.id) AS scan_count FROM qrcodes q WHERE q.user_id = ? ORDER BY q.created_at DESC`),
  getQR: db.prepare(`SELECT * FROM qrcodes WHERE id = ?`),
  getQRForUser: db.prepare(`SELECT * FROM qrcodes WHERE id = ? AND user_id = ?`),
  deleteQR: db.prepare(`DELETE FROM qrcodes WHERE id = ? AND user_id = ?`),
  toggleQR: db.prepare(`UPDATE qrcodes SET is_active = ? WHERE id = ? AND user_id = ?`),
  updateQR: db.prepare(`UPDATE qrcodes SET label = ?, target_url = ?, qr_data_url = ?, color = ?, bg_color = ?, logo_data = ?, logo_size = ? WHERE id = ? AND user_id = ?`),

  // Scans
  insertScan: db.prepare(`INSERT INTO scans (qr_id, ip, user_agent, referer) VALUES (?, ?, ?, ?)`),
  getScansForQR: db.prepare(`SELECT * FROM scans WHERE qr_id = ? ORDER BY scanned_at DESC LIMIT 100`),
  getScanCountByDay: db.prepare(`
    SELECT date(scanned_at) AS day, COUNT(*) AS count
    FROM scans WHERE qr_id = ? GROUP BY date(scanned_at) ORDER BY day DESC LIMIT 30
  `),

  // Dashboard (scoped)
  getTotalScans: db.prepare(`SELECT COUNT(*) AS total FROM scans s JOIN qrcodes q ON q.id = s.qr_id WHERE q.user_id = ?`),
  getTotalQR: db.prepare(`SELECT COUNT(*) AS total FROM qrcodes WHERE user_id = ?`),
  getTopQR: db.prepare(`
    SELECT q.id, q.label, q.target_url, COUNT(s.id) AS scan_count
    FROM qrcodes q LEFT JOIN scans s ON s.qr_id = q.id WHERE q.user_id = ?
    GROUP BY q.id ORDER BY scan_count DESC LIMIT 5
  `),
  getRecentScans: db.prepare(`
    SELECT s.scanned_at, s.ip, s.user_agent, q.label, q.id AS qr_id
    FROM scans s JOIN qrcodes q ON q.id = s.qr_id WHERE q.user_id = ?
    ORDER BY s.scanned_at DESC LIMIT 20
  `),
  getDailyScansAll: db.prepare(`
    SELECT date(scanned_at) AS day, COUNT(*) AS count
    FROM scans s JOIN qrcodes q ON q.id = s.qr_id WHERE q.user_id = ?
    GROUP BY date(scanned_at) ORDER BY day DESC LIMIT 30
  `),
};

// --- Logo compositing helper ---
async function compositeLogoOnQR(qrBuffer, logoBase64, logoSizePercent, qrWidth) {
  const logoBuffer = Buffer.from(logoBase64, 'base64');
  const logoSize = Math.round(qrWidth * (logoSizePercent / 100));
  const padding = Math.round(logoSize * 0.15);
  const totalSize = logoSize + padding * 2;

  const resizedLogo = await sharp(logoBuffer)
    .resize(logoSize, logoSize, { fit: 'contain', background: { r: 255, g: 255, b: 255, alpha: 0 } })
    .png().toBuffer();

  const bgRound = Math.round(totalSize * 0.15);
  const bgSvg = `<svg width="${totalSize}" height="${totalSize}"><rect x="0" y="0" width="${totalSize}" height="${totalSize}" rx="${bgRound}" ry="${bgRound}" fill="white"/></svg>`;
  const logoBg = await sharp(Buffer.from(bgSvg)).png().toBuffer();
  const logoWithBg = await sharp(logoBg).composite([{ input: resizedLogo, left: padding, top: padding }]).png().toBuffer();

  const qrMeta = await sharp(qrBuffer).metadata();
  const left = Math.round((qrMeta.width - totalSize) / 2);
  const top = Math.round((qrMeta.height - totalSize) / 2);
  return sharp(qrBuffer).composite([{ input: logoWithBg, left, top }]).png().toBuffer();
}

async function generateQRBuffer(trackingUrl, opts, logoBase64, logoSize) {
  const width = opts.width || 400;
  let buffer = await QRCode.toBuffer(trackingUrl, { ...opts, width });
  if (logoBase64) buffer = await compositeLogoOnQR(buffer, logoBase64, logoSize || 20, width);
  return buffer;
}

function bufferToDataUrl(buffer) {
  return `data:image/png;base64,${buffer.toString('base64')}`;
}

// --- Auth helpers ---
function signToken(user) {
  return jwt.sign({ id: user.id, email: user.email, name: user.name }, JWT_SECRET, { expiresIn: '7d' });
}

function setAuthCookie(res, token) {
  res.cookie('token', token, { httpOnly: true, sameSite: 'lax', maxAge: 7 * 24 * 60 * 60 * 1000, path: '/' });
}

function requireAuth(req, res, next) {
  const tok = req.cookies?.token;
  if (!tok) return res.status(401).json({ error: 'Unauthorized' });
  try {
    req.user = jwt.verify(tok, JWT_SECRET);
    next();
  } catch {
    res.clearCookie('token');
    return res.status(401).json({ error: 'Unauthorized' });
  }
}

// --- Middleware ---
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// ===================== AUTH ROUTES =====================

app.post('/api/auth/signup', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password) return res.status(400).json({ error: 'All fields are required' });
    if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });

    const existing = stmts.getUserByEmail.get(email.toLowerCase().trim());
    if (existing) return res.status(409).json({ error: 'An account with this email already exists' });

    const id = uuidv4().slice(0, 12);
    const hash = await bcrypt.hash(password, 10);
    stmts.insertUser.run(id, name.trim(), email.toLowerCase().trim(), hash);

    const user = stmts.getUserById.get(id);
    const token = signToken(user);
    setAuthCookie(res, token);
    res.json({ user });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password are required' });

    const user = stmts.getUserByEmail.get(email.toLowerCase().trim());
    if (!user) return res.status(401).json({ error: 'Invalid email or password' });

    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(401).json({ error: 'Invalid email or password' });

    const token = signToken(user);
    setAuthCookie(res, token);
    const { password_hash, ...safe } = user;
    res.json({ user: safe });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('token', { path: '/' });
  res.json({ ok: true });
});

app.get('/api/auth/me', requireAuth, (req, res) => {
  const user = stmts.getUserById.get(req.user.id);
  if (!user) { res.clearCookie('token'); return res.status(401).json({ error: 'Unauthorized' }); }
  res.json({ user });
});

app.post('/api/auth/forgot', (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email is required' });

  const user = stmts.getUserByEmail.get(email.toLowerCase().trim());
  if (!user) return res.json({ message: 'If an account exists, a reset token has been generated', token: null });

  const token = crypto.randomBytes(20).toString('hex');
  const expiresAt = new Date(Date.now() + 60 * 60 * 1000).toISOString(); // 1 hour
  stmts.insertResetToken.run(token, user.id, expiresAt);

  res.json({ message: 'Reset token generated', token, resetUrl: `${BASE_URL}/#reset=${token}` });
});

app.post('/api/auth/reset', async (req, res) => {
  try {
    const { token, password } = req.body;
    if (!token || !password) return res.status(400).json({ error: 'Token and password are required' });
    if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });

    const record = stmts.getResetToken.get(token);
    if (!record) return res.status(400).json({ error: 'Invalid or expired reset token' });
    if (new Date(record.expires_at) < new Date()) {
      stmts.markTokenUsed.run(token);
      return res.status(400).json({ error: 'Reset token has expired' });
    }

    const hash = await bcrypt.hash(password, 10);
    stmts.updateUserPassword.run(hash, record.user_id);
    stmts.markTokenUsed.run(token);

    res.json({ message: 'Password reset successful' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ===================== SCAN REDIRECT (PUBLIC) =====================

app.get('/s/:id', (req, res) => {
  const qr = stmts.getQR.get(req.params.id);
  if (!qr) return res.status(404).send('QR code not found');
  if (!qr.is_active) return res.status(410).send('This QR code has been deactivated');

  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
  const ua = req.headers['user-agent'] || '';
  const ref = req.headers['referer'] || '';
  stmts.insertScan.run(qr.id, ip, ua, ref);
  res.redirect(302, qr.target_url);
});

// ===================== PROTECTED API ROUTES =====================

// --- QR CRUD ---
app.post('/api/qrcodes', requireAuth, upload.single('logo'), async (req, res) => {
  try {
    const { label, targetUrl, color = '#000000', bgColor = '#ffffff', logoSize = '20' } = req.body;
    if (!label || !targetUrl) return res.status(400).json({ error: 'label and targetUrl are required' });

    const id = uuidv4().slice(0, 8);
    const trackingUrl = `${BASE_URL}/s/${id}`;
    const logoBase64 = req.file ? req.file.buffer.toString('base64') : null;
    const logoSizeNum = parseInt(logoSize) || 20;

    const buffer = await generateQRBuffer(trackingUrl, {
      width: 400, margin: 2,
      color: { dark: color, light: bgColor },
      errorCorrectionLevel: 'H',
    }, logoBase64, logoSizeNum);

    const qrDataUrl = bufferToDataUrl(buffer);
    stmts.insertQR.run(id, req.user.id, label, targetUrl, qrDataUrl, color, bgColor, logoBase64, logoSizeNum);
    const qr = stmts.getQR.get(id);
    const { logo_data, ...qrClean } = qr;
    res.json({ ...qrClean, has_logo: !!logo_data, tracking_url: trackingUrl, scan_count: 0 });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/qrcodes', requireAuth, (req, res) => {
  const rows = stmts.getAllQR.all(req.user.id);
  res.json(rows.map(r => {
    const { logo_data, ...clean } = r;
    return { ...clean, has_logo: !!logo_data, tracking_url: `${BASE_URL}/s/${r.id}` };
  }));
});

app.get('/api/qrcodes/:id', requireAuth, (req, res) => {
  const qr = stmts.getQRForUser.get(req.params.id, req.user.id);
  if (!qr) return res.status(404).json({ error: 'Not found' });
  const scans = stmts.getScansForQR.all(qr.id);
  const dailyCounts = stmts.getScanCountByDay.all(qr.id);
  const { logo_data, ...clean } = qr;
  res.json({ ...clean, has_logo: !!logo_data, tracking_url: `${BASE_URL}/s/${qr.id}`, scans, daily_counts: dailyCounts });
});

app.put('/api/qrcodes/:id', requireAuth, upload.single('logo'), async (req, res) => {
  try {
    const qr = stmts.getQRForUser.get(req.params.id, req.user.id);
    if (!qr) return res.status(404).json({ error: 'Not found' });

    const label = req.body.label || qr.label;
    const targetUrl = req.body.targetUrl || qr.target_url;
    const color = req.body.color || qr.color;
    const bgColor = req.body.bgColor || qr.bg_color;
    const logoSizeNum = parseInt(req.body.logoSize) || qr.logo_size || 20;

    let logoBase64 = qr.logo_data;
    if (req.file) logoBase64 = req.file.buffer.toString('base64');
    else if (req.body.removeLogo === '1') logoBase64 = null;

    const trackingUrl = `${BASE_URL}/s/${qr.id}`;
    const buffer = await generateQRBuffer(trackingUrl, {
      width: 400, margin: 2,
      color: { dark: color, light: bgColor },
      errorCorrectionLevel: 'H',
    }, logoBase64, logoSizeNum);

    const qrDataUrl = bufferToDataUrl(buffer);
    stmts.updateQR.run(label, targetUrl, qrDataUrl, color, bgColor, logoBase64, logoSizeNum, qr.id, req.user.id);
    const updated = stmts.getQR.get(qr.id);
    const { logo_data, ...clean } = updated;
    res.json({ ...clean, has_logo: !!logo_data, tracking_url: trackingUrl });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.patch('/api/qrcodes/:id/toggle', requireAuth, (req, res) => {
  const qr = stmts.getQRForUser.get(req.params.id, req.user.id);
  if (!qr) return res.status(404).json({ error: 'Not found' });
  stmts.toggleQR.run(qr.is_active ? 0 : 1, qr.id, req.user.id);
  const updated = stmts.getQR.get(qr.id);
  const { logo_data, ...clean } = updated;
  res.json({ ...clean, has_logo: !!logo_data });
});

app.delete('/api/qrcodes/:id', requireAuth, (req, res) => {
  const qr = stmts.getQRForUser.get(req.params.id, req.user.id);
  if (!qr) return res.status(404).json({ error: 'Not found' });
  stmts.deleteQR.run(qr.id, req.user.id);
  res.json({ ok: true });
});

app.get('/api/qrcodes/:id/export', requireAuth, async (req, res) => {
  try {
    const qr = stmts.getQRForUser.get(req.params.id, req.user.id);
    if (!qr) return res.status(404).json({ error: 'Not found' });

    const format = req.query.format || 'png';
    const transparent = req.query.transparent === '1';
    const color = req.query.color || qr.color || '#000000';
    const bgColor = transparent ? '#00000000' : (req.query.bg || qr.bg_color || '#ffffff');
    const trackingUrl = `${BASE_URL}/s/${qr.id}`;
    const filename = `${qr.label.replace(/[^a-zA-Z0-9_-]/g, '_')}_qr`;

    if (format === 'svg' && !qr.logo_data) {
      const svg = await QRCode.toString(trackingUrl, {
        type: 'svg', width: 400, margin: 2,
        color: { dark: color, light: bgColor }, errorCorrectionLevel: 'H',
      });
      res.setHeader('Content-Type', 'image/svg+xml');
      res.setHeader('Content-Disposition', `attachment; filename="${filename}.svg"`);
      return res.send(svg);
    }

    const buffer = await generateQRBuffer(trackingUrl, {
      width: 800, margin: 2,
      color: { dark: color, light: bgColor }, errorCorrectionLevel: 'H',
    }, qr.logo_data, qr.logo_size || 20);

    res.setHeader('Content-Type', 'image/png');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}.png"`);
    res.send(buffer);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// --- Dashboard ---
app.get('/api/dashboard', requireAuth, (req, res) => {
  const uid = req.user.id;
  const totalScans = stmts.getTotalScans.get(uid).total;
  const totalQR = stmts.getTotalQR.get(uid).total;
  const topQR = stmts.getTopQR.all(uid);
  const recentScans = stmts.getRecentScans.all(uid);
  const dailyCounts = stmts.getDailyScansAll.all(uid);
  res.json({ totalScans, totalQR, topQR, recentScans, dailyCounts });
});

// SPA fallback
app.get('/{*splat}', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`QR Code Generator running at ${BASE_URL}`);
});
