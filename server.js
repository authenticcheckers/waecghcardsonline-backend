import express from 'express';
import dotenv from 'dotenv';
import bodyParser from 'body-parser';
import multer from 'multer';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import axios from 'axios';
import { open } from 'sqlite';
import sqlite3 from 'sqlite3';
import { parse } from 'csv-parse/sync';
import cors from 'cors';

dotenv.config();

const app = express();

// ---------- CORS FIX ----------
app.use(cors({
  origin: [
    "https://waeccardsonline.vercel.app",
    "http://localhost:3000"
  ],
  methods: "GET,POST,PUT,DELETE,OPTIONS",
  allowedHeaders: "Content-Type, Authorization"
}));
// -----------------------------------------------------

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

const DB_FILE = process.env.DB_FILE || './data.db';
const PAYSTACK_SECRET_KEY = process.env.PAYSTACK_SECRET_KEY;


// ---------- FIXED ARKESEL variables ----------
const ARKESEL_API_KEY = process.env.ARKESEL_API_KEY || '';
const ARKESEL_SENDER = process.env.ARKESEL_SENDER || 'WAECCARDS';
// ----------------------------------------------------------

const JWT_SECRET = process.env.JWT_SECRET || 'please_change_me';
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';
let ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH || null;
const ADMIN_PASSWORD_RAW = process.env.ADMIN_PASSWORD || null;

const upload = multer({ dest: path.join('uploads/') });

let db;
async function initDb() {
  db = await open({ filename: DB_FILE, driver: sqlite3.Database });
  const migrations = fs.readFileSync(path.join('./migrations.sql'), 'utf8');
  await db.exec(migrations);

  const admin = await db.get('SELECT * FROM admin LIMIT 1');
  if (!admin) {
    if (!ADMIN_PASSWORD_HASH && ADMIN_PASSWORD_RAW) {
      const salt = await bcrypt.genSalt(10);
      ADMIN_PASSWORD_HASH = await bcrypt.hash(ADMIN_PASSWORD_RAW, salt);
      console.log('Generated ADMIN_PASSWORD_HASH:', ADMIN_PASSWORD_HASH.slice(0, 20) + '...');
    }
    if (!ADMIN_PASSWORD_HASH) {
      console.error('No admin password configured. Set ADMIN_PASSWORD or ADMIN_PASSWORD_HASH in env.');
    } else {
      await db.run('INSERT INTO admin (username, password_hash) VALUES (?,?)', [ADMIN_USERNAME, ADMIN_PASSWORD_HASH]);
      console.log('Admin user created:', ADMIN_USERNAME);
    }
  }
}

function ensureAdmin(req, res, next) {
  const h = req.headers.authorization;
  if (!h) return res.status(401).json({ message: 'Missing auth' });
  const parts = h.split(' ');
  if (parts.length !== 2) return res.status(401).json({ message: 'Bad auth' });
  const token = parts[1];
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    if (payload && payload.role === 'admin') return next();
    return res.status(403).json({ message: 'Forbidden' });
  } catch (e) {
    return res.status(401).json({ message: 'Invalid token' });
  }
}

// serve admin static (if needed later)
app.use('/admin', express.static(path.join(process.cwd(), 'admin'), { extensions: ['html'] }));
// serve frontend static
app.use('/', express.static(path.join(process.cwd(), 'frontend'), { extensions: ['html'] }));

// ------------------ ADMIN LOGIN ------------------
app.post('/admin/api/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ message: 'username+password required' });
  const row = await db.get('SELECT * FROM admin WHERE username = ?', [username]);
  if (!row) return res.status(401).json({ message: 'Invalid credentials' });
  const ok = await bcrypt.compare(password, row.password_hash);
  if (!ok) return res.status(401).json({ message: 'Invalid credentials' });
  const token = jwt.sign({ role: 'admin', user: username }, JWT_SECRET, { expiresIn: '8h' });
  res.json({ token });
});

// ------------------ ADD SINGLE VOUCHER ------------------
app.post('/admin/api/vouchers', ensureAdmin, async (req, res) => {
  const { serial, pin } = req.body;
  if (!serial || !pin) return res.status(400).json({ message: 'serial and pin required' });
  try {
    await db.run('INSERT INTO vouchers (serial, pin, status) VALUES (?,?,?)',
      [serial.trim(), pin.trim(), 'unused']);
    res.json({ success: true });
  } catch (err) {
    if (err.message.includes('UNIQUE')) return res.status(400).json({ message: 'duplicate serial' });
    console.error(err);
    res.status(500).json({ message: 'db error' });
  }
});

// ------------------ BULK UPLOAD ------------------
app.post('/admin/api/vouchers/bulk', ensureAdmin, upload.single('file'), async (req, res) => {
  let content;
  if (req.file) {
    content = fs.readFileSync(req.file.path, 'utf8');
    fs.unlinkSync(req.file.path);
  } else if (req.body.data) {
    content = req.body.data;
  } else {
    return res.status(400).json({ message: 'no file or data' });
  }

  try {
    const records = parse(content, { skip_empty_lines: true, trim: true });
    const insertStmt = await db.prepare('INSERT OR IGNORE INTO vouchers (serial,pin,status) VALUES (?,?,?)');
    let inserted = 0;
    for (const row of records) {
      let serial = null, pin = '';
      if (row.length === 1) {
        const s = row[0].split(/[,\t|;:]/).map(x => x.trim()).filter(Boolean);
        serial = s[0]; pin = s[1] || '';
      } else {
        serial = row[0]; pin = row[1] || '';
      }
      if (!serial) continue;
      const info = await insertStmt.run(serial, pin, 'unused');
      if (info.changes) inserted += 1;
    }
    await insertStmt.finalize();
    res.json({ success: true, inserted });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'import failed' });
  }
});

// ------------------ LIST VOUCHERS ------------------
app.get('/admin/api/vouchers', ensureAdmin, async (req, res) => {
  const status = req.query.status || 'all';
  const limit = parseInt(req.query.limit || '50', 10);
  const page = parseInt(req.query.page || '1', 10);
  const search = req.query.search || '';
  const offset = (page - 1) * limit;
  let where = '';
  const params = [];

  if (status === 'unused') { where = 'WHERE status = ?'; params.push('unused'); }
  else if (status === 'used') { where = 'WHERE status = ?'; params.push('used'); }

  if (search) {
    where += where ? ' AND ' : ' WHERE ';
    where += '(serial LIKE ? OR pin LIKE ?)';
    params.push('%' + search + '%', '%' + search + '%');
  }

  try {
    const totalRow = await db.get('SELECT COUNT(*) AS count FROM vouchers ' + where, params);
    const rows = await db.all(
      'SELECT id, serial, pin, status, date_used, buyer FROM vouchers ' +
      where + ' ORDER BY id DESC LIMIT ? OFFSET ?',
      [...params, limit, offset]
    );
    res.json({ total: totalRow.count, page, per_page: limit, vouchers: rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'db error' });
  }
});

// ------------------ MARK USED ------------------
app.post('/admin/api/vouchers/:id/mark-used', ensureAdmin, async (req, res) => {
  const id = req.params.id;
  const buyer = req.body.buyer || '';
  const now = new Date().toISOString();
  try {
    await db.run(
      'UPDATE vouchers SET status=?, date_used=?, buyer=? WHERE id=?',
      ['used', now, buyer, id]
    );
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'update failed' });
  }
});

// ------------------ DELETE VOUCHER ------------------
app.delete('/admin/api/vouchers/:id', ensureAdmin, async (req, res) => {
  const id = req.params.id;
  try {
    await db.run('DELETE FROM vouchers WHERE id=?', [id]);
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'delete failed' });
  }
});

// ------------------ STATS ------------------
app.get('/admin/api/stats', ensureAdmin, async (req, res) => {
  try {
    const total = (await db.get('SELECT COUNT(*) AS c FROM vouchers')).c;
    const unused = (await db.get("SELECT COUNT(*) AS c FROM vouchers WHERE status='unused'")).c;
    const used = total - unused;
    const today = (await db.get("SELECT COUNT(*) AS c FROM sales WHERE date(timestamp)=date('now')")).c;
    res.json({ total, unused, used, today });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'stats failed' });
  }
});

// ------------------ RESEND SMS ------------------
app.post('/admin/api/resend-sms', ensureAdmin, async (req, res) => {
  const { id } = req.body;
  if (!id) return res.status(400).json({ message: 'id required' });

  try {
    const row = await db.get('SELECT serial, pin, buyer FROM vouchers WHERE id=?', [id]);
    if (!row) return res.status(404).json({ message: 'voucher not found' });

    const phone = row.buyer;
    if (!phone) return res.status(400).json({ message: 'No buyer phone/email recorded' });

    try {
      await axios.post('https://sms.arkesel.com/api/v2/sms/send', {
        recipients: [phone],
        sender: ARKESEL_SENDER,
        message: `Your WASSCE voucher:\nSerial: ${row.serial}\nPIN: ${row.pin}`
      }, { headers: { 'api-key': ARKESEL_API_KEY, 'Content-Type': 'application/json' } });

      return res.json({ success: true });
    } catch (e1) {
      const fallbackUrl =
        `https://sms.arkesel.com/sms/api?action=send-sms&api_key=${encodeURIComponent(ARKESEL_API_KEY)}&to=${encodeURIComponent(phone)}&from=${encodeURIComponent(ARKESEL_SENDER)}&sms=${encodeURIComponent(`Your WASSCE voucher: Serial:${row.serial} PIN:${row.pin}`)}`;

      await axios.get(fallbackUrl);
      return res.json({ success: true, fallback: true });
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'resend failed' });
  }
});

// ------------------ VERIFY PAYMENT ------------------
app.post('/verify-payment', async (req, res) => {
  const { reference, name, phone, email } = req.body;
  if (!reference) return res.status(400).json({ success: false, message: 'Missing reference' });

  try {
    if (!PAYSTACK_SECRET)
      return res.status(500).json({ success: false, message: 'Server not configured with Paystack' });

    const verify = await axios.get(
      `https://api.paystack.co/transaction/verify/${encodeURIComponent(reference)}`,
      { headers: { Authorization: `Bearer ${PAYSTACK_SECRET}` } }
    );

    if (!verify.data || !verify.data.data || verify.data.status !== true)
      return res.status(400).json({ success: false, message: 'Paystack verification failed' });

    const paid = verify.data.data.status === 'success';
    const amount = (verify.data.data.amount || 0) / 100;

    if (!paid) return res.status(400).json({ success: false, message: 'Payment not successful' });

    // reserve voucher
    await db.run('BEGIN TRANSACTION');
    const row = await db.get("SELECT id, serial, pin FROM vouchers WHERE status='unused' ORDER BY id ASC LIMIT 1");
    if (!row) {
      await db.run('ROLLBACK');
      return res.status(500).json({ success: false, message: 'Out of vouchers' });
    }

    const now = new Date().toISOString();

    await db.run(
      'UPDATE vouchers SET status=?, date_used=?, buyer=? WHERE id=?',
      ['used', now, phone || email || '', row.id]
    );

    await db.run(
      'INSERT INTO sales (phone, email, voucher_serial, amount, timestamp, paystack_ref) VALUES (?,?,?,?,?,?)',
      [phone, email, row.serial, amount, now, reference]
    );

    await db.run('COMMIT');

    // send SMS
    if (phone && ARKESEL_API_KEY) {
      try {
        await axios.post('https://sms.arkesel.com/api/v2/sms/send', {
          recipients: [phone],
          sender: ARKESEL_SENDER,
          message: `Your WASSCE voucher:\nSerial: ${row.serial}\nPIN: ${row.pin}`
        }, { headers: { 'api-key': ARKESEL_API_KEY, 'Content-Type': 'application/json' } });
      } catch (e1) {
        const fallbackUrl =
          `https://sms.arkesel.com/sms/api?action=send-sms&api_key=${encodeURIComponent(ARKESEL_API_KEY)}&to=${encodeURIComponent(phone)}&from=${encodeURIComponent(ARKESEL_SENDER)}&sms=${encodeURIComponent(`Your WASSCE voucher: Serial:${row.serial} PIN:${row.pin}`)}`;
        await axios.get(fallbackUrl);
      }
    }

    return res.json({ success: true, voucher: row.serial + ' | ' + row.pin });
  } catch (err) {
    console.error('verify-payment error', err?.response?.data || err.message || err);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ------------------ PAYSTACK WEBHOOK ------------------
app.post('/pay/webhook', async (req, res) => {
  try {
    if (PAYSTACK_SECRET) {
      const hash = crypto.createHmac('sha512', PAYSTACK_SECRET)
        .update(JSON.stringify(req.body))
        .digest('hex');

      if (hash !== req.headers['x-paystack-signature']) {
        return res.status(401).send('Invalid signature');
      }
    }

    const data = req.body.data || {};
    const metadata = data.metadata || {};

    const phone = metadata.phone || null;
    const email = metadata.email || null;
    const amount = (data.amount || 0) / 100;
    const ref = data.reference || '';
    const status = data.status || '';

    if (status !== 'success') return res.status(200).send('ignored');

    await db.run('BEGIN TRANSACTION');
    const row = await db.get("SELECT id, serial, pin FROM vouchers WHERE status='unused' ORDER BY id ASC LIMIT 1");

    if (!row) {
      await db.run('ROLLBACK');
      console.error('out of vouchers');
      return res.status(500).send('out of vouchers');
    }

    const now = new Date().toISOString();

    await db.run(
      'UPDATE vouchers SET status=?, date_used=?, buyer=? WHERE id=?',
      ['used', now, phone || email || '', row.id]
    );

    await db.run(
      'INSERT INTO sales (phone, email, voucher_serial, amount, timestamp, paystack_ref) VALUES (?,?,?,?,?,?)',
      [phone, email, row.serial, amount, now, ref]
    );

    await db.run('COMMIT');

    if (phone && ARKESEL_API_KEY) {
      try {
        await axios.post('https://sms.arkesel.com/api/v2/sms/send', {
          recipients: [phone],
          sender: ARKESEL_SENDER,
          message: `Your WASSCE voucher:\nSerial: ${row.serial}\nPIN: ${row.pin}`
        }, { headers: { 'api-key': ARKESEL_API_KEY, 'Content-Type': 'application/json' } });
      } catch (e1) {
        const fallbackUrl =
          `https://sms.arkesel.com/sms/api?action=send-sms&api_key=${encodeURIComponent(ARKESEL_API_KEY)}&to=${encodeURIComponent(phone)}&from=${encodeURIComponent(ARKESEL_SENDER)}&sms=${encodeURIComponent(`Your WASSCE voucher: Serial:${row.serial} PIN:${row.pin}`)}`;
        await axios.get(fallbackUrl);
      }
    }

    return res.status(200).send('ok');

  } catch (err) {
    console.error('webhook error', err);
    return res.status(500).send('server error');
  }
});

// ------------------ HEALTH ------------------
app.get('/health', (req, res) => res.json({ status: 'ok' }));

// ------------------ START SERVER ------------------
(async () => {
  await initDb();
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => console.log('Server listening on', PORT));
})();
