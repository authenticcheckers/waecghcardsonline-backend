// server.js (final)
import pg from "pg";
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
import { parse } from 'csv-parse/sync';
import cors from 'cors';

dotenv.config();

const { Pool } = pg;
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

const app = express();
app.set('view engine', 'ejs');
app.set('views', path.join(process.cwd(), 'views'));

app.use(cors({
  origin: [
    process.env.FRONTEND_ORIGIN || "https://waeccardsonline.vercel.app",
    "http://localhost:3000"
  ],
  methods: ["GET","POST","PUT","DELETE","OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));

app.use(bodyParser.json({
  verify: (req, res, buf) => { req.rawBody = buf; }
}));
app.use(bodyParser.urlencoded({ extended: true }));

const PAYSTACK_SECRET_KEY = process.env.PAYSTACK_SECRET_KEY || "";
const ARKESEL_API_KEY = process.env.ARKESEL_API_KEY || "";
const ARKESEL_SENDER = process.env.ARKESEL_SENDER || "Arkesel";
const JWT_SECRET = process.env.JWT_SECRET || "please_change_me";
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || "admin";
const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH || ""; // must be set in env

const upload = multer({ dest: path.join("uploads/") });

// ====== Utils ======
async function query(text, params){ return pool.query(text, params); }

function requireAuth(req, res, next){
  try {
    const h = req.headers.authorization;
    if(!h) return res.status(401).json({message:'Missing auth'});
    const token = h.split(' ')[1];
    const payload = jwt.verify(token, JWT_SECRET);
    if(payload.role === 'admin') return next();
    return res.status(403).json({message:'Forbidden'});
  } catch(e){ return res.status(401).json({message:'Invalid token'}); }
}

// ====== Admin login ======
app.post('/admin/api/login', async (req, res) => {
  const { username, password } = req.body;
  if(!username || !password) return res.status(400).json({message:'username+password required'});
  if(username !== ADMIN_USERNAME) return res.status(401).json({message:'Invalid credentials'});
  const ok = await bcrypt.compare(password, ADMIN_PASSWORD_HASH);
  if(!ok) return res.status(401).json({message:'Invalid credentials'});
  const token = jwt.sign({ role: 'admin', user: username }, JWT_SECRET, { expiresIn:'8h' });
  res.json({ token });
});

// ====== Admin: add single voucher ======
app.post('/admin/api/vouchers', requireAuth, async (req, res) => {
  const { serial, pin } = req.body;
  if(!serial || !pin) return res.status(400).json({message:'serial & pin required'});
  try {
    await query("INSERT INTO vouchers (serial,pin,status) VALUES ($1,$2,'unused')", [serial.trim(), pin.trim()]);
    res.json({success:true});
  } catch (err) {
    if(err.detail && err.detail.includes('already exists')) return res.status(400).json({message:'duplicate serial'});
    console.error('add voucher error', err);
    res.status(500).json({message:'db error'});
  }
});

// ====== Admin: bulk upload (CSV) ======
app.post('/admin/api/vouchers/bulk', requireAuth, upload.single('file'), async (req, res) => {
  try {
    if(!req.file) return res.status(400).json({message:'No file uploaded'});
    const content = fs.readFileSync(req.file.path, 'utf8');
    fs.unlinkSync(req.file.path);
    const rows = parse(content, { skip_empty_lines:true, trim:true });
    let inserted = 0;
    for(const r of rows){
      const serial = (r[0]||'').toString().trim();
      const pin = (r[1]||'').toString().trim();
      if(!serial || !pin) continue;
      try {
        await query("INSERT INTO vouchers (serial,pin) VALUES ($1,$2) ON CONFLICT DO NOTHING", [serial, pin]);
        inserted++;
      } catch(e){}
    }
    res.json({success:true, inserted});
  } catch(err){
    console.error('bulk error', err);
    res.status(500).json({message:'import failed'});
  }
});

// ====== Admin: list vouchers ======
app.get('/admin/api/vouchers', requireAuth, async (req, res) => {
  try {
    const status = req.query.status || 'all';
    const search = req.query.search || '';
    const limit = Number(req.query.limit || 50);
    const page = Number(req.query.page || 1);
    const offset = (page-1)*limit;

    let where = 'WHERE 1=1'; const params = [];
    if(status === 'unused'){ where += " AND status='unused'"; }
    if(status === 'used'){ where += " AND status='used'"; }
    if(search){ params.push(`%${search}%`); where += ` AND (serial ILIKE $${params.length} OR pin ILIKE $${params.length})`; }

    const totalRes = await query(`SELECT COUNT(*) FROM vouchers ${where}`, params);
    const rowsRes = await query(`SELECT * FROM vouchers ${where} ORDER BY id DESC LIMIT $${params.length+1} OFFSET $${params.length+2}`, [...params, limit, offset]);

    res.json({ total: Number(totalRes.rows[0].count), vouchers: rowsRes.rows, page, per_page: limit });
  } catch(err){
    console.error('list error', err);
    res.status(500).json({message:'db error'});
  }
});

// ====== Resend SMS ======
app.post('/admin/api/resend-sms', requireAuth, async (req,res) => {
  const { id } = req.body;
  if(!id) return res.status(400).json({message:'id required'});
  try {
    const voucherRes = await query("SELECT serial,pin,buyer FROM vouchers WHERE id=$1", [id]);
    if(!voucherRes.rows.length) return res.status(404).json({message:'not found'});
    const v = voucherRes.rows[0];
    const phone = v.buyer;
    if(!phone) return res.status(400).json({message:'No buyer recorded'});
    // send
    try {
      await axios.post('https://sms.arkesel.com/api/v2/sms/send', {
        recipients:[phone],
        sender: ARKESEL_SENDER,
        message: `Your WASSCE voucher:\nSerial: ${v.serial}\nPIN: ${v.pin}`
      }, { headers: { 'api-key': ARKESEL_API_KEY }});
      return res.json({ success:true });
    } catch (e){
      const url = `https://sms.arkesel.com/sms/api?action=send-sms&api_key=${encodeURIComponent(ARKESEL_API_KEY)}&to=${encodeURIComponent(phone)}&from=${encodeURIComponent(ARKESEL_SENDER)}&sms=${encodeURIComponent(`Your WASSCE voucher: Serial:${v.serial} PIN:${v.pin}`)}`;
      await axios.get(url);
      return res.json({ success:true, fallback:true });
    }
  } catch(err){ console.error('resend error', err); res.status(500).json({message:'resend failed'}); }
});

// ====== Verify payment and assign voucher ======
app.post('/verify-payment', async (req,res) => {
  const { reference, name, phone, email } = req.body;
  if(!reference) return res.status(400).json({success:false, message:'Missing reference'});

  try {
    if(!PAYSTACK_SECRET_KEY) return res.status(500).json({success:false, message:'Paystack not configured'});
    const verifyResp = await axios.get(`https://api.paystack.co/transaction/verify/${encodeURIComponent(reference)}`, { headers: { Authorization: `Bearer ${PAYSTACK_SECRET_KEY}` } });
    if(!verifyResp.data || !verifyResp.data.data || verifyResp.data.status !== true) return res.status(400).json({success:false, message:'Paystack verification failed'});
    if(verifyResp.data.data.status !== 'success') return res.status(400).json({success:false, message:'Payment not successful'});
    const amount = (verifyResp.data.data.amount || 0) / 100;

    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const vres = await client.query("SELECT id,serial,pin FROM vouchers WHERE status='unused' ORDER BY id ASC LIMIT 1 FOR UPDATE");
      if(vres.rows.length === 0){ await client.query('ROLLBACK'); client.release(); return res.status(500).json({success:false, message:'Out of vouchers'}); }
      const v = vres.rows[0];
      const now = new Date();
      await client.query("UPDATE vouchers SET status='used', date_used=$1, buyer=$2 WHERE id=$3", [now, phone || email || '', v.id]);
      await client.query("INSERT INTO sales (name,phone,email,voucher_serial,voucher_pin,reference,amount) VALUES ($1,$2,$3,$4,$5,$6,$7)", [name,phone,email,v.serial,v.pin,reference,amount]);
      await client.query('COMMIT');
      client.release();

      // send SMS
      if(phone && ARKESEL_API_KEY){
        try {
          await axios.post('https://sms.arkesel.com/api/v2/sms/send', { recipients:[phone], sender:ARKESEL_SENDER, message:`Your WASSCE voucher:\nSerial: ${v.serial}\nPIN: ${v.pin}` }, { headers:{ 'api-key': ARKESEL_API_KEY }});
        } catch (e){
          try {
            const fallback = `https://sms.arkesel.com/sms/api?action=send-sms&api_key=${encodeURIComponent(ARKESEL_API_KEY)}&to=${encodeURIComponent(phone)}&from=${encodeURIComponent(ARKESEL_SENDER)}&sms=${encodeURIComponent(`Your WASSCE voucher: Serial:${v.serial} PIN:${v.pin}`)}`;
            await axios.get(fallback);
          } catch(e2){}
        }
      }

      return res.json({ success:true, serial: v.serial, pin: v.pin, voucher:`${v.serial} | ${v.pin}` });

    } catch(e){
      await client.query('ROLLBACK'); client.release(); throw e;
    }

  } catch(err){
    console.error('verify-payment error', err?.response?.data || err.message || err);
    return res.status(500).json({ success:false, message:'Server error' });
  }
});

// ====== Success page (rendered EJS) ======
app.get('/success', (req,res) => {
  const serial = req.query.serial;
  const pin = req.query.pin;
  if(!serial || !pin) return res.status(400).send('Missing voucher');
  res.render('success', { voucher: `${serial} | ${pin}` });
});

// ====== Dev assign voucher endpoint (dev-only) ======
if(process.env.ENABLE_DEV_ASSIGN === 'true'){
  app.post('/dev/assign-voucher', async (req,res)=>{
    const phone = req.body.phone || 'dev';
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const vres = await client.query("SELECT id,serial,pin FROM vouchers WHERE status='unused' ORDER BY id ASC LIMIT 1 FOR UPDATE");
      if(vres.rows.length === 0){ await client.query('ROLLBACK'); client.release(); return res.status(500).json({error:'out of vouchers'}); }
      const v = vres.rows[0];
      const now = new Date();
      await client.query("UPDATE vouchers SET status='used', date_used=$1, buyer=$2 WHERE id=$3", [now, phone, v.id]);
      await client.query("INSERT INTO sales (phone,email,voucher_serial,voucher_pin,reference,amount) VALUES ($1,$2,$3,$4,$5,$6)", [phone,null,v.serial,v.pin,'dev',0]);
      await client.query('COMMIT');
      client.release();
      res.json({ success:true, serial:v.serial, pin:v.pin });
    } catch(e){
      await client.query('ROLLBACK'); client.release(); res.status(500).json({error:'db error'});
    }
  });
}

// ====== Health ======
app.get('/health', (req,res) => res.json({ status:'ok' }));

// ====== Start ======
app.listen(process.env.PORT || 3000, ()=> console.log('Server listening on', process.env.PORT || 3000));
