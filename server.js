// server.js — FINAL (fixed)
import pg from "pg";
import express from "express";
import dotenv from "dotenv";
import bodyParser from "body-parser";
import multer from "multer";
import fs from "fs";
import path from "path";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import axios from "axios";
import { parse } from "csv-parse/sync";
import cors from "cors";

dotenv.config();

const { Pool } = pg;
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

const app = express();
app.set("view engine", "ejs");
app.set("views", path.join(process.cwd(), "views"));

app.use(
  cors({
    origin: [
      process.env.FRONTEND_ORIGIN || "https://waeccardsonline.vercel.app",
      "http://localhost:3000"
    ],
    methods: ["GET", "POST"],
    allowedHeaders: ["Content-Type", "Authorization"]
  })
);

// body parsers
app.use(bodyParser.json({ verify: (req, res, buf) => { req.rawBody = buf; } }));
app.use(bodyParser.urlencoded({ extended: true }));

const PAYSTACK_SECRET = process.env.PAYSTACK_SECRET || process.env.PAYSTACK_SECRET_KEY || "";
const ARKESEL_API_KEY = process.env.ARKESEL_API_KEY || "";
const ARKESEL_SENDER = process.env.ARKESEL_SENDER || "Arkesel";
const JWT_SECRET = process.env.JWT_SECRET || "change_this";
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || "admin";
const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH || "";

const upload = multer({ dest: "uploads/" });

// ------------------ Auth middleware ------------------
function requireAuth(req, res, next) {
  try {
    const h = req.headers.authorization;
    if (!h) return res.status(401).json({ message: "Missing auth" });
    const token = h.split(" ")[1];
    const payload = jwt.verify(token, JWT_SECRET);
    if (payload.role === "admin") return next();
    return res.status(403).json({ message: "Forbidden" });
  } catch {
    return res.status(401).json({ message: "Invalid token" });
  }
}

// ------------------ Admin Login ------------------
app.post("/admin/api/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ message: "username+password required" });
    if (username !== ADMIN_USERNAME) return res.status(401).json({ message: "Invalid credentials" });
    const ok = await bcrypt.compare(password, ADMIN_PASSWORD_HASH);
    if (!ok) return res.status(401).json({ message: "Invalid credentials" });
    const token = jwt.sign({ role: "admin", user: username }, JWT_SECRET, { expiresIn: "8h" });
    res.json({ token });
  } catch (err) {
    console.error('admin login error', err);
    res.status(500).json({ message: 'server error' });
  }
});

// ------------------ Admin: add voucher ------------------
app.post("/admin/api/vouchers", requireAuth, async (req, res) => {
  try {
    const { serial, pin } = req.body;
    if (!serial || !pin) return res.status(400).json({ message: "serial & pin required" });
    await pool.query("INSERT INTO vouchers (serial, pin, used) VALUES ($1,$2,false)", [serial.trim(), pin.trim()]);
    res.json({ success: true });
  } catch (err) {
    console.error('add voucher error', err);
    res.status(500).json({ message: "db error" });
  }
});

// ------------------ Admin: bulk upload ------------------
app.post("/admin/api/vouchers/bulk", requireAuth, upload.single("file"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ message: "No file uploaded" });
    const csv = fs.readFileSync(req.file.path, "utf8");
    fs.unlinkSync(req.file.path);
    const rows = parse(csv, { trim: true, skip_empty_lines: true });
    let inserted = 0;
    for (const r of rows) {
      const serial = r[0]?.toString().trim();
      const pin = r[1]?.toString().trim();
      if (!serial || !pin) continue;
      try {
        await pool.query("INSERT INTO vouchers (serial, pin, used) VALUES ($1,$2,false) ON CONFLICT (serial) DO NOTHING", [serial, pin]);
        inserted++;
      } catch (e) {
        console.error('bulk row error', e);
      }
    }
    res.json({ success: true, inserted });
  } catch (err) {
    console.error('bulk import error', err);
    res.status(500).json({ message: "import failed" });
  }
});

// ------------------ Admin: list vouchers ------------------
app.get("/admin/api/vouchers", requireAuth, async (req, res) => {
  try {
    const search = (req.query.search || "").toString();
    const limit = Math.max(1, Math.min(1000, Number(req.query.limit || 50)));
    const page = Math.max(1, Number(req.query.page || 1));
    const offset = (page - 1) * limit;

    // build where & params safely
    let where = "WHERE 1=1";
    const params = [];
    if (search) {
      params.push(`%${search}%`);
      where += ` AND (serial ILIKE $${params.length} OR pin ILIKE $${params.length})`;
    }

    // total count uses params (without limit/offset)
    const totalRes = await pool.query(`SELECT COUNT(*) FROM vouchers ${where}`, params);
    // now push limit/offset for rows query
    params.push(limit, offset);
    const rowsRes = await pool.query(`SELECT * FROM vouchers ${where} ORDER BY id DESC LIMIT $${params.length-1} OFFSET $${params.length}`, params);

    res.json({
      total: Number(totalRes.rows[0].count),
      vouchers: rowsRes.rows,
      page,
      per_page: limit
    });
  } catch (err) {
    console.error('list vouchers error', err);
    res.status(500).json({ message: "db error" });
  }
});

// ------------------ VERIFY PAYMENT (accepts GET or POST) ------------------
// Accept both GET (for quick tests) and POST (frontend likely uses POST).
async function handleVerifyPayment(req, res) {
  try {
    const reference = (req.method === 'POST' ? req.body.reference : req.query.reference) || req.query.reference;
    if (!reference) return res.status(400).json({ error: "Missing reference" });

    // call Paystack
    const verify = await axios.get(`https://api.paystack.co/transaction/verify/${encodeURIComponent(reference)}`, {
      headers: { Authorization: `Bearer ${PAYSTACK_SECRET}` }
    });

    const result = verify.data;
    if (!result || !result.status || result.data?.status !== "success") {
      return res.status(400).json({ error: "Payment not successful" });
    }

    const customerEmail = result.data?.customer?.email || "";
    const first = result.data?.customer?.first_name || "";
    const last = result.data?.customer?.last_name || "";
    const customerName = `${first} ${last}`.trim();

    // extract phone if frontend provided it (optional)
    const phone = (req.method === 'POST' ? req.body.phone : req.query.phone) || "";

    // Generate voucher
    const serial = "WAC" + Math.random().toString().slice(2, 10);
    const pin = Math.random().toString().slice(2, 8);

    // Save voucher
    await pool.query("INSERT INTO vouchers (serial,pin,used) VALUES ($1,$2,false)", [serial, pin]);

    // Record sale
    await pool.query(
      `INSERT INTO sales (name, phone, email, voucher_serial, voucher_pin, reference, date)
       VALUES ($1,$2,$3,$4,$5,$6,NOW())`,
      [customerName, phone || "", customerEmail, serial, pin, reference]
    );

    // return voucher (no SMS is sent here by default)
    return res.json({ success: true, serial, pin, voucher: `${serial} | ${pin}` });
  } catch (err) {
    console.error('verify-payment error', err?.response?.data || err.message || err);
    return res.status(500).json({ error: "Server error" });
  }
}
app.get("/verify-payment", handleVerifyPayment);
app.post("/verify-payment", handleVerifyPayment);

// ------------------ health ------------------
app.get("/health", (req, res) => res.json({ status: "ok" }));

// ------------------ Start ------------------
const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Server running on ${port}`));
