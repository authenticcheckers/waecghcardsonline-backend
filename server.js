// server.js — FINAL WITH BECE + WASSCE SUPPORT (robustified)
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

app.use(bodyParser.json({ verify: (req, res, buf) => { req.rawBody = buf; } }));
app.use(bodyParser.urlencoded({ extended: true }));

const PAYSTACK_SECRET = process.env.PAYSTACK_SECRET || process.env.PAYSTACK_SECRET_KEY || "";
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
  } catch (e) {
    console.error('auth error', e?.message || e);
    return res.status(401).json({ message: "Invalid token" });
  }
}

// ------------------ Admin Login ------------------
app.post("/admin/api/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password)
      return res.status(400).json({ message: "username+password required" });

    if (username !== ADMIN_USERNAME)
      return res.status(401).json({ message: "Invalid credentials" });

    const ok = await bcrypt.compare(password, ADMIN_PASSWORD_HASH);
    if (!ok) return res.status(401).json({ message: "Invalid credentials" });

    const token = jwt.sign({ role: "admin", user: username }, JWT_SECRET, { expiresIn: "8h" });

    res.json({ token });
  } catch (err) {
    console.error("admin login error", err);
    res.status(500).json({ message: "server error" });
  }
});

// ------------------ Admin: add voucher ------------------
app.post("/admin/api/vouchers", requireAuth, async (req, res) => {
  try {
    const { serial, pin, type } = req.body;

    if (!serial || !pin)
      return res.status(400).json({ message: "serial & pin required" });

    const t = type && String(type).toUpperCase() === "BECE" ? "BECE" : "WASSCE";

    // avoid crashing on duplicate serials
    await pool.query(
      "INSERT INTO vouchers (serial, pin, used, type) VALUES ($1,$2,false,$3) ON CONFLICT (serial) DO NOTHING",
      [serial.trim(), pin.trim(), t]
    );

    res.json({ success: true });
  } catch (err) {
    console.error("add voucher error", err);
    res.status(500).json({ message: "db error" });
  }
});

// ------------------ Admin: bulk upload ------------------
app.post("/admin/api/vouchers/bulk", requireAuth, upload.single("file"), async (req, res) => {
  try {
    if (!req.file)
      return res.status(400).json({ message: "No file uploaded" });

    const csv = fs.readFileSync(req.file.path, "utf8");
    fs.unlinkSync(req.file.path);

    const rows = parse(csv, { trim: true, skip_empty_lines: true });

    let inserted = 0;

    for (const r of rows) {
      const serial = r[0]?.toString().trim();
      const pin = r[1]?.toString().trim();
      const typeCSV = (r[2]?.toString().trim() || "WASSCE").toUpperCase();

      const type = ["WASSCE", "BECE"].includes(typeCSV) ? typeCSV : "WASSCE";

      if (!serial || !pin) continue;

      try {
        const resIns = await pool.query(
          `INSERT INTO vouchers (serial, pin, used, type)
           VALUES ($1,$2,false,$3)
           ON CONFLICT (serial) DO NOTHING`,
          [serial, pin, type]
        );
        // count inserted only when rowCount > 0 (i.e., insert happened)
        if (resIns.rowCount && resIns.rowCount > 0) inserted++;
      } catch (e) {
        console.error('bulk row error', e?.message || e);
      }
    }

    res.json({ success: true, inserted });
  } catch (err) {
    console.error("bulk import error", err);
    res.status(500).json({ message: "import failed" });
  }
});

// ------------------ Admin: list vouchers ------------------
app.get("/admin/api/vouchers", requireAuth, async (req, res) => {
  try {
    const search = (req.query.search || "").toString();
    const typeFilter = (req.query.type || "").toString().toUpperCase();
    const limit = Math.max(1, Math.min(1000, Number(req.query.limit || 50)));
    const page = Math.max(1, Number(req.query.page || 1));
    const offset = (page - 1) * limit;

    let where = "WHERE 1=1";
    const params = [];

    if (search) {
      params.push(`%${search}%`);
      where += ` AND (serial ILIKE $${params.length} OR pin ILIKE $${params.length})`;
    }

    if (["BECE", "WASSCE"].includes(typeFilter)) {
      params.push(typeFilter);
      where += ` AND type = $${params.length}`;
    }

    const totalRes = await pool.query(`SELECT COUNT(*) FROM vouchers ${where}`, params);

    params.push(limit, offset);

    const rowsRes = await pool.query(
      `SELECT * FROM vouchers ${where} ORDER BY id DESC LIMIT $${params.length - 1} OFFSET $${params.length}`,
      params
    );

    res.json({
      total: Number(totalRes.rows[0].count),
      vouchers: rowsRes.rows,
      page,
      per_page: limit
    });
  } catch (err) {
    console.error("list vouchers error", err);
    res.status(500).json({ message: "db error" });
  }
});

// ------------------ VERIFY PAYMENT ------------------
async function handleVerifyPayment(req, res) {
  try {
    const reference =
      req.method === "POST" ? req.body.reference : req.query.reference;

    if (!reference)
      return res.status(400).json({ error: "Missing reference" });

    // safely compute purchaseType so undefined doesn't throw
    const rawType = (req.method === "POST" ? req.body.type : req.query.type) || "WASSCE";
    const purchaseType = String(rawType).toUpperCase() === "BECE" ? "BECE" : "WASSCE";

    // Paystack verify
    const verify = await axios.get(
      `https://api.paystack.co/transaction/verify/${encodeURIComponent(reference)}`,
      { headers: { Authorization: `Bearer ${PAYSTACK_SECRET}` } }
    );

    const result = verify.data;

    if (!result || !result.status || result.data?.status !== "success") {
      return res.status(400).json({ error: "Payment not successful" });
    }

    const email = result.data?.customer?.email || "";
    const first = result.data?.customer?.first_name || "";
    const last = result.data?.customer?.last_name || "";
    const name = `${first} ${last}`.trim();
    const phone = (req.method === "POST" ? req.body.phone : req.query.phone) || "";

    // ----------- Fetch a real unused voucher from DB by type -----------
    const v = await pool.query(
      `SELECT id, serial, pin FROM vouchers 
       WHERE used = false AND type = $1
       ORDER BY id ASC
       LIMIT 1`,
      [purchaseType]
    );

    if (v.rows.length === 0) {
      return res.status(500).json({ error: `${purchaseType} vouchers are sold out.` });
    }

    const voucher = v.rows[0];

    // Mark as used
    await pool.query(
      "UPDATE vouchers SET used = true WHERE id = $1",
      [voucher.id]
    );

    // Record sale (sales table must have a 'type' column; otherwise remove type)
    try {
      await pool.query(
        `INSERT INTO sales (name, phone, email, voucher_serial, voucher_pin, reference, type, date)
         VALUES ($1,$2,$3,$4,$5,$6,$7,NOW())`,
        [name, phone, email, voucher.serial, voucher.pin, reference, purchaseType]
      );
    } catch (e) {
      // If sales table doesn't have 'type', fallback to inserting without it
      if (e && /column .* type .* does not exist/i.test(String(e))) {
        try {
          await pool.query(
            `INSERT INTO sales (name, phone, email, voucher_serial, voucher_pin, reference, date)
             VALUES ($1,$2,$3,$4,$5,$6,NOW())`,
            [name, phone, email, voucher.serial, voucher.pin, reference]
          );
        } catch (e2) {
          console.error('failed inserting sale fallback', e2);
        }
      } else {
        console.error('failed inserting sale', e);
      }
    }

    return res.json({
      success: true,
      type: purchaseType,
      serial: voucher.serial,
      pin: voucher.pin,
      voucher: `${voucher.serial} | ${voucher.pin}`
    });

  } catch (err) {
    console.error("verify-payment error", err?.response?.data || err?.message || err);
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
