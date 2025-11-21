// ------------------ PostgreSQL Setup ------------------
import pg from "pg";
const { Pool } = pg;

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

// ------------------ Imports ------------------
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
const app = express();

// ---------- VIEW ENGINE ----------
app.set('view engine', 'ejs');
app.set('views', path.join(process.cwd(), 'views'));

// ---------- CORS ----------
app.use(cors({
  origin: [
    "https://waeccardsonline.vercel.app",
    "https://waeccardsonline-frontend.vercel.app",
    "http://localhost:3000",
  ],
  methods: ["GET","POST","PUT","DELETE","OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));

// Capture raw body (Paystack)
app.use(bodyParser.json({
  verify: (req, res, buf) => { req.rawBody = buf; }
}));
app.use(bodyParser.urlencoded({ extended: true }));

// ---------- ENV VARIABLES ----------
const PAYSTACK_SECRET_KEY = process.env.PAYSTACK_SECRET_KEY;
const ARKESEL_API_KEY = process.env.ARKESEL_API_KEY || "";
const ARKESEL_SENDER = process.env.ARKESEL_SENDER || "Arkesel";

const JWT_SECRET = process.env.JWT_SECRET || "secret";
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || "admin";
const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH;

// ---------- FILE UPLOAD ----------
const upload = multer({ dest: path.join("uploads/") });

// ==========================================================
//                  ADMIN AUTHENTICATION
// ==========================================================
async function ensureAdmin(req, res, next) {
  try {
    const header = req.headers.authorization;
    if (!header) return res.status(401).json({ message: "No auth" });

    const token = header.split(" ")[1];
    const decoded = jwt.verify(token, JWT_SECRET);

    if (decoded.role === "admin") return next();
    return res.status(403).json({ message: "Forbidden" });

  } catch (err) {
    return res.status(401).json({ message: "Invalid token" });
  }
}

app.post("/admin/api/login", async (req, res) => {
  const { username, password } = req.body;

  if (username !== ADMIN_USERNAME)
    return res.status(401).json({ message: "Invalid credentials" });

  const ok = await bcrypt.compare(password, ADMIN_PASSWORD_HASH);
  if (!ok) return res.status(401).json({ message: "Invalid credentials" });

  const token = jwt.sign({ role: "admin", user: username }, JWT_SECRET, {
    expiresIn: "8h",
  });

  res.json({ token });
});

// Serve admin + frontend
app.use("/admin", express.static("admin"));
app.use("/", express.static("frontend"));



// ==========================================================
//                   ADMIN: ADD SINGLE VOUCHER
// ==========================================================
app.post("/admin/api/vouchers", ensureAdmin, async (req, res) => {
  try {
    const { serial, pin } = req.body;
    if (!serial || !pin)
      return res.status(400).json({ message: "Both required" });

    await pool.query(
      "INSERT INTO vouchers (serial, pin, status) VALUES ($1,$2,'unused')",
      [serial.trim(), pin.trim()]
    );

    res.json({ success: true });

  } catch (err) {
    if (err.message.includes("duplicate"))
      return res.status(400).json({ message: "Duplicate serial" });

    console.error(err);
    res.status(500).json({ message: "DB error" });
  }
});



// ==========================================================
//                     BULK UPLOAD VOUCHERS
// ==========================================================
app.post("/admin/api/vouchers/bulk", ensureAdmin, upload.single("file"), async (req, res) => {
  try {
    let content;
    if (req.file) {
      content = fs.readFileSync(req.file.path, "utf8");
      fs.unlinkSync(req.file.path);
    } else {
      return res.status(400).json({ message: "Upload a CSV file" });
    }

    const records = parse(content, { skip_empty_lines: true, trim: true });

    let inserted = 0;
    for (const row of records) {
      const serial = row[0];
      const pin = row[1];

      if (!serial || !pin) continue;

      try {
        await pool.query(
          "INSERT INTO vouchers (serial, pin, status) VALUES ($1,$2,'unused') ON CONFLICT DO NOTHING;",
          [serial.trim(), pin.trim()]
        );
        inserted++;
      } catch (e) {}
    }

    res.json({ success: true, inserted });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Upload failed" });
  }
});



// ==========================================================
//                        LIST VOUCHERS
// ==========================================================
app.get("/admin/api/vouchers", ensureAdmin, async (req, res) => {
  try {
    const status = req.query.status || "all";
    const search = req.query.search || "";
    const limit = Number(req.query.limit || 50);
    const page = Number(req.query.page || 1);
    const offset = (page - 1) * limit;

    let where = "WHERE 1=1";
    const params = [];

    if (status === "unused") { where += " AND status='unused'"; }
    if (status === "used")   { where += " AND status='used'"; }

    if (search) {
      where += " AND (serial ILIKE $1 OR pin ILIKE $1)";
      params.push(`%${search}%`);
    }

    const total = await pool.query(`SELECT COUNT(*) FROM vouchers ${where}`, params);
    const rows = await pool.query(
      `SELECT * FROM vouchers ${where} ORDER BY id DESC LIMIT ${limit} OFFSET ${offset}`,
      params
    );

    res.json({
      total: Number(total.rows[0].count),
      vouchers: rows.rows,
      page,
      per_page: limit,
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "DB error" });
  }
});



// ==========================================================
//                 VERIFY PAYMENT (MAIN ROUTE)
// ==========================================================
app.post("/verify-payment", async (req, res) => {
  const { reference, name, phone, email } = req.body;

  if (!reference)
    return res.status(400).json({ success: false, message: "Missing reference" });

  try {
    const verify = await axios.get(
      `https://api.paystack.co/transaction/verify/${reference}`,
      { headers: { Authorization: `Bearer ${PAYSTACK_SECRET_KEY}` } }
    );

    if (!verify.data.status || verify.data.data.status !== "success") {
      return res.status(400).json({ success: false, message: "Payment failed" });
    }

    // Start DB transaction
    const client = await pool.connect();
    try {
      await client.query("BEGIN");

      // Fetch 1 unused voucher
      const voucher = await client.query(
        "SELECT * FROM vouchers WHERE status='unused' ORDER BY id ASC LIMIT 1"
      );

      if (voucher.rows.length === 0) {
        await client.query("ROLLBACK");
        return res.status(500).json({ success: false, message: "Out of vouchers" });
      }

      const v = voucher.rows[0];
      const now = new Date().toISOString();
      const amount = verify.data.data.amount / 100;

      // Mark voucher used
      await client.query(
        "UPDATE vouchers SET status='used', date_used=$1, buyer=$2 WHERE id=$3",
        [now, phone || email || "", v.id]
      );

      // Save sales record
      await client.query(
        `INSERT INTO sales (phone,email,voucher_serial,amount,timestamp,paystack_ref)
         VALUES ($1,$2,$3,$4,$5,$6)`,
        [phone, email, v.serial, amount, now, reference]
      );

      await client.query("COMMIT");
      client.release();

      // Send SMS
      if (phone && ARKESEL_API_KEY) {
        try {
          await axios.post(
            "https://sms.arkesel.com/api/v2/sms/send",
            {
              recipients: [phone],
              sender: ARKESEL_SENDER,
              message: `Your WASSCE voucher:\nSerial: ${v.serial}\nPIN: ${v.pin}`,
            },
            { headers: { "api-key": ARKESEL_API_KEY } }
          );
        } catch {}
      }

      return res.json({
        success: true,
        serial: v.serial,
        pin: v.pin,
        voucher: `${v.serial} | ${v.pin}`,
      });

    } catch (err) {
      await client.query("ROLLBACK");
      client.release();
      throw err;
    }

  } catch (err) {
    console.error("verify-payment error", err);
    return res.status(500).json({ success: false, message: "Server error" });
  }
});



// ==========================================================
//                        SUCCESS PAGE
// ==========================================================
app.get("/success", (req, res) => {
  const serial = req.query.serial;
  const pin = req.query.pin;

  if (!serial || !pin)
    return res.status(400).send("Missing voucher");

  res.render("success", { voucher: `${serial} | ${pin}` });
});



// ==========================================================
//                      HEALTH CHECK
// ==========================================================
app.get("/health", (req, res) => res.json({ status: "ok" }));



// ==========================================================
//                      START SERVER
// ==========================================================
app.listen(process.env.PORT || 3000, () =>
  console.log("Server running on port", process.env.PORT || 3000)
);
