// server.js — FINAL VERSION USING: vouchers(id,serial,pin,used), sales(...)

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

app.use(
  bodyParser.json({
    verify: (req, res, buf) => {
      req.rawBody = buf;
    }
  })
);

app.use(bodyParser.urlencoded({ extended: true }));

const PAYSTACK_SECRET_KEY = process.env.PAYSTACK_SECRET_KEY || "";
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
  const { username, password } = req.body;
  if (username !== ADMIN_USERNAME)
    return res.status(401).json({ message: "Invalid credentials" });

  const ok = await bcrypt.compare(password, ADMIN_PASSWORD_HASH);
  if (!ok) return res.status(401).json({ message: "Invalid credentials" });

  const token = jwt.sign({ role: "admin" }, JWT_SECRET, { expiresIn: "8h" });
  res.json({ token });
});

// ------------------ Admin: add voucher ------------------
app.post("/admin/api/vouchers", requireAuth, async (req, res) => {
  const { serial, pin } = req.body;
  if (!serial || !pin)
    return res.status(400).json({ message: "serial & pin required" });

  try {
    await pool.query(
      "INSERT INTO vouchers (serial, pin, used) VALUES ($1,$2,false)",
      [serial.trim(), pin.trim()]
    );
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "db error" });
  }
});

// ------------------ Admin: bulk upload ------------------
app.post(
  "/admin/api/vouchers/bulk",
  requireAuth,
  upload.single("file"),
  async (req, res) => {
    try {
      if (!req.file) return res.status(400).json({ message: "No file uploaded" });

      const csv = fs.readFileSync(req.file.path, "utf8");
      fs.unlinkSync(req.file.path);
      const rows = parse(csv, { trim: true, skip_empty_lines: true });

      let inserted = 0;
      for (const r of rows) {
        const serial = r[0]?.trim();
        const pin = r[1]?.trim();
        if (!serial || !pin) continue;

        try {
          await pool.query(
            "INSERT INTO vouchers (serial, pin, used) VALUES ($1,$2,false) ON CONFLICT DO NOTHING",
            [serial, pin]
          );
          inserted++;
        } catch {}
      }

      res.json({ success: true, inserted });
    } catch (err) {
      console.error(err);
      res.status(500).json({ message: "import failed" });
    }
  }
);

// ------------------ Admin: list vouchers ------------------
app.get("/admin/api/vouchers", requireAuth, async (req, res) => {
  try {
    const search = req.query.search || "";
    const limit = Number(req.query.limit || 50);
    const page = Number(req.query.page || 1);
    const offset = (page - 1) * limit;

    let where = "WHERE 1=1";
    const params = [];

    if (search) {
      params.push(`%${search}%`);
      where += ` AND (serial ILIKE $${params.length} OR pin ILIKE $${params.length})`;
    }

    const totalRes = await pool.query(
      `SELECT COUNT(*) FROM vouchers ${where}`,
      params
    );
    const rowsRes = await pool.query(
      `SELECT * FROM vouchers ${where} ORDER BY id DESC LIMIT ${
        params.length + 1
      } OFFSET ${params.length + 2}`,
      [...params, limit, offset]
    );

    res.json({
      total: Number(totalRes.rows[0].count),
      vouchers: rowsRes.rows,
      page,
      per_page: limit
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "db error" });
  }
});

// ------------------ VERIFY PAYMENT ------------------
app.get("/verify-payment", async (req, res) => {
  try {
    const reference = req.query.reference;
    if (!reference)
      return res.status(400).json({ error: "Missing reference" });

    const verify = await axios.get(
      `https://api.paystack.co/transaction/verify/${reference}`,
      {
        headers: { Authorization: `Bearer ${PAYSTACK_SECRET_KEY}` }
      }
    );

    const result = verify.data;

    if (!result.status || result.data.status !== "success") {
      return res.status(400).json({ error: "Payment not successful" });
    }

    const customerEmail = result.data.customer.email;
    const first = result.data.customer.first_name || "";
    const last = result.data.customer.last_name || "";
    const customerName = `${first} ${last}`.trim();

    // Generate voucher
    const serial = "WAC" + Math.random().toString().slice(2, 10);
    const pin = Math.random().toString().slice(2, 8);

    // Save voucher
    await pool.query(
      "INSERT INTO vouchers (serial,pin,used) VALUES ($1,$2,false)",
      [serial, pin]
    );

    // Record sale
    await pool.query(
      `INSERT INTO sales (name, phone, email, voucher_serial, voucher_pin, reference, date)
       VALUES ($1,$2,$3,$4,$5,$6,NOW())`,
      [customerName, "", customerEmail, serial, pin, reference]
    );

    return res.json({ success: true, serial, pin });
  } catch (err) {
    console.error("verify-payment error", err);
    return res.status(500).json({ error: "Server error" });
  }
});

// ------------------ health ------------------
app.get("/health", (req, res) => res.json({ status: "ok" }));

// ------------------ Start ------------------
app.listen(process.env.PORT || 3000, () =>
  console.log("Server running on", process.env.PORT || 3000)
);
