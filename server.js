import express from "express";
import cors from "cors";
import axios from "axios";
import dotenv from "dotenv";
import crypto from "crypto";
import pkg from "pg";

dotenv.config();
const { Pool } = pkg;

// -----------------------------
// POSTGRES CONNECTION
// -----------------------------
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// -----------------------------
// EXPRESS SETUP
// -----------------------------
const app = express();

// -----------------------------
// CORS
// -----------------------------
const allowedOrigins = [
  "https://waeccardsonline.vercel.app",
  "http://localhost:5500",
  "http://localhost:3000"
];

app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (allowedOrigins.includes(origin)) res.header("Access-Control-Allow-Origin", origin);

  res.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
  res.header("Access-Control-Allow-Credentials", "true");
  res.header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With");

  if (req.method === "OPTIONS") return res.sendStatus(200);
  next();
});

// -----------------------------
// RAW BODY ONLY FOR WEBHOOK
// -----------------------------
app.post(
  "/webhook",
  express.raw({ type: "application/json" }),
  async (req, res) => {
    try {
      const secret = process.env.PAYSTACK_SECRET_KEY;
      const signature = req.headers["x-paystack-signature"];      
      const computedHash = crypto.createHmac("sha512", secret).update(req.body).digest("hex");

      if (computedHash !== signature) {
        console.log("❌ Invalid webhook signature");
        return res.sendStatus(401);
      }

      const event = JSON.parse(req.body.toString());
      console.log("🔥 PAYSTACK WEBHOOK EVENT:", event.event);

      if (event.event !== "charge.success") return res.sendStatus(200);

      const ref = event.data.reference;
      const purchaseType = (event.data.metadata?.purchaseType || "WASSCE").toUpperCase();
      const email = event.data.customer.email || "";
      const name = `${event.data.customer.first_name || ""} ${event.data.customer.last_name || ""}`.trim();
      const phone = event.data.customer.phone || "";

      // Prevent double delivery
      const existing = await pool.query("SELECT * FROM sales WHERE reference = $1 LIMIT 1", [ref]);
      if (existing.rows.length > 0) return res.sendStatus(200);

      // Pick FIRST unused voucher of correct type
      const v = await pool.query(
        `SELECT id, serial, pin FROM vouchers WHERE used = false AND type = $1 ORDER BY id ASC LIMIT 1`,
        [purchaseType]
      );

      if (v.rows.length === 0) {
        console.log(`❌ No ${purchaseType} vouchers available`);
        return res.sendStatus(500);
      }

      const voucher = v.rows[0];

      await pool.query("UPDATE vouchers SET used = true WHERE id = $1", [voucher.id]);

      await pool.query(
        `INSERT INTO sales (name, phone, email, voucher_serial, voucher_pin, reference, type, date)
         VALUES ($1,$2,$3,$4,$5,$6,$7,NOW())`,
        [name, phone, email, voucher.serial, voucher.pin, ref, purchaseType]
      );

      console.log(`🎉 Delivered ${purchaseType} voucher:`, voucher.serial);
      return res.sendStatus(200);

    } catch (err) {
      console.log("❌ Webhook crash:", err);
      return res.sendStatus(500);
    }
  }
);

// -----------------------------
// JSON BODY PARSER
// -----------------------------
app.use(express.json({ limit: "2mb" }));

// -----------------------------
// VERIFY PAYMENT
// -----------------------------
async function handleVerifyPayment(req, res) {
  try {
    const reference = req.body?.reference || req.query?.reference;
    if (!reference) return res.status(400).json({ error: "Missing reference" });

    const PAYSTACK_SECRET =
      process.env.PAYSTACK_SECRET ||
      process.env.PAYSTACK_SECRET_KEY ||
      process.env.PAYSTACK_PRIVATE_KEY ||
      process.env.SECRET_KEY || "";

    const verify = await axios.get(
      `https://api.paystack.co/transaction/verify/${encodeURIComponent(reference)}`,
      { headers: { Authorization: `Bearer ${PAYSTACK_SECRET}` } }
    );

    const result = verify.data;
    if (!result?.status || result.data?.status !== "success") {
      return res.status(400).json({ error: "Payment not successful" });
    }

    // Check if webhook already delivered voucher
    const sale = await pool.query(
      "SELECT voucher_serial, voucher_pin, type FROM sales WHERE reference = $1 LIMIT 1",
      [reference]
    );

    if (sale.rows.length === 0) {
      return res.status(202).json({
        success: false,
        message: "Payment verified. Waiting for voucher delivery..."
      });
    }

    return res.json({
      success: true,
      serial: sale.rows[0].voucher_serial,
      pin: sale.rows[0].voucher_pin,
      type: sale.rows[0].type
    });

  } catch (err) {
    console.log("❌ verify-payment crash:", err?.response?.data || err);
    return res.status(500).json({ error: "Server error" });
  }
}

app.post("/verify-payment", handleVerifyPayment);
app.get("/verify-payment", handleVerifyPayment);

// -----------------------------
// ADMIN: UPLOAD, LIST, LOGIN, MARK USED
// -----------------------------
app.post("/admin/login", async (req, res) => {
  const { username, password } = req.body;

  if (username === process.env.ADMIN_USERNAME && password === process.env.ADMIN_PASSWORD) {
    return res.json({ success: true });
  }
  return res.status(401).json({ success: false, message: "Invalid credentials" });
});

app.get("/admin/sales", async (req, res) => {
  try {
    const q = await pool.query(`SELECT * FROM sales ORDER BY date DESC`);
    res.json({ success: true, data: q.rows });
  } catch (err) {
    res.status(500).json({ success: false });
  }
});

app.get("/admin/vouchers", async (req, res) => {
  try {
    const q = await pool.query(`SELECT * FROM vouchers ORDER BY id ASC`);
    res.json({ success: true, data: q.rows });
  } catch (err) {
    res.status(500).json({ success: false });
  }
});

app.post("/admin/upload", async (req, res) => {
  try {
    const vouchers = req.body?.vouchers;
    if (!Array.isArray(vouchers)) return res.status(400).json({ success: false });

    const client = await pool.connect();
    try {
      await client.query("BEGIN");

      for (const v of vouchers) {
        await client.query(
          `INSERT INTO vouchers (serial, pin, type, used) VALUES ($1, $2, $3, false)`,
          [v.serial, v.pin, (v.type || "WASSCE").toUpperCase()]
        );
      }

      await client.query("COMMIT");
    } catch (err) {
      await client.query("ROLLBACK");
      throw err;
    } finally {
      client.release();
    }

    res.json({ success: true });

  } catch (err) {
    res.status(500).json({ success: false });
  }
});

app.post("/admin/mark-used", async (req, res) => {
  const { serial } = req.body;
  if (!serial) return res.json({ status: false });

  try {
    const update = await pool.query(
      `UPDATE vouchers SET used = true WHERE serial = $1 RETURNING *`,
      [serial]
    );

    if (update.rowCount === 0) return res.json({ status: false });
    res.json({ status: true });

  } catch (err) {
    res.json({ status: false });
