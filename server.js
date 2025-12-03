// server.js (updated)
// CLEAN, SAFE, NOTHING BROKEN + MULTI-VOUCHER & RETRIEVE SUPPORT

import express from "express";
import cors from "cors";
import axios from "axios";
import dotenv from "dotenv";
import crypto from "crypto";
import pkg from "pg";
import csv from "csv-parser";
import { upload } from "./middleware/upload.js";



async function sendSMS(phone, text) {
  try {
    const res = await axios.post(
      "https://sms.arkesel.com/api/v2/sms/send",
      {
        sender: "RESONLINE",   // approved sender ID
        message: text,
        type: "sms",           // required by Arkesel
        recipients: [phone.replace(/^0/, "233")]
      },
      {
        headers: {
          "api-key": process.env.ARKESEL_API_KEY,
          "Content-Type": "application/json"
        }
      }
    );

    console.log("✔ SMS SENT:", res.data);

  } catch (error) {
    console.log("❌ SMS ERROR:", error.response?.data || error.message);
  }
}

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

const allowedOrigins = [
  "https://waeccardsonline.vercel.app",
  "http://localhost:5500",
  "http://localhost:3000"
];

app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (allowedOrigins.includes(origin)) {
    res.header("Access-Control-Allow-Origin", origin);
  }
  res.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
  res.header("Access-Control-Allow-Credentials", "true");
  res.header(
    "Access-Control-Allow-Headers",
    "Content-Type, Authorization, X-Requested-With, x-paystack-signature"
  );

  if (req.method === "OPTIONS") return res.sendStatus(200);
  next();
});

// -----------------------------
// RAW BODY FOR WEBHOOK (BEFORE express.json)
// -----------------------------
app.post(
  "/webhook",
  express.raw({ type: "application/json" }),
  async (req, res) => {
    try {
      const secret = process.env.PAYSTACK_SECRET_KEY;
      const signature = req.headers["x-paystack-signature"];
      const computedHash = crypto
        .createHmac("sha512", secret)
        .update(req.body)
        .digest("hex");

      if (computedHash !== signature) {
        console.log("❌ Invalid webhook signature");
        return res.sendStatus(401);
      }

      const event = JSON.parse(req.body.toString());
      console.log("\n🔥 PAYSTACK WEBHOOK:", event.event);

      if (event.event !== "charge.success") {
        return res.sendStatus(200);
      }

      const ref = event.data.reference;
      const metadata = event.data.metadata || {};
      const purchaseType = (metadata.voucher_type || "WASSCE").toUpperCase();
      const quantity = Number(metadata.quantity || 1);
      // enforce max purchase limit
if (quantity > 30) {
  console.log(`❌ Blocked webhook: quantity ${quantity} exceeds limit of 30`);
  return res.sendStatus(400);
}


      const email = event.data.customer?.email || "";
      const name = `${event.data.customer?.first_name || ""} ${event.data.customer?.last_name || ""}`.trim();
      const phone = event.data.customer?.phone || metadata.phone || "";

      // prevent duplicate deliveries for this reference
      const exists = await pool.query(
        "SELECT 1 FROM sales WHERE reference = $1 LIMIT 1",
        [ref]
      );

      if (exists.rows.length > 0) {
        console.log("⚠️ Already delivered for reference", ref);
        return res.sendStatus(200);
      }

      // pick `quantity` vouchers of requested type
      const client = await pool.connect();
      try {
        await client.query("BEGIN");

        const vRes = await client.query(
          `SELECT id, serial, pin FROM vouchers
           WHERE used = false AND type = $1
           ORDER BY id ASC
           LIMIT $2 FOR UPDATE`,
          [purchaseType, quantity]
        );

        if (vRes.rows.length < quantity) {
          // Not enough vouchers to fulfill the order; rollback & report error.
          await client.query("ROLLBACK");
          console.log(`❌ Insufficient vouchers: requested ${quantity}, available ${vRes.rows.length}`);
          return res.sendStatus(500);
        }

        // Mark each voucher used and insert a sales row for each one
        for (const v of vRes.rows) {
          await client.query("UPDATE vouchers SET used = true WHERE id = $1", [v.id]);

          await client.query(
            `INSERT INTO sales (name, phone, email, voucher_serial, voucher_pin, reference, type, date)
             VALUES ($1,$2,$3,$4,$5,$6,$7,NOW())`,
            [name, phone, email, v.serial, v.pin, ref, purchaseType]
          );
        
// SEND SMS immediately after inserting
const smsText = 
  `${purchaseType} Voucher\n` +
  `SERIAL: ${v.serial}\nPIN: ${v.pin}\nThank you for using WaecGhCardsOnline.com`;

sendSMS(phone, smsText);
        }
        await client.query("COMMIT");
        console.log("🎉 Delivered", vRes.rows.map(x=>x.serial).join(", "), purchaseType, `x${quantity}`);
        return res.sendStatus(200);
      } catch (err) {
        await client.query("ROLLBACK");
        console.log("❌ Webhook transaction error", err);
        return res.sendStatus(500);
      } finally {
        client.release();
      }

    } catch (err) {
      console.log("❌ Webhook crash", err);
      return res.sendStatus(500);
    }
  }
);

app.use(express.json({ limit: "2mb" }));

// -----------------------------
// VERIFY PAYMENT (FRONTEND CALL)
// -----------------------------
async function handleVerifyPayment(req, res) {
  try {
    const reference = req.body?.reference || req.query?.reference;
    if (!reference) return res.status(400).json({ error: "Missing reference" });

    const PAYSTACK_SECRET =
      process.env.PAYSTACK_SECRET_KEY || process.env.PAYSTACK_SECRET;

    const verify = await axios.get(
      `https://api.paystack.co/transaction/verify/${reference}`,
      { headers: { Authorization: `Bearer ${PAYSTACK_SECRET}` } }
    );

    const result = verify.data;
    const metadata = result.data?.metadata || {};
const quantity = Number(metadata.quantity || 1);

// enforce max purchase on verify
if (quantity > 30) {
  return res.status(400).json({
    success: false,
    error: "Maximum 30 vouchers allowed per purchase"
  });
}

    if (!result?.status || result.data?.status !== "success") {
      return res.status(400).json({ error: "Payment failed" });
    }

    // return all sales rows for this reference (may be multiple)
    const sales = await pool.query(
      `SELECT voucher_serial AS serial, voucher_pin AS pin, type, date
       FROM sales WHERE reference = $1 ORDER BY date ASC`,
      [reference]
    );

    if (sales.rows.length === 0) {
      // Payment verified but webhook hasn't delivered vouchers yet
      return res.status(202).json({
        success: true,
        vouchers: [],
        message: "Verified. Waiting for voucher delivery..."
      });
    }

    return res.json({
      success: true,
      vouchers: sales.rows
    });

  } catch (err) {
    console.log("❌ verify-payment crash", err?.response?.data || err);
    return res.status(500).json({ error: "Server error" });
  }
}

app.post("/verify-payment", handleVerifyPayment);
app.get("/verify-payment", handleVerifyPayment);

// -----------------------------
// RETRIEVE VOUCHERS ROUTE
// -----------------------------
app.get("/retrieve-vouchers", async (req, res) => {
  try {
    const { phone, email } = req.query;
    if (!phone && !email) return res.status(400).json({ success: false, message: "Provide phone or email" });

    const params = [];
    let where = "";
    if (phone) {
      params.push(phone);
      where = "phone = $1";
    } else {
      params.push(email);
      where = "email = $1";
    }

    const q = await pool.query(
      `SELECT voucher_serial AS serial, voucher_pin AS pin, type, date
       FROM sales WHERE ${where}
       ORDER BY date DESC`,
      params
    );

    res.json({ success: true, vouchers: q.rows });
  } catch (err) {
    console.log("❌ retrieve-vouchers error", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// -----------------------------
// ADMIN & UTIL ROUTES (UNCHANGED)
// -----------------------------
app.post("/admin/login", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ success: false, message: "Missing credentials" });

  if (username === process.env.ADMIN_USERNAME && password === process.env.ADMIN_PASSWORD)
    return res.json({ success: true });

  return res.status(401).json({ success: false, message: "Invalid credentials" });
});

app.get("/admin/sales", async (req, res) => {
  try {
    const q = await pool.query(
      `SELECT id, name, phone, email, voucher_serial, voucher_pin, reference, type, date
       FROM sales ORDER BY date DESC`
    );
    res.json({ success: true, data: q.rows });
  } catch (err) {
    res.status(500).json({ success: false, message: "Server error" });
  }
});

app.get("/admin/vouchers", async (req, res) => {
  try {
    const q = await pool.query(`SELECT id, serial, pin, type, used FROM vouchers ORDER BY id ASC`);
    res.json({ success: true, data: q.rows });
  } catch (err) {
    res.status(500).json({ success: false, message: "Server error" });
  }
});

app.post("/admin/upload", async (req, res) => {
  try {
    const vouchers = req.body?.vouchers;
    if (!Array.isArray(vouchers)) return res.status(400).json({ success: false, message: "Invalid vouchers format" });

    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      for (const v of vouchers) {
        await client.query(
          `INSERT INTO vouchers (serial, pin, type, used) VALUES ($1,$2,$3,false)`,
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

    res.json({ success: true, message: "Vouchers uploaded" });
  } catch (err) {
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// -----------------------------
// SERVER START
// -----------------------------
app.listen(process.env.PORT || 3000, () =>
  console.log("Backend live on", process.env.PORT || 3000)
);
