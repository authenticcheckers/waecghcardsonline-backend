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
// RAW BODY ONLY FOR WEBHOOK
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

      // Only accept charge.success
      if (event.event !== "charge.success") {
        return res.sendStatus(200);
      }

      const ref = event.data.reference;
      const email = event.data.customer.email || "";
      const name = `${event.data.customer.first_name || ""} ${
        event.data.customer.last_name || ""
      }`.trim();
      const phone = event.data.customer.phone || "";
      const purchaseType = "WASSCE";

      // 1️⃣ CHECK IF ALREADY DELIVERED
      const existing = await pool.query(
        "SELECT * FROM sales WHERE reference = $1 LIMIT 1",
        [ref]
      );

      if (existing.rows.length > 0) {
        console.log("⚠️ Voucher already delivered:", ref);
        return res.sendStatus(200);
      }

      // 2️⃣ PICK UNUSED VOUCHER
      const v = await pool.query(
        `SELECT id, serial, pin 
         FROM vouchers 
         WHERE used = false AND type = $1
         ORDER BY id ASC LIMIT 1`,
        [purchaseType]
      );

      if (v.rows.length === 0) {
        console.log("❌ No vouchers available");
        return res.sendStatus(500);
      }

      const voucher = v.rows[0];

      // 3️⃣ MARK USED
      await pool.query(
        "UPDATE vouchers SET used = true WHERE id = $1",
        [voucher.id]
      );

      // 4️⃣ SAVE SALE RECORD
      await pool.query(
        `INSERT INTO sales 
        (name, phone, email, voucher_serial, voucher_pin, reference, type, date)
        VALUES ($1,$2,$3,$4,$5,$6,$7,NOW())`,
        [name, phone, email, voucher.serial, voucher.pin, ref, purchaseType]
      );

      console.log("🎉 Voucher delivered via WEBHOOK:", voucher.serial);
      return res.sendStatus(200);
    } catch (err) {
      console.log("❌ Webhook crash:", err);
      return res.sendStatus(500);
    }
  }
);

// -----------------------------
// JSON BODY FOR NORMAL ROUTES
// -----------------------------
app.use(express.json({ limit: "2mb" }));

// -----------------------------
// CORS
// -----------------------------
app.use(cors({
  origin: [
    "https://waeccardsonline.vercel.app",
    "http://localhost:5500",
    "http://localhost:3000"
  ],
  methods: ["GET", "POST"],
  allowedHeaders: ["Content-Type"]
}));

// -----------------------------
// DEBUG LOGGER
// -----------------------------
app.use((req, res, next) => {
  console.log("\n===== NEW REQUEST =====");
  console.log("METHOD:", req.method);
  console.log("URL:", req.url);
  console.log("BODY:", req.body);
  next();
});

// -----------------------------
// DEBUG ENDPOINT
// -----------------------------
app.get("/__debug", (req, res) => {
  res.json({
    message: "NEW SERVER CODE ACTIVE",
    env: Object.keys(process.env)
  });
});

// -----------------------------
// VERIFY PAYMENT
// -----------------------------
async function handleVerifyPayment(req, res) {
  try {
    const reference = req.body?.reference || req.query?.reference;

    if (!reference) {
      return res.status(400).json({ error: "Missing reference" });
    }

    const purchaseType =
      String(req.body?.type || req.query?.type || "WASSCE").toUpperCase() === "BECE"
        ? "BECE"
        : "WASSCE";

    // LOAD PAYSTACK SECRET SAFELY
    const PAYSTACK_SECRET =
      process.env.PAYSTACK_SECRET ||
      process.env.PAYSTACK_SECRET_KEY ||
      process.env.PAYSTACK_PRIVATE_KEY ||
      process.env.SECRET_KEY ||
      "";

    console.log("📌 Using Paystack Secret:", PAYSTACK_SECRET.slice(0, 6) + "********");

    if (!PAYSTACK_SECRET.startsWith("sk_")) {
      console.log("❌ INVALID PAYSTACK SECRET LOADED");
      return res.status(500).json({ error: "Invalid Paystack secret key" });
    }

    // VERIFY PAYSTACK
    const verify = await axios.get(
      `https://api.paystack.co/transaction/verify/${encodeURIComponent(reference)}`,
      {
        headers: { Authorization: `Bearer ${PAYSTACK_SECRET}` }
      }
    );

    const result = verify.data;

    if (!result?.status || result.data?.status !== "success") {
      return res.status(400).json({ error: "Payment not successful" });
    }

    const customer = result.data.customer || {};
    let name =
      `${customer.first_name || ""} ${customer.last_name || ""}`.trim() ||
      req.body?.name ||
      "";

    const phone = req.body?.phone || "";
    const email = customer.email || req.body?.email || "";

    // PICK UNUSED VOUCHER
    const v = await pool.query(
      `SELECT id, serial, pin 
       FROM vouchers 
       WHERE used = false AND type = $1
       ORDER BY id ASC
       LIMIT 1`,
      [purchaseType]
    );

    if (v.rows.length === 0) {
      return res.status(500).json({ error: `${purchaseType} vouchers are sold out.` });
    }

    const voucher = v.rows[0];

    // MARK USED
    await pool.query(
      "UPDATE vouchers SET used = true WHERE id = $1",
      [voucher.id]
    );

    // SAVE SALE RECORD
    await pool.query(
      `INSERT INTO sales 
      (name, phone, email, voucher_serial, voucher_pin, reference, type, date)
      VALUES ($1,$2,$3,$4,$5,$6,$7,NOW())`,
      [name, phone, email, voucher.serial, voucher.pin, reference, purchaseType]
    );

    return res.json({
      success: true,
      type: purchaseType,
      serial: voucher.serial,
      pin: voucher.pin,
      voucher: `${voucher.serial} | ${voucher.pin}`,
      reference
    });

  } catch (err) {
    console.log("❌ verify-payment crash:", err?.response?.data || err);
    return res.status(500).json({ error: "Server error" });
  }
}

// ROUTES
app.post("/verify-payment", handleVerifyPayment);
app.get("/verify-payment", handleVerifyPayment);

// HEALTH
app.get("/health", (req, res) => res.json({ status: "ok" }));

// START SERVER
app.listen(process.env.PORT || 3000, () =>
  console.log("Backend live on", process.env.PORT || 3000)
);
