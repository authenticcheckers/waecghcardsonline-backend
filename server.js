import express from "express";
import cors from "cors";
import axios from "axios";
import dotenv from "dotenv";
import pkg from "pg";

dotenv.config();

const { Pool } = pkg;

////////////////////////////////////
// POSTGRES CONNECTION
////////////////////////////////////
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

////////////////////////////////////
// EXPRESS SETUP
////////////////////////////////////
const app = express();

// THE ONLY BODY PARSER — THIS FIXES EVERYTHING
app.use(express.json({ limit: "2mb" }));

app.use(cors({
  origin: [
    "https://waeccardsonline.vercel.app",
    "http://localhost:5500",
    "http://localhost:3000"
  ],
  methods: ["GET", "POST"],
  allowedHeaders: ["Content-Type"]
}));

////////////////////////////////////
// DEBUG LOGGER (DO NOT REMOVE)
////////////////////////////////////
app.use((req, res, next) => {
  console.log("\n===== NEW REQUEST =====");
  console.log("METHOD:", req.method);
  console.log("URL:", req.url);
  console.log("BODY:", req.body);
  next();
});

////////////////////////////////////
// VERIFY PAYMENT ENDPOINT
////////////////////////////////////
async function handleVerifyPayment(req, res) {
  try {
    // FIX 100%: read reference safely from body or query
    const reference = req.body?.reference || req.query?.reference;

    if (!reference) {
      console.log("❌ Reference missing even after fallback!");
      return res.status(400).json({ error: "Missing reference" });
    }

    const purchaseType =
      String(req.body?.type || req.query?.type || "WASSCE").toUpperCase() === "BECE"
        ? "BECE"
        : "WASSCE";

    ////////////////////////////////
    // VERIFY PAYSTACK
    ////////////////////////////////
    const verify = await axios.get(
      `https://api.paystack.co/transaction/verify/${encodeURIComponent(reference)}`,
      { headers: { Authorization: `Bearer ${process.env.PAYSTACK_SECRET}` } }
    );

    const result = verify.data;

    if (!result?.status || result.data?.status !== "success") {
      return res.status(400).json({ error: "Payment not successful" });
    }

    console.log("✔ Paystack verification success");

    ////////////////////////////////
    // EXTRACT CUSTOMER INFO
    ////////////////////////////////
    const customer = result.data.customer || {};

    let name =
      `${customer.first_name || ""} ${customer.last_name || ""}`.trim() ||
      req.body?.name ||
      req.query?.name ||
      "";

    const phone = req.body?.phone || req.query?.phone || "";
    const email = customer.email || req.body?.email || "";

    ////////////////////////////////
    // GET UNUSED VOUCHER
    ////////////////////////////////
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

    ////////////////////////////////
    // MARK VOUCHER USED
    ////////////////////////////////
    await pool.query(
      "UPDATE vouchers SET used = true WHERE id = $1",
      [voucher.id]
    );

    ////////////////////////////////
    // INSERT SALE (SAFE MODE)
    ////////////////////////////////
    try {
      await pool.query(
        `INSERT INTO sales 
        (name, phone, email, voucher_serial, voucher_pin, reference, type, date)
        VALUES ($1,$2,$3,$4,$5,$6,$7,NOW())`,
        [name, phone, email, voucher.serial, voucher.pin, reference, purchaseType]
      );
    } catch (e) {
      console.log("sales insert failed → trying fallback", e.message);
      await pool.query(
        `INSERT INTO sales 
        (name, phone, email, voucher_serial, voucher_pin, reference, date)
        VALUES ($1,$2,$3,$4,$5,$6,NOW())`,
        [name, phone, email, voucher.serial, voucher.pin, reference]
      );
    }

    ////////////////////////////////
    // SUCCESS RESPONSE
    ////////////////////////////////
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

app.post("/verify-payment", handleVerifyPayment);
app.get("/verify-payment", handleVerifyPayment);

// HEALTH CHECK
app.get("/health", (req, res) => res.json({ status: "ok" }));

// START SERVER
app.listen(process.env.PORT || 3000, () =>
  console.log("Backend live on", process.env.PORT || 3000)
);
