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
app.use(express.json());

app.use(cors({
  origin: [
    "https://waeccardsonline.vercel.app",
    "http://localhost:5500"
  ],
  methods: ["GET", "POST"],
  allowedHeaders: ["Content-Type"]
}));

////////////////////////////////////
// LOGGING (DON'T REMOVE)
////////////////////////////////////
app.use((req, res, next) => {
  console.log("\nIncoming:", req.method, req.url);
  console.log("Headers:", req.headers);
  console.log("Body:", req.body);
  next();
});

////////////////////////////////////
// VERIFY PAYMENT ENDPOINT
////////////////////////////////////
async function handleVerifyPayment(req, res) {
  try {
    const reference =
      req.method === "POST" ? req.body.reference : req.query.reference;

    if (!reference) {
      console.log("❌ Missing reference in request");
      return res.status(400).json({ error: "Missing reference" });
    }

    let rawType =
      req.method === "POST" ? req.body.type : req.query.type;

    const purchaseType =
      String(rawType || "").toUpperCase() === "BECE" ? "BECE" : "WASSCE";

    ////////////////////////////////
    // VERIFY WITH PAYSTACK
    ////////////////////////////////
    const verify = await axios.get(
      `https://api.paystack.co/transaction/verify/${encodeURIComponent(reference)}`,
      { headers: { Authorization: `Bearer ${process.env.PAYSTACK_SECRET}` } }
    );

    const result = verify.data;

    if (!result?.status || result.data?.status !== "success") {
      return res.status(400).json({ error: "Payment not successful" });
    }

    console.log("✔ Paystack verification OK");

    ////////////////////////////////
    // CUSTOMER NAME FALLBACK
    ////////////////////////////////
    const customer = result.data?.customer || {};
    let name = `${customer.first_name || ""} ${customer.last_name || ""}`.trim();

    if (!name || name.length < 2) {
      name =
        req.method === "POST"
          ? (req.body.name || "")
          : (req.query.name || "");
    }

    const phone =
      req.method === "POST" ? (req.body.phone || "") : (req.query.phone || "");

    const email = customer.email || req.body.email || "";

    ////////////////////////////////
    // GET AVAILABLE VOUCHER
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
    // MARK AS USED
    ////////////////////////////////
    await pool.query(
      "UPDATE vouchers SET used = true WHERE id = $1",
      [voucher.id]
    );

    ////////////////////////////////
    // INSERT INTO SALES (SAFE)
    ////////////////////////////////
    try {
      await pool.query(
        `INSERT INTO sales (name, phone, email, voucher_serial, voucher_pin, reference, type, date)
         VALUES ($1,$2,$3,$4,$5,$6,$7,NOW())`,
        [name, phone, email, voucher.serial, voucher.pin, reference, purchaseType]
      );
    } catch (e) {
      console.log("Sales insert error, trying fallback:", e.message);

      await pool.query(
        `INSERT INTO sales (name, phone, email, voucher_serial, voucher_pin, reference, date)
         VALUES ($1,$2,$3,$4,$5,$6,NOW())`,
        [name, phone, email, voucher.serial, voucher.pin, reference]
      );
    }

    ////////////////////////////////
    // RETURN SUCCESS PAYLOAD
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
    console.error("verify-payment ERROR →", err?.response?.data || err);
    return res.status(500).json({ error: "Server error" });
  }
}

app.get("/verify-payment", handleVerifyPayment);
app.post("/verify-payment", handleVerifyPayment);

////////////////////////////////////
// HEALTH CHECK
////////////////////////////////////
app.get("/health", (req, res) => res.json({ status: "ok" }));

////////////////////////////////////
// START SERVER
////////////////////////////////////
app.listen(process.env.PORT || 3000, () => {
  console.log("✔ Backend running on port", process.env.PORT || 3000);
});
