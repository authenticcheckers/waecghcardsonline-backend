import express from "express";
import cors from "cors";
import axios from "axios";
import dotenv from "dotenv";
import pkg from "pg";
import csv from "csv-parser";
import { upload } from "./middleware/upload.js";

dotenv.config();
const { Pool } = pkg;

// -----------------------------
// POSTGRES CONNECTION
// -----------------------------
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

// -----------------------------
// EXPRESS SETUP
// -----------------------------
const app = express();
const allowedOrigins = [
  "https://waeccardsonline.vercel.app",
  "http://localhost:5500",
  "http://localhost:3000",
  "https://waeccheckers.com",
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
    "Content-Type, Authorization, X-Requested-With"
  );
  if (req.method === "OPTIONS") return res.sendStatus(200);
  next();
});

app.use(express.json({ limit: "2mb" }));

// -----------------------------
// MOOLRE CONFIG
// -----------------------------
const MOOLRE_API = "https://api.moolre.com";
const MOOLRE_USER = process.env.MOOLRE_USER;
const MOOLRE_PUB_KEY = process.env.MOOLRE_PUB_KEY;
const MOOLRE_ACCOUNT_NUMBER = process.env.MOOLRE_ACCOUNT_NUMBER;


const MOOLRE_WEBHOOK_SECRET = process.env.MOOLRE_WEBHOOK_SECRET;

const moolreHeaders = {
  "X-API-USER": MOOLRE_USER,
  "X-API-PUBKEY": MOOLRE_PUB_KEY,
  "Content-Type": "application/json",
};

// Channel codes: 13=MTN, 6=Telecel, 7=AT
const NETWORK_CHANNELS = { MTN: "13", Telecel: "6", AT: "7" };

// externalref format: WCO_{TYPE}_{QTY}_{TIMESTAMP}
function buildExternalRef(type, qty) {
  return `WCO_${type}_${qty}_${Date.now()}`;
}

function parseExternalRef(ref) {
  const parts = (ref || "").split("_");
  if (parts.length >= 4 && parts[0] === "WCO") {
    return { type: parts[1], qty: Number(parts[2]) };
  }
  return { type: "WASSCE", qty: 1 };
}

// -----------------------------
// HELPER: SEND SMS
// -----------------------------
async function sendSMS(phone, text) {
  try {
    const res = await axios.post(
      "https://sms.arkesel.com/api/v2/sms/send",
      {
        sender: "RESONLINE",
        message: text,
        type: "sms",
        recipients: [phone.replace(/^0/, "233")],
      },
      {
        headers: {
          "api-key": process.env.ARKESEL_API_KEY,
          "Content-Type": "application/json",
        },
      }
    );
    console.log("✔ SMS SENT:", res.data);
  } catch (error) {
    console.log("❌ SMS ERROR:", error.response?.data || error.message);
  }
}

// -----------------------------
// SHARED: DELIVER VOUCHERS
// -----------------------------
async function deliverVouchers({ externalref, phone, name, type, quantity }) {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    const vRes = await client.query(
      `SELECT id, serial, pin FROM vouchers
       WHERE used = false AND type = $1
       ORDER BY id ASC LIMIT $2 FOR UPDATE`,
      [type.toUpperCase(), quantity]
    );

    if (vRes.rows.length < quantity) {
      await client.query("ROLLBACK");
      console.log(
        `❌ Insufficient vouchers for ${externalref}: requested ${quantity}, available ${vRes.rows.length}`
      );
      return false;
    }

    for (const v of vRes.rows) {
      await client.query("UPDATE vouchers SET used = true WHERE id = $1", [v.id]);
      await client.query(
        `INSERT INTO sales (name, phone, email, voucher_serial, voucher_pin, reference, type, date)
         VALUES ($1,$2,$3,$4,$5,$6,$7,NOW())`,
        [name, phone, phone + "@moolre.com", v.serial, v.pin, externalref, type.toUpperCase()]
      );
      const smsText = `${type.toUpperCase()} Voucher\nSERIAL: ${v.serial}\nPIN: ${v.pin}\nThank you for using WaecGhCardsOnline.com`;
      sendSMS(phone, smsText);
    }

    await client.query("COMMIT");
    console.log(
      "🎉 Delivered",
      vRes.rows.map((x) => x.serial).join(", "),
      type,
      `x${quantity}`
    );
    return true;
  } catch (err) {
    await client.query("ROLLBACK");
    console.log("❌ Delivery transaction error", err);
    return false;
  } finally {
    client.release();
  }
}

// -----------------------------
// MOOLRE WEBHOOK  POST /webhook
// Moolre POSTs here when a payment completes
// -----------------------------
app.post("/webhook", async (req, res) => {
  try {
    const body = req.body;
    console.log("\n🔥 MOOLRE WEBHOOK:", JSON.stringify(body));

    const data = body.data || {};

    // Verify the webhook secret Moolre sends
    if (MOOLRE_WEBHOOK_SECRET && data.secret !== MOOLRE_WEBHOOK_SECRET) {
      console.log("❌ Invalid Moolre webhook secret");
      return res.sendStatus(401);
    }

    // txstatus: 1=Successful, 0=Pending, 2=Failed
    if (data.txstatus !== 1) {
      console.log("⚠️ Non-successful txstatus:", data.txstatus);
      return res.sendStatus(200);
    }

    const externalref = data.externalref || "";
    // Moolre sends payer as 233XXXXXXXXX; normalise to 0XXXXXXXXX
    const phone = (data.payer || "").replace(/^233/, "0");

    // Prevent duplicate deliveries
    const exists = await pool.query(
      "SELECT 1 FROM sales WHERE reference = $1 LIMIT 1",
      [externalref]
    );
    if (exists.rows.length > 0) {
      console.log("⚠️ Already delivered for externalref", externalref);
      return res.sendStatus(200);
    }

    const { type, qty } = parseExternalRef(externalref);
    await deliverVouchers({ externalref, phone, name: phone, type, quantity: qty });
    return res.sendStatus(200);
  } catch (err) {
    console.log("❌ Webhook crash", err);
    return res.sendStatus(500);
  }
});

// -----------------------------
// INITIATE PAYMENT  POST /initiate-payment
// Frontend calls this; we call Moolre and return the status
// -----------------------------
app.post("/initiate-payment", async (req, res) => {
  try {
    const { phone, name, type, quantity, network, otpcode } = req.body;

    if (!phone || !type || !quantity) {
      return res.status(400).json({ success: false, error: "Missing required fields" });
    }
    if (Number(quantity) > 30) {
      return res.status(400).json({ success: false, error: "Maximum 30 vouchers per purchase" });
    }

    const channel = NETWORK_CHANNELS[network] || NETWORK_CHANNELS.MTN;
    const amount = 30 * Number(quantity); // GHS 30 per voucher
    const externalref = buildExternalRef(type, quantity);

    // Moolre expects 233XXXXXXXXX
    const payerPhone = phone.startsWith("0")
      ? "233" + phone.slice(1)
      : phone.startsWith("+")
      ? phone.slice(1)
      : phone;

    const payload = {
      type: 1,
      channel,
      currency: "GHS",
      payer: payerPhone,
      amount,
      externalref,
      accountnumber: MOOLRE_ACCOUNT_NUMBER,
      ...(otpcode ? { otpcode } : {}),
    };

    console.log("💳 Initiating Moolre payment:", payload);
    const moolreRes = await axios.post(
      `${MOOLRE_API}/open/transact/payment`,
      payload,
      { headers: moolreHeaders }
    );

    const result = moolreRes.data;
    console.log("📦 Moolre response:", result);

    // TP14 = OTP required → ask frontend to collect OTP
    if (result.code === "TP14") {
      return res.json({ success: true, status: "otp_required", externalref, message: result.message });
    }
    // TP15 = OTP verified → re-submit without OTP to trigger USSD prompt
    if (result.code === "TP15") {
      return res.json({ success: true, status: "otp_verified", externalref, message: result.message });
    }
    // TR099 = payment prompt sent to customer's phone
    if (result.code === "TR099") {
      return res.json({
        success: true,
        status: "pending",
        externalref,
        message: "Payment prompt sent to your phone. Approve with your Mobile Money PIN.",
      });
    }

    return res.json({ success: false, status: "failed", message: result.message || "Payment initiation failed" });
  } catch (err) {
    console.log("❌ initiate-payment error", err?.response?.data || err.message);
    return res.status(500).json({ success: false, error: "Server error initiating payment" });
  }
});

// -----------------------------
// VERIFY / POLL  POST|GET /verify-payment
// Frontend polls this with the externalref to get vouchers
// -----------------------------
async function handleVerifyPayment(req, res) {
  try {
    const externalref = req.body?.reference || req.query?.reference;
    if (!externalref) return res.status(400).json({ error: "Missing reference" });

    // Check DB first (webhook may have already delivered)
    const sales = await pool.query(
      `SELECT voucher_serial AS serial, voucher_pin AS pin, type, date
       FROM sales WHERE reference = $1 ORDER BY date ASC`,
      [externalref]
    );
    if (sales.rows.length > 0) {
      return res.json({ success: true, vouchers: sales.rows });
    }

    // Not in DB yet — query Moolre for current status
    try {
      const statusRes = await axios.post(
        `${MOOLRE_API}/open/transact/status`,
        {
          type: 1,
          idtype: 1, // 1 = externalref
          id: externalref,
          accountnumber: MOOLRE_ACCOUNT_NUMBER,
        },
        { headers: moolreHeaders }
      );

      const sData = statusRes.data?.data || {};
      console.log("📊 Moolre status check:", statusRes.data);

      if (sData.txstatus === 2) {
        return res.status(400).json({ success: false, error: "Payment failed or was rejected" });
      }

      // Successful but vouchers not yet delivered (webhook missed / race)
      if (sData.txstatus === 1) {
        const { type, qty } = parseExternalRef(externalref);
        const phone = (sData.payer || "").replace(/^233/, "0");

        const already = await pool.query(
          "SELECT 1 FROM sales WHERE reference = $1 LIMIT 1",
          [externalref]
        );
        if (already.rows.length === 0) {
          await deliverVouchers({ externalref, phone, name: phone, type, quantity: qty });
        }

        const delivered = await pool.query(
          `SELECT voucher_serial AS serial, voucher_pin AS pin, type, date
           FROM sales WHERE reference = $1 ORDER BY date ASC`,
          [externalref]
        );
        if (delivered.rows.length > 0) {
          return res.json({ success: true, vouchers: delivered.rows });
        }
      }
    } catch (statusErr) {
      console.log("⚠️ Moolre status check failed:", statusErr?.response?.data || statusErr.message);
    }

    return res.status(202).json({ success: true, vouchers: [], message: "Payment pending. Please wait and try again." });
  } catch (err) {
    console.log("❌ verify-payment crash", err?.response?.data || err);
    return res.status(500).json({ error: "Server error" });
  }
}

app.post("/verify-payment", handleVerifyPayment);
app.get("/verify-payment", handleVerifyPayment);

// -----------------------------
// RETRIEVE VOUCHERS
// -----------------------------
app.get("/retrieve-vouchers", async (req, res) => {
  try {
    const { phone, email } = req.query;
    if (!phone && !email) return res.status(400).json({ success: false, message: "Provide phone or email" });

    const params = [];
    let where = "";
    if (phone) { params.push(phone); where = "phone = $1"; }
    else        { params.push(email); where = "email = $1"; }

    const q = await pool.query(
      `SELECT voucher_serial AS serial, voucher_pin AS pin, type, date
       FROM sales WHERE ${where} ORDER BY date DESC`,
      params
    );
    res.json({ success: true, vouchers: q.rows });
  } catch (err) {
    console.log("❌ retrieve-vouchers error", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// -----------------------------
// ADMIN ROUTES
// -----------------------------
app.post("/admin/login", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ success: false, message: "Missing credentials" });
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

app.put("/admin/voucher/void/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const result = await pool.query(
      "UPDATE vouchers SET used = true, used_at = NOW() WHERE id = $1",
      [id]
    );
    if (result.rowCount > 0) res.json({ success: true });
    else res.status(404).json({ success: false, message: "Voucher not found" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/upload-checkers-csv", upload.single("file"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: "No CSV file uploaded" });
    const batchType = req.body.type;
    const rows = [];
    const Readable = await import("stream").then((m) => m.Readable);
    const stream = Readable.from(req.file.buffer.toString());
    await new Promise((resolve, reject) => {
      stream.pipe(csv()).on("data", (row) => rows.push(row)).on("end", resolve).on("error", reject);
    });
    if (rows.length === 0) return res.status(400).json({ error: "CSV is empty" });
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const insertQuery = `INSERT INTO vouchers (serial, pin, type, used) VALUES ($1,$2,$3,false) ON CONFLICT (serial) DO NOTHING`;
      let insertedCount = 0;
      for (const r of rows) {
        const serial = r.Serial || r.serial || r.SERIAL;
        const pin = r.PIN || r.pin || r.Pin;
        const type = batchType || r.Type || r.type || r.TYPE || "BECE";
        if (serial && pin) {
          await client.query(insertQuery, [serial.trim(), pin.trim(), type.trim().toUpperCase()]);
          insertedCount++;
        }
      }
      await client.query("COMMIT");
      res.json({ message: "Upload complete", inserted: insertedCount });
    } catch (err) {
      await client.query("ROLLBACK");
      throw err;
    } finally {
      client.release();
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Server error processing CSV" });
  }
});

// -----------------------------
// SERVER START
// -----------------------------
app.listen(process.env.PORT || 3000, () =>
  console.log("Backend live on", process.env.PORT || 3000)
);
