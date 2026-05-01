import express from "express";
import axios from "axios";
import dotenv from "dotenv";
import pkg from "pg";
import csv from "csv-parser";
import { upload } from "./middleware/upload.js";

dotenv.config();
const { Pool } = pkg;

// ─────────────────────────────────────────
// POSTGRES
// ─────────────────────────────────────────
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

// Ensure pending_payments table exists (idempotent)
pool.query(`
  CREATE TABLE IF NOT EXISTS pending_payments (
    externalref   TEXT PRIMARY KEY,
    phone         TEXT NOT NULL,
    name          TEXT,
    type          TEXT NOT NULL,
    quantity      INTEGER NOT NULL,
    created_at    TIMESTAMPTZ DEFAULT NOW()
  )
`).catch(err => console.error("⚠️ pending_payments table init failed:", err.message));

// ─────────────────────────────────────────
// EXPRESS
// ─────────────────────────────────────────
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
  res.header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With");
  if (req.method === "OPTIONS") return res.sendStatus(200);
  next();
});

app.use(express.json({ limit: "2mb" }));

// ─────────────────────────────────────────
// MOOLRE CONFIG
// ─────────────────────────────────────────
const MOOLRE_API             = "https://api.moolre.com";
const MOOLRE_USER            = process.env.MOOLRE_USER;
const MOOLRE_PUB_KEY         = process.env.MOOLRE_PUB_KEY;
const MOOLRE_ACCOUNT_NUMBER  = process.env.MOOLRE_ACCOUNT_NUMBER;
const MOOLRE_WEBHOOK_SECRET  = process.env.MOOLRE_WEBHOOK_SECRET;

const moolreHeaders = {
  "X-API-USER":    MOOLRE_USER,
  "X-API-PUBKEY":  MOOLRE_PUB_KEY,
  "Content-Type":  "application/json",
};

// Moolre channel codes (doc: 13=MTN, 6=Telecel, 7=AT)
const NETWORK_CHANNELS = { MTN: "13", Telecel: "6", AT: "7" };

// ─────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────
function buildExternalRef(type, qty) {
  return `WCO_${type}_${qty}_${Date.now()}`;
}

function parseExternalRef(ref) {
  // format: WCO_{TYPE}_{QTY}_{timestamp}
  const parts = (ref || "").split("_");
  if (parts.length >= 4 && parts[0] === "WCO") {
    return { type: parts[1], qty: Number(parts[2]) };
  }
  return { type: "WASSCE", qty: 1 };
}

// Normalise any Ghanaian phone format → 0XXXXXXXXX
function normalisePhone(phone) {
  if (!phone) return "";
  const p = String(phone).replace(/[\s\-().]/g, ""); // strip spaces, dashes, parens, dots
  if (p.startsWith("+233")) return "0" + p.slice(4);
  if (p.startsWith("233"))  return "0" + p.slice(3);
  return p;
}

// Moolre requires 233XXXXXXXXX (12 digits total)
function toMoolrePhone(phone) {
  const p = normalisePhone(phone);
  return p.startsWith("0") ? "233" + p.slice(1) : p;
}

// Validate a normalised local phone (0XXXXXXXXX = 10 digits, starting with 0)
function isValidGhanaPhone(phone) {
  const p = normalisePhone(phone);
  return /^0[235]\d{8}$/.test(p); // MTN:024/054/055/059, Telecel:020/050, AT:027/057/026
}

async function sendSMS(phone, text) {
  try {
    await axios.post(
      "https://sms.arkesel.com/api/v2/sms/send",
      {
        sender: "RESONLINE",
        message: text,
        type: "sms",
        recipients: [toMoolrePhone(phone)],
      },
      { headers: { "api-key": process.env.ARKESEL_API_KEY, "Content-Type": "application/json" } }
    );
  } catch (err) {
    console.error("❌ SMS error:", err.response?.data || err.message);
  }
}

// ─────────────────────────────────────────
// CORE: DELIVER VOUCHERS (transactional)
// ─────────────────────────────────────────
async function deliverVouchers({ externalref, phone, name, type, quantity }) {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    // Lock rows to prevent concurrent double-delivery
    const vRes = await client.query(
      `SELECT id, serial, pin FROM vouchers
       WHERE used = false AND type = $1
       ORDER BY id ASC LIMIT $2 FOR UPDATE SKIP LOCKED`,
      [type.toUpperCase(), quantity]
    );

    if (vRes.rows.length < quantity) {
      await client.query("ROLLBACK");
      console.error(`❌ Insufficient vouchers for ${externalref}: need ${quantity}, have ${vRes.rows.length}`);
      return false;
    }

    for (const v of vRes.rows) {
      await client.query("UPDATE vouchers SET used = true WHERE id = $1", [v.id]);
      await client.query(
        `INSERT INTO sales (name, phone, email, voucher_serial, voucher_pin, reference, type, date)
         VALUES ($1,$2,$3,$4,$5,$6,$7,NOW())`,
        [name || phone, phone, phone + "@moolre.com", v.serial, v.pin, externalref, type.toUpperCase()]
      );
      const smsText = `${type.toUpperCase()} Voucher\nSERIAL: ${v.serial}\nPIN: ${v.pin}\nThank you - WaecGhCardsOnline.com`;
      sendSMS(phone, smsText); // fire-and-forget
    }

    // Clean up pending record
    await client.query("DELETE FROM pending_payments WHERE externalref = $1", [externalref]);

    await client.query("COMMIT");
    console.log(`🎉 Delivered ${vRes.rows.length}x ${type} for ${externalref}`);
    return true;
  } catch (err) {
    await client.query("ROLLBACK");
    console.error("❌ deliverVouchers error:", err.message);
    return false;
  } finally {
    client.release();
  }
}

// ─────────────────────────────────────────
// WEBHOOK   POST /webhook
// Moolre posts here on every payment event.
// Docs: https://docs.moolre.com/#payment-webhook
// ─────────────────────────────────────────
app.post("/webhook", async (req, res) => {
  try {
    const body = req.body;
    console.log("\n🔥 MOOLRE WEBHOOK:", JSON.stringify(body));

    const data = body.data || {};

    // Log the webhook secret so you can capture it and set MOOLRE_WEBHOOK_SECRET in your env
    if (data.secret) {
      console.log(`🔑 Moolre webhook secret received: ${data.secret}`);
      if (!MOOLRE_WEBHOOK_SECRET) {
        console.log("💡 Tip: set MOOLRE_WEBHOOK_SECRET=" + data.secret + " in your env to enable webhook verification");
      }
    }

    // Verify the webhook secret only if MOOLRE_WEBHOOK_SECRET is set in env
    if (MOOLRE_WEBHOOK_SECRET && data.secret !== MOOLRE_WEBHOOK_SECRET) {
      console.warn("❌ Invalid Moolre webhook secret — ignoring");
      return res.sendStatus(401);
    }

    // txstatus: 1=Successful, 0=Pending, 2=Failed
    if (Number(data.txstatus) !== 1) {
      console.log(`⚠️ Webhook txstatus=${data.txstatus} — not successful, skipping`);
      return res.sendStatus(200);
    }

    const externalref = data.externalref || "";
    if (!externalref) {
      console.warn("⚠️ Webhook missing externalref");
      return res.sendStatus(200);
    }

    // Idempotency: skip if already delivered
    const already = await pool.query(
      "SELECT 1 FROM sales WHERE reference = $1 LIMIT 1",
      [externalref]
    );
    if (already.rows.length > 0) {
      console.log(`⚠️ Already delivered for ${externalref}`);
      return res.sendStatus(200);
    }

    // Prefer saved pending record; fall back to parsing externalref + webhook payer
    const pending = await pool.query(
      "SELECT phone, name, type, quantity FROM pending_payments WHERE externalref = $1",
      [externalref]
    );

    let phone, name, type, quantity;
    if (pending.rows.length > 0) {
      ({ phone, name, type, quantity } = pending.rows[0]);
    } else {
      // Fallback: webhook carries payer (doc field: payer)
      phone    = normalisePhone(data.payer || "");
      name     = phone;
      const parsed = parseExternalRef(externalref);
      type     = parsed.type;
      quantity = parsed.qty;
    }

    await deliverVouchers({ externalref, phone, name, type, quantity });
    return res.sendStatus(200);
  } catch (err) {
    console.error("❌ Webhook crash:", err.message);
    return res.sendStatus(500);
  }
});

// ─────────────────────────────────────────
// INITIATE PAYMENT   POST /initiate-payment
// Calls: POST https://api.moolre.com/open/transact/payment
// Docs: https://docs.moolre.com/#initiate-payment
// ─────────────────────────────────────────
app.post("/initiate-payment", async (req, res) => {
  try {
    const { phone, name, type, quantity, network, otpcode } = req.body;

    if (!phone || !type || !quantity) {
      return res.status(400).json({ success: false, error: "Missing required fields: phone, type, quantity" });
    }
    if (Number(quantity) > 30) {
      return res.status(400).json({ success: false, error: "Maximum 30 vouchers per purchase" });
    }

    const channel     = NETWORK_CHANNELS[network] || NETWORK_CHANNELS.MTN;
    const amount      = 30 * Number(quantity); // GHS 30 per voucher
    const externalref = buildExternalRef(type, quantity);

    if (!isValidGhanaPhone(phone)) {
      console.warn(`❌ Invalid phone rejected before Moolre: raw="${phone}" normalised="${normalisePhone(phone)}"`);
      return res.status(400).json({ success: false, error: "Invalid phone number. Please enter a valid 10-digit Ghanaian number starting with 0 (e.g. 0244123456)." });
    }

    const payerPhone = toMoolrePhone(phone);
    console.log(`📞 Phone: raw="${phone}" → normalised="${normalisePhone(phone)}" → Moolre="${payerPhone}"`);

    // Save to pending_payments so webhook/verify can recover phone+name without
    // relying on Moolre returning payer in the status response (not always present)
    await pool.query(
      `INSERT INTO pending_payments (externalref, phone, name, type, quantity)
       VALUES ($1,$2,$3,$4,$5)
       ON CONFLICT (externalref) DO NOTHING`,
      [externalref, normalisePhone(phone), name || phone, type.toUpperCase(), Number(quantity)]
    );

    const payload = {
      type:          1,
      channel,
      currency:      "GHS",
      payer:         payerPhone,
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

    // Per updated docs, successful response:
    // { "status": 1, "code": "TR099", "data": "uuid-123" }  ← data is a string
    const result = moolreRes.data;
    console.log("📦 Moolre initiate response:", JSON.stringify(result));

    // TP14 → OTP required: ask frontend to collect OTP and re-submit
    if (result.code === "TP14") {
      return res.json({ success: true, status: "otp_required", externalref, message: result.message });
    }

    // TP15 → OTP verified: frontend must re-submit without OTP to trigger USSD prompt
    if (result.code === "TP15") {
      return res.json({ success: true, status: "otp_verified", externalref, message: result.message });
    }

    // TR099 → USSD prompt sent to customer's phone
    if (result.code === "TR099") {
      return res.json({
        success: true,
        status:  "pending",
        externalref,
        message: "Payment prompt sent to your phone. Approve with your Mobile Money PIN.",
      });
    }

    // Any other response is treated as failure
    return res.json({
      success: false,
      status:  "failed",
      message: result.message || "Payment initiation failed. Please try again.",
    });

  } catch (err) {
    console.error("❌ /initiate-payment error:", err.response?.data || err.message);
    return res.status(500).json({ success: false, error: "Server error initiating payment" });
  }
});

// ─────────────────────────────────────────
// VERIFY / POLL   POST|GET /verify-payment
// Calls: POST https://api.moolre.com/open/transact/status
// Docs: https://docs.moolre.com/#payment-status
// ─────────────────────────────────────────
async function handleVerifyPayment(req, res) {
  try {
    const externalref = req.body?.reference || req.query?.reference;
    if (!externalref) {
      return res.status(400).json({ error: "Missing reference" });
    }

    // 1. Check our own DB first (webhook may have already delivered)
    const sales = await pool.query(
      `SELECT voucher_serial AS serial, voucher_pin AS pin, type, date
       FROM sales WHERE reference = $1 ORDER BY date ASC`,
      [externalref]
    );
    if (sales.rows.length > 0) {
      return res.json({ success: true, vouchers: sales.rows });
    }

    // 2. Not yet delivered — ask Moolre for current status
    // Note: per updated docs, the status response data may not include payer,
    // so we rely on pending_payments table for phone/name.
    let moolreTxStatus = null;
    try {
      const statusRes = await axios.post(
        `${MOOLRE_API}/open/transact/status`,
        {
          type:          1,
          idtype:        1,       // 1 = unique externalref
          id:            externalref,
          accountnumber: MOOLRE_ACCOUNT_NUMBER,
        },
        { headers: moolreHeaders }
      );

      const sData = statusRes.data?.data || {};
      moolreTxStatus = Number(sData.txstatus);
      console.log("📊 Moolre status response:", JSON.stringify(statusRes.data));

      // txstatus 2 = Failed
      if (moolreTxStatus === 2) {
        return res.status(400).json({ success: false, error: "Payment failed or was rejected." });
      }

      // txstatus 1 = Successful but vouchers not yet in our DB (webhook missed / race)
      if (moolreTxStatus === 1) {
        // Look up saved pending record first
        const pending = await pool.query(
          "SELECT phone, name, type, quantity FROM pending_payments WHERE externalref = $1",
          [externalref]
        );

        let phone, name, type, quantity;
        if (pending.rows.length > 0) {
          ({ phone, name, type, quantity } = pending.rows[0]);
        } else {
          // Last resort: parse externalref; payer may be absent in new status response
          const parsed = parseExternalRef(externalref);
          phone    = normalisePhone(sData.payer || "");
          name     = phone;
          type     = parsed.type;
          quantity = parsed.qty;
        }

        // Guard against duplicate delivery
        const alreadyDone = await pool.query(
          "SELECT 1 FROM sales WHERE reference = $1 LIMIT 1",
          [externalref]
        );
        if (alreadyDone.rows.length === 0) {
          await deliverVouchers({ externalref, phone, name, type, quantity });
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
      console.warn("⚠️ Moolre status check error:", statusErr.response?.data || statusErr.message);
    }

    // 3. Still pending — tell frontend to keep polling
    return res.status(202).json({
      success: true,
      vouchers: [],
      message: "Payment pending. Please wait and try again.",
    });

  } catch (err) {
    console.error("❌ /verify-payment error:", err.message);
    return res.status(500).json({ error: "Server error" });
  }
}

app.post("/verify-payment", handleVerifyPayment);
app.get("/verify-payment",  handleVerifyPayment);

// ─────────────────────────────────────────
// RETRIEVE VOUCHERS   GET /retrieve-vouchers
// ─────────────────────────────────────────
app.get("/retrieve-vouchers", async (req, res) => {
  try {
    const { phone, email } = req.query;
    if (!phone && !email) {
      return res.status(400).json({ success: false, message: "Provide phone or email" });
    }
    const param = phone || email;
    const field = phone ? "phone" : "email";
    const q = await pool.query(
      `SELECT voucher_serial AS serial, voucher_pin AS pin, type, date
       FROM sales WHERE ${field} = $1 ORDER BY date DESC`,
      [param]
    );
    res.json({ success: true, vouchers: q.rows });
  } catch (err) {
    console.error("❌ /retrieve-vouchers:", err.message);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// ─────────────────────────────────────────
// ADMIN ROUTES
// ─────────────────────────────────────────
app.post("/admin/login", (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ success: false, message: "Missing credentials" });
  }
  if (username === process.env.ADMIN_USERNAME && password === process.env.ADMIN_PASSWORD) {
    return res.json({ success: true });
  }
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
    const q = await pool.query(
      `SELECT id, serial, pin, type, used FROM vouchers ORDER BY id ASC`
    );
    res.json({ success: true, data: q.rows });
  } catch (err) {
    res.status(500).json({ success: false, message: "Server error" });
  }
});

app.post("/admin/upload", async (req, res) => {
  try {
    const vouchers = req.body?.vouchers;
    if (!Array.isArray(vouchers)) {
      return res.status(400).json({ success: false, message: "Invalid vouchers format" });
    }
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
    const result = await pool.query(
      "UPDATE vouchers SET used = true, used_at = NOW() WHERE id = $1",
      [req.params.id]
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
    const { Readable } = await import("stream");
    await new Promise((resolve, reject) => {
      Readable.from(req.file.buffer.toString())
        .pipe(csv())
        .on("data", row => rows.push(row))
        .on("end",  resolve)
        .on("error", reject);
    });
    if (rows.length === 0) return res.status(400).json({ error: "CSV is empty" });

    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      let inserted = 0;
      for (const r of rows) {
        const serial = r.Serial || r.serial || r.SERIAL;
        const pin    = r.PIN    || r.pin    || r.Pin;
        const type   = batchType || r.Type || r.type || r.TYPE || "BECE";
        if (serial && pin) {
          await client.query(
            `INSERT INTO vouchers (serial, pin, type, used)
             VALUES ($1,$2,$3,false) ON CONFLICT (serial) DO NOTHING`,
            [serial.trim(), pin.trim(), type.trim().toUpperCase()]
          );
          inserted++;
        }
      }
      await client.query("COMMIT");
      res.json({ message: "Upload complete", inserted });
    } catch (err) {
      await client.query("ROLLBACK");
      throw err;
    } finally {
      client.release();
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error processing CSV" });
  }
});

// ─────────────────────────────────────────
// START
// ─────────────────────────────────────────
app.listen(process.env.PORT || 3000, () =>
  console.log("✅ Backend live on port", process.env.PORT || 3000)
);
