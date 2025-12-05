// server.js (patched webhook + small safety improvements)
// Keep the rest of your file as-is (I only modified the webhook area and a couple helpers)

import express from "express";
import cors from "cors";
import axios from "axios";
import dotenv from "dotenv";
import crypto from "crypto";
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
  ssl: { rejectUnauthorized: false }
});

// -----------------------------
// EXPRESS SETUP
// -----------------------------
const app = express();

const allowedOrigins = [
  "https://waeccardsonline.vercel.app",
  "http://localhost:5500",
  "http://localhost:3000",
  "https://waeccheckers.com"
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
// helper: sendSMS (unchanged, but kept below for context)
// -----------------------------
async function sendSMS(phone, text) {
  try {
    const res = await axios.post(
      "https://sms.arkesel.com/api/v2/sms/send",
      {
        sender: "RESONLINE",
        message: text,
        type: "sms",
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

// -----------------------------
// RAW BODY FOR PAYSTACK WEBHOOK (MUST be registered BEFORE express.json)
// -----------------------------
app.post(
  "/webhook",
  // keep raw so we can verify signature exactly
  express.raw({ type: "application/json" }),
  (req, res) => {
    // Immediately validate signature and return 200 to stop Paystack retries.
    // Do heavy work asynchronously so we respond quickly.
    try {
      const secret = process.env.PAYSTACK_SECRET_KEY || process.env.PAYSTACK_SECRET;
      const signature = req.headers["x-paystack-signature"];

      // Use Buffer for HMAC input to match Paystack's signing
      const payload = req.body; // this is a Buffer because of express.raw
      if (!payload || !signature || !secret) {
        console.log("❌ Webhook: missing payload/signature/secret");
        // Respond 400 so Paystack will not treat as success. If secret missing it's a deploy issue.
        return res.sendStatus(400);
      }

      const computedHash = crypto
        .createHmac("sha512", secret)
        .update(payload)
        .digest("hex");

      if (computedHash !== signature) {
        console.log("❌ Invalid webhook signature (blocked)");
        return res.sendStatus(401);
      }

      // parse event safely
      let event;
      try {
        event = JSON.parse(payload.toString("utf8"));
      } catch (e) {
        console.log("❌ Webhook: invalid JSON payload");
        return res.sendStatus(400);
      }

      console.log("\n🔥 PAYSTACK WEBHOOK (received):", event.event);
      console.log("WEBHOOK REF (received):", event?.data?.reference || "N/A");

      // Immediately send 200 to stop retries. Actual processing will happen asynchronously.
      res.sendStatus(200);

      // --- process asynchronously, do NOT await here ---
      (async () => {
        try {
          // only care about charge.success
          if (event.event !== "charge.success") {
            console.log("ℹ️ Ignored event:", event.event);
            return;
          }

          const ref = event.data?.reference;
          if (!ref) {
            console.log("❌ charge.success missing reference, abort");
            return;
          }

          // Basic metadata extraction and hygiene
          const metadata = event.data?.metadata || {};
          const purchaseType = (metadata.voucher_type || "WASSCE").toUpperCase();
          let quantity = Number(metadata.quantity || 1);
          if (!Number.isFinite(quantity) || quantity < 1) quantity = 1;

          // enforce sensible max to prevent abuse
          if (quantity > 30) {
            console.log(`❌ Blocked processing for ${ref}: quantity ${quantity} exceeds limit`);
            return;
          }

          const email = event.data?.customer?.email || "";
          const name = `${event.data?.customer?.first_name || ""} ${event.data?.customer?.last_name || ""}`.trim();
          const phone = event.data?.customer?.phone || metadata.phone || "";

          // Quick anti-abuse: phone must look like digits if present
          if (phone && !/^\+?\d{8,15}$/.test(phone) && !/^\d{8,15}$/.test(phone)) {
            console.log(`❌ Bad phone format for ${ref} (${phone}) — continuing but without SMS`);
          }

          // IDempotency: check if we've processed this reference before
          const exists = await pool.query(
            "SELECT 1 FROM sales WHERE reference = $1 LIMIT 1",
            [ref]
          );

          if (exists.rows.length > 0) {
            console.log("⚠️ Already delivered for reference", ref);
            return;
          }

          // Extra safety: verify transaction via Paystack API to ensure it's genuinely successful,
          // and to guard against test/live mismatches or other unexpected states.
          try {
            const PAYSTACK_SECRET = process.env.PAYSTACK_SECRET_KEY || process.env.PAYSTACK_SECRET;
            const verifyResp = await axios.get(
              `https://api.paystack.co/transaction/verify/${encodeURIComponent(ref)}`,
              { headers: { Authorization: `Bearer ${PAYSTACK_SECRET}` }, timeout: 8000 }
            );

            if (!verifyResp?.data?.status || verifyResp.data?.data?.status !== "success") {
              console.log(`❌ Paystack verify failed for ${ref} — status not success`, verifyResp?.data?.data?.status);
              return;
            }

            // Optional: you could validate amount/currency here against your metadata if desired.
          } catch (err) {
            console.log("❌ Paystack verify request failed for", ref, " — aborting processing for safety", err?.message || err);
            return;
          }

          // Acquire client and perform transactional voucher allocation
          const client = await pool.connect();
          try {
            await client.query("BEGIN");

            // select available vouchers and lock them for this transaction
            const vRes = await client.query(
              `SELECT id, serial, pin FROM vouchers
               WHERE used = false AND type = $1
               ORDER BY id ASC
               LIMIT $2
               FOR UPDATE`,
              [purchaseType, quantity]
            );

            if (vRes.rows.length < quantity) {
              await client.query("ROLLBACK");
              console.log(`❌ Insufficient vouchers for ${ref}: requested ${quantity}, available ${vRes.rows.length}`);
              // Optionally: create a 'failed_delivery' row or notify admin
              return;
            }

            // reserve & record
            for (const v of vRes.rows) {
              await client.query("UPDATE vouchers SET used = true WHERE id = $1", [v.id]);

              await client.query(
                `INSERT INTO sales (name, phone, email, voucher_serial, voucher_pin, reference, type, date)
                 VALUES ($1,$2,$3,$4,$5,$6,$7,NOW())`,
                [name, phone, email, v.serial, v.pin, ref, purchaseType]
              );

              // send SMS but don't let SMS failure break DB commit
              try {
                if (phone && /^\+?\d{8,15}$/.test(phone.replace(/^0/, "233")) || /^\d{8,15}$/.test(phone.replace(/^0/, "233"))) {
                  const smsText =
                    `${purchaseType} Voucher\n` +
                    `SERIAL: ${v.serial}\nPIN: ${v.pin}\nThank you for using WaecGhCardsOnline.com`;
                  // do not await if you want to push throughput; we await here to avoid unbounded concurrency
                  await sendSMS(phone, smsText);
                } else {
                  console.log(`ℹ️ Skipping SMS for ${ref} due to invalid phone: ${phone}`);
                }
              } catch (smsErr) {
                console.log("❌ SMS send error for", ref, smsErr?.message || smsErr);
              }
            }

            await client.query("COMMIT");
            console.log("🎉 Delivered", vRes.rows.map(x => x.serial).join(", "), purchaseType, `x${quantity}`, "for ref", ref);
          } catch (err) {
            await client.query("ROLLBACK");
            console.log("❌ Webhook DB transaction error for", ref, err?.message || err);
          } finally {
            client.release();
          }
        } catch (procErr) {
          console.log("❌ Error processing webhook async:", procErr?.message || procErr);
        }
      })();

    } catch (outerErr) {
      console.log("❌ Webhook top-level error:", outerErr?.message || outerErr);
      // If signature could not be validated, we returned earlier; if we reach here it's an unexpected error.
      try {
        // If response hasn't been sent yet (rare) send 500
        if (!res.headersSent) res.sendStatus(500);
      } catch (e) {}
    }
  }
);

// Now register JSON parser for the rest of routes
app.use(express.json({ limit: "2mb" }));

// -----------------------------
// VERIFY PAYMENT (FRONTEND CALL)  (unchanged logic, only minor hardening)
// -----------------------------
async function handleVerifyPayment(req, res) {
  try {
    const reference = req.body?.reference || req.query?.reference;
    if (!reference) return res.status(400).json({ error: "Missing reference" });

    const PAYSTACK_SECRET =
      process.env.PAYSTACK_SECRET_KEY || process.env.PAYSTACK_SECRET;

    const verify = await axios.get(
      `https://api.paystack.co/transaction/verify/${encodeURIComponent(reference)}`,
      { headers: { Authorization: `Bearer ${PAYSTACK_SECRET}` }, timeout: 8000 }
    );

    const result = verify.data;
    const metadata = result.data?.metadata || {};
    const quantity = Number(metadata.quantity || 1);

    if (quantity > 30) {
      return res.status(400).json({
        success: false,
        error: "Maximum 30 vouchers allowed per purchase"
      });
    }

    if (!result?.status || result.data?.status !== "success") {
      return res.status(400).json({ error: "Payment failed" });
    }

    const sales = await pool.query(
      `SELECT voucher_serial AS serial, voucher_pin AS pin, type, date
       FROM sales WHERE reference = $1 ORDER BY date ASC`,
      [reference]
    );

    if (sales.rows.length === 0) {
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

//
// The rest of your routes (retrieve-vouchers, admin, upload, etc.) remain unchanged.
// Make sure you keep them exactly as they were below in your file.
//

// -----------------------------
// SERVER START
// -----------------------------
app.listen(process.env.PORT || 3000, () =>
  console.log("Backend live on", process.env.PORT || 3000)
);
