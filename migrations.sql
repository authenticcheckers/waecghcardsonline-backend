-- migrations.sql — Postgres schema for waecghcardsonline
CREATE TABLE IF NOT EXISTS admin (
  id SERIAL PRIMARY KEY,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

CREATE TABLE IF NOT EXISTS vouchers (
  id SERIAL PRIMARY KEY,
  serial TEXT UNIQUE NOT NULL,
  pin TEXT,
  status TEXT NOT NULL DEFAULT 'unused',
  date_used TIMESTAMP WITH TIME ZONE,
  buyer TEXT,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

CREATE TABLE IF NOT EXISTS sales (
  id SERIAL PRIMARY KEY,
  phone TEXT,
  email TEXT,
  voucher_serial TEXT,
  amount NUMERIC(10,2),
  timestamp TIMESTAMP WITH TIME ZONE DEFAULT now(),
  paystack_ref TEXT
);

-- Index for fast search
CREATE INDEX IF NOT EXISTS idx_vouchers_serial ON vouchers (serial);
