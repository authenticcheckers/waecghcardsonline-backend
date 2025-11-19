-- Vouchers table: stores serial and pin, status and buyer info
CREATE TABLE IF NOT EXISTS vouchers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  serial TEXT NOT NULL UNIQUE,
  pin TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'unused', -- unused | used
  date_used TEXT,
  buyer TEXT
);

-- Sales table: records each sale and reference
CREATE TABLE IF NOT EXISTS sales (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  phone TEXT,
  email TEXT,
  voucher_serial TEXT,
  amount REAL,
  timestamp TEXT,
  paystack_ref TEXT
);

-- Admin table: simple admin user storage (username + password hash)
CREATE TABLE IF NOT EXISTS admin (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL
);
