-- vouchers table
CREATE TABLE IF NOT EXISTS vouchers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  serial TEXT NOT NULL UNIQUE,
  pin TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'unused',
  date_used TEXT,
  buyer TEXT
);

-- sales table
CREATE TABLE IF NOT EXISTS sales (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  phone TEXT,
  email TEXT,
  voucher_serial TEXT,
  amount REAL,
  timestamp TEXT,
  paystack_ref TEXT
);

-- admin table
CREATE TABLE IF NOT EXISTS admin (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL
);
