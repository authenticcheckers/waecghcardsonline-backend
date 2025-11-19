-- vouchers table: id, serial, pin, status, date_used, buyer
CREATE TABLE IF NOT EXISTS vouchers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  serial TEXT NOT NULL UNIQUE,
  pin TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'unused',
  date_used TEXT,
  buyer TEXT
);

-- sales table: id, phone, email, voucher_serial, amount, timestamp, paystack_ref
CREATE TABLE IF NOT EXISTS sales (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  phone TEXT,
  email TEXT,
  voucher_serial TEXT,
  amount REAL,
  timestamp TEXT,
  paystack_ref TEXT
);
