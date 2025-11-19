import sqlite3 from 'sqlite3';
import { open } from 'sqlite';
import fs from 'fs';
import path from 'path';
import dotenv from 'dotenv';
dotenv.config();

const DB_FILE = process.env.DB_FILE || './data.db';

async function migrate() {
  const db = await open({ filename: DB_FILE, driver: sqlite3.Database });
  const migrations = fs.readFileSync(path.join('./migrations.sql'), 'utf8');
  await db.exec(migrations);
  console.log('Migrations applied to', DB_FILE);
  await db.close();
}

migrate().catch(err => { console.error(err); process.exit(1); });
