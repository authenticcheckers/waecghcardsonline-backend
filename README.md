# waecghcardsonline (monorepo)

This repo contains a ready-to-deploy backend + frontend for selling WASSCE checker vouchers.
- Backend: Node.js + Express + SQLite (admin + webhook + SMS)
- Admin UI: static HTML (Tailwind) under `/admin`
- Frontend: static site (premium navy+gold theme)
- SMS: Arkesel (auto-detect POST JSON or GET fallback)
- Payments: Paystack (webhook)

## Quick start (local)
1. `cd` into project folder
2. `npm install`
3. Create a `.env` file (see `.env.example`)
4. Run migrations: `node db.js`
5. Start server: `npm start`
6. Open `http://localhost:3000` and admin at `/admin/login.html`

## Notes
- Replace Paystack public key in `frontend/index.html`
- The backend expects Paystack webhook POST to `/pay/webhook`
- Admin credentials via env vars. Provide `ADMIN_PASSWORD` (first run will print hash)
