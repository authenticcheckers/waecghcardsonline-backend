# waecghcardsonline Backend (Regenerated)

This backend provides:
- Admin panel (static files under /admin)
- Voucher storage (SQLite)
- Admin APIs: add, bulk upload, list, mark-used, delete, resend SMS
- Paystack verification endpoint (/verify-payment) and webhook (/pay/webhook)
- SMS sending via Arkesel with POST JSON and GET fallback
- Sales logging to SQLite

## Quick start (local)

1. Install dependencies:
   ```bash
   npm install
   ```
2. Create `.env` file (see `.env.example` below)
3. Run migrations:
   ```bash
   npm run migrate
   ```
4. Start server:
   ```bash
   npm start
   ```
5. Visit admin login: http://localhost:3000/admin/login.html
   Default admin username from env: ADMIN_USERNAME (default: admin). Provide ADMIN_PASSWORD or ADMIN_PASSWORD_HASH in env.

## Notes
- Do NOT commit secrets to GitHub. Use Render/GitHub Actions env vars.
- After first run, if you provided ADMIN_PASSWORD (raw), the server prints a generated ADMIN_PASSWORD_HASH — copy that into env and remove raw password.

