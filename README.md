# ShipNovaShop — Vercel + Render

## Architecture
- Frontend: Vercel (`frontend/`)
- Backend API: Render (`backend/`)
- Database: Render PostgreSQL

## Render
1. Create a PostgreSQL database on Render.
2. Create a Web Service from this repository and set Root Directory to `backend`.
3. Build: `npm install`
4. Start: `npm start`
5. Add `DATABASE_URL` from your Render PostgreSQL database.
6. Add `JWT_SECRET` (Render can generate it).
7. Add `ADMIN_EMAIL` and a strong `ADMIN_PASSWORD`.

## Vercel
1. Import the repository.
2. Root Directory: `frontend`.
3. Framework Preset: Other.
4. Build Command: leave empty.
5. Output Directory: `.`.
6. Before deploy, edit `frontend/api-config.js` and replace `YOUR-RENDER-SERVICE.onrender.com` with the real Render API URL.
7. Also update `vercel.json` if you want Vercel `/api/*` proxying. Direct frontend API calls use `api-config.js`.

## Admin
The admin account is created automatically when the API first connects to PostgreSQL, using `ADMIN_EMAIL` and `ADMIN_PASSWORD`.

## Important
Do not commit `.env` or real passwords/secrets to GitHub.
