# Pruvate Platform — Backend API (FastAPI)

Production-ready authentication, licensing, and client loader backend built on FastAPI, Firebase (Firestore & Realtime Database), Argon2id + pepper, and Ed25519/X25519 cryptography.

## 🚀 Vercel Deployment

This repository is pre-configured for seamless serverless deployment on Vercel via `vercel.json` and `api/index.py`.

### 1. Import to Vercel
1. Go to [Vercel Dashboard](https://vercel.com/new).
2. Import this repository (`eshankhanmaim-rgb/backend`).
3. Leave Framework Preset as **Other** (Vercel automatically detects Python serverless functions via `requirements.txt` and `vercel.json`).

### 2. Configure Environment Variables in Vercel
In your Vercel Project Settings > **Environment Variables**, add the following (see `.env.example` for details):

| Variable | Description |
|---|---|
| `APP_ENV` | `production` |
| `ALLOWED_ORIGINS` | Comma-separated list of web origins (e.g., `https://your-frontend.vercel.app`) |
| `FIREBASE_PROJECT_ID` | Your Firebase Project ID |
| `FIREBASE_DATABASE_URL` | Firebase Realtime Database URL (if using RTDB) |
| `FIREBASE_SERVICE_ACCOUNT_JSON` | Single-line JSON string of your Firebase service account key |
| `JWT_SECRET` | 64 random bytes, base64 encoded |
| `ARGON2_PEPPER` | 32 random bytes, hex encoded |
| `ED25519_PRIVATE_KEY_B64` | Ed25519 private key for signing loader responses |
| `ED25519_PUBLIC_KEY_B64` | Ed25519 public key |
| `LICENSE_KEY_ENCRYPTION_KEY` | 32 random bytes hex for AES-256-GCM license encryption |
| `LICENSE_KEY_HMAC_KEY` | 32 random bytes hex for license lookup HMAC |

### 3. Deploy
Click **Deploy**. Once built, your API will be live at:
- Root: `https://<your-project>.vercel.app/`
- Interactive API Docs: `https://<your-project>.vercel.app/docs` (when `APP_ENV=development`)
- Health Check: `https://<your-project>.vercel.app/health`
- Auth Endpoints: `https://<your-project>.vercel.app/api/v1/auth/*`
- Loader Endpoints: `https://<your-project>.vercel.app/api/v1/loader/*`

---

## 💻 Local Execution

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run local development server
python main.py
# Server will run on http://127.0.0.1:11731
```
