# Personal CA — secure Python backend

This build replaces the old `server.js` backend with `server.py` (FastAPI). A `.js` file cannot be Python, so the correct conversion is a Python backend rather than putting Python inside `server.js`.

## Security changes
- `.env` is ignored by Git and is **not included** in this ZIP.
- Production refuses to start without `SESSION_SECRET` and `DATA_ENCRYPTION_KEY`.
- Google ID tokens are verified server-side.
- Gemini secrets stay server-side. This is the free edition; no payment gateway is included.
- Server-side random sessions are stored as SHA-256 hashes in SQLite; the browser receives only an HttpOnly, SameSite cookie.
- User name/email/picture are encrypted at rest with Fernet when `DATA_ENCRYPTION_KEY` is configured.
- OTPs are stored only as SHA-256 hashes, expire after 10 minutes, and have attempt/rate limits.
- Same-origin checks block cross-site state-changing API requests.
- Security headers include CSP, HSTS in production, X-Content-Type-Options, X-Frame-Options, Referrer-Policy and Permissions-Policy.
- AI requests are rate-limited and Gemini requests are made server-side with the Gemini API key kept out of the browser.
- Database files are ignored by Git.
- API docs are disabled in production.

## Run
1. Install Python 3.11+.
2. Create a virtual environment.
3. `pip install -r requirements.txt`
4. Copy `.env.example` to `.env` and fill real values.
5. Start: `python server.py`
6. Open `http://127.0.0.1:3000/`

For public deployment, use HTTPS behind a trusted reverse proxy and set `NODE_ENV=production`.

## Stocks AI
- The three-dots menu now includes **Stocks AI**.
- Stocks AI is educational only: it explains stock-market concepts, company-analysis metrics, hypothetical comparisons, risk and order types. It does **not** recommend specific stocks or execute real-money trades.
- The feature is deliberately conservative for younger users and should not be used as a personalised investment adviser.

## Important
Security is not absolute. Before accepting real customers, add a managed database/session store, backups, monitoring, dependency scanning, a proper privacy policy/terms/refund policy, secret rotation, and a reviewed payment webhook implementation. Never paste real API keys, SMTP passwords, Google secrets, into chat or frontend files.


## Android / Termux
This build is Android/Termux-friendly and does not require the Google GenAI Python SDK. The AI endpoints call the Gemini REST API over HTTPS using Python standard-library HTTP, keeping the Gemini key server-side and avoiding an extra SDK dependency. FastAPI/Pydantic versions are pinned for Termux compatibility.

## AI access flow
- Nivara AI and Stocks AI are access-gated.
- Clicking either AI first requires Google Sign-In; Google verifies the account, so this build does not send email or SMS OTPs.
- After verification, the customer sees a 3-day free-trial gate and must explicitly click the trial button.
- The selected AI opens only after the server starts the trial.
- The Python backend also enforces an active trial for both AI endpoints, so bypassing the browser UI does not unlock the AI.
- The employee 80CCD calculator is shown only inside the post-analysis Review screen, not on the sign-in/upload screen.


## Nivara AI tax intelligence
Nivara AI is instructed to perform a structured opportunity scan when financial/tax information is analyzed: income sources, salary components, deductions, NPS, HRA/rent, insurance, loans, investments, capital gains, TDS/TCS, compliance gaps, missing evidence, and applicable legal tax-saving routes. It must show assumptions and avoid inventing schemes or promising savings.

## Stocks AI live research
Optional live market data is configured with `TWELVE_DATA_API_KEY` on the server. Never place this key in frontend code. The market connector supplies current quote data and daily history to the research layer. Stocks AI remains educational and does not make personalized buy/sell/hold decisions or execute trades.


## Sign-in methods
The final build uses Google Sign-In only. Email OTP, SMS OTP, SMTP, and Twilio are not required by this build.

## AI separation
Nivara AI is the tax/CA assistant. Stocks AI is a separate market-research and learning assistant. The stock module is not used by Nivara AI.

## Security
No website can honestly be guaranteed to be impossible to hack. This build uses server-side secrets, encrypted sensitive user fields, hashed session tokens, HttpOnly/SameSite cookies, rate limits, OTP expiry/attempt limits, same-origin checks, security headers and production secret checks. Keep the server, dependencies and hosting patched and use HTTPS.


## Personal profile gate
