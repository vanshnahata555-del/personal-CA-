# Personal CA — Free Gemini Edition

This build is the free edition of Personal CA.

- Google Sign-In only
- Nivara AI powered by Google Gemini
- Stocks AI powered by Google Gemini for educational research
- Tax computation, rules and updates
- Remote Desktop (RDP) launcher/configuration
- No subscription checkout or payment integration

## Server environment

Set these variables on your backend host:

- `GOOGLE_CLIENT_ID`
- `GEMINI_API_KEY`
- `GEMINI_MODEL` (default: `gemini-3.8-flash`)
- `SESSION_SECRET`
- `DATA_ENCRYPTION_KEY`
- `FRONTEND_ORIGIN` when frontend and backend use different origins

Keep all secrets on the server. Do not put the Gemini API key in browser JavaScript or commit a real `.env` file to GitHub.

Gemini API usage is subject to Google's current model availability, quota and rate limits.
