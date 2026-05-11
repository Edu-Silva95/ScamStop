**Very Important**
This website should not be the one to judge wether you should or should not click the link, it is made to give you information and for you to use this information to make a decision. I am not responsible if anything happens to you or your device if you clicked a link.
At the end of the day only you can protect yourself from these attacks.

Always treat unexpected messages and unfamiliar links with caution. Attackers often rely on urgency, impersonation, and convincing domains to trick users into clicking or entering sensitive information. Never follow links directly from messages when dealing with accounts, payments, or personal data—access services manually through their official websites or apps instead. If something feels off, verify it through a trusted channel before taking action. Staying cautious with links is one of the simplest and most effective ways to avoid scams and protect your data.

This is a personal project, not intended for public distribution.

**Use**

- **What it does:** Scan messages for scam links, brand impersonation, and known malicious URLs.
- **How to use:** Open the app in your browser, paste a message into the input, and click "Analyze". Results show a score, overall status, reasons, and per-link details including any threat-intel matches.

**How it works**

- The client sends the message text to the server's `/api/analyze` endpoint.
- The server extracts URLs, normalizes hostnames/domains, and applies heuristic checks for phishing patterns (lookalikes, brand injection, punycode, shorteners, suspicious paths/query parameters).
- A trust layer classifies unknown-only results as neutral (not automatically safe) and applies minimum score thresholds for lookalike/impersonation signals.
- Optional enrichments:
	- **Threat intelligence:** Local Postgres-backed feeds (URLHaus, PhishTank) are checked; matches mark the URL as malicious and raise the score.
	- **Network enrichment:** RDAP/domain age lookups can be enabled to add context for suspicious domains.
- Final analysis returns: `status`, `score`, `reasons`, per-URL `verdict`/`notes`, and `threatIntel` metadata (if enabled).

**Built with**

- **Client:** React + Vite (located at `client/ScamStop/`) for the interactive UI.
- **Server:** Node.js (ESM) + Express. Server code is under `server/src/`.
- **URL parsing & heuristics:** `tldts` for registrable domain extraction and custom normalization + heuristics modules.
- **Threat intel & DB:** Postgres accessed via `pg` for ingestion and lookups of URLHaus / PhishTank exports. Sync scripts live in `server/scripts/`.
- **Networking & fetches:** `axios` for feed downloads and optional RDAP lookups.
- **Scheduler:** `node-cron` for periodic threat-intel sync jobs.

**Run locally (quick)**

1. Install dependencies:

```bash
cd server && npm install
cd ../client/ScamStop && npm install
```
- (Optional, get the latest updates from URLhaus):

```bash
npm run threat-intel:sync
```

2. Start the server (from `server/`):

```bash
DATABASE_URL=postgres://... npm start
```

3. Start the client (from `client/ScamStop`):

```bash
npm run dev
```