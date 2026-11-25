# Ledgerly

A private personal finance tracker built with Rust and Actix Web. Users manually record bank balance snapshots, card purchases, recurring subscriptions, and savings goals. The app does not connect to financial institutions.

## Run locally

Create `.env` from `.env.example` and set `MONGODB_URI` to a MongoDB deployment you control. For a local MongoDB server, the URI is `mongodb://127.0.0.1:27017`; for hosting, use your provider's connection string and permitted network access settings. `MONGODB_DATABASE` is optional and defaults to `ledgerly`.

```powershell
cd ledgerly
$env:MONGODB_URI = "mongodb://127.0.0.1:27017"
$env:MONGODB_DATABASE = "ledgerly"
$env:ADMIN_EMAILS = "admin@example.com"
cargo run
```

Open <http://localhost:8080>. The app creates its MongoDB collections and unique indexes on startup. It also loads a local `.env` file when present. Keep MongoDB credentials out of source control and configure `COOKIE_SECURE=true` when serving over HTTPS. Put the app behind HTTPS before exposing it publicly.

## Deploy on Railway with Docker

Railway can build this repository from the included `Dockerfile`. In the service's **Variables**, set `MONGODB_URI` to your MongoDB connection string and optionally set `MONGODB_DATABASE`, `ADMIN_EMAILS`, and `COOKIE_SECURE=true`. Railway supplies `PORT`; the app binds to it automatically. Make sure your MongoDB provider allows connections from the Railway service. Do not add database credentials or API keys to the Dockerfile or commit a populated `.env` file.

Investment values are entered and updated manually. Update a holding's units, price, and cost basis from the Investments page; the app keeps the latest portfolio value for each date for its history chart. No market data provider or API key is required.

Set `ADMIN_EMAILS` to a comma-separated list of trusted administrator email addresses before starting the server. Register with one of those addresses to see **User admin** in the sidebar. The server checks this allowlist for every admin API request; hiding the navigation alone does not grant or protect admin access. Set `COOKIE_SECURE=true` when serving over HTTPS.

## Privacy design

Passwords are hashed with Argon2id. Each account receives a random 256-bit data key. A key derived from the password wraps that data key; the financial JSON payload is encrypted with AES-256-GCM before it is written to MongoDB. The database stores the email, password hash, wrapped key, and ciphertext. The unwrapped key and session tokens currently live in process memory, so sessions end on restart.

Users receive a high-entropy recovery code when they register, and older accounts are prompted to create one after signing in. A user with the code can reset their password without losing access to encrypted finance data; reset rotates the code. Users can rotate it again under **Security & recovery**. Email delivery and passkey recovery are not implemented. Before public launch, move sessions to a shared persistent store with expiry, apply login and recovery rate limits, use HTTPS-only cookies, and establish tested database backups. The current in-memory session store supports a single server process.

## Current scope

- Email registration and login
- Password recovery and recovery-code rotation that preserve each user's finance data key
- Encrypted per-user finance payloads
- Monthly manual account snapshots
- Card list and manually logged purchases
- Category search and spending summaries
- Subscription tracking and savings goals
- Manually valued investment holdings with price history, colored category allocation with a bar/pie toggle, and unrealized P/L
- Editable and removable purchase history with matching category colors
- Manually tracked cards with masked last-four display and name-derived colors
- Separate retirement accounts with user-entered balances, contributions, and adjustable growth projections
- Responsive dashboard with a six-month spending chart
- Net worth overview and monthly snapshots across accounts, investments, retirement, cards, and debts
- Month-to-date spending compared with the same days in the previous month
- Account, card, transaction, subscription, goal, and debt progress metrics

This is an early starter and not yet suitable for handling real financial information on a public deployment.

## Recent additions

- Optional dark theme follows the system preference on first visit and remembers a manual choice in the browser.
- Account snapshots are unique by account name and calendar month; saving the same account again for that month replaces its balance.
- Credit card balances start from the current balance you enter, rise when you log a purchase against that card, and fall when you record a payment. You can manually reconcile a balance with your latest statement.
- Loans and other debts have current balances, APR, expected monthly payments, and monthly balance snapshots. Card balances should be tracked in Cards or Debts, not both, to avoid double-counting.
- The admin page lists registered email addresses, last successful sign-in, and successful sign-ins in the previous 30 days. Login history begins when this version is deployed. Removing a user deletes their finance payload, login events, account, and active process-local sessions.

## Existing local data

This version uses MongoDB and does not automatically import the previous `ledgerly.db` SQLite file. Keep that file as a backup until you have decided whether to migrate any existing accounts and finance data.
