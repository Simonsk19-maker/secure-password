# The one-time-secret server (Cloudflare Worker)

This tiny free server stores the **encrypted** secret and deletes it after one
read. It never sees the real password (the key stays in the link). You deploy it
once, then paste its address into the site's `config.js`.

You need a free **Cloudflare** account.

## Option A — the dashboard (no tools, ~5 minutes)
1. Sign in at **dash.cloudflare.com**.
2. **Storage & Databases → KV → Create namespace**. Name it `SECRETS`.
3. **Workers & Pages → Create → Create Worker**. Give it a name like
   `secret-store`, then **Deploy** (the placeholder code is fine for now).
4. Open the worker → **Edit code**. Delete what's there, paste in the contents of
   **`worker.js`** from this folder, then **Deploy**.
5. Worker → **Settings → Bindings → Add → KV namespace**. Variable name
   **`SECRETS`**, namespace **`SECRETS`**. Save.
6. Copy the worker's address (like `https://secret-store.YOURNAME.workers.dev`).
7. In the website, open **`config.js`** and set:
   `window.SP_WORKER_URL = "https://secret-store.YOURNAME.workers.dev";`
   Save and re-publish the site. The one-time link now works.

## Option B — command line (wrangler)
```bash
npm i -g wrangler
wrangler login
wrangler kv namespace create SECRETS      # copy the id it prints
# paste that id into wrangler.toml
wrangler deploy
```
Then set `SP_WORKER_URL` in `config.js` to the URL wrangler prints.

## What it does / doesn't
- Stores only the **encrypted blob**; the decrypt key is in the link's `#`
  fragment and never reaches Cloudflare.
- **GET deletes on read** — a secret opens once, then it's gone.
- Unopened secrets **auto-expire after 7 days** (KV TTL).
- Max 20 KB per secret. Free Cloudflare limits are plenty for this.

## Keeping it tidy
Nothing to maintain. If you ever want to wipe everything, delete the `SECRETS`
KV namespace in the dashboard.
