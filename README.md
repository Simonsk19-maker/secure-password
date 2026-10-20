# Password Generator &amp; Secure Share

A free, self-hosted **password generator** that also lets you send a password as a
**one-time, self-destructing link**. Everything happens in the browser — the
generator sends nothing, and shared secrets are **encrypted before they leave your
device**.

👉 **Live site** (once GitHub Pages is on): `https://simonsk19-maker.github.io/secure-password/`

## Two things it does

**1. Make a strong password**
- Random characters (length, capitals, numbers, symbols) — avoids look-alike
  characters like `l`/`1`/`O`/`0`.
- Or memorable "three random words" style passphrases.
- A strength meter shows the real randomness (entropy) in bits.
- One-click copy. Uses the browser's secure randomness (Web Crypto).

**2. Send it securely (one-time link)**
- Creates a link that reveals the secret **once**, then destroys it forever
  (and auto-expires in 7 days if never opened).
- The secret is **encrypted in your browser** (AES-GCM). Only the encrypted blob
  is stored; the key lives in the link, so the server can never read it.
- Optional **PIN**: the recipient also needs a PIN you tell them a different way
  (text/call), so the link alone isn't enough.

## How it works (plain version)
```
  You:  type/generate a secret ──▶ browser encrypts it ──▶ server stores the
                                       (key stays here)        ENCRYPTED blob, gives a short id
        link = open.html#<id>.<key>[.p]   ◀── you send this link

  Them: open link ──▶ browser fetches the blob (server DELETES it) ──▶ browser
                                                                        decrypts with the key in the link ──▶ shows once
```
Because the key is in the part of the link after `#`, it is **never sent to the
server** — browsers don't transmit the `#` fragment. So even the person running
the server cannot read any password.

## Setup
1. **Password generator** works immediately — just open `index.html` (or the live
   site). No server needed.
2. **One-time links** need a tiny free server (a Cloudflare Worker). Follow
   [`worker/README.md`](worker/README.md), then put its address in
   [`config.js`](config.js). Until then, the generator still works and the link
   button explains that the server isn't set up.

### Turn on the website (GitHub Pages)
Settings → Pages → Deploy from a branch → **main**, folder **/ (root)** → Save.

## Security notes
- Secrets are end-to-end encrypted (AES-GCM 256). The server is zero-knowledge.
- One-time by design: the blob is deleted the moment the open page loads it, so a
  link can't be reused even if someone closes the page before revealing.
- Send the **link** and any **PIN** by different routes for best safety.
- This is a convenience tool, not a secrets manager — for long-term storage use a
  proper password manager.

## Licence
See [LICENSE](LICENSE). Free to view and run; not for reuse in other products.
