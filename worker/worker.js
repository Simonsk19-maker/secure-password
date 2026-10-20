/* Cloudflare Worker — one-time secret store for the password tool.
 *
 * It only ever stores an ENCRYPTED blob. The decryption key is in the link's
 * # fragment and never reaches this Worker, so a breach of the store cannot
 * reveal any password.
 *
 * POST /           body = encrypted blob (<= 20 KB)         -> { "id": "..." }
 * GET  /?id=<id>   reads the blob ONCE, then deletes it     -> { "blob": "..." } or 404 { "gone": true }
 *
 * Needs a KV namespace bound as SECRETS (see wrangler.toml).
 */
const TTL_SECONDS = 7 * 24 * 60 * 60;   // unopened secrets auto-expire after 7 days
const MAX_BYTES = 20000;

function cors(origin) {
  return {
    'Access-Control-Allow-Origin': origin || '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Cache-Control': 'no-store'
  };
}
function json(obj, status, headers) {
  return new Response(JSON.stringify(obj), { status: status || 200, headers: { 'Content-Type': 'application/json', ...headers } });
}

export default {
  async fetch(request, env) {
    const origin = request.headers.get('Origin') || '*';
    const h = cors(origin);
    if (request.method === 'OPTIONS') return new Response(null, { headers: h });

    try {
      if (request.method === 'POST') {
        const blob = await request.text();
        if (!blob || blob.length === 0) return json({ error: 'empty' }, 400, h);
        if (blob.length > MAX_BYTES) return json({ error: 'too big' }, 413, h);
        const id = crypto.randomUUID().replace(/-/g, '');
        await env.SECRETS.put(id, blob, { expirationTtl: TTL_SECONDS });
        return json({ id }, 200, h);
      }

      if (request.method === 'GET') {
        const id = new URL(request.url).searchParams.get('id');
        if (!id || !/^[a-f0-9]{16,64}$/.test(id)) return json({ error: 'bad id' }, 400, h);
        const blob = await env.SECRETS.get(id);
        if (blob === null) return json({ gone: true }, 404, h);
        await env.SECRETS.delete(id);     // one-time: destroy after the first read
        return json({ blob }, 200, h);
      }

      return json({ error: 'method not allowed' }, 405, h);
    } catch (e) {
      return json({ error: 'server error' }, 500, h);
    }
  }
};
