// Throwaway: nuxt's tarballs (bench/nuxt-urls.txt) downloaded by Node over HTTP/1.1 with N
// keep-alive sockets, one request each at a time, and over HTTP/2 with S streams in flight on C
// connections. Bytes only.
import fs from 'node:fs';
import https from 'node:https';
import http2 from 'node:http2';
const urls = fs.readFileSync(process.argv[2], 'utf8').split('\n').filter(Boolean);
const now = () => Number(process.hrtime.bigint() / 1000n) / 1000;
async function pool(n, work) {
  let i = 0;
  await Promise.all(Array.from({ length: n }, async () => { while (i < urls.length) await work(urls[i++]); }));
}
async function h1(conns) {
  const agent = new https.Agent({ keepAlive: true, maxSockets: conns });
  const heads = []; let bytes = 0; const t = now();
  await pool(conns, (u) => new Promise((ok, fail) => {
    const t0 = now();
    https.get(u, { agent }, (res) => { heads.push(now() - t0); res.on('data', (b) => bytes += b.length); res.on('end', ok); }).on('error', fail);
  }));
  agent.destroy();
  return { ms: now() - t, bytes, heads };
}
async function h2(conns, streams) {
  const sessions = Array.from({ length: conns }, () => { const s = http2.connect('https://registry.npmjs.org', { settings: { initialWindowSize: 8 << 20 } }); s.on('connect', () => s.setLocalWindowSize(64 << 20)); return s; });
  let k = 0; const heads = []; let bytes = 0; const t = now();
  await pool(streams, (u) => new Promise((ok, fail) => {
    const s = sessions[k++ % conns]; const t0 = now();
    const req = s.request({ ':path': new URL(u).pathname });
    req.on('response', () => heads.push(now() - t0));
    req.on('data', (b) => bytes += b.length); req.on('end', ok); req.on('error', fail); req.end();
  }));
  sessions.forEach((s) => s.close());
  return { ms: now() - t, bytes, heads };
}
function show(name, r) {
  const h = r.heads.sort((a, b) => a - b);
  console.log(`${name}: ${r.ms.toFixed(0)} ms, ${(r.bytes / 1e6).toFixed(1)} MB, head p50 ${h[h.length >> 1].toFixed(0)} p90 ${h[Math.floor(h.length * 0.9)].toFixed(0)} max ${h[h.length - 1].toFixed(0)}`);
}
for (let round = 0; round < 5; round++) {
  show('h1 32', await h1(32));
  show('h1 64', await h1(64));
  show('h2 1x32', await h2(1, 32));
  show('h2 1x64', await h2(1, 64));
  show('h2 1x128', await h2(1, 128));
  show('h2 2x128', await h2(2, 128));
  show('h2 4x558', await h2(4, 558));
}
