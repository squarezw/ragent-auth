import http from 'node:http';
import net from 'node:net';
import { readFile, stat } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { readConfig } from '../src/config.js';

const root = fileURLToPath(new URL('../', import.meta.url));
const configFile = process.env.IDENTITY_LOCAL_CONFIG || new URL('../secrets/local/runtime.json', import.meta.url);
let env;
try {
  const info = await stat(configFile);
  if (info.mode & 0o077) throw new Error('Private configuration permissions required');
  const values = JSON.parse(await readFile(configFile, 'utf8'));
  if (Object.values(values).some(value => typeof value !== 'string')) throw new Error('String environment values required');
  env = { ...process.env, ...values };
  const config = readConfig(env);
  if (!config || env.NODE_ENV !== 'development' || config.bindHost !== '127.0.0.1' || config.port !== 8020 || config.issuer !== 'http://127.0.0.1:8021') throw new Error('Local development configuration required');
} catch {
  console.error('Local auth configuration unavailable or invalid; see README local development.');
  process.exit(1);
}

// Refuse to replace existing listeners, including a previous local launcher.
for (const port of [8020, 8021]) {
  const occupied = await new Promise((resolve, reject) => {
    const socket = net.connect({ host: '127.0.0.1', port });
    socket.once('connect', () => { socket.destroy(); resolve(true); });
    socket.once('error', error => error.code === 'ECONNREFUSED' ? resolve(false) : reject(error));
  });
  if (occupied) { console.error(`Local port ${port} already occupied; existing service unchanged.`); process.exit(1); }
}

const protocol = /^\/(?:\.well-known(?:\/|$)|auth(?:\/|$)|token(?:\/|$)|me(?:\/|$)|jwks(?:\/|$)|interaction(?:\/|$)|session(?:\/|$)|request(?:\/|$))/;
const loginUI = /^\/(?:identity-login\/?$|forgot-password\/?$|reset-password\/?$|_next\/|favicon\.ico$|api\/system\/?$|api\/oss\/system\/|api\/v1\/password\/(?:forgot|verify-token|reset)\/?$)/;
const proxy = http.createServer((req, res) => {
  const pathname = new URL(req.url, 'http://127.0.0.1:8021').pathname;
  const port = protocol.test(pathname) ? 8020 : loginUI.test(pathname) ? 3000 : null;
  if (!port) { res.writeHead(404); res.end(); return; }
  const upstream = http.request({ hostname: '127.0.0.1', port, path: req.url, method: req.method, headers: req.headers }, reply => {
    res.writeHead(reply.statusCode, reply.headers); reply.pipe(res);
  });
  upstream.setTimeout(15000, () => upstream.destroy());
  upstream.on('error', () => {
    if (!res.headersSent) res.writeHead(502, { 'Content-Type': 'text/plain' });
    res.end('Local identity dependency unavailable');
  });
  req.on('aborted', () => upstream.destroy());
  req.pipe(upstream);
});
const issuer = spawn(process.execPath, ['src/main.js'], { cwd: root, env, stdio: 'inherit' });
let stopping = false;
function stop(code) {
  if (stopping) return;
  stopping = true;
  issuer.kill('SIGTERM');
  proxy.close();
  const timer = setTimeout(() => { issuer.kill('SIGKILL'); process.exit(code); }, 5000);
  issuer.once('exit', () => { clearTimeout(timer); process.exit(code); });
  if (issuer.exitCode !== null || issuer.signalCode !== null) { clearTimeout(timer); process.exit(code); }
}
issuer.once('error', () => { console.error('Local issuer could not start'); stop(1); });
issuer.once('exit', code => stop(code === 0 ? 0 : 1));
proxy.on('error', () => { console.error('Local proxy could not start'); stop(1); });
process.on('SIGINT', () => stop(0));
process.on('SIGTERM', () => stop(0));
proxy.listen(8021, '127.0.0.1', () => console.log('Local auth proxy listening on http://127.0.0.1:8021'));
