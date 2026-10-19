export function readConfig(env = process.env) {
  if (env.IDENTITY_ENABLED !== 'true') return null;
  const required = (key) => { if (!env[key]) throw new Error(`Missing ${key}`); return env[key]; };
  const bindHost = env.IDENTITY_BIND_HOST || '127.0.0.1';
  const port = Number(env.IDENTITY_PORT || 8020);
  if (!['127.0.0.1','::1','0.0.0.0'].includes(bindHost) || !Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Invalid listener configuration');
  const production = env.NODE_ENV !== 'test' && env.NODE_ENV !== 'development';
  const issuer = new URL(required('IDENTITY_ISSUER'));
  const bridge = new URL(required('IDENTITY_ACCOUNT_BASE_URL'));
  if (production && (issuer.protocol !== 'https:' || bridge.protocol !== 'https:')) throw new Error('HTTPS required');
  if (bridge.username || bridge.password || bridge.search || bridge.hash || bridge.pathname !== '/') throw new Error('Invalid account bridge URL');
  if (issuer.pathname !== '/' || issuer.search || issuer.hash || issuer.username || issuer.password) throw new Error('Invalid issuer');
  const serviceToken = required('IDENTITY_SERVICE_TOKEN');
  const cookieKeys = JSON.parse(required('IDENTITY_COOKIE_KEYS'));
  if (serviceToken.length < 32 || !Array.isArray(cookieKeys) || !cookieKeys.length || cookieKeys.some(k => typeof k !== 'string' || k.length < 32 || k === serviceToken)) throw new Error('Independent strong service and cookie keys required');
  const jwks = JSON.parse(required('IDENTITY_JWKS'));
  if (!jwks.keys?.length || jwks.keys.some(k => !k.d || !k.kid || !['RSA', 'EC'].includes(k.kty))) throw new Error('Private asymmetric signing JWKS required');
  const clients = JSON.parse(required('IDENTITY_CLIENTS'));
  if (!Array.isArray(clients) || !clients.length || new Set(clients.map(c => c.client_id)).size !== clients.length) throw new Error('Static clients required');
  for (const c of clients) {
    if (typeof c.client_id !== 'string' || !c.client_id || typeof c.client_secret !== 'string' || c.client_secret.length < 32 || !Array.isArray(c.redirect_uris) || !c.redirect_uris.length) throw new Error('Confidential clients required');
    for (const redirect of c.redirect_uris) {
      const u = new URL(redirect);
      if (u.hash || u.username || u.password || redirect.includes('*') || (production && u.protocol !== 'https:') || !['http:', 'https:'].includes(u.protocol)) throw new Error('Exact HTTPS redirect required');
    }
    // Ignore caller-supplied capabilities; this slice only permits code with S256 PKCE.
    Object.assign(c, { grant_types: ['authorization_code'], response_types: ['code'], token_endpoint_auth_method: 'client_secret_basic' });
  }
  const secrets = [serviceToken, ...cookieKeys, ...clients.map(c => c.client_secret)];
  if (new Set(secrets).size !== secrets.length) throw new Error('Service, cookie and client secrets must be independent');
  const interactionUiPath = env.IDENTITY_INTERACTION_UI_PATH || '';
  if (interactionUiPath && (!interactionUiPath.startsWith('/') || interactionUiPath.startsWith('//') || /[?#\\]/.test(interactionUiPath) || interactionUiPath.startsWith('/interaction'))) throw new Error('Invalid same-origin interaction UI path');
  const cloudbaseEnvId = env.CLOUDBASE_ENV_ID || '';
  if (cloudbaseEnvId && !/^[a-z0-9-]+$/i.test(cloudbaseEnvId)) throw new Error('Invalid CloudBase environment');
  return { bindHost, interactionUiPath, cloudbaseEnvId, issuer: issuer.href.replace(/\/$/, ''), bridge: bridge.href.replace(/\/$/, ''), serviceToken, cookieKeys, jwks, clients, databaseUrl: required('IDENTITY_DATABASE_URL'), production, port };
}
