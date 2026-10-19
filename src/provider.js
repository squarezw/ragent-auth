import { createServer } from 'node:http';
import { randomBytes, createHmac, timingSafeEqual } from 'node:crypto';
import Provider from 'oidc-provider';
import { accountBridge } from './bridge.js';
const escape = value => String(value).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
export function createIdentityServer(config, { Adapter, testTtl } = {}) {
  if (!config || !Adapter) throw new Error('Enabled configuration and persistent adapter required');
  if (config.production && testTtl) throw new Error('Test TTL override forbidden in production');
  const bridge = accountBridge(config);
  const provider = new Provider(config.issuer, {
    adapter: Adapter, jwks: config.jwks, clients: config.clients,
    responseTypes: ['code'], scopes: ['openid','profile','email','phone'],
    claims: { openid: ['sub'], profile: ['preferred_username','tenant_status','ragent_user_id','cloudbase_uid','cloudbase_env'], email: ['email'], phone: ['phone_number'] },
    cookies: { keys: config.cookieKeys, long: {httpOnly:true, sameSite:'lax', secure:config.production}, short: {httpOnly:true, sameSite:'lax', secure:config.production} },
    pkce: { required: () => true },
    features: { devInteractions: {enabled:false}, registration: {enabled:false}, requestObjects: {enabled:false}, userinfo: {enabled:true} },
    ttl: { AccessToken: testTtl || 600, IdToken: 600, AuthorizationCode: 60, Interaction: 300, Session: 604800, Grant: 604800 },
    interactions: { url: (_ctx, interaction) => `/interaction/${interaction.uid}` },
    async renderError(ctx) { ctx.type = 'text'; ctx.body = 'Identity request could not be completed'; },
    async findAccount(_ctx, sub) {
      let account;
      try { account = await bridge.account(sub); } catch { return undefined; }
      return { accountId: account.sub, async claims() { return {sub:account.sub, preferred_username:account.username, ragent_user_id:account.ragent_user_id, cloudbase_uid:account.cloudbase_uid, cloudbase_env:account.cloudbase_env, email:account.email, phone_number:account.phone, tenant_status:account.tenant_status}; } };
    },
    async loadExistingGrant(ctx) {
      const id = ctx.oidc.result?.consent?.grantId || ctx.oidc.session.grantIdFor(ctx.oidc.client.clientId);
      if (id) {
        const existing = await provider.Grant.find(id);
        if (existing) return existing;
      }
      if (ctx.oidc.session.accountId) {
        // Only explicitly configured first-party clients receive pre-authorized basic identity claims.
        await bridge.account(ctx.oidc.session.accountId);
        const grant = new provider.Grant({accountId:ctx.oidc.session.accountId,clientId:ctx.oidc.client.clientId});
        grant.addOIDCScope('openid profile email phone'); await grant.save(); return grant;
      }
      return undefined;
    },
  });
  provider.proxy = config.production;
  // Reject legacy/plain PKCE even if future provider defaults broaden.
  provider.use(async (ctx, next) => {
    if (ctx.path === '/auth' && ctx.query.code_challenge_method !== 'S256') { ctx.status=400; ctx.body={error:'invalid_request',error_description:'S256 PKCE required'}; return; }
    await next();
  });
  const protocol = provider.callback();
  const csrf = uid => createHmac('sha256',config.cookieKeys[0]).update(`interaction:${uid}`).digest('base64url');
  const server = createServer(async (req,res) => {
    res.setHeader('Cache-Control','no-store');
    res.setHeader('Referrer-Policy','no-referrer');
    res.setHeader('X-Content-Type-Options','nosniff');
    res.setHeader('Content-Security-Policy',"default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'");
    const path = new URL(req.url,config.issuer).pathname;
    const match = /^\/interaction\/([^/]+)(?:\/(context|register))?$/.exec(path);
    if (!match) return protocol(req,res);
    try {
      const details = await provider.interactionDetails(req,res);
      if (details.uid !== match[1]) {res.writeHead(400);return res.end('Invalid interaction');}
      if (req.method === 'GET' && match[2] === 'context') {
        if (details.prompt.name !== 'login') {res.writeHead(400);return res.end('Invalid interaction');}
        res.setHeader('Content-Type','application/json');
        return res.end(JSON.stringify({csrf:csrf(details.uid),cloudbaseEnvId:config.cloudbaseEnvId || null}));
      }
      if (req.method === 'GET' && details.prompt.name === 'consent') {
        await bridge.account(details.session.accountId);
        const grant = details.grantId ? await provider.Grant.find(details.grantId) : new provider.Grant({accountId:details.session.accountId,clientId:details.params.client_id});
        grant.addOIDCScope('openid profile email phone');
        const grantId = await grant.save();
        return provider.interactionFinished(req,res,{consent:{grantId}},{mergeWithLastSubmission:true});
      }
      if (req.method === 'GET') {
        if (config.interactionUiPath) {
          res.writeHead(303,{Location:config.interactionUiPath+'?uid='+encodeURIComponent(details.uid)});
          return res.end();
        }
        const nonce = csrf(details.uid);
        res.setHeader('Content-Type','text/html; charset=utf-8');
        return res.end(`<!doctype html><html lang="en"><title>RAgent Identity — test slice</title><main><h1>Sign in to RAgent</h1><p>Identity center protocol preview</p><form method="post"><input type="hidden" name="csrf" value="${nonce}"><label>Username or phone<input name="username" autocomplete="username" required></label><label>Password<input name="password" type="password" autocomplete="current-password" required></label><button>Sign in</button></form><form method="post"><input type="hidden" name="csrf" value="${nonce}"><label>Verified CloudBase access token<input name="access_token" type="password" required></label><button>Verify phone identity</button></form></main></html>`);
      }
      if (req.method !== 'POST') {res.writeHead(405);return res.end();}
      if (req.headers.origin !== new URL(config.issuer).origin || !(req.headers['content-type'] || '').startsWith('application/x-www-form-urlencoded')) {res.writeHead(403);return res.end('Invalid request origin');}
      let raw=''; for await (const chunk of req) { raw+=chunk; if (Buffer.byteLength(raw)>16384) {res.writeHead(413);return res.end();} }
      const form = new URLSearchParams(raw); const actual = Buffer.from(form.get('csrf') || '');const expected=Buffer.from(csrf(details.uid));
      if (actual.length!==expected.length || !timingSafeEqual(actual,expected) || details.prompt.name !== 'login') {res.writeHead(403);return res.end('Invalid interaction');}
      const account = match[2] === 'register'
        ? await bridge.register({access_token:form.get('access_token'),username:form.get('username'),password:form.get('password')})
        : form.has('access_token') ? await bridge.phone({access_token:form.get('access_token')}) : await bridge.password({username:form.get('username'),password:form.get('password')});
      // Browser-supplied account IDs are never read.
      const result = {login:{accountId:account.sub,amr:[form.has('access_token')?'sms':'pwd']}};
      if ((req.headers.accept || '').includes('application/json')) {
        const redirectTo = await provider.interactionResult(req,res,result,{mergeWithLastSubmission:false});
        res.setHeader('Content-Type','application/json');return res.end(JSON.stringify({redirectTo}));
      }
      await provider.interactionFinished(req,res,result,{mergeWithLastSubmission:false});
    } catch (error) {
      const json = (req.headers.accept || '').includes('application/json');
      if (!res.headersSent) res.writeHead(error.status === 429 ? 429 : 401, {'Content-Type':json?'application/json':'text/plain'});
      res.end(json ? JSON.stringify({errorCode:error.code || 'AUTH_UNAVAILABLE'}) : 'Sign-in unavailable or credentials invalid');
    }
  });
  return {server,provider};
}
