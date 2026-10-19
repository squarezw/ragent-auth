import assert from 'node:assert/strict';
import {test} from 'node:test';
import {createServer} from 'node:http';
import {generateKeyPairSync,randomBytes,createHash} from 'node:crypto';
import {createIdentityServer} from '../src/provider.js';
import {postgresAdapter} from '../src/postgres-adapter.js';
import {readConfig} from '../src/config.js';
import {jwtVerify,importJWK} from 'jose';
class MemoryAdapter {
  static records=new Map();
  constructor(name){this.name=name;}
  async upsert(id,payload,ttl){MemoryAdapter.records.set(this.name+id,{payload:structuredClone(payload),exp:Date.now()+ttl*1000,ttl});}
  async find(id){const r=MemoryAdapter.records.get(this.name+id);return r&&r.exp>Date.now()?structuredClone(r.payload):undefined;}
  async findByUid(uid){for(const [k,v] of MemoryAdapter.records)if(k.startsWith(this.name)&&v.payload.uid===uid&&v.exp>Date.now())return structuredClone(v.payload);}
  async consume(id){const r=MemoryAdapter.records.get(this.name+id);if(!r||r.payload.consumed)throw Error('consumed');r.payload.consumed=Math.floor(Date.now()/1000);}
  async destroy(id){MemoryAdapter.records.delete(this.name+id);}
  async revokeByGrantId(id){for(const [k,v] of MemoryAdapter.records)if(k.startsWith(this.name)&&v.payload.grantId===id)MemoryAdapter.records.delete(k);}
}
const listen=server=>new Promise(resolve=>server.listen(0,'127.0.0.1',()=>resolve(`http://127.0.0.1:${server.address().port}`)));
const close=server=>new Promise(resolve=>server.close(resolve));
const sub='e5d30bde-df31-42c1-8cee-bbde94160fab';
function jarFetch(onCookie=()=>{}){const cookies=new Map();return async(url,options={})=>{const r=await fetch(url,{...options,redirect:'manual',headers:{...options.headers,cookie:[...cookies].map(([k,v])=>`${k}=${v}`).join('; ')}});for(const s of r.headers.getSetCookie()){onCookie(s);const [pair]=s.split(';');const i=pair.indexOf('=');cookies.set(pair.slice(0,i),pair.slice(i+1));}return r;};}
test('configuration defaults closed and enforces exact confidential code clients',()=>{
 assert.equal(readConfig({}),null);
 assert.throws(()=>readConfig({IDENTITY_ENABLED:'true'}));
});
for (const testTtl of [undefined, 1]) test(`real OIDC protocol; ${testTtl ? 'short test override' : 'default ten-minute tokens'}`,async(t)=>{
 MemoryAdapter.records.clear();
 let disabled=false,passwordLogins=0,phoneLogins=0;
 const switchedSub='bcdf17a0-c93e-4ff7-9797-a0fedb0c6183';
 let selectedSub=sub;
 const serviceToken='bridge-service-token-for-fixtures-only-123456';
 const backend=createServer(async(req,res)=>{
  assert.equal(req.headers.authorization,`Bearer ${serviceToken}`);
  res.setHeader('content-type','application/json');
  let raw='';for await(const chunk of req)raw+=chunk;
  const body=raw?JSON.parse(raw):{};
  if(disabled){res.writeHead(403);return res.end('{}');}
  if(req.url.endsWith('authenticate-password')){passwordLogins++;if(!['alice','square'].includes(body.username)||body.password!=='valid-password'){res.writeHead(401);return res.end('{}');}selectedSub=body.username==='square'?switchedSub:sub;}
  else if(req.url.endsWith('authenticate-phone')){phoneLogins++;if(body.access_token!=='verified-phone'){res.writeHead(401);return res.end('{}');}}
  else if(req.url.endsWith('register-phone')){if(body.username!=='new_user'||body.password!=='123456'||body.access_token!=='verified-phone'){res.writeHead(400);return res.end('{}');}}
  else if(![sub,switchedSub].some(id=>req.url===`/api/v1/identity/accounts/${id}`)){res.writeHead(404);return res.end('{}');}
  const responseSub=req.url.includes('/accounts/')?req.url.split('/').pop():selectedSub;
  res.end(JSON.stringify({sub:responseSub,ragent_user_id:42,cloudbase_uid:'trusted-cloud',cloudbase_env:'test-env',username:'alice',phone:'+8613800000000',email:null,tenant_status:'pending'}));
 });
 const bridge=await listen(backend);t.after(()=>close(backend));
 const {privateKey,publicKey}=generateKeyPairSync('rsa',{modulusLength:2048});
 const key={...privateKey.export({format:'jwk'}),kid:'fixture-key',alg:'RS256',use:'sig'};
 const reserve=createServer();const issuer=await listen(reserve);await close(reserve);
 const clients=['review','convert'].map(id=>({client_id:id,client_secret:`${id}-fixture-secret-012345678901234567890`,redirect_uris:[`https://${id}.example/callback`],grant_types:['authorization_code'],response_types:['code'],token_endpoint_auth_method:'client_secret_basic'}));
 const storage=process.env.IDENTITY_TEST_DATABASE_URL?await postgresAdapter(process.env.IDENTITY_TEST_DATABASE_URL):null;
 if(storage)t.after(()=>storage.close());
 const {server}=createIdentityServer({issuer,bridge,serviceToken,cookieKeys:['cookie-key-fixture-independent-01234567890123456789'],jwks:{keys:[key]},clients,production:false},{Adapter:storage?.Adapter || MemoryAdapter,testTtl});
 await new Promise(resolve=>server.listen(new URL(issuer).port,'127.0.0.1',resolve));t.after(()=>close(server));
 const sessionCookies=[];
 const browser=jarFetch(cookie=>sessionCookies.push(cookie));
 const verifier=randomBytes(32).toString('base64url');const challenge=createHash('sha256').update(verifier).digest('base64url');
 function authUrl(client='review',extra={}){return issuer+'/auth?'+new URLSearchParams({client_id:client,redirect_uri:`https://${client}.example/callback`,response_type:'code',scope:'openid profile phone',state:'fixture-state',nonce:'fixture-nonce',code_challenge:challenge,code_challenge_method:'S256',...extra});}
 async function authorize(browser,client='review',credentials={username:'alice',password:'valid-password'},extra={}){
  let url=authUrl(client,extra);let logins=0;
  for(let i=0;i<12;i++){
   const r=await browser(url);
   const location=r.headers.get('location');
   if(location){if(location.startsWith('https://')){const u=new URL(location);assert.equal(u.searchParams.get('state'),'fixture-state');assert.ok(u.searchParams.get('code'),location);return {code:u.searchParams.get('code'),logins};}url=new URL(location,issuer).href;continue;}
   const html=await r.text();assert.equal(r.status,200,url+' '+html);
   if (html.includes('<title>Submitting Callback</title>')) {
    const script=/<script>([\s\S]*?)<\/script>/.exec(html)?.[1];
    assert.ok(script);
    const digest=createHash('sha256').update(script).digest('base64');
    const csp=r.headers.get('content-security-policy');
    assert.ok(csp?.includes("'sha256-"+digest+"'"),'account switch auto-submit must be allowed by an exact CSP hash');
    assert.ok(!csp.includes("'unsafe-inline'"));
    assert.match(csp,/default-src 'none'/);
    assert.match(csp,/form-action 'self'/);
    const formSources=csp.split(';').find(value=>value.trim().startsWith('form-action')).trim().split(/\s+/).slice(1);
    assert.deepEqual(new Set(formSources),new Set(["'self'",'https://review.example','https://convert.example']));
    assert.ok(!formSources.includes('*'));
    assert.ok(!formSources.includes('https://evil.example'));
    const action=/<form method="post" action="([^"]+)"/.exec(html)[1];
    const fields=[...html.matchAll(/<input type="hidden" name="([^"]+)" value="([^"]*)"/g)].map(m=>[m[1],m[2]]);
    const logout=await browser(new URL(action,issuer),{method:'POST',headers:{origin:issuer,'content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams(fields)});
    assert.equal(logout.status,303,await logout.clone().text());
    url=new URL(logout.headers.get('location'),issuer).href;continue;
   }
   const csrf=/name="csrf" value="([^"]+)"/.exec(html)?.[1];assert.ok(csrf,html);
   const post=await browser(url,{method:'POST',headers:{origin:issuer,'content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams({csrf,...credentials})});
   assert.equal(post.status,303,await post.clone().text());logins++;url=new URL(post.headers.get('location'),issuer).href;
  }throw Error('too many redirects');
 }
 async function token(code,client='review',codeVerifier=verifier){return fetch(issuer+'/token',{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded',authorization:'Basic '+Buffer.from(`${client}:${clients.find(c=>c.client_id===client).client_secret}`).toString('base64')},body:new URLSearchParams({grant_type:'authorization_code',code,redirect_uri:`https://${client}.example/callback`,code_verifier:codeVerifier})});}
 const discovery=await fetch(issuer+'/.well-known/openid-configuration').then(r=>r.json());
 assert.deepEqual(discovery.response_types_supported,['code']);assert.ok(!discovery.registration_endpoint);assert.deepEqual(discovery.code_challenge_methods_supported,['S256']);
 const first=await authorize(browser);assert.equal(first.logins,1);assert.equal(passwordLogins,1);
 const tr=await token(first.code);const tokens=await tr.json();assert.equal(tr.status,200,JSON.stringify(tokens));
 const verified=await jwtVerify(tokens.id_token,await importJWK(publicKey.export({format:'jwk'}),'RS256'),{issuer,audience:'review'});assert.equal(verified.payload.sub,sub);assert.equal(verified.payload.nonce,'fixture-nonce');
 assert.equal(tokens.expires_in,testTtl || 600);
 assert.equal(verified.payload.exp-verified.payload.iat,600,'ID token lifetime stays ten minutes with or without access-token test override');
 if (!storage) {
  const session=[...MemoryAdapter.records].find(([key,value])=>key.startsWith('Session')&&value.payload.accountId===sub);
  const grant=[...MemoryAdapter.records].find(([key,value])=>key.startsWith('Grant')&&value.payload.clientId==='review');
  assert.ok(session);assert.ok(grant);
  assert.equal(session[1].ttl,604800,'server session is persisted for seven days');
  assert.equal(grant[1].ttl,604800,'server grant is persisted for seven days');
  assert.equal(session[1].payload.transient,undefined,'central login survives browser restarts');
 }
 const longCookies=sessionCookies.filter(cookie=>/^_session(?:\.sig)?=/.test(cookie)&&!cookie.includes('expires=Thu, 01 Jan 1970'));
 assert.ok(longCookies.length>=2,'session and signature cookies are issued');
 for (const cookie of longCookies) {
  const expiry=/expires=([^;]+)/i.exec(cookie)?.[1];assert.ok(expiry,'persistent cookie has explicit expiry');
  const remaining=Date.parse(expiry)-Date.now();
  assert.ok(remaining>604790000&&remaining<=604800000,'actual cookie expires in seven days: '+cookie);
  assert.match(cookie,/httponly/i);assert.match(cookie,/samesite=lax/i);
 }
 const realNow=Date.now;
 try {
  Date.now=()=>realNow()+8*3600*1000;
  const afterHour=await browser(authUrl('review',{prompt:'none'}));
  assert.ok(afterHour.headers.get('location')?.includes('code='),'central SSO remains usable after eight hours overnight');
  const renewedResponse=await token(new URL(afterHour.headers.get('location')).searchParams.get('code'));
  assert.equal(renewedResponse.status,200);
  const renewed=await renewedResponse.json();assert.equal(renewed.expires_in,testTtl || 600);
  const renewedId=await jwtVerify(renewed.id_token,await importJWK(publicKey.export({format:'jwk'}),'RS256'),{issuer,audience:'review'});
  assert.equal(renewedId.payload.sub,sub);assert.equal(renewedId.payload.exp-renewedId.payload.iat,600);
 } finally { Date.now=realNow; }

 const info=await fetch(issuer+'/me',{headers:{authorization:`Bearer ${tokens.access_token}`}});assert.equal(info.status,200);const infoClaims=await info.json();assert.equal(infoClaims.sub,sub);assert.equal(infoClaims.ragent_user_id,42);assert.equal(infoClaims.cloudbase_uid,'trusted-cloud');
 const silent=await browser(authUrl('review',{prompt:'none'}));assert.ok(silent.headers.get('location')?.includes('code='),'prompt none reuses existing authenticated grant: '+silent.status+' '+silent.headers.get('location'));
 const noSilent=await jarFetch()(authUrl('review',{prompt:'none'}));assert.ok(noSilent.headers.get('location')?.includes('error=login_required'),'prompt none requires existing center session');
 // Token expiry must not end central SSO; a separately expired grant must be re-established for the same first-party account.
 await new Promise(resolve=>setTimeout(resolve,1150));
 const afterExpiry=await browser(authUrl('review',{prompt:'none'}));
 assert.ok(afterExpiry.headers.get('location')?.includes('code='),'central SSO survives access-token expiry');
 const staleGrant=[...MemoryAdapter.records].find(([key,value])=>key.startsWith('Grant')&&value.payload.clientId==='review');
 if (!storage) {
  assert.ok(staleGrant);staleGrant[1].exp=Date.now()-1;
  const afterGrantExpiry=await browser(authUrl('review',{prompt:'none'}));
  assert.ok(afterGrantExpiry.headers.get('location')?.includes('code='),'first-party silent renewal replaces an expired grant while central session remains valid: '+afterGrantExpiry.headers.get('location'));
  const renewedResponse=await token(new URL(afterGrantExpiry.headers.get('location')).searchParams.get('code'));
  assert.equal(renewedResponse.status,200);
  const renewed=await renewedResponse.json();
  const renewedId=await jwtVerify(renewed.id_token,await importJWK(publicKey.export({format:'jwk'}),'RS256'),{issuer,audience:'review'});
  assert.equal(renewedId.payload.sub,sub);
  assert.equal(renewed.scope,'openid profile phone');
  const currentGrant=[...MemoryAdapter.records].find(([key,value])=>key.startsWith('Grant')&&value.payload.clientId==='review'&&value.exp>Date.now());
  assert.ok(currentGrant);assert.equal(currentGrant[1].payload.accountId,sub);
  assert.equal(currentGrant[1].payload.openid.scope,'openid profile email phone');
  MemoryAdapter.records.delete(currentGrant[0]);
  const afterMissingGrant=await browser(authUrl('review',{prompt:'none'}));
  assert.ok(afterMissingGrant.headers.get('location')?.includes('code='),'missing grant is also re-established');
  const unknownClient=await browser(authUrl('unregistered',{prompt:'none',redirect_uri:'https://evil.example/callback'}));
  assert.notEqual(unknownClient.status,302);assert.equal(unknownClient.headers.get('location'),null);

 }
 const second=await authorize(browser,'convert');assert.equal(second.logins,0);assert.equal(passwordLogins,1,'center session reused by second client');assert.equal((await token(second.code,'convert')).status,200);
 assert.equal((await token(first.code)).status,400,'code is single use');
 const cross=await authorize(browser);assert.equal((await token(cross.code,'convert')).status,400,'code cannot be redeemed by another client');
 const pkce=await authorize(browser);assert.equal((await token(pkce.code,'review','x'.repeat(43))).status,400);
 const redirect=await browser(authUrl('review',{redirect_uri:'https://evil.example/callback'}));assert.notEqual(redirect.status,302);assert.equal(redirect.headers.get('location'),null);
 const plain=await browser(authUrl('review',{code_challenge_method:'plain'}));assert.equal(plain.status,400);
 const noChallenge=await browser(authUrl('review',{code_challenge:'',code_challenge_method:''}));assert.equal(noChallenge.status,400);
 const fresh=jarFetch();let start=await fresh(authUrl());const loginUrl=new URL(start.headers.get('location'),issuer).href;const loginPage=await fresh(loginUrl);const loginHtml=await loginPage.text();const csrf=/name="csrf" value="([^"]+)"/.exec(loginHtml)[1];
 const wrongOrigin=await fresh(loginUrl,{method:'POST',headers:{origin:'https://evil.example','content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams({csrf,username:'alice',password:'valid-password'})});assert.equal(wrongOrigin.status,403);
 const wrongCsrf=await fresh(loginUrl,{method:'POST',headers:{origin:issuer,'content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams({csrf:'invalid',username:'alice',password:'valid-password'})});assert.equal(wrongCsrf.status,403);
 const wrongPassword=await fresh(loginUrl,{method:'POST',headers:{origin:issuer,'content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams({csrf,username:'alice',password:'bad-password',accountId:sub})});assert.equal(wrongPassword.status,401,'client accountId cannot authenticate');
 const phone=await authorize(jarFetch(),'review',{access_token:'verified-phone',accountId:'attacker'});assert.equal(phone.logins,1);assert.equal(phoneLogins,1);const phoneResponse=await token(phone.code);assert.equal(phoneResponse.status,200);const phoneTokens=await phoneResponse.json();
 const registrationBrowser=jarFetch();
 const registrationStart=await registrationBrowser(authUrl());
 const registrationUrl=new URL(registrationStart.headers.get('location'),issuer).href;
 const contextResponse=await registrationBrowser(registrationUrl+'/context');
 assert.equal(contextResponse.status,200);
 const context=await contextResponse.json();assert.ok(context.csrf);
 const invalidRegistration=await registrationBrowser(registrationUrl+'/register',{method:'POST',headers:{origin:issuer,accept:'application/json','content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams({csrf:context.csrf,username:'new_user',password:'bad',access_token:'verified-phone'})});
 assert.equal(invalidRegistration.status,401);assert.equal((await invalidRegistration.json()).errorCode,'AUTH_UNAVAILABLE');
 const registration=await registrationBrowser(registrationUrl+'/register',{method:'POST',headers:{origin:issuer,accept:'application/json','content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams({csrf:context.csrf,username:'new_user',password:'123456',access_token:'verified-phone'})});
 assert.equal(registration.status,200,await registration.clone().text());
 const registrationBody=await registration.json();assert.ok(registrationBody.redirectTo);assert.deepEqual(Object.keys(registrationBody),['redirectTo']);
 let resume=await registrationBrowser(new URL(registrationBody.redirectTo,issuer));
 for(let i=0;i<5&&resume.headers.get('location')&&!resume.headers.get('location').startsWith('https://');i++)resume=await registrationBrowser(new URL(resume.headers.get('location'),issuer));
 assert.ok(resume.headers.get('location')?.includes('code='));
 const beforeSwitch=await authorize(browser);
 const beforeSwitchResponse=await token(beforeSwitch.code);assert.equal(beforeSwitchResponse.status,200);
 const beforeSwitchTokens=await beforeSwitchResponse.json();
 const switched=await authorize(browser,'review',{username:'square',password:'valid-password'},{prompt:'login'});
 assert.equal(switched.logins,1);
 const revokedOldInfo=await fetch(issuer+'/me',{headers:{authorization:`Bearer ${beforeSwitchTokens.access_token}`}});assert.equal(revokedOldInfo.status,401,'switching accounts revokes old session tokens');
 const switchedTokenResponse=await token(switched.code);assert.equal(switchedTokenResponse.status,200);
 const switchedTokens=await switchedTokenResponse.json();
 const switchedId=await jwtVerify(switchedTokens.id_token,await importJWK(publicKey.export({format:'jwk'}),'RS256'),{issuer,audience:'review'});
 assert.equal(switchedId.payload.sub,switchedSub,'forced login uses new account, not previous session');
 const switchedInfo=await fetch(issuer+'/me',{headers:{authorization:`Bearer ${switchedTokens.access_token}`}});assert.equal((await switchedInfo.json()).sub,switchedSub);
 const switchedSilent=await browser(authUrl('convert',{prompt:'none'}));assert.ok(switchedSilent.headers.get('location')?.includes('code='));
 const switchedSecond=await token(new URL(switchedSilent.headers.get('location')).searchParams.get('code'),'convert');assert.equal(switchedSecond.status,200);
 const switchedSecondId=await jwtVerify((await switchedSecond.json()).id_token,await importJWK(publicKey.export({format:'jwk'}),'RS256'),{issuer,audience:'convert'});assert.equal(switchedSecondId.payload.sub,switchedSub);
 // Exercise repeated switches, same-account forced login and both first-party clients.
 for (const [username,client] of [['alice','review'],['square','convert'],['alice','convert'],['alice','review'],['square','review'],['square','convert'],['alice','review']]) {
  const expectedSub=username==='square'?switchedSub:sub;
  const next=await authorize(browser,client,{username,password:'valid-password'},{prompt:'login'});assert.equal(next.logins,1);
  const response=await token(next.code,client);assert.equal(response.status,200);
  const nextTokens=await response.json();
  const nextId=await jwtVerify(nextTokens.id_token,await importJWK(publicKey.export({format:'jwk'}),'RS256'),{issuer,audience:client});assert.equal(nextId.payload.sub,expectedSub);
  const nextInfo=await fetch(issuer+'/me',{headers:{authorization:`Bearer ${nextTokens.access_token}`}});assert.equal(nextInfo.status,200);assert.equal((await nextInfo.json()).sub,expectedSub);
  for(const otherClient of ['review','convert']) {
   const sso=await browser(authUrl(otherClient,{prompt:'none'}));assert.ok(sso.headers.get('location')?.includes('code='));
   const ssoResponse=await token(new URL(sso.headers.get('location')).searchParams.get('code'),otherClient);assert.equal(ssoResponse.status,200);
   const ssoId=await jwtVerify((await ssoResponse.json()).id_token,await importJWK(publicKey.export({format:'jwk'}),'RS256'),{issuer,audience:otherClient});assert.equal(ssoId.payload.sub,expectedSub);
  }
 }
 const disableBeforeExchange=await authorize(browser);
 disabled=true;
 if (!storage) for (const [key,value] of MemoryAdapter.records) if (key.startsWith('Grant')) value.exp=Date.now()-1;
 const disabledToken=await token(disableBeforeExchange.code);assert.equal(disabledToken.status,400,'disabled account rejected during token exchange');
 const disabledSilent=await browser(authUrl('review',{prompt:'none'}));assert.ok(!disabledSilent.headers.get('location')?.includes('code='),'disabled account cannot reuse center session with prompt none');
 const disabledInfo=await fetch(issuer+'/me',{headers:{authorization:`Bearer ${phoneTokens.access_token}`}});assert.equal(disabledInfo.status,401,'live disabled lookup rejects existing token');
 disabled=false;
 if (!testTtl) return;
 await new Promise(resolve=>setTimeout(resolve,1150));
 const expiredInfo=await fetch(issuer+'/me',{headers:{authorization:`Bearer ${tokens.access_token}`}});assert.equal(expiredInfo.status,401,'expired access token rejected');
});
