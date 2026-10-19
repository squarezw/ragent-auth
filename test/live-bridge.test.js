import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {generateKeyPairSync,createHash,randomBytes} from 'node:crypto';
import {createIdentityServer} from '../src/provider.js';
import {postgresAdapter} from '../src/postgres-adapter.js';
const enabled=!!process.env.IDENTITY_LIVE_BRIDGE_URL;
test('real Python account bridge -> OIDC password code/token/userinfo and second-client SSO',{skip:!enabled},async(t)=>{
 const env=process.env;
 for(const name of ['IDENTITY_LIVE_USERNAME','IDENTITY_LIVE_PASSWORD','IDENTITY_LIVE_SERVICE_TOKEN','IDENTITY_TEST_DATABASE_URL'])assert.ok(env[name],`Missing ${name}`);
 const temporary=createServer();await new Promise(resolve=>temporary.listen(0,'127.0.0.1',resolve));const port=temporary.address().port;await new Promise(resolve=>temporary.close(resolve));const issuer=`http://127.0.0.1:${port}`;
 const storage=await postgresAdapter(env.IDENTITY_TEST_DATABASE_URL);t.after(()=>storage.close());
 const {privateKey}=generateKeyPairSync('rsa',{modulusLength:2048});
 const clients=['review-live','convert-live'].map(id=>({client_id:id,client_secret:id+'-fixture-secret-01234567890123456789',redirect_uris:[`https://${id}.example/callback`],grant_types:['authorization_code'],response_types:['code'],token_endpoint_auth_method:'client_secret_basic'}));
 const {server}=createIdentityServer({issuer,bridge:env.IDENTITY_LIVE_BRIDGE_URL,serviceToken:env.IDENTITY_LIVE_SERVICE_TOKEN,cookieKeys:['live-test-cookie-independent-01234567890123456789'],jwks:{keys:[{...privateKey.export({format:'jwk'}),kid:'live-fixture',alg:'RS256'}]},clients,production:false},{Adapter:storage.Adapter});
 await new Promise(resolve=>server.listen(port,'127.0.0.1',resolve));t.after(()=>new Promise(resolve=>server.close(resolve)));
 const cookies=new Map();
 async function browser(url,options={}){const r=await fetch(url,{...options,redirect:'manual',headers:{...options.headers,cookie:[...cookies].map(([k,v])=>`${k}=${v}`).join('; ')}});for(const line of r.headers.getSetCookie()){const pair=line.split(';')[0];const i=pair.indexOf('=');cookies.set(pair.slice(0,i),pair.slice(i+1));}return r;}
 let subject;
 for(const [index,client] of clients.entries()){
  const verifier=randomBytes(32).toString('base64url');const challenge=createHash('sha256').update(verifier).digest('base64url');
  let url=issuer+'/auth?'+new URLSearchParams({client_id:client.client_id,redirect_uri:client.redirect_uris[0],response_type:'code',scope:'openid profile phone',state:'live-fixture-state',nonce:'live-fixture-nonce',code_challenge:challenge,code_challenge_method:'S256'});let code,logins=0;
  for(let step=0;step<12;step++){
   const r=await browser(url);const location=r.headers.get('location');
   if(location){if(location.startsWith('https://')){const result=new URL(location);assert.equal(result.searchParams.get('state'),'live-fixture-state');code=result.searchParams.get('code');assert.ok(code,'OIDC response must contain code');break;}url=new URL(location,issuer).href;continue;}
   assert.equal(r.status,200,'login page must load');const html=await r.text();const csrf=/name="csrf" value="([^"]+)"/.exec(html)?.[1];assert.ok(csrf);
   const login=await browser(url,{method:'POST',headers:{origin:issuer,'content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams({csrf,username:env.IDENTITY_LIVE_USERNAME,password:env.IDENTITY_LIVE_PASSWORD})});assert.equal(login.status,303,'Python bridge authentication must succeed');logins++;url=new URL(login.headers.get('location'),issuer).href;
  }
  assert.ok(code);assert.equal(logins,index===0?1:0,'second client reuses center session');
  const exchange=await fetch(issuer+'/token',{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded',authorization:'Basic '+Buffer.from(`${client.client_id}:${client.client_secret}`).toString('base64')},body:new URLSearchParams({grant_type:'authorization_code',code,redirect_uri:client.redirect_uris[0],code_verifier:verifier})});assert.equal(exchange.status,200);
  const token=await exchange.json();const info=await fetch(issuer+'/me',{headers:{authorization:`Bearer ${token.access_token}`}});assert.equal(info.status,200,'Python account lookup must succeed');const account=await info.json();assert.equal(account.preferred_username,env.IDENTITY_LIVE_USERNAME);assert.ok(account.sub);if(subject)assert.equal(account.sub,subject);else subject=account.sub;
 }
});
