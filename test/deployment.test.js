import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,writeFileSync,chmodSync,symlinkSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import http from 'node:http';
import {loadSecretFiles} from '../src/secret-files.js';
import {checkDiscovery} from '../scripts/healthcheck.js';
test('protected file secrets fail closed without revealing file values or paths',()=>{
 const dir=mkdtempSync(join(tmpdir(),'identity-secret-'));const path=join(dir,'secret');const value='private-test-value-do-not-reflect';
 try {
  writeFileSync(path,value+'\n',{mode:0o600});
  const env={IDENTITY_ENABLED:'true',IDENTITY_SERVICE_TOKEN_FILE:path};
  assert.equal(loadSecretFiles(env).IDENTITY_SERVICE_TOKEN,value);
  assert.equal(env.IDENTITY_SERVICE_TOKEN,undefined);
  assert.throws(()=>loadSecretFiles({...env,IDENTITY_SERVICE_TOKEN:value}),/Conflicting secret sources/);
  for(const mode of [0o644,0o660,0o606]){chmodSync(path,mode);assert.throws(()=>loadSecretFiles(env),error=>!error.message.includes(value)&&!error.message.includes(dir));}
  chmodSync(path,0o440);assert.equal(loadSecretFiles(env).IDENTITY_SERVICE_TOKEN,value);
  symlinkSync(path,join(dir,'link'));assert.throws(()=>loadSecretFiles({...env,IDENTITY_SERVICE_TOKEN_FILE:join(dir,'link')}));
  assert.throws(()=>loadSecretFiles({...env,IDENTITY_SERVICE_TOKEN_FILE:dir}));
  chmodSync(path,0o600);writeFileSync(path,'');assert.throws(()=>loadSecretFiles(env));
  assert.equal(loadSecretFiles({IDENTITY_ENABLED:'false',IDENTITY_JWKS_FILE:'/not-present'}).IDENTITY_JWKS,undefined);
 }finally{rmSync(dir,{recursive:true,force:true});}
});
test('production discovery healthcheck supplies trusted proxy host and requires HTTPS issuer/endpoints',async()=>{
 let malformed=false;
 const server=http.createServer((req,res)=>{
  assert.equal(req.headers.host,'auth.example');assert.equal(req.headers['x-forwarded-proto'],'https');
  res.setHeader('content-type','application/json');res.end(JSON.stringify({issuer:'https://auth.example',authorization_endpoint:'https://auth.example/auth',token_endpoint:malformed?'http://auth.example/token':'https://auth.example/token',jwks_uri:'https://auth.example/jwks',userinfo_endpoint:'https://auth.example/me'}));
 });await new Promise(r=>server.listen(0,'127.0.0.1',r));
 try{await checkDiscovery({issuer:'https://auth.example',port:server.address().port});malformed=true;await assert.rejects(checkDiscovery({issuer:'https://auth.example',port:server.address().port}));}finally{await new Promise(r=>server.close(r));}
});

test('startup and migration failures never echo invalid secret configuration',async()=>{
 const {spawnSync}=await import('node:child_process');
 const marker='sensitive-do-not-log-fixture';
 for(const script of ['src/main.js','scripts/migrate.js']) {
  const run=spawnSync(process.execPath,[script],{cwd:new URL('../',import.meta.url),env:{PATH:process.env.PATH,IDENTITY_ENABLED:'true',IDENTITY_JWKS:marker},encoding:'utf8'});
  assert.equal(run.status,1);assert.ok(!run.stderr.includes(marker));assert.match(run.stderr,/failed/);
 }
});
