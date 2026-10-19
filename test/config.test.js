import {test} from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync} from 'node:crypto';
import {readConfig} from '../src/config.js';
const {privateKey}=generateKeyPairSync('rsa',{modulusLength:2048});
function env(){return {IDENTITY_ENABLED:'true',NODE_ENV:'production',IDENTITY_ISSUER:'https://auth.example',IDENTITY_ACCOUNT_BASE_URL:'https://accounts.example',IDENTITY_SERVICE_TOKEN:'bridge-service-fixture-01234567890123456789',IDENTITY_COOKIE_KEYS:JSON.stringify(['cookie-signing-fixture-01234567890123456789']),IDENTITY_JWKS:JSON.stringify({keys:[{...privateKey.export({format:'jwk'}),kid:'test'}]}),IDENTITY_DATABASE_URL:'postgresql://test:test@localhost/fixture',IDENTITY_CLIENTS:JSON.stringify([{client_id:'review',client_secret:'confidential-client-fixture-01234567890123456789',redirect_uris:['https://review.example/callback']}])};}
test('enabled production validates independent keys, HTTPS, persistent DB and static redirects',()=>{
 const conf=readConfig(env());assert.equal(conf.production,true);assert.deepEqual(conf.clients[0].grant_types,['authorization_code']);
 for(const key of ['IDENTITY_DATABASE_URL','IDENTITY_SERVICE_TOKEN','IDENTITY_COOKIE_KEYS','IDENTITY_JWKS','IDENTITY_CLIENTS']){const e=env();delete e[key];assert.throws(()=>readConfig(e),key);}
 for(const key of ['IDENTITY_ISSUER','IDENTITY_ACCOUNT_BASE_URL'])assert.throws(()=>readConfig({...env(),[key]:'http://example.test'}));
 for(const uri of ['https://*.example/callback','https://example/callback#fragment','http://example/callback']){const e=env();const clients=JSON.parse(e.IDENTITY_CLIENTS);clients[0].redirect_uris=[uri];e.IDENTITY_CLIENTS=JSON.stringify(clients);assert.throws(()=>readConfig(e));}
 const e=env();e.IDENTITY_COOKIE_KEYS=JSON.stringify([e.IDENTITY_SERVICE_TOKEN]);assert.throws(()=>readConfig(e));
});


test('client secrets cannot reuse service/cookie keys or another client key',()=>{
 for(const source of ['IDENTITY_SERVICE_TOKEN','IDENTITY_COOKIE_KEYS']){
  const e=env();const clients=JSON.parse(e.IDENTITY_CLIENTS);
  clients[0].client_secret=source==='IDENTITY_COOKIE_KEYS'?JSON.parse(e[source])[0]:e[source];
  e.IDENTITY_CLIENTS=JSON.stringify(clients);assert.throws(()=>readConfig(e));
 }
 const e=env();const clients=JSON.parse(e.IDENTITY_CLIENTS);clients.push({...clients[0],client_id:'convert'});e.IDENTITY_CLIENTS=JSON.stringify(clients);assert.throws(()=>readConfig(e));
 for(const bridge of ['https://user:password@accounts.example','https://accounts.example/path','https://accounts.example/?secret=value'])assert.throws(()=>readConfig({...env(),IDENTITY_ACCOUNT_BASE_URL:bridge}));
});

test('listener defaults to loopback and permits only explicit container bind and valid ports',()=>{
 assert.equal(readConfig(env()).bindHost,'127.0.0.1');
 assert.equal(readConfig({...env(),IDENTITY_BIND_HOST:'0.0.0.0'}).bindHost,'0.0.0.0');
 for(const host of ['example.com','*','192.168.1.1'])assert.throws(()=>readConfig({...env(),IDENTITY_BIND_HOST:host}));
 for(const port of ['0','-1','65536','NaN','8020.5'])assert.throws(()=>readConfig({...env(),IDENTITY_PORT:port}));
});
