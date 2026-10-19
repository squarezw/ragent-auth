import {test} from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {postgresAdapter} from '../src/postgres-adapter.js';
test('Postgres persists across reconnect, consumes once, expires, looks up uid and revokes grants',{skip:!process.env.IDENTITY_TEST_DATABASE_URL},async()=>{
 const url=process.env.IDENTITY_TEST_DATABASE_URL;
 const store=await postgresAdapter(url);const a=new store.Adapter('AccessToken');const id=randomUUID();const grant=randomUUID();
 await a.upsert(id,{uid:id,grantId:grant,sub:'fixture'},60);await store.close();
 const reopened=await postgresAdapter(url);try{
 const b=new reopened.Adapter('AccessToken');assert.equal((await b.find(id)).sub,'fixture');assert.equal((await b.findByUid(id)).grantId,grant);
 const consumes=await Promise.allSettled([b.consume(id),b.consume(id)]);assert.equal(consumes.filter(x=>x.status==='fulfilled').length,1);assert.ok((await b.find(id)).consumed);
 const models=['Grant','Interaction','AuthorizationCode','RefreshToken'];
 const peers=models.map(name=>new reopened.Adapter(name));
 try {
  for(const peer of peers)await peer.upsert(id,{uid:id,grantId:grant},60);
  await b.revokeByGrantId(grant);assert.equal(await b.find(id),undefined);
  for(const peer of peers)assert.ok(await peer.find(id),peer.name+' must survive AccessToken revocation');
  for(const name of ['AuthorizationCode','RefreshToken']){const peer=peers.find(a=>a.name===name);await peer.revokeByGrantId(grant);assert.equal(await peer.find(id),undefined);}
  for(const name of ['Grant','Interaction'])assert.ok(await peers.find(a=>a.name===name).find(id),name+' must survive token-model revocation');
 }finally{for(const peer of peers)await peer.destroy(id);}
 await b.upsert(id,{uid:id},1);await new Promise(resolve=>setTimeout(resolve,1100));assert.equal(await b.find(id),undefined);
 await b.upsert(id,{uid:id},60);await b.destroy(id);assert.equal(await b.find(id),undefined);
 }finally{await reopened.close();}
});
