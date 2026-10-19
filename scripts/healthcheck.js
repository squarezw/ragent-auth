import http from 'node:http';
export async function checkDiscovery({issuer,port=8020,host='127.0.0.1'} = {}) {
  const expected = new URL(issuer);
  const body = await new Promise((resolve,reject)=>{
    const request=http.get({hostname:host,port,path:'/.well-known/openid-configuration',headers:{Host:expected.host,'X-Forwarded-Proto':'https'}},response=>{
      let data=''; response.setEncoding('utf8');
      response.on('data',chunk=>{data+=chunk;if(data.length>65536)request.destroy(new Error('Invalid discovery'));});
      response.on('end',()=>response.statusCode===200?resolve(data):reject(new Error('Discovery unavailable')));
    });
    request.setTimeout(4000,()=>request.destroy(new Error('Discovery timeout')));request.on('error',reject);
  });
  const metadata=JSON.parse(body);
  if(metadata.issuer!==expected.href.replace(/\/$/,''))throw new Error('Discovery issuer mismatch');
  for(const key of ['authorization_endpoint','token_endpoint','jwks_uri','userinfo_endpoint']) {
    const endpoint=new URL(metadata[key]);
    if(endpoint.origin!==expected.origin||endpoint.protocol!=='https:')throw new Error('Invalid discovery endpoint');
  }
}
if (process.argv[1] && new URL(import.meta.url).pathname === process.argv[1]) {
  try { await checkDiscovery({issuer:process.env.IDENTITY_ISSUER,port:Number(process.env.IDENTITY_PORT||8020)}); }
  catch { console.error('Identity discovery healthcheck failed');process.exitCode=1; }
}
