import {generateKeyPairSync,randomUUID} from 'node:crypto';
import {writeFileSync} from 'node:fs';
const path=process.argv[2];
if(!path)throw Error('Usage: node scripts/generate-jwks.js /secure/path/identity.private.json');
const {privateKey}=generateKeyPairSync('rsa',{modulusLength:3072});
writeFileSync(path,JSON.stringify({keys:[{...privateKey.export({format:'jwk'}),kid:randomUUID(),use:'sig',alg:'RS256'}]},null,2)+'\n',{mode:0o600,flag:'wx'});
console.log('Private JWKS file created; do not commit it');
