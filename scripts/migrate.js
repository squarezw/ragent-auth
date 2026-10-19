import pg from 'pg';
import {readFile} from 'node:fs/promises';
import {loadSecretFiles} from '../src/secret-files.js';
try {
const env=loadSecretFiles();
if(env.IDENTITY_ENABLED!=='true' || !env.IDENTITY_DATABASE_URL) throw Error('Explicit IDENTITY_ENABLED and IDENTITY_DATABASE_URL required for migration');
const pool=new pg.Pool({connectionString:env.IDENTITY_DATABASE_URL,max:1});
try{await pool.query(await readFile(new URL('../migrations/001-artifacts.sql',import.meta.url),'utf8'));console.log('Identity protocol schema migration applied');}finally{await pool.end();}

} catch { console.error('Identity migration failed; verify protected configuration and database permissions'); process.exitCode=1; }
