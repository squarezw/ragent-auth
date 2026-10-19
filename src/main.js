import { readConfig } from './config.js';
import { postgresAdapter } from './postgres-adapter.js';
import { createIdentityServer } from './provider.js';
import { loadSecretFiles } from './secret-files.js';
try {
const config = readConfig(loadSecretFiles());
if (!config) { console.log('Identity provider disabled'); } else {
  const storage = await postgresAdapter(config.databaseUrl);
  const {server} = createIdentityServer(config,{Adapter:storage.Adapter});
  server.listen(config.port,config.bindHost,()=>console.log('Identity provider listening'));
  const stop = () => server.close(async()=>{await storage.close();process.exit(0);});
  process.on('SIGTERM',stop);process.on('SIGINT',stop);
}

} catch { console.error('Identity provider startup failed; verify protected configuration and storage'); process.exitCode=1; }
