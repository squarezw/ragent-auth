import {openSync, readFileSync, closeSync, constants, fstatSync} from 'node:fs';
export const SECRET_KEYS = ['IDENTITY_SERVICE_TOKEN','IDENTITY_COOKIE_KEYS','IDENTITY_JWKS','IDENTITY_CLIENTS','IDENTITY_DATABASE_URL'];
// Never interpolate a path, file content or upstream exception into an error.
export function loadSecretFiles(env = process.env) {
  const result = {...env};
  if (env.IDENTITY_ENABLED !== 'true') return result;
  for (const key of SECRET_KEYS) {
    const path = env[`${key}_FILE`];
    if (!path) continue;
    if (env[key]) throw new Error(`Conflicting secret sources for ${key}`);
    let fd;
    try {
      fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
      const stat = fstatSync(fd);
      if (!stat.isFile() || stat.size > 1024 * 1024 || (stat.mode & 0o027) || ![0,process.getuid?.()].includes(stat.uid)) throw new Error();
      const value = readFileSync(fd,'utf8').trim();
      if (!value || value.includes('\u0000')) throw new Error();
      result[key] = value;
    } catch { throw new Error(`Cannot read protected file for ${key}`); }
    finally { if (fd !== undefined) closeSync(fd); }
  }
  return result;
}
