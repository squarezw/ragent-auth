import pg from 'pg';
export async function postgresAdapter(url) {
  const pool = new pg.Pool({ connectionString: url, max: 5 });
  // Schema is created only by the explicit migration command, never at server startup.
  await pool.query('SELECT 1 FROM identity_oidc.artifacts LIMIT 0');
  const cleanup = setInterval(() => { pool.query('DELETE FROM identity_oidc.artifacts WHERE expires_at <= NOW()').catch(() => {}); }, 60000);
  cleanup.unref();
  class Adapter {
    constructor(name) { this.name = name; }
    async upsert(id, payload, expiresIn) {
      if (!(expiresIn > 0)) throw new Error('Artifact TTL required');
      await pool.query(`INSERT INTO identity_oidc.artifacts VALUES($1,$2,$3,NOW()+$4*interval '1 second')
        ON CONFLICT(model,id) DO UPDATE SET payload=EXCLUDED.payload,expires_at=EXCLUDED.expires_at`, [this.name,id,payload,expiresIn]);
    }
    async find(id) { return (await pool.query('SELECT payload FROM identity_oidc.artifacts WHERE model=$1 AND id=$2 AND expires_at>NOW()', [this.name,id])).rows[0]?.payload; }
    async findByUid(uid) { return (await pool.query("SELECT payload FROM identity_oidc.artifacts WHERE model=$1 AND payload->>'uid'=$2 AND expires_at>NOW()", [this.name,uid])).rows[0]?.payload; }
    async consume(id) {
      const result = await pool.query(`UPDATE identity_oidc.artifacts SET payload=jsonb_set(payload,'{consumed}',to_jsonb(EXTRACT(EPOCH FROM NOW())::bigint)) WHERE model=$1 AND id=$2 AND expires_at>NOW() AND NOT(payload ? 'consumed')`, [this.name,id]);
      if (!result.rowCount) throw new Error('Artifact expired or consumed');
    }
    async destroy(id) { await pool.query('DELETE FROM identity_oidc.artifacts WHERE model=$1 AND id=$2',[this.name,id]); }
    async revokeByGrantId(id) { await pool.query("DELETE FROM identity_oidc.artifacts WHERE payload->>'grantId'=$1",[id]); }
  }
  return { Adapter, close: async () => {clearInterval(cleanup); await pool.end();} };
}
