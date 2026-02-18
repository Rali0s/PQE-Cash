import { Pool } from 'pg';
import Redis from 'ioredis';

export class DurableStorage {
  constructor({ postgresUrl, redisUrl }) {
    this.pg = new Pool({ connectionString: postgresUrl });
    this.redis = new Redis(redisUrl, { lazyConnect: true, maxRetriesPerRequest: 3 });
  }

  async init() {
    await this.redis.connect();

    await this.pg.query(`
      CREATE TABLE IF NOT EXISTS relayer_quotes (
        quote_id UUID PRIMARY KEY,
        pool TEXT NOT NULL,
        fee_bps INT NOT NULL,
        fee TEXT NOT NULL,
        chain_id INT NOT NULL,
        expires_at BIGINT NOT NULL,
        signature TEXT NOT NULL,
        created_at BIGINT NOT NULL
      )
    `);

    await this.pg.query(`
      CREATE TABLE IF NOT EXISTS relayer_jobs (
        job_id UUID PRIMARY KEY,
        status TEXT NOT NULL,
        tx_hash TEXT,
        block_number BIGINT,
        error TEXT,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL
      )
    `);

    await this.pg.query(`CREATE INDEX IF NOT EXISTS relayer_quotes_expires_at_idx ON relayer_quotes (expires_at)`);
    await this.pg.query(`CREATE INDEX IF NOT EXISTS relayer_jobs_status_idx ON relayer_jobs (status)`);
  }

  async ping() {
    await this.redis.ping();
    await this.pg.query('SELECT 1');
  }

  async close() {
    await this.redis.quit();
    await this.pg.end();
  }

  async createSession(sessionId, data, ttlMs) {
    const key = `session:${sessionId}`;
    await this.redis.set(key, JSON.stringify(data), 'PX', ttlMs);
  }

  async getSession(sessionId) {
    const key = `session:${sessionId}`;
    const raw = await this.redis.get(key);
    return raw ? JSON.parse(raw) : null;
  }

  async deleteSession(sessionId) {
    await this.redis.del(`session:${sessionId}`);
  }

  async useNonce(sessionId, nonce, ttlMs) {
    const key = `nonce:${sessionId}:${nonce}`;
    const result = await this.redis.set(key, '1', 'NX', 'PX', ttlMs);
    return result === 'OK';
  }

  async consumeRateLimit(bucket, subject, limit, windowMs) {
    const key = `rl:${bucket}:${encodeURIComponent(subject)}`;
    const count = await this.redis.incr(key);
    if (count === 1) {
      await this.redis.pexpire(key, windowMs);
    }
    return {
      allowed: count <= limit,
      count,
      remaining: Math.max(0, limit - count)
    };
  }

  async incrementAbuse(subject, ttlMs, amount = 1) {
    const key = `abuse:${encodeURIComponent(subject)}`;
    const score = await this.redis.incrby(key, amount);
    const ttl = await this.redis.pttl(key);
    if (ttl < 0) {
      await this.redis.pexpire(key, ttlMs);
    }
    return score;
  }

  async getAbuseScore(subject) {
    const key = `abuse:${encodeURIComponent(subject)}`;
    const score = await this.redis.get(key);
    return Number(score || 0);
  }

  async putQuote(quote) {
    const q = `
      INSERT INTO relayer_quotes (quote_id, pool, fee_bps, fee, chain_id, expires_at, signature, created_at)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
      ON CONFLICT (quote_id)
      DO UPDATE SET
        pool = EXCLUDED.pool,
        fee_bps = EXCLUDED.fee_bps,
        fee = EXCLUDED.fee,
        chain_id = EXCLUDED.chain_id,
        expires_at = EXCLUDED.expires_at,
        signature = EXCLUDED.signature,
        created_at = EXCLUDED.created_at
    `;
    await this.pg.query(q, [
      quote.quoteId,
      quote.pool,
      quote.feeBps,
      quote.fee,
      quote.chainId,
      quote.expiresAt,
      quote.signature,
      quote.createdAt
    ]);
  }

  async getQuote(quoteId) {
    const { rows } = await this.pg.query('SELECT * FROM relayer_quotes WHERE quote_id = $1', [quoteId]);
    if (rows.length === 0) return null;
    const row = rows[0];
    return {
      quoteId: row.quote_id,
      pool: row.pool,
      feeBps: row.fee_bps,
      fee: row.fee,
      chainId: row.chain_id,
      expiresAt: Number(row.expires_at),
      signature: row.signature,
      createdAt: Number(row.created_at)
    };
  }

  async putJob(jobId, data) {
    const now = Date.now();
    const q = `
      INSERT INTO relayer_jobs (job_id, status, tx_hash, block_number, error, created_at, updated_at)
      VALUES ($1, $2, $3, $4, $5, $6, $7)
      ON CONFLICT (job_id)
      DO UPDATE SET
        status = EXCLUDED.status,
        tx_hash = EXCLUDED.tx_hash,
        block_number = EXCLUDED.block_number,
        error = EXCLUDED.error,
        updated_at = EXCLUDED.updated_at
    `;
    await this.pg.query(q, [
      jobId,
      data.status,
      data.txHash ?? null,
      data.blockNumber ?? null,
      data.error ?? null,
      data.createdAt ?? now,
      now
    ]);
  }

  async getJob(jobId) {
    const { rows } = await this.pg.query('SELECT * FROM relayer_jobs WHERE job_id = $1', [jobId]);
    if (rows.length === 0) return null;
    const row = rows[0];
    return {
      status: row.status,
      txHash: row.tx_hash,
      blockNumber: row.block_number ? Number(row.block_number) : undefined,
      error: row.error,
      createdAt: Number(row.created_at),
      updatedAt: Number(row.updated_at)
    };
  }

  async pruneExpired({ nowMs, quoteRetentionMs, jobRetentionMs }) {
    const quoteCutoff = nowMs - quoteRetentionMs;
    const jobCutoff = nowMs - jobRetentionMs;

    await this.pg.query('DELETE FROM relayer_quotes WHERE expires_at < $1', [quoteCutoff]);
    await this.pg.query(
      "DELETE FROM relayer_jobs WHERE updated_at < $1 AND status IN ('confirmed', 'failed')",
      [jobCutoff]
    );
  }
}
