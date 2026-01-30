const { Pool } = require('pg');

const connectionString = process.env.DATABASE_URL || 'postgresql://chatapp_reports_user:praxPsnoB7jV3sqj1VjG4OUCyzIhcs3x@dpg-d5udd494tr6s73crvtng-a.frankfurt-postgres.render.com/chatapp_reports?ssl=true';

const pool = new Pool({
  connectionString,
  ssl: {
    rejectUnauthorized: false
  } // Render postgres requires SSL
});

// Tablo oluşturma sorguları
const createTablesQuery = `
  CREATE EXTENSION IF NOT EXISTS "pgcrypto";

  CREATE TABLE IF NOT EXISTS users_anon (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id TEXT UNIQUE NOT NULL,
    username TEXT, -- Old field, keeping for safety but moving to nickname
    nickname TEXT, -- V6: Persistent display name
    nickname_set_at TIMESTAMPTZ, -- V6
    created_at TIMESTAMPTZ DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ DEFAULT NOW(),
    last_ip TEXT
  );

  CREATE TABLE IF NOT EXISTS conversations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_a_id UUID REFERENCES users_anon(id),
    user_b_id UUID REFERENCES users_anon(id),
    started_at TIMESTAMPTZ DEFAULT NOW(),
    ended_at TIMESTAMPTZ,
    ended_reason TEXT
  );

  CREATE TABLE IF NOT EXISTS reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    reporter_user_id UUID REFERENCES users_anon(id),
    reported_user_id UUID REFERENCES users_anon(id),
    conversation_id UUID REFERENCES conversations(id),
    reason TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    meta JSONB
  );

  CREATE TABLE IF NOT EXISTS bans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users_anon(id),
    ban_type TEXT NOT NULL, -- 'temp' | 'perm' | 'shadow'
    ban_until TIMESTAMPTZ,
    reason TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    created_by TEXT DEFAULT 'auto'
  );

  CREATE TABLE IF NOT EXISTS blocks (
    blocker_id UUID REFERENCES users_anon(id),
    blocked_id UUID REFERENCES users_anon(id),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    PRIMARY KEY (blocker_id, blocked_id)
  );

  -- Migration for existing tables (if nickname column missing)
  DO $$
  BEGIN
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='users_anon' AND column_name='nickname') THEN
          ALTER TABLE users_anon ADD COLUMN nickname TEXT;
          ALTER TABLE users_anon ADD COLUMN nickname_set_at TIMESTAMPTZ;
      END IF;
  END
  $$;
`;

const ensureTables = async () => {
  try {
    const client = await pool.connect();
    await client.query(createTablesQuery);
    console.log('Database tables ensured.');
    client.release();
  } catch (err) {
    console.error('Error creating tables:', err);
  }
};

module.exports = {
  pool,
  ensureTables
};
