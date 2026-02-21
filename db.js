const { Pool } = require('pg');

const connectionString = process.env.DATABASE_URL;
if (!connectionString) {
  throw new Error('DATABASE_URL is required (set it in your environment).');
}

const pool = new Pool({
  connectionString,
  ssl: {
    rejectUnauthorized: false
  } // Render postgres requires SSL
});

// Tablo oluşturma sorguları
const createTablesQuery = `
  CREATE EXTENSION IF NOT EXISTS "pgcrypto";

  -- V2 Auth Tables
  CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ DEFAULT NOW(),
    status TEXT DEFAULT 'active'
  );

  CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    device_id TEXT, 
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
  );

  CREATE TABLE IF NOT EXISTS profiles (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    display_name TEXT,
    avatar_url TEXT,
    bio TEXT,
    tags JSONB DEFAULT '[]',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
  );

  CREATE TABLE IF NOT EXISTS friendships (
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    friend_user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    status TEXT NOT NULL DEFAULT 'pending', 
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    PRIMARY KEY (user_id, friend_user_id)
  );

  -- Legacy Tables
  CREATE TABLE IF NOT EXISTS users_anon (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id TEXT UNIQUE NOT NULL,
    username TEXT,
    nickname TEXT,
    nickname_set_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ DEFAULT NOW(),
    last_ip TEXT
  );

  CREATE TABLE IF NOT EXISTS conversations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_a_id UUID, 
    user_b_id UUID,
    started_at TIMESTAMPTZ DEFAULT NOW(),
    ended_at TIMESTAMPTZ,
    ended_reason TEXT
  );

  CREATE TABLE IF NOT EXISTS reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    reporter_user_id UUID,
    reported_user_id UUID,
    conversation_id UUID,
    reason TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    meta JSONB
  );

  CREATE TABLE IF NOT EXISTS bans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID,
    ban_type TEXT NOT NULL,
    ban_until TIMESTAMPTZ,
    reason TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    created_by TEXT DEFAULT 'auto'
  );

  CREATE TABLE IF NOT EXISTS ephemeral_media (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    sender_id UUID REFERENCES users(id) ON DELETE CASCADE,
    receiver_id UUID REFERENCES users(id) ON DELETE CASCADE,
    media_data TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
  );

  CREATE TABLE IF NOT EXISTS messages (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    conversation_id UUID REFERENCES conversations(id) ON DELETE CASCADE,
    sender_id UUID REFERENCES users(id),
    text TEXT NOT NULL,
    msg_type TEXT DEFAULT 'text',
    is_read BOOLEAN DEFAULT FALSE,
    media_id UUID,
    created_at TIMESTAMPTZ DEFAULT NOW()
  );

  CREATE TABLE IF NOT EXISTS push_devices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    device_id TEXT,
    platform TEXT NOT NULL DEFAULT 'android',
    push_token TEXT UNIQUE NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ DEFAULT NOW()
  );

  CREATE TABLE IF NOT EXISTS blocks (
    blocker_id UUID,
    blocked_id UUID,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    PRIMARY KEY (blocker_id, blocked_id)
  );

  -- Migration
  DO $$
  BEGIN
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='users_anon' AND column_name='nickname') THEN
          ALTER TABLE users_anon ADD COLUMN nickname TEXT;
          ALTER TABLE users_anon ADD COLUMN nickname_set_at TIMESTAMPTZ;
      END IF;
      
      CREATE INDEX IF NOT EXISTS idx_friendships_user ON friendships(user_id);
      CREATE INDEX IF NOT EXISTS idx_friendships_friend ON friendships(friend_user_id);

      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='messages' AND column_name='is_read') THEN
          ALTER TABLE messages ADD COLUMN is_read BOOLEAN DEFAULT FALSE;
      END IF;

      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='messages' AND column_name='media_id') THEN
          ALTER TABLE messages ADD COLUMN media_id UUID;
      END IF;

      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='push_devices' AND column_name='updated_at') THEN
          ALTER TABLE push_devices ADD COLUMN updated_at TIMESTAMPTZ DEFAULT NOW();
      END IF;

      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='push_devices' AND column_name='last_seen_at') THEN
          ALTER TABLE push_devices ADD COLUMN last_seen_at TIMESTAMPTZ DEFAULT NOW();
      END IF;

      CREATE INDEX IF NOT EXISTS idx_push_devices_user ON push_devices(user_id);
      CREATE INDEX IF NOT EXISTS idx_push_devices_active ON push_devices(is_active);

      -- V13 Fix: Drop legacy FK constraints on conversations to allow Auth Users
      BEGIN
        ALTER TABLE conversations DROP CONSTRAINT IF EXISTS conversations_user_a_id_fkey;
        ALTER TABLE conversations DROP CONSTRAINT IF EXISTS conversations_user_b_id_fkey;
      EXCEPTION WHEN OTHERS THEN 
        RAISE NOTICE 'Constraint drop failed or already gone %', SQLERRM;
      END;
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
