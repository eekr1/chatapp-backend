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
    client_msg_id TEXT,
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

  CREATE TABLE IF NOT EXISTS push_delivery_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    delivery_id UUID,
    event_type TEXT NOT NULL,
    target_user_id UUID,
    token_count INTEGER NOT NULL DEFAULT 0,
    sent_count INTEGER NOT NULL DEFAULT 0,
    failure_count INTEGER NOT NULL DEFAULT 0,
    invalid_token_count INTEGER NOT NULL DEFAULT 0,
    channel_id TEXT,
    meta JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ DEFAULT NOW()
  );

  CREATE TABLE IF NOT EXISTS support_reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    subject TEXT NOT NULL,
    description TEXT NOT NULL,
    contact_email TEXT,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    username_snapshot TEXT,
    app_version TEXT,
    platform TEXT,
    device_model TEXT,
    client_timestamp TIMESTAMPTZ,
    network_type TEXT,
    last_error_code TEXT,
    ip TEXT,
    user_agent TEXT,
    brevo_status TEXT NOT NULL DEFAULT 'pending',
    brevo_message_id TEXT,
    brevo_error TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
  );

  CREATE TABLE IF NOT EXISTS support_report_media (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    report_id UUID NOT NULL REFERENCES support_reports(id) ON DELETE CASCADE,
    mime_type TEXT NOT NULL,
    file_name TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    media_kind TEXT NOT NULL,
    data BYTEA NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
  );

  CREATE TABLE IF NOT EXISTS blocks (
    -- Intentionally no foreign keys: this table stores both auth users and anon users UUIDs.
    blocker_id UUID,
    blocked_id UUID,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    PRIMARY KEY (blocker_id, blocked_id)
  );

  CREATE TABLE IF NOT EXISTS app_settings (
    key TEXT PRIMARY KEY,
    value JSONB NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT NOW()
  );

  CREATE TABLE IF NOT EXISTS legal_acceptances (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    terms_version TEXT NOT NULL,
    privacy_version TEXT NOT NULL,
    accepted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ip TEXT,
    user_agent TEXT
  );

  CREATE TABLE IF NOT EXISTS account_deletion_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    username_snapshot TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'requested',
    requested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    reviewed_at TIMESTAMPTZ,
    reviewed_by TEXT,
    note TEXT
  );

  CREATE TABLE IF NOT EXISTS admin_action_audit (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_admin TEXT NOT NULL,
    action_type TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    entity_id TEXT,
    payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  );

  CREATE OR REPLACE FUNCTION prevent_admin_action_audit_mutation()
  RETURNS trigger
  LANGUAGE plpgsql
  AS $func$
  BEGIN
      RAISE EXCEPTION 'admin_action_audit is immutable';
  END;
  $func$;

  DROP TRIGGER IF EXISTS trg_admin_action_audit_immutable ON admin_action_audit;
  CREATE TRIGGER trg_admin_action_audit_immutable
  BEFORE UPDATE OR DELETE ON admin_action_audit
  FOR EACH ROW
  EXECUTE FUNCTION prevent_admin_action_audit_mutation();

  -- Migration
  DO $$
  DECLARE
      _blocks_fk RECORD;
      _deletion_fk RECORD;
  BEGIN
      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='users_anon' AND column_name='nickname') THEN
          ALTER TABLE users_anon ADD COLUMN nickname TEXT;
          ALTER TABLE users_anon ADD COLUMN nickname_set_at TIMESTAMPTZ;
      END IF;

      -- Shared blocks model: drop legacy FK constraints so auth + anon IDs can coexist.
      FOR _blocks_fk IN
          SELECT c.conname
          FROM pg_constraint c
          JOIN pg_class t ON t.oid = c.conrelid
          JOIN pg_namespace n ON n.oid = t.relnamespace
          WHERE c.contype = 'f'
            AND t.relname = 'blocks'
            AND n.nspname = current_schema()
      LOOP
          EXECUTE format('ALTER TABLE blocks DROP CONSTRAINT IF EXISTS %I', _blocks_fk.conname);
      END LOOP;

      -- Keep deletion request history after hard delete: drop any FK on account_deletion_requests.
      FOR _deletion_fk IN
          SELECT c.conname
          FROM pg_constraint c
          JOIN pg_class t ON t.oid = c.conrelid
          JOIN pg_namespace n ON n.oid = t.relnamespace
          WHERE c.contype = 'f'
            AND t.relname = 'account_deletion_requests'
            AND n.nspname = current_schema()
      LOOP
          EXECUTE format('ALTER TABLE account_deletion_requests DROP CONSTRAINT IF EXISTS %I', _deletion_fk.conname);
      END LOOP;
      
      CREATE INDEX IF NOT EXISTS idx_friendships_user ON friendships(user_id);
      CREATE INDEX IF NOT EXISTS idx_friendships_friend ON friendships(friend_user_id);

      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='messages' AND column_name='is_read') THEN
          ALTER TABLE messages ADD COLUMN is_read BOOLEAN DEFAULT FALSE;
      END IF;

      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='messages' AND column_name='media_id') THEN
          ALTER TABLE messages ADD COLUMN media_id UUID;
      END IF;

      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='messages' AND column_name='client_msg_id') THEN
          ALTER TABLE messages ADD COLUMN client_msg_id TEXT;
      END IF;

      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='push_devices' AND column_name='updated_at') THEN
          ALTER TABLE push_devices ADD COLUMN updated_at TIMESTAMPTZ DEFAULT NOW();
      END IF;

      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='push_devices' AND column_name='last_seen_at') THEN
          ALTER TABLE push_devices ADD COLUMN last_seen_at TIMESTAMPTZ DEFAULT NOW();
      END IF;

      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='push_delivery_logs' AND column_name='invalid_token_count') THEN
          ALTER TABLE push_delivery_logs ADD COLUMN invalid_token_count INTEGER NOT NULL DEFAULT 0;
      END IF;

      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='push_delivery_logs' AND column_name='meta') THEN
          ALTER TABLE push_delivery_logs ADD COLUMN meta JSONB DEFAULT '{}'::jsonb;
      END IF;

      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='support_reports' AND column_name='updated_at') THEN
          ALTER TABLE support_reports ADD COLUMN updated_at TIMESTAMPTZ DEFAULT NOW();
      END IF;

      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='support_reports' AND column_name='brevo_status') THEN
          ALTER TABLE support_reports ADD COLUMN brevo_status TEXT NOT NULL DEFAULT 'pending';
      END IF;

      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='support_reports' AND column_name='brevo_message_id') THEN
          ALTER TABLE support_reports ADD COLUMN brevo_message_id TEXT;
      END IF;

      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='support_reports' AND column_name='brevo_error') THEN
          ALTER TABLE support_reports ADD COLUMN brevo_error TEXT;
      END IF;

      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='support_report_media' AND column_name='created_at') THEN
          ALTER TABLE support_report_media ADD COLUMN created_at TIMESTAMPTZ DEFAULT NOW();
      END IF;

      CREATE INDEX IF NOT EXISTS idx_push_devices_user ON push_devices(user_id);
      CREATE INDEX IF NOT EXISTS idx_push_devices_active ON push_devices(is_active);
      CREATE INDEX IF NOT EXISTS idx_push_logs_created_at ON push_delivery_logs(created_at DESC);
      CREATE INDEX IF NOT EXISTS idx_push_logs_delivery_id ON push_delivery_logs(delivery_id);
      CREATE INDEX IF NOT EXISTS idx_push_logs_event_type ON push_delivery_logs(event_type);
      CREATE INDEX IF NOT EXISTS idx_support_reports_created_at ON support_reports(created_at DESC);
      CREATE INDEX IF NOT EXISTS idx_support_reports_subject ON support_reports(subject);
      CREATE INDEX IF NOT EXISTS idx_support_reports_brevo_status ON support_reports(brevo_status);
      CREATE INDEX IF NOT EXISTS idx_support_report_media_report_id ON support_report_media(report_id);
      CREATE INDEX IF NOT EXISTS idx_support_report_media_created_at ON support_report_media(created_at DESC);
      CREATE INDEX IF NOT EXISTS idx_blocks_blocker ON blocks(blocker_id);
      CREATE INDEX IF NOT EXISTS idx_blocks_blocked ON blocks(blocked_id);
      CREATE INDEX IF NOT EXISTS idx_legal_acceptances_user_accepted ON legal_acceptances(user_id, accepted_at DESC);
      CREATE INDEX IF NOT EXISTS idx_account_deletion_requests_status_requested ON account_deletion_requests(status, requested_at DESC);
      CREATE UNIQUE INDEX IF NOT EXISTS idx_account_deletion_requests_user_requested
        ON account_deletion_requests(user_id)
        WHERE status = 'requested';
      CREATE INDEX IF NOT EXISTS idx_admin_action_audit_created_at ON admin_action_audit(created_at DESC);
      CREATE INDEX IF NOT EXISTS idx_admin_action_audit_action_created ON admin_action_audit(action_type, created_at DESC);
      CREATE INDEX IF NOT EXISTS idx_admin_action_audit_actor_created ON admin_action_audit(actor_admin, created_at DESC);
      CREATE UNIQUE INDEX IF NOT EXISTS idx_messages_sender_client_msg
        ON messages(sender_id, client_msg_id)
        WHERE client_msg_id IS NOT NULL;

      INSERT INTO app_settings (key, value, updated_at)
      VALUES (
        'legal_content_v1',
        jsonb_build_object(
          'footer', jsonb_build_object(
            'tagline', 'Kimligini gizle, ozgurce konus.',
            'privacyLabel', 'Gizlilik Politikasi',
            'privacyUrl', '/privacy-policy',
            'termsLabel', 'Kullanim Sartlari',
            'termsUrl', '/terms-of-use'
          ),
          'versions', jsonb_build_object(
            'terms', 'v1',
            'privacy', 'v1'
          ),
          'documents', jsonb_build_object(
            'privacy', jsonb_build_object(
              'tr', jsonb_build_object(
                'title', 'Gizlilik Politikasi',
                'content', E'Bu metin admin panelinden guncellenebilir.\n\nKisisel verilerinizi yalnizca hizmetin sunulmasi, guvenlik ve yasal yukumlulukler kapsaminda isleriz.'
              ),
              'en', jsonb_build_object(
                'title', 'Privacy Policy',
                'content', E'This text can be updated from the admin panel.\n\nWe process your personal data only for service delivery, security, and legal compliance.'
              )
            ),
            'terms', jsonb_build_object(
              'tr', jsonb_build_object(
                'title', 'Kullanim Sartlari',
                'content', E'Bu metin admin panelinden guncellenebilir.\n\nUygulamayi kullanarak topluluk kurallarina ve gecerli mevzuata uygun davranmayi kabul edersiniz.'
              ),
              'en', jsonb_build_object(
                'title', 'Terms of Use',
                'content', E'This text can be updated from the admin panel.\n\nBy using the app, you agree to follow community rules and applicable laws.'
              )
            )
          )
        ),
        NOW()
      )
      ON CONFLICT (key) DO NOTHING;

      UPDATE app_settings
      SET
        value = jsonb_set(
          jsonb_set(
            value,
            '{versions,terms}',
            to_jsonb(COALESCE(NULLIF(value->'versions'->>'terms', ''), 'v1')),
            true
          ),
          '{versions,privacy}',
          to_jsonb(COALESCE(NULLIF(value->'versions'->>'privacy', ''), 'v1')),
          true
        ),
        updated_at = NOW()
      WHERE key = 'legal_content_v1'
        AND (
          value->'versions' IS NULL
          OR COALESCE(value->'versions'->>'terms', '') = ''
          OR COALESCE(value->'versions'->>'privacy', '') = ''
        );

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
  const client = await pool.connect();
  try {
    await client.query(createTablesQuery);
    console.log('Database tables ensured.');
  } catch (err) {
    console.error('Error creating tables:', err);
    throw err;
  } finally {
    client.release();
  }
};

module.exports = {
  pool,
  ensureTables
};
