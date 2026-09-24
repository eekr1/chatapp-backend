const { Pool } = require('pg');
const { createMigrationRunner } = require('./migrations/runner');
const { resolveDatabaseRuntimeConfig } = require('./utils/runtimeConfig');

const connectionString = process.env.DATABASE_URL;
if (!connectionString) {
  throw new Error('DATABASE_URL is required (set it in your environment).');
}

const databaseRuntimeConfig = resolveDatabaseRuntimeConfig(process.env);
const pool = new Pool({
  connectionString,
  ssl: {
    rejectUnauthorized: false
  },
  max: databaseRuntimeConfig.max,
  idleTimeoutMillis: databaseRuntimeConfig.idleTimeoutMillis,
  connectionTimeoutMillis: databaseRuntimeConfig.connectionTimeoutMillis,
  query_timeout: databaseRuntimeConfig.query_timeout,
  statement_timeout: databaseRuntimeConfig.statement_timeout
});

pool.on('error', (error) => {
  console.error('Database pool error.', { code: error?.code || 'DB_POOL_ERROR' });
});

// Table creation queries
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
    locale TEXT CHECK (locale IN ('tr', 'en')),
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

  CREATE TABLE IF NOT EXISTS notification_schedules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    duration_ms INTEGER NOT NULL DEFAULT 10000,
    schedule_time TEXT NOT NULL CHECK (schedule_time ~ '^(?:[01][0-9]|2[0-3]):[0-5][0-9]$'),
    timezone TEXT NOT NULL DEFAULT 'Europe/Istanbul',
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    last_sent_local_date TEXT,
    last_sent_at TIMESTAMPTZ,
    created_by TEXT DEFAULT 'admin',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  );

  CREATE TABLE IF NOT EXISTS legal_acceptances (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    terms_version TEXT NOT NULL,
    privacy_version TEXT NOT NULL,
    accepted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ip TEXT,
    user_agent TEXT,
    location_city TEXT,
    location_country TEXT,
    location_label TEXT,
    location_source TEXT,
    location_resolved_at TIMESTAMPTZ
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

  CREATE TABLE IF NOT EXISTS http_request_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    method TEXT NOT NULL,
    route TEXT NOT NULL,
    status INTEGER NOT NULL,
    duration_ms INTEGER NOT NULL,
    response_size_bytes INTEGER,
    request_id TEXT,
    sample_reason TEXT NOT NULL DEFAULT 'sampled',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  );

  CREATE TABLE IF NOT EXISTS http_request_metrics_minute (
    bucket_minute TIMESTAMPTZ NOT NULL,
    method TEXT NOT NULL,
    route TEXT NOT NULL,
    status_class TEXT NOT NULL,
    req_count INTEGER NOT NULL DEFAULT 0,
    error_count INTEGER NOT NULL DEFAULT 0,
    slow_count INTEGER NOT NULL DEFAULT 0,
    total_duration_ms BIGINT NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (bucket_minute, method, route, status_class)
  );

  CREATE TABLE IF NOT EXISTS behavior_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_name TEXT NOT NULL,
    user_id UUID,
    client_id TEXT,
    device_id TEXT,
    platform TEXT,
    match_id UUID,
    conversation_id UUID,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
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
      _reports_fk RECORD;
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

      -- Report model must support both auth users and anon users.
      -- Remove legacy foreign keys/strict nullability if they exist from old deployments.
      FOR _reports_fk IN
          SELECT c.conname
          FROM pg_constraint c
          JOIN pg_class t ON t.oid = c.conrelid
          JOIN pg_namespace n ON n.oid = t.relnamespace
          WHERE c.contype = 'f'
            AND t.relname = 'reports'
            AND n.nspname = current_schema()
      LOOP
          EXECUTE format('ALTER TABLE reports DROP CONSTRAINT IF EXISTS %I', _reports_fk.conname);
      END LOOP;
      ALTER TABLE reports ALTER COLUMN reporter_user_id DROP NOT NULL;
      ALTER TABLE reports ALTER COLUMN reported_user_id DROP NOT NULL;
      ALTER TABLE reports ALTER COLUMN conversation_id DROP NOT NULL;
      
      CREATE INDEX IF NOT EXISTS idx_friendships_user ON friendships(user_id);
      CREATE INDEX IF NOT EXISTS idx_friendships_friend ON friendships(friend_user_id);

      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='messages' AND column_name='is_read') THEN
          ALTER TABLE messages ADD COLUMN is_read BOOLEAN DEFAULT FALSE;
      END IF;

      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='profiles' AND column_name='locale') THEN
          ALTER TABLE profiles ADD COLUMN locale TEXT;
      END IF;
      BEGIN
        ALTER TABLE profiles DROP CONSTRAINT IF EXISTS profiles_locale_check;
        ALTER TABLE profiles
          ADD CONSTRAINT profiles_locale_check
          CHECK (locale IS NULL OR locale IN ('tr', 'en'));
      EXCEPTION WHEN OTHERS THEN
        RAISE NOTICE 'profiles locale check constraint update skipped: %', SQLERRM;
      END;

      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='messages' AND column_name='media_id') THEN
          ALTER TABLE messages ADD COLUMN media_id UUID;
      END IF;

      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='legal_acceptances' AND column_name='location_city') THEN
          ALTER TABLE legal_acceptances ADD COLUMN location_city TEXT;
      END IF;

      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='legal_acceptances' AND column_name='location_country') THEN
          ALTER TABLE legal_acceptances ADD COLUMN location_country TEXT;
      END IF;

      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='legal_acceptances' AND column_name='location_label') THEN
          ALTER TABLE legal_acceptances ADD COLUMN location_label TEXT;
      END IF;

      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='legal_acceptances' AND column_name='location_source') THEN
          ALTER TABLE legal_acceptances ADD COLUMN location_source TEXT;
      END IF;

      IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='legal_acceptances' AND column_name='location_resolved_at') THEN
          ALTER TABLE legal_acceptances ADD COLUMN location_resolved_at TIMESTAMPTZ;
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
      CREATE INDEX IF NOT EXISTS idx_users_created_at ON users(created_at DESC);
      CREATE INDEX IF NOT EXISTS idx_users_last_seen_at ON users(last_seen_at DESC);
      CREATE INDEX IF NOT EXISTS idx_sessions_user_created_at ON sessions(user_id, created_at DESC);
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
      CREATE INDEX IF NOT EXISTS idx_http_request_events_created_at ON http_request_events(created_at DESC);
      CREATE INDEX IF NOT EXISTS idx_http_request_events_route_created_at ON http_request_events(route, created_at DESC);
      CREATE INDEX IF NOT EXISTS idx_http_request_events_status_created_at ON http_request_events(status, created_at DESC);
      CREATE INDEX IF NOT EXISTS idx_http_request_metrics_minute_bucket ON http_request_metrics_minute(bucket_minute DESC);
      CREATE INDEX IF NOT EXISTS idx_http_request_metrics_minute_route_bucket ON http_request_metrics_minute(route, bucket_minute DESC);
      CREATE INDEX IF NOT EXISTS idx_behavior_events_created_at ON behavior_events(created_at DESC);
      CREATE INDEX IF NOT EXISTS idx_behavior_events_event_created_at ON behavior_events(event_name, created_at DESC);
      CREATE INDEX IF NOT EXISTS idx_behavior_events_user_created_at ON behavior_events(user_id, created_at DESC);
      CREATE INDEX IF NOT EXISTS idx_behavior_events_platform_created_at ON behavior_events(platform, created_at DESC);
      CREATE INDEX IF NOT EXISTS idx_behavior_events_match_created_at ON behavior_events(match_id, created_at DESC);
      CREATE INDEX IF NOT EXISTS idx_behavior_events_conversation_created_at ON behavior_events(conversation_id, created_at DESC);
      CREATE INDEX IF NOT EXISTS idx_notification_schedules_active_time ON notification_schedules(is_active, schedule_time);
      CREATE INDEX IF NOT EXISTS idx_notification_schedules_updated_at ON notification_schedules(updated_at DESC);

      -- One-time cleanup: remove admin panel traffic from telemetry history.
      DELETE FROM http_request_events WHERE route LIKE '/admin%';
      DELETE FROM http_request_metrics_minute WHERE route LIKE '/admin%';

      CREATE UNIQUE INDEX IF NOT EXISTS idx_messages_sender_client_msg
        ON messages(sender_id, client_msg_id)
        WHERE client_msg_id IS NOT NULL;

      INSERT INTO app_settings (key, value, updated_at)
      VALUES (
        'legal_content_v1',
        jsonb_build_object(
          'footer', jsonb_build_object(
            'urls', jsonb_build_object(
              'privacy', '/privacy-policy',
              'terms', '/terms-of-use'
            ),
            'tr', jsonb_build_object(
              'tagline', 'Kimligini gizle, ozgurce konus.',
              'privacyLabel', 'Gizlilik Politikasi',
              'termsLabel', 'Kullanim Sartlari'
            ),
            'en', jsonb_build_object(
              'tagline', 'Hide your identity, speak freely.',
              'privacyLabel', 'Privacy Policy',
              'termsLabel', 'Terms of Use'
            )
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
            ),
            'childSafety', jsonb_build_object(
              'tr', jsonb_build_object(
                'title', 'Cocuk Guvenligi Standartlari',
                'content', E'Bu metin admin panelinden guncellenebilir.\n\nTalkX, cocuklarin cinsel istismari ve suistimali (CSAE/CSAM) iceriklerini kesin olarak yasaklar. Bu tur icerikler veya davranislar raporlandiginda veya tespit edildiginde gerekli inceleme ve yaptirim adimlari uygulanir.'
              ),
              'en', jsonb_build_object(
                'title', 'Child Safety Standards',
                'content', E'This text can be updated from the admin panel.\n\nTalkX strictly prohibits child sexual abuse and exploitation (CSAE/CSAM) content. When such content or behavior is reported or detected, required review and enforcement actions are applied.'
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

      UPDATE app_settings
      SET
        value = jsonb_set(
          value,
          '{footer}',
          jsonb_build_object(
            'urls', jsonb_build_object(
              'privacy', COALESCE(NULLIF(value->'footer'->>'privacyUrl', ''), COALESCE(value->'footer'->'urls'->>'privacy', '/privacy-policy')),
              'terms', COALESCE(NULLIF(value->'footer'->>'termsUrl', ''), COALESCE(value->'footer'->'urls'->>'terms', '/terms-of-use'))
            ),
            'tr', jsonb_build_object(
              'tagline', COALESCE(NULLIF(value->'footer'->>'tagline', ''), COALESCE(value->'footer'->'tr'->>'tagline', 'Kimligini gizle, ozgurce konus.')),
              'privacyLabel', COALESCE(NULLIF(value->'footer'->>'privacyLabel', ''), COALESCE(value->'footer'->'tr'->>'privacyLabel', 'Gizlilik Politikasi')),
              'termsLabel', COALESCE(NULLIF(value->'footer'->>'termsLabel', ''), COALESCE(value->'footer'->'tr'->>'termsLabel', 'Kullanim Sartlari'))
            ),
            'en', jsonb_build_object(
              'tagline', COALESCE(value->'footer'->'en'->>'tagline', 'Hide your identity, speak freely.'),
              'privacyLabel', COALESCE(value->'footer'->'en'->>'privacyLabel', 'Privacy Policy'),
              'termsLabel', COALESCE(value->'footer'->'en'->>'termsLabel', 'Terms of Use')
            )
          ),
          true
        ),
        updated_at = NOW()
      WHERE key = 'legal_content_v1'
        AND (
          value->'footer'->'urls' IS NULL
          OR value->'footer'->'tr' IS NULL
          OR value->'footer'->'en' IS NULL
          OR (value->'footer' ? 'privacyUrl')
          OR (value->'footer' ? 'termsUrl')
          OR (value->'footer' ? 'tagline')
        );

      UPDATE app_settings
      SET
        value = jsonb_set(
          value,
          '{documents,childSafety}',
          jsonb_build_object(
            'tr', jsonb_build_object(
              'title', COALESCE(value->'documents'->'childSafety'->'tr'->>'title', 'Cocuk Guvenligi Standartlari'),
              'content', COALESCE(value->'documents'->'childSafety'->'tr'->>'content', E'Bu metin admin panelinden guncellenebilir.\n\nTalkX, cocuklarin cinsel istismari ve suistimali (CSAE/CSAM) iceriklerini kesin olarak yasaklar. Bu tur icerikler veya davranislar raporlandiginda veya tespit edildiginde gerekli inceleme ve yaptirim adimlari uygulanir.')
            ),
            'en', jsonb_build_object(
              'title', COALESCE(value->'documents'->'childSafety'->'en'->>'title', 'Child Safety Standards'),
              'content', COALESCE(value->'documents'->'childSafety'->'en'->>'content', E'This text can be updated from the admin panel.\n\nTalkX strictly prohibits child sexual abuse and exploitation (CSAE/CSAM) content. When such content or behavior is reported or detected, required review and enforcement actions are applied.')
            )
          ),
          true
        ),
        updated_at = NOW()
      WHERE key = 'legal_content_v1'
        AND (
          value->'documents' IS NULL
          OR value->'documents'->'childSafety' IS NULL
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


const migrations = Object.freeze([
  Object.freeze({
    version: '001',
    name: 'legacy_schema_baseline',
    sql: createTablesQuery
  }),
  Object.freeze({
    version: '002',
    name: 'connection_presence_leases',
    sql: `
      CREATE TABLE IF NOT EXISTS connection_leases (
        connection_id UUID PRIMARY KEY,
        user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        session_hash TEXT NOT NULL,
        device_hash TEXT NOT NULL,
        instance_id TEXT NOT NULL,
        generation INTEGER NOT NULL DEFAULT 1 CHECK (generation > 0),
        connected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        last_heartbeat_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        expires_at TIMESTAMPTZ NOT NULL
      );

      CREATE INDEX IF NOT EXISTS idx_connection_leases_user_expiry
        ON connection_leases(user_id, expires_at DESC);
      CREATE INDEX IF NOT EXISTS idx_connection_leases_expiry
        ON connection_leases(expires_at);
      CREATE INDEX IF NOT EXISTS idx_connection_leases_instance
        ON connection_leases(instance_id, expires_at DESC);
    `
  }),
  Object.freeze({
    version: '003',
    name: 'wave06_data_lifecycle',
    sql: `
      CREATE TABLE IF NOT EXISTS user_match_country (
        user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
        country_code CHAR(2),
        source TEXT NOT NULL,
        status TEXT NOT NULL CHECK (status IN ('eligible', 'stale', 'unavailable', 'disputed')),
        confidence TEXT NOT NULL CHECK (confidence IN ('policy_verified', 'inferred', 'unknown')),
        source_observed_at TIMESTAMPTZ,
        resolved_at TIMESTAMPTZ,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        policy_version TEXT NOT NULL,
        CHECK (country_code IS NULL OR country_code ~ '^[A-Z]{2}$'),
        CHECK (status <> 'eligible' OR (country_code IS NOT NULL AND confidence = 'policy_verified'))
      );
      CREATE INDEX IF NOT EXISTS idx_user_match_country_status_updated
        ON user_match_country(status, updated_at DESC);

      ALTER TABLE account_deletion_requests
        ALTER COLUMN user_id DROP NOT NULL,
        ALTER COLUMN username_snapshot DROP NOT NULL,
        ADD COLUMN IF NOT EXISTS idempotency_key TEXT,
        ADD COLUMN IF NOT EXISTS policy_version TEXT NOT NULL DEFAULT 'talkx-data-policy-v1',
        ADD COLUMN IF NOT EXISTS processing_started_at TIMESTAMPTZ,
        ADD COLUMN IF NOT EXISTS completed_at TIMESTAMPTZ,
        ADD COLUMN IF NOT EXISTS failure_code TEXT,
        ADD COLUMN IF NOT EXISTS receipt JSONB,
        ADD COLUMN IF NOT EXISTS runtime_ack JSONB;
      DROP INDEX IF EXISTS idx_account_deletion_requests_user_requested;
      CREATE UNIQUE INDEX IF NOT EXISTS idx_account_deletion_requests_user_open
        ON account_deletion_requests(user_id)
        WHERE status IN ('requested', 'reviewing', 'approved', 'processing', 'failed_retryable');
      CREATE UNIQUE INDEX IF NOT EXISTS idx_account_deletion_requests_idempotency
        ON account_deletion_requests(user_id, idempotency_key)
        WHERE idempotency_key IS NOT NULL;

      CREATE TABLE IF NOT EXISTS account_deletion_steps (
        request_id UUID NOT NULL REFERENCES account_deletion_requests(id) ON DELETE CASCADE,
        step_key TEXT NOT NULL,
        status TEXT NOT NULL CHECK (status IN ('pending', 'processing', 'completed', 'failed_retryable', 'blocked')),
        cursor JSONB,
        affected_count INTEGER NOT NULL DEFAULT 0 CHECK (affected_count >= 0),
        result JSONB NOT NULL DEFAULT '{}'::jsonb,
        started_at TIMESTAMPTZ,
        completed_at TIMESTAMPTZ,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        PRIMARY KEY (request_id, step_key)
      );

      CREATE TABLE IF NOT EXISTS erasure_journal (
        erasure_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        request_id UUID NOT NULL UNIQUE REFERENCES account_deletion_requests(id) ON DELETE RESTRICT,
        subject_ref TEXT NOT NULL,
        key_version TEXT NOT NULL,
        policy_version TEXT NOT NULL,
        step_checksum TEXT NOT NULL,
        completed_at TIMESTAMPTZ NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );

      ALTER TABLE support_reports
        ADD COLUMN IF NOT EXISTS submission_id TEXT,
        ADD COLUMN IF NOT EXISTS submission_scope_hash TEXT,
        ADD COLUMN IF NOT EXISTS record_status TEXT NOT NULL DEFAULT 'received',
        ADD COLUMN IF NOT EXISTS delivery_status TEXT NOT NULL DEFAULT 'pending',
        ADD COLUMN IF NOT EXISTS owner_admin TEXT,
        ADD COLUMN IF NOT EXISTS duplicate_group_ref TEXT,
        ADD COLUMN IF NOT EXISTS resolved_at TIMESTAMPTZ;
      UPDATE support_reports
      SET delivery_status = CASE
        WHEN brevo_status IN ('sent', 'failed', 'pending') THEN brevo_status
        ELSE 'unknown'
      END
      WHERE delivery_status = 'pending';
      DROP INDEX IF EXISTS idx_support_reports_submission_id;
      CREATE UNIQUE INDEX IF NOT EXISTS idx_support_reports_submission_scope
        ON support_reports(submission_scope_hash, submission_id)
        WHERE submission_id IS NOT NULL AND submission_scope_hash IS NOT NULL;
      CREATE INDEX IF NOT EXISTS idx_support_reports_record_status_updated
        ON support_reports(record_status, updated_at DESC);
    `
  }),
  Object.freeze({
    version: '004',
    name: 'wave09_match_conversation_identity',
    sql: `
      ALTER TABLE conversations
        ADD COLUMN IF NOT EXISTS match_id UUID;
      CREATE UNIQUE INDEX IF NOT EXISTS idx_conversations_match_id_unique
        ON conversations(match_id)
        WHERE match_id IS NOT NULL;
    `
  }),
  Object.freeze({
    version: '005',
    name: 'wave11_media_trust_lifecycle',
    sql: `
      ALTER TABLE ephemeral_media
        ALTER COLUMN media_data DROP NOT NULL,
        ADD COLUMN IF NOT EXISTS conversation_id UUID REFERENCES conversations(id) ON DELETE CASCADE,
        ADD COLUMN IF NOT EXISTS client_msg_id TEXT,
        ADD COLUMN IF NOT EXISTS message_id UUID REFERENCES messages(id) ON DELETE SET NULL,
        ADD COLUMN IF NOT EXISTS content_type TEXT,
        ADD COLUMN IF NOT EXISTS byte_size INTEGER,
        ADD COLUMN IF NOT EXISTS width INTEGER,
        ADD COLUMN IF NOT EXISTS height INTEGER,
        ADD COLUMN IF NOT EXISTS content_fingerprint TEXT,
        ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'available',
        ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ,
        ADD COLUMN IF NOT EXISTS consumed_at TIMESTAMPTZ,
        ADD COLUMN IF NOT EXISTS purged_at TIMESTAMPTZ,
        ADD COLUMN IF NOT EXISTS revision INTEGER NOT NULL DEFAULT 1,
        ADD COLUMN IF NOT EXISTS policy_version TEXT NOT NULL DEFAULT 'talkx-media-policy-wave11-v1';
      UPDATE ephemeral_media
      SET expires_at=COALESCE(expires_at,created_at + INTERVAL '7 days'),
          status=CASE WHEN status IS NULL THEN 'available' ELSE status END;
      ALTER TABLE ephemeral_media
        ALTER COLUMN expires_at SET DEFAULT (NOW() + INTERVAL '7 days'),
        ALTER COLUMN expires_at SET NOT NULL;
      CREATE UNIQUE INDEX IF NOT EXISTS idx_ephemeral_media_sender_client_msg
        ON ephemeral_media(sender_id,client_msg_id) WHERE client_msg_id IS NOT NULL;
      CREATE INDEX IF NOT EXISTS idx_ephemeral_media_cleanup
        ON ephemeral_media(status,expires_at);
      CREATE INDEX IF NOT EXISTS idx_ephemeral_media_message
        ON ephemeral_media(message_id);

      ALTER TABLE reports
        ADD COLUMN IF NOT EXISTS command_id TEXT,
        ADD COLUMN IF NOT EXISTS reason_category TEXT,
        ADD COLUMN IF NOT EXISTS subject_message_id UUID REFERENCES messages(id) ON DELETE SET NULL,
        ADD COLUMN IF NOT EXISTS subject_media_id UUID REFERENCES ephemeral_media(id) ON DELETE SET NULL,
        ADD COLUMN IF NOT EXISTS evidence_availability TEXT NOT NULL DEFAULT 'metadata_only',
        ADD COLUMN IF NOT EXISTS moderation_status TEXT NOT NULL DEFAULT 'received',
        ADD COLUMN IF NOT EXISTS owner_admin TEXT,
        ADD COLUMN IF NOT EXISTS protocol_version TEXT NOT NULL DEFAULT 'wave11-v1';
      CREATE UNIQUE INDEX IF NOT EXISTS idx_reports_reporter_command
        ON reports(reporter_user_id,command_id) WHERE command_id IS NOT NULL;
      CREATE INDEX IF NOT EXISTS idx_reports_subject_media
        ON reports(subject_media_id,created_at DESC);
    `
  }),
  Object.freeze({
    version: '006',
    name: 'wave12_legal_acceptance_identity',
    sql: `
      ALTER TABLE legal_acceptances
        ADD COLUMN IF NOT EXISTS release_id TEXT,
        ADD COLUMN IF NOT EXISTS release_revision TEXT,
        ADD COLUMN IF NOT EXISTS requirement_fingerprint TEXT,
        ADD COLUMN IF NOT EXISTS command_id TEXT,
        ADD COLUMN IF NOT EXISTS locale TEXT;
      CREATE UNIQUE INDEX IF NOT EXISTS idx_legal_acceptance_requirement
        ON legal_acceptances(user_id,requirement_fingerprint)
        WHERE requirement_fingerprint IS NOT NULL;
      CREATE UNIQUE INDEX IF NOT EXISTS idx_legal_acceptance_command
        ON legal_acceptances(user_id,command_id)
        WHERE command_id IS NOT NULL;
      CREATE INDEX IF NOT EXISTS idx_legal_acceptance_release
        ON legal_acceptances(release_id,accepted_at DESC)
        WHERE release_id IS NOT NULL;
    `
  })
]);

const migrationRunner = createMigrationRunner({ pool, migrations });

const runMigrations = async () => {
  const state = await migrationRunner.run();
  console.log('Database migrations current.', {
    currentHead: state.currentHead,
    expectedHead: state.expectedHead
  });
  return state;
};

const ensureTables = runMigrations;

const getDatabaseReadiness = async () => {
  let client;
  try {
    client = await pool.connect();
    const schemaResult = await client.query({
      text: 'SELECT current_schema() AS schema, NOW() AS server_time',
      query_timeout: databaseRuntimeConfig.readinessTimeoutMs
    });
    const schema = String(schemaResult.rows?.[0]?.schema || 'unknown');
    if (schema !== 'public') {
      return {
        ok: false,
        code: 'DB_SCHEMA_INVALID',
        schema,
        migrationHead: null,
        expectedMigrationHead: migrationRunner.expectedHead
      };
    }

    const migrationState = await migrationRunner.inspect(client);
    if (!migrationState.ok) {
      return {
        ok: false,
        code: migrationState.checksumMismatch.length ? 'MIGRATION_CHECKSUM_MISMATCH' : 'MIGRATION_NOT_CURRENT',
        schema,
        migrationHead: migrationState.currentHead,
        expectedMigrationHead: migrationState.expectedHead
      };
    }

    return {
      ok: true,
      code: 'OK',
      schema,
      migrationHead: migrationState.currentHead,
      expectedMigrationHead: migrationState.expectedHead
    };
  } catch (error) {
    const timeoutCodes = new Set(['57014', 'ETIMEDOUT', 'ECONNRESET']);
    return {
      ok: false,
      code: timeoutCodes.has(error?.code) ? 'DB_TIMEOUT' : 'DB_UNAVAILABLE',
      schema: 'unknown',
      migrationHead: null,
      expectedMigrationHead: migrationRunner.expectedHead
    };
  } finally {
    client?.release();
  }
};

const closeDatabase = () => pool.end();

module.exports = {
  pool,
  ensureTables,
  runMigrations,
  getDatabaseReadiness,
  closeDatabase,
  databaseRuntimeConfig,
  migrations
};

