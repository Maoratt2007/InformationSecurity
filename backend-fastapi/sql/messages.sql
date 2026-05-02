-- Run once in Supabase SQL editor (schema: signal_protocol).
-- Matches supabase/migrations/20260429130000_signal_protocol_schema.sql (messages table).
--
-- After DDL changes, reload PostgREST schema cache:
--   notify pgrst, 'reload schema';

create table if not exists signal_protocol.messages (
  id uuid primary key default gen_random_uuid(),
  sender_id uuid not null references signal_protocol.users(id) on delete cascade,
  recipient_id uuid not null references signal_protocol.users(id) on delete cascade,
  encrypted_header jsonb not null,
  ciphertext text not null,
  delivered_at timestamptz,
  created_at timestamptz not null default now()
);

create index if not exists idx_signal_messages_recipient_pending
  on signal_protocol.messages (recipient_id)
  where delivered_at is null;
