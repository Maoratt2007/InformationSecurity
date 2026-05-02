-- OBSOLETE: The canonical messages schema uses ciphertext + encrypted_header only
-- (see backend-fastapi/sql/messages.sql and supabase/migrations/). Do not run this
-- unless you intentionally add a client_message_id column for dedup.
--
-- Run in Supabase → SQL Editor if you already have signal_protocol.messages
-- but see: PGRST204 "Could not find the 'client_message_id' column"
-- (e.g. table was created before that column was added to messages.sql)

alter table signal_protocol.messages
  add column if not exists client_message_id text;

-- Optional: help idempotent client sends (uncomment if you use unique on this pair)
-- create unique index if not exists messages_client_dedup_idx
--   on signal_protocol.messages (sender_id, client_message_id)
--   where client_message_id is not null;
