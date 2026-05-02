-- OBSOLETE: Messages table does not use content/encryption_header/client_message_id;
-- use ciphertext + encrypted_header (see messages.sql). Do not run this migration.
--
-- Run in Supabase → SQL Editor when PostgREST returns PGRST204 for columns on
-- signal_protocol.messages (e.g. "Could not find the 'content' column").
--
-- Cause: the table was created earlier without those columns. CREATE TABLE IF NOT EXISTS
-- in messages.sql does not add new columns to an existing table.
--
-- After running, reload PostgREST cache:
--   notify pgrst, 'reload schema';

alter table signal_protocol.messages
  add column if not exists content text not null default '';

alter table signal_protocol.messages
  add column if not exists encryption_header jsonb;

alter table signal_protocol.messages
  add column if not exists client_message_id text;
