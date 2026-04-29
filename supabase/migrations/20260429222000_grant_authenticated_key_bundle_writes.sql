-- Allow authenticated users to upload their public X3DH registration bundle.
-- Private keys are never stored in Supabase; only public Identity, Signed Pre-Key, and One-Time Pre-Keys are written.

grant insert, update on signal_protocol.identity_keys to authenticated;
grant insert, update on signal_protocol.pre_keys to authenticated;
grant insert, update on signal_protocol.one_time_pre_keys to authenticated;
