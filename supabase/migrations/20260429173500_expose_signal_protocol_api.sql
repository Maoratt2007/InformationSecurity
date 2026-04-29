-- Expose the isolated Signal schema through Supabase PostgREST.
-- Without this, the browser SDK cannot read or write signal_protocol tables.

alter role authenticator set pgrst.db_schemas = 'public, graphql_public, signal_protocol';
notify pgrst, 'reload config';
notify pgrst, 'reload schema';
