-- App profiles live in signal_protocol.users, while passwords remain in Supabase Auth.
-- The frontend needs API access to create/read profiles after registration and sign-in.

alter table signal_protocol.users
add column if not exists email text unique;

update signal_protocol.users
set email = lower(username || '@example.local')
where email is null;

alter table signal_protocol.users
alter column email set not null;

grant usage on schema signal_protocol to anon, authenticated;
grant select, insert, update on signal_protocol.users to anon, authenticated;
grant select on signal_protocol.identity_keys to anon, authenticated;
grant select on signal_protocol.pre_keys to anon, authenticated;
grant select on signal_protocol.one_time_pre_keys to anon, authenticated;
grant select, insert, update on signal_protocol.messages to anon, authenticated;
grant select, insert, update on signal_protocol.sessions to anon, authenticated;

insert into signal_protocol.users (id, username, email)
values
    ('22222222-2222-2222-2222-222222222222', 'Bob', 'bob@example.local'),
    ('33333333-3333-3333-3333-333333333333', 'Charlie', 'charlie@example.local')
on conflict (id) do update
set
    username = excluded.username,
    email = excluded.email;
