-- Signal Protocol schema refinement for X3DH and Double Ratchet.
-- Amit, Etay, and Maor: one-time pre-keys must be separate rows so the server can hand out
-- exactly one key and remove it immediately during the X3DH handshake.

create schema if not exists signal_protocol;

alter table signal_protocol.pre_keys
add column if not exists signature text;

update signal_protocol.pre_keys
set signature = signed_pre_key_signature
where signature is null
  and signed_pre_key_signature is not null;

alter table signal_protocol.pre_keys
alter column signature set not null;

create table if not exists signal_protocol.one_time_pre_keys (
    id uuid primary key default gen_random_uuid(),
    user_id uuid not null references signal_protocol.users(id) on delete cascade,
    key_id integer not null,
    public_key text not null,
    created_at timestamptz not null default now(),
    unique (user_id, key_id)
);

-- Migrate existing JSON one-time pre-keys into consumable rows before the JSON column is retired.
insert into signal_protocol.one_time_pre_keys (user_id, key_id, public_key)
select
    pre_keys.user_id,
    (one_time_pre_key.value ->> 'key_id')::integer as key_id,
    one_time_pre_key.value ->> 'public_key' as public_key
from signal_protocol.pre_keys
cross join lateral jsonb_array_elements(pre_keys.one_time_pre_keys) as one_time_pre_key(value)
where pre_keys.one_time_pre_keys is not null
  and jsonb_typeof(pre_keys.one_time_pre_keys) = 'array'
  and one_time_pre_key.value ? 'key_id'
  and one_time_pre_key.value ? 'public_key'
on conflict (user_id, key_id) do update
set public_key = excluded.public_key;

alter table signal_protocol.pre_keys
drop column if exists one_time_pre_keys;

create index if not exists idx_signal_one_time_pre_keys_user_created
on signal_protocol.one_time_pre_keys(user_id, created_at);

-- Atomic one-time pre-key consumption prevents two initiators from receiving the same X3DH key.
create or replace function signal_protocol.consume_one_time_pre_key(target_user_id uuid)
returns table (
    id uuid,
    user_id uuid,
    key_id integer,
    public_key text,
    created_at timestamptz
)
language sql
security definer
set search_path = signal_protocol, public
as $$
    with selected_key as (
        select one_time_pre_keys.id
        from signal_protocol.one_time_pre_keys
        where one_time_pre_keys.user_id = target_user_id
        order by one_time_pre_keys.created_at asc, one_time_pre_keys.key_id asc
        limit 1
        for update skip locked
    )
    delete from signal_protocol.one_time_pre_keys
    using selected_key
    where one_time_pre_keys.id = selected_key.id
    returning
        one_time_pre_keys.id,
        one_time_pre_keys.user_id,
        one_time_pre_keys.key_id,
        one_time_pre_keys.public_key,
        one_time_pre_keys.created_at;
$$;

-- Double Ratchet state must be stored per local user and contact pair.
-- root_key and chain_key are stored as encoded client-generated state values.
create table if not exists signal_protocol.sessions (
    id uuid primary key default gen_random_uuid(),
    user_id uuid not null references signal_protocol.users(id) on delete cascade,
    contact_id uuid not null references signal_protocol.users(id) on delete cascade,
    ratchet_key_id text not null,
    root_key text not null,
    chain_key text not null,
    last_received_index integer not null default 0,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    unique (user_id, contact_id)
);

create index if not exists idx_signal_sessions_user_contact
on signal_protocol.sessions(user_id, contact_id);

insert into signal_protocol.one_time_pre_keys (user_id, key_id, public_key)
values
    ('11111111-1111-1111-1111-111111111111', 1, 'alice_opk_1_public_base64url'),
    ('11111111-1111-1111-1111-111111111111', 2, 'alice_opk_2_public_base64url'),
    ('11111111-1111-1111-1111-111111111111', 3, 'alice_opk_3_public_base64url'),
    ('22222222-2222-2222-2222-222222222222', 1, 'bob_opk_1_public_base64url'),
    ('22222222-2222-2222-2222-222222222222', 2, 'bob_opk_2_public_base64url'),
    ('22222222-2222-2222-2222-222222222222', 3, 'bob_opk_3_public_base64url'),
    ('33333333-3333-3333-3333-333333333333', 1, 'charlie_opk_1_public_base64url'),
    ('33333333-3333-3333-3333-333333333333', 2, 'charlie_opk_2_public_base64url'),
    ('33333333-3333-3333-3333-333333333333', 3, 'charlie_opk_3_public_base64url')
on conflict (user_id, key_id) do update
set public_key = excluded.public_key;
