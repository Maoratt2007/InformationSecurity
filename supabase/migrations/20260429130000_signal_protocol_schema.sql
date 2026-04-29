create schema if not exists signal_protocol;

create table if not exists signal_protocol.users (
    id uuid primary key default gen_random_uuid(),
    username text not null unique,
    created_at timestamptz not null default now()
);

create table if not exists signal_protocol.identity_keys (
    id uuid primary key default gen_random_uuid(),
    user_id uuid not null unique references signal_protocol.users(id) on delete cascade,
    identity_key_public text not null,
    created_at timestamptz not null default now()
);

create table if not exists signal_protocol.pre_keys (
    id uuid primary key default gen_random_uuid(),
    user_id uuid not null unique references signal_protocol.users(id) on delete cascade,
    signed_pre_key_id integer not null,
    signed_pre_key_public text not null,
    signed_pre_key_signature text not null,
    one_time_pre_keys jsonb not null default '[]'::jsonb,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

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
on signal_protocol.messages(recipient_id)
where delivered_at is null;

insert into signal_protocol.users (id, username)
values
    ('11111111-1111-1111-1111-111111111111', 'Alice'),
    ('22222222-2222-2222-2222-222222222222', 'Bob'),
    ('33333333-3333-3333-3333-333333333333', 'Charlie')
on conflict (id) do nothing;

insert into signal_protocol.identity_keys (user_id, identity_key_public)
values
    ('11111111-1111-1111-1111-111111111111', 'alice_identity_public_key_base64url'),
    ('22222222-2222-2222-2222-222222222222', 'bob_identity_public_key_base64url'),
    ('33333333-3333-3333-3333-333333333333', 'charlie_identity_public_key_base64url')
on conflict (user_id) do update
set identity_key_public = excluded.identity_key_public;

insert into signal_protocol.pre_keys (
    user_id,
    signed_pre_key_id,
    signed_pre_key_public,
    signed_pre_key_signature,
    one_time_pre_keys
)
values
    (
        '11111111-1111-1111-1111-111111111111',
        1,
        'alice_signed_pre_key_public_base64url',
        'alice_signed_pre_key_signature_base64url',
        '[
            {"key_id": "1", "public_key": "alice_opk_1_public_base64url"},
            {"key_id": "2", "public_key": "alice_opk_2_public_base64url"},
            {"key_id": "3", "public_key": "alice_opk_3_public_base64url"}
        ]'::jsonb
    ),
    (
        '22222222-2222-2222-2222-222222222222',
        1,
        'bob_signed_pre_key_public_base64url',
        'bob_signed_pre_key_signature_base64url',
        '[
            {"key_id": "1", "public_key": "bob_opk_1_public_base64url"},
            {"key_id": "2", "public_key": "bob_opk_2_public_base64url"},
            {"key_id": "3", "public_key": "bob_opk_3_public_base64url"}
        ]'::jsonb
    ),
    (
        '33333333-3333-3333-3333-333333333333',
        1,
        'charlie_signed_pre_key_public_base64url',
        'charlie_signed_pre_key_signature_base64url',
        '[
            {"key_id": "1", "public_key": "charlie_opk_1_public_base64url"},
            {"key_id": "2", "public_key": "charlie_opk_2_public_base64url"},
            {"key_id": "3", "public_key": "charlie_opk_3_public_base64url"}
        ]'::jsonb
    )
on conflict (user_id) do update
set
    signed_pre_key_id = excluded.signed_pre_key_id,
    signed_pre_key_public = excluded.signed_pre_key_public,
    signed_pre_key_signature = excluded.signed_pre_key_signature,
    one_time_pre_keys = excluded.one_time_pre_keys,
    updated_at = now();
