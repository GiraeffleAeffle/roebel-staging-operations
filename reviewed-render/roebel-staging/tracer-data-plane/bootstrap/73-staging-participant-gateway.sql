-- Bounded, staging-only post/comment capability for ADR 0021.
--
-- PRECONDITIONS (verify against the live staging catalog before applying):
--   * public.app_settings contains roebel_env = staging
--   * Supabase Vault contains an independently provisioned arm named
--     roebel_staging_participant_environment_arm with value staging-only
--   * Supabase Vault contains a random 32+ byte secret named
--     roebel_staging_participant_rpc_secret
--   * public.posts/post_comments/users and public.enforce_posting_rules()
--     match the reviewed source schema
--
-- The gateway uses the ordinary public anon key for PostgREST routing plus the
-- Vault capability in a private request header. It never receives service_role,
-- a database password, or a custom JWT role that would inherit unrelated
-- PUBLIC EXECUTE functions. This migration does not repair unrelated app-wide
-- policy debt. It does close direct client writes to the two feed tables in the
-- armed staging project, so this capability cannot be bypassed through the
-- browser-public anon key.

begin;

-- Fail before creating any object unless this is the separately armed staging
-- database. `app_settings` is useful environment evidence but is not deployment
-- authority: the independent Vault arm is required before this migration can
-- run, and the RPC capability must already exist.
do $$
begin
  if not exists (
    select 1 from public.app_settings
     where key = 'roebel_env' and value = 'staging'
  ) then
    raise exception 'STAGING_PARTICIPANT_MIGRATION_REQUIRES_STAGING'
      using errcode = 'P0001';
  end if;
  if not exists (
    select 1 from vault.decrypted_secrets
     where name = 'roebel_staging_participant_environment_arm'
       and decrypted_secret = 'staging-only'
  ) then
    raise exception 'STAGING_PARTICIPANT_MIGRATION_REQUIRES_PRIVATE_ARM'
      using errcode = 'P0001';
  end if;
  if not exists (
    select 1 from vault.decrypted_secrets
     where name = 'roebel_staging_participant_rpc_secret'
       and length(decrypted_secret) >= 32
  ) then
    raise exception 'STAGING_PARTICIPANT_MIGRATION_REQUIRES_RPC_SECRET'
      using errcode = 'P0001';
  end if;
  if not exists (
    select 1
      from pg_catalog.pg_extension e
      join pg_catalog.pg_namespace n on n.oid = e.extnamespace
     where e.extname = 'pgcrypto' and n.nspname = 'extensions'
  ) then
    raise exception 'STAGING_PARTICIPANT_MIGRATION_REQUIRES_PGCRYPTO_EXTENSIONS'
      using errcode = 'P0001';
  end if;
  if not exists (
    select 1
      from pg_catalog.pg_trigger t
      join pg_catalog.pg_class c on c.oid = t.tgrelid
      join pg_catalog.pg_namespace n on n.oid = c.relnamespace
     where n.nspname = 'public'
       and c.relname = 'post_comments'
       and t.tgname = 'trg_post_comment_counts'
       and not t.tgisinternal
       and t.tgenabled in ('O', 'A')
       and t.tgtype = 13
       and t.tgfoid = pg_catalog.to_regprocedure(
         'public.post_comment_counts_sync()'
       )
  ) then
    raise exception 'STAGING_PARTICIPANT_MIGRATION_REQUIRES_COMMENT_COUNT_TRIGGER'
      using errcode = 'P0001';
  end if;
  if pg_catalog.to_regprocedure('public.delete_owned_post(uuid,text)') is null
     or pg_catalog.to_regprocedure(
       'public.delete_owned_post_comment(uuid,text)'
     ) is null
     or pg_catalog.to_regprocedure(
       'public.delete_owned_experience(uuid,text)'
     ) is null
     or pg_catalog.to_regprocedure(
       'public.pin_own_post(uuid,text,boolean)'
     ) is null then
    raise exception 'STAGING_PARTICIPANT_MIGRATION_REQUIRES_LEGACY_DELETE_RPCS'
      using errcode = 'P0001';
  end if;
  if pg_catalog.to_regclass('public.account_owners') is null or not exists (
    select 1
      from pg_catalog.pg_attribute wallet_column
      join pg_catalog.pg_class users_table
        on users_table.oid = wallet_column.attrelid
      join pg_catalog.pg_namespace users_schema
        on users_schema.oid = users_table.relnamespace
     where users_schema.nspname = 'public'
       and users_table.relname = 'users'
       and wallet_column.attname = 'wallet_address'
       and wallet_column.atttypid = 'text'::pg_catalog.regtype
       and exists (
         select 1 from pg_catalog.pg_index users_unique
          where users_unique.indrelid = users_table.oid
            and users_unique.indisunique
            and users_unique.indnkeyatts = 1
            and users_unique.indkey[0] = wallet_column.attnum
       )
  ) or exists (
    select 1
      from pg_catalog.pg_attribute required_column
     where required_column.attrelid = 'public.users'::pg_catalog.regclass
       and required_column.attnum > 0
       and not required_column.attisdropped
       and required_column.attnotnull
       and not required_column.atthasdef
       and required_column.attidentity = ''
       and required_column.attgenerated = ''
       and required_column.attname not in (
         'wallet_address', 'tier', 'is_verified_citizen', 'verification_status'
       )
  ) or not exists (
    select 1 from pg_catalog.pg_attribute
     where attrelid = 'public.users'::pg_catalog.regclass
       and attname = 'tier' and atttypid = 'text'::pg_catalog.regtype
  ) or not exists (
    select 1 from pg_catalog.pg_attribute
     where attrelid = 'public.users'::pg_catalog.regclass
       and attname = 'is_verified_citizen'
       and atttypid = 'boolean'::pg_catalog.regtype
  ) or not exists (
    select 1 from pg_catalog.pg_attribute
     where attrelid = 'public.users'::pg_catalog.regclass
       and attname = 'verification_status'
       and atttypid = 'text'::pg_catalog.regtype
  ) then
    raise exception 'STAGING_PARTICIPANT_MIGRATION_REQUIRES_GUEST_USER_SHAPE'
      using errcode = 'P0001';
  end if;
end;
$$;

create schema staging_participant_private;
revoke all on schema staging_participant_private from public, anon, authenticated;

create table staging_participant_private.staging_participant_environment (
  singleton boolean primary key default true check (singleton),
  environment text not null check (environment = 'staging')
);
insert into staging_participant_private.staging_participant_environment (singleton, environment)
values (true, 'staging')
on conflict (singleton) do nothing;

-- The database attests only to this marker and fixed catalog facts.
-- It does not claim to know the raw historical migration bytes; source/GitOps pins
-- bind those separately as release evidence.
create table staging_participant_private.staging_participant_schema_contract (
  singleton boolean primary key default true check (singleton),
  migration_id text not null,
  canonical_contract text not null,
  prior_function_definitions_sha256 text,
  prior_privileges_sha256 text,
  database_schema_sha256 text not null check (database_schema_sha256 ~ '^sha256:[0-9a-f]{64}$')
);

-- Captured at activation from the then-trusted staging catalog. Preflight
-- compares these values with the current catalog; this proves current
-- executable identity, not unverifiable historic SQL-file bytes.
create table staging_participant_private.staging_participant_catalog_contract (
  object_identity text primary key,
  owner_name text not null,
  language_name text not null,
  return_type text not null,
  volatility "char" not null,
  security_definer boolean not null,
  search_path text not null,
  definition_sha256 text not null check (definition_sha256 ~ '^[0-9a-f]{64}$'),
  source_sha256 text not null check (source_sha256 ~ '^[0-9a-f]{64}$')
);
insert into staging_participant_private.staging_participant_schema_contract
  (singleton, migration_id, canonical_contract, database_schema_sha256)
values (
  true,
  '20260825_staging_participant_gateway',
  $contract${"assertions":{"catalog":{"capturedDefinitionAndSourceDigests":true,"capturedOwnerLanguageReturnVolatilitySecuritySearchPath":true,"priorRollbackEvidenceDigests":true},"deniedExecute":["public.delete_owned_post(uuid,text)","public.delete_owned_post_comment(uuid,text)","public.delete_owned_experience(uuid,text)","public.pin_own_post(uuid,text,boolean)"],"privateTables":["staging_participant_private.staging_participant_environment","staging_participant_private.staging_participant_admissions","staging_participant_private.staging_participant_write_reservations","staging_participant_private.staging_participant_write_audit","staging_participant_private.staging_participant_nostr_post_mirror_receipts","staging_participant_private.staging_participant_schema_contract","staging_participant_private.staging_participant_catalog_contract","staging_participant_private.staging_participant_prior_function_definitions","staging_participant_private.staging_participant_prior_privileges"],"publicRpc":["public.staging_participant_gateway_create_main_text_post(text,text,uuid)","public.staging_participant_gateway_create_main_text_comment(text,uuid,text,uuid)","public.staging_participant_gateway_read_owned_main_text_post(text,uuid)","public.staging_participant_gateway_reserve_nostr_post_mirror(text,uuid,uuid,text,bigint,text)","public.staging_participant_gateway_complete_nostr_post_mirror(text,uuid,uuid,text,text)","public.staging_participant_gateway_preflight()"],"triggers":{"commentCount":{"function":"public.post_comment_counts_sync()","name":"trg_post_comment_counts","noArgs":true,"noWhen":true,"table":"public.post_comments","tgtype":13},"posting":{"function":"public.enforce_posting_rules()","name":"enforce_posting_rules_trg","noArgs":true,"noWhen":true,"table":"public.posts","tgtype":7}}},"migrationId":"20260825_staging_participant_gateway","schemaVersion":"roebel_staging_participant_gateway_schema_contract_v1"}
$contract$,
  'sha256:a540591c718d4b2c74f56fe7310baf5b522ac6541384223a5263079e207f3d5d'
)
on conflict (singleton) do update
  set migration_id = excluded.migration_id,
      canonical_contract = excluded.canonical_contract,
      database_schema_sha256 = excluded.database_schema_sha256;

create table staging_participant_private.staging_participant_admissions (
  wallet_address text primary key,
  issued_at timestamptz not null default now(),
  expires_at timestamptz not null,
  revoked_at timestamptz,
  issued_by text not null default 'staging_participant_gateway_v1',
  constraint staging_participant_admission_wallet_check
    check (wallet_address = lower(wallet_address)
      and wallet_address ~ '^0x[0-9a-f]{40}$'),
  constraint staging_participant_admission_time_check
    check (expires_at > issued_at and expires_at <= issued_at + interval '2 hours')
);

create table staging_participant_private.staging_participant_write_reservations (
  id uuid primary key default extensions.gen_random_uuid(),
  request_id uuid not null unique,
  wallet_address text not null references staging_participant_private.staging_participant_admissions(wallet_address),
  action text not null check (action in ('post', 'comment')),
  target_id uuid not null,
  source_post_id uuid,
  content_sha256 bytea not null,
  expires_at timestamptz not null,
  consumed_at timestamptz,
  constraint staging_participant_reservation_target_check
    check ((action = 'post' and source_post_id is null)
      or (action = 'comment' and source_post_id is not null))
);

create table staging_participant_private.staging_participant_write_audit (
  request_id uuid primary key,
  wallet_address text not null references staging_participant_private.staging_participant_admissions(wallet_address),
  action text not null check (action in ('post', 'comment')),
  result_id uuid not null,
  source_post_id uuid,
  content_sha256 bytea not null,
  created_at timestamptz not null default now(),
  constraint staging_participant_audit_target_check
    check ((action = 'post' and source_post_id is null)
      or (action = 'comment' and source_post_id is not null))
);

-- A relay is external to this transaction. Reserve the immutable event first,
-- publish precisely that event, then mark the receipt complete. A crash leaves
-- a durable `reserved` receipt that can retry only the original event id.
create table staging_participant_private.staging_participant_nostr_post_mirror_receipts (
  wallet_address text not null references staging_participant_private.staging_participant_admissions(wallet_address),
  source_post_id uuid not null,
  request_id uuid not null unique,
  event_id text not null,
  event_created_at bigint not null check (event_created_at >= 0),
  content_sha256 bytea not null,
  state text not null default 'reserved' check (state in ('reserved', 'published')),
  created_at timestamptz not null default now(),
  published_at timestamptz,
  primary key (wallet_address, source_post_id),
  constraint staging_participant_nostr_mirror_event_check
    check (event_id ~ '^[0-9a-f]{64}$'),
  constraint staging_participant_nostr_mirror_digest_check
    check (octet_length(content_sha256) = 32),
  constraint staging_participant_nostr_mirror_completion_check
    check ((state = 'reserved' and published_at is null)
      or (state = 'published' and published_at is not null))
);

-- Capture the exact compatibility state before changing it. The companion
-- deactivation transaction restores these definitions/grants from the armed
-- catalog instead of guessing from historical SQL files.
create table staging_participant_private.staging_participant_prior_function_definitions (
  object_identity text primary key,
  definition text not null
);
insert into staging_participant_private.staging_participant_prior_function_definitions (
  object_identity, definition
)
select 'public.enforce_posting_rules()',
       pg_catalog.pg_get_functiondef(
         pg_catalog.to_regprocedure('public.enforce_posting_rules()')
       );

create table staging_participant_private.staging_participant_prior_privileges (
  object_kind text not null check (object_kind in ('table', 'table_column', 'function')),
  object_identity text not null,
  column_name text not null default '',
  grantee text not null,
  privilege_type text not null,
  is_grantable boolean not null,
  primary key (object_kind, object_identity, column_name, grantee, privilege_type)
);

-- Defense in depth for the private capability/audit catalog. No public policy
-- is created; only the owning SECURITY DEFINER functions may use these rows.
alter table staging_participant_private.staging_participant_environment
  enable row level security;
alter table staging_participant_private.staging_participant_schema_contract
  enable row level security;
alter table staging_participant_private.staging_participant_catalog_contract
  enable row level security;
alter table staging_participant_private.staging_participant_admissions
  enable row level security;
alter table staging_participant_private.staging_participant_write_reservations
  enable row level security;
alter table staging_participant_private.staging_participant_write_audit
  enable row level security;
alter table staging_participant_private.staging_participant_nostr_post_mirror_receipts
  enable row level security;
alter table staging_participant_private.staging_participant_prior_function_definitions
  enable row level security;
alter table staging_participant_private.staging_participant_prior_privileges
  enable row level security;

insert into staging_participant_private.staging_participant_prior_privileges
  (object_kind, object_identity, column_name, grantee, privilege_type, is_grantable)
select 'table', pg_catalog.format('%I.%I', n.nspname, c.relname), '',
       case when acl.grantee = 0 then 'PUBLIC' else grantee_role.rolname end,
       acl.privilege_type, acl.is_grantable
  from pg_catalog.pg_class c
  join pg_catalog.pg_namespace n on n.oid = c.relnamespace
  cross join lateral pg_catalog.aclexplode(
    coalesce(c.relacl, pg_catalog.acldefault('r', c.relowner))
  ) acl
  left join pg_catalog.pg_roles grantee_role on grantee_role.oid = acl.grantee
 where n.nspname = 'public'
   and c.relname in ('posts', 'post_comments', 'post_likes', 'app_settings')
   and (acl.grantee = 0 or grantee_role.rolname in ('anon', 'authenticated'))
   and acl.privilege_type in ('INSERT', 'UPDATE', 'DELETE');

insert into staging_participant_private.staging_participant_prior_privileges
  (object_kind, object_identity, column_name, grantee, privilege_type, is_grantable)
select 'function', target.object_identity, '',
       case when acl.grantee = 0 then 'PUBLIC' else grantee_role.rolname end,
       acl.privilege_type, acl.is_grantable
  from (values
    ('public.delete_owned_post(uuid,text)'),
    ('public.delete_owned_post_comment(uuid,text)'),
    ('public.delete_owned_experience(uuid,text)'),
    ('public.pin_own_post(uuid,text,boolean)')
  ) target(object_identity)
  join pg_catalog.pg_proc p
    on p.oid = pg_catalog.to_regprocedure(target.object_identity)
  cross join lateral pg_catalog.aclexplode(
    coalesce(p.proacl, pg_catalog.acldefault('f', p.proowner))
  ) acl
  left join pg_catalog.pg_roles grantee_role on grantee_role.oid = acl.grantee
 where (acl.grantee = 0 or grantee_role.rolname in ('anon', 'authenticated'))
   and acl.privilege_type = 'EXECUTE';

-- Table-level REVOKE does not remove explicit column ACLs. Capture any
-- existing INSERT/UPDATE column grants so deactivation can restore precisely
-- the catalog baseline, then close them below. Effective privileges are
-- asserted after revocation to catch role membership or inherited grants that
-- a migration cannot safely guess away.
insert into staging_participant_private.staging_participant_prior_privileges
  (object_kind, object_identity, column_name, grantee, privilege_type, is_grantable)
select 'table_column', pg_catalog.format('%I.%I', n.nspname, c.relname), a.attname,
       case when acl.grantee = 0 then 'PUBLIC' else grantee_role.rolname end,
       acl.privilege_type, acl.is_grantable
  from pg_catalog.pg_class c
  join pg_catalog.pg_namespace n on n.oid = c.relnamespace
  join pg_catalog.pg_attribute a on a.attrelid = c.oid
    and a.attnum > 0 and not a.attisdropped
  cross join lateral pg_catalog.aclexplode(coalesce(a.attacl, '{}'::pg_catalog.aclitem[])) acl
  left join pg_catalog.pg_roles grantee_role on grantee_role.oid = acl.grantee
 where n.nspname = 'public'
   and c.relname in ('posts', 'post_comments', 'post_likes', 'app_settings')
   and (acl.grantee = 0 or grantee_role.rolname in ('anon', 'authenticated'))
   and acl.privilege_type in ('INSERT', 'UPDATE');

create index if not exists staging_participant_write_audit_rate_idx
  on staging_participant_private.staging_participant_write_audit
    (wallet_address, action, created_at desc);

revoke all on all tables in schema staging_participant_private from public, anon, authenticated;

-- The public key remains sufficient for reads. All direct feed mutations are
-- closed in staging; the two SECURITY DEFINER functions below are the only
-- browser-reachable creation seam. Old caller-asserted ownership deletion RPCs
-- are also disabled here because they do not verify a wallet signature.
revoke insert, update, delete on table public.posts
  from public, anon, authenticated;
revoke insert, update, delete on table public.post_comments
  from public, anon, authenticated;
revoke insert, update, delete on table public.post_likes
  from public, anon, authenticated;
revoke insert, update, delete on table public.app_settings
  from public, anon, authenticated;
revoke all on function public.delete_owned_post(uuid, text)
  from public, anon, authenticated;
revoke all on function public.delete_owned_post_comment(uuid, text)
  from public, anon, authenticated;
revoke all on function public.delete_owned_experience(uuid, text)
  from public, anon, authenticated;
revoke all on function public.pin_own_post(uuid, text, boolean)
  from public, anon, authenticated;

-- Remove explicit column ACLs too, then assert the effective privilege result
-- for each browser role. If a parent role still grants a direct mutation, stop
-- rather than silently leaving a bypass beside the gateway RPCs.
do $$
declare
  v_column record;
  v_table text;
begin
  for v_column in
    select n.nspname, c.relname, a.attname
      from pg_catalog.pg_class c
      join pg_catalog.pg_namespace n on n.oid = c.relnamespace
      join pg_catalog.pg_attribute a on a.attrelid = c.oid
        and a.attnum > 0 and not a.attisdropped
     where n.nspname = 'public'
       and c.relname in ('posts', 'post_comments', 'post_likes', 'app_settings')
  loop
    execute pg_catalog.format(
      'revoke insert (%I), update (%I) on table %I.%I from public, anon, authenticated',
      v_column.attname, v_column.attname, v_column.nspname, v_column.relname
    );
  end loop;

  foreach v_table in array array[
    'public.posts', 'public.post_comments', 'public.post_likes', 'public.app_settings'
  ] loop
    if has_table_privilege('anon', v_table, 'INSERT')
       or has_table_privilege('anon', v_table, 'UPDATE')
       or has_table_privilege('anon', v_table, 'DELETE')
       or has_table_privilege('authenticated', v_table, 'INSERT')
       or has_table_privilege('authenticated', v_table, 'UPDATE')
       or has_table_privilege('authenticated', v_table, 'DELETE') then
      raise exception 'STAGING_PARTICIPANT_DIRECT_WRITE_PRIVILEGE_REMAINS:%', v_table
        using errcode = 'P0001';
    end if;
  end loop;
  for v_column in
    select n.nspname, c.relname, a.attname
      from pg_catalog.pg_class c
      join pg_catalog.pg_namespace n on n.oid = c.relnamespace
      join pg_catalog.pg_attribute a on a.attrelid = c.oid
        and a.attnum > 0 and not a.attisdropped
     where n.nspname = 'public'
       and c.relname in ('posts', 'post_comments', 'post_likes', 'app_settings')
  loop
    v_table := pg_catalog.format('%I.%I', v_column.nspname, v_column.relname);
    if has_column_privilege('anon', v_table, v_column.attname, 'INSERT')
       or has_column_privilege('anon', v_table, v_column.attname, 'UPDATE')
       or has_column_privilege('authenticated', v_table, v_column.attname, 'INSERT')
       or has_column_privilege('authenticated', v_table, v_column.attname, 'UPDATE') then
      raise exception 'STAGING_PARTICIPANT_DIRECT_COLUMN_WRITE_PRIVILEGE_REMAINS:%.%',
        v_table, v_column.attname using errcode = 'P0001';
    end if;
  end loop;
end;
$$;

create or replace function staging_participant_private.staging_participant_rpc_secret()
returns text
language plpgsql
stable
security definer
set search_path = pg_catalog, vault
as $$
declare
  v_secret text;
begin
  if not exists (
    select 1 from vault.decrypted_secrets
     where name = 'roebel_staging_participant_environment_arm'
       and decrypted_secret = 'staging-only'
  ) then
    raise exception 'STAGING_PARTICIPANT_ENVIRONMENT_ARM_UNAVAILABLE'
      using errcode = 'P0001';
  end if;

  select decrypted_secret into v_secret
    from vault.decrypted_secrets
   where name = 'roebel_staging_participant_rpc_secret'
   limit 1;

  if v_secret is null or length(v_secret) < 32 then
    raise exception 'STAGING_PARTICIPANT_SECRET_UNAVAILABLE'
      using errcode = 'P0001';
  end if;
  return v_secret;
end;
$$;
revoke all on function staging_participant_private.staging_participant_rpc_secret() from public, anon, authenticated;

create or replace function staging_participant_private.require_staging_participant_gateway()
returns text
language plpgsql
security definer
set search_path = pg_catalog, staging_participant_private
as $$
declare
  v_headers jsonb;
  v_provided text;
  v_secret text;
begin
  begin
    v_headers := nullif(current_setting('request.headers', true), '')::jsonb;
  exception when others then
    raise exception 'STAGING_PARTICIPANT_GATEWAY_REQUIRED'
      using errcode = 'P0001';
  end;
  v_provided := v_headers ->> 'x-staging-participant-rpc-secret';
  v_secret := staging_participant_private.staging_participant_rpc_secret();

  if v_provided is null
     or length(v_provided) < 32
     or extensions.digest(v_provided, 'sha256') <>
        extensions.digest(v_secret, 'sha256') then
    raise exception 'STAGING_PARTICIPANT_GATEWAY_REQUIRED'
      using errcode = 'P0001';
  end if;

  if not exists (
    select 1 from staging_participant_private.staging_participant_environment
     where singleton and environment = 'staging'
  ) or not exists (
    select 1 from public.app_settings
     where key = 'roebel_env' and value = 'staging'
  ) then
    raise exception 'STAGING_PARTICIPANT_ENVIRONMENT_REQUIRED'
      using errcode = 'P0001';
  end if;
  return v_secret;
end;
$$;
revoke all on function staging_participant_private.require_staging_participant_gateway() from public, anon, authenticated;

create or replace function staging_participant_private.ensure_active_staging_participant(p_wallet_address text)
returns staging_participant_private.staging_participant_admissions
language plpgsql
security definer
set search_path = pg_catalog, staging_participant_private
as $$
declare
  v_admission staging_participant_private.staging_participant_admissions%rowtype;
  v_user_was_missing boolean;
begin
  if p_wallet_address is null
     or p_wallet_address <> lower(p_wallet_address)
     or p_wallet_address !~ '^0x[0-9a-f]{40}$' then
    raise exception 'STAGING_PARTICIPANT_WALLET_INVALID'
      using errcode = 'P0001';
  end if;

  -- Thirdweb's first-login profile is deliberately ephemeral in staging. The
  -- first signed, invite-bound write provisions only the minimum referential
  -- prerequisite in the same transaction. It creates no personal account,
  -- citizen verification, organisation membership, or civic authority.
  select not exists (
    select 1 from public.users
     where lower(wallet_address) = p_wallet_address
  ) into v_user_was_missing;

  if v_user_was_missing then
    insert into public.users (
      wallet_address, tier, is_verified_citizen, verification_status
    ) values (
      p_wallet_address, 'guest', false, 'pending'
    ) on conflict (wallet_address) do nothing;
  end if;

  if not exists (
    select 1 from public.users
     where lower(wallet_address) = p_wallet_address
  ) then
    raise exception 'STAGING_PARTICIPANT_GUEST_PROVISION_FAILED'
      using errcode = 'P0001';
  end if;

  if v_user_was_missing and (
    not exists (
      select 1 from public.users
       where lower(wallet_address) = p_wallet_address
         and tier = 'guest'
         and is_verified_citizen is false
         and verification_status = 'pending'
    ) or exists (
      select 1 from public.account_owners
       where lower(wallet_address) = p_wallet_address
    )
  ) then
    raise exception 'STAGING_PARTICIPANT_GUEST_PROJECTION_ESCALATED'
      using errcode = 'P0001';
  end if;

  insert into staging_participant_private.staging_participant_admissions (
    wallet_address, expires_at
  ) values (
    p_wallet_address, now() + interval '2 hours'
  ) on conflict (wallet_address) do update
       set issued_at = excluded.issued_at,
           expires_at = excluded.expires_at
     where staging_participant_admissions.revoked_at is null
       and staging_participant_admissions.expires_at <= now();

  select * into v_admission
    from staging_participant_private.staging_participant_admissions
   where wallet_address = p_wallet_address
   for update;

  if not found
     or v_admission.revoked_at is not null
     or v_admission.expires_at <= now() then
    raise exception 'STAGING_PARTICIPANT_ADMISSION_INACTIVE'
      using errcode = 'P0001';
  end if;
  return v_admission;
end;
$$;
revoke all on function staging_participant_private.ensure_active_staging_participant(text) from public, anon, authenticated;

create or replace function staging_participant_private.consume_staging_post_reservation(p_post public.posts)
returns boolean
language plpgsql
security definer
set search_path = pg_catalog, staging_participant_private
as $$
declare
  v_reservation staging_participant_private.staging_participant_write_reservations%rowtype;
  v_secret text;
  v_reservation_id uuid;
  v_received_guard text;
  v_expected_guard text;
begin
  begin
    v_reservation_id := nullif(
      current_setting('roebel.staging_participant_reservation_id', true), ''
    )::uuid;
  exception when others then
    return false;
  end;
  v_received_guard := nullif(
    current_setting('roebel.staging_participant_reservation_guard', true), ''
  );
  if v_reservation_id is null or v_received_guard is null then
    return false;
  end if;

  select * into v_reservation
    from staging_participant_private.staging_participant_write_reservations
   where id = v_reservation_id
     and action = 'post'
   for update;
  if not found
     or v_reservation.consumed_at is not null
     or v_reservation.expires_at <= now() then
    return false;
  end if;

  v_secret := staging_participant_private.staging_participant_rpc_secret();
  v_expected_guard := encode(
    extensions.hmac(
      v_reservation.id::text || ':' || v_reservation.wallet_address || ':' ||
        encode(v_reservation.content_sha256, 'hex'),
      v_secret,
      'sha256'
    ),
    'hex'
  );

  if extensions.digest(v_received_guard, 'sha256') <>
       extensions.digest(v_expected_guard, 'sha256')
     or p_post.id <> v_reservation.target_id
     or lower(p_post.wallet_address) <> v_reservation.wallet_address
     or extensions.digest(btrim(p_post.content), 'sha256') <>
        v_reservation.content_sha256
     or p_post.account_id is not null
     or p_post.feed_type is distinct from 'main'
     or p_post.post_type is distinct from 'user'
     or p_post.category is distinct from 'generell'
     or p_post.status is distinct from 'published'
     or coalesce(cardinality(p_post.media_urls), 0) <> 0
     or p_post.video_url is not null
     or p_post.linked_event_id is not null
     or p_post.linked_experience_id is not null
     or p_post.likes_count <> 0
     or p_post.comments_count <> 0 then
    return false;
  end if;

  update staging_participant_private.staging_participant_write_reservations
     set consumed_at = now()
   where id = v_reservation.id
     and consumed_at is null;
  return found;
end;
$$;
revoke all on function staging_participant_private.consume_staging_post_reservation(public.posts) from public, anon, authenticated;

-- Retain the existing citizen/tourist behaviour. Only a consumed, secret-bound,
-- exact-shape reservation can bypass it.
create or replace function public.enforce_posting_rules() returns trigger
language plpgsql
security definer
set search_path = pg_catalog, public, staging_participant_private
as $$
declare
  v_user public.users%rowtype;
  v_now timestamptz := now();
  v_day_count int;
  v_week_count int;
  v_oldest_day timestamptz;
  v_oldest_week timestamptz;
begin
  if staging_participant_private.consume_staging_post_reservation(new) then
    return new;
  end if;
  if new.post_type is distinct from 'user' then
    return new;
  end if;
  if new.account_id is not null then
    return new;
  end if;

  select * into v_user
    from public.users
   where lower(wallet_address) = lower(new.wallet_address)
   limit 1;
  if not found then
    raise exception 'USER_NOT_FOUND' using errcode = 'P0001';
  end if;
  if coalesce(v_user.is_verified_citizen, false) or v_user.tier = 'citizen' then
    return new;
  end if;
  if v_user.location_verified_at is null then
    raise exception 'LOCATION_REQUIRED' using errcode = 'P0001';
  end if;
  if v_user.created_at is null or v_user.created_at > v_now - interval '24 hours' then
    raise exception 'ACCOUNT_TOO_YOUNG:%',
      to_char(coalesce(v_user.created_at, v_now) + interval '24 hours',
              'YYYY-MM-DD"T"HH24:MI:SSOF')
      using errcode = 'P0001';
  end if;

  select count(*), min(created_at) into v_day_count, v_oldest_day
    from public.posts
   where lower(wallet_address) = lower(new.wallet_address)
     and post_type = 'user'
     and status <> 'deleted'
     and created_at > v_now - interval '24 hours';
  if v_day_count >= 2 then
    raise exception 'RATE_LIMIT_DAY:%',
      to_char(v_oldest_day + interval '24 hours', 'YYYY-MM-DD"T"HH24:MI:SSOF')
      using errcode = 'P0001';
  end if;

  select count(*), min(created_at) into v_week_count, v_oldest_week
    from public.posts
   where lower(wallet_address) = lower(new.wallet_address)
     and post_type = 'user'
     and status <> 'deleted'
     and created_at > v_now - interval '7 days';
  if v_week_count >= 5 then
    raise exception 'RATE_LIMIT_WEEK:%',
      to_char(v_oldest_week + interval '7 days', 'YYYY-MM-DD"T"HH24:MI:SSOF')
      using errcode = 'P0001';
  end if;
  return new;
end;
$$;

drop trigger if exists enforce_posting_rules_trg on public.posts;
create trigger enforce_posting_rules_trg
before insert on public.posts
for each row
execute function public.enforce_posting_rules();

create or replace function public.staging_participant_gateway_create_main_text_post(
  p_wallet_address text,
  p_content text,
  p_request_id uuid
) returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public, staging_participant_private
as $$
declare
  v_secret text;
  v_wallet text := lower(p_wallet_address);
  v_content text := btrim(p_content);
  v_content_sha bytea;
  v_existing staging_participant_private.staging_participant_write_audit%rowtype;
  v_reservation staging_participant_private.staging_participant_write_reservations%rowtype;
  v_post public.posts%rowtype;
  v_day_count int;
  v_week_count int;
  v_guard text;
begin
  v_secret := staging_participant_private.require_staging_participant_gateway();
  if p_wallet_address is null
     or v_wallet !~ '^0x[0-9a-f]{40}$'
     or p_request_id is null
     or v_content = ''
     or char_length(v_content) > 250
     or v_content ~ '[[:cntrl:]]'
     or v_content ~* '(https?://|www\.)' then
    raise exception 'STAGING_PARTICIPANT_POST_INVALID'
      using errcode = 'P0001';
  end if;
  v_content_sha := extensions.digest(v_content, 'sha256');
  perform pg_advisory_xact_lock(hashtextextended(v_wallet, 20260825));

  select * into v_existing
    from staging_participant_private.staging_participant_write_audit
   where request_id = p_request_id;
  if found then
    if v_existing.action <> 'post'
       or v_existing.wallet_address <> v_wallet
       or v_existing.content_sha256 <> v_content_sha then
      raise exception 'STAGING_PARTICIPANT_REQUEST_REUSED'
        using errcode = 'P0001';
    end if;
    select * into strict v_post from public.posts where id = v_existing.result_id;
    return to_jsonb(v_post);
  end if;

  perform staging_participant_private.ensure_active_staging_participant(v_wallet);

  select count(*) filter (where created_at > now() - interval '24 hours'),
         count(*) filter (where created_at > now() - interval '7 days')
    into v_day_count, v_week_count
    from staging_participant_private.staging_participant_write_audit
   where wallet_address = v_wallet and action = 'post';
  if v_day_count >= 2 or v_week_count >= 5 then
    raise exception 'STAGING_PARTICIPANT_POST_RATE_LIMIT'
      using errcode = 'P0001';
  end if;

  insert into staging_participant_private.staging_participant_write_reservations (
    request_id, wallet_address, action, target_id, content_sha256, expires_at
  ) values (
    p_request_id, v_wallet, 'post', extensions.gen_random_uuid(), v_content_sha,
    now() + interval '60 seconds'
  ) returning * into v_reservation;

  v_guard := encode(
    extensions.hmac(
      v_reservation.id::text || ':' || v_wallet || ':' || encode(v_content_sha, 'hex'),
      v_secret,
      'sha256'
    ),
    'hex'
  );
  perform set_config(
    'roebel.staging_participant_reservation_id', v_reservation.id::text, true
  );
  perform set_config(
    'roebel.staging_participant_reservation_guard', v_guard, true
  );

  insert into public.posts (
    id, wallet_address, account_id, content, category, feed_type, post_type,
    status, media_urls, video_url, linked_event_id, linked_experience_id,
    likes_count, comments_count
  ) values (
    v_reservation.target_id, v_wallet, null, v_content, 'generell', 'main',
    'user', 'published', '{}'::text[], null, null, null, 0, 0
  ) returning * into v_post;

  if v_reservation.consumed_at is null and not exists (
    select 1 from staging_participant_private.staging_participant_write_reservations
     where id = v_reservation.id and consumed_at is not null
  ) then
    raise exception 'STAGING_PARTICIPANT_RESERVATION_NOT_CONSUMED'
      using errcode = 'P0001';
  end if;

  insert into staging_participant_private.staging_participant_write_audit (
    request_id, wallet_address, action, result_id, content_sha256
  ) values (
    p_request_id, v_wallet, 'post', v_post.id, v_content_sha
  );
  return to_jsonb(v_post);
end;
$$;

create or replace function public.staging_participant_gateway_create_main_text_comment(
  p_wallet_address text,
  p_post_id uuid,
  p_content text,
  p_request_id uuid
) returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public, staging_participant_private
as $$
declare
  v_wallet text := lower(p_wallet_address);
  v_content text := btrim(p_content);
  v_content_sha bytea;
  v_existing staging_participant_private.staging_participant_write_audit%rowtype;
  v_comment public.post_comments%rowtype;
  v_day_count int;
  v_week_count int;
begin
  perform staging_participant_private.require_staging_participant_gateway();
  if p_wallet_address is null
     or v_wallet !~ '^0x[0-9a-f]{40}$'
     or p_request_id is null
     or p_post_id is null
     or v_content = ''
     or char_length(v_content) > 500
     or v_content ~ '[[:cntrl:]]'
     or v_content ~* '(https?://|www\.)' then
    raise exception 'STAGING_PARTICIPANT_COMMENT_INVALID'
      using errcode = 'P0001';
  end if;
  v_content_sha := extensions.digest(v_content, 'sha256');
  perform pg_advisory_xact_lock(hashtextextended(v_wallet, 20260825));

  select * into v_existing
    from staging_participant_private.staging_participant_write_audit
   where request_id = p_request_id;
  if found then
    if v_existing.action <> 'comment'
       or v_existing.wallet_address <> v_wallet
       or v_existing.source_post_id is distinct from p_post_id
       or v_existing.content_sha256 <> v_content_sha then
      raise exception 'STAGING_PARTICIPANT_REQUEST_REUSED'
        using errcode = 'P0001';
    end if;
    select * into strict v_comment
      from public.post_comments where id = v_existing.result_id;
    return to_jsonb(v_comment) || jsonb_build_object(
      'author_username', null,
      'author_profile_picture_url', null
    );
  end if;

  perform staging_participant_private.ensure_active_staging_participant(v_wallet);
  if not exists (
    select 1 from public.posts
     where id = p_post_id
       and feed_type = 'main'
       and status = 'published'
  ) then
    raise exception 'STAGING_PARTICIPANT_PARENT_INVALID'
      using errcode = 'P0001';
  end if;

  select count(*) filter (where created_at > now() - interval '24 hours'),
         count(*) filter (where created_at > now() - interval '7 days')
    into v_day_count, v_week_count
    from staging_participant_private.staging_participant_write_audit
   where wallet_address = v_wallet and action = 'comment';
  if v_day_count >= 10 or v_week_count >= 40 then
    raise exception 'STAGING_PARTICIPANT_COMMENT_RATE_LIMIT'
      using errcode = 'P0001';
  end if;

  insert into public.post_comments (
    id, post_id, wallet_address, account_id, content, media_urls, video_url,
    status
  ) values (
    extensions.gen_random_uuid(), p_post_id, v_wallet, null, v_content, '{}'::text[], null,
    'published'
  ) returning * into v_comment;

  insert into staging_participant_private.staging_participant_write_audit (
    request_id, wallet_address, action, result_id, source_post_id,
    content_sha256
  ) values (
    p_request_id, v_wallet, 'comment', v_comment.id, p_post_id, v_content_sha
  );
  return to_jsonb(v_comment) || jsonb_build_object(
    'author_username', null,
    'author_profile_picture_url', null
  );
end;
$$;

-- This read is intentionally narrower than a feed API. It returns only the
-- exact source post produced by this gateway for the session wallet, so a
-- signed Nostr mention cannot be pointed at a different user's or legacy row.
create or replace function public.staging_participant_gateway_read_owned_main_text_post(
  p_wallet_address text,
  p_post_id uuid
) returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public, staging_participant_private
as $$
declare
  v_wallet text := lower(p_wallet_address);
  v_post public.posts%rowtype;
begin
  perform staging_participant_private.require_staging_participant_gateway();
  if p_wallet_address is null
     or v_wallet !~ '^0x[0-9a-f]{40}$'
     or p_post_id is null then
    raise exception 'STAGING_PARTICIPANT_SOURCE_INVALID'
      using errcode = 'P0001';
  end if;
  select p.* into v_post
    from public.posts p
    join staging_participant_private.staging_participant_write_audit a
      on a.result_id = p.id
     and a.action = 'post'
     and a.wallet_address = v_wallet
   where p.id = p_post_id
     and lower(p.wallet_address) = v_wallet
     and p.account_id is null
     and p.feed_type = 'main'
     and p.post_type = 'user'
     and p.category = 'generell'
     and p.status = 'published'
     and coalesce(cardinality(p.media_urls), 0) = 0
     and p.video_url is null
     and p.linked_event_id is null
     and p.linked_experience_id is null
   limit 1;
  if not found then return null; end if;
  return to_jsonb(v_post);
end;
$$;

-- Claim one immutable ordinary-post conversation mention. This is the durable replay
-- authority: request id, source row, event id, and content digest are bound
-- together before the gateway ever calls the private workbench.
create or replace function public.staging_participant_gateway_reserve_nostr_post_mirror(
  p_wallet_address text,
  p_source_post_id uuid,
  p_request_id uuid,
  p_event_id text,
  p_event_created_at bigint,
  p_content_sha256 text
) returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public, staging_participant_private
as $$
declare
  v_wallet text := lower(p_wallet_address);
  v_event_id text := lower(p_event_id);
  v_content_sha bytea;
  v_receipt staging_participant_private.staging_participant_nostr_post_mirror_receipts%rowtype;
begin
  perform staging_participant_private.require_staging_participant_gateway();
  if p_wallet_address is null or v_wallet !~ '^0x[0-9a-f]{40}$'
     or p_source_post_id is null or p_request_id is null
     or p_event_id is null or v_event_id !~ '^[0-9a-f]{64}$'
     or p_event_created_at is null or p_event_created_at < 0
     or p_content_sha256 is null or lower(p_content_sha256) !~ '^[0-9a-f]{64}$' then
    raise exception 'STAGING_PARTICIPANT_MIRROR_INVALID' using errcode = 'P0001';
  end if;
  v_content_sha := decode(lower(p_content_sha256), 'hex');
  perform staging_participant_private.ensure_active_staging_participant(v_wallet);
  perform pg_advisory_xact_lock(hashtextextended(v_wallet || ':' || p_source_post_id::text, 20260825));

  select * into v_receipt
    from staging_participant_private.staging_participant_nostr_post_mirror_receipts
   where wallet_address = v_wallet and source_post_id = p_source_post_id;
  if found then
    if v_receipt.request_id <> p_request_id or v_receipt.event_id <> v_event_id
       or v_receipt.event_created_at <> p_event_created_at
       or v_receipt.content_sha256 <> v_content_sha then
      raise exception 'STAGING_PARTICIPANT_MIRROR_SOURCE_REUSED' using errcode = 'P0001';
    end if;
    return jsonb_build_object(
      'wallet_address', v_receipt.wallet_address,
      'source_post_id', v_receipt.source_post_id,
      'request_id', v_receipt.request_id,
      'event_id', v_receipt.event_id,
      'event_created_at', v_receipt.event_created_at,
      'content_sha256', encode(v_receipt.content_sha256, 'hex'),
      'state', v_receipt.state
    );
  end if;

  select * into v_receipt
    from staging_participant_private.staging_participant_nostr_post_mirror_receipts
   where request_id = p_request_id;
  if found then
    raise exception 'STAGING_PARTICIPANT_MIRROR_REQUEST_REUSED' using errcode = 'P0001';
  end if;

  -- Freshness is an admission condition for the first durable reservation
  -- only. Once the exact signed event has a receipt, its immutable identity
  -- is the replay guard and a recovery retry must not be rejected merely
  -- because five minutes elapsed while the relay was unavailable.
  if abs(p_event_created_at - extract(epoch from clock_timestamp())::bigint) > 300 then
    raise exception 'STAGING_PARTICIPANT_MIRROR_EVENT_STALE' using errcode = 'P0001';
  end if;

  if not exists (
    select 1
      from public.posts p
      join staging_participant_private.staging_participant_write_audit a
        on a.result_id = p.id and a.action = 'post' and a.wallet_address = v_wallet
     where p.id = p_source_post_id
       and lower(p.wallet_address) = v_wallet
       and p.account_id is null and p.feed_type = 'main' and p.post_type = 'user'
       and p.category = 'generell' and p.status = 'published'
       and coalesce(cardinality(p.media_urls), 0) = 0 and p.video_url is null
       and p.linked_event_id is null and p.linked_experience_id is null
       and extensions.digest(p.content, 'sha256') = v_content_sha
  ) then
    raise exception 'STAGING_PARTICIPANT_MIRROR_SOURCE_INVALID' using errcode = 'P0001';
  end if;

  insert into staging_participant_private.staging_participant_nostr_post_mirror_receipts (
    wallet_address, source_post_id, request_id, event_id, event_created_at, content_sha256
  ) values (v_wallet, p_source_post_id, p_request_id, v_event_id, p_event_created_at, v_content_sha)
  returning * into v_receipt;
  return jsonb_build_object(
    'wallet_address', v_receipt.wallet_address,
    'source_post_id', v_receipt.source_post_id,
    'request_id', v_receipt.request_id,
    'event_id', v_receipt.event_id,
    'event_created_at', v_receipt.event_created_at,
    'content_sha256', encode(v_receipt.content_sha256, 'hex'),
    'state', v_receipt.state
  );
end;
$$;

-- Only the exact receipt that was reserved before external publication may be
-- completed. No retry can replace its event id or change its source content.
create or replace function public.staging_participant_gateway_complete_nostr_post_mirror(
  p_wallet_address text,
  p_source_post_id uuid,
  p_request_id uuid,
  p_event_id text,
  p_content_sha256 text
) returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public, staging_participant_private
as $$
declare
  v_wallet text := lower(p_wallet_address);
  v_event_id text := lower(p_event_id);
  v_content_sha bytea;
  v_receipt staging_participant_private.staging_participant_nostr_post_mirror_receipts%rowtype;
begin
  perform staging_participant_private.require_staging_participant_gateway();
  if p_wallet_address is null or v_wallet !~ '^0x[0-9a-f]{40}$'
     or p_source_post_id is null or p_request_id is null
     or p_event_id is null or v_event_id !~ '^[0-9a-f]{64}$'
     or p_content_sha256 is null or lower(p_content_sha256) !~ '^[0-9a-f]{64}$' then
    raise exception 'STAGING_PARTICIPANT_MIRROR_INVALID' using errcode = 'P0001';
  end if;
  v_content_sha := decode(lower(p_content_sha256), 'hex');
  perform staging_participant_private.ensure_active_staging_participant(v_wallet);
  perform pg_advisory_xact_lock(hashtextextended(v_wallet || ':' || p_source_post_id::text, 20260825));
  select * into v_receipt
    from staging_participant_private.staging_participant_nostr_post_mirror_receipts
   where wallet_address = v_wallet and source_post_id = p_source_post_id
   for update;
  if not found then
    raise exception 'STAGING_PARTICIPANT_MIRROR_RECEIPT_MISSING' using errcode = 'P0001';
  end if;
  if v_receipt.request_id <> p_request_id or v_receipt.event_id <> v_event_id
     or v_receipt.content_sha256 <> v_content_sha then
    raise exception 'STAGING_PARTICIPANT_MIRROR_RECEIPT_MISMATCH' using errcode = 'P0001';
  end if;
  if v_receipt.state = 'reserved' then
    update staging_participant_private.staging_participant_nostr_post_mirror_receipts
       set state = 'published', published_at = now()
     where wallet_address = v_wallet and source_post_id = p_source_post_id
     returning * into v_receipt;
  end if;
  return jsonb_build_object(
    'wallet_address', v_receipt.wallet_address,
    'source_post_id', v_receipt.source_post_id,
    'request_id', v_receipt.request_id,
    'event_id', v_receipt.event_id,
    'event_created_at', v_receipt.event_created_at,
    'content_sha256', encode(v_receipt.content_sha256, 'hex'),
    'state', v_receipt.state
  );
end;
$$;

-- Exact no-argument readiness RPC. It is intentionally not a generic
-- diagnostics endpoint: fixed catalog checks, no DML, no dynamic object
-- selection, and a two-field response only.
create or replace function public.staging_participant_gateway_preflight()
returns jsonb
language plpgsql
stable
security definer
set search_path = pg_catalog, public, staging_participant_private
as $$
declare
  v_marker staging_participant_private.staging_participant_schema_contract%rowtype;
  v_table text;
  v_column text;
  v_function text;
  v_expected_search_path text;
  v_expected_volatility "char";
begin
  perform staging_participant_private.require_staging_participant_gateway();
  select * into strict v_marker
    from staging_participant_private.staging_participant_schema_contract
   where singleton;
  if v_marker.migration_id <> '20260825_staging_participant_gateway'
     or v_marker.canonical_contract <> $contract${"assertions":{"catalog":{"capturedDefinitionAndSourceDigests":true,"capturedOwnerLanguageReturnVolatilitySecuritySearchPath":true,"priorRollbackEvidenceDigests":true},"deniedExecute":["public.delete_owned_post(uuid,text)","public.delete_owned_post_comment(uuid,text)","public.delete_owned_experience(uuid,text)","public.pin_own_post(uuid,text,boolean)"],"privateTables":["staging_participant_private.staging_participant_environment","staging_participant_private.staging_participant_admissions","staging_participant_private.staging_participant_write_reservations","staging_participant_private.staging_participant_write_audit","staging_participant_private.staging_participant_nostr_post_mirror_receipts","staging_participant_private.staging_participant_schema_contract","staging_participant_private.staging_participant_catalog_contract","staging_participant_private.staging_participant_prior_function_definitions","staging_participant_private.staging_participant_prior_privileges"],"publicRpc":["public.staging_participant_gateway_create_main_text_post(text,text,uuid)","public.staging_participant_gateway_create_main_text_comment(text,uuid,text,uuid)","public.staging_participant_gateway_read_owned_main_text_post(text,uuid)","public.staging_participant_gateway_reserve_nostr_post_mirror(text,uuid,uuid,text,bigint,text)","public.staging_participant_gateway_complete_nostr_post_mirror(text,uuid,uuid,text,text)","public.staging_participant_gateway_preflight()"],"triggers":{"commentCount":{"function":"public.post_comment_counts_sync()","name":"trg_post_comment_counts","noArgs":true,"noWhen":true,"table":"public.post_comments","tgtype":13},"posting":{"function":"public.enforce_posting_rules()","name":"enforce_posting_rules_trg","noArgs":true,"noWhen":true,"table":"public.posts","tgtype":7}}},"migrationId":"20260825_staging_participant_gateway","schemaVersion":"roebel_staging_participant_gateway_schema_contract_v1"}
$contract$
     or v_marker.database_schema_sha256 <> 'sha256:a540591c718d4b2c74f56fe7310baf5b522ac6541384223a5263079e207f3d5d'
     or extensions.digest(v_marker.canonical_contract, 'sha256') <> decode('a540591c718d4b2c74f56fe7310baf5b522ac6541384223a5263079e207f3d5d', 'hex') then
    raise exception 'STAGING_PARTICIPANT_SCHEMA_MARKER_INVALID' using errcode = 'P0001';
  end if;
  if not exists (
    select 1 from pg_catalog.pg_proc p
     where p.oid = 'public.staging_participant_gateway_preflight()'::pg_catalog.regprocedure
       and p.prosecdef and p.provolatile = 's'::"char" and p.pronargs = 0
  ) or not exists (
    select 1 from pg_catalog.pg_trigger t
     where t.tgrelid = 'public.posts'::pg_catalog.regclass
       and t.tgfoid = 'public.enforce_posting_rules()'::pg_catalog.regprocedure
       and not t.tgisinternal and t.tgenabled <> 'D'
  ) then
    raise exception 'STAGING_PARTICIPANT_SCHEMA_CATALOG_INVALID' using errcode = 'P0001';
  end if;
  foreach v_table in array array['public.posts', 'public.post_comments', 'public.post_likes', 'public.app_settings'] loop
    if has_table_privilege('anon', v_table, 'INSERT')
       or has_table_privilege('anon', v_table, 'UPDATE')
       or has_table_privilege('anon', v_table, 'DELETE')
       or has_table_privilege('authenticated', v_table, 'INSERT')
       or has_table_privilege('authenticated', v_table, 'UPDATE')
       or has_table_privilege('authenticated', v_table, 'DELETE') then
      raise exception 'STAGING_PARTICIPANT_SCHEMA_ACL_INVALID:%', v_table using errcode = 'P0001';
    end if;
    for v_column in
      select a.attname
        from pg_catalog.pg_attribute a
       where a.attrelid = to_regclass(v_table)
         and a.attnum > 0 and not a.attisdropped
    loop
      if has_column_privilege('anon', v_table, v_column, 'INSERT')
         or has_column_privilege('anon', v_table, v_column, 'UPDATE')
         or has_column_privilege('authenticated', v_table, v_column, 'INSERT')
         or has_column_privilege('authenticated', v_table, v_column, 'UPDATE') then
        raise exception 'STAGING_PARTICIPANT_SCHEMA_COLUMN_ACL_INVALID:%.%', v_table, v_column using errcode = 'P0001';
      end if;
    end loop;
  end loop;
  foreach v_function in array array[
    'public.staging_participant_gateway_create_main_text_post(text,text,uuid)',
    'public.staging_participant_gateway_create_main_text_comment(text,uuid,text,uuid)',
    'public.staging_participant_gateway_read_owned_main_text_post(text,uuid)',
    'public.staging_participant_gateway_reserve_nostr_post_mirror(text,uuid,uuid,text,bigint,text)',
    'public.staging_participant_gateway_complete_nostr_post_mirror(text,uuid,uuid,text,text)',
    'public.staging_participant_gateway_preflight()'
  ] loop
    if not exists (
      select 1 from pg_catalog.pg_proc p
       where p.oid = to_regprocedure(v_function)
         and p.prosecdef
         and p.proconfig @> array['search_path=pg_catalog, public, staging_participant_private']
    ) or has_function_privilege('authenticated', to_regprocedure(v_function), 'EXECUTE')
       or not has_function_privilege('anon', to_regprocedure(v_function), 'EXECUTE')
       or exists (
         select 1 from pg_catalog.pg_proc p
         cross join lateral pg_catalog.aclexplode(coalesce(p.proacl, pg_catalog.acldefault('f', p.proowner))) acl
          where p.oid = to_regprocedure(v_function)
            and acl.grantee = 0 and acl.privilege_type = 'EXECUTE'
       ) then
      raise exception 'STAGING_PARTICIPANT_SCHEMA_FUNCTION_INVALID:%', v_function using errcode = 'P0001';
    end if;
  end loop;
  foreach v_function in array array[
    'staging_participant_private.require_staging_participant_gateway()',
    'staging_participant_private.staging_participant_rpc_secret()',
    'staging_participant_private.ensure_active_staging_participant(text)',
    'staging_participant_private.consume_staging_post_reservation(public.posts)'
  ] loop
    v_expected_search_path := case v_function
      when 'staging_participant_private.staging_participant_rpc_secret()' then 'search_path=pg_catalog, vault'
      else 'search_path=pg_catalog, staging_participant_private'
    end;
    v_expected_volatility := case v_function
      when 'staging_participant_private.staging_participant_rpc_secret()' then 's'::"char"
      else 'v'::"char"
    end;
    if not exists (
      select 1 from pg_catalog.pg_proc p
       where p.oid = to_regprocedure(v_function)
         and p.prosecdef and p.provolatile = v_expected_volatility
         and p.proconfig @> array[v_expected_search_path]
    ) or has_function_privilege('anon', to_regprocedure(v_function), 'EXECUTE')
       or has_function_privilege('authenticated', to_regprocedure(v_function), 'EXECUTE')
       or exists (
         select 1 from pg_catalog.pg_proc p
         cross join lateral pg_catalog.aclexplode(coalesce(p.proacl, pg_catalog.acldefault('f', p.proowner))) acl
          where p.oid = to_regprocedure(v_function)
            and acl.grantee = 0 and acl.privilege_type = 'EXECUTE'
       ) then
      raise exception 'STAGING_PARTICIPANT_SCHEMA_PRIVATE_FUNCTION_INVALID:%', v_function using errcode = 'P0001';
    end if;
  end loop;
  foreach v_table in array array[
    'staging_participant_private.staging_participant_environment',
    'staging_participant_private.staging_participant_admissions',
    'staging_participant_private.staging_participant_write_reservations',
    'staging_participant_private.staging_participant_write_audit',
    'staging_participant_private.staging_participant_nostr_post_mirror_receipts',
    'staging_participant_private.staging_participant_schema_contract',
    'staging_participant_private.staging_participant_catalog_contract',
    'staging_participant_private.staging_participant_prior_function_definitions',
    'staging_participant_private.staging_participant_prior_privileges'
  ] loop
    if not exists (select 1 from pg_catalog.pg_class where oid = to_regclass(v_table) and relrowsecurity) then
      raise exception 'STAGING_PARTICIPANT_SCHEMA_PRIVATE_TABLE_INVALID:%', v_table using errcode = 'P0001';
    end if;
  end loop;
  if (select count(*) from staging_participant_private.staging_participant_catalog_contract) <> 12
     or exists (
       select 1
         from staging_participant_private.staging_participant_catalog_contract contract
         left join pg_catalog.pg_proc proc on proc.oid = to_regprocedure(contract.object_identity)
         left join pg_catalog.pg_roles owner_role on owner_role.oid = proc.proowner
         left join pg_catalog.pg_language language on language.oid = proc.prolang
        where proc.oid is null
           or owner_role.rolname <> contract.owner_name
           or language.lanname <> contract.language_name
           or pg_catalog.pg_get_function_result(proc.oid) <> contract.return_type
           or proc.provolatile <> contract.volatility
           or proc.prosecdef <> contract.security_definer
           or coalesce(array_to_string(proc.proconfig, E'\n'), '') <> contract.search_path
           or encode(extensions.digest(pg_catalog.pg_get_functiondef(proc.oid), 'sha256'), 'hex') <> contract.definition_sha256
           or encode(extensions.digest(proc.prosrc, 'sha256'), 'hex') <> contract.source_sha256
     ) then
    raise exception 'STAGING_PARTICIPANT_SCHEMA_EXECUTABLE_CATALOG_INVALID' using errcode = 'P0001';
  end if;
  if not exists (
    select 1 from pg_catalog.pg_trigger trigger
     where trigger.tgrelid = 'public.posts'::pg_catalog.regclass
       and trigger.tgname = 'enforce_posting_rules_trg'
       and trigger.tgfoid = 'public.enforce_posting_rules()'::pg_catalog.regprocedure
       and trigger.tgtype = 7 and trigger.tgenabled in ('O', 'A')
       and trigger.tgargs = ''::bytea and trigger.tgqual is null
       and not trigger.tgisinternal
  ) or not exists (
    select 1 from pg_catalog.pg_trigger trigger
     where trigger.tgrelid = 'public.post_comments'::pg_catalog.regclass
       and trigger.tgname = 'trg_post_comment_counts'
       and trigger.tgfoid = 'public.post_comment_counts_sync()'::pg_catalog.regprocedure
       and trigger.tgtype = 13 and trigger.tgenabled in ('O', 'A')
       and trigger.tgargs = ''::bytea and trigger.tgqual is null
       and not trigger.tgisinternal
  ) then
    raise exception 'STAGING_PARTICIPANT_SCHEMA_TRIGGER_INVALID' using errcode = 'P0001';
  end if;
  foreach v_function in array array[
    'public.delete_owned_post(uuid,text)',
    'public.delete_owned_post_comment(uuid,text)',
    'public.delete_owned_experience(uuid,text)',
    'public.pin_own_post(uuid,text,boolean)'
  ] loop
    if to_regprocedure(v_function) is null
       or has_function_privilege('anon', to_regprocedure(v_function), 'EXECUTE')
       or has_function_privilege('authenticated', to_regprocedure(v_function), 'EXECUTE')
       or exists (
         select 1 from pg_catalog.pg_proc proc
         cross join lateral pg_catalog.aclexplode(coalesce(proc.proacl, pg_catalog.acldefault('f', proc.proowner))) acl
          where proc.oid = to_regprocedure(v_function)
            and acl.grantee = 0 and acl.privilege_type = 'EXECUTE'
       ) then
      raise exception 'STAGING_PARTICIPANT_SCHEMA_LEGACY_EXECUTE_INVALID:%', v_function using errcode = 'P0001';
    end if;
  end loop;
  if v_marker.prior_function_definitions_sha256 is null
     or v_marker.prior_privileges_sha256 is null
     or v_marker.prior_function_definitions_sha256 <> (
       select encode(extensions.digest(coalesce(string_agg(
         object_identity || E'\x1f' || definition, E'\x1e' order by object_identity
       ), ''), 'sha256'), 'hex')
         from staging_participant_private.staging_participant_prior_function_definitions
     ) or v_marker.prior_privileges_sha256 <> (
       select encode(extensions.digest(coalesce(string_agg(
         object_kind || E'\x1f' || object_identity || E'\x1f' || column_name || E'\x1f' ||
         grantee || E'\x1f' || privilege_type || E'\x1f' || is_grantable::text,
         E'\x1e' order by object_kind, object_identity, column_name, grantee, privilege_type
       ), ''), 'sha256'), 'hex')
         from staging_participant_private.staging_participant_prior_privileges
     ) then
    raise exception 'STAGING_PARTICIPANT_SCHEMA_ROLLBACK_EVIDENCE_INVALID' using errcode = 'P0001';
  end if;
  return jsonb_build_object(
    'migration_id', v_marker.migration_id,
    'database_schema_sha256', v_marker.database_schema_sha256
  );
end;
$$;

-- Freeze the activation-trusted executable catalog after every owned helper
-- and RPC exists. The status RPC compares the live catalog to these rows.
insert into staging_participant_private.staging_participant_catalog_contract (
  object_identity, owner_name, language_name, return_type, volatility,
  security_definer, search_path, definition_sha256, source_sha256
)
select target.object_identity, owner_role.rolname, language.lanname,
       pg_catalog.pg_get_function_result(proc.oid), proc.provolatile,
       proc.prosecdef, coalesce(array_to_string(proc.proconfig, E'\n'), ''),
       encode(extensions.digest(pg_catalog.pg_get_functiondef(proc.oid), 'sha256'), 'hex'),
       encode(extensions.digest(proc.prosrc, 'sha256'), 'hex')
  from (values
    ('public.enforce_posting_rules()'),
    ('public.post_comment_counts_sync()'),
    ('public.staging_participant_gateway_create_main_text_post(text,text,uuid)'),
    ('public.staging_participant_gateway_create_main_text_comment(text,uuid,text,uuid)'),
    ('public.staging_participant_gateway_read_owned_main_text_post(text,uuid)'),
    ('public.staging_participant_gateway_reserve_nostr_post_mirror(text,uuid,uuid,text,bigint,text)'),
    ('public.staging_participant_gateway_complete_nostr_post_mirror(text,uuid,uuid,text,text)'),
    ('public.staging_participant_gateway_preflight()'),
    ('staging_participant_private.staging_participant_rpc_secret()'),
    ('staging_participant_private.require_staging_participant_gateway()'),
    ('staging_participant_private.ensure_active_staging_participant(text)'),
    ('staging_participant_private.consume_staging_post_reservation(public.posts)')
  ) target(object_identity)
  join pg_catalog.pg_proc proc on proc.oid = pg_catalog.to_regprocedure(target.object_identity)
  join pg_catalog.pg_roles owner_role on owner_role.oid = proc.proowner
  join pg_catalog.pg_language language on language.oid = proc.prolang;

-- These rollback records are deactivation evidence. Store deterministic raw
-- snapshots so missing or edited compatibility rows fail the readiness proof.
update staging_participant_private.staging_participant_schema_contract marker
   set prior_function_definitions_sha256 = (
         select encode(extensions.digest(coalesce(string_agg(
           object_identity || E'\x1f' || definition, E'\x1e' order by object_identity
         ), ''), 'sha256'), 'hex')
           from staging_participant_private.staging_participant_prior_function_definitions
       ),
       prior_privileges_sha256 = (
         select encode(extensions.digest(coalesce(string_agg(
           object_kind || E'\x1f' || object_identity || E'\x1f' || column_name || E'\x1f' ||
           grantee || E'\x1f' || privilege_type || E'\x1f' || is_grantable::text,
           E'\x1e' order by object_kind, object_identity, column_name, grantee, privilege_type
         ), ''), 'sha256'), 'hex')
           from staging_participant_private.staging_participant_prior_privileges
       )
 where singleton;

revoke all on function public.staging_participant_gateway_create_main_text_post(text, text, uuid)
  from public, anon, authenticated;
revoke all on function public.staging_participant_gateway_create_main_text_comment(text, uuid, text, uuid)
  from public, anon, authenticated;
revoke all on function public.staging_participant_gateway_read_owned_main_text_post(text, uuid)
  from public, anon, authenticated;
revoke all on function public.staging_participant_gateway_reserve_nostr_post_mirror(text, uuid, uuid, text, bigint, text)
  from public, anon, authenticated;
revoke all on function public.staging_participant_gateway_complete_nostr_post_mirror(text, uuid, uuid, text, text)
  from public, anon, authenticated;
revoke all on function public.staging_participant_gateway_preflight()
  from public, anon, authenticated;
grant execute on function public.staging_participant_gateway_create_main_text_post(text, text, uuid)
  to anon;
grant execute on function public.staging_participant_gateway_create_main_text_comment(text, uuid, text, uuid)
  to anon;
grant execute on function public.staging_participant_gateway_read_owned_main_text_post(text, uuid)
  to anon;
grant execute on function public.staging_participant_gateway_reserve_nostr_post_mirror(text, uuid, uuid, text, bigint, text)
  to anon;
grant execute on function public.staging_participant_gateway_complete_nostr_post_mirror(text, uuid, uuid, text, text)
  to anon;
grant execute on function public.staging_participant_gateway_preflight()
  to anon;

comment on function public.staging_participant_gateway_create_main_text_post(text, text, uuid)
  is 'STAGING ONLY: exact text-only main-feed post capability for ADR 0021.';
comment on function public.staging_participant_gateway_create_main_text_comment(text, uuid, text, uuid)
  is 'STAGING ONLY: exact text-only main-feed comment capability for ADR 0021.';
comment on function public.staging_participant_gateway_read_owned_main_text_post(text, uuid)
  is 'STAGING ONLY: exact participant-owned source row for a same-thread Nostr Mecky mention.';
comment on function public.staging_participant_gateway_reserve_nostr_post_mirror(text, uuid, uuid, text, bigint, text)
  is 'STAGING ONLY: fresh-first durable immutable post-to-Nostr conversation receipt reservation for ADR 0021.';
comment on function public.staging_participant_gateway_complete_nostr_post_mirror(text, uuid, uuid, text, text)
  is 'STAGING ONLY: completes only the exact durable post-to-Nostr receipt for ADR 0021.';
comment on function public.staging_participant_gateway_preflight()
  is 'STAGING ONLY: catalog-bound readiness proof for the exact ADR 0021 gateway migration.';

commit;
