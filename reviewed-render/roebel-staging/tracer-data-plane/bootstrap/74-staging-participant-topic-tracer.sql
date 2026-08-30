-- ADR 0022: durable, no-authority topic-tracer claims.
--
-- This is intentionally a new migration. It does not modify the already
-- deployed 20260825 participant gateway contract. The private workbench is
-- responsible for resolving and publishing signed Nostr artifacts; these RPCs
-- only atomically bind the server-verified artifact identities to the one
-- invited participant's already-admitted ordinary source row.

begin;

do $$
begin
  if not exists (
    select 1 from public.app_settings where key = 'roebel_env' and value = 'staging'
  ) or not exists (
    select 1 from vault.decrypted_secrets
     where name = 'roebel_staging_participant_environment_arm'
       and decrypted_secret = 'staging-only'
  ) or not exists (
    select 1 from vault.decrypted_secrets
     where name = 'roebel_staging_participant_rpc_secret'
       and length(decrypted_secret) >= 32
  ) then
    raise exception 'STAGING_PARTICIPANT_TOPIC_TRACER_REQUIRES_ARMED_STAGING'
      using errcode = 'P0001';
  end if;
end;
$$;

create table staging_participant_private.staging_participant_source_post_promotions (
  namespace text not null,
  wallet_address text not null references staging_participant_private.staging_participant_admissions(wallet_address),
  source_post_id uuid not null,
  request_id uuid not null unique,
  idempotency_key_sha256 bytea not null,
  discussion_root_id text not null,
  discussion_root_sha256 bytea not null,
  topic_id text not null,
  policy_version text not null,
  state text not null default 'reserved' check (state in ('reserved', 'published')),
  receipt_checksum bytea not null,
  created_at timestamptz not null default clock_timestamp(),
  published_at timestamptz,
  primary key (namespace, source_post_id),
  check (namespace ~ '^urn:stadtstack:topic:municipality:[a-z0-9][a-z0-9-]{0,63}$'),
  check (topic_id like namespace || ':%'),
  check (discussion_root_id ~ '^[0-9a-f]{64}$'),
  check (octet_length(idempotency_key_sha256) = 32),
  check (octet_length(discussion_root_sha256) = 32),
  check (octet_length(receipt_checksum) = 32),
  check ((state = 'reserved' and published_at is null) or (state = 'published' and published_at is not null))
);

create table staging_participant_private.staging_participant_topic_suggestions (
  namespace text not null,
  wallet_address text not null references staging_participant_private.staging_participant_admissions(wallet_address),
  discussion_root_id text not null,
  source_author_pubkey text not null,
  request_id uuid not null unique,
  idempotency_key_sha256 bytea not null,
  suggestion_id text not null,
  suggestion_sha256 bytea not null,
  mecky_answer_id text not null,
  mecky_receipt_id text not null,
  topic_id text not null,
  policy_version text not null,
  state text not null default 'reserved' check (state in ('reserved', 'published')),
  receipt_checksum bytea not null,
  created_at timestamptz not null default clock_timestamp(),
  published_at timestamptz,
  primary key (namespace, discussion_root_id, source_author_pubkey),
  check (namespace ~ '^urn:stadtstack:topic:municipality:[a-z0-9][a-z0-9-]{0,63}$'),
  check (topic_id like namespace || ':%'),
  check (discussion_root_id ~ '^[0-9a-f]{64}$'),
  check (source_author_pubkey ~ '^[0-9a-f]{64}$'),
  check (suggestion_id ~ '^[0-9a-f]{64}$'),
  check (mecky_answer_id ~ '^[0-9a-f]{64}$'),
  check (mecky_receipt_id ~ '^urn:stadtstack:mecky-answer:[0-9a-f]{64}$'),
  check (octet_length(idempotency_key_sha256) = 32),
  check (octet_length(suggestion_sha256) = 32),
  check (octet_length(receipt_checksum) = 32),
  check ((state = 'reserved' and published_at is null) or (state = 'published' and published_at is not null))
);

alter table staging_participant_private.staging_participant_source_post_promotions enable row level security;
alter table staging_participant_private.staging_participant_topic_suggestions enable row level security;

create or replace function staging_participant_private.staging_participant_topic_receipt_checksum(
  p_values text[]
) returns bytea
language sql
immutable
security definer
set search_path = pg_catalog, extensions
as $$ select extensions.digest(array_to_string(p_values, E'\x1f'), 'sha256') $$;

revoke all on function staging_participant_private.staging_participant_topic_receipt_checksum(text[]) from public, anon, authenticated;

create or replace function public.staging_participant_gateway_reserve_source_post_promotion(
  p_wallet_address text,
  p_namespace text,
  p_source_post_id uuid,
  p_request_id uuid,
  p_idempotency_key_sha256 text,
  p_discussion_root_id text,
  p_discussion_root_sha256 text,
  p_topic_id text,
  p_policy_version text
) returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, public, staging_participant_private, extensions
as $$
declare
  v_wallet text := lower(p_wallet_address);
  v_namespace text := p_namespace;
  v_root_id text := lower(p_discussion_root_id);
  v_idempotency bytea;
  v_root_sha bytea;
  v_receipt staging_participant_private.staging_participant_source_post_promotions%rowtype;
begin
  perform staging_participant_private.require_staging_participant_gateway();
  if p_wallet_address is null or v_wallet !~ '^0x[0-9a-f]{40}$' or p_namespace is null
     or p_namespace !~ '^urn:stadtstack:topic:municipality:[a-z0-9][a-z0-9-]{0,63}$'
     or p_source_post_id is null or p_request_id is null
     or p_idempotency_key_sha256 is null or lower(p_idempotency_key_sha256) !~ '^[0-9a-f]{64}$'
     or p_discussion_root_id is null or v_root_id !~ '^[0-9a-f]{64}$'
     or p_discussion_root_sha256 is null or lower(p_discussion_root_sha256) !~ '^[0-9a-f]{64}$'
     or p_topic_id is null or p_topic_id not like p_namespace || ':%'
     or p_policy_version is null or p_policy_version !~ '^[a-z0-9][a-z0-9._-]{2,99}$' then
    raise exception 'STAGING_PARTICIPANT_PROMOTION_INVALID' using errcode = 'P0001';
  end if;
  v_idempotency := decode(lower(p_idempotency_key_sha256), 'hex');
  v_root_sha := decode(lower(p_discussion_root_sha256), 'hex');
  perform staging_participant_private.ensure_active_staging_participant(v_wallet);
  perform pg_advisory_xact_lock(hashtextextended(v_namespace || ':' || p_source_post_id::text, 20260825));

  select * into v_receipt from staging_participant_private.staging_participant_source_post_promotions
   where namespace = v_namespace and source_post_id = p_source_post_id;
  if found then
    if v_receipt.wallet_address <> v_wallet or v_receipt.request_id <> p_request_id
       or v_receipt.idempotency_key_sha256 <> v_idempotency or v_receipt.discussion_root_id <> v_root_id
       or v_receipt.discussion_root_sha256 <> v_root_sha or v_receipt.topic_id <> p_topic_id
       or v_receipt.policy_version <> p_policy_version then
      raise exception 'STAGING_PARTICIPANT_PROMOTION_SOURCE_REUSED' using errcode = 'P0001';
    end if;
    return jsonb_build_object(
      'namespace', v_receipt.namespace, 'wallet_address', v_receipt.wallet_address,
      'source_post_id', v_receipt.source_post_id, 'request_id', v_receipt.request_id,
      'idempotency_key_sha256', encode(v_receipt.idempotency_key_sha256, 'hex'),
      'discussion_root_id', v_receipt.discussion_root_id,
      'discussion_root_sha256', encode(v_receipt.discussion_root_sha256, 'hex'),
      'topic_id', v_receipt.topic_id, 'policy_version', v_receipt.policy_version,
      'state', v_receipt.state, 'receipt_checksum', encode(v_receipt.receipt_checksum, 'hex')
    );
  end if;
  if exists (select 1 from staging_participant_private.staging_participant_source_post_promotions where request_id = p_request_id) then
    raise exception 'STAGING_PARTICIPANT_PROMOTION_REQUEST_REUSED' using errcode = 'P0001';
  end if;
  if not exists (
    select 1 from public.posts p
    join staging_participant_private.staging_participant_write_audit a
      on a.result_id = p.id and a.action = 'post' and a.wallet_address = v_wallet
     where p.id = p_source_post_id and lower(p.wallet_address) = v_wallet and p.account_id is null
       and p.feed_type = 'main' and p.post_type = 'user' and p.category = 'generell'
       and p.status = 'published' and coalesce(cardinality(p.media_urls), 0) = 0
       and p.video_url is null and p.linked_event_id is null and p.linked_experience_id is null
  ) then
    raise exception 'STAGING_PARTICIPANT_PROMOTION_SOURCE_INVALID' using errcode = 'P0001';
  end if;
  insert into staging_participant_private.staging_participant_source_post_promotions (
    namespace, wallet_address, source_post_id, request_id, idempotency_key_sha256,
    discussion_root_id, discussion_root_sha256, topic_id, policy_version, receipt_checksum
  ) values (
    v_namespace, v_wallet, p_source_post_id, p_request_id, v_idempotency, v_root_id, v_root_sha,
    p_topic_id, p_policy_version,
    staging_participant_private.staging_participant_topic_receipt_checksum(array[
      v_namespace, v_wallet, p_source_post_id::text, p_request_id::text, encode(v_idempotency, 'hex'),
      v_root_id, encode(v_root_sha, 'hex'), p_topic_id, p_policy_version
    ])
  ) returning * into v_receipt;
  return jsonb_build_object(
    'namespace', v_receipt.namespace, 'wallet_address', v_receipt.wallet_address,
    'source_post_id', v_receipt.source_post_id, 'request_id', v_receipt.request_id,
    'idempotency_key_sha256', encode(v_receipt.idempotency_key_sha256, 'hex'),
    'discussion_root_id', v_receipt.discussion_root_id,
    'discussion_root_sha256', encode(v_receipt.discussion_root_sha256, 'hex'),
    'topic_id', v_receipt.topic_id, 'policy_version', v_receipt.policy_version,
    'state', v_receipt.state, 'receipt_checksum', encode(v_receipt.receipt_checksum, 'hex')
  );
end;
$$;

create or replace function public.staging_participant_gateway_complete_source_post_promotion(
  p_wallet_address text, p_namespace text, p_source_post_id uuid, p_request_id uuid,
  p_idempotency_key_sha256 text, p_discussion_root_id text, p_discussion_root_sha256 text
) returns jsonb
language plpgsql security definer
set search_path = pg_catalog, public, staging_participant_private
as $$
declare
  v_wallet text := lower(p_wallet_address);
  v_receipt staging_participant_private.staging_participant_source_post_promotions%rowtype;
begin
  perform staging_participant_private.require_staging_participant_gateway();
  if p_wallet_address is null or v_wallet !~ '^0x[0-9a-f]{40}$' or p_namespace is null
     or p_source_post_id is null or p_request_id is null or p_idempotency_key_sha256 is null
     or lower(p_idempotency_key_sha256) !~ '^[0-9a-f]{64}$' or p_discussion_root_id is null
     or lower(p_discussion_root_id) !~ '^[0-9a-f]{64}$' or p_discussion_root_sha256 is null
     or lower(p_discussion_root_sha256) !~ '^[0-9a-f]{64}$' then
    raise exception 'STAGING_PARTICIPANT_PROMOTION_INVALID' using errcode = 'P0001';
  end if;
  perform staging_participant_private.ensure_active_staging_participant(v_wallet);
  perform pg_advisory_xact_lock(hashtextextended(p_namespace || ':' || p_source_post_id::text, 20260825));
  select * into v_receipt from staging_participant_private.staging_participant_source_post_promotions
   where namespace = p_namespace and source_post_id = p_source_post_id for update;
  if not found then raise exception 'STAGING_PARTICIPANT_PROMOTION_RECEIPT_MISSING' using errcode = 'P0001'; end if;
  if v_receipt.wallet_address <> v_wallet or v_receipt.request_id <> p_request_id
     or encode(v_receipt.idempotency_key_sha256, 'hex') <> lower(p_idempotency_key_sha256)
     or v_receipt.discussion_root_id <> lower(p_discussion_root_id)
     or encode(v_receipt.discussion_root_sha256, 'hex') <> lower(p_discussion_root_sha256) then
    raise exception 'STAGING_PARTICIPANT_PROMOTION_RECEIPT_MISMATCH' using errcode = 'P0001';
  end if;
  if v_receipt.state = 'reserved' then
    update staging_participant_private.staging_participant_source_post_promotions
       set state = 'published', published_at = clock_timestamp()
     where namespace = p_namespace and source_post_id = p_source_post_id returning * into v_receipt;
  end if;
  return jsonb_build_object(
    'namespace', v_receipt.namespace, 'wallet_address', v_receipt.wallet_address,
    'source_post_id', v_receipt.source_post_id, 'request_id', v_receipt.request_id,
    'idempotency_key_sha256', encode(v_receipt.idempotency_key_sha256, 'hex'),
    'discussion_root_id', v_receipt.discussion_root_id,
    'discussion_root_sha256', encode(v_receipt.discussion_root_sha256, 'hex'),
    'topic_id', v_receipt.topic_id, 'policy_version', v_receipt.policy_version,
    'state', v_receipt.state, 'receipt_checksum', encode(v_receipt.receipt_checksum, 'hex')
  );
end;
$$;

create or replace function public.staging_participant_gateway_reserve_topic_suggestion(
  p_wallet_address text, p_namespace text, p_discussion_root_id text, p_source_author_pubkey text,
  p_request_id uuid, p_idempotency_key_sha256 text, p_suggestion_id text, p_suggestion_sha256 text,
  p_mecky_answer_id text, p_mecky_receipt_id text, p_topic_id text, p_policy_version text
) returns jsonb
language plpgsql security definer
set search_path = pg_catalog, public, staging_participant_private, extensions
as $$
declare
  v_wallet text := lower(p_wallet_address);
  v_root text := lower(p_discussion_root_id);
  v_author text := lower(p_source_author_pubkey);
  v_suggestion text := lower(p_suggestion_id);
  v_answer text := lower(p_mecky_answer_id);
  v_idempotency bytea;
  v_suggestion_sha bytea;
  v_receipt staging_participant_private.staging_participant_topic_suggestions%rowtype;
begin
  perform staging_participant_private.require_staging_participant_gateway();
  if p_wallet_address is null or v_wallet !~ '^0x[0-9a-f]{40}$' or p_namespace is null
     or p_namespace !~ '^urn:stadtstack:topic:municipality:[a-z0-9][a-z0-9-]{0,63}$'
     or p_discussion_root_id is null or v_root !~ '^[0-9a-f]{64}$'
     or p_source_author_pubkey is null or v_author !~ '^[0-9a-f]{64}$' or p_request_id is null
     or p_idempotency_key_sha256 is null or lower(p_idempotency_key_sha256) !~ '^[0-9a-f]{64}$'
     or p_suggestion_id is null or v_suggestion !~ '^[0-9a-f]{64}$'
     or p_suggestion_sha256 is null or lower(p_suggestion_sha256) !~ '^[0-9a-f]{64}$'
     or p_mecky_answer_id is null or v_answer !~ '^[0-9a-f]{64}$'
     or p_mecky_receipt_id is null or p_mecky_receipt_id !~ '^urn:stadtstack:mecky-answer:[0-9a-f]{64}$'
     or p_topic_id is null or p_topic_id not like p_namespace || ':%'
     or p_policy_version is null or p_policy_version !~ '^[a-z0-9][a-z0-9._-]{2,99}$' then
    raise exception 'STAGING_PARTICIPANT_SUGGESTION_INVALID' using errcode = 'P0001';
  end if;
  v_idempotency := decode(lower(p_idempotency_key_sha256), 'hex');
  v_suggestion_sha := decode(lower(p_suggestion_sha256), 'hex');
  perform staging_participant_private.ensure_active_staging_participant(v_wallet);
  perform pg_advisory_xact_lock(hashtextextended(p_namespace || ':' || v_root || ':' || v_author, 20260825));
  select * into v_receipt from staging_participant_private.staging_participant_topic_suggestions
   where namespace = p_namespace and discussion_root_id = v_root and source_author_pubkey = v_author;
  if found then
    if v_receipt.wallet_address <> v_wallet or v_receipt.request_id <> p_request_id
       or v_receipt.idempotency_key_sha256 <> v_idempotency or v_receipt.suggestion_id <> v_suggestion
       or v_receipt.suggestion_sha256 <> v_suggestion_sha or v_receipt.mecky_answer_id <> v_answer
       or v_receipt.mecky_receipt_id <> p_mecky_receipt_id or v_receipt.topic_id <> p_topic_id
       or v_receipt.policy_version <> p_policy_version then
      raise exception 'STAGING_PARTICIPANT_SUGGESTION_CLAIM_REUSED' using errcode = 'P0001';
    end if;
    return jsonb_build_object(
      'namespace', v_receipt.namespace, 'wallet_address', v_receipt.wallet_address,
      'discussion_root_id', v_receipt.discussion_root_id, 'source_author_pubkey', v_receipt.source_author_pubkey,
      'request_id', v_receipt.request_id, 'idempotency_key_sha256', encode(v_receipt.idempotency_key_sha256, 'hex'),
      'suggestion_id', v_receipt.suggestion_id, 'suggestion_sha256', encode(v_receipt.suggestion_sha256, 'hex'),
      'mecky_answer_id', v_receipt.mecky_answer_id, 'mecky_receipt_id', v_receipt.mecky_receipt_id,
      'topic_id', v_receipt.topic_id, 'policy_version', v_receipt.policy_version,
      'state', v_receipt.state, 'receipt_checksum', encode(v_receipt.receipt_checksum, 'hex')
    );
  end if;
  if exists (select 1 from staging_participant_private.staging_participant_topic_suggestions where request_id = p_request_id) then
    raise exception 'STAGING_PARTICIPANT_SUGGESTION_REQUEST_REUSED' using errcode = 'P0001';
  end if;
  if not exists (
    select 1 from staging_participant_private.staging_participant_source_post_promotions p
     where p.namespace = p_namespace and p.discussion_root_id = v_root and p.wallet_address = v_wallet
       and p.topic_id = p_topic_id and p.policy_version = p_policy_version and p.state = 'published'
  ) then
    raise exception 'STAGING_PARTICIPANT_SUGGESTION_SOURCE_INVALID' using errcode = 'P0001';
  end if;
  insert into staging_participant_private.staging_participant_topic_suggestions (
    namespace, wallet_address, discussion_root_id, source_author_pubkey, request_id,
    idempotency_key_sha256, suggestion_id, suggestion_sha256, mecky_answer_id,
    mecky_receipt_id, topic_id, policy_version, receipt_checksum
  ) values (
    p_namespace, v_wallet, v_root, v_author, p_request_id, v_idempotency, v_suggestion, v_suggestion_sha,
    v_answer, p_mecky_receipt_id, p_topic_id, p_policy_version,
    staging_participant_private.staging_participant_topic_receipt_checksum(array[
      p_namespace, v_wallet, v_root, v_author, p_request_id::text, encode(v_idempotency, 'hex'),
      v_suggestion, encode(v_suggestion_sha, 'hex'), v_answer, p_mecky_receipt_id, p_topic_id, p_policy_version
    ])
  ) returning * into v_receipt;
  return jsonb_build_object(
    'namespace', v_receipt.namespace, 'wallet_address', v_receipt.wallet_address,
    'discussion_root_id', v_receipt.discussion_root_id, 'source_author_pubkey', v_receipt.source_author_pubkey,
    'request_id', v_receipt.request_id, 'idempotency_key_sha256', encode(v_receipt.idempotency_key_sha256, 'hex'),
    'suggestion_id', v_receipt.suggestion_id, 'suggestion_sha256', encode(v_receipt.suggestion_sha256, 'hex'),
    'mecky_answer_id', v_receipt.mecky_answer_id, 'mecky_receipt_id', v_receipt.mecky_receipt_id,
    'topic_id', v_receipt.topic_id, 'policy_version', v_receipt.policy_version,
    'state', v_receipt.state, 'receipt_checksum', encode(v_receipt.receipt_checksum, 'hex')
  );
end;
$$;

create or replace function public.staging_participant_gateway_complete_topic_suggestion(
  p_wallet_address text, p_namespace text, p_discussion_root_id text, p_source_author_pubkey text,
  p_request_id uuid, p_idempotency_key_sha256 text, p_suggestion_id text, p_suggestion_sha256 text
) returns jsonb
language plpgsql security definer
set search_path = pg_catalog, public, staging_participant_private
as $$
declare
  v_wallet text := lower(p_wallet_address);
  v_receipt staging_participant_private.staging_participant_topic_suggestions%rowtype;
begin
  perform staging_participant_private.require_staging_participant_gateway();
  if p_wallet_address is null or v_wallet !~ '^0x[0-9a-f]{40}$' or p_namespace is null
     or p_discussion_root_id is null or lower(p_discussion_root_id) !~ '^[0-9a-f]{64}$'
     or p_source_author_pubkey is null or lower(p_source_author_pubkey) !~ '^[0-9a-f]{64}$'
     or p_request_id is null or p_idempotency_key_sha256 is null
     or lower(p_idempotency_key_sha256) !~ '^[0-9a-f]{64}$' or p_suggestion_id is null
     or lower(p_suggestion_id) !~ '^[0-9a-f]{64}$' or p_suggestion_sha256 is null
     or lower(p_suggestion_sha256) !~ '^[0-9a-f]{64}$' then
    raise exception 'STAGING_PARTICIPANT_SUGGESTION_INVALID' using errcode = 'P0001';
  end if;
  perform staging_participant_private.ensure_active_staging_participant(v_wallet);
  perform pg_advisory_xact_lock(hashtextextended(p_namespace || ':' || lower(p_discussion_root_id) || ':' || lower(p_source_author_pubkey), 20260825));
  select * into v_receipt from staging_participant_private.staging_participant_topic_suggestions
   where namespace = p_namespace and discussion_root_id = lower(p_discussion_root_id)
     and source_author_pubkey = lower(p_source_author_pubkey) for update;
  if not found then raise exception 'STAGING_PARTICIPANT_SUGGESTION_RECEIPT_MISSING' using errcode = 'P0001'; end if;
  if v_receipt.wallet_address <> v_wallet or v_receipt.request_id <> p_request_id
     or encode(v_receipt.idempotency_key_sha256, 'hex') <> lower(p_idempotency_key_sha256)
     or v_receipt.suggestion_id <> lower(p_suggestion_id)
     or encode(v_receipt.suggestion_sha256, 'hex') <> lower(p_suggestion_sha256) then
    raise exception 'STAGING_PARTICIPANT_SUGGESTION_RECEIPT_MISMATCH' using errcode = 'P0001';
  end if;
  if v_receipt.state = 'reserved' then
    update staging_participant_private.staging_participant_topic_suggestions
       set state = 'published', published_at = clock_timestamp()
     where namespace = p_namespace and discussion_root_id = lower(p_discussion_root_id)
       and source_author_pubkey = lower(p_source_author_pubkey) returning * into v_receipt;
  end if;
  return jsonb_build_object(
    'namespace', v_receipt.namespace, 'wallet_address', v_receipt.wallet_address,
    'discussion_root_id', v_receipt.discussion_root_id, 'source_author_pubkey', v_receipt.source_author_pubkey,
    'request_id', v_receipt.request_id, 'idempotency_key_sha256', encode(v_receipt.idempotency_key_sha256, 'hex'),
    'suggestion_id', v_receipt.suggestion_id, 'suggestion_sha256', encode(v_receipt.suggestion_sha256, 'hex'),
    'mecky_answer_id', v_receipt.mecky_answer_id, 'mecky_receipt_id', v_receipt.mecky_receipt_id,
    'topic_id', v_receipt.topic_id, 'policy_version', v_receipt.policy_version,
    'state', v_receipt.state, 'receipt_checksum', encode(v_receipt.receipt_checksum, 'hex')
  );
end;
$$;

revoke all on function public.staging_participant_gateway_reserve_source_post_promotion(text,text,uuid,uuid,text,text,text,text,text) from public, anon, authenticated;
revoke all on function public.staging_participant_gateway_complete_source_post_promotion(text,text,uuid,uuid,text,text,text) from public, anon, authenticated;
revoke all on function public.staging_participant_gateway_reserve_topic_suggestion(text,text,text,text,uuid,text,text,text,text,text,text,text) from public, anon, authenticated;
revoke all on function public.staging_participant_gateway_complete_topic_suggestion(text,text,text,text,uuid,text,text,text) from public, anon, authenticated;
grant execute on function public.staging_participant_gateway_reserve_source_post_promotion(text,text,uuid,uuid,text,text,text,text,text) to anon;
grant execute on function public.staging_participant_gateway_complete_source_post_promotion(text,text,uuid,uuid,text,text,text) to anon;
grant execute on function public.staging_participant_gateway_reserve_topic_suggestion(text,text,text,text,uuid,text,text,text,text,text,text,text) to anon;
grant execute on function public.staging_participant_gateway_complete_topic_suggestion(text,text,text,text,uuid,text,text,text) to anon;

-- v2 source binding: ADR-0021 receipts intentionally lacked the proof-bound
-- Nostr author. This additive table never backfills or rewrites them.
create table staging_participant_private.staging_participant_nostr_post_mirror_bindings (
  wallet_address text not null references staging_participant_private.staging_participant_admissions(wallet_address),
  source_post_id uuid not null,
  event_id text not null,
  nostr_pubkey text not null,
  created_at timestamptz not null default clock_timestamp(),
  primary key (wallet_address, source_post_id),
  unique (event_id),
  check (event_id ~ '^[0-9a-f]{64}$'),
  check (nostr_pubkey ~ '^[0-9a-f]{64}$')
);
alter table staging_participant_private.staging_participant_nostr_post_mirror_bindings enable row level security;

create or replace function public.staging_participant_gateway_bind_published_nostr_post_mirror(
  p_wallet_address text, p_source_post_id uuid, p_event_id text, p_nostr_pubkey text
) returns jsonb language plpgsql security definer
set search_path = pg_catalog, public, staging_participant_private
as $$
declare v_wallet text := lower(p_wallet_address); v_event text := lower(p_event_id); v_pubkey text := lower(p_nostr_pubkey);
  v_existing staging_participant_private.staging_participant_nostr_post_mirror_bindings%rowtype;
begin
  perform staging_participant_private.require_staging_participant_gateway();
  if v_wallet !~ '^0x[0-9a-f]{40}$' or p_source_post_id is null or v_event !~ '^[0-9a-f]{64}$' or v_pubkey !~ '^[0-9a-f]{64}$' then
    raise exception 'STAGING_PARTICIPANT_MIRROR_BINDING_INVALID' using errcode = 'P0001';
  end if;
  perform staging_participant_private.ensure_active_staging_participant(v_wallet);
  perform pg_advisory_xact_lock(hashtextextended(v_wallet || ':' || p_source_post_id::text, 20260825));
  if not exists (select 1 from staging_participant_private.staging_participant_nostr_post_mirror_receipts m
    where m.wallet_address = v_wallet and m.source_post_id = p_source_post_id and m.event_id = v_event and m.state = 'published') then
    raise exception 'STAGING_PARTICIPANT_MIRROR_BINDING_SOURCE_INVALID' using errcode = 'P0001';
  end if;
  select * into v_existing from staging_participant_private.staging_participant_nostr_post_mirror_bindings
    where wallet_address = v_wallet and source_post_id = p_source_post_id;
  if found and (v_existing.event_id <> v_event or v_existing.nostr_pubkey <> v_pubkey) then
    raise exception 'STAGING_PARTICIPANT_MIRROR_BINDING_REUSED' using errcode = 'P0001';
  end if;
  if not found then insert into staging_participant_private.staging_participant_nostr_post_mirror_bindings(wallet_address, source_post_id, event_id, nostr_pubkey)
    values (v_wallet, p_source_post_id, v_event, v_pubkey) returning * into v_existing; end if;
  return jsonb_build_object('wallet_address', v_existing.wallet_address, 'source_post_id', v_existing.source_post_id,
    'event_id', v_existing.event_id, 'nostr_pubkey', v_existing.nostr_pubkey);
end; $$;

create or replace function public.staging_participant_gateway_resolve_published_nostr_post_mirror(
  p_wallet_address text, p_source_post_id uuid
) returns jsonb language plpgsql security definer
set search_path = pg_catalog, public, staging_participant_private
as $$
declare v_wallet text := lower(p_wallet_address); v_binding staging_participant_private.staging_participant_nostr_post_mirror_bindings%rowtype;
begin
  perform staging_participant_private.require_staging_participant_gateway();
  if v_wallet !~ '^0x[0-9a-f]{40}$' or p_source_post_id is null then raise exception 'STAGING_PARTICIPANT_MIRROR_BINDING_INVALID' using errcode = 'P0001'; end if;
  perform staging_participant_private.ensure_active_staging_participant(v_wallet);
  select b.* into v_binding from staging_participant_private.staging_participant_nostr_post_mirror_bindings b
   join staging_participant_private.staging_participant_nostr_post_mirror_receipts m on m.wallet_address=b.wallet_address and m.source_post_id=b.source_post_id and m.event_id=b.event_id
   where b.wallet_address=v_wallet and b.source_post_id=p_source_post_id and m.state='published';
  if not found then return null; end if;
  return jsonb_build_object('wallet_address',v_binding.wallet_address,'source_post_id',v_binding.source_post_id,'event_id',v_binding.event_id,'nostr_pubkey',v_binding.nostr_pubkey);
end; $$;

create or replace function public.staging_participant_gateway_resolve_published_source_post_promotion(
  p_wallet_address text, p_namespace text, p_discussion_root_id text, p_source_author_pubkey text
) returns jsonb language plpgsql security definer
set search_path = pg_catalog, public, staging_participant_private
as $$
declare v_wallet text := lower(p_wallet_address); v_root text := lower(p_discussion_root_id); v_author text := lower(p_source_author_pubkey);
  v_receipt staging_participant_private.staging_participant_source_post_promotions%rowtype;
begin
  perform staging_participant_private.require_staging_participant_gateway();
  if v_wallet !~ '^0x[0-9a-f]{40}$' or p_namespace !~ '^urn:stadtstack:topic:municipality:[a-z0-9][a-z0-9-]{0,63}$' or v_root !~ '^[0-9a-f]{64}$' or v_author !~ '^[0-9a-f]{64}$' then
    raise exception 'STAGING_PARTICIPANT_PROMOTION_INVALID' using errcode = 'P0001'; end if;
  perform staging_participant_private.ensure_active_staging_participant(v_wallet);
  select p.* into v_receipt from staging_participant_private.staging_participant_source_post_promotions p
   join staging_participant_private.staging_participant_nostr_post_mirror_bindings b on b.wallet_address=p.wallet_address and b.source_post_id=p.source_post_id
   where p.wallet_address=v_wallet and p.namespace=p_namespace and p.discussion_root_id=v_root and p.state='published' and b.nostr_pubkey=v_author;
  if not found then return null; end if;
  return jsonb_build_object('namespace',v_receipt.namespace,'wallet_address',v_receipt.wallet_address,'source_post_id',v_receipt.source_post_id,'request_id',v_receipt.request_id,
    'idempotency_key_sha256',encode(v_receipt.idempotency_key_sha256,'hex'),'discussion_root_id',v_receipt.discussion_root_id,'discussion_root_sha256',encode(v_receipt.discussion_root_sha256,'hex'),
    'topic_id',v_receipt.topic_id,'policy_version',v_receipt.policy_version,'state',v_receipt.state,'receipt_checksum',encode(v_receipt.receipt_checksum,'hex'));
end; $$;

revoke all on function public.staging_participant_gateway_bind_published_nostr_post_mirror(text,uuid,text,text) from public, anon, authenticated;
revoke all on function public.staging_participant_gateway_resolve_published_nostr_post_mirror(text,uuid) from public, anon, authenticated;
revoke all on function public.staging_participant_gateway_resolve_published_source_post_promotion(text,text,text,text) from public, anon, authenticated;
grant execute on function public.staging_participant_gateway_bind_published_nostr_post_mirror(text,uuid,text,text) to anon;
grant execute on function public.staging_participant_gateway_resolve_published_nostr_post_mirror(text,uuid) to anon;
grant execute on function public.staging_participant_gateway_resolve_published_source_post_promotion(text,text,text,text) to anon;

-- Immutable v3 readiness marker and private executable catalog. The preflight
-- below compares the complete reviewed executable metadata and privilege
-- boundary on every probe; additive-object drift therefore closes the gateway
-- rather than falling back to the ADR-0021 readiness result.
create table staging_participant_private.staging_participant_topic_tracer_schema_contract (
  singleton boolean primary key default true check (singleton), migration_id text not null,
  database_schema_sha256 text not null check (database_schema_sha256 ~ '^sha256:[0-9a-f]{64}$'),
  canonical_contract_sha256 text not null check (canonical_contract_sha256 ~ '^sha256:[0-9a-f]{64}$')
);
create table staging_participant_private.staging_participant_topic_tracer_catalog_contract (
  object_identity text primary key,
  owner_name text not null,
  language_name text not null,
  return_type text not null,
  volatility "char" not null check (volatility in ('i'::"char", 's'::"char", 'v'::"char")),
  security_definer boolean not null,
  definition_sha256 text not null check (definition_sha256 ~ '^sha256:[0-9a-f]{64}$'),
  source_sha256 text not null check (source_sha256 ~ '^sha256:[0-9a-f]{64}$'),
  configuration text not null check (configuration like 'search_path=pg_catalog,%')
);
alter table staging_participant_private.staging_participant_topic_tracer_schema_contract enable row level security;
alter table staging_participant_private.staging_participant_topic_tracer_catalog_contract enable row level security;
insert into staging_participant_private.staging_participant_topic_tracer_schema_contract(singleton,migration_id,database_schema_sha256,canonical_contract_sha256)
values (true,'20260825_staging_participant_topic_tracer','sha256:298ef4a02f5f299afd157210a1074f179b08478c683bad3ed36430eb013854eb','sha256:298ef4a02f5f299afd157210a1074f179b08478c683bad3ed36430eb013854eb');
insert into staging_participant_private.staging_participant_topic_tracer_catalog_contract(
  object_identity, owner_name, language_name, return_type, volatility,
  security_definer, definition_sha256, source_sha256, configuration
)
select reviewed.object_identity, owner_role.rolname, language.lanname,
  pg_catalog.pg_get_function_result(proc.oid), proc.provolatile, proc.prosecdef,
  'sha256:' || encode(extensions.digest(pg_catalog.pg_get_functiondef(proc.oid), 'sha256'),'hex'),
  'sha256:' || encode(extensions.digest(proc.prosrc, 'sha256'),'hex'),
  coalesce(array_to_string(proc.proconfig, E'\n'), '')
from (values
  ('public.staging_participant_gateway_reserve_source_post_promotion(text,text,uuid,uuid,text,text,text,text,text)'),
  ('public.staging_participant_gateway_complete_source_post_promotion(text,text,uuid,uuid,text,text,text)'),
  ('public.staging_participant_gateway_reserve_topic_suggestion(text,text,text,text,uuid,text,text,text,text,text,text,text)'),
  ('public.staging_participant_gateway_complete_topic_suggestion(text,text,text,text,uuid,text,text,text)'),
  ('public.staging_participant_gateway_bind_published_nostr_post_mirror(text,uuid,text,text)'),
  ('public.staging_participant_gateway_resolve_published_nostr_post_mirror(text,uuid)'),
  ('public.staging_participant_gateway_resolve_published_source_post_promotion(text,text,text,text)'),
  ('staging_participant_private.staging_participant_topic_receipt_checksum(text[])')
) as reviewed(object_identity)
join pg_catalog.pg_proc proc on proc.oid = to_regprocedure(reviewed.object_identity)
join pg_catalog.pg_roles owner_role on owner_role.oid = proc.proowner
join pg_catalog.pg_language language on language.oid = proc.prolang;

create or replace function public.staging_participant_gateway_topic_tracer_preflight()
returns jsonb language plpgsql stable security definer
set search_path = pg_catalog, public, staging_participant_private, extensions
as $$
declare v_marker staging_participant_private.staging_participant_topic_tracer_schema_contract%rowtype;
  v_function text;
  v_table text;
begin
  perform staging_participant_private.require_staging_participant_gateway();
  select * into v_marker from staging_participant_private.staging_participant_topic_tracer_schema_contract where singleton=true;
  if not found or v_marker.migration_id <> '20260825_staging_participant_topic_tracer'
    or v_marker.database_schema_sha256 <> 'sha256:298ef4a02f5f299afd157210a1074f179b08478c683bad3ed36430eb013854eb'
    or v_marker.canonical_contract_sha256 <> 'sha256:298ef4a02f5f299afd157210a1074f179b08478c683bad3ed36430eb013854eb' then
    raise exception 'STAGING_PARTICIPANT_TOPIC_TRACER_SCHEMA_DRIFT' using errcode='P0001'; end if;

  foreach v_function in array array[
    'public.staging_participant_gateway_reserve_source_post_promotion(text,text,uuid,uuid,text,text,text,text,text)',
    'public.staging_participant_gateway_complete_source_post_promotion(text,text,uuid,uuid,text,text,text)',
    'public.staging_participant_gateway_reserve_topic_suggestion(text,text,text,text,uuid,text,text,text,text,text,text,text)',
    'public.staging_participant_gateway_complete_topic_suggestion(text,text,text,text,uuid,text,text,text)',
    'public.staging_participant_gateway_bind_published_nostr_post_mirror(text,uuid,text,text)',
    'public.staging_participant_gateway_resolve_published_nostr_post_mirror(text,uuid)',
    'public.staging_participant_gateway_resolve_published_source_post_promotion(text,text,text,text)',
    'public.staging_participant_gateway_topic_tracer_preflight()'
  ] loop
    if to_regprocedure(v_function) is null
      or not exists (
        select 1 from staging_participant_private.staging_participant_topic_tracer_catalog_contract
         where object_identity = v_function
      )
      or not has_function_privilege('anon', to_regprocedure(v_function), 'EXECUTE')
      or has_function_privilege('authenticated', to_regprocedure(v_function), 'EXECUTE')
      or not exists (
        select 1 from pg_catalog.pg_proc proc
        cross join lateral pg_catalog.aclexplode(
          coalesce(proc.proacl, pg_catalog.acldefault('f', proc.proowner))
        ) acl
         where proc.oid = to_regprocedure(v_function)
           and acl.grantee = (select oid from pg_catalog.pg_roles where rolname = 'anon')
           and acl.privilege_type = 'EXECUTE' and not acl.is_grantable
      )
      or exists (
        select 1 from pg_catalog.pg_proc proc
        cross join lateral pg_catalog.aclexplode(
          coalesce(proc.proacl, pg_catalog.acldefault('f', proc.proowner))
        ) acl
         where proc.oid = to_regprocedure(v_function)
           and acl.privilege_type = 'EXECUTE'
           and (
             (acl.grantee <> proc.proowner
               and acl.grantee <> (select oid from pg_catalog.pg_roles where rolname = 'anon'))
             or (acl.grantee = (select oid from pg_catalog.pg_roles where rolname = 'anon')
               and acl.is_grantable)
           )
      ) then
      raise exception 'STAGING_PARTICIPANT_TOPIC_TRACER_RPC_ACL_DRIFT:%', v_function using errcode='P0001';
    end if;
  end loop;

  v_function := 'staging_participant_private.staging_participant_topic_receipt_checksum(text[])';
  if to_regprocedure(v_function) is null
    or not exists (
      select 1 from staging_participant_private.staging_participant_topic_tracer_catalog_contract
       where object_identity = v_function
    )
    or has_function_privilege('anon', to_regprocedure(v_function), 'EXECUTE')
    or has_function_privilege('authenticated', to_regprocedure(v_function), 'EXECUTE')
    or exists (
      select 1 from pg_catalog.pg_proc proc
      cross join lateral pg_catalog.aclexplode(
        coalesce(proc.proacl, pg_catalog.acldefault('f', proc.proowner))
      ) acl
       where proc.oid = to_regprocedure(v_function)
         and acl.privilege_type = 'EXECUTE' and acl.grantee <> proc.proowner
    ) then
    raise exception 'STAGING_PARTICIPANT_TOPIC_TRACER_HELPER_ACL_DRIFT' using errcode='P0001';
  end if;

  foreach v_table in array array[
    'staging_participant_private.staging_participant_source_post_promotions',
    'staging_participant_private.staging_participant_topic_suggestions',
    'staging_participant_private.staging_participant_nostr_post_mirror_bindings',
    'staging_participant_private.staging_participant_topic_tracer_schema_contract',
    'staging_participant_private.staging_participant_topic_tracer_catalog_contract'
  ] loop
    if to_regclass(v_table) is null
      or not exists (
        select 1 from pg_catalog.pg_class relation
         where relation.oid = to_regclass(v_table) and relation.relkind = 'r'
           and relation.relrowsecurity
      )
      or exists (
        select 1 from pg_catalog.pg_class relation
        cross join lateral pg_catalog.aclexplode(
          coalesce(relation.relacl, pg_catalog.acldefault('r', relation.relowner))
        ) acl
         where relation.oid = to_regclass(v_table) and acl.grantee <> relation.relowner
      )
      or exists (
        select 1
          from (values ('anon'), ('authenticated')) as actor(role_name)
          cross join (values ('SELECT'), ('INSERT'), ('UPDATE'), ('DELETE'),
            ('TRUNCATE'), ('REFERENCES'), ('TRIGGER')) as permission(privilege_name)
         where has_table_privilege(
           actor.role_name, to_regclass(v_table), permission.privilege_name
         )
      ) then
      raise exception 'STAGING_PARTICIPANT_TOPIC_TRACER_PRIVATE_TABLE_DRIFT:%', v_table using errcode='P0001';
    end if;
  end loop;

  if (select count(*) from staging_participant_private.staging_participant_topic_tracer_catalog_contract) <> 9
    or exists (
      select 1
        from staging_participant_private.staging_participant_topic_tracer_catalog_contract contract
        left join pg_catalog.pg_proc proc on proc.oid = to_regprocedure(contract.object_identity)
        left join pg_catalog.pg_roles owner_role on owner_role.oid = proc.proowner
        left join pg_catalog.pg_language language on language.oid = proc.prolang
       where proc.oid is null
         or owner_role.rolname <> contract.owner_name
         or language.lanname <> contract.language_name
         or pg_catalog.pg_get_function_result(proc.oid) <> contract.return_type
         or proc.provolatile <> contract.volatility
         or proc.prosecdef <> contract.security_definer
         or 'sha256:' || encode(extensions.digest(pg_catalog.pg_get_functiondef(proc.oid), 'sha256'),'hex') <> contract.definition_sha256
         or 'sha256:' || encode(extensions.digest(proc.prosrc, 'sha256'),'hex') <> contract.source_sha256
         or coalesce(array_to_string(proc.proconfig, E'\n'), '') <> contract.configuration
    ) then
    raise exception 'STAGING_PARTICIPANT_TOPIC_TRACER_CATALOG_DRIFT' using errcode='P0001';
  end if;
  return jsonb_build_object('migration_id',v_marker.migration_id,'database_schema_sha256',v_marker.database_schema_sha256);
end; $$;
insert into staging_participant_private.staging_participant_topic_tracer_catalog_contract(
  object_identity, owner_name, language_name, return_type, volatility,
  security_definer, definition_sha256, source_sha256, configuration
)
select reviewed.object_identity, owner_role.rolname, language.lanname,
  pg_catalog.pg_get_function_result(proc.oid), proc.provolatile, proc.prosecdef,
  'sha256:' || encode(extensions.digest(pg_catalog.pg_get_functiondef(proc.oid), 'sha256'),'hex'),
  'sha256:' || encode(extensions.digest(proc.prosrc, 'sha256'),'hex'),
  coalesce(array_to_string(proc.proconfig, E'\n'), '')
from (values ('public.staging_participant_gateway_topic_tracer_preflight()')) as reviewed(object_identity)
join pg_catalog.pg_proc proc on proc.oid = to_regprocedure(reviewed.object_identity)
join pg_catalog.pg_roles owner_role on owner_role.oid = proc.proowner
join pg_catalog.pg_language language on language.oid = proc.prolang;
revoke all on function public.staging_participant_gateway_topic_tracer_preflight() from public, anon, authenticated;
grant execute on function public.staging_participant_gateway_topic_tracer_preflight() to anon;

commit;
