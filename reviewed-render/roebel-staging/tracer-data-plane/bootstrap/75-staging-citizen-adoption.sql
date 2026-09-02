-- ADR-0023 staging tracer: durable citizen eligibility and adoption hand-off.
--
-- Every callable function below reuses the deployed gateway's Vault-bound
-- `require_staging_participant_gateway()` capability. That helper compares
-- request.headers->>'x-staging-participant-rpc-secret' without exposing it.
-- This migration records eligibility and an advisory Case-Steward hand-off;
-- it has no CivicCase, administration, vote, council, treasury, or payment
-- write capability.

begin;

do $$
begin
  if not exists (
    select 1 from public.app_settings
     where key = 'roebel_env' and value = 'staging'
  ) or not exists (
    select 1 from vault.decrypted_secrets
     where name = 'roebel_staging_participant_environment_arm'
       and decrypted_secret = 'staging-only'
  ) or not exists (
    select 1 from vault.decrypted_secrets
     where name = 'roebel_staging_participant_rpc_secret'
       and length(decrypted_secret) >= 32
  ) then
    raise exception 'STAGING_PARTICIPANT_CITIZEN_ADOPTION_REQUIRES_ARMED_STAGING'
      using errcode = 'P0001';
  end if;
end;
$$;

create table staging_participant_private.staging_participant_citizen_eligibility_challenges (
  challenge_id text not null,
  municipality_id text not null,
  wallet_address text not null,
  session_binding_sha256 bytea not null,
  subject_pubkey text not null,
  participant_suggestion_id text not null,
  topic_id text not null,
  policy_version text not null,
  issued_at bigint not null,
  expires_at bigint not null,
  consumed_at bigint,
  challenge jsonb not null,
  created_at timestamptz not null default clock_timestamp(),
  primary key (challenge_id),
  check (challenge_id ~ '^[0-9a-f]{32}$'),
  check (municipality_id ~ '^[a-z0-9][a-z0-9-]{0,63}$'),
  check (wallet_address ~ '^0x[0-9a-f]{40}$'),
  check (octet_length(session_binding_sha256) = 32),
  check (subject_pubkey ~ '^[0-9a-f]{64}$'),
  check (participant_suggestion_id ~ '^[0-9a-f]{64}$'),
  check (topic_id like 'urn:stadtstack:topic:municipality:' || municipality_id || ':%'),
  check (policy_version ~ '^[a-z0-9][a-z0-9._-]{2,99}$'),
  check (issued_at >= 0 and expires_at > issued_at),
  check (consumed_at is null or (consumed_at >= issued_at and consumed_at < expires_at))
);

alter table staging_participant_private.staging_participant_citizen_eligibility_challenges
  enable row level security;
revoke all on table staging_participant_private.staging_participant_citizen_eligibility_challenges from public, anon, authenticated;

create or replace function public.staging_participant_gateway_issue_citizen_challenge(
  p_challenge jsonb
) returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, staging_participant_private
as $$
declare
  v_challenge staging_participant_private.staging_participant_citizen_eligibility_challenges%rowtype;
  v_challenge_id text := p_challenge->>'challengeId';
  v_municipality_id text := p_challenge->>'municipalityId';
  v_wallet text := lower(p_challenge->>'walletAddress');
  v_session_binding text := lower(p_challenge->>'sessionBindingSha256');
  v_subject_pubkey text := lower(p_challenge->>'subjectPubkey');
  v_suggestion_id text := lower(p_challenge->>'participantSuggestionId');
  v_topic_id text := p_challenge->>'topicId';
  v_policy_version text := p_challenge->>'policyVersion';
  v_issued_at bigint;
  v_expires_at bigint;
begin
  perform staging_participant_private.require_staging_participant_gateway();
  if p_challenge is null
     or jsonb_typeof(p_challenge) is distinct from 'object'
     or not (p_challenge ?& array[
       'schemaVersion', 'challengeId', 'audience', 'sessionBindingSha256',
       'walletAddress', 'chainId', 'subjectPubkey', 'municipalityId',
       'policyVersion', 'participantSuggestionId', 'topicId', 'issuedAt',
       'expiresAt', 'authorityBinding', 'canonicalChallenge', 'message'
     ])
     or (
       select count(*)
         from pg_catalog.jsonb_object_keys(
           case when pg_catalog.jsonb_typeof(p_challenge) = 'object'
             then p_challenge else '{}'::jsonb end
         )
     ) <> 16
     or exists (
       select 1
         from pg_catalog.jsonb_each(
           case when pg_catalog.jsonb_typeof(p_challenge) = 'object'
             then p_challenge else '{}'::jsonb end
         ) as field(key, value)
        where field.value = 'null'::jsonb
     )
     or p_challenge->'schemaVersion' is distinct from
       '"municipal_civic_eligibility_challenge_v1"'::jsonb
     or v_challenge_id is null or v_challenge_id !~ '^[0-9a-f]{32}$'
     or p_challenge->'audience' is distinct from
       '"roebel-staging-citizen-adoption"'::jsonb
     or v_session_binding is null or v_session_binding !~ '^[0-9a-f]{64}$'
     or v_wallet is null or v_wallet !~ '^0x[0-9a-f]{40}$'
     or p_challenge->'chainId' is distinct from '100'::jsonb
     or v_subject_pubkey is null or v_subject_pubkey !~ '^[0-9a-f]{64}$'
     or v_municipality_id is null
     or v_municipality_id !~ '^[a-z0-9][a-z0-9-]{0,63}$'
     or v_policy_version is null
     or v_policy_version !~ '^[a-z0-9][a-z0-9._-]{2,99}$'
     or v_suggestion_id is null or v_suggestion_id !~ '^[0-9a-f]{64}$'
     or v_topic_id is null
     or v_topic_id not like
       'urn:stadtstack:topic:municipality:' || v_municipality_id || ':%'
     or p_challenge->'authorityBinding' is distinct from
       '"civic_eligibility_only"'::jsonb
     or coalesce(p_challenge->>'canonicalChallenge', '') = ''
     or p_challenge->'message' is distinct from
       p_challenge->'canonicalChallenge' then
    raise exception 'STAGING_PARTICIPANT_CITIZEN_CHALLENGE_INVALID'
      using errcode = 'P0001';
  end if;
  begin
    v_issued_at := (p_challenge->>'issuedAt')::bigint;
    v_expires_at := (p_challenge->>'expiresAt')::bigint;
  exception when others then
    raise exception 'STAGING_PARTICIPANT_CITIZEN_CHALLENGE_INVALID'
      using errcode = 'P0001';
  end;
  if v_issued_at is null or v_expires_at is null
     or v_issued_at < 0 or v_expires_at <= v_issued_at then
    raise exception 'STAGING_PARTICIPANT_CITIZEN_CHALLENGE_INVALID'
      using errcode = 'P0001';
  end if;
  perform staging_participant_private.ensure_active_staging_participant(v_wallet);
  if not exists (
    select 1
      from staging_participant_private.staging_participant_topic_suggestions suggestion
     where suggestion.namespace =
       'urn:stadtstack:topic:municipality:' || v_municipality_id
       and suggestion.suggestion_id = v_suggestion_id
       and suggestion.topic_id = v_topic_id
       and suggestion.state = 'published'
  ) then
    raise exception 'STAGING_PARTICIPANT_CITIZEN_CHALLENGE_MISMATCH'
      using errcode = 'P0001';
  end if;
  perform pg_advisory_xact_lock(
    hashtextextended('citizen-challenge:' || v_challenge_id, 20260901)
  );
  select * into v_challenge
    from staging_participant_private.staging_participant_citizen_eligibility_challenges
   where challenge_id = v_challenge_id
   for update;
  if found then
    if v_challenge.challenge is distinct from p_challenge then
      raise exception 'STAGING_PARTICIPANT_CITIZEN_CHALLENGE_MISMATCH'
        using errcode = 'P0001';
    end if;
    return v_challenge.challenge;
  end if;
  insert into staging_participant_private.staging_participant_citizen_eligibility_challenges (
    challenge_id, municipality_id, wallet_address, session_binding_sha256,
    subject_pubkey, participant_suggestion_id, topic_id, policy_version,
    issued_at, expires_at, challenge
  ) values (
    v_challenge_id, v_municipality_id, v_wallet, decode(v_session_binding, 'hex'),
    v_subject_pubkey, v_suggestion_id, v_topic_id, v_policy_version,
    v_issued_at, v_expires_at, p_challenge
  ) returning * into v_challenge;
  return v_challenge.challenge;
end;
$$;

create or replace function public.staging_participant_gateway_consume_citizen_challenge(
  p_challenge_id text,
  p_wallet_address text,
  p_session_binding_sha256 text,
  p_consumed_at bigint
) returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, staging_participant_private
as $$
declare
  v_challenge staging_participant_private.staging_participant_citizen_eligibility_challenges%rowtype;
  v_wallet text := lower(p_wallet_address);
  v_session_binding text := lower(p_session_binding_sha256);
begin
  perform staging_participant_private.require_staging_participant_gateway();
  if p_challenge_id is null or p_challenge_id !~ '^[0-9a-f]{32}$'
     or v_wallet is null or v_wallet !~ '^0x[0-9a-f]{40}$'
     or v_session_binding is null or v_session_binding !~ '^[0-9a-f]{64}$'
     or p_consumed_at is null or p_consumed_at < 0 then
    raise exception 'STAGING_PARTICIPANT_CITIZEN_CHALLENGE_MISMATCH'
      using errcode = 'P0001';
  end if;
  perform pg_advisory_xact_lock(
    hashtextextended('citizen-challenge:' || p_challenge_id, 20260901)
  );
  select * into v_challenge
    from staging_participant_private.staging_participant_citizen_eligibility_challenges
   where challenge_id = p_challenge_id
   for update;
  if not found then
    raise exception 'STAGING_PARTICIPANT_CITIZEN_CHALLENGE_MISSING'
      using errcode = 'P0001';
  end if;
  if v_challenge.consumed_at is not null then
    raise exception 'STAGING_PARTICIPANT_CITIZEN_CHALLENGE_USED'
      using errcode = 'P0001';
  end if;
  if p_consumed_at < v_challenge.issued_at
     or p_consumed_at >= v_challenge.expires_at then
    raise exception 'STAGING_PARTICIPANT_CITIZEN_CHALLENGE_EXPIRED'
      using errcode = 'P0001';
  end if;
  if v_challenge.wallet_address is distinct from v_wallet
     or v_challenge.session_binding_sha256 is distinct from
       decode(v_session_binding, 'hex') then
    raise exception 'STAGING_PARTICIPANT_CITIZEN_CHALLENGE_MISMATCH'
      using errcode = 'P0001';
  end if;
  update staging_participant_private.staging_participant_citizen_eligibility_challenges
     set consumed_at = p_consumed_at
   where challenge_id = p_challenge_id;
  return v_challenge.challenge;
end;
$$;

revoke all on function public.staging_participant_gateway_issue_citizen_challenge(jsonb)
  from public, anon, authenticated;
grant execute on function public.staging_participant_gateway_issue_citizen_challenge(jsonb)
  to anon;
revoke all on function public.staging_participant_gateway_consume_citizen_challenge(text,text,text,bigint)
  from public, anon, authenticated;
grant execute on function public.staging_participant_gateway_consume_citizen_challenge(text,text,text,bigint)
  to anon;

create table staging_participant_private.staging_participant_citizen_eligibility_receipts (
  receipt_id text primary key,
  challenge_id text not null unique references
    staging_participant_private.staging_participant_citizen_eligibility_challenges(challenge_id),
  municipality_id text not null,
  subject_pubkey text not null,
  participant_suggestion_id text not null,
  topic_id text not null,
  policy_version text not null,
  public_receipt jsonb not null,
  private_eligibility_evidence jsonb not null,
  created_at timestamptz not null default clock_timestamp(),
  check (receipt_id ~ '^urn:stadtstack:municipal-civic-eligibility-receipt:[0-9a-f]{64}$'),
  check (municipality_id ~ '^[a-z0-9][a-z0-9-]{0,63}$'),
  check (subject_pubkey ~ '^[0-9a-f]{64}$'),
  check (participant_suggestion_id ~ '^[0-9a-f]{64}$'),
  check (topic_id like 'urn:stadtstack:topic:municipality:' || municipality_id || ':%'),
  check (policy_version ~ '^[a-z0-9][a-z0-9._-]{2,99}$')
);

alter table staging_participant_private.staging_participant_citizen_eligibility_receipts
  enable row level security;
revoke all on table staging_participant_private.staging_participant_citizen_eligibility_receipts from public, anon, authenticated;

create or replace function public.staging_participant_gateway_store_citizen_eligibility_receipt(
  p_challenge_id text,
  p_receipt jsonb,
  p_private_eligibility_evidence jsonb
) returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, staging_participant_private
as $$
declare
  v_challenge staging_participant_private.staging_participant_citizen_eligibility_challenges%rowtype;
  v_receipt staging_participant_private.staging_participant_citizen_eligibility_receipts%rowtype;
  v_core jsonb := p_receipt->'eligibilityCore';
  v_proof jsonb := p_receipt->'proof';
  v_receipt_id text := p_receipt->>'receiptId';
  v_payload_checksum text := lower(p_receipt->>'payloadChecksum');
begin
  perform staging_participant_private.require_staging_participant_gateway();
  if p_challenge_id is null or p_challenge_id !~ '^[0-9a-f]{32}$'
     or p_receipt is null
     or jsonb_typeof(p_receipt) is distinct from 'object'
     or not (p_receipt ?& array[
       'schemaVersion', 'eligibilityCore', 'receiptId', 'payloadChecksum',
       'statusRef', 'proof'
     ])
     or (
       select count(*)
         from pg_catalog.jsonb_object_keys(
           case when pg_catalog.jsonb_typeof(p_receipt) = 'object'
             then p_receipt else '{}'::jsonb end
         )
     ) <> 6
     or exists (
       select 1
         from pg_catalog.jsonb_each(
           case when pg_catalog.jsonb_typeof(p_receipt) = 'object'
             then p_receipt else '{}'::jsonb end
         ) as field(key, value)
        where field.value = 'null'::jsonb
     )
     or p_receipt->'schemaVersion' is distinct from
       '"municipal_civic_eligibility_receipt_v1"'::jsonb
     or jsonb_typeof(v_core) is distinct from 'object'
     or not (v_core ?& array[
       'municipalityId', 'eligibilityClass', 'subjectPubkey',
       'participantSuggestionId', 'topicId', 'policyVersion', 'issuer',
       'issuedAt', 'expiresAt', 'authorityBinding'
     ])
     or (
       select count(*)
         from pg_catalog.jsonb_object_keys(
           case when pg_catalog.jsonb_typeof(v_core) = 'object'
             then v_core else '{}'::jsonb end
         )
     ) <> 10
     or exists (
       select 1
         from pg_catalog.jsonb_each(
           case when pg_catalog.jsonb_typeof(v_core) = 'object'
             then v_core else '{}'::jsonb end
         ) as field(key, value)
        where field.value = 'null'::jsonb
     )
     or v_core->'eligibilityClass' is distinct from
       '"municipal_civic_participation"'::jsonb
     or v_core->'authorityBinding' is distinct from
       '"civic_eligibility_only"'::jsonb
     or v_payload_checksum is null
     or v_payload_checksum !~ '^[0-9a-f]{64}$'
     or v_receipt_id is null
     or v_receipt_id is distinct from
       'urn:stadtstack:municipal-civic-eligibility-receipt:' || v_payload_checksum
     or p_receipt->>'statusRef' is null
     or p_receipt->>'statusRef' !~ '^https://[^?#]+/[0-9a-f]{64}$'
     or right(p_receipt->>'statusRef', 64) is distinct from v_payload_checksum
     or jsonb_typeof(v_proof) is distinct from 'object'
     or not (v_proof ?& array['algorithm', 'keyId', 'signature'])
     or (
       select count(*)
         from pg_catalog.jsonb_object_keys(
           case when pg_catalog.jsonb_typeof(v_proof) = 'object'
             then v_proof else '{}'::jsonb end
         )
     ) <> 3
     or exists (
       select 1
         from pg_catalog.jsonb_each(
           case when pg_catalog.jsonb_typeof(v_proof) = 'object'
             then v_proof else '{}'::jsonb end
         ) as field(key, value)
        where field.value = 'null'::jsonb
     )
     or v_proof->'algorithm' is distinct from '"Ed25519"'::jsonb
     or v_proof->>'keyId' is null
     or v_proof->>'keyId' !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$'
     or v_proof->>'signature' is null
     or v_proof->>'signature' !~ '^[A-Za-z0-9_-]+$'
     or p_private_eligibility_evidence is null
     or jsonb_typeof(p_private_eligibility_evidence) is distinct from 'object'
     or not (p_private_eligibility_evidence ?& array[
       'active', 'chainId', 'contractAddress', 'finalizedBlockNumber',
       'finalizedBlockHash'
     ])
     or (
       select count(*)
         from pg_catalog.jsonb_object_keys(
           case when pg_catalog.jsonb_typeof(
             p_private_eligibility_evidence
           ) = 'object' then p_private_eligibility_evidence
           else '{}'::jsonb end
         )
     ) <> 5
     or exists (
       select 1
         from pg_catalog.jsonb_each(
           case when pg_catalog.jsonb_typeof(
             p_private_eligibility_evidence
           ) = 'object' then p_private_eligibility_evidence
           else '{}'::jsonb end
         ) as field(key, value)
        where field.value = 'null'::jsonb
     )
     or p_private_eligibility_evidence->'active' is distinct from 'true'::jsonb
     or p_private_eligibility_evidence->'chainId' is distinct from '100'::jsonb
     or p_private_eligibility_evidence->>'contractAddress' is null
     or lower(p_private_eligibility_evidence->>'contractAddress') is distinct from
       '0x59aa26f499d7c2b3ec2c8524ed06f54fc4e85de5'
     or p_private_eligibility_evidence->>'finalizedBlockNumber' is null
     or p_private_eligibility_evidence->>'finalizedBlockNumber' !~ '^[0-9]+$'
     or p_private_eligibility_evidence->>'finalizedBlockHash' is null
     or lower(p_private_eligibility_evidence->>'finalizedBlockHash') !~ '^0x[0-9a-f]{64}$' then
    raise exception 'STAGING_PARTICIPANT_CITIZEN_ELIGIBILITY_RECEIPT_INVALID'
      using errcode = 'P0001';
  end if;
  perform pg_advisory_xact_lock(
    hashtextextended('citizen-challenge:' || p_challenge_id, 20260901)
  );
  select * into v_challenge
    from staging_participant_private.staging_participant_citizen_eligibility_challenges challenge
   where challenge.challenge_id = p_challenge_id
   for update;
  if not found or v_challenge.consumed_at is null then
    raise exception 'STAGING_PARTICIPANT_CITIZEN_ELIGIBILITY_RECEIPT_INVALID'
      using errcode = 'P0001';
  end if;
  if v_core->>'municipalityId' is distinct from v_challenge.municipality_id
     or lower(v_core->>'subjectPubkey') is distinct from v_challenge.subject_pubkey
     or lower(v_core->>'participantSuggestionId') is distinct from
       v_challenge.participant_suggestion_id
     or v_core->>'topicId' is distinct from v_challenge.topic_id
     or v_core->>'policyVersion' is distinct from v_challenge.policy_version
     or v_core->>'issuer' is null or btrim(v_core->>'issuer') = ''
     or v_core->>'issuedAt' is null
     or v_core->>'expiresAt' is null
     or (v_core->>'issuedAt')::bigint < v_challenge.issued_at
     or (v_core->>'issuedAt')::bigint > v_challenge.consumed_at
     or (v_core->>'expiresAt')::bigint <= (v_core->>'issuedAt')::bigint then
    raise exception 'STAGING_PARTICIPANT_CITIZEN_ELIGIBILITY_RECEIPT_INVALID'
      using errcode = 'P0001';
  end if;
  perform pg_advisory_xact_lock(
    hashtextextended('citizen-receipt:' || v_receipt_id, 20260901)
  );
  select * into v_receipt
    from staging_participant_private.staging_participant_citizen_eligibility_receipts
   where challenge_id = p_challenge_id or receipt_id = v_receipt_id
   for update;
  if found then
    if v_receipt.challenge_id is distinct from p_challenge_id
       or v_receipt.receipt_id is distinct from v_receipt_id
       or v_receipt.public_receipt is distinct from p_receipt
       or v_receipt.private_eligibility_evidence is distinct from
         p_private_eligibility_evidence then
      raise exception 'STAGING_PARTICIPANT_CITIZEN_ELIGIBILITY_RECEIPT_CONFLICT'
        using errcode = 'P0001';
    end if;
    return v_receipt.public_receipt;
  end if;
  insert into staging_participant_private.staging_participant_citizen_eligibility_receipts (
    receipt_id, challenge_id, municipality_id, subject_pubkey,
    participant_suggestion_id, topic_id, policy_version, public_receipt,
    private_eligibility_evidence
  ) values (
    v_receipt_id, p_challenge_id, v_challenge.municipality_id,
    v_challenge.subject_pubkey, v_challenge.participant_suggestion_id,
    v_challenge.topic_id, v_challenge.policy_version, p_receipt,
    p_private_eligibility_evidence
  ) returning * into v_receipt;
  return v_receipt.public_receipt;
exception when invalid_text_representation or numeric_value_out_of_range then
  raise exception 'STAGING_PARTICIPANT_CITIZEN_ELIGIBILITY_RECEIPT_INVALID'
    using errcode = 'P0001';
end;
$$;

create or replace function public.staging_participant_gateway_get_citizen_eligibility_receipt(
  p_receipt_id text
) returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, staging_participant_private
as $$
declare
  v_receipt staging_participant_private.staging_participant_citizen_eligibility_receipts%rowtype;
begin
  perform staging_participant_private.require_staging_participant_gateway();
  if p_receipt_id is null
     or p_receipt_id !~ '^urn:stadtstack:municipal-civic-eligibility-receipt:[0-9a-f]{64}$' then
    raise exception 'STAGING_PARTICIPANT_CITIZEN_ELIGIBILITY_RECEIPT_INVALID'
      using errcode = 'P0001';
  end if;
  select * into v_receipt
    from staging_participant_private.staging_participant_citizen_eligibility_receipts
   where receipt_id = p_receipt_id;
  if not found then return null; end if;
  return v_receipt.public_receipt;
end;
$$;

revoke all on function public.staging_participant_gateway_store_citizen_eligibility_receipt(text,jsonb,jsonb)
  from public, anon, authenticated;
grant execute on function public.staging_participant_gateway_store_citizen_eligibility_receipt(text,jsonb,jsonb)
  to anon;
revoke all on function public.staging_participant_gateway_get_citizen_eligibility_receipt(text)
  from public, anon, authenticated;
grant execute on function public.staging_participant_gateway_get_citizen_eligibility_receipt(text)
  to anon;

create or replace function public.staging_participant_gateway_get_citizen_suggestion_root(
  p_municipality_id text,
  p_suggestion_id text
) returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, staging_participant_private
as $$
declare
  v_suggestion staging_participant_private.staging_participant_topic_suggestions%rowtype;
begin
  perform staging_participant_private.require_staging_participant_gateway();
  if p_municipality_id is null
     or p_municipality_id !~ '^[a-z0-9][a-z0-9-]{0,63}$'
     or p_suggestion_id is null
     or p_suggestion_id !~ '^[0-9a-f]{64}$' then
    raise exception 'STAGING_PARTICIPANT_CITIZEN_ADOPTION_SOURCE_INVALID'
      using errcode = 'P0001';
  end if;
  select suggestion.* into strict v_suggestion
    from staging_participant_private.staging_participant_topic_suggestions suggestion
   where suggestion.namespace =
     'urn:stadtstack:topic:municipality:' || p_municipality_id
     and suggestion.suggestion_id = p_suggestion_id
     and suggestion.state = 'published';
  return jsonb_build_object(
    'municipality_id', p_municipality_id,
    'suggestion_id', v_suggestion.suggestion_id,
    'discussion_root_id', v_suggestion.discussion_root_id,
    'source_author_pubkey', v_suggestion.source_author_pubkey
  );
exception
  when no_data_found then return null;
  when too_many_rows then
    raise exception 'STAGING_PARTICIPANT_CITIZEN_ADOPTION_SOURCE_INVALID'
      using errcode = 'P0001';
end;
$$;

revoke all on function public.staging_participant_gateway_get_citizen_suggestion_root(text,text)
  from public, anon, authenticated;
grant execute on function public.staging_participant_gateway_get_citizen_suggestion_root(text,text)
  to anon;

create table staging_participant_private.staging_participant_citizen_adoptions (
  municipality_id text not null,
  participant_suggestion_id text not null,
  adopter_pubkey text not null,
  request_id uuid not null unique,
  idempotency_key_sha256 bytea not null unique,
  request_checksum bytea not null,
  adoption_event_id text not null unique,
  adoption_id text not null unique,
  eligibility_receipt_id text not null unique references
    staging_participant_private.staging_participant_citizen_eligibility_receipts(receipt_id),
  event_created_at bigint not null,
  received_at bigint not null,
  public_projection jsonb not null,
  created_at timestamptz not null default clock_timestamp(),
  primary key (municipality_id, participant_suggestion_id, adopter_pubkey),
  check (municipality_id ~ '^[a-z0-9][a-z0-9-]{0,63}$'),
  check (participant_suggestion_id ~ '^[0-9a-f]{64}$'),
  check (adopter_pubkey ~ '^[0-9a-f]{64}$'),
  check (octet_length(idempotency_key_sha256) = 32),
  check (octet_length(request_checksum) = 32),
  check (adoption_event_id ~ '^[0-9a-f]{64}$'),
  check (adoption_id ~ '^urn:stadtstack:citizen-topic-suggestion-adoption:[0-9a-f]{64}$'),
  check (event_created_at >= 0 and received_at >= 0)
);

alter table staging_participant_private.staging_participant_citizen_adoptions
  enable row level security;
revoke all on table staging_participant_private.staging_participant_citizen_adoptions from public, anon, authenticated;

create or replace function public.staging_participant_gateway_resolve_citizen_adoption_replay(
  p_municipality_id text,
  p_request_id uuid,
  p_idempotency_key_sha256 text,
  p_request_checksum text,
  p_adoption_event_id text
) returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, staging_participant_private
as $$
declare
  v_adoption staging_participant_private.staging_participant_citizen_adoptions%rowtype;
begin
  perform staging_participant_private.require_staging_participant_gateway();
  if p_municipality_id is null
     or p_municipality_id !~ '^[a-z0-9][a-z0-9-]{0,63}$'
     or p_request_id is null
     or p_idempotency_key_sha256 is null
     or lower(p_idempotency_key_sha256) !~ '^[0-9a-f]{64}$'
     or p_request_checksum is null
     or lower(p_request_checksum) !~ '^[0-9a-f]{64}$'
     or p_adoption_event_id is null
     or lower(p_adoption_event_id) !~ '^[0-9a-f]{64}$' then
    raise exception 'STAGING_PARTICIPANT_CITIZEN_ADOPTION_REQUEST_CONFLICT'
      using errcode = 'P0001';
  end if;
  perform pg_advisory_xact_lock(
    hashtextextended('citizen-adoption:' || p_municipality_id, 20260901)
  );
  select * into v_adoption
    from staging_participant_private.staging_participant_citizen_adoptions
   where request_id = p_request_id
   for update;
  if not found then return null; end if;
  if v_adoption.municipality_id is distinct from p_municipality_id
     or v_adoption.request_checksum is distinct from
       decode(lower(p_request_checksum), 'hex') then
    raise exception 'STAGING_PARTICIPANT_CITIZEN_ADOPTION_REQUEST_CONFLICT'
      using errcode = 'P0001';
  end if;
  if v_adoption.idempotency_key_sha256 is distinct from
     decode(lower(p_idempotency_key_sha256), 'hex') then
    raise exception 'STAGING_PARTICIPANT_CITIZEN_ADOPTION_IDEMPOTENCY_CONFLICT'
      using errcode = 'P0001';
  end if;
  if v_adoption.adoption_event_id is distinct from
     lower(p_adoption_event_id) then
    raise exception 'STAGING_PARTICIPANT_CITIZEN_ADOPTION_EVENT_CONFLICT'
      using errcode = 'P0001';
  end if;
  return v_adoption.public_projection;
end;
$$;

create or replace function public.staging_participant_gateway_accept_citizen_adoption(
  p_municipality_id text,
  p_request_id uuid,
  p_idempotency_key_sha256 text,
  p_request_checksum text,
  p_received_at bigint,
  p_max_event_clock_skew_seconds integer,
  p_adoption jsonb,
  p_eligibility_receipt jsonb,
  p_acceptance_receipt jsonb
) returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, staging_participant_private
as $$
declare
  v_adoption staging_participant_private.staging_participant_citizen_adoptions%rowtype;
  v_receipt staging_participant_private.staging_participant_citizen_eligibility_receipts%rowtype;
  v_public_adoption jsonb := p_adoption->'adoption';
  v_event jsonb := p_adoption->'event';
  v_municipality_id text := p_adoption->'adoption'->>'municipalityId';
  v_suggestion_id text := lower(p_adoption->>'participantSuggestionId');
  v_adopter_pubkey text := lower(p_adoption->>'signerPubkey');
  v_event_id text := lower(p_adoption->'event'->>'id');
  v_adoption_id text := p_adoption->>'adoptionId';
  v_receipt_id text := p_eligibility_receipt->>'receiptId';
  v_event_created_at bigint;
  v_projection jsonb;
begin
  perform staging_participant_private.require_staging_participant_gateway();
  if p_municipality_id is null
     or p_municipality_id !~ '^[a-z0-9][a-z0-9-]{0,63}$'
     or p_request_id is null
     or p_idempotency_key_sha256 is null
     or lower(p_idempotency_key_sha256) !~ '^[0-9a-f]{64}$'
     or p_request_checksum is null
     or lower(p_request_checksum) !~ '^[0-9a-f]{64}$'
     or p_received_at is null or p_received_at < 0
     or p_max_event_clock_skew_seconds is null
     or p_max_event_clock_skew_seconds < 0
     or p_max_event_clock_skew_seconds > 300
     or p_adoption is null
     or jsonb_typeof(p_adoption) is distinct from 'object'
     or not (p_adoption ?& array[
       'schemaVersion', 'adoptionId', 'signerPubkey',
       'participantSuggestionId', 'eligibilityReceiptId', 'adoption', 'event',
       'verification', 'entryState', 'authorityBinding',
       'submittedToCivicWorkflow'
     ])
     or (
       select count(*)
         from pg_catalog.jsonb_object_keys(
           case when pg_catalog.jsonb_typeof(p_adoption) = 'object'
             then p_adoption else '{}'::jsonb end
         )
     ) <> 11
     or exists (
       select 1
         from pg_catalog.jsonb_each(
           case when pg_catalog.jsonb_typeof(p_adoption) = 'object'
             then p_adoption else '{}'::jsonb end
         ) as field(key, value)
        where field.value = 'null'::jsonb
     )
     or p_adoption->'schemaVersion' is distinct from
       '"citizen_adopted_topic_suggestion_v1"'::jsonb
     or p_adoption->'verification' is distinct from
       '{"kind":"nostr_nip01","verified":true}'::jsonb
     or jsonb_typeof(v_public_adoption) is distinct from 'object'
     or not (v_public_adoption ?& array[
       'schemaVersion', 'adoptionId', 'municipalityId', 'topicId',
       'participantSuggestionId', 'participantSuggestionRef',
       'participantPubkey', 'sourceDiscussionId', 'sourceAnswerReceiptId',
       'adopterPubkey', 'eligibilityReceiptId',
       'eligibilityReceiptChecksum', 'title', 'summary', 'entryState',
       'authorityBinding', 'submittedToCivicWorkflow'
     ])
     or (
       select count(*)
         from pg_catalog.jsonb_object_keys(
           case when pg_catalog.jsonb_typeof(v_public_adoption) = 'object'
             then v_public_adoption else '{}'::jsonb end
         )
     ) <> 17
     or exists (
       select 1
         from pg_catalog.jsonb_each(
           case when pg_catalog.jsonb_typeof(v_public_adoption) = 'object'
             then v_public_adoption else '{}'::jsonb end
         ) as field(key, value)
        where field.value = 'null'::jsonb
     )
     or jsonb_typeof(v_event) is distinct from 'object'
     or not (v_event ?& array[
       'id', 'pubkey', 'created_at', 'kind', 'tags', 'content', 'sig'
     ])
     or (
       select count(*)
         from pg_catalog.jsonb_object_keys(
           case when pg_catalog.jsonb_typeof(v_event) = 'object'
             then v_event else '{}'::jsonb end
         )
     ) <> 7
     or exists (
       select 1
         from pg_catalog.jsonb_each(
           case when pg_catalog.jsonb_typeof(v_event) = 'object'
             then v_event else '{}'::jsonb end
         ) as field(key, value)
        where field.value = 'null'::jsonb
     )
     or v_municipality_id is distinct from p_municipality_id
     or v_suggestion_id is null or v_suggestion_id !~ '^[0-9a-f]{64}$'
     or v_adopter_pubkey is null or v_adopter_pubkey !~ '^[0-9a-f]{64}$'
     or v_event_id is null or v_event_id !~ '^[0-9a-f]{64}$'
     or v_adoption_id is null
     or v_adoption_id !~ '^urn:stadtstack:citizen-topic-suggestion-adoption:[0-9a-f]{64}$'
     or v_public_adoption->>'adoptionId' is distinct from v_adoption_id
     or v_public_adoption->>'municipalityId' is distinct from p_municipality_id
     or v_public_adoption->>'participantSuggestionId' is distinct from
       v_suggestion_id
     or v_public_adoption->>'adopterPubkey' is distinct from v_adopter_pubkey
     or v_event->>'pubkey' is distinct from v_adopter_pubkey
     or v_event->'kind' is distinct from '1'::jsonb
     or p_adoption->>'eligibilityReceiptId' is distinct from v_receipt_id
     or v_public_adoption->>'eligibilityReceiptId' is distinct from v_receipt_id
     or p_adoption->'entryState' is distinct from
       '"case_steward_review_required"'::jsonb
     or p_adoption->'authorityBinding' is distinct from
       '"civic_eligibility_only"'::jsonb
     or p_adoption->'submittedToCivicWorkflow' is distinct from 'false'::jsonb
     or v_public_adoption->'entryState' is distinct from
       '"case_steward_review_required"'::jsonb
     or v_public_adoption->'authorityBinding' is distinct from
       '"civic_eligibility_only"'::jsonb
     or v_public_adoption->'submittedToCivicWorkflow' is distinct from
       'false'::jsonb
     or p_eligibility_receipt is null
     or jsonb_typeof(p_eligibility_receipt) is distinct from 'object'
     or not (p_eligibility_receipt ?& array[
       'schemaVersion', 'eligibilityCore', 'receiptId', 'payloadChecksum',
       'statusRef', 'proof'
     ])
     or (
       select count(*)
         from pg_catalog.jsonb_object_keys(
           case when pg_catalog.jsonb_typeof(p_eligibility_receipt) = 'object'
             then p_eligibility_receipt else '{}'::jsonb end
         )
     ) <> 6
     or exists (
       select 1
         from pg_catalog.jsonb_each(
           case when pg_catalog.jsonb_typeof(p_eligibility_receipt) = 'object'
             then p_eligibility_receipt else '{}'::jsonb end
         ) as field(key, value)
        where field.value = 'null'::jsonb
     )
     or p_eligibility_receipt->'schemaVersion' is distinct from
       '"municipal_civic_eligibility_receipt_v1"'::jsonb
     or jsonb_typeof(p_eligibility_receipt->'eligibilityCore') is distinct from
       'object'
     or p_eligibility_receipt->'eligibilityCore'->>'municipalityId'
       is distinct from p_municipality_id
     or lower(p_eligibility_receipt->'eligibilityCore'->>'subjectPubkey')
       is distinct from v_adopter_pubkey
     or lower(
       p_eligibility_receipt->'eligibilityCore'->>'participantSuggestionId'
     ) is distinct from v_suggestion_id
     or p_acceptance_receipt is null
     or jsonb_typeof(p_acceptance_receipt) is distinct from 'object'
     or not (p_acceptance_receipt ?& array[
       'schemaVersion', 'adoptionId', 'adoptionEventId', 'municipalityId',
       'topicId', 'participantSuggestionId', 'adopterPubkey',
       'eligibilityReceiptId', 'requestChecksum', 'eventCreatedAt',
       'receivedAt', 'policyVersion', 'status', 'authorityBinding',
       'receiptChecksum'
     ])
     or (
       select count(*)
         from pg_catalog.jsonb_object_keys(
           case when pg_catalog.jsonb_typeof(p_acceptance_receipt) = 'object'
             then p_acceptance_receipt else '{}'::jsonb end
         )
     ) <> 15
     or exists (
       select 1
         from pg_catalog.jsonb_each(
           case when pg_catalog.jsonb_typeof(p_acceptance_receipt) = 'object'
             then p_acceptance_receipt else '{}'::jsonb end
         ) as field(key, value)
        where field.value = 'null'::jsonb
     )
     or p_acceptance_receipt->'schemaVersion' is distinct from
       '"citizen_topic_suggestion_adoption_acceptance_receipt_v1"'::jsonb
     or p_acceptance_receipt->>'adoptionId' is distinct from v_adoption_id
     or lower(p_acceptance_receipt->>'adoptionEventId') is distinct from
       v_event_id
     or p_acceptance_receipt->>'municipalityId' is distinct from
       p_municipality_id
     or lower(p_acceptance_receipt->>'participantSuggestionId')
       is distinct from v_suggestion_id
     or lower(p_acceptance_receipt->>'adopterPubkey') is distinct from
       v_adopter_pubkey
     or p_acceptance_receipt->>'eligibilityReceiptId' is distinct from
       v_receipt_id
     or lower(p_acceptance_receipt->>'requestChecksum') is distinct from
       lower(p_request_checksum)
     or p_acceptance_receipt->>'eventCreatedAt' is null
     or p_acceptance_receipt->>'receivedAt' is distinct from
       p_received_at::text
     or p_acceptance_receipt->'status' is distinct from '"accepted"'::jsonb
     or p_acceptance_receipt->'authorityBinding' is distinct from
       '"civic_eligibility_only"'::jsonb
     or p_acceptance_receipt->>'receiptChecksum' is null
     or p_acceptance_receipt->>'receiptChecksum' !~ '^[0-9a-f]{64}$' then
    raise exception 'STAGING_PARTICIPANT_CITIZEN_ADOPTION_REQUEST_CONFLICT'
      using errcode = 'P0001';
  end if;
  begin
    v_event_created_at := (v_event->>'created_at')::bigint;
  exception when others then
    raise exception 'STAGING_PARTICIPANT_CITIZEN_ADOPTION_REQUEST_CONFLICT'
      using errcode = 'P0001';
  end;
  if v_event_created_at is null or v_event_created_at < 0
     or abs(p_received_at::numeric - v_event_created_at::numeric) >
       p_max_event_clock_skew_seconds
     or p_acceptance_receipt->>'eventCreatedAt' is distinct from
       v_event_created_at::text then
    raise exception 'STAGING_PARTICIPANT_CITIZEN_ADOPTION_REQUEST_CONFLICT'
      using errcode = 'P0001';
  end if;
  select * into v_receipt
    from staging_participant_private.staging_participant_citizen_eligibility_receipts
   where receipt_id = v_receipt_id;
  if not found
     or v_receipt.public_receipt is distinct from p_eligibility_receipt
     or v_receipt.municipality_id is distinct from p_municipality_id
     or v_receipt.subject_pubkey is distinct from v_adopter_pubkey
     or v_receipt.participant_suggestion_id is distinct from v_suggestion_id
     or p_eligibility_receipt->'eligibilityCore'->>'issuedAt' is null
     or p_eligibility_receipt->'eligibilityCore'->>'expiresAt' is null
     or (p_eligibility_receipt->'eligibilityCore'->>'issuedAt')::bigint > p_received_at
     or (p_eligibility_receipt->'eligibilityCore'->>'expiresAt')::bigint <= p_received_at then
    raise exception 'STAGING_PARTICIPANT_CITIZEN_ADOPTION_REQUEST_CONFLICT'
      using errcode = 'P0001';
  end if;
  if not exists (
    select 1
      from staging_participant_private.staging_participant_topic_suggestions suggestion
     where suggestion.namespace =
       'urn:stadtstack:topic:municipality:' || p_municipality_id
       and suggestion.suggestion_id = v_suggestion_id
       and suggestion.topic_id = v_public_adoption->>'topicId'
       and suggestion.state = 'published'
  ) then
    raise exception 'STAGING_PARTICIPANT_CITIZEN_ADOPTION_REQUEST_CONFLICT'
      using errcode = 'P0001';
  end if;
  v_projection := jsonb_build_object(
    'schemaVersion', 'public_citizen_adoption_projection_v1',
    'participantSuggestionId', v_suggestion_id,
    'adoptionEvent', v_event,
    'eligibilityReceipt', p_eligibility_receipt,
    'acceptanceReceipt', p_acceptance_receipt,
    'entryState', 'case_steward_review_required',
    'authorityBinding', 'civic_eligibility_only',
    'submittedToCivicWorkflow', false,
    'administrativeEndorsement', false,
    'bindingVote', false,
    'councilDecision', false,
    'treasuryEffect', false,
    'paymentEffect', false
  );
  perform pg_advisory_xact_lock(
    hashtextextended('citizen-adoption:' || p_municipality_id, 20260901)
  );
  select * into v_adoption
    from staging_participant_private.staging_participant_citizen_adoptions
   where request_id = p_request_id
   for update;
  if found then
    if v_adoption.municipality_id is distinct from p_municipality_id
       or v_adoption.request_checksum is distinct from
         decode(lower(p_request_checksum), 'hex') then
      raise exception 'STAGING_PARTICIPANT_CITIZEN_ADOPTION_REQUEST_CONFLICT'
        using errcode = 'P0001';
    end if;
    if v_adoption.idempotency_key_sha256 is distinct from
       decode(lower(p_idempotency_key_sha256), 'hex') then
      raise exception 'STAGING_PARTICIPANT_CITIZEN_ADOPTION_IDEMPOTENCY_CONFLICT'
        using errcode = 'P0001';
    end if;
    if v_adoption.adoption_event_id is distinct from v_event_id then
      raise exception 'STAGING_PARTICIPANT_CITIZEN_ADOPTION_EVENT_CONFLICT'
        using errcode = 'P0001';
    end if;
    if v_adoption.municipality_id is distinct from v_municipality_id
       or v_adoption.participant_suggestion_id is distinct from v_suggestion_id
       or v_adoption.adopter_pubkey is distinct from v_adopter_pubkey
       or v_adoption.public_projection is distinct from v_projection then
      raise exception 'STAGING_PARTICIPANT_CITIZEN_ADOPTION_TUPLE_CONFLICT'
        using errcode = 'P0001';
    end if;
    return v_adoption.public_projection;
  end if;
  if exists (
    select 1 from staging_participant_private.staging_participant_citizen_adoptions
     where idempotency_key_sha256 = decode(lower(p_idempotency_key_sha256), 'hex')
  ) then
    raise exception 'STAGING_PARTICIPANT_CITIZEN_ADOPTION_IDEMPOTENCY_CONFLICT'
      using errcode = 'P0001';
  end if;
  if exists (
    select 1 from staging_participant_private.staging_participant_citizen_adoptions
     where adoption_event_id = v_event_id
  ) then
    raise exception 'STAGING_PARTICIPANT_CITIZEN_ADOPTION_EVENT_CONFLICT'
      using errcode = 'P0001';
  end if;
  select * into v_adoption
    from staging_participant_private.staging_participant_citizen_adoptions
   where municipality_id = p_municipality_id
     and participant_suggestion_id = v_suggestion_id
     and adopter_pubkey = v_adopter_pubkey
   for update;
  if found then
    raise exception 'STAGING_PARTICIPANT_CITIZEN_ADOPTION_TUPLE_CONFLICT'
      using errcode = 'P0001';
  end if;
  if exists (
    select 1 from staging_participant_private.staging_participant_citizen_adoptions
     where eligibility_receipt_id = v_receipt_id
  ) then
    raise exception 'STAGING_PARTICIPANT_CITIZEN_ADOPTION_TUPLE_CONFLICT'
      using errcode = 'P0001';
  end if;
  insert into staging_participant_private.staging_participant_citizen_adoptions (
    municipality_id, participant_suggestion_id, adopter_pubkey, request_id,
    idempotency_key_sha256, request_checksum, adoption_event_id, adoption_id,
    eligibility_receipt_id, event_created_at, received_at, public_projection
  ) values (
    p_municipality_id, v_suggestion_id, v_adopter_pubkey, p_request_id,
    decode(lower(p_idempotency_key_sha256), 'hex'),
    decode(lower(p_request_checksum), 'hex'), v_event_id, v_adoption_id,
    v_receipt_id, v_event_created_at, p_received_at, v_projection
  ) returning * into v_adoption;
  return v_adoption.public_projection;
exception when invalid_text_representation or numeric_value_out_of_range then
  raise exception 'STAGING_PARTICIPANT_CITIZEN_ADOPTION_REQUEST_CONFLICT'
    using errcode = 'P0001';
end;
$$;

create or replace function public.staging_participant_gateway_read_public_citizen_adoption(
  p_municipality_id text,
  p_participant_suggestion_id text,
  p_adopter_pubkey text
) returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, staging_participant_private
as $$
declare
  v_adoption staging_participant_private.staging_participant_citizen_adoptions%rowtype;
begin
  perform staging_participant_private.require_staging_participant_gateway();
  if p_municipality_id is null
     or p_municipality_id !~ '^[a-z0-9][a-z0-9-]{0,63}$'
     or p_participant_suggestion_id is null
     or lower(p_participant_suggestion_id) !~ '^[0-9a-f]{64}$'
     or p_adopter_pubkey is null
     or lower(p_adopter_pubkey) !~ '^[0-9a-f]{64}$' then
    raise exception 'STAGING_PARTICIPANT_CITIZEN_ADOPTION_REQUEST_CONFLICT'
      using errcode = 'P0001';
  end if;
  select * into v_adoption
    from staging_participant_private.staging_participant_citizen_adoptions
   where municipality_id = p_municipality_id
     and participant_suggestion_id = lower(p_participant_suggestion_id)
     and adopter_pubkey = lower(p_adopter_pubkey);
  if not found then return null; end if;
  return v_adoption.public_projection;
end;
$$;

revoke all on function public.staging_participant_gateway_resolve_citizen_adoption_replay(text,uuid,text,text,text)
  from public, anon, authenticated;
grant execute on function public.staging_participant_gateway_resolve_citizen_adoption_replay(text,uuid,text,text,text)
  to anon;
revoke all on function public.staging_participant_gateway_accept_citizen_adoption(text,uuid,text,text,bigint,integer,jsonb,jsonb,jsonb)
  from public, anon, authenticated;
grant execute on function public.staging_participant_gateway_accept_citizen_adoption(text,uuid,text,text,bigint,integer,jsonb,jsonb,jsonb)
  to anon;
revoke all on function public.staging_participant_gateway_read_public_citizen_adoption(text,text,text)
  from public, anon, authenticated;
grant execute on function public.staging_participant_gateway_read_public_citizen_adoption(text,text,text)
  to anon;

create table staging_participant_private.staging_participant_citizen_adoption_schema_contract (
  singleton boolean primary key default true check (singleton),
  migration_id text not null,
  database_schema_sha256 text not null
    check (database_schema_sha256 ~ '^sha256:[0-9a-f]{64}$'),
  canonical_contract_sha256 text not null
    check (canonical_contract_sha256 ~ '^sha256:[0-9a-f]{64}$'),
  canonical_contract text not null
);

alter table staging_participant_private.staging_participant_citizen_adoption_schema_contract
  enable row level security;
revoke all on table staging_participant_private.staging_participant_citizen_adoption_schema_contract from public, anon, authenticated;

create table staging_participant_private.staging_participant_citizen_adoption_catalog_contract (
  object_identity text primary key,
  owner_name text not null,
  language_name text not null,
  return_type text not null,
  volatility "char" not null
    check (volatility in ('i'::"char", 's'::"char", 'v'::"char")),
  security_definer boolean not null,
  definition_sha256 text not null
    check (definition_sha256 ~ '^sha256:[0-9a-f]{64}$'),
  source_sha256 text not null
    check (source_sha256 ~ '^sha256:[0-9a-f]{64}$'),
  configuration text not null
    check (configuration like 'search_path=pg_catalog,%')
);

alter table staging_participant_private.staging_participant_citizen_adoption_catalog_contract
  enable row level security;
revoke all on table staging_participant_private.staging_participant_citizen_adoption_catalog_contract from public, anon, authenticated;

insert into staging_participant_private.staging_participant_citizen_adoption_schema_contract (
  singleton, migration_id, database_schema_sha256,
  canonical_contract_sha256, canonical_contract
) values (
  true,
  '20260901_staging_citizen_adoption',
  'sha256:79fea3feb09029e6138c7675fa0b877c3367390bec012b07e052c55103de7c9c',
  'sha256:79fea3feb09029e6138c7675fa0b877c3367390bec012b07e052c55103de7c9c',
  $contract${"assertions":{"adoptionKey":["municipality_id","participant_suggestion_id","adopter_pubkey"],"authorityBinding":"civic_eligibility_only","challenge":{"atomicOneUse":true,"normalizedFailures":["missing","used","expired","mismatch"],"sessionBound":true},"executeAcl":{"publicRpcAllowed":["anon"],"publicRpcDenied":["PUBLIC","authenticated"]},"finalityEvidence":{"chainId":100,"contractAddress":"0x59aa26f499d7c2b3ec2c8524ed06f54fc4e85de5","privateOnly":true,"rule":"finalized"},"idempotency":{"adoptionEventIdsUnique":true,"conflicts":["tuple","request","idempotency","event"],"exactLateRetryReturnsOriginal":true,"idempotencyKeysUnique":true,"requestIdsUnique":true,"serializedBy":"municipality_id"},"privateTableIsolation":{"noDirectAcl":true,"rowLevelSecurity":true},"privateTables":["staging_participant_private.staging_participant_citizen_eligibility_challenges","staging_participant_private.staging_participant_citizen_eligibility_receipts","staging_participant_private.staging_participant_citizen_adoptions","staging_participant_private.staging_participant_citizen_adoption_schema_contract","staging_participant_private.staging_participant_citizen_adoption_catalog_contract"],"publicProjection":{"administrativeEndorsement":false,"bindingVote":false,"councilDecision":false,"entryState":"case_steward_review_required","paymentEffect":false,"submittedToCivicWorkflow":false,"treasuryEffect":false},"publicRpc":["public.staging_participant_gateway_issue_citizen_challenge(jsonb)","public.staging_participant_gateway_consume_citizen_challenge(text,text,text,bigint)","public.staging_participant_gateway_store_citizen_eligibility_receipt(text,jsonb,jsonb)","public.staging_participant_gateway_get_citizen_eligibility_receipt(text)","public.staging_participant_gateway_get_citizen_suggestion_root(text,text)","public.staging_participant_gateway_resolve_citizen_adoption_replay(text,uuid,text,text,text)","public.staging_participant_gateway_accept_citizen_adoption(text,uuid,text,text,bigint,integer,jsonb,jsonb,jsonb)","public.staging_participant_gateway_read_public_citizen_adoption(text,text,text)","public.staging_participant_gateway_citizen_adoption_preflight()"]},"migrationId":"20260901_staging_citizen_adoption","schemaVersion":"roebel_staging_citizen_adoption_schema_contract_v1"}
$contract$
);

insert into staging_participant_private.staging_participant_citizen_adoption_catalog_contract (
  object_identity, owner_name, language_name, return_type, volatility,
  security_definer, definition_sha256, source_sha256, configuration
)
select reviewed.object_identity, owner_role.rolname, language.lanname,
  pg_catalog.pg_get_function_result(proc.oid), proc.provolatile, proc.prosecdef,
  'sha256:' || encode(extensions.digest(
    pg_catalog.pg_get_functiondef(proc.oid), 'sha256'
  ), 'hex'),
  'sha256:' || encode(extensions.digest(proc.prosrc, 'sha256'), 'hex'),
  coalesce(array_to_string(proc.proconfig, E'\n'), '')
from (values
  ('public.staging_participant_gateway_issue_citizen_challenge(jsonb)'),
  ('public.staging_participant_gateway_consume_citizen_challenge(text,text,text,bigint)'),
  ('public.staging_participant_gateway_store_citizen_eligibility_receipt(text,jsonb,jsonb)'),
  ('public.staging_participant_gateway_get_citizen_eligibility_receipt(text)'),
  ('public.staging_participant_gateway_get_citizen_suggestion_root(text,text)'),
  ('public.staging_participant_gateway_resolve_citizen_adoption_replay(text,uuid,text,text,text)'),
  ('public.staging_participant_gateway_accept_citizen_adoption(text,uuid,text,text,bigint,integer,jsonb,jsonb,jsonb)'),
  ('public.staging_participant_gateway_read_public_citizen_adoption(text,text,text)')
) as reviewed(object_identity)
join pg_catalog.pg_proc proc
  on proc.oid = to_regprocedure(reviewed.object_identity)
join pg_catalog.pg_roles owner_role on owner_role.oid = proc.proowner
join pg_catalog.pg_language language on language.oid = proc.prolang;

create or replace function public.staging_participant_gateway_citizen_adoption_preflight()
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, staging_participant_private
as $$
declare
  v_marker staging_participant_private.staging_participant_citizen_adoption_schema_contract%rowtype;
  v_function text;
  v_table text;
begin
  perform staging_participant_private.require_staging_participant_gateway();
  select * into v_marker
    from staging_participant_private.staging_participant_citizen_adoption_schema_contract
   where singleton = true;
  if not found
     or v_marker.migration_id <> '20260901_staging_citizen_adoption'
     or v_marker.database_schema_sha256 <>
       'sha256:79fea3feb09029e6138c7675fa0b877c3367390bec012b07e052c55103de7c9c'
     or v_marker.canonical_contract_sha256 <>
       'sha256:79fea3feb09029e6138c7675fa0b877c3367390bec012b07e052c55103de7c9c'
     or v_marker.canonical_contract <> $contract${"assertions":{"adoptionKey":["municipality_id","participant_suggestion_id","adopter_pubkey"],"authorityBinding":"civic_eligibility_only","challenge":{"atomicOneUse":true,"normalizedFailures":["missing","used","expired","mismatch"],"sessionBound":true},"executeAcl":{"publicRpcAllowed":["anon"],"publicRpcDenied":["PUBLIC","authenticated"]},"finalityEvidence":{"chainId":100,"contractAddress":"0x59aa26f499d7c2b3ec2c8524ed06f54fc4e85de5","privateOnly":true,"rule":"finalized"},"idempotency":{"adoptionEventIdsUnique":true,"conflicts":["tuple","request","idempotency","event"],"exactLateRetryReturnsOriginal":true,"idempotencyKeysUnique":true,"requestIdsUnique":true,"serializedBy":"municipality_id"},"privateTableIsolation":{"noDirectAcl":true,"rowLevelSecurity":true},"privateTables":["staging_participant_private.staging_participant_citizen_eligibility_challenges","staging_participant_private.staging_participant_citizen_eligibility_receipts","staging_participant_private.staging_participant_citizen_adoptions","staging_participant_private.staging_participant_citizen_adoption_schema_contract","staging_participant_private.staging_participant_citizen_adoption_catalog_contract"],"publicProjection":{"administrativeEndorsement":false,"bindingVote":false,"councilDecision":false,"entryState":"case_steward_review_required","paymentEffect":false,"submittedToCivicWorkflow":false,"treasuryEffect":false},"publicRpc":["public.staging_participant_gateway_issue_citizen_challenge(jsonb)","public.staging_participant_gateway_consume_citizen_challenge(text,text,text,bigint)","public.staging_participant_gateway_store_citizen_eligibility_receipt(text,jsonb,jsonb)","public.staging_participant_gateway_get_citizen_eligibility_receipt(text)","public.staging_participant_gateway_get_citizen_suggestion_root(text,text)","public.staging_participant_gateway_resolve_citizen_adoption_replay(text,uuid,text,text,text)","public.staging_participant_gateway_accept_citizen_adoption(text,uuid,text,text,bigint,integer,jsonb,jsonb,jsonb)","public.staging_participant_gateway_read_public_citizen_adoption(text,text,text)","public.staging_participant_gateway_citizen_adoption_preflight()"]},"migrationId":"20260901_staging_citizen_adoption","schemaVersion":"roebel_staging_citizen_adoption_schema_contract_v1"}
$contract$ then
    raise exception 'STAGING_PARTICIPANT_CITIZEN_ADOPTION_SCHEMA_DRIFT'
      using errcode = 'P0001';
  end if;

  foreach v_function in array array[
    'public.staging_participant_gateway_issue_citizen_challenge(jsonb)',
    'public.staging_participant_gateway_consume_citizen_challenge(text,text,text,bigint)',
    'public.staging_participant_gateway_store_citizen_eligibility_receipt(text,jsonb,jsonb)',
    'public.staging_participant_gateway_get_citizen_eligibility_receipt(text)',
    'public.staging_participant_gateway_get_citizen_suggestion_root(text,text)',
    'public.staging_participant_gateway_resolve_citizen_adoption_replay(text,uuid,text,text,text)',
    'public.staging_participant_gateway_accept_citizen_adoption(text,uuid,text,text,bigint,integer,jsonb,jsonb,jsonb)',
    'public.staging_participant_gateway_read_public_citizen_adoption(text,text,text)',
    'public.staging_participant_gateway_citizen_adoption_preflight()'
  ] loop
    if to_regprocedure(v_function) is null
       or not exists (
         select 1
           from staging_participant_private.staging_participant_citizen_adoption_catalog_contract contract
          where contract.object_identity = v_function
       )
       or not has_function_privilege('anon', to_regprocedure(v_function), 'EXECUTE')
       or has_function_privilege('authenticated', to_regprocedure(v_function), 'EXECUTE')
       or exists (
         select 1
           from pg_catalog.pg_proc proc
           cross join lateral pg_catalog.aclexplode(
             coalesce(proc.proacl, pg_catalog.acldefault('f', proc.proowner))
           ) acl
          where proc.oid = to_regprocedure(v_function)
            and acl.privilege_type = 'EXECUTE'
            and (
              (acl.grantee <> proc.proowner
                and acl.grantee <>
                  (select oid from pg_catalog.pg_roles where rolname = 'anon'))
              or (acl.grantee =
                  (select oid from pg_catalog.pg_roles where rolname = 'anon')
                and acl.is_grantable)
            )
       ) then
      raise exception 'STAGING_PARTICIPANT_CITIZEN_ADOPTION_CATALOG_DRIFT:%',
        v_function using errcode = 'P0001';
    end if;
  end loop;

  if has_schema_privilege(
       'anon', 'staging_participant_private', 'USAGE'
     )
     or has_schema_privilege(
       'authenticated', 'staging_participant_private', 'USAGE'
     ) then
    raise exception 'STAGING_PARTICIPANT_CITIZEN_ADOPTION_RLS_DRIFT'
      using errcode = 'P0001';
  end if;
  foreach v_table in array array[
    'staging_participant_private.staging_participant_citizen_eligibility_challenges',
    'staging_participant_private.staging_participant_citizen_eligibility_receipts',
    'staging_participant_private.staging_participant_citizen_adoptions',
    'staging_participant_private.staging_participant_citizen_adoption_schema_contract',
    'staging_participant_private.staging_participant_citizen_adoption_catalog_contract'
  ] loop
    if to_regclass(v_table) is null
       or not exists (
         select 1
           from pg_catalog.pg_class relation
          where relation.oid = to_regclass(v_table)
            and relation.relkind = 'r'
            and relation.relrowsecurity
       )
       or exists (
         select 1 from pg_catalog.pg_policy policy
          where policy.polrelid = to_regclass(v_table)
       )
       or exists (
         select 1
           from pg_catalog.pg_class relation
           cross join lateral pg_catalog.aclexplode(
             coalesce(
               relation.relacl,
               pg_catalog.acldefault('r', relation.relowner)
             )
           ) acl
          where relation.oid = to_regclass(v_table)
            and acl.grantee <> relation.relowner
       )
       or exists (
         select 1
           from (values ('anon'), ('authenticated')) as actor(role_name)
           cross join (values
             ('SELECT'), ('INSERT'), ('UPDATE'), ('DELETE'), ('TRUNCATE'),
             ('REFERENCES'), ('TRIGGER')
           ) as permission(privilege_name)
          where has_table_privilege(
            actor.role_name, to_regclass(v_table), permission.privilege_name
          )
       ) then
      raise exception 'STAGING_PARTICIPANT_CITIZEN_ADOPTION_RLS_DRIFT:%',
        v_table using errcode = 'P0001';
    end if;
  end loop;

  if (
    select count(*)
      from pg_catalog.pg_proc proc
      join pg_catalog.pg_namespace namespace
        on namespace.oid = proc.pronamespace
     where namespace.nspname = 'public'
       and proc.proname = any(array[
         'staging_participant_gateway_issue_citizen_challenge',
         'staging_participant_gateway_consume_citizen_challenge',
         'staging_participant_gateway_store_citizen_eligibility_receipt',
         'staging_participant_gateway_get_citizen_eligibility_receipt',
         'staging_participant_gateway_get_citizen_suggestion_root',
         'staging_participant_gateway_resolve_citizen_adoption_replay',
         'staging_participant_gateway_accept_citizen_adoption',
         'staging_participant_gateway_read_public_citizen_adoption',
         'staging_participant_gateway_citizen_adoption_preflight'
       ]::text[])
  ) <> 9
     or (
       select count(*)
         from staging_participant_private.staging_participant_citizen_adoption_catalog_contract
     ) <> 9
     or exists (
       select 1
         from staging_participant_private.staging_participant_citizen_adoption_catalog_contract contract
         left join pg_catalog.pg_proc proc
           on proc.oid = to_regprocedure(contract.object_identity)
         left join pg_catalog.pg_roles owner_role
           on owner_role.oid = proc.proowner
         left join pg_catalog.pg_language language
           on language.oid = proc.prolang
        where proc.oid is null
          or owner_role.rolname <> contract.owner_name
          or language.lanname <> contract.language_name
          or pg_catalog.pg_get_function_result(proc.oid) <> contract.return_type
          or proc.provolatile <> contract.volatility
          or proc.prosecdef <> contract.security_definer
          or 'sha256:' || encode(extensions.digest(
               pg_catalog.pg_get_functiondef(proc.oid), 'sha256'
             ), 'hex') <> contract.definition_sha256
          or 'sha256:' || encode(
               extensions.digest(proc.prosrc, 'sha256'), 'hex'
             ) <> contract.source_sha256
          or coalesce(array_to_string(proc.proconfig, E'\n'), '') <>
             contract.configuration
     ) then
    raise exception 'STAGING_PARTICIPANT_CITIZEN_ADOPTION_CATALOG_DRIFT'
      using errcode = 'P0001';
  end if;
  return jsonb_build_object(
    'migration_id', v_marker.migration_id,
    'database_schema_sha256', v_marker.database_schema_sha256
  );
end;
$$;

insert into staging_participant_private.staging_participant_citizen_adoption_catalog_contract (
  object_identity, owner_name, language_name, return_type, volatility,
  security_definer, definition_sha256, source_sha256, configuration
)
select reviewed.object_identity, owner_role.rolname, language.lanname,
  pg_catalog.pg_get_function_result(proc.oid), proc.provolatile, proc.prosecdef,
  'sha256:' || encode(extensions.digest(
    pg_catalog.pg_get_functiondef(proc.oid), 'sha256'
  ), 'hex'),
  'sha256:' || encode(extensions.digest(proc.prosrc, 'sha256'), 'hex'),
  coalesce(array_to_string(proc.proconfig, E'\n'), '')
from (values
  ('public.staging_participant_gateway_citizen_adoption_preflight()')
) as reviewed(object_identity)
join pg_catalog.pg_proc proc
  on proc.oid = to_regprocedure(reviewed.object_identity)
join pg_catalog.pg_roles owner_role on owner_role.oid = proc.proowner
join pg_catalog.pg_language language on language.oid = proc.prolang;

revoke all on function public.staging_participant_gateway_citizen_adoption_preflight()
  from public, anon, authenticated;
grant execute on function public.staging_participant_gateway_citizen_adoption_preflight()
  to anon;

commit;
