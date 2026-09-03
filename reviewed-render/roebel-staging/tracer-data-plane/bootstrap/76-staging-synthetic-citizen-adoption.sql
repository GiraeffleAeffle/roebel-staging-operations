-- ADR-0023 synthetic browser tracer. This migration is intentionally
-- incompatible with municipal eligibility, real citizen adoption and every
-- Case/governance/treasury path. It stores only a staging test-pass proof and
-- an explicitly no-authority public projection.

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
    raise exception 'STAGING_PARTICIPANT_SYNTHETIC_ADOPTION_REQUIRES_ARMED_STAGING'
      using errcode = 'P0001';
  end if;
end;
$$;

create table staging_participant_private.staging_participant_synthetic_citizen_challenges (
  challenge_id text primary key,
  municipality_id text not null,
  wallet_address text not null,
  session_binding_sha256 bytea not null,
  subject_pubkey text not null,
  participant_suggestion_id text not null,
  topic_id text not null,
  policy_version text not null,
  test_citizen_nft_contract text not null,
  issued_at bigint not null,
  expires_at bigint not null,
  consumed_at bigint,
  challenge jsonb not null,
  created_at timestamptz not null default clock_timestamp(),
  check (challenge_id ~ '^[0-9a-f]{32}$'),
  check (municipality_id ~ '^[a-z0-9][a-z0-9-]{0,63}$'),
  check (wallet_address ~ '^0x[0-9a-f]{40}$'),
  check (octet_length(session_binding_sha256) = 32),
  check (subject_pubkey ~ '^[0-9a-f]{64}$'),
  check (participant_suggestion_id ~ '^[0-9a-f]{64}$'),
  check (topic_id like 'urn:stadtstack:topic:municipality:' || municipality_id || ':%'),
  check (policy_version ~ '^[a-z0-9][a-z0-9._-]{2,99}$'),
  check (test_citizen_nft_contract ~ '^0x[0-9a-f]{40}$'),
  check (issued_at >= 0 and expires_at > issued_at),
  check (consumed_at is null or (consumed_at >= issued_at and consumed_at < expires_at))
);

alter table staging_participant_private.staging_participant_synthetic_citizen_challenges
  enable row level security;
revoke all on table staging_participant_private.staging_participant_synthetic_citizen_challenges
  from public, anon, authenticated;

create or replace function public.staging_participant_gateway_issue_synthetic_challenge(
  p_challenge jsonb,
  p_wallet_address text,
  p_session_binding_sha256 text
) returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, staging_participant_private
as $$
declare
  v_row staging_participant_private.staging_participant_synthetic_citizen_challenges%rowtype;
  v_challenge_id text := lower(p_challenge->>'challengeId');
  v_municipality_id text := p_challenge->>'municipalityId';
  v_wallet text := lower(p_wallet_address);
  v_session text := lower(p_session_binding_sha256);
  v_subject text := lower(p_challenge->>'subjectPubkey');
  v_suggestion text := lower(p_challenge->>'participantSuggestionId');
  v_topic text := p_challenge->>'topicId';
  v_policy text := p_challenge->>'policyVersion';
  v_contract text := lower(p_challenge->>'testCitizenNftContract');
  v_issued bigint;
  v_expires bigint;
begin
  perform staging_participant_private.require_staging_participant_gateway();
  if p_challenge is null or jsonb_typeof(p_challenge) is distinct from 'object'
     or not (p_challenge ?& array[
       'schemaVersion','challengeId','audience','chainId',
       'testCitizenNftContract','subjectPubkey','municipalityId','policyVersion',
       'participantSuggestionId','topicId','issuedAt','expiresAt','environment',
       'testOnly','authorityBinding','canonicalChallenge','message'
     ])
     or (select count(*) from jsonb_object_keys(
       case when jsonb_typeof(p_challenge) = 'object' then p_challenge else '{}'::jsonb end
     )) <> 17
     or exists (select 1 from jsonb_each(
       case when jsonb_typeof(p_challenge) = 'object' then p_challenge else '{}'::jsonb end
     ) field where field.value = 'null'::jsonb)
     or p_challenge->'schemaVersion' is distinct from '"staging_test_citizen_pass_v1"'::jsonb
     or p_challenge->'audience' is distinct from '"roebel-staging-synthetic-citizen-adoption"'::jsonb
     or p_challenge->'chainId' is distinct from '100'::jsonb
     or p_challenge->'environment' is distinct from '"staging"'::jsonb
     or p_challenge->'testOnly' is distinct from 'true'::jsonb
     or p_challenge->'authorityBinding' is distinct from '"none"'::jsonb
     or p_challenge->'message' is distinct from p_challenge->'canonicalChallenge'
     or coalesce(p_challenge->>'message','') = ''
     or v_challenge_id is null or v_challenge_id !~ '^[0-9a-f]{32}$'
     or v_wallet is null or v_wallet !~ '^0x[0-9a-f]{40}$'
     or v_session is null or v_session !~ '^[0-9a-f]{64}$'
     or v_subject is null or v_subject !~ '^[0-9a-f]{64}$'
     or v_suggestion is null or v_suggestion !~ '^[0-9a-f]{64}$'
     or v_municipality_id is null
     or v_municipality_id !~ '^[a-z0-9][a-z0-9-]{0,63}$'
     or v_policy is null or v_policy !~ '^[a-z0-9][a-z0-9._-]{2,99}$'
     or v_contract is distinct from '0x0be374808a567c9088ac8208b90a4239432b3220'
     or v_topic is null or v_topic not like
       'urn:stadtstack:topic:municipality:' || v_municipality_id || ':%' then
    raise exception 'STAGING_PARTICIPANT_SYNTHETIC_CHALLENGE_MISMATCH'
      using errcode = 'P0001';
  end if;
  begin
    v_issued := (p_challenge->>'issuedAt')::bigint;
    v_expires := (p_challenge->>'expiresAt')::bigint;
  exception when others then
    raise exception 'STAGING_PARTICIPANT_SYNTHETIC_CHALLENGE_MISMATCH'
      using errcode = 'P0001';
  end;
  if v_issued is null or v_expires is null or v_issued < 0
     or v_expires - v_issued <> 300 then
    raise exception 'STAGING_PARTICIPANT_SYNTHETIC_CHALLENGE_MISMATCH'
      using errcode = 'P0001';
  end if;
  perform staging_participant_private.ensure_active_staging_participant(v_wallet);
  if not exists (
    select 1
      from staging_participant_private.staging_participant_topic_suggestions s
     where s.namespace =
       'urn:stadtstack:topic:municipality:' || v_municipality_id
       and s.suggestion_id = v_suggestion
       and s.topic_id = v_topic
       and s.state = 'published'
  ) then
    raise exception 'STAGING_PARTICIPANT_SYNTHETIC_CHALLENGE_MISMATCH'
      using errcode = 'P0001';
  end if;
  perform pg_advisory_xact_lock(
    hashtextextended('synthetic-challenge:' || v_challenge_id, 20260902)
  );
  select * into v_row
    from staging_participant_private.staging_participant_synthetic_citizen_challenges
   where challenge_id = v_challenge_id for update;
  if found then
    if v_row.challenge is distinct from p_challenge
       or v_row.wallet_address is distinct from v_wallet
       or v_row.session_binding_sha256 is distinct from decode(v_session,'hex') then
      raise exception 'STAGING_PARTICIPANT_SYNTHETIC_CHALLENGE_MISMATCH'
        using errcode = 'P0001';
    end if;
    return v_row.challenge;
  end if;
  insert into staging_participant_private.staging_participant_synthetic_citizen_challenges (
    challenge_id, municipality_id, wallet_address, session_binding_sha256,
    subject_pubkey, participant_suggestion_id, topic_id, policy_version,
    test_citizen_nft_contract, issued_at, expires_at, challenge
  ) values (
    v_challenge_id, v_municipality_id, v_wallet, decode(v_session,'hex'),
    v_subject, v_suggestion, v_topic, v_policy, v_contract,
    v_issued, v_expires, p_challenge
  ) returning * into v_row;
  return v_row.challenge;
end;
$$;

create or replace function public.staging_participant_gateway_consume_synthetic_challenge(
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
  v_row staging_participant_private.staging_participant_synthetic_citizen_challenges%rowtype;
  v_wallet text := lower(p_wallet_address);
  v_session text := lower(p_session_binding_sha256);
begin
  perform staging_participant_private.require_staging_participant_gateway();
  if p_challenge_id is null or p_challenge_id !~ '^[0-9a-f]{32}$'
     or v_wallet is null or v_wallet !~ '^0x[0-9a-f]{40}$'
     or v_session is null or v_session !~ '^[0-9a-f]{64}$'
     or p_consumed_at is null or p_consumed_at < 0 then
    raise exception 'STAGING_PARTICIPANT_SYNTHETIC_CHALLENGE_MISMATCH'
      using errcode = 'P0001';
  end if;
  perform pg_advisory_xact_lock(
    hashtextextended('synthetic-challenge:' || p_challenge_id, 20260902)
  );
  select * into v_row
    from staging_participant_private.staging_participant_synthetic_citizen_challenges
   where challenge_id = p_challenge_id for update;
  if not found then
    raise exception 'STAGING_PARTICIPANT_SYNTHETIC_CHALLENGE_MISSING'
      using errcode = 'P0001';
  end if;
  if v_row.consumed_at is not null then
    raise exception 'STAGING_PARTICIPANT_SYNTHETIC_CHALLENGE_USED'
      using errcode = 'P0001';
  end if;
  if v_row.expires_at <= p_consumed_at then
    raise exception 'STAGING_PARTICIPANT_SYNTHETIC_CHALLENGE_EXPIRED'
      using errcode = 'P0001';
  end if;
  if p_consumed_at < v_row.issued_at then
    raise exception 'STAGING_PARTICIPANT_SYNTHETIC_CHALLENGE_MISMATCH'
      using errcode = 'P0001';
  end if;
  if v_row.wallet_address is distinct from v_wallet
     or v_row.session_binding_sha256 is distinct from decode(v_session,'hex') then
    raise exception 'STAGING_PARTICIPANT_SYNTHETIC_CHALLENGE_MISMATCH'
      using errcode = 'P0001';
  end if;
  update staging_participant_private.staging_participant_synthetic_citizen_challenges
     set consumed_at = p_consumed_at
   where challenge_id = p_challenge_id;
  return v_row.challenge;
end;
$$;

create table staging_participant_private.staging_participant_synthetic_citizen_adoptions (
  municipality_id text not null,
  participant_suggestion_id text not null,
  adopter_pubkey text not null,
  wallet_address text not null,
  request_id uuid not null unique,
  idempotency_key_sha256 bytea not null unique,
  request_checksum bytea not null,
  proof_event_id text not null unique,
  tracer_id text not null unique,
  event_created_at bigint not null,
  received_at bigint not null,
  private_eligibility_evidence jsonb not null,
  public_projection jsonb not null,
  created_at timestamptz not null default clock_timestamp(),
  primary key (municipality_id, participant_suggestion_id, adopter_pubkey),
  check (municipality_id ~ '^[a-z0-9][a-z0-9-]{0,63}$'),
  check (participant_suggestion_id ~ '^[0-9a-f]{64}$'),
  check (adopter_pubkey ~ '^[0-9a-f]{64}$'),
  check (wallet_address ~ '^0x[0-9a-f]{40}$'),
  check (octet_length(idempotency_key_sha256) = 32),
  check (octet_length(request_checksum) = 32),
  check (proof_event_id ~ '^[0-9a-f]{64}$'),
  check (tracer_id ~ '^urn:stadtstack:synthetic-citizen-adoption-tracer:[0-9a-f]{64}$'),
  check (event_created_at >= 0 and received_at >= 0)
);

alter table staging_participant_private.staging_participant_synthetic_citizen_adoptions
  enable row level security;
revoke all on table staging_participant_private.staging_participant_synthetic_citizen_adoptions
  from public, anon, authenticated;

create or replace function public.staging_participant_gateway_resolve_synthetic_adoption_replay(
  p_municipality_id text,
  p_request_id uuid,
  p_idempotency_key_sha256 text,
  p_request_checksum text,
  p_proof_event_id text
) returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, staging_participant_private
as $$
declare
  v_row staging_participant_private.staging_participant_synthetic_citizen_adoptions%rowtype;
begin
  perform staging_participant_private.require_staging_participant_gateway();
  if p_municipality_id is null
     or p_municipality_id !~ '^[a-z0-9][a-z0-9-]{0,63}$'
     or p_request_id is null
     or p_idempotency_key_sha256 is null
     or lower(p_idempotency_key_sha256) !~ '^[0-9a-f]{64}$'
     or p_request_checksum is null
     or lower(p_request_checksum) !~ '^[0-9a-f]{64}$'
     or p_proof_event_id is null
     or lower(p_proof_event_id) !~ '^[0-9a-f]{64}$' then
    raise exception 'STAGING_PARTICIPANT_SYNTHETIC_ADOPTION_REQUEST_CONFLICT'
      using errcode = 'P0001';
  end if;
  select * into v_row
    from staging_participant_private.staging_participant_synthetic_citizen_adoptions
   where request_id = p_request_id for update;
  if not found then return null; end if;
  if v_row.municipality_id is distinct from p_municipality_id
     or v_row.request_checksum is distinct from decode(lower(p_request_checksum),'hex') then
    raise exception 'STAGING_PARTICIPANT_SYNTHETIC_ADOPTION_REQUEST_CONFLICT'
      using errcode = 'P0001';
  end if;
  if v_row.idempotency_key_sha256 is distinct from decode(lower(p_idempotency_key_sha256),'hex') then
    raise exception 'STAGING_PARTICIPANT_SYNTHETIC_ADOPTION_IDEMPOTENCY_CONFLICT'
      using errcode = 'P0001';
  end if;
  if v_row.proof_event_id is distinct from lower(p_proof_event_id) then
    raise exception 'STAGING_PARTICIPANT_SYNTHETIC_ADOPTION_EVENT_CONFLICT'
      using errcode = 'P0001';
  end if;
  return v_row.public_projection;
end;
$$;

create or replace function public.staging_participant_gateway_accept_synthetic_adoption(
  p_municipality_id text,
  p_request_id uuid,
  p_idempotency_key_sha256 text,
  p_request_checksum text,
  p_received_at bigint,
  p_max_event_clock_skew_seconds integer,
  p_proof_event jsonb,
  p_private_eligibility_evidence jsonb,
  p_public_projection jsonb
) returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, staging_participant_private
as $$
declare
  v_row staging_participant_private.staging_participant_synthetic_citizen_adoptions%rowtype;
  v_challenge staging_participant_private.staging_participant_synthetic_citizen_challenges%rowtype;
  v_tracer jsonb := p_public_projection->'tracer';
  v_acceptance jsonb := p_public_projection->'acceptanceReceipt';
  v_labels jsonb := p_public_projection->'labels';
  v_suggestion text := lower(v_tracer->>'participantSuggestionId');
  v_adopter text := lower(v_tracer->>'adopterPubkey');
  v_event_id text := lower(p_proof_event->>'id');
  v_tracer_id text := v_tracer->>'tracerId';
  v_challenge_id text;
  v_event_created_at bigint;
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
     or p_max_event_clock_skew_seconds not between 0 and 300
     or jsonb_typeof(p_proof_event) is distinct from 'object'
     or not (p_proof_event ?& array['id','pubkey','created_at','kind','tags','content','sig'])
     or (select count(*) from jsonb_object_keys(
       case when jsonb_typeof(p_proof_event) = 'object' then p_proof_event else '{}'::jsonb end
     )) <> 7
     or exists (select 1 from jsonb_each(
       case when jsonb_typeof(p_proof_event) = 'object' then p_proof_event else '{}'::jsonb end
     ) field where field.value = 'null'::jsonb)
     or p_proof_event->'kind' is distinct from '1'::jsonb
     or jsonb_typeof(p_proof_event->'tags') is distinct from 'array'
     or v_event_id is null or v_event_id !~ '^[0-9a-f]{64}$'
     or jsonb_typeof(p_public_projection) is distinct from 'object'
     or not (p_public_projection ?& array[
       'schemaVersion','participantSuggestionId','proofEvent','tracer',
       'acceptanceReceipt','labels','entryState','environment','testOnly',
       'authorityBinding','submittedToCivicWorkflow','civicCaseCreated',
       'administrativeEndorsement','bindingVote','councilDecision',
       'treasuryEffect','paymentEffect'
     ])
     or (select count(*) from jsonb_object_keys(
       case when jsonb_typeof(p_public_projection) = 'object' then p_public_projection else '{}'::jsonb end
     )) <> 17
     or exists (select 1 from jsonb_each(
       case when jsonb_typeof(p_public_projection) = 'object' then p_public_projection else '{}'::jsonb end
     ) field where field.value = 'null'::jsonb)
     or p_public_projection->'schemaVersion' is distinct from
       '"public_synthetic_citizen_adoption_projection_v1"'::jsonb
     or p_public_projection->'entryState' is distinct from '"synthetic_journey_preview_only"'::jsonb
     or p_public_projection->'environment' is distinct from '"staging"'::jsonb
     or p_public_projection->'testOnly' is distinct from 'true'::jsonb
     or p_public_projection->'authorityBinding' is distinct from '"none"'::jsonb
     or p_public_projection->'submittedToCivicWorkflow' is distinct from 'false'::jsonb
     or p_public_projection->'civicCaseCreated' is distinct from 'false'::jsonb
     or p_public_projection->'administrativeEndorsement' is distinct from 'false'::jsonb
     or p_public_projection->'bindingVote' is distinct from 'false'::jsonb
     or p_public_projection->'councilDecision' is distinct from 'false'::jsonb
     or p_public_projection->'treasuryEffect' is distinct from 'false'::jsonb
     or p_public_projection->'paymentEffect' is distinct from 'false'::jsonb
     or p_public_projection->'proofEvent' is distinct from p_proof_event
     or lower(p_public_projection->>'participantSuggestionId') is distinct from v_suggestion
     or jsonb_typeof(v_tracer) is distinct from 'object'
     or not (v_tracer ?& array[
       'schemaVersion','tracerId','municipalityId','topicId',
       'participantSuggestionId','participantSuggestionRef','participantPubkey',
       'sourceDiscussionId','sourceAnswerReceiptId','adopterPubkey',
       'proofEventId','title','summary','entryState','environment','testOnly',
       'authorityBinding','submittedToCivicWorkflow'
     ])
     or (select count(*) from jsonb_object_keys(
       case when jsonb_typeof(v_tracer) = 'object' then v_tracer else '{}'::jsonb end
     )) <> 18
     or exists (select 1 from jsonb_each(
       case when jsonb_typeof(v_tracer) = 'object' then v_tracer else '{}'::jsonb end
     ) field where field.value = 'null'::jsonb)
     or v_tracer->'schemaVersion' is distinct from '"synthetic_citizen_adoption_tracer_v1"'::jsonb
     or v_tracer->>'municipalityId' is distinct from p_municipality_id
     or v_suggestion is null or v_suggestion !~ '^[0-9a-f]{64}$'
     or v_adopter is null or v_adopter !~ '^[0-9a-f]{64}$'
     or v_event_id is distinct from lower(v_tracer->>'proofEventId')
     or v_adopter is distinct from lower(p_proof_event->>'pubkey')
     or v_tracer_id is null
     or v_tracer_id !~ '^urn:stadtstack:synthetic-citizen-adoption-tracer:[0-9a-f]{64}$'
     or v_tracer->'entryState' is distinct from '"synthetic_journey_preview_only"'::jsonb
     or v_tracer->'environment' is distinct from '"staging"'::jsonb
     or v_tracer->'testOnly' is distinct from 'true'::jsonb
     or v_tracer->'authorityBinding' is distinct from '"none"'::jsonb
     or v_tracer->'submittedToCivicWorkflow' is distinct from 'false'::jsonb
     or jsonb_typeof(v_acceptance) is distinct from 'object'
     or not (v_acceptance ?& array[
       'schemaVersion','tracerId','proofEventId','municipalityId','topicId',
       'participantSuggestionId','adopterPubkey','requestChecksum',
       'eventCreatedAt','receivedAt','policyVersion','status','environment',
       'testOnly','authorityBinding','receiptChecksum'
     ])
     or (select count(*) from jsonb_object_keys(
       case when jsonb_typeof(v_acceptance) = 'object' then v_acceptance else '{}'::jsonb end
     )) <> 16
     or exists (select 1 from jsonb_each(
       case when jsonb_typeof(v_acceptance) = 'object' then v_acceptance else '{}'::jsonb end
     ) field where field.value = 'null'::jsonb)
     or v_acceptance->'schemaVersion' is distinct from
       '"synthetic_citizen_adoption_tracer_acceptance_v1"'::jsonb
     or v_acceptance->>'tracerId' is distinct from v_tracer_id
     or lower(v_acceptance->>'proofEventId') is distinct from v_event_id
     or v_acceptance->>'municipalityId' is distinct from p_municipality_id
     or v_acceptance->>'topicId' is distinct from v_tracer->>'topicId'
     or lower(v_acceptance->>'participantSuggestionId') is distinct from v_suggestion
     or lower(v_acceptance->>'adopterPubkey') is distinct from v_adopter
     or lower(v_acceptance->>'requestChecksum') is distinct from lower(p_request_checksum)
     or v_acceptance->>'receivedAt' is distinct from p_received_at::text
     or v_acceptance->'status' is distinct from '"accepted_for_synthetic_preview"'::jsonb
     or v_acceptance->'environment' is distinct from '"staging"'::jsonb
     or v_acceptance->'testOnly' is distinct from 'true'::jsonb
     or v_acceptance->'authorityBinding' is distinct from '"none"'::jsonb
     or v_acceptance->>'policyVersion' is null
     or v_acceptance->>'policyVersion' !~ '^[a-z0-9][a-z0-9._-]{2,99}$'
     or v_acceptance->>'receiptChecksum' is null
     or (v_acceptance->>'receiptChecksum') !~ '^[0-9a-f]{64}$'
     or v_labels is distinct from jsonb_build_object(
       'citizenship','Test-Bürger-Pass – keine reale Bürgerberechtigung',
       'civicWorkflow','Nur synthetische Vorschau – kein CivicCase und keine Verwaltungsbefürwortung',
       'governance','Keine bindende Abstimmung, kein Beschluss, keine Treasury-Wirkung und keine Zahlung'
     )
     or p_public_projection ?| array['eligibilityReceipt','adoptionEvent','caseBindingReceipt']
     or jsonb_typeof(p_private_eligibility_evidence) is distinct from 'object'
     or not (p_private_eligibility_evidence ?& array[
       'active','chainId','contractAddress','finalizedBlockNumber','finalizedBlockHash'
     ])
     or (select count(*) from jsonb_object_keys(
       case when jsonb_typeof(p_private_eligibility_evidence) = 'object'
         then p_private_eligibility_evidence else '{}'::jsonb end
     )) <> 5
     or exists (
       select 1 from jsonb_each(
         case when jsonb_typeof(p_private_eligibility_evidence) = 'object'
           then p_private_eligibility_evidence else '{}'::jsonb end
       ) field
        where field.value = 'null'::jsonb
     )
     or p_private_eligibility_evidence->'active' is distinct from 'true'::jsonb
     or p_private_eligibility_evidence->'chainId' is distinct from '100'::jsonb
     or lower(p_private_eligibility_evidence->>'contractAddress') is distinct from
       '0x0be374808a567c9088ac8208b90a4239432b3220'
     or p_private_eligibility_evidence->>'finalizedBlockHash' is null
     or lower(p_private_eligibility_evidence->>'finalizedBlockHash') !~ '^0x[0-9a-f]{64}$'
     or p_private_eligibility_evidence->>'finalizedBlockNumber' is null
     or (p_private_eligibility_evidence->>'finalizedBlockNumber') !~ '^[0-9]+$' then
    raise exception 'STAGING_PARTICIPANT_SYNTHETIC_ADOPTION_REQUEST_CONFLICT'
      using errcode = 'P0001';
  end if;
  begin
    v_event_created_at := (p_proof_event->>'created_at')::bigint;
  exception when others then
    raise exception 'STAGING_PARTICIPANT_SYNTHETIC_ADOPTION_REQUEST_CONFLICT'
      using errcode = 'P0001';
  end;
  if v_event_created_at < 0
     or abs(p_received_at::numeric - v_event_created_at::numeric) >
       p_max_event_clock_skew_seconds
     or v_acceptance->>'eventCreatedAt' is distinct from v_event_created_at::text then
    raise exception 'STAGING_PARTICIPANT_SYNTHETIC_ADOPTION_REQUEST_CONFLICT'
      using errcode = 'P0001';
  end if;
  select tag->>1 into v_challenge_id
    from jsonb_array_elements(p_proof_event->'tags') tag
   where tag->>0 = 'challenge';
  if v_challenge_id is null or v_challenge_id !~ '^[0-9a-f]{32}$'
     or (select count(*) from jsonb_array_elements(p_proof_event->'tags') tag
          where tag->>0 = 'challenge') <> 1 then
    raise exception 'STAGING_PARTICIPANT_SYNTHETIC_ADOPTION_REQUEST_CONFLICT'
      using errcode = 'P0001';
  end if;
  select * into v_challenge
    from staging_participant_private.staging_participant_synthetic_citizen_challenges
   where challenge_id = v_challenge_id;
  if not found or v_challenge.consumed_at is null
     or v_challenge.municipality_id is distinct from p_municipality_id
     or v_challenge.participant_suggestion_id is distinct from v_suggestion
     or v_challenge.subject_pubkey is distinct from v_adopter
     or v_challenge.topic_id is distinct from v_tracer->>'topicId'
     or v_challenge.policy_version is distinct from v_acceptance->>'policyVersion'
     or v_challenge.test_citizen_nft_contract is distinct from
       lower(p_private_eligibility_evidence->>'contractAddress')
     or v_challenge.challenge->>'message' is distinct from p_proof_event->>'content' then
    raise exception 'STAGING_PARTICIPANT_SYNTHETIC_ADOPTION_REQUEST_CONFLICT'
      using errcode = 'P0001';
  end if;
  if not exists (
    select 1
      from staging_participant_private.staging_participant_topic_suggestions s
     where s.namespace = 'urn:stadtstack:topic:municipality:' || p_municipality_id
       and s.suggestion_id = v_suggestion
       and s.topic_id = v_tracer->>'topicId'
       and s.state = 'published'
  ) then
    raise exception 'STAGING_PARTICIPANT_SYNTHETIC_ADOPTION_REQUEST_CONFLICT'
      using errcode = 'P0001';
  end if;
  perform pg_advisory_xact_lock(
    hashtextextended('synthetic-adoption:' || p_municipality_id, 20260902)
  );
  select * into v_row
    from staging_participant_private.staging_participant_synthetic_citizen_adoptions
   where request_id = p_request_id for update;
  if found then
    if v_row.municipality_id is distinct from p_municipality_id
       or v_row.request_checksum is distinct from decode(lower(p_request_checksum),'hex') then
      raise exception 'STAGING_PARTICIPANT_SYNTHETIC_ADOPTION_REQUEST_CONFLICT'
        using errcode = 'P0001';
    end if;
    if v_row.idempotency_key_sha256 is distinct from decode(lower(p_idempotency_key_sha256),'hex') then
      raise exception 'STAGING_PARTICIPANT_SYNTHETIC_ADOPTION_IDEMPOTENCY_CONFLICT'
        using errcode = 'P0001';
    end if;
    if v_row.proof_event_id is distinct from v_event_id then
      raise exception 'STAGING_PARTICIPANT_SYNTHETIC_ADOPTION_EVENT_CONFLICT'
        using errcode = 'P0001';
    end if;
    if v_row.public_projection is distinct from p_public_projection then
      raise exception 'STAGING_PARTICIPANT_SYNTHETIC_ADOPTION_TUPLE_CONFLICT'
        using errcode = 'P0001';
    end if;
    return v_row.public_projection;
  end if;
  if exists (
    select 1 from staging_participant_private.staging_participant_synthetic_citizen_adoptions
     where idempotency_key_sha256 = decode(lower(p_idempotency_key_sha256),'hex')
  ) then
    raise exception 'STAGING_PARTICIPANT_SYNTHETIC_ADOPTION_IDEMPOTENCY_CONFLICT'
      using errcode = 'P0001';
  end if;
  if exists (
    select 1 from staging_participant_private.staging_participant_synthetic_citizen_adoptions
     where proof_event_id = v_event_id
  ) then
    raise exception 'STAGING_PARTICIPANT_SYNTHETIC_ADOPTION_EVENT_CONFLICT'
      using errcode = 'P0001';
  end if;
  if exists (
    select 1 from staging_participant_private.staging_participant_synthetic_citizen_adoptions
     where municipality_id = p_municipality_id
       and participant_suggestion_id = v_suggestion
       and adopter_pubkey = v_adopter
  ) then
    raise exception 'STAGING_PARTICIPANT_SYNTHETIC_ADOPTION_TUPLE_CONFLICT'
      using errcode = 'P0001';
  end if;
  insert into staging_participant_private.staging_participant_synthetic_citizen_adoptions (
    municipality_id, participant_suggestion_id, adopter_pubkey, wallet_address,
    request_id, idempotency_key_sha256, request_checksum, proof_event_id,
    tracer_id, event_created_at, received_at, private_eligibility_evidence,
    public_projection
  ) values (
    p_municipality_id, v_suggestion, v_adopter, v_challenge.wallet_address,
    p_request_id, decode(lower(p_idempotency_key_sha256),'hex'),
    decode(lower(p_request_checksum),'hex'), v_event_id, v_tracer_id,
    v_event_created_at, p_received_at, p_private_eligibility_evidence,
    p_public_projection
  ) returning * into v_row;
  return v_row.public_projection;
exception when invalid_text_representation or numeric_value_out_of_range then
  raise exception 'STAGING_PARTICIPANT_SYNTHETIC_ADOPTION_REQUEST_CONFLICT'
    using errcode = 'P0001';
end;
$$;

create or replace function public.staging_participant_gateway_read_public_synthetic_adoption(
  p_municipality_id text,
  p_participant_suggestion_id text,
  p_adopter_pubkey text
) returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, staging_participant_private
as $$
declare
  v_projection jsonb;
begin
  perform staging_participant_private.require_staging_participant_gateway();
  if p_municipality_id is null
     or p_municipality_id !~ '^[a-z0-9][a-z0-9-]{0,63}$'
     or p_participant_suggestion_id is null
     or lower(p_participant_suggestion_id) !~ '^[0-9a-f]{64}$'
     or p_adopter_pubkey is null
     or lower(p_adopter_pubkey) !~ '^[0-9a-f]{64}$' then
    raise exception 'STAGING_PARTICIPANT_SYNTHETIC_ADOPTION_REQUEST_CONFLICT'
      using errcode = 'P0001';
  end if;
  select public_projection into v_projection
    from staging_participant_private.staging_participant_synthetic_citizen_adoptions
   where municipality_id = p_municipality_id
     and participant_suggestion_id = lower(p_participant_suggestion_id)
     and adopter_pubkey = lower(p_adopter_pubkey);
  return v_projection;
end;
$$;

revoke all on function public.staging_participant_gateway_issue_synthetic_challenge(jsonb,text,text)
  from public, anon, authenticated;
grant execute on function public.staging_participant_gateway_issue_synthetic_challenge(jsonb,text,text)
  to anon;
revoke all on function public.staging_participant_gateway_consume_synthetic_challenge(text,text,text,bigint)
  from public, anon, authenticated;
grant execute on function public.staging_participant_gateway_consume_synthetic_challenge(text,text,text,bigint)
  to anon;
revoke all on function public.staging_participant_gateway_resolve_synthetic_adoption_replay(text,uuid,text,text,text)
  from public, anon, authenticated;
grant execute on function public.staging_participant_gateway_resolve_synthetic_adoption_replay(text,uuid,text,text,text)
  to anon;
revoke all on function public.staging_participant_gateway_accept_synthetic_adoption(text,uuid,text,text,bigint,integer,jsonb,jsonb,jsonb)
  from public, anon, authenticated;
grant execute on function public.staging_participant_gateway_accept_synthetic_adoption(text,uuid,text,text,bigint,integer,jsonb,jsonb,jsonb)
  to anon;
revoke all on function public.staging_participant_gateway_read_public_synthetic_adoption(text,text,text)
  from public, anon, authenticated;
grant execute on function public.staging_participant_gateway_read_public_synthetic_adoption(text,text,text)
  to anon;

create table staging_participant_private.staging_participant_synthetic_adoption_schema_contract (
  singleton boolean primary key default true check (singleton),
  migration_id text not null,
  database_schema_sha256 text not null
    check (database_schema_sha256 ~ '^sha256:[0-9a-f]{64}$'),
  canonical_contract text not null
);
alter table staging_participant_private.staging_participant_synthetic_adoption_schema_contract
  enable row level security;
revoke all on table staging_participant_private.staging_participant_synthetic_adoption_schema_contract
  from public, anon, authenticated;

insert into staging_participant_private.staging_participant_synthetic_adoption_schema_contract (
  singleton, migration_id, database_schema_sha256, canonical_contract
) values (
  true,
  '20260902_staging_synthetic_citizen_adoption',
  'sha256:bcaa0b098a99b145e5111c17e29e5e7d9e9eb0840ee27643b3c26db34118bd66',
  $contract${"authorityBinding":"none","environment":"staging","migrationId":"20260902_staging_synthetic_citizen_adoption","privateTables":["staging_participant_private.staging_participant_synthetic_citizen_challenges","staging_participant_private.staging_participant_synthetic_citizen_adoptions"],"publicProjection":"public_synthetic_citizen_adoption_projection_v1","realSchemasForbidden":["municipal_civic_eligibility_receipt_v1","citizen_topic_suggestion_adoption_request_v1","public_citizen_adoption_projection_v1","public_case_binding_receipt_v2"],"rpc":["staging_participant_gateway_issue_synthetic_challenge","staging_participant_gateway_consume_synthetic_challenge","staging_participant_gateway_resolve_synthetic_adoption_replay","staging_participant_gateway_accept_synthetic_adoption","staging_participant_gateway_read_public_synthetic_adoption"],"testOnly":true}
$contract$
);

create or replace function public.staging_participant_gateway_synthetic_adoption_preflight()
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, staging_participant_private, extensions
as $$
declare
  v_contract staging_participant_private.staging_participant_synthetic_adoption_schema_contract%rowtype;
begin
  perform staging_participant_private.require_staging_participant_gateway();
  select * into strict v_contract
    from staging_participant_private.staging_participant_synthetic_adoption_schema_contract
   where singleton;
  if v_contract.migration_id is distinct from
       '20260902_staging_synthetic_citizen_adoption'
     or v_contract.database_schema_sha256 is distinct from
       'sha256:' || encode(digest(convert_to(v_contract.canonical_contract,'UTF8'),'sha256'),'hex')
     or to_regclass('staging_participant_private.staging_participant_synthetic_citizen_challenges') is null
     or to_regclass('staging_participant_private.staging_participant_synthetic_citizen_adoptions') is null
     or to_regprocedure('public.staging_participant_gateway_issue_synthetic_challenge(jsonb,text,text)') is null
     or to_regprocedure('public.staging_participant_gateway_consume_synthetic_challenge(text,text,text,bigint)') is null
     or to_regprocedure('public.staging_participant_gateway_resolve_synthetic_adoption_replay(text,uuid,text,text,text)') is null
     or to_regprocedure('public.staging_participant_gateway_accept_synthetic_adoption(text,uuid,text,text,bigint,integer,jsonb,jsonb,jsonb)') is null
     or to_regprocedure('public.staging_participant_gateway_read_public_synthetic_adoption(text,text,text)') is null then
    raise exception 'STAGING_PARTICIPANT_SYNTHETIC_ADOPTION_SCHEMA_DRIFT'
      using errcode = 'P0001';
  end if;
  return jsonb_build_object(
    'migration_id', v_contract.migration_id,
    'database_schema_sha256', v_contract.database_schema_sha256
  );
end;
$$;

revoke all on function public.staging_participant_gateway_synthetic_adoption_preflight()
  from public, anon, authenticated;
grant execute on function public.staging_participant_gateway_synthetic_adoption_preflight()
  to anon;

commit;
