-- ADR-0023: private holder lookup for a fresh eligibility-status check.
-- Additive only: historical receipts, challenges and their public read RPC
-- remain unchanged. Operations must pin this migration and its function ACL
-- before composing the status reader; the older preflight covers older RPCs.
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
    raise exception 'STAGING_PARTICIPANT_CITIZEN_STATUS_REQUIRES_ARMED_STAGING';
  end if;
end;
$$;

create function public.staging_participant_gateway_get_citizen_status_holder(
  p_receipt_id text,
  p_municipality_id text,
  p_policy_version text
) returns jsonb
language plpgsql
stable
security definer
set search_path = pg_catalog, staging_participant_private
as $$
declare
  v_binding record;
begin
  -- The anon role is only PostgREST routing. The Vault-bound private header
  -- remains mandatory, even for an unknown receipt or invalid request.
  perform staging_participant_private.require_staging_participant_gateway();
  if p_receipt_id is null
     or p_receipt_id !~ '^urn:stadtstack:municipal-civic-eligibility-receipt:[0-9a-f]{64}$'
     or p_municipality_id is null
     or p_municipality_id !~ '^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?$'
     or p_policy_version is null
     or p_policy_version !~ '^[a-z0-9][a-z0-9._-]{2,99}$' then
    raise exception 'STAGING_PARTICIPANT_CITIZEN_STATUS_LOOKUP_INVALID';
  end if;

  -- One statement gives the receipt and its original holder one snapshot.
  -- No wallet selector, list endpoint, admission renewal or cached status.
  select issued_receipt as receipt, original_challenge as challenge into v_binding
    from staging_participant_private.staging_participant_citizen_eligibility_receipts issued_receipt
    join staging_participant_private.staging_participant_citizen_eligibility_challenges original_challenge
      on original_challenge.challenge_id = issued_receipt.challenge_id
   where issued_receipt.receipt_id = p_receipt_id
     and issued_receipt.municipality_id = p_municipality_id
     and issued_receipt.policy_version = p_policy_version;
  if not found then return null; end if;

  if (v_binding.challenge).consumed_at is null
     or (v_binding.challenge).municipality_id is distinct from p_municipality_id
     or (v_binding.challenge).policy_version is distinct from p_policy_version
     or (v_binding.challenge).subject_pubkey is distinct from (v_binding.receipt).subject_pubkey
     or (v_binding.challenge).participant_suggestion_id is distinct from (v_binding.receipt).participant_suggestion_id
     or (v_binding.challenge).topic_id is distinct from (v_binding.receipt).topic_id
     or (v_binding.challenge).wallet_address is distinct from lower((v_binding.challenge).challenge->>'walletAddress')
     or (v_binding.challenge).challenge->>'challengeId' is distinct from (v_binding.receipt).challenge_id
     or (v_binding.receipt).public_receipt->>'receiptId' is distinct from p_receipt_id
     or (v_binding.receipt).public_receipt->'eligibilityCore'->>'municipalityId' is distinct from p_municipality_id
     or (v_binding.receipt).public_receipt->'eligibilityCore'->>'policyVersion' is distinct from p_policy_version
     or (v_binding.receipt).public_receipt->'eligibilityCore'->>'subjectPubkey' is distinct from (v_binding.challenge).subject_pubkey
     or (v_binding.receipt).public_receipt->'eligibilityCore'->>'participantSuggestionId' is distinct from (v_binding.challenge).participant_suggestion_id
     or (v_binding.receipt).public_receipt->'eligibilityCore'->>'topicId' is distinct from (v_binding.challenge).topic_id then
    raise exception 'STAGING_PARTICIPANT_CITIZEN_STATUS_BINDING_INVALID';
  end if;
  -- Signature, receipt lifetime and fresh chain eligibility belong to the
  -- issuer resolver. The private evidence/session/challenge never leave here.
  return jsonb_build_object(
    'receipt', (v_binding.receipt).public_receipt,
    'walletAddress', (v_binding.challenge).wallet_address
  );
end;
$$;

revoke all on function public.staging_participant_gateway_get_citizen_status_holder(text,text,text)
  from public, anon, authenticated, service_role, postgres;
grant execute on function public.staging_participant_gateway_get_citizen_status_holder(text,text,text)
  to anon;

commit;
