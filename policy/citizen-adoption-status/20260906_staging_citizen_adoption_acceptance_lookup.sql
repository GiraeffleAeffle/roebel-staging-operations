-- ADR-0023: exact accepted-event lookup for the trusted Case admission reader.
-- Additive read only; existing adoption/preflight contracts are unchanged.
-- Operations must pin this migration and its ACL before enabling the endpoint.
begin;

do $$
begin
  if not exists (
    select 1 from public.app_settings where key = 'roebel_env' and value = 'staging'
  ) or not exists (
    select 1 from vault.decrypted_secrets
     where name = 'roebel_staging_participant_environment_arm' and decrypted_secret = 'staging-only'
  ) or not exists (
    select 1 from vault.decrypted_secrets
     where name = 'roebel_staging_participant_rpc_secret' and length(decrypted_secret) >= 32
  ) then
    raise exception 'STAGING_PARTICIPANT_CITIZEN_ADOPTION_LOOKUP_REQUIRES_ARMED_STAGING';
  end if;
end;
$$;

create function public.staging_participant_gateway_read_citizen_adoption_event(
  p_municipality_id text,
  p_adoption_event_id text
) returns jsonb
language plpgsql
stable
security definer
set search_path = pg_catalog, staging_participant_private
as $$
declare
  v_projection jsonb;
begin
  perform staging_participant_private.require_staging_participant_gateway();
  if p_municipality_id is null
     or p_municipality_id !~ '^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?$'
     or p_adoption_event_id is null
     or p_adoption_event_id !~ '^[0-9a-f]{64}$' then
    raise exception 'STAGING_PARTICIPANT_CITIZEN_ADOPTION_LOOKUP_INVALID';
  end if;
  -- adoption_event_id already has a unique constraint. No latest/tuple fallback,
  -- history rewrite, new acceptance time or private eligibility evidence.
  select public_projection into v_projection
    from staging_participant_private.staging_participant_citizen_adoptions
   where municipality_id = p_municipality_id and adoption_event_id = p_adoption_event_id;
  return v_projection;
end;
$$;

revoke all on function public.staging_participant_gateway_read_citizen_adoption_event(text,text)
  from public, anon, authenticated, service_role, postgres;
grant execute on function public.staging_participant_gateway_read_citizen_adoption_event(text,text)
  to anon;

commit;
