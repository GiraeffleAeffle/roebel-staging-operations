-- ADR-0023: attest the two additive reads before enabling signed status.
-- The older nine-function preflight and its immutable migration stay intact.
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
    raise exception 'STAGING_PARTICIPANT_CITIZEN_STATUS_REQUIRES_ARMED_STAGING';
  end if;
end;
$$;

create function public.staging_participant_gateway_citizen_adoption_status_preflight()
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog, staging_participant_private
as $$
declare
  v_base jsonb;
  v_owner oid;
  v_expected record;
  v_proc record;
begin
  -- This includes the Vault capability, staging arm, older function catalog,
  -- receipt/challenge/ledger isolation and their existing RLS/ACL checks.
  v_base := public.staging_participant_gateway_citizen_adoption_preflight();
  if v_base is distinct from jsonb_build_object(
    'migration_id', '20260901_staging_citizen_adoption',
    'database_schema_sha256', 'sha256:79fea3feb09029e6138c7675fa0b877c3367390bec012b07e052c55103de7c9c'
  ) then
    raise exception 'STAGING_PARTICIPANT_CITIZEN_STATUS_PREREQUISITE_DRIFT';
  end if;
  select proowner into v_owner from pg_catalog.pg_proc
   where oid = to_regprocedure('public.staging_participant_gateway_citizen_adoption_preflight()');

  -- Hashes are reviewed prosrc bytes from the two immutable SQL migrations,
  -- not a snapshot of whatever happened to be installed at activation time.
  for v_expected in select * from (values
    ('public.staging_participant_gateway_get_citizen_status_holder(text,text,text)',
     '150c02831159ad22a5e9c8b8533321a4fbe7c5912bbb16167eb152ef79b0df15',
     array['p_receipt_id', 'p_municipality_id', 'p_policy_version'], 's'),
    ('public.staging_participant_gateway_read_citizen_adoption_event(text,text)',
     '430cbec51e25a00eea0df63750f424c811b77eb7f56d59e5ac20f5689e991e43',
     array['p_municipality_id', 'p_adoption_event_id'], 's'),
    ('public.staging_participant_gateway_citizen_adoption_status_preflight()',
     null, null::text[], 'v')
  ) as expected(identity, source_sha256, argument_names, volatility)
  loop
    select proc.*, lang.lanname into v_proc from pg_catalog.pg_proc proc
      join pg_catalog.pg_language lang on lang.oid = proc.prolang
     where proc.oid = to_regprocedure(v_expected.identity);
    if not found then
      raise exception 'STAGING_PARTICIPANT_CITIZEN_STATUS_CATALOG_DRIFT';
    end if;
    if v_proc.proowner is distinct from v_owner
       or v_proc.lanname <> 'plpgsql' or not v_proc.prosecdef
       or v_proc.prorettype <> 'jsonb'::regtype or v_proc.proretset
       or v_proc.prokind <> 'f' or v_proc.provolatile::text <> v_expected.volatility
       or v_proc.proleakproof or v_proc.proisstrict or v_proc.proparallel <> 'u'
       or v_proc.pronargdefaults <> 0 or v_proc.provariadic <> 0 or v_proc.prosupport <> 0
       or v_proc.proargnames is distinct from v_expected.argument_names
       or v_proc.proconfig is distinct from array['search_path=pg_catalog, staging_participant_private']
       or (v_expected.source_sha256 is not null and
         encode(extensions.digest(v_proc.prosrc, 'sha256'), 'hex') <> v_expected.source_sha256)
       or (select count(*) from pg_catalog.pg_proc
            where pronamespace = v_proc.pronamespace and proname = v_proc.proname) <> 1
       or not has_function_privilege('anon', v_proc.oid, 'EXECUTE')
       or has_function_privilege('authenticated', v_proc.oid, 'EXECUTE')
       or exists (
         select 1 from pg_catalog.aclexplode(
           coalesce(v_proc.proacl, pg_catalog.acldefault('f', v_proc.proowner))
         ) acl
         where acl.privilege_type = 'EXECUTE' and (
           acl.grantee not in (v_proc.proowner, (select oid from pg_catalog.pg_roles where rolname = 'anon'))
           or (acl.grantee <> v_proc.proowner and acl.is_grantable)
         )
       ) then
      raise exception 'STAGING_PARTICIPANT_CITIZEN_STATUS_CATALOG_DRIFT';
    end if;
  end loop;
  -- Digest of staging-citizen-adoption-status-schema-contract-v1.json.
  -- Operations pins this migration's full bytes separately, including this
  -- checker; the contract claims exact source hashes only for the two reads.
  return jsonb_build_object(
    'migration_id', '20260906_staging_citizen_adoption_status_readiness',
    'database_schema_sha256', 'sha256:85c778d6b805fbfb9c82e343cfd966b1865c15c1fad628173da247ceecff2332'
  );
end;
$$;

revoke all on function public.staging_participant_gateway_citizen_adoption_status_preflight()
  from public, anon, authenticated, service_role, postgres;
grant execute on function public.staging_participant_gateway_citizen_adoption_status_preflight() to anon;

commit;
