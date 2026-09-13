-- Replace identity-state.sql's final COMMIT with this rollback-only rehearsal.
do $$
begin
  if exists (select 1 from pg_roles where rolname = 'roebel_staging_identity'
             and (rolcanlogin or rolinherit or rolsuper or rolcreatedb
                  or rolcreaterole or rolreplication or rolbypassrls))
     or has_schema_privilege('roebel_staging_identity', 'public', 'CREATE')
     or exists (
       select 1 from pg_class c join pg_namespace n on n.oid = c.relnamespace
       where n.nspname = 'public' and c.relkind in ('r', 'p', 'v', 'm')
         and c.relname <> 'oidc_payloads'
         and has_table_privilege('roebel_staging_identity', c.oid,
                                 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
     ) then raise exception 'Identity role is overprivileged';
  end if;
  if exists (
    select 1 from unnest(array['anon', 'authenticated', 'service_role']) r
    where has_table_privilege(r, 'public.oidc_payloads',
                             'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
  ) then raise exception 'Broad API role can access OAuth state'; end if;
end;
$$;
set local role roebel_staging_identity;
do $$
declare claims text;
begin
  foreach claims in array array['{}',
    '{"iss":"roebel-id-staging","aud":"another-service"}',
    '{"iss":"another-service","aud":"roebel-id-state-store"}'] loop
    perform set_config('request.jwt.claims', claims, true);
    begin
      insert into public.oidc_payloads (type, id, payload)
        values ('Session', 'identity-rehearsal', '{"synthetic":true}');
      raise exception 'Invalid identity claims unexpectedly allowed a write';
    exception when insufficient_privilege then null;
    end;
  end loop;
end;
$$;
set local request.jwt.claims = '{"iss":"roebel-id-staging","aud":"roebel-id-state-store"}';
insert into public.oidc_payloads (type, id, payload, grant_id, uid, expires_at)
  values ('Session', 'identity-rehearsal', '{"synthetic":true}', 'test-grant', 'test-uid', now() + interval '1 hour');
update public.oidc_payloads set payload = '{"synthetic":true,"consumed":1}'
  where type = 'Session' and id = 'identity-rehearsal';
do $$
begin
  if not exists (select 1 from public.oidc_payloads where uid = 'test-uid'
                 and payload ->> 'consumed' = '1' and expires_at > now()) then
    raise exception 'OAuth CRUD failed';
  end if;
end;
$$;
set local request.jwt.claims = '{}';
do $$
begin
  if exists (select 1 from public.oidc_payloads) then
    raise exception 'Missing identity claims can read OAuth state';
  end if;
end;
$$;
set local request.jwt.claims = '{"iss":"roebel-id-staging","aud":"roebel-id-state-store"}';
delete from public.oidc_payloads where grant_id = 'test-grant';
do $$
begin
  if exists (select 1 from public.oidc_payloads where id = 'identity-rehearsal') then
    raise exception 'Grant revocation did not delete OAuth state';
  end if;
end;
$$;
reset role;
select json_build_object('identityCrudPassed', true, 'invalidClaimsDenied', true,
  'unclaimedReadDenied', true, 'broadApiRolesDenied', true, 'otherPublicTablesDenied', true);
rollback;
