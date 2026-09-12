-- Append inside workspace-sessions.sql's open transaction, replacing its final
-- COMMIT with this file. No live OAuth tokens or existing application rows.
do $$
begin
  if exists (select 1 from pg_roles where rolname = 'roebel_workspace_session'
             and (rolcanlogin or rolinherit or rolsuper or rolcreatedb
                  or rolcreaterole or rolreplication or rolbypassrls)) then
    raise exception 'Session role is overprivileged';
  end if;
  if has_schema_privilege('roebel_workspace_session', 'public', 'CREATE')
     or exists (
       select 1 from pg_class c join pg_namespace n on n.oid = c.relnamespace
       where n.nspname = 'public' and c.relkind in ('r', 'p', 'v', 'm')
         and c.relname <> 'workspace_sessions'
         and has_table_privilege('roebel_workspace_session', c.oid,
                                 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
     ) then
    raise exception 'Session role can access other public data or create objects';
  end if;
  if exists (
    select 1 from unnest(array['anon', 'authenticated', 'service_role']) r
    where has_table_privilege(r, 'public.workspace_sessions',
                             'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
  ) then
    raise exception 'Broad API role can access sessions';
  end if;
end;
$$;

set local role roebel_workspace_session;
set local request.jwt.claims = '{}';
do $$
begin
  begin
    insert into public.workspace_sessions (id, sub, access_token, expires_at)
      values ('workspace-rehearsal', 'synthetic-test-subject', 'synthetic-token', now());
    raise exception 'Missing session claims unexpectedly allowed a write';
  exception when insufficient_privilege then null;
  end;
end;
$$;

set local request.jwt.claims = '{"iss":"roebel-town-workspace-staging","aud":"another-service"}';
do $$
begin
  begin
    insert into public.workspace_sessions (id, sub, access_token, expires_at)
      values ('workspace-rehearsal', 'synthetic-test-subject', 'synthetic-token', now());
    raise exception 'Wrong audience unexpectedly allowed a write';
  exception when insufficient_privilege then null;
  end;
end;
$$;

set local request.jwt.claims = '{"iss":"roebel-town-workspace-staging","aud":"roebel-workspace-session-store"}';
insert into public.workspace_sessions (id, sub, access_token, expires_at)
  values ('workspace-rehearsal', 'synthetic-test-subject', 'synthetic-token', now() + interval '1 hour');
update public.workspace_sessions set groups = array['synthetic-test'], access_token = 'synthetic-refreshed'
  where id = 'workspace-rehearsal';
do $$
begin
  if not exists (select 1 from public.workspace_sessions
                 where id = 'workspace-rehearsal' and groups = array['synthetic-test']
                   and access_token = 'synthetic-refreshed') then
    raise exception 'Session create/read/update did not preserve the expected value';
  end if;
end;
$$;
delete from public.workspace_sessions where id = 'workspace-rehearsal';
do $$
begin
  if exists (select 1 from public.workspace_sessions where id = 'workspace-rehearsal') then
    raise exception 'Session logout did not delete the session';
  end if;
end;
$$;
reset role;
select json_build_object('sessionCrudPassed', true, 'missingClaimsDenied', true,
                         'wrongAudienceDenied', true, 'broadApiRolesDenied', true,
                         'otherPublicTablesDenied', true);
rollback;
