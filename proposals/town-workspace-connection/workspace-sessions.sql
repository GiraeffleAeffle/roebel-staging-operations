-- Additive staging session storage. Apply once with psql ON_ERROR_STOP=1.
-- Existing session tables or roles are an error, never implicitly adopted.
begin;
set local lock_timeout = '3s';
set local statement_timeout = '30s';

do $$
begin
  if current_database() <> 'postgres' or current_user <> 'supabase_admin'
     or not exists (select 1 from public.app_settings
                    where key = 'roebel_env' and value = 'staging') then
    raise exception 'Town Workspace session migration requires the staging database owner';
  end if;
end;
$$;

create role roebel_workspace_session nologin noinherit nosuperuser nocreatedb
  nocreaterole noreplication nobypassrls;

create table public.workspace_sessions (
  id text primary key,
  sub text not null,
  groups text[] not null default '{}',
  access_token text not null,
  refresh_token text,
  expires_at timestamptz not null,
  created_at timestamptz not null default now()
);
create index workspace_sessions_sub_idx on public.workspace_sessions (sub);

-- The staging Supabase image grants new tables to these roles by default.
-- Remove only this table's inherited grants; leave all database defaults alone.
revoke all on public.workspace_sessions from public, anon, authenticated, service_role;
alter table public.workspace_sessions enable row level security;
alter table public.workspace_sessions force row level security;

grant usage on schema public to roebel_workspace_session;
grant select, insert, update, delete on public.workspace_sessions to roebel_workspace_session;
create policy workspace_session_server on public.workspace_sessions
  for all to roebel_workspace_session
  using (
    current_setting('request.jwt.claims', true)::jsonb ->> 'iss' = 'roebel-town-workspace-staging'
    and current_setting('request.jwt.claims', true)::jsonb ->> 'aud' = 'roebel-workspace-session-store'
  )
  with check (
    current_setting('request.jwt.claims', true)::jsonb ->> 'iss' = 'roebel-town-workspace-staging'
    and current_setting('request.jwt.claims', true)::jsonb ->> 'aud' = 'roebel-workspace-session-store'
  );
grant roebel_workspace_session to authenticator;

-- Delivered only if the entire transaction commits.
notify pgrst, 'reload schema';
commit;
