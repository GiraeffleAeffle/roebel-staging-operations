-- Additive state for the independent, synthetic-only staging issuer.
-- Run once with ON_ERROR_STOP=1; an existing table/role is an error.
begin;
set local lock_timeout = '3s';
set local statement_timeout = '30s';
do $$
begin
  if current_database() <> 'postgres' or current_user <> 'supabase_admin'
     or not exists (select 1 from public.app_settings
                    where key = 'roebel_env' and value = 'staging') then
    raise exception 'Identity migration requires the staging database owner';
  end if;
end;
$$;

create role roebel_staging_identity nologin noinherit nosuperuser nocreatedb
  nocreaterole noreplication nobypassrls;
create table public.oidc_payloads (
  id text not null,
  type text not null,
  payload jsonb not null,
  grant_id text,
  user_code text,
  uid text,
  expires_at timestamptz,
  primary key (type, id)
);
create index oidc_payloads_uid_idx on public.oidc_payloads (uid);
create index oidc_payloads_user_code_idx on public.oidc_payloads (user_code);
create index oidc_payloads_grant_id_idx on public.oidc_payloads (grant_id);
revoke all on public.oidc_payloads from public, anon, authenticated, service_role;
alter table public.oidc_payloads enable row level security;
alter table public.oidc_payloads force row level security;
grant usage on schema public to roebel_staging_identity;
grant select, insert, update, delete on public.oidc_payloads to roebel_staging_identity;
create policy staging_identity_server on public.oidc_payloads
  for all to roebel_staging_identity
  using (
    current_setting('request.jwt.claims', true)::jsonb ->> 'iss' = 'roebel-id-staging'
    and current_setting('request.jwt.claims', true)::jsonb ->> 'aud' = 'roebel-id-state-store'
  )
  with check (
    current_setting('request.jwt.claims', true)::jsonb ->> 'iss' = 'roebel-id-staging'
    and current_setting('request.jwt.claims', true)::jsonb ->> 'aud' = 'roebel-id-state-store'
  );
grant roebel_staging_identity to authenticator;
notify pgrst, 'reload schema';
commit;
