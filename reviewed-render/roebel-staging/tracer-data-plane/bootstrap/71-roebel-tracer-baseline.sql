-- Röbel staging tracer overlay baseline v1.
--
-- This is deliberately not a full Supabase schema clone. It provides only the
-- ordinary feed/read compatibility surface needed to run the real participant
-- tracer while the collaborator-owned staging database is unavailable.
-- It creates no CivicCase, decision, voting, treasury, or municipal-authority
-- record. The public feed remains a mixed set of ordinary posts.
--
-- Apply this baseline first, provision the two Vault values out of band, then
-- apply these reviewed files byte-for-byte in this exact order:
--   1. 20260825_staging_participant_gateway.sql
--      sha256 ad050047a71bf2cc82361c16169627dc0a0a66a7982db804b1612624f0f97eab
--   2. 20260825_staging_participant_topic_tracer.sql
--      sha256 739cbcb189e3b12913ebf28dae74c931eab3cfae514e476bea4071092aef242e

begin;

create schema if not exists extensions;
create extension if not exists pgcrypto with schema extensions;
create schema if not exists vault;
create extension if not exists supabase_vault with schema vault cascade;

do $$
begin
  if not exists (select 1 from pg_catalog.pg_roles where rolname = 'anon') then
    create role anon nologin noinherit;
  end if;
  if not exists (
    select 1 from pg_catalog.pg_roles where rolname = 'authenticated'
  ) then
    create role authenticated nologin noinherit;
  end if;
  if not exists (
    select 1 from pg_catalog.pg_roles where rolname = 'service_role'
  ) then
    create role service_role nologin noinherit bypassrls;
  end if;
  if not exists (
    select 1 from pg_catalog.pg_roles where rolname = 'authenticator'
  ) then
    create role authenticator nologin noinherit;
  end if;
end;
$$;

grant anon, authenticated to authenticator;
revoke create on schema public from public;

create table public.app_settings (
  key text primary key,
  value text not null,
  updated_at timestamptz not null default now()
);

insert into public.app_settings (key, value)
values
  ('roebel_env', 'staging'),
  ('staging_banner_text', 'STAGING — Testumgebung, keine echten Daten')
on conflict (key) do update
  set value = excluded.value,
      updated_at = now();

create table public.users (
  id uuid primary key default extensions.gen_random_uuid(),
  wallet_address text not null unique,
  tier text not null default 'guest'
    check (tier in ('guest', 'tourist', 'citizen')),
  is_verified_citizen boolean not null default false,
  verification_status text not null default 'pending'
    check (verification_status in ('pending', 'approved', 'rejected')),
  username text unique,
  display_name text,
  profile_picture_url text,
  neighborhood text,
  bio text,
  is_extern boolean not null default false,
  location_verified_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table public.account_owners (
  account_id uuid not null,
  wallet_address text not null
    references public.users(wallet_address) on delete cascade,
  role text not null default 'owner',
  joined_at timestamptz not null default now(),
  primary key (account_id, wallet_address)
);

create table public.posts (
  id uuid primary key default extensions.gen_random_uuid(),
  wallet_address text not null
    references public.users(wallet_address) on delete cascade,
  account_id uuid,
  content text not null check (char_length(content) between 1 and 250),
  category text not null default 'generell',
  feed_type text not null default 'main'
    check (feed_type in ('main', 'rathaus', 'app')),
  post_type text not null default 'user',
  status text not null default 'published'
    check (status in ('published', 'deleted', 'flagged')),
  media_urls text[] not null default '{}'::text[],
  video_url text,
  linked_event_id uuid,
  linked_experience_id uuid,
  likes_count integer not null default 0 check (likes_count >= 0),
  comments_count integer not null default 0 check (comments_count >= 0),
  views_count integer not null default 0 check (views_count >= 0),
  is_pinned boolean not null default false,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index posts_feed_created_idx
  on public.posts (feed_type, status, created_at desc);
create index posts_wallet_idx on public.posts (wallet_address);

create table public.post_comments (
  id uuid primary key default extensions.gen_random_uuid(),
  post_id uuid not null references public.posts(id) on delete cascade,
  wallet_address text not null
    references public.users(wallet_address) on delete cascade,
  account_id uuid,
  content text not null check (char_length(content) between 1 and 500),
  media_urls text[] not null default '{}'::text[],
  video_url text,
  status text not null default 'published'
    check (status in ('published', 'deleted')),
  parent_comment_id uuid references public.post_comments(id) on delete cascade,
  likes_count integer not null default 0 check (likes_count >= 0),
  reply_count integer not null default 0 check (reply_count >= 0),
  created_at timestamptz not null default now()
);

create index post_comments_post_created_idx
  on public.post_comments (post_id, created_at);

create table public.post_likes (
  id uuid primary key default extensions.gen_random_uuid(),
  post_id uuid not null references public.posts(id) on delete cascade,
  wallet_address text not null
    references public.users(wallet_address) on delete cascade,
  created_at timestamptz not null default now(),
  unique (post_id, wallet_address)
);

create table public.post_reports (
  id uuid primary key default extensions.gen_random_uuid(),
  post_id uuid not null references public.posts(id) on delete cascade,
  reporter_wallet_address text not null,
  reason text,
  created_at timestamptz not null default now(),
  unique (post_id, reporter_wallet_address)
);

create table public.post_links (
  id uuid primary key default extensions.gen_random_uuid(),
  post_id uuid not null references public.posts(id) on delete cascade,
  url text not null,
  og_title text,
  og_description text,
  og_image text,
  og_site_name text,
  fetched_at timestamptz not null default now()
);

create table public.post_polls (
  id uuid primary key default extensions.gen_random_uuid(),
  post_id uuid not null unique references public.posts(id) on delete cascade,
  poll_type text not null check (poll_type in ('single', 'multi')),
  options text[] not null,
  expires_at timestamptz not null,
  created_at timestamptz not null default now()
);

create table public.poll_votes (
  id uuid primary key default extensions.gen_random_uuid(),
  poll_id uuid not null references public.post_polls(id) on delete cascade,
  wallet_address text not null,
  selected_options integer[] not null,
  created_at timestamptz not null default now(),
  unique (poll_id, wallet_address)
);

-- Mecky replies are read from the signed public conversation API during the
-- tracer. This empty table exists only so the optional feed projection query
-- remains a successful, neutral read.
create table public.public_mecky_replies (
  event_id text primary key check (event_id ~ '^[0-9a-f]{64}$'),
  request_event_id text not null unique
    check (request_event_id ~ '^[0-9a-f]{64}$'),
  source_post_id text not null check (
    source_post_id ~ '^([0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}|[0-9a-f]{64})$'
  ),
  source_comment_id text check (
    source_comment_id is null or source_comment_id ~ '^([0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}|[0-9a-f]{64})$'
  ),
  agent_pubkey text not null check (agent_pubkey ~ '^[0-9a-f]{64}$'),
  content text not null check (length(btrim(content)) between 1 and 2000),
  evidence_refs jsonb not null default '[]'::jsonb
    check (jsonb_typeof(evidence_refs) = 'array'),
  event_created_at timestamptz not null,
  projected_at timestamptz not null default now(),
  authority_binding text not null default 'none'
    check (authority_binding = 'none'),
  signed_event jsonb not null check (jsonb_typeof(signed_event) = 'object')
);

create index public_mecky_replies_post_time_idx
  on public.public_mecky_replies (source_post_id, event_created_at, event_id);
create index public_mecky_replies_comment_time_idx
  on public.public_mecky_replies (source_comment_id, event_created_at, event_id)
  where source_comment_id is not null;

create function public.post_comment_counts_sync()
returns trigger
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
begin
  if tg_op = 'INSERT' then
    if new.parent_comment_id is null then
      update public.posts
         set comments_count = comments_count + 1,
             updated_at = now()
       where id = new.post_id;
    else
      update public.post_comments
         set reply_count = reply_count + 1
       where id = new.parent_comment_id;
    end if;
  elsif tg_op = 'DELETE' then
    if old.parent_comment_id is null then
      update public.posts
         set comments_count = greatest(comments_count - 1, 0),
             updated_at = now()
       where id = old.post_id;
    else
      update public.post_comments
         set reply_count = greatest(reply_count - 1, 0)
       where id = old.parent_comment_id;
    end if;
  end if;
  return null;
end;
$$;

create trigger trg_post_comment_counts
after insert or delete on public.post_comments
for each row
execute function public.post_comment_counts_sync();

-- The reviewed participant migration replaces this exact compatibility seam
-- with its secret-bound reservation gate. It exists here only as the captured
-- rollback predecessor required by that migration.
create function public.enforce_posting_rules()
returns trigger
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
begin
  if new.post_type is distinct from 'user' or new.account_id is not null then
    return new;
  end if;
  if exists (
    select 1 from public.users
     where lower(wallet_address) = lower(new.wallet_address)
       and (is_verified_citizen or tier = 'citizen')
  ) then
    return new;
  end if;
  raise exception 'LEGACY_POSTING_GATE_DISABLED_FOR_UNVERIFIED_USER'
    using errcode = 'P0001';
end;
$$;

create function public.delete_owned_post(p_post_id uuid, p_wallet text)
returns void
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
begin
  raise exception 'LEGACY_WRITE_DISABLED' using errcode = 'P0001';
end;
$$;

create function public.delete_owned_post_comment(
  p_comment_id uuid,
  p_wallet text
)
returns void
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
begin
  raise exception 'LEGACY_WRITE_DISABLED' using errcode = 'P0001';
end;
$$;

create function public.delete_owned_experience(
  p_experience_id uuid,
  p_wallet text
)
returns void
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
begin
  raise exception 'LEGACY_WRITE_DISABLED' using errcode = 'P0001';
end;
$$;

create function public.pin_own_post(
  p_post_id uuid,
  p_wallet text,
  p_is_pinned boolean
)
returns timestamptz
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
begin
  raise exception 'LEGACY_WRITE_DISABLED' using errcode = 'P0001';
end;
$$;

revoke all on function public.post_comment_counts_sync()
  from public, anon, authenticated;
revoke all on function public.enforce_posting_rules()
  from public, anon, authenticated;
revoke all on function public.delete_owned_post(uuid, text)
  from public, anon, authenticated;
revoke all on function public.delete_owned_post_comment(uuid, text)
  from public, anon, authenticated;
revoke all on function public.delete_owned_experience(uuid, text)
  from public, anon, authenticated;
revoke all on function public.pin_own_post(uuid, text, boolean)
  from public, anon, authenticated;

alter table public.app_settings enable row level security;
alter table public.users enable row level security;
alter table public.account_owners enable row level security;
alter table public.posts enable row level security;
alter table public.post_comments enable row level security;
alter table public.post_likes enable row level security;
alter table public.post_reports enable row level security;
alter table public.post_links enable row level security;
alter table public.post_polls enable row level security;
alter table public.poll_votes enable row level security;
alter table public.public_mecky_replies enable row level security;

create policy app_settings_public_read on public.app_settings
  for select using (true);
create policy users_public_read on public.users
  for select using (true);
create policy account_owners_public_read on public.account_owners
  for select using (true);
create policy posts_public_read on public.posts
  for select using (status = 'published');
create policy post_comments_public_read on public.post_comments
  for select using (status = 'published');
create policy post_likes_public_read on public.post_likes
  for select using (true);
create policy post_reports_public_read on public.post_reports
  for select using (true);
create policy post_links_public_read on public.post_links
  for select using (true);
create policy post_polls_public_read on public.post_polls
  for select using (true);
create policy poll_votes_public_read on public.poll_votes
  for select using (true);
create policy public_mecky_replies_public_read on public.public_mecky_replies
  for select using (authority_binding = 'none');

grant usage on schema public to anon, authenticated, service_role;
grant select on table
  public.app_settings,
  public.users,
  public.account_owners,
  public.posts,
  public.post_comments,
  public.post_likes,
  public.post_reports,
  public.post_links,
  public.post_polls,
  public.poll_votes,
  public.public_mecky_replies
to anon, authenticated;

grant all privileges on all tables in schema public to service_role;
grant all privileges on all sequences in schema public to service_role;

-- The checksum-pinned participant migration snapshots explicit column ACLs
-- before closing browser writes. Fresh PostgreSQL columns have a NULL attacl;
-- PostgreSQL 15 rejects the migration's empty-array aclexplode fallback because
-- it is zero-dimensional. Materialize a redundant server-only SELECT ACL on
-- every inspected column so the snapshot sees a valid one-dimensional ACL.
-- service_role already has table-level SELECT, so this neither widens browser
-- access nor changes the effective server privilege.
do $$
declare
  v_table text;
  v_columns text;
begin
  foreach v_table in array array[
    'posts', 'post_comments', 'post_likes', 'app_settings'
  ] loop
    select string_agg(pg_catalog.format('%I', a.attname), ', ' order by a.attnum)
      into v_columns
      from pg_catalog.pg_attribute a
     where a.attrelid = pg_catalog.to_regclass(
       pg_catalog.format('public.%I', v_table)
     )
       and a.attnum > 0
       and not a.attisdropped;

    execute pg_catalog.format(
      'grant select (%s) on table public.%I to service_role',
      v_columns,
      v_table
    );
  end loop;
end;
$$;

insert into public.users (
  id,
  wallet_address,
  username,
  display_name,
  bio,
  neighborhood,
  tier,
  is_verified_citizen,
  verification_status,
  created_at
)
values
  (
    'dada0001-0000-4000-8000-000000000001',
    '0xda7a000000000000000000000000000000000001',
    'anke_b',
    'Anke Böttcher',
    'Seit vielen Jahren in Röbel und gern am Wochenmarkt.',
    'Altstadt',
    'citizen',
    true,
    'approved',
    now() - interval '30 days'
  ),
  (
    'dada0002-0000-4000-8000-000000000002',
    '0xda7a000000000000000000000000000000000002',
    'jonas_m',
    'Jonas Malchin',
    'Angler und Segler auf der Müritz.',
    'Hafen',
    'tourist',
    false,
    'pending',
    now() - interval '20 days'
  ),
  (
    'dada0003-0000-4000-8000-000000000003',
    '0xda7a000000000000000000000000000000000003',
    'kulturverein',
    'Kulturverein Röbel',
    'Wir organisieren Konzerte und Lesungen.',
    'Marktplatz',
    'citizen',
    true,
    'approved',
    now() - interval '60 days'
  ),
  (
    'dada0004-0000-4000-8000-000000000004',
    '0xda7a000000000000000000000000000000000004',
    'grit_w',
    'Grit Wendt',
    'Bäckerei-Fan und Hobbyfotografin.',
    'Neustadt',
    'tourist',
    false,
    'pending',
    now() - interval '14 days'
  )
on conflict (wallet_address) do nothing;

insert into public.posts (
  id,
  wallet_address,
  content,
  feed_type,
  post_type,
  status,
  likes_count,
  comments_count,
  views_count,
  created_at
)
values
  (
    'b0570001-0000-4000-8000-000000000001',
    '0xda7a000000000000000000000000000000000001',
    'Wunderschöner Sonnenaufgang heute früh über der Müritz. 🌅',
    'main', 'user', 'published', 18, 0, 312, now() - interval '2 hours'
  ),
  (
    'b0570002-0000-4000-8000-000000000002',
    '0xda7a000000000000000000000000000000000002',
    'Frischer Fang am frühen Morgen. Wer tauscht Tipps fürs Angeln? 🎣',
    'main', 'user', 'published', 27, 0, 540, now() - interval '7 hours'
  ),
  (
    'b0570003-0000-4000-8000-000000000003',
    '0xda7a000000000000000000000000000000000003',
    'Am Samstag ist Sommerkonzert in St. Marien. Eintritt frei. 🎶',
    'main', 'user', 'published', 41, 0, 880, now() - interval '1 day'
  ),
  (
    'b0570004-0000-4000-8000-000000000004',
    '0xda7a000000000000000000000000000000000001',
    'Der neue Radweg Richtung Bollewick ist fertig. Eine schöne Runde! 🚲',
    'main', 'user', 'published', 33, 0, 610, now() - interval '2 days'
  ),
  (
    'b0570005-0000-4000-8000-000000000005',
    '0xda7a000000000000000000000000000000000004',
    'Kleiner Gruß vom Markt – die Streuselschnecken sind wieder da. 😋',
    'main', 'user', 'published', 22, 0, 430, now() - interval '3 days'
  ),
  (
    'b0570006-0000-4000-8000-000000000006',
    '0xda7a000000000000000000000000000000000002',
    'Müritz-Sonnenuntergang gestern. Davon werde ich nie müde. ❤️',
    'main', 'user', 'published', 55, 0, 1220, now() - interval '5 days'
  )
on conflict (id) do nothing;

-- Install the captured compatibility gate only after the deterministic seed.
-- The real staging schema historically contains ordinary posts from tourist
-- identities, while new writes must still meet the reviewed migration's exact
-- trigger precondition.
create trigger enforce_posting_rules_trg
before insert on public.posts
for each row
execute function public.enforce_posting_rules();

-- The pinned Supabase PostgreSQL image grants EXECUTE on every future public
-- function created by supabase_admin to its four API/server roles. The pinned
-- topic-tracer migration intentionally accepts only its owner and the explicit
-- anon grant on each public RPC. Normalize only future public-function
-- defaults after this baseline has created its compatibility functions; the
-- participant migrations then materialize their reviewed ACLs themselves.
alter default privileges for role supabase_admin in schema public
  revoke all on functions from postgres, anon, authenticated, service_role;

commit;
