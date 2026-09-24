-- =====================================================================
-- Team Knowledge Base: schema, auth gate, revisions, and RLS.
--
-- Paste into the Supabase SQL editor and run. The whole file is
-- RE-RUNNABLE: every trigger and policy is dropped before it is created,
-- and every table uses `create table if not exists`. Re-running it is the
-- intended way to apply a change, so it must never half-apply.
--
-- The SQL editor runs a paste as ONE transaction. That single fact drives
-- several defensive choices below, because a statement that raises halfway
-- through aborts everything after it, including policies. A schema deploy
-- that half-works and reports success is the worst available outcome.
--
-- Replace ALLOWED_EMAIL_DOMAIN below with your own domain before running.
-- =====================================================================

-- ---------------------------------------------------------------------
-- 0. Identity helpers
--
-- Every function in this file pins `set search_path`. It matters most on
-- the security-definer ones and on the auth hook (executed by
-- supabase_auth_admin), but Supabase's linter flags
-- function_search_path_mutable on all of them, so they are all pinned
-- rather than leaving a half-clean report that nobody reads. The bodies
-- use built-ins and schema-qualified names only, so pinning changes no
-- behaviour.
-- ---------------------------------------------------------------------

create or replace function public.jwt_email() returns text
language sql stable set search_path = public as $$
  select lower(coalesce(
    nullif(current_setting('request.jwt.claims', true), '')::jsonb ->> 'email', ''))
$$;

-- Everyone in the organisation can READ. Change the domain here.
create or replace function public.is_member() returns boolean
language sql stable set search_path = public as $$
  select public.jwt_email() like '%@example.com'
$$;

-- ---------------------------------------------------------------------
-- 1. Content tables
-- ---------------------------------------------------------------------

create table if not exists public.sections (
  id         text primary key,
  title      text not null,
  position   int  not null default 0,
  updated_at timestamptz not null default now()
);

create table if not exists public.pages (
  id         text primary key,
  section_id text references public.sections(id) on delete set null,
  title      text not null,
  summary    text,
  body_html  text not null default '',
  position   int  not null default 0,
  updated_at timestamptz not null default now(),
  updated_by text
);

create table if not exists public.settings (
  key        text primary key,
  value      jsonb not null default '{}'::jsonb,
  updated_at timestamptz not null default now()
);

-- ---------------------------------------------------------------------
-- 2. Editors: the allowlist that separates read from write
--
-- Membership in the org gets you READ. Presence in this table gets you
-- WRITE. Keeping the two separate is the entire point: "everyone can see
-- it, two people can change it" is the common real-world requirement and
-- it does not fall out of Supabase auth on its own.
-- ---------------------------------------------------------------------

create table if not exists public.editors (
  email        text primary key,
  display_name text,
  note         text,
  added_at     timestamptz not null default now()
);

-- Emails are compared with `=`, so a mixed-case row silently never matches
-- and the person just cannot save, with no error that explains why.
create or replace function public.normalize_editor_email() returns trigger
language plpgsql set search_path = public as $$
begin
  new.email := lower(btrim(new.email));
  return new;
end $$;

drop trigger if exists editors_normalize on public.editors;
create trigger editors_normalize before insert or update on public.editors
for each row execute function public.normalize_editor_email();

-- Backfill any rows that predate the trigger.
--
-- The two guard clauses are what keep this file re-runnable. `email` is the
-- primary key, so an UPDATE that folds two addresses onto the same value
-- raises 23505 partway through and aborts the WHOLE file. There are two
-- distinct ways to collide and both need covering:
--   'Alex@' when 'alex@' already exists      -> caught by the `not exists`
--   'Alex@' and 'ALEX@', no lowercase row    -> caught by the `min()`, which
--                                               lets exactly one row per fold
--                                               group through
-- Any row left behind stays visibly mixed-case, which is the point: it gets
-- noticed and fixed by hand rather than aborting a deploy.
update public.editors e set email = lower(btrim(e.email))
where e.email <> lower(btrim(e.email))
  and not exists (select 1 from public.editors d where d.email = lower(btrim(e.email)))
  and e.email = (select min(d.email) from public.editors d
                 where lower(btrim(d.email)) = lower(btrim(e.email)));

-- SECURITY DEFINER on purpose: the write policies on pages/settings need to
-- read `editors`, and a plain function would itself be filtered by editors'
-- own RLS, so it would always return false. Execute is revoked from public
-- and granted only to authenticated.
create or replace function public.is_editor() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.editors e where e.email = public.jwt_email())
$$;

revoke execute on function public.is_editor() from public;
grant  execute on function public.is_editor() to authenticated;

-- ---------------------------------------------------------------------
-- 3. Revision history
--
-- page_id carries NO foreign key on purpose: history should outlive the
-- deletion of the page it describes.
-- ---------------------------------------------------------------------

create table if not exists public.page_revisions (
  id         bigint generated always as identity primary key,
  page_id    text not null,
  title      text,
  summary    text,
  body_html  text,
  saved_at   timestamptz not null default now(),
  saved_by   text
);

create index if not exists page_revisions_page_idx
  on public.page_revisions (page_id, saved_at desc);

-- Snapshot the OLD row before an update, so a revision is what the page
-- looked like before the change, not after.
create or replace function public.snapshot_page() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if old.title is distinct from new.title
     or old.summary is distinct from new.summary
     or old.body_html is distinct from new.body_html then
    insert into public.page_revisions (page_id, title, summary, body_html, saved_by)
    values (old.id, old.title, old.summary, old.body_html, old.updated_by);
  end if;
  return new;
end $$;

drop trigger if exists pages_snapshot on public.pages;
create trigger pages_snapshot before update on public.pages
for each row execute function public.snapshot_page();

-- Bound the growth: keep the newest 50 revisions per page.
create or replace function public.prune_page_revisions() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  delete from public.page_revisions r
   where r.page_id = new.page_id
     and r.id not in (
       select id from public.page_revisions
        where page_id = new.page_id
        order by saved_at desc
        limit 50);
  return null;
end $$;

drop trigger if exists page_revisions_prune on public.page_revisions;
create trigger page_revisions_prune after insert on public.page_revisions
for each row execute function public.prune_page_revisions();

-- ---------------------------------------------------------------------
-- 4. Markup guard (defence in depth, NOT the boundary)
--
-- READ THIS BEFORE EDITING. This is a denylist, and denylists leak. The
-- load-bearing control is client-side sanitisation on every render (see
-- app/js/sanitize.js), which also covers content that reached the browser
-- from a local cache or from a REST write made before this trigger existed.
-- Do not treat this function as the security boundary.
--
-- Three things this must not get wrong, each of which is a real bug that
-- shipped in an earlier version:
--
--  1. Postgres regex uses \y for a word boundary. \b is a literal backspace
--     character and silently never matches. A guard written with \b looks
--     correct, passes review, and blocks nothing.
--
--  2. The event-handler check must stay INSIDE a tag ('<' then non-'>').
--     Unanchored, '\son[a-z]+\s*=' matches ordinary prose. Real content
--     lines like "Plan only = referral required" were refused as attacks.
--
--  3. The attribute separator class must be [\s/], not \s. HTML accepts '/'
--     between attributes, so <img/src=x/onerror=...> contains no whitespace
--     at all and slips past every version that only checked \s.
--
--  4. Guard every field that reaches the DOM, not just the body. Once the
--     editor can write title and summary, checking body_html alone leaves
--     two unguarded paths in.
-- ---------------------------------------------------------------------

create or replace function public.reject_dangerous_html() returns trigger
language plpgsql set search_path = public as $$
declare blob text := coalesce(new.body_html,'') || ' ' ||
                     coalesce(new.title,'')     || ' ' ||
                     coalesce(new.summary,'');
begin
  if blob ~* '<\s*(script|iframe|object|embed|form|link|meta|base|img|svg|style|video|audio|math|template|input|marquee)\y'
     or blob ~* 'javascript\s*:'
     or blob ~* '<[^>]*[\s/]on[a-z]+\s*=' then
    raise exception 'content contains disallowed markup';
  end if;

  -- Generous on purpose. These are backstops against a raw REST write, not
  -- the editor's own limits (which are far tighter and enforced in the UI).
  -- Set anywhere near the real maximums and a re-run of this file starts
  -- rejecting ordinary saves of pages that already exist.
  if length(coalesce(new.body_html,'')) > 200000 then
    raise exception 'body_html too large';
  end if;
  if length(coalesce(new.title,'')) > 500 then
    raise exception 'title too large';
  end if;
  if length(coalesce(new.summary,'')) > 2000 then
    raise exception 'summary too large';
  end if;
  return new;
end $$;

drop trigger if exists pages_html_guard on public.pages;
create trigger pages_html_guard before insert or update on public.pages
for each row execute function public.reject_dangerous_html();

-- ---------------------------------------------------------------------
-- 5. Keep-alive
--
-- Supabase pauses a free project after a week of inactivity, and a paused
-- project means the team opens the app to an error. One tiny row that a
-- scheduled job reads daily is enough to keep it awake. Readable by anon so
-- the pinger needs no credentials.
-- ---------------------------------------------------------------------

create table if not exists public.heartbeat (
  id         int primary key default 1,
  pinged_at  timestamptz not null default now(),
  constraint heartbeat_singleton check (id = 1)
);

insert into public.heartbeat (id) values (1) on conflict (id) do nothing;

-- ---------------------------------------------------------------------
-- 6. Row level security
--
-- Read: any authenticated member of the domain.
-- Write: members who are ALSO in the editors table.
-- ---------------------------------------------------------------------

alter table public.sections       enable row level security;
alter table public.pages          enable row level security;
alter table public.settings       enable row level security;
alter table public.editors        enable row level security;
alter table public.page_revisions enable row level security;
alter table public.heartbeat      enable row level security;

-- Data API access, granted explicitly. Supabase stopped granting it automatically for new
-- tables in public (new projects already; existing ones from 2026-10-30). Without these lines
-- a fresh project gets every table and then "permission denied" from the app. This is exactly
-- what Supabase used to grant; the row level security above still decides who sees what.
grant usage on schema public to anon, authenticated, service_role;
grant all on all tables in schema public to anon, authenticated, service_role;
grant all on all sequences in schema public to anon, authenticated, service_role;

drop policy if exists read_sections on public.sections;
create policy read_sections on public.sections for select to authenticated using (public.is_member());

drop policy if exists read_pages on public.pages;
create policy read_pages on public.pages for select to authenticated using (public.is_member());

drop policy if exists read_settings on public.settings;
create policy read_settings on public.settings for select to authenticated using (public.is_member());

drop policy if exists write_pages_upd on public.pages;
create policy write_pages_upd on public.pages for update to authenticated
  using (public.is_member() and public.is_editor())
  with check (public.is_member() and public.is_editor());

drop policy if exists write_pages_ins on public.pages;
create policy write_pages_ins on public.pages for insert to authenticated
  with check (public.is_member() and public.is_editor());

drop policy if exists write_sections_upd on public.sections;
create policy write_sections_upd on public.sections for update to authenticated
  using (public.is_member() and public.is_editor())
  with check (public.is_member() and public.is_editor());

drop policy if exists write_settings_upd on public.settings;
create policy write_settings_upd on public.settings for update to authenticated
  using (public.is_member() and public.is_editor())
  with check (public.is_member() and public.is_editor());

drop policy if exists write_settings_ins on public.settings;
create policy write_settings_ins on public.settings for insert to authenticated
  with check (public.is_member() and public.is_editor());

-- A user may see their OWN editor row (so the app can show or hide the Edit
-- button) but not enumerate the whole allowlist.
drop policy if exists read_own_editor on public.editors;
create policy read_own_editor on public.editors for select to authenticated
  using (email = public.jwt_email());

drop policy if exists read_page_revs on public.page_revisions;
create policy read_page_revs on public.page_revisions for select to authenticated
  using (public.is_member());

drop policy if exists read_heartbeat on public.heartbeat;
create policy read_heartbeat on public.heartbeat for select to anon, authenticated using (true);

-- NOTE: there is deliberately no INSERT/UPDATE/DELETE policy on
-- page_revisions. History is written only by the SECURITY DEFINER trigger,
-- so no client can forge or rewrite it.

-- ---------------------------------------------------------------------
-- 7. Domain gate at sign-up
--
-- RLS stops a stranger reading data, but without this ANY Google account
-- can still complete sign-in and create an auth user. This hook rejects
-- them at the door with a message they can understand.
-- ---------------------------------------------------------------------

create or replace function public.before_user_created(event jsonb) returns jsonb
language plpgsql stable set search_path = public as $$
declare em text := lower(coalesce(event -> 'user' ->> 'email', ''));
begin
  if em not like '%@example.com' then
    return jsonb_build_object('error', jsonb_build_object(
      'http_code', 403,
      'message', 'Only company accounts can sign in.'));
  end if;
  return '{}'::jsonb;
end $$;

grant execute on function public.before_user_created(jsonb) to supabase_auth_admin;
revoke execute on function public.before_user_created(jsonb) from authenticated, anon, public;

-- Register it under Authentication > Hooks > Before User Created.
-- See docs/SETUP.md.

-- ---------------------------------------------------------------------
-- 8. Seed your editors (edit, then uncomment)
-- ---------------------------------------------------------------------

-- insert into public.editors (email, display_name, note) values
--   ('manager@example.com', 'Office Manager', 'seed'),
--   ('lead@example.com',    'Team Lead',      'seed')
-- on conflict (email) do nothing;
