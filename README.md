# Supabase Team Knowledge Base

A pattern for the internal knowledge base almost every small organisation
eventually needs: **everyone in the company can read it, only two named people
can change it, and it keeps working when the wifi does not.**

That requirement sounds trivial and is not. Supabase gives you authentication
and row level security, but "everyone reads, these two write" does not fall out
of either one on its own, and the offline-first behaviour that makes the app
usable on a tablet creates a specific family of sync bugs that are easy to ship
and hard to notice.

This repo is the schema, the sanitiser, and the sync layer, with the reasoning
written down next to the code. It is derived from a system running daily in a
27-person clinic, rebuilt generically with no client content.

```
supabase/schema.sql     tables, RLS, revisions, auth gate, markup guard
app/js/sanitize.js      allowlist sanitiser (the real security boundary)
app/js/sync.js          offline-first cache and refresh, with the race fixes
tests/                  21 tests, mostly regressions from real bugs
docs/SETUP.md           console steps that cannot be done in SQL
```

## The four problems it solves

### 1. Read for everyone, write for two people

Domain membership gets you `select`. Presence in an `editors` table gets you
`update`. Keeping those separate is the whole design.

```sql
create policy read_pages on public.pages for select to authenticated
  using (public.is_member());

create policy write_pages_upd on public.pages for update to authenticated
  using (public.is_member() and public.is_editor())
  with check (public.is_member() and public.is_editor());
```

`is_editor()` has to be `security definer`. A plain function reading the
`editors` table would itself be filtered by that table's own RLS and would
always return false, so the write policies would silently deny everyone. That
is a genuinely confusing failure to debug from the client side, where all you
see is a save that does nothing.

A user can read their **own** editor row and no one else's, which is what lets
the UI show or hide the Edit button without leaking the allowlist.

### 2. Strangers cannot even sign in

RLS stops an outsider reading rows, but without a gate at the door, any Google
account can still complete OAuth and create a user. A `before_user_created`
hook rejects non-domain addresses with a message a human can act on, rather
than letting them in to an empty app.

### 3. Untrusted HTML, guarded twice

The database trigger is a **denylist**, and denylists leak. The load-bearing
control is `sanitize()`, an allowlist built on `DOMParser`, which runs on every
render and therefore also covers content that arrived from the offline cache or
from a REST write made before the trigger existed.

Both layers exist because they fail differently. Four things the SQL guard must
not get wrong, each of which is a bug that actually shipped:

- **Postgres regex uses `\y` for a word boundary.** `\b` is a literal backspace
  and silently never matches. A guard written with `\b` looks right, passes
  review, and blocks nothing.
- **The event-handler check must stay inside a tag.** Unanchored,
  `\son[a-z]+\s*=` matches ordinary prose. Real content lines like
  `Plan only = referral required` were being refused as attacks.
- **The attribute separator class must be `[\s/]`, not `\s`.** HTML accepts `/`
  between attributes, so `<img/src=x/onerror=...>` contains no whitespace at
  all and slips past anything checking only for spaces.
- **Guard every field that reaches the DOM.** Checking `body_html` alone was
  correct exactly until the editor could also write `title` and `summary`.

The sanitiser **unwraps** unknown tags rather than deleting them. Deleting a
stray `<font>` or `<section>` silently eats the paragraphs inside it, which
turns a formatting nuisance into data loss the author discovers much later.
`<script>` and `<style>` are the exception, since their contents are code.

### 4. Offline-first sync, without eating anyone's work

Rendering from cache and refreshing in the background is what makes the app
usable on bad wifi. It also causes every bug in `sync.js`, all found in real
use rather than in review:

- **The restore/refresh race.** Cache restore and network refresh run at once
  and whichever lands last wins, so a slow connection replaces the view under
  someone mid-scroll and a fast one reverts fresh data to stale. Fixed with a
  generation counter, not a timer.
- **The open-editor guard.** A background refresh landing mid-edit destroys
  unsaved work. Critically, a `force` flag must **not** be able to skip this
  check. An earlier version let it, and the takeover path quietly ate edits.
- **The spurious toast.** Notifying on every successful refresh means saving a
  page shows you "Updated with the latest changes" about your own edit one
  second later. Users read that as someone overwriting them. Only announce a
  real difference.
- **`TOKEN_REFRESHED`.** Supabase emits it roughly hourly. Treating every auth
  event as a sign-in re-renders the page, so a tablet left open all day resets
  itself at random with no user action.

## Also included

**Revision history.** A `before update` trigger snapshots the old row, so a
revision is what the page looked like *before* the change. `page_id` carries no
foreign key on purpose: history should outlive the page it describes. Growth is
bounded to the newest 50 per page. There is deliberately no write policy on the
revisions table, so history is written only by the trigger and no client can
forge or rewrite it.

**A re-runnable schema.** Every policy and trigger is dropped before creation,
so re-running the file is the intended way to apply a change. The SQL editor
runs a paste as one transaction, which means a statement that raises halfway
through aborts everything after it. The email-normalisation backfill therefore
carries two guard clauses against a `23505` collision, because a schema deploy
that half-applies and reports success is the worst available outcome.

**A keep-alive table.** Supabase pauses a free project after a week of
inactivity, and a paused project means the team opens the app to an error. One
row, pinged daily by any scheduler, prevents it. Readable by `anon` so the
pinger needs no credentials.

## Setup

```bash
npm install
npm test
```

Then:

1. Create a Supabase project.
2. Replace `example.com` in `supabase/schema.sql` with your domain (two places:
   `is_member()` and `before_user_created()`).
3. Paste the file into the SQL editor and run it.
4. Follow `docs/SETUP.md` for the console steps that cannot be done in SQL:
   the Google provider, the auth hook, and redirect URLs.
5. Uncomment and edit the editor seed at the bottom of the schema.

The SQL editor shows a red "destructive operations" banner on this file. That
is a keyword scan, not an analysis: it is reacting to the `drop ... if exists`
statements that make the file re-runnable and to a `delete` inside the revision
pruning function. Nothing in it can reach your content.

## License

MIT.
