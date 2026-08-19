# Setup

The parts that cannot be done from `schema.sql`, in the order they need doing.

## 1. Project and schema

1. Create a Supabase project. The free tier is enough.
2. Open `supabase/schema.sql` and replace **`example.com`** with your domain.
   It appears twice, in `is_member()` and in `before_user_created()`. Missing
   the second one is the common mistake: reads are correctly locked down while
   anyone can still create an account.
3. Paste the whole file into the SQL editor and run it.

Expect a red **"destructive operations"** warning. It is a keyword scan
reacting to the `drop ... if exists` lines (each immediately re-created, which
is what makes the file re-runnable) and to a `delete` inside
`prune_page_revisions()`. There is no `drop table` and no `truncate`. Safe to
re-run.

## 2. Google sign-in

**Google Cloud console** → APIs & Services → Credentials → Create OAuth client
ID → Web application.

- Authorised redirect URI: `https://<project-ref>.supabase.co/auth/v1/callback`

**Supabase** → Authentication → Providers → Google. Paste the client ID and
secret, enable it.

**Supabase** → Authentication → Providers → Email. **Disable it.** Leaving it
on means someone can bypass the whole domain gate with an email and password.

## 3. The domain gate

**Supabase** → Authentication → Hooks → *Before User Created* → select
`public.before_user_created`.

Verify it: try signing in with a personal Gmail account. You should be refused
with the message from the function, and no row should appear in
Authentication → Users.

If your project does not offer that hook type, the schema contains a commented
trigger fallback on `auth.users`. It works, but produces an unfriendly 500 from
GoTrue that the client has to translate into readable copy.

## 4. Redirect URLs

**Supabase** → Authentication → URL Configuration. Add every origin the app is
served from, including `http://localhost:3000` for development.

**Gotcha worth knowing:** signing in on a local preview will bounce you to the
*deployed* site if its URL is the configured redirect. You then QA production
while believing you are testing your branch, conclude your changes did not
apply, and go hunting for a bug that does not exist. Verify local changes
without signing in, or add localhost here first.

## 5. Editors

Uncomment the seed block at the bottom of `schema.sql`, put in real addresses,
and run it. Confirm the exact spelling with the people involved: the address in
their Google account is not always the one you assume, and a typo presents as
"the Edit button never appears" with no error anywhere.

Emails are lowercased by a trigger, so case does not matter on insert.

## 6. Keep-alive

Point any daily scheduler at the heartbeat row so the free project never pauses.
A Vercel cron, a GitHub Action, or any uptime pinger works. The table is
readable by `anon`, so no credentials are needed:

```
GET https://<project-ref>.supabase.co/rest/v1/heartbeat?select=pinged_at
    apikey: <anon key>
```

## 7. Backups

**The free tier keeps no backups.** Whatever export you run and commit *is* the
backup. Put it on a monthly calendar entry, not in your memory.
