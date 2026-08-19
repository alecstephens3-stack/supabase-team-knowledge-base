/**
 * Offline-first sync between a local cache and Supabase.
 *
 * This is the part that looks trivial and is not. The app has to work on a
 * tablet with bad wifi, so it renders from a local cache first and refreshes
 * in the background. That single decision creates every bug below, and all of
 * them were found in real use rather than in review.
 */

const CACHE_KEY = "kb.cache.v1";

export class Sync {
  #client;
  #onChange;
  #state = "idle";      // idle | refreshing | editing
  #editorOpen = false;
  #pendingRefresh = null;

  constructor(client, onChange) {
    this.#client = client;
    this.#onChange = onChange;
  }

  readCache() {
    try {
      const raw = localStorage.getItem(CACHE_KEY);
      return raw ? JSON.parse(raw) : null;
    } catch {
      // A corrupt cache must never be fatal. Drop it and fetch fresh: the
      // alternative is an app that will not open until someone clears storage
      // by hand, which for a non-technical user means it is simply broken.
      localStorage.removeItem(CACHE_KEY);
      return null;
    }
  }

  writeCache(data) {
    try {
      localStorage.setItem(CACHE_KEY, JSON.stringify(data));
    } catch {
      // Quota exceeded. Not fatal: the app works from memory this session.
    }
  }

  /**
   * BUG 1 (restore/refresh race). On launch the app restores from cache and
   * simultaneously kicks off a network refresh. Whichever resolves LAST wins.
   * On a slow connection the refresh landed after the user had already
   * scrolled and started reading, replacing the view underneath them. On a
   * fast one the restore sometimes landed second and reverted fresh data to
   * stale.
   *
   * The fix is a generation counter, not a timer. Every refresh claims a
   * generation; a result that is not from the current generation is dropped.
   */
  #generation = 0;

  async refresh({ force = false } = {}) {
    // BUG 2 (the open-editor guard). A background refresh that lands while
    // someone is mid-edit destroys unsaved work. The guard must NOT be
    // bypassable by a `force` flag from a caller that does not know an editor
    // is open. An earlier version let `force` skip this check, and the
    // takeover path then quietly ate edits. force may only skip the
    // throttle, never this.
    if (this.#editorOpen) {
      this.#pendingRefresh = { queuedAt: Date.now() };
      return { skipped: "editor-open" };
    }

    if (this.#state === "refreshing" && !force) {
      return { skipped: "in-flight" };
    }

    const gen = ++this.#generation;
    this.#state = "refreshing";

    try {
      const { data, error } = await this.#client
        .from("pages")
        .select("id, section_id, title, summary, body_html, position, updated_at");

      if (error) throw error;

      // Stale generation: a newer refresh started while this one was in
      // flight. Discard rather than apply out of order.
      if (gen !== this.#generation) return { skipped: "superseded" };

      const cached = this.readCache();
      const changed = !cached || hasChanged(cached.pages, data);

      this.writeCache({ pages: data, fetchedAt: Date.now() });

      // BUG 3 (the spurious toast). This used to notify on every successful
      // refresh, so saving a page produced "Updated with the latest changes"
      // about your OWN edit, one second after you made it. Users read that as
      // someone else overwriting them. Only announce a genuine difference.
      if (changed) this.#onChange(data, { announce: true });
      else this.#onChange(data, { announce: false });

      return { ok: true, changed };
    } catch (err) {
      // Offline is an expected state, not an error worth shouting about. The
      // cached render stays on screen and we retry on the next trigger.
      return { ok: false, offline: true, error: err };
    } finally {
      if (gen === this.#generation) this.#state = "idle";
    }
  }

  openEditor() {
    this.#editorOpen = true;
  }

  /**
   * BUG 4 (TOKEN_REFRESHED). Supabase emits TOKEN_REFRESHED roughly hourly.
   * The auth listener treated every event as a sign-in and re-rendered, which
   * on a tablet left open all day meant the page reset itself at random
   * intervals with no user action. Handle the event types separately.
   */
  attachAuth(onSignIn, onSignOut) {
    return this.#client.auth.onAuthStateChange((event, session) => {
      switch (event) {
        case "SIGNED_IN":
        case "INITIAL_SESSION":
          if (session) onSignIn(session);
          break;
        case "SIGNED_OUT":
          localStorage.removeItem(CACHE_KEY);
          onSignOut();
          break;
        case "TOKEN_REFRESHED":
        case "USER_UPDATED":
          // Session is still valid. Do nothing visible.
          break;
      }
    });
  }

  async closeEditor() {
    this.#editorOpen = false;
    if (this.#pendingRefresh) {
      this.#pendingRefresh = null;
      return this.refresh();
    }
  }
}

function hasChanged(before, after) {
  if (!before || before.length !== after.length) return true;
  const prev = new Map(before.map((p) => [p.id, p.updated_at]));
  return after.some((p) => prev.get(p.id) !== p.updated_at);
}
