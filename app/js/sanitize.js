/**
 * Client-side HTML sanitiser.
 *
 * THIS is the security boundary, not the database trigger. The trigger in
 * supabase/schema.sql is a denylist and denylists leak; this runs on every
 * render, which means it also covers content that reached the browser from
 * the offline cache or from a REST write made before the trigger existed.
 *
 * It is an ALLOWLIST built on the browser's own parser. Anything not named
 * here is removed. That is the whole design: an attacker has to get past a
 * list of what IS permitted, not past a list of what is forbidden.
 */

const ALLOWED_TAGS = new Set([
  "p", "br", "strong", "em", "u", "s",
  "h2", "h3", "h4",
  "ul", "ol", "li",
  "blockquote", "code", "pre",
  "table", "thead", "tbody", "tr", "th", "td",
  "a", "span", "div",
]);

// Per-tag attribute allowlist. Everything else is stripped, including every
// on* handler, style, and any data-* an injected node might rely on.
const ALLOWED_ATTRS = {
  a: new Set(["href", "title"]),
  th: new Set(["colspan", "rowspan"]),
  td: new Set(["colspan", "rowspan"]),
};

// Only these can appear in an href. Blocking "javascript:" by string match is
// not enough: entities, tabs, and newlines inside the scheme all survive a
// naive check, and browsers still execute it.
const SAFE_URL = /^(https?:|mailto:|tel:|#|\/)/i;

function safeHref(value) {
  // Strip control characters and whitespace BEFORE testing. "java\tscript:"
  // and "java&#10;script:" are both live in some parsers.
  const cleaned = String(value)
    .replace(/[\u0000-\u0020\u007f-\u00a0]/g, "")
    .toLowerCase();
  if (!SAFE_URL.test(cleaned)) return null;
  if (cleaned.includes("javascript:") || cleaned.includes("data:")) return null;
  return value;
}

/**
 * @param {string} dirty untrusted HTML
 * @returns {string} HTML containing only allowlisted tags and attributes
 */
export function sanitize(dirty) {
  if (!dirty) return "";

  // DOMParser does NOT execute scripts or fire load handlers, unlike
  // innerHTML on a live node. Parsing into an inert document first is what
  // makes it safe to inspect the tree at all.
  const doc = new DOMParser().parseFromString(String(dirty), "text/html");

  /**
   * Cursor-based, NOT a snapshot of childNodes.
   *
   * This is the bug the tests caught. Unwrapping a disallowed tag inserts its
   * children into the parent's child list. If you iterate over a snapshot
   * taken before that ([...node.childNodes]), the newly moved nodes are never
   * visited, so <section><img onerror=...></section> unwraps the section and
   * leaves the img completely unsanitised. The cursor has to step BACK onto
   * the moved subtree instead of past it.
   */
  const walk = (node) => {
    let child = node.firstChild;

    while (child) {
      let next = child.nextSibling;

      if (child.nodeType === Node.TEXT_NODE) {
        child = next;
        continue;
      }

      if (child.nodeType !== Node.ELEMENT_NODE) {
        // Comments included: conditional comments are an execution vector in
        // old engines and carry no display value regardless.
        child.remove();
        child = next;
        continue;
      }

      const tag = child.tagName.toLowerCase();

      if (!ALLOWED_TAGS.has(tag)) {
        if (tag === "script" || tag === "style") {
          // Their text content is code, so unwrapping would paste the source
          // into the page as visible text.
          child.remove();
        } else {
          // UNWRAP rather than delete. Deleting a stray <font> or <section>
          // silently eats the paragraphs inside it, turning a formatting
          // nuisance into data loss the author notices much later.
          const firstMoved = child.firstChild;
          while (child.firstChild) node.insertBefore(child.firstChild, child);
          child.remove();
          if (firstMoved) next = firstMoved; // re-process what we just moved
        }
        child = next;
        continue;
      }

      const permitted = ALLOWED_ATTRS[tag] ?? new Set();
      for (const attr of [...child.attributes]) {
        const name = attr.name.toLowerCase();
        if (!permitted.has(name)) {
          child.removeAttribute(attr.name);
          continue;
        }
        if (name === "href") {
          const safe = safeHref(attr.value);
          if (safe === null) child.removeAttribute(attr.name);
          else child.setAttribute("href", safe);
        }
      }

      // Any surviving link leaves the app, so close the reverse-tabnabbing
      // hole that target=_blank opens.
      if (tag === "a" && child.hasAttribute("href")) {
        child.setAttribute("rel", "noopener noreferrer");
      }

      walk(child);
      child = next;
    }
  };

  walk(doc.body);
  return doc.body.innerHTML;
}

/** Escape text destined for a text node or attribute. */
export function esc(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}
