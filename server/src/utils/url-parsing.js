export function parseUrlSafely(raw) {
  if (!raw || typeof raw !== "string") return null;

  try {
    const ensured = /^[a-z][a-z0-9+.-]*:\/\//i.test(raw) ? raw : `http://${raw}`;
    const u = new URL(ensured);
    return {
      href: u.href,
      protocol: u.protocol,
      hostname: u.hostname,
      pathname: u.pathname,
      search: u.search,
      username: u.username,
      password: u.password,
    };
  } catch {
    return null;
  }
}

export function getUrlPathname(raw) {
  const p = parseUrlSafely(raw);
  if (!p) return null;
  return p.pathname || "/";
}

export function getUrlSearch(raw) {
  const p = parseUrlSafely(raw);
  if (!p) return null;
  return p.search || "";
}
