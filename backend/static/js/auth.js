// Session handling for Audinexia.
//
// The JWTs live in httpOnly cookies set by the server -- JavaScript on this
// page can't read them, so a script injected into the page (XSS) can't steal
// a session token. What this module keeps in sessionStorage is only the
// non-secret profile (name/role/org) the UI needs to decide what to show; it's
// a UX cache, never proof of identity -- the server re-checks the real session
// on every request, and /api/auth/me refreshes this cache from the database.
//
// Because cookies are attached automatically, state-changing requests also
// send the CSRF token (double-submit: the server sets a readable
// csrf_access_token cookie, we echo it back in an X-CSRF-TOKEN header).
(function () {
  const USER_KEY = 'audinexia_user';
  const ORG_KEY = 'audinexia_org';

  function readCookie(name) {
    const match = document.cookie.split('; ').find(c => c.startsWith(name + '='));
    return match ? decodeURIComponent(match.slice(name.length + 1)) : null;
  }

  function getCurrentUser() {
    try {
      const raw = sessionStorage.getItem(USER_KEY);
      return raw ? JSON.parse(raw) : null;
    } catch (e) {
      return null;
    }
  }

  function getCurrentOrg() {
    try {
      const raw = sessionStorage.getItem(ORG_KEY);
      return raw ? JSON.parse(raw) : null;
    } catch (e) {
      return null;
    }
  }

  // Called with the login/register/me response body ({user, organization}).
  function setSession(data) {
    if (data.user) sessionStorage.setItem(USER_KEY, JSON.stringify(data.user));
    if (data.organization) sessionStorage.setItem(ORG_KEY, JSON.stringify(data.organization));
  }

  function clearSession() {
    sessionStorage.removeItem(USER_KEY);
    sessionStorage.removeItem(ORG_KEY);
  }

  // UX-only gate (redirects to /login without a cached profile). Not a
  // security boundary: every API route enforces the real session itself.
  function requireLogin() {
    if (!getCurrentUser()) {
      window.location.href = '/login';
      return false;
    }
    return true;
  }

  // Asks the server whether the session cookie is actually valid, and
  // refreshes the cached profile (e.g. after an admin changes this user's
  // role). Returns true if the session is valid.
  async function verifySession() {
    try {
      const response = await authFetch('/api/auth/me', {}, { redirectOnFail: false });
      if (!response.ok) { clearSession(); return false; }
      setSession(await response.json());
      return true;
    } catch (e) {
      return false;
    }
  }

  async function logout() {
    try {
      await fetch('/api/auth/logout', {
        method: 'POST',
        headers: { 'X-CSRF-TOKEN': readCookie('csrf_access_token') || '' },
      });
    } catch (e) { /* clear locally regardless */ }
    clearSession();
    window.location.href = '/login';
  }

  // Wraps fetch(): sends the CSRF header, and on a 401 tries one silent
  // refresh via /api/auth/refresh (access tokens expire after 30 minutes)
  // before giving up and redirecting to /login.
  async function authFetch(url, options, behavior) {
    options = options || {};
    const redirectOnFail = !behavior || behavior.redirectOnFail !== false;
    const withCsrf = () => {
      options.headers = Object.assign({}, options.headers, {
        'X-CSRF-TOKEN': readCookie('csrf_access_token') || '',
      });
    };

    withCsrf();
    let response = await fetch(url, options);

    if (response.status === 401) {
      const refreshResponse = await fetch('/api/auth/refresh', {
        method: 'POST',
        headers: { 'X-CSRF-TOKEN': readCookie('csrf_refresh_token') || '' },
      });
      if (refreshResponse.ok) {
        withCsrf(); // the refresh issued a new csrf_access_token cookie
        response = await fetch(url, options);
      } else if (redirectOnFail) {
        clearSession();
        window.location.href = '/login';
      }
    }
    return response;
  }

  window.AudinexiaAuth = {
    getCurrentUser,
    getCurrentOrg,
    setSession,
    clearSession,
    requireLogin,
    verifySession,
    logout,
    authFetch,
  };
})();
