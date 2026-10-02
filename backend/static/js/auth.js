// Session handling for Audinexia.
//
// The JWTs live in httpOnly cookies set by the server -- JavaScript on this page
// can't read them, so a script injected into the page (XSS) can't steal a session
// token. The dashboard announces itself with `X-Session-Mode: cookie`, so the
// server doesn't even put tokens in the JSON response body.
//
// What this module keeps in sessionStorage is only the non-secret profile
// (name/role/org/must_change_password) the UI needs to decide what to show. It is
// a UX cache, never proof of identity: the server re-checks the real session on
// every request, and /api/auth/me refreshes this cache from the database.
//
// Cookies are attached automatically, so state-changing requests also send the
// CSRF token (double-submit: the server sets a readable csrf_access_token cookie
// and we echo it back in an X-CSRF-TOKEN header).
(function () {
  const USER_KEY = 'audinexia_user';
  const ORG_KEY = 'audinexia_org';
  const MODE_HEADER = { 'X-Session-Mode': 'cookie' };

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

  // Called with the login/register//me response body ({user, organization}).
  function setSession(data) {
    if (data.user) sessionStorage.setItem(USER_KEY, JSON.stringify(data.user));
    if (data.organization) sessionStorage.setItem(ORG_KEY, JSON.stringify(data.organization));
  }

  // True when the signed-in account is still using a password somebody else set
  // (an admin-created account or an admin reset). Mirrors the server-side gate in
  // security.password_change_gate, which refuses the API until the change
  // happens -- this flag exists so the UI can send the user to the form instead of
  // letting them discover it via a 403.
  function passwordChangeRequired() {
    const user = getCurrentUser();
    return !!(user && user.must_change_password);
  }

  function clearSession() {
    sessionStorage.removeItem(USER_KEY);
    sessionStorage.removeItem(ORG_KEY);
  }

  // UX-only gate (redirects to /login without a cached profile). Not a security
  // boundary: every API route enforces the real session itself.
  function requireLogin() {
    if (!getCurrentUser()) {
      window.location.href = '/login';
      return false;
    }
    return true;
  }

  // Asks the server whether the session cookie is really still valid and refreshes
  // the cached profile (e.g. after an admin changes this user's role). Resolves
  // true if the session is valid.
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

  // Revokes the session server-side (and clears the httpOnly cookies, which JS
  // can't touch), then returns to the login page.
  async function logout() {
    try {
      await fetch('/api/auth/logout', {
        method: 'POST',
        headers: Object.assign({ 'Content-Type': 'application/json',
                                 'X-CSRF-TOKEN': readCookie('csrf_access_token') || '' }, MODE_HEADER),
        body: '{}',
      });
    } catch (e) { /* the redirect must still happen */ }
    clearSession();
    window.location.href = '/login';
  }

  // Wraps fetch(): sends the CSRF header, and on a 401 tries one silent refresh
  // via /api/auth/refresh (access tokens expire after 30 minutes) before giving up
  // and redirecting to /login.
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

    if (response.status === 403) {
      // The server refused because this account has not changed its forced
      // password. Re-reading the body costs nothing here (a 403 was already a
      // dead end) and lets every caller share one recovery path.
      let payload = null;
      try {
        payload = await response.clone().json();
      } catch (e) {
        payload = null;
      }
      if (payload && payload.code === 'password_change_required') {
        window.dispatchEvent(new CustomEvent('audinexia:password-required'));
      }
      return response;
    }

    if (response.status === 401) {
      const refreshResponse = await fetch('/api/auth/refresh', {
        method: 'POST',
        headers: Object.assign({ 'X-CSRF-TOKEN': readCookie('csrf_refresh_token') || '' }, MODE_HEADER),
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
    passwordChangeRequired,
    requireLogin,
    verifySession,
    logout,
    authFetch,
    MODE_HEADER,
  };
})();
