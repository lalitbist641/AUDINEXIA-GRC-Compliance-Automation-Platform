// Shared token storage + fetch wrapper for Audinexia's Bearer-token auth.
// sessionStorage (not localStorage) is deliberate: cleared on tab/browser
// close, a safer default for a compliance tool than indefinite persistence
// on a shared machine. No "remember me" this phase.
(function () {
  const TOKEN_KEY = 'audinexia_access_token';
  const REFRESH_KEY = 'audinexia_refresh_token';
  const USER_KEY = 'audinexia_user';
  const ORG_KEY = 'audinexia_org';

  function getAccessToken() {
    return sessionStorage.getItem(TOKEN_KEY);
  }

  function getRefreshToken() {
    return sessionStorage.getItem(REFRESH_KEY);
  }

  function getCurrentUser() {
    const raw = sessionStorage.getItem(USER_KEY);
    return raw ? JSON.parse(raw) : null;
  }

  function getCurrentOrg() {
    const raw = sessionStorage.getItem(ORG_KEY);
    return raw ? JSON.parse(raw) : null;
  }

  function setSession(data) {
    sessionStorage.setItem(TOKEN_KEY, data.access_token);
    sessionStorage.setItem(REFRESH_KEY, data.refresh_token);
    if (data.user) sessionStorage.setItem(USER_KEY, JSON.stringify(data.user));
    if (data.organization) sessionStorage.setItem(ORG_KEY, JSON.stringify(data.organization));
  }

  function clearSession() {
    sessionStorage.removeItem(TOKEN_KEY);
    sessionStorage.removeItem(REFRESH_KEY);
    sessionStorage.removeItem(USER_KEY);
    sessionStorage.removeItem(ORG_KEY);
  }

  function requireLogin() {
    if (!getAccessToken()) {
      window.location.href = '/login';
      return false;
    }
    return true;
  }

  // Wraps fetch() to attach the Authorization header. On a 401, tries one
  // silent refresh via /api/auth/refresh before giving up and redirecting
  // to /login (access tokens expire after 30 minutes).
  async function authFetch(url, options) {
    options = options || {};
    options.headers = Object.assign({}, options.headers, {
      Authorization: 'Bearer ' + getAccessToken(),
    });
    let response = await fetch(url, options);

    if (response.status === 401 && getRefreshToken()) {
      const refreshResponse = await fetch('/api/auth/refresh', {
        method: 'POST',
        headers: { Authorization: 'Bearer ' + getRefreshToken() },
      });
      if (refreshResponse.ok) {
        const refreshed = await refreshResponse.json();
        sessionStorage.setItem(TOKEN_KEY, refreshed.access_token);
        options.headers.Authorization = 'Bearer ' + refreshed.access_token;
        response = await fetch(url, options);
      } else {
        clearSession();
        window.location.href = '/login';
        return response;
      }
    }
    return response;
  }

  window.AudinexiaAuth = {
    getAccessToken,
    getRefreshToken,
    getCurrentUser,
    getCurrentOrg,
    setSession,
    clearSession,
    requireLogin,
    authFetch,
  };
})();
