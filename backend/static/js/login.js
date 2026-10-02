(function () {
  const tabLogin = document.getElementById('tabLogin');
  const tabRegister = document.getElementById('tabRegister');
  const loginSection = document.getElementById('loginSection');
  const registerSection = document.getElementById('registerSection');
  const errorBox = document.getElementById('errorBox');

  const infoBox = document.getElementById('infoBox');
  const forgotSection = document.getElementById('forgotSection');
  const resetSection = document.getElementById('resetSection');
  const resetToken = new URLSearchParams(window.location.search).get('token');

  // If the server still considers this browser signed in, skip straight to the
  // dashboard. (Asks the server: the httpOnly session cookie isn't readable from
  // JS, and a cached profile alone could be stale.) Not on the reset-link page.
  if (!resetToken && AudinexiaAuth.getCurrentUser()) {
    AudinexiaAuth.verifySession().then(ok => { if (ok) window.location.href = '/dashboard'; });
  }

  function showTab(name) {
    errorBox.style.display = 'none';
    infoBox.style.display = 'none';
    tabLogin.classList.toggle('active', name === 'login');
    tabRegister.classList.toggle('active', name === 'register');
    loginSection.classList.toggle('active', name === 'login');
    registerSection.classList.toggle('active', name === 'register');
    forgotSection.classList.toggle('active', name === 'forgot');
    resetSection.classList.toggle('active', name === 'reset');
  }

  function showInfo(msg) {
    infoBox.textContent = msg;
    infoBox.style.display = 'block';
    errorBox.style.display = 'none';
  }

  tabLogin.addEventListener('click', () => showTab('login'));
  tabRegister.addEventListener('click', () => showTab('register'));

  function showError(msg) {
    errorBox.textContent = msg;
    errorBox.style.display = 'block';
  }

  // The hint is fetched rather than hardcoded, so the form can never advertise
  // a minimum length the server stopped enforcing (or, worse, one it now
  // rejects). Falls back to the deployed default if the request fails.
  fetch('/api/auth/password-policy')
    .then(r => (r.ok ? r.json() : null))
    .then(policy => {
      const hint = document.getElementById('policyHint');
      const text = policy ? 'Password: ' + policy.rules.join(', ') + '.' : 'Password: choose a long passphrase.';
      if (hint) hint.textContent = text;
      const resetHint = document.getElementById('resetPolicyHint');
      if (resetHint) resetHint.textContent = text;
    })
    .catch(() => {
      const hint = document.getElementById('policyHint');
      if (hint) hint.textContent = '';
    });

  async function handleAuthResponse(response) {
    let data = {};
    try { data = await response.json(); } catch (e) { /* non-JSON error page */ }
    if (!response.ok) {
      const message = data.error || 'Something went wrong';
      showError(response.status === 429
        ? message + (data.retry_after_seconds ? ` (retry in ${data.retry_after_seconds}s)` : '')
        : message);
      return;
    }
    AudinexiaAuth.setSession(data);
    // A freshly created or reset account still carries the credential an admin
    // chose. The server blocks every tenant API until it is changed
    // (security.password_change_gate), so land the user on the password form
    // rather than on a dashboard full of 403s.
    window.location.href = '/dashboard' + (data.password_change_required ? '?force_password=1' : '');
  }

  // Enter submits whichever tab is visible, instead of only the first field's
  // implicit form submission (these inputs sit outside a <form>).
  function submitOnEnter(event) {
    if (event.key !== 'Enter') return;
    event.preventDefault();
    const active = loginSection.classList.contains('active') ? 'login' : 'register';
    (active === 'login' ? doLogin : doRegister)();
  }
  document.getElementById('loginEmail').addEventListener('keydown', submitOnEnter);
  document.getElementById('loginPassword').addEventListener('keydown', submitOnEnter);
  ['regOrgName', 'regName', 'regEmail', 'regPassword'].forEach(id =>
    document.getElementById(id).addEventListener('keydown', submitOnEnter));

  async function doLogin() {
    const email = document.getElementById('loginEmail').value.trim();
    const password = document.getElementById('loginPassword').value;
    if (!email || !password) { showError('Email and password are required'); return; }
    const btn = document.getElementById('loginBtn');
    btn.disabled = true;
    try {
      const response = await fetch('/api/auth/login', {
        method: 'POST',
        headers: Object.assign({ 'Content-Type': 'application/json' }, AudinexiaAuth.MODE_HEADER),
        body: JSON.stringify({ email, password }),
      });
      await handleAuthResponse(response);
    } catch (e) {
      showError('Could not reach the server');
    } finally {
      btn.disabled = false;
    }
  }
  document.getElementById('loginBtn').addEventListener('click', doLogin);

  async function doRegister() {
    const org_name = document.getElementById('regOrgName').value.trim();
    const name = document.getElementById('regName').value.trim();
    const email = document.getElementById('regEmail').value.trim();
    const password = document.getElementById('regPassword').value;
    if (!org_name || !name || !email || !password) { showError('All fields are required'); return; }
    const btn = document.getElementById('registerBtn');
    btn.disabled = true;
    try {
      const response = await fetch('/api/auth/register', {
        method: 'POST',
        headers: Object.assign({ 'Content-Type': 'application/json' }, AudinexiaAuth.MODE_HEADER),
        body: JSON.stringify({ org_name, name, email, password }),
      });
      await handleAuthResponse(response);
    } catch (e) {
      showError('Could not reach the server');
    } finally {
      btn.disabled = false;
    }
  }
  document.getElementById('registerBtn').addEventListener('click', doRegister);

  /* ── Forgot / reset password ── */
  document.getElementById('forgotLink').addEventListener('click', () => showTab('forgot'));
  document.getElementById('forgotBack').addEventListener('click', () => showTab('login'));

  async function doForgot() {
    const email = document.getElementById('forgotEmail').value.trim();
    if (!email) { showError('Enter your email address'); return; }
    const btn = document.getElementById('forgotBtn');
    btn.disabled = true;
    try {
      const response = await fetch('/api/auth/request-password-reset', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email }),
      });
      const data = await response.json().catch(() => ({}));
      if (response.status === 429) { showError(data.error || 'Too many requests. Try again later.'); return; }
      // Identical message whether or not the address has an account.
      showInfo(data.message || 'If an account exists for that address, a password reset link has been sent.');
    } catch (e) {
      showError('Could not reach the server');
    } finally {
      btn.disabled = false;
    }
  }
  document.getElementById('forgotBtn').addEventListener('click', doForgot);
  document.getElementById('forgotEmail').addEventListener('keydown', e => {
    if (e.key === 'Enter') { e.preventDefault(); doForgot(); }
  });

  async function doReset() {
    const newPassword = document.getElementById('resetPassword').value;
    if (!newPassword) { showError('Enter a new password'); return; }
    const btn = document.getElementById('resetBtn');
    btn.disabled = true;
    try {
      const response = await fetch('/api/auth/reset-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token: resetToken, new_password: newPassword }),
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) { showError(data.error || 'Could not reset the password'); return; }
      AudinexiaAuth.clearSession();
      history.replaceState(null, '', '/login');   // drop the single-use token from the URL
      showTab('login');
      showInfo('Password updated. Sign in with your new password.');
    } catch (e) {
      showError('Could not reach the server');
    } finally {
      btn.disabled = false;
    }
  }
  document.getElementById('resetBtn').addEventListener('click', doReset);
  document.getElementById('resetPassword').addEventListener('keydown', e => {
    if (e.key === 'Enter') { e.preventDefault(); doReset(); }
  });

  if (resetToken) {
    showTab('reset');
    const hint = document.getElementById('policyHint');
    document.getElementById('resetPolicyHint').textContent = hint ? hint.textContent : '';
  }
})();
