'use strict';

/* ── HTML escaping ──
   Every value that originates from a user (descriptions, filenames, titles,
   names, notes, evidence excerpts...) MUST go through esc() before being
   interpolated into an innerHTML template -- including inside quoted
   attributes. Escapes & < > " ' so it is safe in text and attribute contexts.
   It is NOT safe inside the JavaScript of an inline handler (the browser
   HTML-decodes the attribute before the JS parses): pass such values through a
   data- attribute and read them from the element instead. */
function esc(v) {
  if (v === null || v === undefined) return '';
  return String(v).replace(/[&<>"']/g, ch => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]
  ));
}

/* ── Delegated click actions ──
   Handlers are wired with data-action="<name>" data-args='[...]' instead of inline
   onclick attributes, so the page's CSP can forbid inline script entirely. The
   handler is called as fn(...args); args is JSON the page built with
   esc(JSON.stringify(...)), never evaluated as code. Only names that exist as
   functions on window can run. Handlers that also need the clicked element or
   the event are listed in ACTIONS_WITH_ELEMENT and get (...args, element, event). */
const ACTIONS_WITH_ELEMENT = new Set(['runWatch', 'downloadEvidence', 'createRiskFromControl', 'toggleNotif']);
document.addEventListener('click', e => {
  const el = e.target.closest('[data-action]');
  if (!el) return;
  const fn = window[el.dataset.action];
  if (typeof fn !== 'function') { console.error('Unknown action', el.dataset.action); return; }
  let args = [];
  if (el.dataset.args) {
    try { args = JSON.parse(el.dataset.args); } catch (err) { console.error('Bad data-args', err); return; }
  }
  if (ACTIONS_WITH_ELEMENT.has(el.dataset.action)) fn(...args, el, e); else fn(...args);
});

/* ── Auth guard ── */
// This is a UX redirect, not the real security boundary — the actual
// boundary is @jwt_required()/@roles_required() on the API routes, which is
// correct since this HTML page itself contains no sensitive data.
if (!AudinexiaAuth.requireLogin()) {
  throw new Error('Not authenticated'); // stop the rest of this script from running
}

(function initUserCard() {
  const user = AudinexiaAuth.getCurrentUser();
  const org  = AudinexiaAuth.getCurrentOrg();
  if (user) {
    const initials = user.name.split(' ').map(p => p[0]).join('').slice(0, 2).toUpperCase();
    document.getElementById('userAvatar').textContent = initials || '?';
    document.getElementById('userNameLabel').textContent = user.name;
    document.getElementById('userRoleLabel').textContent =
      user.role.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase()) +
      (org ? ' · ' + org.name : '');
  }
  document.getElementById('logoutBtn').addEventListener('click', function (e) {
    e.stopPropagation();
    // Best-effort server-side revocation first: clearing sessionStorage alone
    // leaves the refresh token valid for its full lifetime, which is exactly
    // what a "sign out" button must not do.
    signOutNow();
  });
})();

/* ── Page navigation ── */
const PAGE_TITLES = {
  dashboard:  ['Compliance Audit Platform',  'Dashboard · Enterprise v5.0'],
  scanner:    ['Audit Scanner',              'Frameworks · Run Scans'],
  reports:    ['Compliance Reports',         'Reports · View & Download'],
  policies:   ['Policy Library',             'Documents · Policy Management'],
  'risk-register': ['Risk Register',         'Risk Management · Register & Tracking'],
  'audits':   ['Audit Management',           'Audits · Plan, Track & Close'],
  'fw-dpdpa': ['DPDPA 2023',                 'Frameworks · India Privacy Law'],
  'fw-iso':   ['ISO 27001',                  'Frameworks · Security Standard'],
  'fw-gdpr':  ['GDPR',                       'Frameworks · EU Privacy'],
  'fw-pci':   ['PCI DSS',                    'Frameworks · Payment Security'],
  'fw-hipaa': ['HIPAA',                      'Frameworks · Health Data'],
  'fw-nistcsf':['NIST CSF 2.0',              'Frameworks · Cybersecurity Framework'],
  'fw-certin':['CERT-In Directions',         'Frameworks · India Incident Reporting'],
  config:     ['Configuration',              'Settings · Platform Config'],
  team:       ['Team Management',            'Settings · Team Members'],
};

function navigate(pageId) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  const page = document.getElementById('page-' + pageId);
  if (page) page.classList.add('active');
  document.querySelectorAll(`.nav-item[data-page="${pageId}"]`).forEach(n => n.classList.add('active'));
  const [title, crumb] = PAGE_TITLES[pageId] || [pageId, ''];
  document.getElementById('headerTitle').textContent = title;
  document.getElementById('headerBreadcrumb').textContent = crumb;
  window.scrollTo(0, 0);
  if (pageId === 'reports') loadReports();
  if (pageId === 'risk-register') loadRisks();
  if (pageId === 'audits') loadAudits();
  if (pageId === 'vendors') loadVendors();
  if (pageId === 'maturity') loadMaturity();
  if (pageId === 'monitoring') loadWatches();
  if (pageId === 'trail') loadTrail();
  if (pageId === 'policies') loadLibrary();
  if (pageId === 'config') loadConfig();
  if (pageId === 'team') loadTeam();
}

const FW_ICONS = { dpdpa:'🇮🇳', iso27001:'🌐', gdpr:'🇪🇺', pcidss:'💳', hipaa:'🏥', nistcsf:'📋', certin:'🛡️' };

async function loadReports() {
  const tbody = document.getElementById('reportsTableBody');
  try {
    const res = await AudinexiaAuth.authFetch('/api/assessments');
    if (!res.ok) {
      tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--danger);padding:20px">Could not load reports</td></tr>';
      return;
    }
    const data = await res.json();
    const rows = data.assessments || [];
    if (!rows.length) {
      tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--muted);padding:20px">No scans yet — run one from the Dashboard.</td></tr>';
      return;
    }
    // Real data has no lifecycle/status field like the old mock rows implied
    // (Completed/In Review/Pending) -- showing actual language-found/
    // partial/not-found counts instead rather than fabricating one.
    tbody.innerHTML = rows.map(a => {
      const score = Math.round(a.overall_score);
      const scoreCol = score >= 80 ? 'var(--success)' : score >= 50 ? 'var(--warn)' : 'var(--danger)';
      const icon = FW_ICONS[a.framework] || '📄';
      const fwLabel = FW_NAMES[a.framework] || a.framework;
      const date = new Date(a.created_at).toLocaleDateString();
      return `<tr>
        <td style="font-weight:600">${esc(a.filename)}</td>
        <td><span class="badge badge-blue">${icon} ${esc(fwLabel)}</span></td>
        <td style="color:${scoreCol};font-weight:700">${esc(score)}%</td>
        <td style="color:var(--muted)">${esc(date)}</td>
        <td style="white-space:nowrap">
          <span class="badge badge-green">${esc(a.compliant_count)} ✅</span>
          <span class="badge badge-yellow">${esc(a.partial_count)} ⚠️</span>
          <span class="badge badge-red">${esc(a.non_compliant_count)} ❌</span>
        </td>
        <td style="white-space:nowrap">
          <button class="btn btn-secondary btn-sm" data-action="viewAssessment" data-args="${esc(JSON.stringify([a.id]))}">👁 View</button>
          <button class="btn btn-secondary btn-sm" data-action="downloadReportRow" data-args="${esc(JSON.stringify([a.id, a.framework]))}">⬇</button>
        </td>
      </tr>`;
    }).join('');
  } catch (e) {
    tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--danger);padding:20px">Could not reach server</td></tr>';
  }
}

window.viewAssessment = async assessmentId => {
  try {
    const res = await AudinexiaAuth.authFetch(`/api/assessments/${assessmentId}`);
    if (!res.ok) { showToast('Could not load assessment'); setTimeout(hideToast, 2000); return; }
    const data = await res.json();
    data.assessment_id = data.id; // the export handlers read results.assessment_id
    results = data;
    renderResults(data);
    navigate('dashboard');
  } catch (e) {
    showToast('Could not reach server');
    setTimeout(hideToast, 2000);
  }
};

window.downloadReportRow = async (assessmentId, framework) => {
  try {
    const res = await AudinexiaAuth.authFetch('/api/export-pdf', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ assessment_id: assessmentId })
    });
    if (!res.ok) { showToast('Download failed'); setTimeout(hideToast, 2000); return; }
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = `Audinexia_Report_${framework}.pdf`;
    document.body.appendChild(a); a.click(); document.body.removeChild(a);
    URL.revokeObjectURL(url);
  } catch (e) {
    showToast('Could not reach server');
    setTimeout(hideToast, 2000);
  }
};

document.querySelectorAll('.nav-item[data-page]').forEach(el =>
  el.addEventListener('click', () => navigate(el.dataset.page))
);
document.querySelector('.user-card[data-page]').addEventListener('click', function() {
  navigate(this.dataset.page);
});

/* ── Scanner state ── */
const FW_NAMES = {
  dpdpa:   'DPDPA 2023',
  iso27001:'ISO 27001',
  gdpr:    'GDPR',
  pcidss:  'PCI DSS',
  hipaa:   'HIPAA',
  nistcsf: 'NIST CSF 2.0',
  certin:  'CERT-In Directions'
};

let fw           = 'dpdpa';
let selectedFile = null;
let results      = null;
let scanning     = false;

/* Framework selector */
document.querySelectorAll('.fw-item').forEach(el => {
  el.addEventListener('click', () => {
    document.querySelectorAll('.fw-item').forEach(e => e.classList.remove('active'));
    el.classList.add('active');
    fw = el.dataset.fw;
    document.getElementById('fwActive').textContent = FW_NAMES[fw];
    setStep(1);
  });
});

/* ── Upload zone ── */
const uploadZone = document.getElementById('uploadZone');
const fileInput  = document.getElementById('fileInput');

uploadZone.addEventListener('click', () => fileInput.click());
uploadZone.addEventListener('dragover',  e => { e.preventDefault(); uploadZone.classList.add('drag'); });
uploadZone.addEventListener('dragleave', () => uploadZone.classList.remove('drag'));
uploadZone.addEventListener('drop', e => {
  e.preventDefault();
  uploadZone.classList.remove('drag');
  if (e.dataTransfer.files[0]) handleFile(e.dataTransfer.files[0]);
});
fileInput.addEventListener('change', e => {
  if (e.target.files[0]) handleFile(e.target.files[0]);
});

function formatBytes(bytes) {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
}

function handleFile(f) {
  const allowed = ['.txt', '.pdf', '.docx'];
  const ext = '.' + f.name.split('.').pop().toLowerCase();
  if (!allowed.includes(ext)) {
    showErr('Unsupported file format. Please upload a .txt, .pdf, or .docx file.');
    return;
  }
  if (f.size > 50 * 1024 * 1024) {
    showErr('File exceeds the 50 MB limit. Please upload a smaller file.');
    return;
  }
  selectedFile = f;
  document.getElementById('fileChipName').textContent = f.name;
  document.getElementById('fileChipSize').textContent = formatBytes(f.size);
  document.getElementById('fileChip').style.display   = 'flex';
  document.getElementById('scanRow').style.display    = 'flex';
  hideErr();
  setStep(2);
}

document.getElementById('fileRemove').addEventListener('click', () => {
  selectedFile = null;
  fileInput.value = '';
  document.getElementById('fileChip').style.display = 'none';
  document.getElementById('scanRow').style.display  = 'none';
  setStep(1);
});

/* ── Error strip ── */
function showErr(msg) {
  document.getElementById('errMsg').textContent = msg;
  document.getElementById('errStrip').style.display = 'flex';
}
function hideErr() {
  document.getElementById('errStrip').style.display = 'none';
}
document.getElementById('errClose').addEventListener('click', hideErr);

/* ── Step wizard ── */
function setStep(n) {
  for (let i = 1; i <= 4; i++) {
    const sc = document.getElementById('sc' + i);
    const sl = document.getElementById('sl' + i);
    sc.className = 'step-circle' + (i < n ? ' done' : i === n ? ' active' : '');
    sl.className = 'step-label'  + (i < n ? ' done' : i === n ? ' active' : '');
    if (i < 4) {
      document.getElementById('sline' + i).className = 'step-line' + (i < n ? ' done' : '');
    }
  }
}

/* ── Toast ── */
function showToast(msg) {
  const t = document.getElementById('scanToast');
  document.getElementById('toastMsg').textContent = msg;
  t.classList.add('show');
}
function hideToast() {
  document.getElementById('scanToast').classList.remove('show');
}

/* ── Progress animation ── */
async function runProgress() {
  const pb   = document.getElementById('progressBlock');
  const ids   = ['ps1', 'ps2', 'ps3'];
  const labels = [
    'Extracting text from document...',
    'Checking controls against policy...',
    'Scoring results and generating report...'
  ];
  pb.style.display = 'block';
  for (let i = 0; i < ids.length; i++) {
    const el = document.getElementById(ids[i]);
    el.className = 'progress-step active';
    el.innerHTML = `<span class="ps-icon">🔄</span> ${esc(labels[i])}`;
    await sleep(650);
    el.className = 'progress-step done';
    el.innerHTML = `<span class="ps-icon">✅</span> ${esc(labels[i])}`;
  }
  await sleep(300);
  pb.style.display = 'none';
  ids.forEach(id => {
    const el = document.getElementById(id);
    el.className = 'progress-step';
    el.textContent = '';
  });
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

/* ── Disable / enable scan buttons ── */
function setScanBtns(disabled) {
  document.getElementById('scanBtn').disabled    = disabled;
  document.getElementById('scanAllBtn').disabled = disabled;
}

/* ── SCAN single framework ── */
document.getElementById('scanBtn').addEventListener('click', async () => {
  if (!selectedFile || scanning) return;
  scanning = true;
  setScanBtns(true);
  setStep(3);
  showToast(`Scanning against ${FW_NAMES[fw]}...`);
  await runProgress();

  const fd = new FormData();
  fd.append('file', selectedFile);
  fd.append('framework', fw);

  try {
    const res  = await AudinexiaAuth.authFetch('/api/scan', { method: 'POST', body: fd });
    if (!res.ok) throw new Error(`Server error ${res.status}`);
    const data = await res.json();
    if (data.success) {
      results = data;
      renderResults(data);
      addActivity(`✅ Scan complete: ${FW_NAMES[fw]} — ${Math.round(data.overall_score)}%`);
      pushNotif(`Scan complete: ${FW_NAMES[fw]} scored ${Math.round(data.overall_score)}%`);
      setStep(4);
    } else {
      showErr(data.error || 'Scan failed. Please try again.');
      setStep(2);
    }
  } catch (e) {
    showErr('Cannot connect to backend. Ensure Flask is running on http://127.0.0.1:5000');
    setStep(2);
  } finally {
    scanning = false;
    setScanBtns(false);
    hideToast();
  }
});

/* ── SCAN all frameworks ── */
document.getElementById('scanAllBtn').addEventListener('click', async () => {
  if (!selectedFile || scanning) return;
  scanning = true;
  setScanBtns(true);
  setStep(3);
  showToast('Running all 7 framework scans...');
  await runProgress();

  const allFws = ['dpdpa', 'iso27001', 'gdpr', 'pcidss', 'hipaa', 'nistcsf', 'certin'];
  const rows = [];

  for (const f of allFws) {
    showToast(`Scanning ${FW_NAMES[f]}...`);
    const fd = new FormData();
    fd.append('file', selectedFile);
    fd.append('framework', f);
    try {
      const res  = await AudinexiaAuth.authFetch('/api/scan', { method: 'POST', body: fd });
      const data = await res.json();
      if (data.success) {
        rows.push({
          name:  FW_NAMES[f],
          score: Math.round(data.overall_score),
          c:     data.compliant_count,
          p:     data.partial_count,
          n:     data.non_compliant_count,
          total: (data.compliant_count + data.partial_count + data.non_compliant_count)
        });
      }
    } catch {}
  }

  // Render multi-framework table
  let html = `<div style="overflow-x:auto">
    <table style="width:100%;border-collapse:collapse;font-size:12.5px">
    <thead><tr style="border-bottom:2px solid var(--border)">`;
  ['Framework','Score','Found','Partial','Not Found','Status'].forEach(h => {
    html += `<th style="padding:10px 14px;text-align:left;font-size:10.5px;font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:.5px">${esc(h)}</th>`;
  });
  html += '</tr></thead><tbody>';

  rows.forEach((r, i) => {
    const col = r.score >= 80 ? 'var(--success)' : r.score >= 50 ? 'var(--warn)' : 'var(--danger)';
    const lbl = r.score >= 80 ? '✅ Language Found' : r.score >= 50 ? '⚠️ Partial' : '❌ Not Found';
    const cls = r.score >= 80 ? 'badge-green' : r.score >= 50 ? 'badge-yellow' : 'badge-red';
    const bg  = i % 2 === 0 ? 'transparent' : 'var(--surface-alt)';
    html += `<tr style="border-bottom:1px solid var(--border);background:${bg}">
      <td style="padding:11px 14px;font-weight:700">${esc(r.name)}</td>
      <td style="padding:11px 14px">
        <div style="display:flex;align-items:center;gap:8px">
          <div style="flex:1;height:6px;background:var(--border);border-radius:3px;overflow:hidden;max-width:80px">
            <div style="width:${esc(r.score)}%;height:100%;background:${col};border-radius:3px"></div>
          </div>
          <span style="font-weight:800;color:${col};font-size:13px">${esc(r.score)}%</span>
        </div>
      </td>
      <td style="padding:11px 14px;color:var(--success);font-weight:700">${esc(r.c)}</td>
      <td style="padding:11px 14px;color:var(--warn);font-weight:700">${esc(r.p)}</td>
      <td style="padding:11px 14px;color:var(--danger);font-weight:700">${esc(r.n)}</td>
      <td style="padding:11px 14px"><span class="badge ${cls}">${lbl}</span></td>
    </tr>`;
  });
  html += '</tbody></table></div>';

  document.getElementById('ctrlList').innerHTML = html;
  addActivity(`📊 Multi-framework scan complete — ${rows.length} frameworks analysed`);
  setStep(4);
  scanning = false;
  setScanBtns(false);
  hideToast();
});

/* ── Render results ── */
function renderResults(data) {
  const score = Math.round(data.overall_score);
  const total = data.controls.length;
  const col   = score >= 80 ? 'var(--success)' : score >= 60 ? 'var(--warn)' : 'var(--danger)';

  // Summary cards
  document.getElementById('ovScore').textContent     = score + '%';
  document.getElementById('ovScore').style.color     = col;
  document.getElementById('cntCompliant').textContent = data.compliant_count;
  document.getElementById('cntPartial').textContent   = data.partial_count;
  document.getElementById('cntNon').textContent       = data.non_compliant_count;

  // Score ring (circumference = 2π × 54 ≈ 339)
  const ring = document.getElementById('ringFill');
  ring.style.stroke            = score >= 80 ? '#059669' : score >= 60 ? '#d97706' : '#dc2626';
  ring.style.strokeDashoffset  = 339 * (1 - score / 100);
  document.getElementById('ringPct').textContent  = score + '%';
  document.getElementById('ringPct').style.color  = col;

  // Bars
  const pct = n => total > 0 ? Math.round(n / total * 100) : 0;
  document.getElementById('bCompliant').style.width  = pct(data.compliant_count)  + '%';
  document.getElementById('bPartial').style.width    = pct(data.partial_count)    + '%';
  document.getElementById('bNonComp').style.width    = pct(data.non_compliant_count) + '%';
  document.getElementById('bvCompliant').textContent = data.compliant_count;
  document.getElementById('bvPartial').textContent   = data.partial_count;
  document.getElementById('bvNonComp').textContent   = data.non_compliant_count;

  // Controls list
  renderControls(data.controls, 'all');

  // Action plan
  const bad = data.controls
    .filter(c => c.status !== 'Language found')
    .sort((a, b) => ({'critical':0,'major':1,'minor':2}[a.severity]||1) - ({'critical':0,'major':1,'minor':2}[b.severity]||1));

  const ac = document.getElementById('actionCount');
  ac.style.display = bad.length ? '' : 'none';
  ac.textContent   = bad.length;

  document.getElementById('actionList').innerHTML = bad.length
    ? bad.map((item, i) => `
        <div class="action-item">
          <div class="action-num" style="background:${item.severity==='critical'?'var(--danger-bg)':'var(--warn-bg)'};color:${item.severity==='critical'?'#dc2626':'#d97706'}">${esc(i+1)}</div>
          <div class="action-body">
            <div class="action-name">${esc(item.id)} — ${esc(item.name)}</div>
            <div class="action-remed">${esc(item.fix_suggestion||'Review required.')}</div>
            <div class="action-meta">
              <span class="tag tag-${esc(item.severity||'major')}">${esc((item.severity||'major').toUpperCase())}</span>
              <span class="tag" style="background:var(--surface-alt);color:var(--muted)">${esc(item.owner||'Unassigned')}</span>
              <span class="tag" style="background:var(--surface-alt);color:var(--muted)">Score: ${esc(item.score||0)}%</span>
            </div>
          </div>
        </div>`).join('')
    : '<div class="empty-state" style="padding:20px"><div class="empty-icon" style="font-size:28px">🎉</div><div class="empty-label" style="font-size:12.5px">Required language found for every scanned control</div></div>';

  // Enable export buttons
  document.getElementById('exportHtmlBtn').disabled = false;
  document.getElementById('exportPdfBtn').disabled  = false;
  document.getElementById('reviseBtn').disabled     = false;

  loadCrosswalk(data.assessment_id || data.id);
}

/* ── Framework crosswalk ── */
function toggleOpenDetail(id) {
  const el = document.getElementById(id);
  if (el) el.classList.toggle('open-detail');
}

function toggleCrosswalk() {
  const body = document.getElementById('crosswalkBody');
  const icon = document.getElementById('crosswalkToggleIcon');
  const open = body.style.display !== 'none';
  body.style.display = open ? 'none' : 'block';
  icon.textContent = open ? '▾' : '▴';
}

async function loadCrosswalk(assessmentId) {
  const card = document.getElementById('crosswalkCard');
  if (!assessmentId) { card.style.display = 'none'; return; }
  try {
    const res = await AudinexiaAuth.authFetch(`/api/assessments/${assessmentId}/crosswalk`);
    if (!res.ok) { card.style.display = 'none'; return; }
    const data = await res.json();
    card.style.display = '';

    const scoreCls = s => s === 'Language found' ? 'badge-green' : s === 'Partially found' ? 'badge-yellow' : 'badge-red';
    const scoreSym = s => s === 'Language found' ? '✅' : s === 'Partially found' ? '⚠️' : '❌';

    const targetRows = data.targets.map((t, i) => {
      const bd = t.status_breakdown;
      const mappedRows = t.mapped_controls.map(m => `
        <div style="padding:8px 0;border-bottom:1px solid var(--border)">
          <div style="display:flex;justify-content:space-between;align-items:center">
            <span style="font-size:12.5px;font-weight:600">${esc(m.target_control_id)} — ${esc(m.target_control_name)}</span>
            <span class="badge ${esc(scoreCls(m.projected_status))}">${esc(scoreSym(m.projected_status))} ${esc(m.projected_status)}</span>
          </div>
          <div style="font-size:11px;color:var(--muted);margin-top:2px">
            Projected from ${esc(m.source_control_id)} — ${esc(m.source_control_name)} (scored ${esc(m.source_score)}% · ${esc(data.source_framework_name)}) via "${esc(m.cluster)}"
          </div>
        </div>`).join('');
      const unmappedRows = t.unmapped_controls.length
        ? `<div style="margin-top:8px;font-size:11px;color:var(--muted)">
             <strong>Not covered — needs a direct scan:</strong>
             ${t.unmapped_controls.map(u => u.target_control_id).join(', ')}
           </div>`
        : '';
      return `
        <div class="ctrl-item" style="cursor:pointer" data-action="toggleOpenDetail" data-args="${esc(JSON.stringify(['crosswalkDetail' + i]))}">
          <div class="ctrl-item-icon" style="background:var(--surface-alt)">${esc(FW_ICONS[t.target_framework] || '📄')}</div>
          <div class="ctrl-info">
            <div class="ctrl-id">${esc(t.target_framework_name)}</div>
            <div class="ctrl-owner">${esc(t.mapped_count)}/${esc(t.total_target_controls)} controls mapped</div>
          </div>
          <span class="badge badge-green" style="margin-right:4px">${esc(bd.language_found)} ✅</span>
          <span class="badge badge-yellow" style="margin-right:4px">${esc(bd.partially_found)} ⚠️</span>
          <span class="badge badge-red">${esc(bd.not_found)} ❌</span>
        </div>
        <div id="crosswalkDetail${esc(i)}" class="crosswalk-detail">
          ${mappedRows || '<em style="color:var(--muted);font-size:12px">No mapped controls for this framework.</em>'}
          ${unmappedRows}
        </div>`;
    }).join('');

    document.getElementById('crosswalkBody').innerHTML = `
      <div style="font-size:11.5px;color:var(--muted);font-style:italic;margin-bottom:12px">ℹ️ ${esc(data.disclaimer)}</div>
      ${targetRows}`;
  } catch (e) {
    card.style.display = 'none';
  }
}

/* ── Render controls list ── */
function renderControls(controls, filter) {
  const map = { compliant:'Language found', partial:'Partially found', noncompliant:'Not found' };
  const filtered = filter === 'all'
    ? controls
    : controls.filter(c => c.status === map[filter]);

  if (!filtered.length) {
    document.getElementById('ctrlList').innerHTML =
      '<div class="empty-state"><div class="empty-icon">🔍</div><div class="empty-label">No controls match this filter</div></div>';
    return;
  }

  document.getElementById('ctrlList').innerHTML = filtered.map(c => {
    const isC = c.status === 'Language found';
    const isP = c.status === 'Partially found';
    const iconBg = isC ? 'var(--success-bg)' : isP ? 'var(--warn-bg)' : 'var(--danger-bg)';
    const scoreCol = c.score >= 80 ? 'var(--success)' : c.score >= 50 ? 'var(--warn)' : 'var(--danger)';
    const badgeCls = isC ? 'badge-green' : isP ? 'badge-yellow' : 'badge-red';
    const sym = isC ? '✅' : isP ? '⚠️' : '❌';
    const lbl = isC ? 'Language Found' : isP ? 'Partial' : 'Not Found';
    return `<div class="ctrl-item" data-action="showCtrl" data-args="${esc(JSON.stringify([c.id]))}">
      <div class="ctrl-item-icon" style="background:${iconBg}">${sym}</div>
      <div class="ctrl-info">
        <div class="ctrl-id">${esc(c.id)}</div>
        <div class="ctrl-name">${esc(c.name)}</div>
        <div class="ctrl-owner">${esc(c.owner||'')}</div>
      </div>
      <div class="ctrl-score" style="color:${scoreCol}">${esc(c.score||0)}%</div>
      <div class="badge ${badgeCls}">${lbl}</div>
    </div>`;
  }).join('');
}

document.getElementById('filterSel').addEventListener('change', e => {
  if (results) renderControls(results.controls, e.target.value);
});

/* ── Control detail modal ── */
let orgUsersCache = null;
async function fetchOrgUsers() {
  if (orgUsersCache) return orgUsersCache;
  try {
    const res = await AudinexiaAuth.authFetch('/api/admin/users');
    orgUsersCache = res.ok ? (await res.json()).users || [] : [];
  } catch (e) {
    orgUsersCache = [];
  }
  return orgUsersCache;
}

// Role gates below are UX only -- the API enforces these same role lists
// server-side regardless (routes/review_routes.py), consistent with the
// login-redirect guard elsewhere in this file.
function canReviewControls() {
  const user = AudinexiaAuth.getCurrentUser();
  return !!user && ['org_admin', 'compliance_manager', 'auditor'].includes(user.role);
}
function canUploadEvidence() {
  const user = AudinexiaAuth.getCurrentUser();
  return !!user && ['org_admin', 'compliance_manager', 'auditor', 'member'].includes(user.role);
}
function canDeleteEvidence() {
  const user = AudinexiaAuth.getCurrentUser();
  return !!user && ['org_admin', 'compliance_manager'].includes(user.role);
}

window.showCtrl = async id => {
  if (!results) return;
  const c = results.controls.find(x => x.id === id);
  if (!c) return;
  const isC = c.status === 'Language found';
  const isP = c.status === 'Partially found';
  const col = isC ? 'var(--success)' : isP ? 'var(--warn)' : 'var(--danger)';
  const crId = c.control_result_id;

  document.getElementById('modalTitle').innerHTML =
    `<span style="font-family:var(--mono);font-size:12px;background:var(--surface-alt);padding:2px 8px;border-radius:5px;margin-right:8px;color:var(--muted)">${esc(c.id)}</span>${esc(c.name)}`;

  const foundHtml   = (c.found_phrases||[]).map(p => `<span style="display:inline-block;background:var(--success-bg);color:#065f46;font-size:11px;padding:2px 8px;border-radius:6px;margin:2px;font-weight:600">${esc(p)}</span>`).join('') || '<em style="color:var(--muted);font-size:12px">None detected</em>';
  const missingHtml = (c.missing_phrases||[]).map(p => `<span style="display:inline-block;background:var(--danger-bg);color:#991b1b;font-size:11px;padding:2px 8px;border-radius:6px;margin:2px;font-weight:600">${esc(p)}</span>`).join('') || '<em style="color:var(--muted);font-size:12px">None — fully covered</em>';

  document.getElementById('modalBody').innerHTML = `
    <div class="modal-row">
      <div class="modal-field"><div class="field-label">Status</div><div class="field-val" style="color:${col}">${esc(c.status)}</div></div>
      <div class="modal-field"><div class="field-label">Score</div><div class="field-val">${esc(c.score||0)}%</div></div>
      <div class="modal-field"><div class="field-label">Severity</div><div class="field-val">${esc((c.severity||'').toUpperCase())}</div></div>
    </div>
    <div class="modal-row">
      <div class="modal-field"><div class="field-label">Owner</div><div class="field-val">${esc(c.owner||'—')}</div></div>
      <div class="modal-field"><div class="field-label">Risk Level</div><div class="field-val">${esc(c.risk_level||'—')}</div></div>
      <div class="modal-field"><div class="field-label">Weight</div><div class="field-val">${esc(c.weight||'—')}</div></div>
    </div>
    <div class="field-label" style="margin-bottom:6px">Found Keywords</div>
    <div style="margin-bottom:12px">${foundHtml}</div>
    <div class="field-label" style="margin-bottom:6px">Missing Keywords</div>
    <div style="margin-bottom:12px">${missingHtml}</div>
    ${c.evidence ? `<div class="field-label" style="margin-bottom:6px">Evidence from Policy</div><div class="evidence-box">"${esc(c.evidence.substring(0,300))}${c.evidence.length>300?'…':''}"</div>` : ''}
    ${c.why_matters ? `<div class="why-box"><strong>⚠️ Why it matters:</strong> ${esc(c.why_matters)}</div>` : ''}
    <div class="field-label" style="margin:12px 0 6px">Recommended Fix</div>
    <div class="remed-box">${esc(c.fix_suggestion||'No remediation info available.')}</div>
    ${crId ? `
    <div style="margin-top:18px;padding-top:14px;border-top:1px solid var(--border)">
      <div class="field-label" style="margin-bottom:8px">🔍 Review &amp; Remediation</div>
      <div id="reviewSectionBody"><em style="color:var(--muted);font-size:12px">Loading…</em></div>
    </div>
    <div style="margin-top:18px;padding-top:14px;border-top:1px solid var(--border)">
      <div class="field-label" style="margin-bottom:8px">📎 Evidence Files</div>
      <div id="evidenceSectionBody"><em style="color:var(--muted);font-size:12px">Loading…</em></div>
    </div>
    <div style="margin-top:18px;padding-top:14px;border-top:1px solid var(--border)">
      <div class="field-label" style="margin-bottom:8px">🎯 Risks</div>
      <div id="riskSectionBody"><em style="color:var(--muted);font-size:12px">Loading…</em></div>
    </div>
    <div style="margin-top:18px;padding-top:14px;border-top:1px solid var(--border)">
      <div class="field-label" style="margin-bottom:8px">📝 Findings</div>
      <div id="findingSectionBody"><em style="color:var(--muted);font-size:12px">Loading…</em></div>
    </div>` : ''}`;

  document.getElementById('modal').classList.add('open');

  if (crId) {
    renderReviewSection(crId, c.status);
    renderEvidenceSection(crId);
    renderRiskSection(crId, c.name);
    renderFindingSection(crId);
  }
};

async function renderReviewSection(crId, controlStatus) {
  const body = document.getElementById('reviewSectionBody');
  if (!body) return;

  if (!canReviewControls()) {
    body.innerHTML = '<em style="color:var(--muted);font-size:12px">Only Org Admin, Compliance Manager, or Auditor roles can review findings.</em>';
    return;
  }

  const isCompliant = controlStatus === 'Language found';
  const [reviewRes, users] = await Promise.all([
    AudinexiaAuth.authFetch(`/api/control-results/${crId}`),
    fetchOrgUsers(),
  ]);
  if (!reviewRes.ok) {
    body.innerHTML = '<em style="color:var(--danger);font-size:12px">Could not load review state.</em>';
    return;
  }
  const r = await reviewRes.json();

  const userOptions = users.map(u =>
    `<option value="${esc(u.id)}" ${r.assigned_to_id === u.id ? 'selected' : ''}>${esc(u.name)} (${esc(u.role.replace(/_/g,' '))})</option>`
  ).join('');

  // The scanner's status is phrase-match coverage, not an audit verdict: every
  // result starts 'unreviewed' and should read as provisional until a human
  // confirms or overrides it, not look identical to a reviewed one.
  const provisionalBanner = r.reviewer_status === 'unreviewed'
    ? `<div style="background:var(--warn-bg);color:#92400e;border:1px solid var(--warn);border-radius:8px;padding:8px 12px;font-size:11.5px;font-weight:600;margin-bottom:12px">
         ⚠️ Provisional — this is language-match coverage, not a confirmed finding. Review it below.
       </div>`
    : `<div style="background:var(--success-bg);color:#065f46;border:1px solid var(--success);border-radius:8px;padding:8px 12px;font-size:11.5px;font-weight:600;margin-bottom:12px">
         ✓ ${r.reviewer_status === 'overridden' ? 'Overridden' : 'Confirmed'} by ${esc(r.reviewed_by_name || 'a reviewer')}${r.reviewed_at ? ' on ' + esc(new Date(r.reviewed_at).toLocaleDateString()) : ''}
       </div>`;

  body.innerHTML = `
    ${provisionalBanner}
    <div class="modal-row">
      <div class="modal-field">
        <div class="field-label">Reviewer Status</div>
        <select class="config-input" id="reviewStatusInput" style="margin-bottom:0">
          <option value="unreviewed" ${r.reviewer_status==='unreviewed'?'selected':''}>Unreviewed</option>
          <option value="confirmed" ${r.reviewer_status==='confirmed'?'selected':''}>Confirmed</option>
          <option value="overridden" ${r.reviewer_status==='overridden'?'selected':''}>Overridden</option>
        </select>
      </div>
      <div class="modal-field">
        <div class="field-label">Assign To</div>
        <select class="config-input" id="assigneeInput" style="margin-bottom:0">
          <option value="">— Unassigned —</option>
          ${userOptions}
        </select>
      </div>
    </div>
    <div class="modal-row">
      <div class="modal-field">
        <div class="field-label">Due Date</div>
        <input class="config-input" type="date" id="dueDateInput" value="${esc(r.due_date || '')}" style="margin-bottom:0">
      </div>
      <div class="modal-field">
        ${!isCompliant ? `
        <div class="field-label">Remediation Status</div>
        <select class="config-input" id="remediationStatusInput" style="margin-bottom:0">
          <option value="open" ${r.remediation_status==='open'?'selected':''}>Open</option>
          <option value="in_progress" ${r.remediation_status==='in_progress'?'selected':''}>In Progress</option>
          <option value="closed" ${r.remediation_status==='closed'?'selected':''}>Closed</option>
        </select>` : ''}
      </div>
    </div>
    <div class="field-label" style="margin:10px 0 6px">Reviewer Note</div>
    <textarea class="config-input" id="reviewerNoteInput" rows="2" style="resize:vertical">${esc(r.reviewer_note || '')}</textarea>
    ${r.reviewed_by_name ? `<div style="font-size:11.5px;color:var(--muted);margin-bottom:10px">Last reviewed by ${esc(r.reviewed_by_name)}${esc(r.reviewed_at ? ' on ' + new Date(r.reviewed_at).toLocaleString() : '')}</div>` : ''}
    <button class="btn btn-primary btn-sm" data-action="saveReview" data-args="${esc(JSON.stringify([crId, isCompliant]))}">💾 Save Review</button>`;
}

window.saveReview = async (crId, isCompliant) => {
  const body = {
    reviewer_status: document.getElementById('reviewStatusInput').value,
    reviewer_note: document.getElementById('reviewerNoteInput').value,
    assigned_to_id: document.getElementById('assigneeInput').value ? parseInt(document.getElementById('assigneeInput').value, 10) : null,
    due_date: document.getElementById('dueDateInput').value || null,
  };
  if (!isCompliant) {
    const remEl = document.getElementById('remediationStatusInput');
    if (remEl) body.remediation_status = remEl.value;
  }
  try {
    const res = await AudinexiaAuth.authFetch(`/api/control-results/${crId}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      const d = await res.json().catch(() => ({}));
      showToast(`Review save failed: ${d.error || res.status}`);
      setTimeout(hideToast, 2500);
      return;
    }
    showToast('✅ Review saved');
    setTimeout(hideToast, 1800);
    renderReviewSection(crId, isCompliant ? 'Language found' : 'Not found');
  } catch (e) {
    showToast('Could not reach server');
    setTimeout(hideToast, 2500);
  }
};

async function renderEvidenceSection(crId) {
  const body = document.getElementById('evidenceSectionBody');
  if (!body) return;
  try {
    const res = await AudinexiaAuth.authFetch(`/api/control-results/${crId}/evidence`);
    if (!res.ok) { body.innerHTML = '<em style="color:var(--danger);font-size:12px">Could not load evidence.</em>'; return; }
    const data = await res.json();
    const canUpload = canUploadEvidence();
    const canDelete = canDeleteEvidence();

    const listHtml = (data.evidence||[]).length
      ? data.evidence.map(f => `
        <div style="display:flex;align-items:center;gap:8px;padding:6px 0;border-bottom:1px solid var(--border)">
          <span style="flex:1;font-size:12.5px">📄 ${esc(f.original_filename)} <span style="color:var(--muted);font-size:11px">(${(f.file_size/1024).toFixed(1)} KB · ${esc(f.uploaded_by_name||'unknown')} · ${esc(new Date(f.uploaded_at).toLocaleDateString())})</span></span>
          <button class="btn btn-secondary btn-sm" data-filename="${esc(f.original_filename)}" data-action="downloadEvidence" data-args="${esc(JSON.stringify([Number(f.id)]))}">⬇</button>
          ${canDelete ? `<button class="btn btn-secondary btn-sm" data-action="deleteEvidence" data-args="${esc(JSON.stringify([f.id, crId]))}">🗑</button>` : ''}
        </div>`).join('')
      : '<em style="color:var(--muted);font-size:12px">No evidence uploaded yet.</em>';

    body.innerHTML = `
      <div style="margin-bottom:10px">${listHtml}</div>
      ${canUpload ? `
      <div style="display:flex;gap:8px;align-items:center">
        <input type="file" id="evidenceFileInput" style="flex:1;font-size:12px">
        <button class="btn btn-primary btn-sm" data-action="uploadEvidence" data-args="${esc(JSON.stringify([crId]))}">⬆ Upload</button>
      </div>` : ''}`;
  } catch (e) {
    body.innerHTML = '<em style="color:var(--danger);font-size:12px">Could not load evidence.</em>';
  }
}

window.uploadEvidence = async crId => {
  const input = document.getElementById('evidenceFileInput');
  if (!input || !input.files.length) { showToast('Choose a file first'); setTimeout(hideToast, 1800); return; }
  const fd = new FormData();
  fd.append('file', input.files[0]);
  try {
    const res = await AudinexiaAuth.authFetch(`/api/control-results/${crId}/evidence`, { method: 'POST', body: fd });
    if (!res.ok) {
      const d = await res.json().catch(() => ({}));
      showToast(`Upload failed: ${d.error || res.status}`);
      setTimeout(hideToast, 2500);
      return;
    }
    showToast('✅ Evidence uploaded');
    setTimeout(hideToast, 1800);
    renderEvidenceSection(crId);
  } catch (e) {
    showToast('Could not reach server');
    setTimeout(hideToast, 2500);
  }
};

window.downloadEvidence = async (evidenceId, btn) => {
  const filename = btn.dataset.filename; // read from a data attribute, never from handler source
  try {
    const res = await AudinexiaAuth.authFetch(`/api/evidence/${evidenceId}/download`);
    if (!res.ok) { showToast('Download failed'); setTimeout(hideToast, 1800); return; }
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = filename;
    document.body.appendChild(a); a.click(); document.body.removeChild(a);
    URL.revokeObjectURL(url);
  } catch (e) {
    showToast('Could not reach server');
    setTimeout(hideToast, 1800);
  }
};

window.deleteEvidence = async (evidenceId, crId) => {
  if (!confirm('Delete this evidence file? This cannot be undone.')) return;
  try {
    const res = await AudinexiaAuth.authFetch(`/api/evidence/${evidenceId}`, { method: 'DELETE' });
    if (!res.ok) { showToast('Delete failed'); setTimeout(hideToast, 1800); return; }
    showToast('🗑 Evidence deleted');
    setTimeout(hideToast, 1500);
    renderEvidenceSection(crId);
  } catch (e) {
    showToast('Could not reach server');
    setTimeout(hideToast, 1800);
  }
};

/* ── Approval workflows (risk acceptance, finding closure, audit reopen/withdraw) ──
   Each of these goes through its own endpoint with a written reason, so the
   server can enforce segregation of duties and write the audit trail. The UI
   only decides what to offer; the API still refuses anything not permitted. */
function currentUserId() {
  const u = AudinexiaAuth.getCurrentUser();
  return u ? u.id : null;
}
function fieldValue(id) {
  const el = document.getElementById(id);
  return el ? el.value.trim() : '';
}
async function workflowPost(url, body, method) {
  try {
    const res = await AudinexiaAuth.authFetch(url, {
      method: method || 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body || {}),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      showToast(data.error || `Request failed (${res.status})`);
      setTimeout(hideToast, 3500);
      return null;
    }
    return data;
  } catch (e) {
    showToast('Could not reach server');
    setTimeout(hideToast, 1800);
    return null;
  }
}
function workflowDone(msg) {
  showToast(msg);
  setTimeout(hideToast, 1800);
}
function pendingBanner(text, detail) {
  return `<div class="wf-box wf-pending"><strong>${esc(text)}</strong>${detail ? `<div class="wf-detail">${esc(detail)}</div>` : ''}</div>`;
}

/* ══════════════════════════ RISK REGISTER ══════════════════════════ */
const MAX_RISK_ACCEPTANCE_MONTHS = 12;   // mirrors the server's cap; the server enforces it
const LIKELIHOOD_LEVELS = { 1: 'Rare', 2: 'Unlikely', 3: 'Possible', 4: 'Likely', 5: 'Almost Certain' };
const IMPACT_LEVELS = { 1: 'Negligible', 2: 'Minor', 3: 'Moderate', 4: 'Major', 5: 'Severe' };

function canManageRisks() {
  const user = AudinexiaAuth.getCurrentUser();
  return !!user && ['org_admin', 'compliance_manager', 'auditor'].includes(user.role);
}
function isRiskOwner(risk) {
  const user = AudinexiaAuth.getCurrentUser();
  return !!user && user.role === 'member' && risk.owner_id === user.id;
}
function riskLevelBadgeClass(level) {
  return level === 'Low' ? 'badge-green' : level === 'Medium' ? 'badge-yellow'
       : level === 'High' ? 'badge-orange' : 'badge-red';
}

/* ── Risk Register page (list) ── */
async function loadRisks() {
  document.getElementById('newRiskBtn').style.display = canManageRisks() ? '' : 'none';
  const tbody = document.getElementById('risksTableBody');
  try {
    const res = await AudinexiaAuth.authFetch('/api/risks');
    if (!res.ok) {
      tbody.innerHTML = '<tr><td colspan="8" style="text-align:center;color:var(--danger);padding:20px">Could not load risks</td></tr>';
      return;
    }
    const data = await res.json();
    const rows = data.risks || [];
    if (!rows.length) {
      tbody.innerHTML = '<tr><td colspan="8" style="text-align:center;color:var(--muted);padding:20px">No risks tracked yet.</td></tr>';
      return;
    }
    tbody.innerHTML = rows.map(r => `
      <tr style="cursor:pointer" data-action="openRiskModal" data-args="${esc(JSON.stringify([r.id]))}">
        <td style="max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(r.description)}</td>
        <td>${esc(r.likelihood)} · ${esc(LIKELIHOOD_LEVELS[r.likelihood] || '')}</td>
        <td>${esc(r.impact)} · ${esc(IMPACT_LEVELS[r.impact] || '')}</td>
        <td style="font-weight:700">${esc(r.risk_score)}</td>
        <td><span class="badge ${esc(riskLevelBadgeClass(r.risk_level))}">${esc(r.risk_level)}</span></td>
        <td>${esc(r.owner_name || '—')}</td>
        <td style="text-transform:capitalize">${esc(r.status.replace('_',' '))}</td>
        <td>${esc(r.review_date || '—')}</td>
      </tr>`).join('');
  } catch (e) {
    tbody.innerHTML = '<tr><td colspan="8" style="text-align:center;color:var(--danger);padding:20px">Could not reach server</td></tr>';
  }
}

/* ── Risk create/edit modal (reuses the #modal overlay) ── */
window.openRiskModal = async (riskIdOrNull, prefill) => {
  let risk = null;
  if (typeof riskIdOrNull === 'number') {
    try {
      const res = await AudinexiaAuth.authFetch(`/api/risks/${riskIdOrNull}`);
      if (res.ok) risk = await res.json();
    } catch (e) { /* fall through to blank form */ }
  }

  const users = await fetchOrgUsers();
  const isNew = !risk;
  const manage = canManageRisks();
  const ownerEdit = risk && isRiskOwner(risk);
  const readOnly = !isNew && !manage && !ownerEdit;

  document.getElementById('modalTitle').textContent = isNew ? 'New Risk' : `Risk #${risk.id}`;

  const likelihoodOptions = ['<option value="">Select…</option>']
    .concat(Object.entries(LIKELIHOOD_LEVELS).map(([v, l]) =>
      `<option value="${esc(v)}" ${risk && risk.likelihood == v ? 'selected' : ''}>${esc(v)} — ${esc(l)}</option>`)).join('');
  const impactOptions = ['<option value="">Select…</option>']
    .concat(Object.entries(IMPACT_LEVELS).map(([v, l]) =>
      `<option value="${esc(v)}" ${risk && risk.impact == v ? 'selected' : ''}>${esc(v)} — ${esc(l)}</option>`)).join('');
  const ownerOptions = ['<option value="">Unassigned</option>']
    .concat(users.map(u => `<option value="${esc(u.id)}" ${risk && risk.owner_id === u.id ? 'selected' : ''}>${esc(u.name)}</option>`)).join('');
  // Nobody can set 'accepted' directly: it goes through the request/approve
  // workflow below. An owner also can't set 'closed'; a manager can. A risk's
  // current status always stays listed so a save leaves it unchanged.
  const directStatuses = ownerEdit ? ['open', 'mitigating'] : ['open', 'mitigating', 'closed'];
  const statusChoices = (risk && !directStatuses.includes(risk.status))
    ? directStatuses.concat([risk.status]) : directStatuses;
  const statusOptions = statusChoices
    .map(s => `<option value="${esc(s)}" ${risk && risk.status === s ? 'selected' : ''}>${esc(s)}</option>`).join('');

  const scoreFieldsDisabled = (manage || isNew) ? '' : 'disabled';
  const linkedHtml = risk && risk.linked_controls.length
    ? risk.linked_controls.map(l => `
        <div style="display:flex;justify-content:space-between;align-items:center;padding:4px 0;font-size:12px">
          <span>${esc(l.control_id)} — ${esc(l.control_name)} (${esc(l.framework)})</span>
          ${manage ? `<button class="btn btn-secondary btn-sm" data-action="unlinkRiskControl" data-args="${esc(JSON.stringify([risk.id, l.control_result_id]))}">✕</button>` : ''}
        </div>`).join('')
    : '<em style="color:var(--muted);font-size:12px">No linked controls.</em>';

  document.getElementById('modalBody').innerHTML = `
    <div class="modal-field" style="margin-bottom:10px">
      <div class="field-label">Description</div>
      <textarea id="riskDescription" rows="3" style="width:100%;font-family:inherit;font-size:13px;padding:8px;border:1px solid var(--border);border-radius:6px" ${scoreFieldsDisabled}>${esc(risk ? risk.description : (prefill?.description || ''))}</textarea>
    </div>
    <div class="modal-row">
      <div class="modal-field"><div class="field-label">Likelihood</div>
        <select id="riskLikelihood" style="width:100%;padding:6px" ${scoreFieldsDisabled}>${likelihoodOptions}</select>
      </div>
      <div class="modal-field"><div class="field-label">Impact</div>
        <select id="riskImpact" style="width:100%;padding:6px" ${scoreFieldsDisabled}>${impactOptions}</select>
      </div>
      <div class="modal-field"><div class="field-label">Risk Score</div>
        <div class="field-val">${risk ? `${esc(risk.risk_score)} (${esc(risk.risk_level)})` : '—'}</div>
      </div>
    </div>
    <div class="modal-row">
      <div class="modal-field"><div class="field-label">Owner</div>
        <select id="riskOwner" style="width:100%;padding:6px" ${scoreFieldsDisabled}>${ownerOptions}</select>
      </div>
      <div class="modal-field"><div class="field-label">Status</div>
        <select id="riskStatus" style="width:100%;padding:6px" ${readOnly ? 'disabled' : ''}>${statusOptions}</select>
      </div>
      <div class="modal-field"><div class="field-label">Review Date</div>
        <input type="date" id="riskReviewDate" style="width:100%;padding:6px" value="${esc(risk?.review_date || '')}" ${scoreFieldsDisabled}>
      </div>
    </div>
    <div class="modal-field" style="margin:10px 0">
      <div class="field-label">Mitigation Notes</div>
      <textarea id="riskMitigation" rows="2" style="width:100%;font-family:inherit;font-size:13px;padding:8px;border:1px solid var(--border);border-radius:6px" ${readOnly ? 'disabled' : ''}>${esc(risk?.mitigation || '')}</textarea>
    </div>
    ${!isNew ? `<div class="field-label" style="margin:12px 0 6px">Linked Controls</div><div>${linkedHtml}</div>` : ''}
    ${renderRiskWorkflow(risk, manage, ownerEdit)}
    ${readOnly ? '<em style="color:var(--muted);font-size:12px">View only — you are not the owner of this risk.</em>' : `
    <div style="display:flex;gap:8px;margin-top:14px">
      <button class="btn btn-primary btn-sm" data-action="saveRisk" data-args="${esc(JSON.stringify([risk ? risk.id : null]))}">💾 Save</button>
      ${!isNew && manage ? `<button class="btn btn-secondary btn-sm" data-action="deleteRiskFromModal" data-args="${esc(JSON.stringify([risk.id]))}">🗑 Delete</button>` : ''}
    </div>`}`;

  document.getElementById('modal').classList.add('open');
};

function renderRiskWorkflow(risk, manage, ownerEdit) {
  if (!risk) return '';
  let html = '';
  if (risk.status === 'accepted' && risk.risk_acceptance_expires_at) {
    const expired = risk.risk_acceptance_expires_at < new Date().toISOString().slice(0, 10);
    html += expired
      ? `<div class="wf-box wf-pending"><strong>Acceptance expired on ${esc(risk.risk_acceptance_expires_at)}.</strong>
         <div class="wf-detail">The status is not changed automatically: re-review this risk and set its status or request acceptance again.</div></div>`
      : `<div class="wf-box">Risk accepted until <strong>${esc(risk.risk_acceptance_expires_at)}</strong>. The status is not changed automatically on that date; re-review it before then.</div>`;
  }
  if (risk.pending_action === 'risk_acceptance') {
    const when = risk.pending_requested_at ? new Date(risk.pending_requested_at).toLocaleDateString() : '';
    html += pendingBanner(
      `Risk acceptance requested by ${risk.pending_requested_by_name || 'a user'}${when ? ' on ' + when : ''}, until ${risk.pending_expiry_date || '?'}`,
      risk.pending_reason);
    if (manage && risk.owner_id !== currentUserId() && risk.pending_requested_by_id !== currentUserId()) {
      html += `
        <div class="wf-box">
          <div class="field-label">Decision note (optional)</div>
          <input id="riskDecisionReason" class="wf-input" maxlength="500">
          <div class="wf-actions">
            <button class="btn btn-primary btn-sm" data-action="resolveRiskAcceptance" data-args="${esc(JSON.stringify([risk.id, 'approve']))}">Approve acceptance</button>
            <button class="btn btn-secondary btn-sm" data-action="resolveRiskAcceptance" data-args="${esc(JSON.stringify([risk.id, 'reject']))}">Reject</button>
          </div>
          <div class="wf-detail">The person who requested this, and the risk's owner, cannot decide it.</div>
        </div>`;
    } else {
      html += '<div class="wf-detail" style="margin-bottom:8px">Waiting for a different manager to approve or reject.</div>';
    }
  } else if (risk.status !== 'accepted' && risk.status !== 'closed' && (manage || ownerEdit)) {
    html += `
      <div class="wf-box">
        <div class="field-label">Request risk acceptance</div>
        <textarea id="riskAcceptReason" rows="2" class="wf-input" placeholder="Written justification (required)"></textarea>
        <div class="wf-actions">
          <label class="wf-detail">Accept until
            <input type="date" id="riskAcceptExpiry" class="wf-input" style="width:auto"></label>
          <button class="btn btn-secondary btn-sm" data-action="requestRiskAcceptance" data-args="${esc(JSON.stringify([risk.id]))}">Submit for approval</button>
        </div>
        <div class="wf-detail">At most ${MAX_RISK_ACCEPTANCE_MONTHS} months out. A different manager must approve it.</div>
      </div>`;
  }
  return html;
}

window.requestRiskAcceptance = async riskId => {
  const data = await workflowPost(`/api/risks/${riskId}/request-risk-acceptance`, {
    reason: fieldValue('riskAcceptReason'),
    expiry_date: fieldValue('riskAcceptExpiry'),
  });
  if (!data) return;
  workflowDone('Risk acceptance submitted for approval');
  openRiskModal(riskId);
  loadRisks();
};

window.resolveRiskAcceptance = async (riskId, decision) => {
  const data = await workflowPost(`/api/risks/${riskId}/${decision}-risk-acceptance`,
                                  { reason: fieldValue('riskDecisionReason') });
  if (!data) return;
  workflowDone(decision === 'approve' ? 'Risk acceptance approved' : 'Risk acceptance rejected');
  openRiskModal(riskId);
  loadRisks();
};

window.saveRisk = async riskId => {
  const isNew = !riskId;
  const manage = canManageRisks();
  let body = {};

  if (manage || isNew) {
    body = {
      description: document.getElementById('riskDescription').value,
      likelihood: parseInt(document.getElementById('riskLikelihood').value, 10),
      impact: parseInt(document.getElementById('riskImpact').value, 10),
      owner_id: document.getElementById('riskOwner').value ? parseInt(document.getElementById('riskOwner').value, 10) : null,
      status: document.getElementById('riskStatus').value,
      mitigation: document.getElementById('riskMitigation').value,
      review_date: document.getElementById('riskReviewDate').value || null,
    };
    if (isNew && window._riskCreatePrefillCrId) {
      body.control_result_ids = [window._riskCreatePrefillCrId];
    }
  } else {
    // Owner-only path: the API rejects any other key, so only send these two.
    body = {
      status: document.getElementById('riskStatus').value,
      mitigation: document.getElementById('riskMitigation').value,
    };
  }

  try {
    const res = await AudinexiaAuth.authFetch(isNew ? '/api/risks' : `/api/risks/${riskId}`, {
      method: isNew ? 'POST' : 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      const d = await res.json().catch(() => ({}));
      showToast(`Save failed: ${d.error || res.status}`);
      setTimeout(hideToast, 2800);
      return;
    }
    showToast('✅ Risk saved');
    setTimeout(hideToast, 1500);
    window._riskCreatePrefillCrId = null;
    document.getElementById('modal').classList.remove('open');
    if (document.getElementById('page-risk-register').classList.contains('active')) loadRisks();
  } catch (e) {
    showToast('Could not reach server');
    setTimeout(hideToast, 1800);
  }
};

window.deleteRiskFromModal = async riskId => {
  if (!confirm('Delete this risk? This cannot be undone.')) return;
  try {
    const res = await AudinexiaAuth.authFetch(`/api/risks/${riskId}`, { method: 'DELETE' });
    if (!res.ok) { showToast('Delete failed'); setTimeout(hideToast, 1800); return; }
    showToast('🗑 Risk deleted');
    setTimeout(hideToast, 1500);
    document.getElementById('modal').classList.remove('open');
    if (document.getElementById('page-risk-register').classList.contains('active')) loadRisks();
  } catch (e) {
    showToast('Could not reach server');
    setTimeout(hideToast, 1800);
  }
};

window.unlinkRiskControl = async (riskId, crId) => {
  try {
    const res = await AudinexiaAuth.authFetch(`/api/risks/${riskId}/links/${crId}`, { method: 'DELETE' });
    if (!res.ok) { showToast('Unlink failed'); setTimeout(hideToast, 1800); return; }
    openRiskModal(riskId);
  } catch (e) {
    showToast('Could not reach server');
    setTimeout(hideToast, 1800);
  }
};

/* ── "Risks" section inside the control-detail modal ── */
async function renderRiskSection(crId, controlName) {
  const body = document.getElementById('riskSectionBody');
  if (!body) return;
  try {
    const res = await AudinexiaAuth.authFetch('/api/risks');
    const data = res.ok ? await res.json() : { risks: [] };
    const linked = (data.risks || []).filter(r => r.linked_controls.some(l => l.control_result_id === crId));

    const listHtml = linked.length
      ? linked.map(r => `
        <div style="display:flex;justify-content:space-between;align-items:center;padding:5px 0;border-bottom:1px solid var(--border)">
          <span style="font-size:12.5px;cursor:pointer" data-action="openRiskModal" data-args="${esc(JSON.stringify([r.id]))}">${esc(r.description.substring(0, 60))}${r.description.length > 60 ? '…' : ''}</span>
          <span class="badge ${esc(riskLevelBadgeClass(r.risk_level))}">${esc(r.risk_level)}</span>
        </div>`).join('')
      : '<em style="color:var(--muted);font-size:12px">No risks linked to this control yet.</em>';

    body.innerHTML = `
      <div style="margin-bottom:10px">${listHtml}</div>
      ${canManageRisks() ? `<button class="btn btn-secondary btn-sm" data-control-name="${esc(controlName||'')}" data-action="createRiskFromControl" data-args="${esc(JSON.stringify([Number(crId)]))}">+ Create risk from this control</button>` : ''}`;
  } catch (e) {
    body.innerHTML = '<em style="color:var(--danger);font-size:12px">Could not load risks.</em>';
  }
}

/* ── "Findings" section inside the control-detail modal (read-only list;
   linking a NEW finding to a control happens from the audit side via the
   optional control_result_id field on the add-finding form, not from here --
   keeps this section simple, no searchable audit picker needed). ── */
async function renderFindingSection(crId) {
  const body = document.getElementById('findingSectionBody');
  if (!body) return;
  try {
    const res = await AudinexiaAuth.authFetch('/api/audits?include_findings=true');
    const data = res.ok ? await res.json() : { audits: [] };
    const linked = [];
    (data.audits || []).forEach(a => {
      (a.findings || []).forEach(f => {
        if (f.linked_controls.some(l => l.control_result_id === crId)) linked.push(f);
      });
    });

    body.innerHTML = linked.length
      ? linked.map(f => `
        <div style="display:flex;justify-content:space-between;align-items:center;padding:5px 0;border-bottom:1px solid var(--border)">
          <span style="font-size:12.5px;cursor:pointer" data-action="openAuditModal" data-args="${esc(JSON.stringify([f.audit_id]))}">${esc(f.description.substring(0, 60))}${f.description.length > 60 ? '…' : ''}</span>
          <span class="badge ${esc(findingSeverityBadgeClass(f.severity))}">${esc(f.severity)}</span>
        </div>`).join('')
      : '<em style="color:var(--muted);font-size:12px">No findings linked to this control yet — link one from an audit\'s finding form.</em>';
  } catch (e) {
    body.innerHTML = '<em style="color:var(--danger);font-size:12px">Could not load findings.</em>';
  }
}

window.createRiskFromControl = async (crId, btn) => {
  const controlName = btn && btn.dataset ? btn.dataset.controlName : '';
  let suggestedDescription = controlName || '';
  try {
    const res = await AudinexiaAuth.authFetch(`/api/control-results/${crId}/risk-suggestion`);
    if (res.ok) {
      const d = await res.json();
      suggestedDescription = d.suggested_description;
    }
  } catch (e) { /* fall back to controlName */ }
  window._riskCreatePrefillCrId = crId;
  openRiskModal(null, { description: suggestedDescription });
};

/* ══════════════════════════ AUDIT MANAGEMENT ══════════════════════════ */
const FINDING_SEVERITIES = ['critical', 'high', 'medium', 'low'];
const FINDING_STATUSES = ['open', 'in_remediation', 'resolved', 'accepted_risk', 'closed'];
const FINDING_CLOSING_STATUSES = ['resolved', 'accepted_risk', 'closed'];
const AUDIT_STATUSES = ['planned', 'in_progress', 'completed', 'closed'];   // 'withdrawn' is reached only via the withdraw action

function canManageAudits() {
  const user = AudinexiaAuth.getCurrentUser();
  return !!user && ['org_admin', 'compliance_manager', 'auditor'].includes(user.role);
}
function isFindingOwner(finding) {
  const user = AudinexiaAuth.getCurrentUser();
  return !!user && user.role === 'member' && finding.owner_id === user.id;
}
// Reuses Risk's four badge colors 1:1 for Finding severity -- both are
//4-band scales, no new CSS needed.
function findingSeverityBadgeClass(severity) {
  return severity === 'low' ? 'badge-blue' : severity === 'medium' ? 'badge-yellow'
       : severity === 'high' ? 'badge-orange' : 'badge-red';
}

/* ── Audit Management page (list + client-side dashboard stats) ── */
async function loadAudits() {
  document.getElementById('newAuditBtn').style.display = canManageAudits() ? '' : 'none';
  const tbody = document.getElementById('auditsTableBody');
  const statsEl = document.getElementById('auditDashboardStats');
  try {
    const res = await AudinexiaAuth.authFetch('/api/audits');
    if (!res.ok) {
      tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--danger);padding:20px">Could not load audits</td></tr>';
      return;
    }
    const data = await res.json();
    const audits = data.audits || [];

    // Client-side aggregation over the already-fetched list -- no dedicated
    // dashboard endpoint, same call Phase 3 made for the crosswalk summary.
    const openAudits = audits.filter(a => a.status !== 'closed').length;
    const counts = { critical: 0, high: 0, medium: 0, low: 0 };
    audits.forEach(a => { FINDING_SEVERITIES.forEach(s => { counts[s] += a.finding_counts[s] || 0; }); });
    statsEl.innerHTML = `
      <div class="modal-field"><div class="field-label">Open Audits</div><div class="field-val" style="font-size:22px">${esc(openAudits)}</div></div>
      <div class="modal-field"><div class="field-label">Critical Findings</div><div class="field-val" style="font-size:22px;color:var(--danger)">${esc(counts.critical)}</div></div>
      <div class="modal-field"><div class="field-label">High Findings</div><div class="field-val" style="font-size:22px;color:#c2410c">${esc(counts.high)}</div></div>
      <div class="modal-field"><div class="field-label">Medium Findings</div><div class="field-val" style="font-size:22px;color:var(--warn)">${esc(counts.medium)}</div></div>
      <div class="modal-field"><div class="field-label">Low Findings</div><div class="field-val" style="font-size:22px;color:var(--info)">${esc(counts.low)}</div></div>`;

    if (!audits.length) {
      tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--muted);padding:20px">No audits yet.</td></tr>';
      return;
    }
    tbody.innerHTML = audits.map(a => {
      const fc = a.finding_counts;
      const badges = FINDING_SEVERITIES.filter(s => fc[s] > 0)
        .map(s => `<span class="badge ${esc(findingSeverityBadgeClass(s))}" style="margin-right:3px">${esc(fc[s])} ${esc(s)}</span>`).join('')
        || '<span style="color:var(--muted);font-size:12px">none</span>';
      return `
      <tr style="cursor:pointer" data-action="openAuditModal" data-args="${esc(JSON.stringify([a.id]))}">
        <td style="max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-weight:600">${esc(a.title)}</td>
        <td>${esc(a.lead_auditor_name || '—')}</td>
        <td><span class="badge ${a.status === 'closed' ? 'badge-green' : 'badge-blue'}" style="text-transform:capitalize">${esc(a.status.replace('_',' '))}</span></td>
        <td>${badges}</td>
        <td style="color:var(--muted);font-size:12px">${esc(a.start_date || '—')} → ${esc(a.end_date || '—')}</td>
      </tr>`;
    }).join('');
  } catch (e) {
    tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--danger);padding:20px">Could not reach server</td></tr>';
  }
}

/* ── Audit create/edit modal (reuses the #modal overlay); Findings render
   as an in-place accordion within the same modal body -- no second modal. ── */
window._currentAuditId = null;

window.openAuditModal = async (auditIdOrNull) => {
  let audit = null;
  if (typeof auditIdOrNull === 'number') {
    try {
      const res = await AudinexiaAuth.authFetch(`/api/audits/${auditIdOrNull}`);
      if (res.ok) audit = await res.json();
    } catch (e) { /* fall through to blank form */ }
  }
  window._currentAuditId = audit ? audit.id : null;
  window._currentAuditStatus = audit ? audit.status : null;

  const users = await fetchOrgUsers();
  const isNew = !audit;
  const isClosed = !!audit && audit.status === 'closed';
  const isWithdrawn = !!audit && audit.status === 'withdrawn';
  const frozen = isClosed || isWithdrawn;          // no edits until an org_admin reopens a closed audit
  const manage = canManageAudits() && !frozen;

  document.getElementById('modalTitle').textContent = isNew ? 'New Audit' : audit.title;

  const leadOptions = ['<option value="">Unassigned</option>']
    .concat(users.map(u => `<option value="${esc(u.id)}" ${audit && audit.lead_auditor_id === u.id ? 'selected' : ''}>${esc(u.name)}</option>`)).join('');
  const statusOptions = (isWithdrawn ? AUDIT_STATUSES.concat(['withdrawn']) : AUDIT_STATUSES)
    .map(s => `<option value="${esc(s)}" ${audit && audit.status === s ? 'selected' : ''}>${esc(s.replace('_',' '))}</option>`).join('');
  const fieldsDisabled = manage ? '' : 'disabled';

  document.getElementById('modalBody').innerHTML = `
    ${renderAuditStateBanner(audit)}
    <div class="modal-field" style="margin-bottom:10px">
      <div class="field-label">Title</div>
      <input id="auditTitle" style="width:100%;padding:8px;border:1px solid var(--border);border-radius:6px" value="${esc(audit ? audit.title : '')}" ${fieldsDisabled}>
    </div>
    <div class="modal-field" style="margin-bottom:10px">
      <div class="field-label">Scope Description</div>
      <textarea id="auditScope" rows="2" style="width:100%;font-family:inherit;font-size:13px;padding:8px;border:1px solid var(--border);border-radius:6px" ${fieldsDisabled}>${esc(audit?.scope_description || '')}</textarea>
    </div>
    <div class="modal-row">
      <div class="modal-field"><div class="field-label">Lead Auditor</div>
        <select id="auditLead" style="width:100%;padding:6px" ${fieldsDisabled}>${leadOptions}</select>
      </div>
      <div class="modal-field"><div class="field-label">Status</div>
        <select id="auditStatus" style="width:100%;padding:6px" ${(!manage || isNew) ? 'disabled' : ''}>${statusOptions}</select>
      </div>
    </div>
    <div class="modal-row">
      <div class="modal-field"><div class="field-label">Start Date</div>
        <input type="date" id="auditStart" style="width:100%;padding:6px" value="${esc(audit?.start_date || '')}" ${fieldsDisabled}>
      </div>
      <div class="modal-field"><div class="field-label">End Date</div>
        <input type="date" id="auditEnd" style="width:100%;padding:6px" value="${esc(audit?.end_date || '')}" ${fieldsDisabled}>
      </div>
    </div>
    ${manage ? `
    <div style="display:flex;gap:8px;margin:14px 0">
      <button class="btn btn-primary btn-sm" data-action="saveAudit" data-args="${esc(JSON.stringify([audit ? audit.id : null]))}">💾 Save</button>
      ${!isNew && audit.status === 'planned' ? `<button class="btn btn-secondary btn-sm" data-action="deleteAuditFromModal" data-args="${esc(JSON.stringify([audit.id]))}">🗑 Delete</button>` : ''}
    </div>` : '<div style="margin:14px 0"></div>'}
    ${renderAuditStateActions(audit)}
    ${!isNew ? `
    <div style="margin-top:10px;padding-top:14px;border-top:1px solid var(--border)">
      <div class="field-label" style="margin-bottom:8px">Findings</div>
      <div id="findingsListBody"></div>
      ${manage ? `<button class="btn btn-secondary btn-sm" style="margin-top:8px" data-action="toggleNewFindingForm">+ Add Finding</button>
      <div id="newFindingForm" style="display:none;margin-top:10px"></div>` : ''}
    </div>` : ''}`;

  document.getElementById('modal').classList.add('open');

  if (!isNew) renderFindingsList(audit);
};

function renderAuditStateBanner(audit) {
  if (!audit) return '';
  if (audit.status === 'closed') {
    const when = audit.closed_at ? new Date(audit.closed_at).toLocaleDateString() : '';
    return `<div class="wf-box wf-locked"><strong>🔒 Closed${when ? ' on ' + esc(when) : ''}${audit.closed_by_name ? ' by ' + esc(audit.closed_by_name) : ''}.</strong>
      <div class="wf-detail">The audit and its findings are locked. Only an org_admin can reopen it, with a written reason.</div></div>`;
  }
  if (audit.status === 'withdrawn') {
    return `<div class="wf-box wf-locked"><strong>Withdrawn.</strong>
      <div class="wf-detail">This audit was withdrawn and is kept for the record; it can't be edited or deleted.</div></div>`;
  }
  return '';
}

function renderAuditStateActions(audit) {
  if (!audit) return '';
  const me = AudinexiaAuth.getCurrentUser();
  if (audit.status === 'closed' && me && me.role === 'org_admin') {
    return `<div class="wf-box">
      <div class="field-label">Reopen this audit</div>
      <input id="auditStateReason" class="wf-input" placeholder="Reason (required, recorded in the audit trail)" maxlength="500">
      <div class="wf-actions"><button class="btn btn-secondary btn-sm" data-action="reopenAudit" data-args="${esc(JSON.stringify([audit.id]))}">Reopen audit</button></div>
    </div>`;
  }
  if (canManageAudits() && ['in_progress', 'completed'].includes(audit.status)) {
    return `<div class="wf-box">
      <div class="field-label">Withdraw this audit</div>
      <input id="auditStateReason" class="wf-input" placeholder="Reason (required, recorded in the audit trail)" maxlength="500">
      <div class="wf-actions"><button class="btn btn-secondary btn-sm" data-action="withdrawAudit" data-args="${esc(JSON.stringify([audit.id]))}">Withdraw audit</button></div>
      <div class="wf-detail">Only a planned audit can be deleted. Once work has started, it is withdrawn and kept on record.</div>
    </div>`;
  }
  return '';
}

window.reopenAudit = async auditId => {
  const data = await workflowPost(`/api/audits/${auditId}`,
    { status: 'in_progress', reason: fieldValue('auditStateReason') }, 'PATCH');
  if (!data) return;
  workflowDone('Audit reopened');
  openAuditModal(auditId);
  if (document.getElementById('page-audits').classList.contains('active')) loadAudits();
};

window.withdrawAudit = async auditId => {
  if (!confirm('Withdraw this audit? It stays on record but can no longer be edited.')) return;
  const data = await workflowPost(`/api/audits/${auditId}`,
    { status: 'withdrawn', reason: fieldValue('auditStateReason') }, 'PATCH');
  if (!data) return;
  workflowDone('Audit withdrawn');
  openAuditModal(auditId);
  if (document.getElementById('page-audits').classList.contains('active')) loadAudits();
};

window.saveAudit = async auditId => {
  const isNew = !auditId;
  const body = {
    title: document.getElementById('auditTitle').value,
    scope_description: document.getElementById('auditScope').value,
    lead_auditor_id: document.getElementById('auditLead').value ? parseInt(document.getElementById('auditLead').value, 10) : null,
    start_date: document.getElementById('auditStart').value || null,
    end_date: document.getElementById('auditEnd').value || null,
  };
  if (!isNew) body.status = document.getElementById('auditStatus').value;

  try {
    const res = await AudinexiaAuth.authFetch(isNew ? '/api/audits' : `/api/audits/${auditId}`, {
      method: isNew ? 'POST' : 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      const d = await res.json().catch(() => ({}));
      showToast(`Save failed: ${d.error || res.status}`);
      setTimeout(hideToast, 2800);
      return;
    }
    showToast('✅ Audit saved');
    setTimeout(hideToast, 1500);
    const saved = await res.json();
    const savedAudit = saved.audit || saved;
    if (isNew) {
      openAuditModal(savedAudit.id);
    } else {
      openAuditModal(auditId);
    }
    if (document.getElementById('page-audits').classList.contains('active')) loadAudits();
  } catch (e) {
    showToast('Could not reach server');
    setTimeout(hideToast, 1800);
  }
};

window.deleteAuditFromModal = async auditId => {
  if (!confirm('Delete this audit and all its findings? This cannot be undone.')) return;
  try {
    const res = await AudinexiaAuth.authFetch(`/api/audits/${auditId}`, { method: 'DELETE' });
    if (!res.ok) { showToast('Delete failed'); setTimeout(hideToast, 1800); return; }
    showToast('🗑 Audit deleted');
    setTimeout(hideToast, 1500);
    document.getElementById('modal').classList.remove('open');
    if (document.getElementById('page-audits').classList.contains('active')) loadAudits();
  } catch (e) {
    showToast('Could not reach server');
    setTimeout(hideToast, 1800);
  }
};

/* ── Findings: rendered in-place inside the Audit modal (accordion, not a
   second modal) ── */
function renderFindingsList(audit) {
  const body = document.getElementById('findingsListBody');
  if (!body) return;
  const findings = audit.findings || [];
  if (!findings.length) {
    body.innerHTML = '<em style="color:var(--muted);font-size:12px">No findings recorded yet.</em>';
    return;
  }
  body.innerHTML = findings.map(f => `
    <div class="ctrl-item" style="cursor:pointer" data-action="toggleFindingDetail" data-args="${esc(JSON.stringify([f.id]))}">
      <div class="ctrl-item-icon" style="background:var(--surface-alt)">📝</div>
      <div class="ctrl-info">
        <div class="ctrl-id" style="max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(f.description)}</div>
        <div class="ctrl-owner">${esc(f.owner_name || 'Unassigned')} ${esc(f.due_date ? '· due ' + f.due_date : '')}</div>
      </div>
      <span class="badge ${esc(findingSeverityBadgeClass(f.severity))}" style="margin-right:4px">${esc(f.severity)}</span>
      <span class="badge badge-blue" style="text-transform:capitalize">${esc(f.status.replace('_',' '))}</span>
    </div>
    <div id="findingDetail${esc(f.id)}" class="crosswalk-detail"></div>
  `).join('');
}

window.toggleFindingDetail = async findingId => {
  const detailEl = document.getElementById(`findingDetail${findingId}`);
  if (!detailEl) return;
  const isOpen = detailEl.classList.contains('open-detail');
  // Collapse any other open finding details first (accordion, one at a time).
  document.querySelectorAll('.crosswalk-detail.open-detail').forEach(el => el.classList.remove('open-detail'));
  if (isOpen) return;

  detailEl.classList.add('open-detail');
  detailEl.innerHTML = '<em style="color:var(--muted);font-size:12px">Loading…</em>';

  const auditId = window._currentAuditId;
  try {
    const [findingRes, users] = await Promise.all([
      AudinexiaAuth.authFetch(`/api/audits/${auditId}/findings/${findingId}`),
      fetchOrgUsers(),
    ]);
    if (!findingRes.ok) { detailEl.innerHTML = '<em style="color:var(--danger);font-size:12px">Could not load finding.</em>'; return; }
    const f = await findingRes.json();
    detailEl.innerHTML = renderFindingEditForm(f, users, auditId);
  } catch (e) {
    detailEl.innerHTML = '<em style="color:var(--danger);font-size:12px">Could not reach server.</em>';
  }
};

function renderFindingEditForm(f, users, auditId) {
  const locked = window._currentAuditStatus === 'closed' || window._currentAuditStatus === 'withdrawn';
  const manage = canManageAudits() && !locked;
  const ownerEdit = isFindingOwner(f) && !locked;
  const readOnly = !manage && !ownerEdit;
  const fieldsDisabled = manage ? '' : 'disabled';

  const severityOptions = FINDING_SEVERITIES.map(s => `<option value="${esc(s)}" ${f.severity === s ? 'selected' : ''}>${esc(s)}</option>`).join('');
  // A closing status can't be picked here -- it goes through request/approve below.
  // The finding's current status always stays listed so a save leaves it unchanged.
  const statusOptions = FINDING_STATUSES
    .filter(s => !FINDING_CLOSING_STATUSES.includes(s) || s === f.status)
    .map(s => `<option value="${esc(s)}" ${f.status === s ? 'selected' : ''}>${esc(s.replace('_',' '))}</option>`).join('');
  const ownerOptions = ['<option value="">Unassigned</option>']
    .concat(users.map(u => `<option value="${esc(u.id)}" ${f.owner_id === u.id ? 'selected' : ''}>${esc(u.name)}</option>`)).join('');
  const linkedHtml = f.linked_controls.length
    ? f.linked_controls.map(l => `
        <div style="display:flex;justify-content:space-between;align-items:center;padding:4px 0;font-size:12px">
          <span>${esc(l.control_id)} — ${esc(l.control_name)} (${esc(l.framework)})</span>
          ${manage ? `<button class="btn btn-secondary btn-sm" data-action="unlinkFindingControl" data-args="${esc(JSON.stringify([auditId, f.id, l.control_result_id]))}">✕</button>` : ''}
        </div>`).join('')
    : '<em style="color:var(--muted);font-size:12px">No linked controls.</em>';

  return `
    <div class="modal-field" style="margin-bottom:8px">
      <div class="field-label">Description</div>
      <textarea id="findingDescription${esc(f.id)}" rows="2" style="width:100%;font-family:inherit;font-size:13px;padding:6px;border:1px solid var(--border);border-radius:6px" ${fieldsDisabled}>${esc(f.description)}</textarea>
    </div>
    <div class="modal-row">
      <div class="modal-field"><div class="field-label">Severity</div>
        <select id="findingSeverity${esc(f.id)}" style="width:100%;padding:6px" ${fieldsDisabled}>${severityOptions}</select>
      </div>
      <div class="modal-field"><div class="field-label">Owner</div>
        <select id="findingOwner${esc(f.id)}" style="width:100%;padding:6px" ${fieldsDisabled}>${ownerOptions}</select>
      </div>
      <div class="modal-field"><div class="field-label">Due Date</div>
        <input type="date" id="findingDueDate${esc(f.id)}" style="width:100%;padding:6px" value="${esc(f.due_date || '')}" ${fieldsDisabled}>
      </div>
    </div>
    <div class="modal-field" style="margin:8px 0">
      <div class="field-label">Recommendation</div>
      <textarea id="findingRecommendation${esc(f.id)}" rows="2" style="width:100%;font-family:inherit;font-size:13px;padding:6px;border:1px solid var(--border);border-radius:6px" ${fieldsDisabled}>${esc(f.recommendation || '')}</textarea>
    </div>
    <div class="modal-row">
      <div class="modal-field"><div class="field-label">Status</div>
        <select id="findingStatus${esc(f.id)}" style="width:100%;padding:6px" ${readOnly ? 'disabled' : ''}>${statusOptions}</select>
      </div>
    </div>
    <div class="modal-field" style="margin:8px 0">
      <div class="field-label">Management Response</div>
      <textarea id="findingManagementResponse${esc(f.id)}" rows="2" style="width:100%;font-family:inherit;font-size:13px;padding:6px;border:1px solid var(--border);border-radius:6px" ${readOnly ? 'disabled' : ''}>${esc(f.management_response || '')}</textarea>
    </div>
    <div class="field-label" style="margin:10px 0 6px">Linked Controls</div>
    <div>${linkedHtml}</div>
    ${locked ? '<div class="wf-detail" style="margin-top:8px">Locked: this finding\'s audit is closed or withdrawn.</div>' : renderFindingWorkflow(f, auditId, manage, ownerEdit)}
    ${readOnly ? `<em style="color:var(--muted);font-size:12px">${locked ? 'View only.' : 'View only — you are not the owner of this finding.'}</em>` : `
    <div style="display:flex;gap:8px;margin-top:10px;flex-wrap:wrap">
      <button class="btn btn-primary btn-sm" data-action="saveFinding" data-args="${esc(JSON.stringify([auditId, f.id]))}">💾 Save</button>
      ${manage && ['planned', 'in_progress'].includes(window._currentAuditStatus) ? `<button class="btn btn-secondary btn-sm" data-action="deleteFinding" data-args="${esc(JSON.stringify([auditId, f.id]))}">🗑 Delete</button>` : ''}
      <button class="btn btn-secondary btn-sm" data-action="createRiskFromFinding" data-args="${esc(JSON.stringify([f.id]))}">🎯 Create risk from this finding</button>
    </div>`}`;
}

function renderFindingWorkflow(f, auditId, manage, ownerEdit) {
  let html = '';
  if (f.pending_action) {
    const when = f.pending_requested_at ? new Date(f.pending_requested_at).toLocaleDateString() : '';
    html += pendingBanner(
      `Closure as "${f.pending_action.replace('_', ' ')}" requested by ${f.pending_requested_by_name || 'a user'}${when ? ' on ' + when : ''}`,
      f.pending_reason);
    if (manage && f.owner_id !== currentUserId() && f.pending_requested_by_id !== currentUserId()) {
      html += `
        <div class="wf-box">
          <div class="field-label">Decision note (optional)</div>
          <input id="findingDecisionReason${esc(f.id)}" class="wf-input" maxlength="500">
          <div class="wf-actions">
            <button class="btn btn-primary btn-sm" data-action="resolveFindingClosure" data-args="${esc(JSON.stringify([auditId, f.id, 'approve']))}">Approve closure</button>
            <button class="btn btn-secondary btn-sm" data-action="resolveFindingClosure" data-args="${esc(JSON.stringify([auditId, f.id, 'reject']))}">Reject</button>
          </div>
          <div class="wf-detail">The person who requested this, and the finding's owner, cannot decide it.</div>
        </div>`;
    } else {
      html += '<div class="wf-detail" style="margin-bottom:8px">Waiting for a different manager to approve or reject.</div>';
    }
  } else if (!FINDING_CLOSING_STATUSES.includes(f.status) && (manage || ownerEdit)) {
    const hasEvidence = f.linked_controls.length > 0;
    html += `
      <div class="wf-box">
        <div class="field-label">Request closure</div>
        ${hasEvidence ? '' : '<div class="wf-detail">Link the scanned control this closure relies on first; a closure needs evidence behind it.</div>'}
        <select id="findingCloseTarget${esc(f.id)}" class="wf-input" ${hasEvidence ? '' : 'disabled'}>
          ${FINDING_CLOSING_STATUSES.map(s => `<option value="${esc(s)}">${esc(s.replace('_', ' '))}</option>`).join('')}
        </select>
        <textarea id="findingCloseReason${esc(f.id)}" rows="2" class="wf-input" placeholder="Why can this be closed? (required)" ${hasEvidence ? '' : 'disabled'}></textarea>
        <div class="wf-actions">
          <button class="btn btn-secondary btn-sm" data-action="requestFindingClosure" data-args="${esc(JSON.stringify([auditId, f.id]))}" ${hasEvidence ? '' : 'disabled'}>Submit for approval</button>
        </div>
      </div>`;
  }
  return html;
}

window.requestFindingClosure = async (auditId, findingId) => {
  const data = await workflowPost(`/api/audits/${auditId}/findings/${findingId}/request-closure`, {
    target_status: fieldValue(`findingCloseTarget${findingId}`),
    reason: fieldValue(`findingCloseReason${findingId}`),
  });
  if (!data) return;
  workflowDone('Closure submitted for approval');
  openAuditModal(auditId);
};

window.resolveFindingClosure = async (auditId, findingId, decision) => {
  const data = await workflowPost(`/api/audits/${auditId}/findings/${findingId}/${decision}-closure`,
                                  { reason: fieldValue(`findingDecisionReason${findingId}`) });
  if (!data) return;
  workflowDone(decision === 'approve' ? 'Finding closure approved' : 'Finding closure rejected');
  openAuditModal(auditId);
};

window.saveFinding = async (auditId, findingId) => {
  const manage = canManageAudits();
  let body = {};
  if (manage) {
    body = {
      description: document.getElementById(`findingDescription${findingId}`).value,
      severity: document.getElementById(`findingSeverity${findingId}`).value,
      owner_id: document.getElementById(`findingOwner${findingId}`).value ? parseInt(document.getElementById(`findingOwner${findingId}`).value, 10) : null,
      due_date: document.getElementById(`findingDueDate${findingId}`).value || null,
      recommendation: document.getElementById(`findingRecommendation${findingId}`).value,
      status: document.getElementById(`findingStatus${findingId}`).value,
      management_response: document.getElementById(`findingManagementResponse${findingId}`).value,
    };
  } else {
    // Owner-only path: the API rejects any other key, so only send these two.
    body = {
      status: document.getElementById(`findingStatus${findingId}`).value,
      management_response: document.getElementById(`findingManagementResponse${findingId}`).value,
    };
  }

  try {
    const res = await AudinexiaAuth.authFetch(`/api/audits/${auditId}/findings/${findingId}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      const d = await res.json().catch(() => ({}));
      showToast(`Save failed: ${d.error || res.status}`);
      setTimeout(hideToast, 2800);
      return;
    }
    showToast('✅ Finding saved');
    setTimeout(hideToast, 1500);
    openAuditModal(auditId);
  } catch (e) {
    showToast('Could not reach server');
    setTimeout(hideToast, 1800);
  }
};

window.deleteFinding = async (auditId, findingId) => {
  if (!confirm('Delete this finding? This cannot be undone.')) return;
  try {
    const res = await AudinexiaAuth.authFetch(`/api/audits/${auditId}/findings/${findingId}`, { method: 'DELETE' });
    if (!res.ok) { showToast('Delete failed'); setTimeout(hideToast, 1800); return; }
    showToast('🗑 Finding deleted');
    setTimeout(hideToast, 1500);
    openAuditModal(auditId);
  } catch (e) {
    showToast('Could not reach server');
    setTimeout(hideToast, 1800);
  }
};

window.unlinkFindingControl = async (auditId, findingId, crId) => {
  try {
    const res = await AudinexiaAuth.authFetch(`/api/audits/${auditId}/findings/${findingId}/links/${crId}`, { method: 'DELETE' });
    if (!res.ok) { showToast('Unlink failed'); setTimeout(hideToast, 1800); return; }
    openAuditModal(auditId);
  } catch (e) {
    showToast('Could not reach server');
    setTimeout(hideToast, 1800);
  }
};

window.toggleNewFindingForm = () => {
  const form = document.getElementById('newFindingForm');
  if (!form) return;
  const showing = form.style.display !== 'none';
  if (showing) { form.style.display = 'none'; return; }
  form.style.display = 'block';
  form.innerHTML = `
    <div class="modal-field" style="margin-bottom:8px">
      <div class="field-label">Description</div>
      <textarea id="newFindingDescription" rows="2" style="width:100%;font-family:inherit;font-size:13px;padding:6px;border:1px solid var(--border);border-radius:6px"></textarea>
    </div>
    <div class="modal-row">
      <div class="modal-field"><div class="field-label">Severity</div>
        <select id="newFindingSeverity" style="width:100%;padding:6px">
          <option value="">Select…</option>
          ${FINDING_SEVERITIES.map(s => `<option value="${esc(s)}">${esc(s)}</option>`).join('')}
        </select>
      </div>
      <div class="modal-field"><div class="field-label">Due Date</div>
        <input type="date" id="newFindingDueDate" style="width:100%;padding:6px">
      </div>
    </div>
    <div class="modal-field" style="margin:8px 0">
      <div class="field-label">Recommendation</div>
      <textarea id="newFindingRecommendation" rows="2" style="width:100%;font-family:inherit;font-size:13px;padding:6px;border:1px solid var(--border);border-radius:6px"></textarea>
    </div>
    <div class="modal-field" style="margin:8px 0">
      <div class="field-label">Link Control Result ID (optional)</div>
      <input type="number" id="newFindingControlResultId" style="width:100%;padding:6px" placeholder="e.g. the control_result_id shown in a scan result">
    </div>
    <button class="btn btn-primary btn-sm" data-action="createFinding" data-args="${esc(JSON.stringify([window._currentAuditId]))}">➕ Add Finding</button>`;
};

window.createFinding = async auditId => {
  const severity = document.getElementById('newFindingSeverity').value;
  if (!severity) { showToast('Severity is required'); setTimeout(hideToast, 1800); return; }
  const crIdRaw = document.getElementById('newFindingControlResultId').value;
  const body = {
    description: document.getElementById('newFindingDescription').value,
    severity,
    due_date: document.getElementById('newFindingDueDate').value || null,
    recommendation: document.getElementById('newFindingRecommendation').value,
  };
  if (crIdRaw) body.control_result_ids = [parseInt(crIdRaw, 10)];
  try {
    const res = await AudinexiaAuth.authFetch(`/api/audits/${auditId}/findings`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      const d = await res.json().catch(() => ({}));
      showToast(`Add finding failed: ${d.error || res.status}`);
      setTimeout(hideToast, 2800);
      return;
    }
    showToast('✅ Finding added');
    setTimeout(hideToast, 1500);
    openAuditModal(auditId);
  } catch (e) {
    showToast('Could not reach server');
    setTimeout(hideToast, 1800);
  }
};

window.createRiskFromFinding = async findingId => {
  let suggestedDescription = '';
  try {
    const res = await AudinexiaAuth.authFetch(`/api/findings/${findingId}/risk-suggestion`);
    if (res.ok) {
      const d = await res.json();
      suggestedDescription = d.suggested_description;
    }
  } catch (e) { /* fall back to blank */ }
  openRiskModal(null, { description: suggestedDescription });
};

document.getElementById('modalClose').addEventListener('click', () =>
  document.getElementById('modal').classList.remove('open')
);
document.getElementById('modal').addEventListener('click', e => {
  if (e.target === document.getElementById('modal'))
    document.getElementById('modal').classList.remove('open');
});

/* ── Export HTML Report ── */
document.getElementById('exportHtmlBtn').addEventListener('click', async () => {
  if (!results) return;
  const btn = document.getElementById('exportHtmlBtn');
  btn.disabled = true;
  btn.textContent = '⏳ Generating...';
  try {
    const res = await AudinexiaAuth.authFetch('/api/export-report', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ assessment_id: results.assessment_id })
    });
    if (!res.ok) {
      let msg = `Server error ${res.status}`;
      try { const d = await res.json(); if (d.error) msg = d.error; } catch(_){}
      throw new Error(msg);
    }
    const blob = await res.blob();
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href = url; a.download = `Audinexia_Report_${fw}.html`;
    document.body.appendChild(a); a.click(); document.body.removeChild(a);
    URL.revokeObjectURL(url);
    addActivity(`📄 HTML report exported — ${FW_NAMES[fw]}`);
  } catch (err) {
    showErr(`HTML export failed: ${err.message}`);
  } finally {
    btn.disabled = false; btn.textContent = '📄 HTML Report';
  }
});

/* ── Export PDF Report ── */
document.getElementById('exportPdfBtn').addEventListener('click', async () => {
  if (!results) return;
  const btn = document.getElementById('exportPdfBtn');
  btn.disabled = true;
  btn.textContent = '⏳ Generating...';
  try {
    const res = await AudinexiaAuth.authFetch('/api/export-pdf', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ assessment_id: results.assessment_id })
    });
    if (!res.ok) {
      let msg = `Server error ${res.status}`;
      try { const d = await res.json(); if (d.error) msg = d.error; } catch(_){}
      throw new Error(msg);
    }
    const blob = await res.blob();
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href = url; a.download = `Audinexia_Report_${fw}.pdf`;
    document.body.appendChild(a); a.click(); document.body.removeChild(a);
    URL.revokeObjectURL(url);
    addActivity(`📑 PDF report exported — ${FW_NAMES[fw]}`);
  } catch (err) {
    showErr(`PDF export failed: ${err.message}`);
  } finally {
    btn.disabled = false; btn.textContent = '📑 PDF Report';
  }
});

/* ── Generate Revised Policy PDF ── */
document.getElementById('reviseBtn').addEventListener('click', async () => {
  if (!selectedFile) {
    showErr('No policy file selected. Please upload a file first.');
    return;
  }
  const btn = document.getElementById('reviseBtn');
  btn.disabled = true;
  btn.textContent = '⏳ Generating...';
  showToast('Generating revised policy PDF...');
  try {
    const formData = new FormData();
    formData.append('file', selectedFile);
    formData.append('framework', fw);
    formData.append('pdf', 'true');

    const res = await AudinexiaAuth.authFetch('/api/revise-policy', { method: 'POST', body: formData });

    // If the server returned an error, try to read the JSON error message
    if (!res.ok) {
      let errMsg = `Server error ${res.status}`;
      try {
        const errData = await res.json();
        if (errData.error) errMsg = errData.error;
      } catch (_) {}
      throw new Error(errMsg);
    }

    // Verify we got a PDF back, not an accidental JSON response
    const contentType = res.headers.get('Content-Type') || '';
    if (!contentType.includes('pdf') && !contentType.includes('octet')) {
      // Try reading as JSON to surface the backend error
      try {
        const data = await res.json();
        throw new Error(data.error || 'Unexpected non-PDF response from server');
      } catch (jsonErr) {
        throw new Error('Server returned unexpected content. Check backend logs.');
      }
    }

    const blob = await res.blob();
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href     = url;
    a.download = `Revised_Policy_${fw}.pdf`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    addActivity(`✏️ Revised policy PDF generated — ${FW_NAMES[fw]}`);
    pushNotif(`Revised Policy PDF ready — ${FW_NAMES[fw]}`);
  } catch (err) {
    showErr(`Revised Policy PDF failed: ${err.message}`);
  } finally {
    btn.disabled    = false;
    btn.textContent = '✏️ Revised Policy PDF';
    hideToast();
  }
});

/* ── Activity feed ── */
function addActivity(text) {
  const feed = document.getElementById('activityFeed');
  const now  = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  const item = document.createElement('div');
  item.className = 'activity-item';
  item.innerHTML = `<div class="activity-dot" style="background:var(--accent)"></div>
    <div><div class="activity-text">${esc(text)}</div><div class="activity-time">${esc(now)}</div></div>`;
  feed.insertBefore(item, feed.firstChild);
  // Keep only 8 latest
  while (feed.children.length > 8) feed.removeChild(feed.lastChild);
}

/* ── Notification bell ── */
let notifUnread = 3;

function toggleNotif(_el, e) {
  e.stopPropagation();
  const panel = document.getElementById('notifPanel');
  panel.classList.toggle('open');
}

// Close notification panel when clicking outside
document.addEventListener('click', e => {
  const panel = document.getElementById('notifPanel');
  const btn   = document.getElementById('notifBtn');
  if (panel.classList.contains('open') && !panel.contains(e.target) && e.target !== btn) {
    panel.classList.remove('open');
  }
});

// Mark all read
document.getElementById('notifClear').addEventListener('click', () => {
  document.querySelectorAll('.notif-unread').forEach(el => {
    el.classList.remove('notif-unread');
    const dot = el.querySelector('.notif-dot');
    if (dot) dot.style.opacity = '0';
  });
  // Remove red dot from bell
  document.getElementById('notifBtn').classList.remove('hbtn-dot');
  notifUnread = 0;
});

// Helper: push a new notification programmatically (called by activity feed)
function pushNotif(text) {
  const list = document.getElementById('notifList');
  const empty = document.getElementById('notifEmpty');
  if (empty) empty.remove();
  const now = new Date().toISOString().slice(0, 16).replace('T', ' ') + ' UTC';
  const item = document.createElement('div');
  item.className = 'notif-item notif-unread';
  item.innerHTML = `<div class="notif-dot"></div>
    <div class="notif-body">
      <div class="notif-text">${esc(text)}</div>
      <div class="notif-time">${esc(now)}</div>
    </div>`;
  list.insertBefore(item, list.firstChild);
  // Restore red dot on bell if removed
  document.getElementById('notifBtn').classList.add('hbtn-dot');
  notifUnread++;
}

/* ── Toggle pills on config page ── */
document.querySelectorAll('.toggle-pill').forEach(pill => {
  pill.addEventListener('click', () => pill.classList.toggle('off'));
});

/* ══════════════════════════════════════════════════════════════════════
   Phase 6-8 modules: vendor risk, maturity, monitoring, audit trail.
   Each loader is read-only against the API and re-renders from the payload;
   mutations go through the shared #modal overlay like Risk/Audit already do.
   ══════════════════════════════════════════════════════════════════════ */

const TIER_BADGE = { critical:'badge-red', high:'badge-red', medium:'badge-yellow', low:'badge-green', unassessed:'badge-blue' };
const STATE_BADGE = { drift_down:'badge-red', no_new_version:'badge-red', error:'badge-red',
                      control_flip:'badge-yellow', framework_updated:'badge-yellow',
                      drift_up:'badge-green', stable:'badge-green', initial:'badge-blue' };
const FRESH_BADGE = { overdue:'badge-red', due_soon:'badge-yellow', current:'badge-green', unscheduled:'badge-blue' };
const MATURITY_LABELS = {1:'Initial',2:'Managed',3:'Defined',4:'Quantitatively Managed',5:'Optimizing'};

function canManageVendors() {
  const u = AudinexiaAuth.getCurrentUser();
  return !!u && ['org_admin','compliance_manager'].includes(u.role);
}
function isOrgAdmin() {
  const u = AudinexiaAuth.getCurrentUser();
  return !!u && u.role === 'org_admin';
}

/* ── Vendor register ── */
async function loadVendors() {
  document.getElementById('newVendorBtn').style.display = canManageVendors() ? '' : 'none';
  const tbody = document.getElementById('vendorsTableBody');
  try {
    const res  = await AudinexiaAuth.authFetch('/api/vendors/risk-register');
    if (!res.ok) { tbody.innerHTML = `<tr><td colspan="8" style="text-align:center;color:var(--danger);padding:20px">Could not load vendors (${esc(res.status)})</td></tr>`; return; }
    const data = await res.json();
    const rows = data.vendors || [];
    const sum  = data.summary || {};
    const badge = document.getElementById('navVendorBadge');
    const urgent = (sum.tier_counts?.critical || 0) + (sum.tier_counts?.unassessed || 0);
    badge.textContent = urgent; badge.style.display = urgent ? '' : 'none';

    document.getElementById('vendorSummary').innerHTML = [
      ['Vendors', sum.vendor_count ?? rows.length, ''],
      ['Critical', sum.tier_counts?.critical ?? 0, 'var(--danger)'],
      ['High', sum.tier_counts?.high ?? 0, '#f97316'],
      ['Unassessed', sum.tier_counts?.unassessed ?? 0, 'var(--info)'],
      ['Avg coverage', sum.average_coverage == null ? '—' : sum.average_coverage + '%', ''],
    ].map(([l,v,c]) => `<div style="border:1px solid var(--border);border-radius:10px;padding:10px 12px">
        <div class="empty-label" style="font-size:11px">${esc(l)}</div>
        <div style="font-size:22px;font-weight:800;color:${esc(c||'var(--text)')}">${esc(v)}</div></div>`).join('');

    document.getElementById('vendorMethodology').innerHTML =
      `<strong>How the tier is derived.</strong> ${esc(data.methodology || '')}` +
      (sum.note ? `<br>${esc(sum.note)}` : '');

    if (!rows.length) {
      tbody.innerHTML = '<tr><td colspan="8" style="text-align:center;color:var(--muted);padding:20px">No vendors registered. Add one, then upload their policy document.</td></tr>';
      return;
    }
    tbody.innerHTML = rows.map(v => `
      <tr style="cursor:pointer" data-action="openVendorModal" data-args="${esc(JSON.stringify([v.vendor_id]))}">
        <td style="max-width:220px"><strong>${esc(v.name)}</strong><div style="font-size:11px;color:var(--muted)">${esc(v.status)}</div></td>
        <td style="font-size:12px">${esc((v.data_sensitivity||'').replace(/_/g,' '))}</td>
        <td>${v.coverage_percent == null ? '<em style="color:var(--muted)">none</em>' : esc(v.coverage_percent) + '%'}</td>
        <td><span class="badge ${esc(TIER_BADGE[v.risk_tier]||'badge-blue')}">${esc(v.risk_tier)}</span></td>
        <td style="font-weight:700">${esc(v.risk_score)}</td>
        <td>${esc(v.open_gap_count)}${v.open_findings ? ` <span style="color:var(--muted);font-size:11px">+${esc(v.open_findings)} finding(s)</span>` : ''}</td>
        <td style="font-size:12px">${v.review_overdue_days > 0 ? `<span class="badge badge-red">${esc(v.review_overdue_days)}d overdue</span>` : (v.review_overdue_days === null ? '<em style="color:var(--muted)">no cadence</em>' : '<span style="color:var(--success)">in window</span>')}</td>
        <td style="font-size:12px">${v.contract ? esc(v.contract.label) : '<em style="color:var(--muted)">none</em>'}</td>
      </tr>`).join('');
  } catch (e) {
    tbody.innerHTML = '<tr><td colspan="8" style="text-align:center;color:var(--danger);padding:20px">Could not reach server</td></tr>';
  }
}

async function exportVendorRegister() {
  try {
    const res = await AudinexiaAuth.authFetch('/api/vendors/export/register');
    if (!res.ok) { showToast('Export failed'); return; }
    const blob = await res.blob();
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'audinexia_vendor_register.csv';
    a.click(); URL.revokeObjectURL(a.href);
    showToast('Vendor register downloaded');
  } catch (e) { showToast('Could not reach server'); }
}

window.openVendorModal = async (vendorIdOrNull) => {
  let vendor = null, detail = null;
  if (typeof vendorIdOrNull === 'number') {
    const res = await AudinexiaAuth.authFetch(`/api/vendors/${vendorIdOrNull}`);
    if (res.ok) { detail = await res.json(); vendor = detail.vendor; }
  }
  const users = await fetchOrgUsers();
  const manage = canManageVendors();
  const ownerOptions = ['<option value="">Unassigned</option>']
    .concat((users||[]).map(u => `<option value="${esc(u.id)}" ${vendor && vendor.owner_id === u.id ? 'selected':''}>${esc(u.name)}</option>`)).join('');
  const sens = ['public','internal','confidential','personal_data','health_data','cardholder_data','restricted'];
  const stat = ['onboarding','active','under_review','suspended','offboarded'];

  document.getElementById('modalTitle').textContent = vendor ? vendor.name : 'New Vendor';
  document.getElementById('modalBody').innerHTML = `
    <div class="modal-row">
      <div class="modal-field"><div class="field-label">Name</div>
        <input id="vName" value="${esc(vendor ? vendor.name : '')}" ${manage?'':'disabled'} style="width:100%;padding:6px"></div>
      <div class="modal-field"><div class="field-label">Owner</div>
        <select id="vOwner" style="width:100%;padding:6px" ${manage?'':'disabled'}>${ownerOptions}</select></div>
    </div>
    <div class="modal-row">
      <div class="modal-field"><div class="field-label">Data sensitivity</div>
        <select id="vSens" style="width:100%;padding:6px" ${manage?'':'disabled'}>${sens.map(x=>`<option value="${esc(x)}" ${vendor&&vendor.data_sensitivity===x?'selected':''}>${esc(x.replace(/_/g,' '))}</option>`).join('')}</select></div>
      <div class="modal-field"><div class="field-label">Status</div>
        <select id="vStatus" style="width:100%;padding:6px" ${manage?'':'disabled'}>${stat.map(x=>`<option value="${esc(x)}" ${vendor&&vendor.status===x?'selected':''}>${esc(x.replace(/_/g,' '))}</option>`).join('')}</select></div>
    </div>
    <div class="modal-row">
      <div class="modal-field"><div class="field-label">Review every (days)</div>
        <input id="vFreq" type="number" min="30" max="3650" value="${esc(vendor ? vendor.review_frequency_days : 365)}" ${manage?'':'disabled'} style="width:100%;padding:6px"></div>
      <div class="modal-field"><div class="field-label">Contract end</div>
        <input id="vContractEnd" type="date" value="${esc(vendor ? (vendor.contract_end||'') : '')}" ${manage?'':'disabled'} style="width:100%;padding:6px"></div>
    </div>
    <div class="modal-field"><div class="field-label">Service description</div>
      <textarea id="vService" rows="2" ${manage?'':'disabled'} style="width:100%;padding:6px;font-size:12px">${esc(vendor ? (vendor.service_description||'') : '')}</textarea></div>
    ${detail ? `
    <div style="margin-top:12px;padding:10px 12px;background:var(--surface-alt);border-radius:8px;font-size:12px;line-height:1.6">
      <div class="field-label" style="margin-bottom:4px">Why this tier</div>
      ${detail.rollup.reasons.map(r => `• ${esc(r)}`).join('<br>')}
      <div style="margin-top:8px;color:var(--muted)"><em>${esc(detail.rollup.assurance_note)}</em></div>
    </div>
    <div style="margin-top:12px">
      <div class="field-label">Assessments (${detail.assessments.length})</div>
      ${detail.assessments.length ? detail.assessments.map(a => `<div style="display:flex;justify-content:space-between;padding:3px 0;font-size:12px">
          <span>${esc(a.filename)} · ${esc(a.framework)}</span>
          <span style="font-weight:700">${esc(a.overall_score)}%</span></div>`).join('')
        : '<em style="color:var(--muted);font-size:12px">None yet.</em>'}
    </div>
    <div style="margin-top:12px">
      <div class="field-label">Upload vendor policy document</div>
      <input type="file" id="vDoc" accept=".txt,.pdf,.docx" style="font-size:12px">
      <select id="vDocFw" style="padding:5px;margin-top:6px">
        ${Object.entries(FW_ICONS).map(([k]) => `<option value="${esc(k)}">${esc(k)}</option>`).join('')}
      </select>
      <button class="btn btn-primary btn-sm" style="margin-top:6px" data-action="assessVendor" data-args="${esc(JSON.stringify([vendor.id]))}">Score it</button>
    </div>` : ''}
    ${manage ? `<div style="margin-top:14px"><button class="btn btn-primary btn-sm" data-action="saveVendor" data-args="${esc(JSON.stringify([vendor ? vendor.id : null]))}">${vendor?'Save changes':'Create vendor'}</button></div>` : ''}`;
  document.getElementById('modal').classList.add('open');
};

window.saveVendor = async (vendorId) => {
  const body = {
    name: document.getElementById('vName').value.trim(),
    data_sensitivity: document.getElementById('vSens').value,
    status: document.getElementById('vStatus').value,
    review_frequency_days: Number(document.getElementById('vFreq').value),
    service_description: document.getElementById('vService').value,
    contract_end: document.getElementById('vContractEnd').value || null,
  };
  const owner = document.getElementById('vOwner').value;
  if (owner) body.owner_id = Number(owner);
  const res = await AudinexiaAuth.authFetch(vendorId ? `/api/vendors/${vendorId}` : '/api/vendors', {
    method: vendorId ? 'PATCH' : 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify(body),
  });
  const data = await res.json();
  if (!res.ok) { showToast(data.error || 'Could not save vendor'); return; }
  showToast(vendorId ? 'Vendor updated' : 'Vendor registered');
  document.getElementById('modal').classList.remove('open');
  loadVendors();
};

window.assessVendor = async (vendorId) => {
  const input = document.getElementById('vDoc');
  if (!input.files.length) { showToast('Choose a document first'); return; }
  const fd = new FormData();
  fd.append('file', input.files[0]);
  fd.append('framework', document.getElementById('vDocFw').value);
  const res = await AudinexiaAuth.authFetch(`/api/vendors/${vendorId}/assessments`, { method:'POST', body: fd });
  const data = await res.json();
  if (!res.ok) { showToast(data.error || 'Scan failed'); return; }
  showToast(`Scored ${data.overall_score}% · tier ${data.vendor_risk_tier}`);
  openVendorModal(vendorId);
  loadVendors();
};

/* ── Maturity ── */
async function loadMaturity() {
  const host = document.getElementById('maturityFrameworks');
  try {
    const res = await AudinexiaAuth.authFetch('/api/maturity');
    if (!res.ok) { host.innerHTML = `<div class="card" style="padding:20px">Could not load maturity (${esc(res.status)})</div>`; return; }
    const data = await res.json();
    const p = data.portfolio;
    document.getElementById('portfolioLevel').textContent = p ? `Level ${p.portfolio_level} · ${p.portfolio_level_label}` : '—';
    document.getElementById('portfolioBody').innerHTML = p ? `
      <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:10px">
        ${[['Frameworks in scope',p.frameworks_in_scope],['Portfolio level',p.portfolio_level_label],['Avg composite',p.portfolio_score_average]]
          .map(([l,v]) => `<div style="border:1px solid var(--border);border-radius:10px;padding:10px 12px">
            <div class="empty-label" style="font-size:11px">${esc(l)}</div><div style="font-size:20px;font-weight:800">${esc(v)}</div></div>`).join('')}
      </div>
      <div style="font-size:12px;color:var(--muted)">${esc(p.aggregation_note)}</div>` :
      `<em style="color:var(--muted)">No framework has an assessment of your own documents yet — nothing to measure. ${esc(data.note||'')}</em>`;

    if (!data.frameworks?.length) { host.innerHTML = ''; return; }
    host.innerHTML = data.frameworks.map(f => {
      const pct = Math.round((f.derived_score||0));
      const claimBad = f.claim_overstates;
      return `<div class="card" style="margin-bottom:16px">
        <div class="card-header">
          <span class="card-title">${esc(FW_ICONS[f.framework]||'')} ${esc(f.framework_name)}</span>
          <span>
            <span class="badge ${esc(f.derived_level>=3?'badge-green':f.derived_level===2?'badge-yellow':'badge-red')}">Level ${esc(f.derived_level)} · ${esc(f.derived_level_label)}</span>
            ${f.claimed_level ? `<span class="badge ${claimBad?'badge-red':'badge-blue'}">claimed ${esc(f.claimed_level)}</span>`:''}
            ${canManageVendors() ? `<button class="btn btn-secondary btn-sm" data-action="openMaturityModal" data-args="${esc(JSON.stringify([f.framework]))}">Record claim</button>
            <button class="btn btn-secondary btn-sm" data-action="recalcMaturity" data-args="${esc(JSON.stringify([f.framework]))}">Recalculate</button>`:''}
          </span>
        </div>
        <div style="padding:14px 20px">
          <div style="height:8px;background:var(--surface-alt);border-radius:6px;overflow:hidden;margin-bottom:10px">
            <div style="height:100%;width:${esc(pct)}%;background:${esc(pct>=65?'var(--success)':pct>=45?'#f59e0b':'var(--danger)')}"></div>
          </div>
          <div style="display:flex;gap:6px;margin-bottom:12px">
            ${[1,2,3,4,5].map(l => `<div style="flex:1;text-align:center;font-size:10.5px;padding:6px 4px;border-radius:6px;
                 border:1px solid ${l<=f.derived_level?'var(--success)':'var(--border)'};
                 background:${l<=f.derived_level?'var(--success-bg)':'transparent'};
                 color:${l<=f.derived_level?'#065f46':'var(--muted)'}">${esc(l)}<br>${esc(MATURITY_LABELS[l].split(' ')[0])}</div>`).join('')}
          </div>
          ${f.blockers?.length ? `<div style="font-size:12px;line-height:1.7;background:var(--surface-alt);border-radius:8px;padding:10px 12px">
              <strong>Blocking the next level</strong><br>
              ${f.blockers.slice(0,4).map(b=>`• <span style="color:var(--muted)">L${esc(b.level)} ${esc(b.level_label)}:</span> ${esc(b.gate)} — ${esc(b.detail)}`).join('<br>')}
            </div>` : '<div style="font-size:12px;color:var(--success)">Every gate on the ladder is satisfied for this framework.</div>'}
          ${f.claim_gap_note ? `<div style="font-size:12px;margin-top:8px;color:${claimBad?'var(--danger)':'var(--muted)'}">${esc(f.claim_gap_note)}</div>`:''}
          <div style="font-size:11px;color:var(--muted);margin-top:8px">${esc(f.limitation)}</div>
          ${f.snapshots?.length ? `<details style="margin-top:8px;font-size:11.5px"><summary style="cursor:pointer;color:var(--muted)">Trend (${f.snapshots.length})</summary>
            ${f.snapshots.map(s=>`<div style="display:flex;justify-content:space-between;padding:2px 0"><span>${esc((s.taken_at||'').slice(0,10))} · ${esc(s.trigger)}</span><strong>L${esc(s.level)} · ${esc(s.score)}</strong></div>`).join('')}
          </details>`:''}
        </div>
      </div>`;
    }).join('');
  } catch (e) {
    host.innerHTML = '<div class="card" style="padding:20px;color:var(--danger)">Could not reach server</div>';
  }
}

window.openMaturityModal = async (framework) => {
  const res = await AudinexiaAuth.authFetch(`/api/maturity/${framework}`);
  const m = await res.json();
  document.getElementById('modalTitle').textContent = `Maturity claim · ${m.framework_name}`;
  document.getElementById('modalBody').innerHTML = `
    <div style="font-size:12.5px;color:var(--text-2);margin-bottom:12px">
      Evidence currently supports <strong>Level ${esc(m.derived_level)} · ${esc(m.derived_level_label)}</strong> (${esc(m.derived_score)} composite).
      A claim recorded here is never substituted for that figure; the gap between them is reported instead.
    </div>
    <div class="modal-row">
      <div class="modal-field"><div class="field-label">Claimed level</div>
        <select id="mClaim" style="width:100%;padding:6px">${[1,2,3,4,5].map(l=>`<option value="${esc(l)}" ${m.claimed_level===l?'selected':''}>${esc(l)} — ${esc(MATURITY_LABELS[l])}</option>`).join('')}</select></div>
      <div class="modal-field"><div class="field-label">Target level</div>
        <select id="mTarget" style="width:100%;padding:6px">${[1,2,3,4,5].map(l=>`<option value="${esc(l)}" ${m.target_level===l?'selected':''}>${esc(l)} — ${esc(MATURITY_LABELS[l])}</option>`).join('')}</select></div>
    </div>
    <div class="modal-field"><div class="field-label">Self-assessment notes</div>
      <textarea id="mNotes" rows="4" style="width:100%;padding:8px;font-size:12px">${esc(m.self_assessment_notes||'')}</textarea></div>
    <label style="display:flex;gap:6px;align-items:center;font-size:12px;margin-top:8px">
      <input type="checkbox" id="mApprove"> Approve as compliance manager sign-off (records you and a 12-month re-review date)</label>
    <div style="margin-top:14px"><button class="btn btn-primary btn-sm" data-action="saveMaturity" data-args="${esc(JSON.stringify([framework]))}">Save claim</button></div>`;
  document.getElementById('modal').classList.add('open');
};

window.saveMaturity = async (framework) => {
  const res = await AudinexiaAuth.authFetch(`/api/maturity/${framework}`, {
    method:'PATCH', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({
      current_level: Number(document.getElementById('mClaim').value),
      target_level: Number(document.getElementById('mTarget').value),
      self_assessment_notes: document.getElementById('mNotes').value,
      approve: document.getElementById('mApprove').checked,
    }),
  });
  const data = await res.json();
  if (!res.ok) { showToast(data.error || 'Could not save'); return; }
  showToast('Claim recorded');
  document.getElementById('modal').classList.remove('open');
  loadMaturity();
};

window.recalcMaturity = async (framework) => {
  const res = await AudinexiaAuth.authFetch(`/api/maturity/${framework}/recalculate`, { method:'POST' });
  showToast(res.ok ? 'Recalculated and snapshotted' : 'Could not recalculate');
  loadMaturity();
};

/* ── Monitoring ── */
async function loadWatches() {
  document.getElementById('newWatchBtn').style.display = canManageVendors() ? '' : 'none';
  const tbody = document.getElementById('watchesTableBody');
  try {
    const [wRes, sRes] = await Promise.all([
      AudinexiaAuth.authFetch('/api/monitoring/watches'),
      AudinexiaAuth.authFetch('/api/monitoring/summary'),
    ]);
    if (!wRes.ok) { tbody.innerHTML = `<tr><td colspan="7" style="text-align:center;color:var(--danger);padding:20px">Could not load watches (${esc(wRes.status)})</td></tr>`; return; }
    const data = await wRes.json();
    const sum  = sRes.ok ? await sRes.json() : {};
    const rows = data.watches || [];

    const urgent = (sum.overdue_count||0);
    const badge = document.getElementById('navWatchBadge');
    badge.textContent = urgent; badge.style.display = urgent ? '' : 'none';

    document.getElementById('monTotal').textContent = `${sum.watch_count ?? rows.length} active`;
    document.getElementById('monitoringSummary').innerHTML = `
      <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:10px">
        ${[['Overdue',sum.overdue_count||0,'var(--danger)'],['Due soon',sum.due_soon_count||0,'#f59e0b'],
           ['Regressed',sum.regressed_count||0,'var(--danger)'],['Not re-verified',sum.unverified_count||0,'#f59e0b']]
          .map(([l,v,c])=>`<div style="border:1px solid var(--border);border-radius:10px;padding:10px 12px">
            <div class="empty-label" style="font-size:11px">${esc(l)}</div><div style="font-size:22px;font-weight:800;color:${esc(c)}">${esc(v)}</div></div>`).join('')}
      </div>
      <div style="font-size:11.5px;color:var(--muted);line-height:1.55">${esc(sum.honesty_note||'')}</div>`;

    if (!rows.length) {
      tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;color:var(--muted);padding:20px">No watches yet. Track a scanned policy document to get drift and overdue alerts.</td></tr>';
      return;
    }
    tbody.innerHTML = rows.map(w => `
      <tr>
        <td style="max-width:240px"><strong>${esc(w.name)}</strong><div style="font-size:11px;color:var(--muted)">${esc(w.filename)}</div></td>
        <td style="font-size:12px">${esc(FW_ICONS[w.framework]||'')} ${esc(w.framework)}</td>
        <td style="font-size:12px">${esc(w.review_interval_days)}d</td>
        <td style="font-weight:700">${esc(w.last_score ?? '—')}</td>
        <td><span class="badge ${esc(STATE_BADGE[w.last_state]||'badge-blue')}">${esc(w.state_label)}</span></td>
        <td><span class="badge ${esc(FRESH_BADGE[w.freshness.status]||'badge-blue')}">${esc(w.freshness.label)}</span></td>
        <td style="white-space:nowrap">
          <button class="btn btn-secondary btn-sm" data-action="runWatch" data-args="${esc(JSON.stringify([w.id]))}">Run now</button>
          ${canManageVendors() ? `<button class="btn btn-secondary btn-sm" data-action="toggleWatch" data-args="${esc(JSON.stringify([w.id, w.is_active]))}">${w.is_active?'Pause':'Resume'}</button>`:''}
        </td>
      </tr>
      ${w.latest_run ? `<tr><td colspan="7" style="background:var(--surface-alt);font-size:11.5px;color:var(--text-2);padding:8px 14px">
          Last run ${esc((w.latest_run.run_at||'').slice(0,16).replace('T',' '))} UTC · ${esc(w.latest_run.message||'')}</td></tr>`:''}`).join('');
  } catch (e) {
    tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;color:var(--danger);padding:20px">Could not reach server</td></tr>';
  }
}

window.runWatch = async (watchId, btn) => {
  btn.disabled = true; btn.textContent = 'Running…';
  const res = await AudinexiaAuth.authFetch(`/api/monitoring/watches/${watchId}/run`, { method:'POST' });
  const data = await res.json();
  btn.disabled = false; btn.textContent = 'Run now';
  if (!res.ok && !data.state) { showToast(data.error || 'Run failed'); return; }
  showToast(data.verified === false ? 'Not re-verified — no new document' : `Check complete: ${data.state}`);
  loadWatches();
};

window.toggleWatch = async (watchId, currentlyActive) => {
  const res = await AudinexiaAuth.authFetch(`/api/monitoring/watches/${watchId}`, {
    method:'PATCH', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({ is_active: !currentlyActive }),
  });
  showToast(res.ok ? (currentlyActive ? 'Watch paused' : 'Watch resumed') : 'Could not update');
  loadWatches();
};

window.openWatchModal = async () => {
  const a = await AudinexiaAuth.authFetch('/api/assessments');
  const assessments = a.ok ? (await a.json()).assessments || [] : [];
  document.getElementById('modalTitle').textContent = 'New Policy Watch';
  document.getElementById('modalBody').innerHTML = `
    <div class="modal-field"><div class="field-label">Name</div>
      <input id="wName" style="width:100%;padding:6px" placeholder="e.g. Privacy policy — annual re-verification"></div>
    <div class="modal-field" style="margin-top:8px"><div class="field-label">Tracked document (filename as scanned)</div>
      <select id="wFile" style="width:100%;padding:6px">${assessments.length ? assessments.map(x=>`<option value="${esc(x.filename)}" data-fw="${esc(x.framework)}">${esc(x.filename)} · ${esc(x.framework)} · ${esc(x.overall_score)}%</option>`).join('') : '<option value="">No assessments yet</option>'}</select></div>
    <div class="modal-row" style="margin-top:8px">
      <div class="modal-field"><div class="field-label">Review interval (days)</div>
        <input id="wInterval" type="number" min="1" max="3650" value="180" style="width:100%;padding:6px"></div>
      <div class="modal-field"><div class="field-label">Drift threshold (points)</div>
        <input id="wThreshold" type="number" min="0" max="100" step="0.5" value="5" style="width:100%;padding:6px"></div>
    </div>
    <div style="font-size:11.5px;color:var(--muted);margin-top:8px">The watch anchors on the selected document's newest scan, so adopting an old policy starts out overdue rather than getting a fresh interval.</div>
    <div style="margin-top:14px"><button class="btn btn-primary btn-sm" data-action="saveWatch">Create watch</button></div>`;
  document.getElementById('modal').classList.add('open');
};

window.saveWatch = async () => {
  const sel = document.getElementById('wFile');
  const chosen = sel.options[sel.selectedIndex];
  const res = await AudinexiaAuth.authFetch('/api/monitoring/watches', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({
      name: document.getElementById('wName').value.trim(),
      filename: sel.value,
      framework: chosen ? chosen.dataset.fw : 'dpdpa',
      review_interval_days: Number(document.getElementById('wInterval').value),
      drift_threshold_points: Number(document.getElementById('wThreshold').value),
    }),
  });
  const data = await res.json();
  if (!res.ok) { showToast(data.error || 'Could not create watch'); return; }
  showToast('Watch created');
  document.getElementById('modal').classList.remove('open');
  loadWatches();
};

/* ── Audit trail ── */
async function loadTrail() {
  const tbody = document.getElementById('trailTableBody');
  try {
    const res = await AudinexiaAuth.authFetch('/api/admin/audit-trail?limit=100');
    if (!res.ok) { tbody.innerHTML = `<tr><td colspan="6" style="text-align:center;color:var(--danger);padding:20px">Audit trail requires admin, compliance manager or auditor access (${esc(res.status)})</td></tr>`; return; }
    const data = await res.json();
    if (!data.events.length) { tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--muted);padding:20px">No recorded events yet.</td></tr>'; return; }
    tbody.innerHTML = data.events.map(e => `
      <tr>
        <td style="font-size:11.5px;white-space:nowrap">${esc((e.created_at||'').slice(0,19).replace('T',' '))}</td>
        <td><code style="font-size:11px">${esc(e.action)}</code></td>
        <td style="font-size:11.5px">${esc(e.entity_type)}${esc(e.entity_id ? ' #'+e.entity_id : '')}</td>
        <td style="max-width:340px;font-size:12px">${esc(e.summary||'')}</td>
        <td style="font-size:11.5px">${esc(e.actor||'system')}<div style="color:var(--muted)">${esc(e.actor_role||'')}</div></td>
        <td style="font-size:10.5px;color:var(--muted)">${esc((e.request_id||'').slice(0,8))}</td>
      </tr>`).join('');
  } catch (err) {
    tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--danger);padding:20px">Could not reach server</td></tr>';
  }
}

/* ── Real notifications on the dashboard (replaces the static seed items) ── */
async function loadRealNotifications() {
  try {
    const res = await AudinexiaAuth.authFetch('/api/monitoring/summary');
    if (!res.ok) return;
    const sum = await res.json();
    const vRes = await AudinexiaAuth.authFetch('/api/vendors/risk-register');
    const vData = vRes.ok ? await vRes.json() : { vendors: [] };
    const items = [];
    (sum.attention || []).slice(0,4).forEach(a =>
      items.push(`${a.name}: ${a.reason}${a.state === 'drift_down' ? ' — score regressed' : ''}`));
    (vData.vendors || []).filter(v => v.risk_tier === 'critical').slice(0,3).forEach(v =>
      items.push(`Vendor ${v.name} is critical: ${v.coverage_percent}% documented coverage`));
    items.forEach(t => pushNotif(t));
  } catch (e) { /* notifications are advisory; never block the dashboard */ }
}

/* ── Policy library (derived from stored assessments; no separate document table) ── */
const CADENCE_BADGE = { overdue:'badge-red', due_soon:'badge-yellow', unmonitored:'badge-blue',
                        current:'badge-green', unscheduled:'badge-blue' };
const CADENCE_LABEL = { overdue:'Overdue', due_soon:'Due soon', unmonitored:'No cadence',
                        current:'On track', unscheduled:'Unscheduled' };

async function loadLibrary() {
  const tbody = document.getElementById('libraryTableBody');
  try {
    const res = await AudinexiaAuth.authFetch('/api/policy-documents');
    if (!res.ok) { tbody.innerHTML = `<tr><td colspan="8" style="text-align:center;color:var(--danger);padding:20px">Could not load documents (${esc(res.status)})</td></tr>`; return; }
    const data = await res.json();
    document.getElementById('libCount').textContent = `${data.counts.total} document(s)`;
    document.getElementById('libraryNote').innerHTML =
      `${data.note} ${data.counts.overdue} overdue, ${data.counts.unmonitored} without a review cadence` +
      (data.counts.framework_drift ? `, ${data.counts.framework_drift} last measured against superseded framework definitions` : '') + '.';
    if (!data.documents.length) {
      tbody.innerHTML = '<tr><td colspan="8" style="text-align:center;color:var(--muted);padding:20px">Nothing scanned yet. Upload a policy from the scanner to populate the library.</td></tr>';
      return;
    }
    tbody.innerHTML = data.documents.map(d => `
      <tr>
        <td style="max-width:260px"><strong>${esc(d.filename)}</strong>
          <div style="font-size:11px;color:var(--muted)">${esc(d.format ? '.'+d.format : '')}${esc(d.size_bytes ? ' · ' + Math.round(d.size_bytes/1024) + ' KB' : ' · size unavailable (upload not retained)')}${esc(d.vendor_name ? ' · vendor: ' + d.vendor_name : '')}</div></td>
        <td style="font-size:12px">${esc(FW_ICONS[d.framework] || '')} ${esc(d.framework_name)}</td>
        <td style="font-weight:700;color:${esc(d.latest_score >= 80 ? 'var(--success)' : d.latest_score >= 50 ? '#f59e0b' : 'var(--danger)')}">${esc(d.latest_score)}%</td>
        <td>${esc(d.scan_count)}</td>
        <td>${d.open_gaps ? `<span class="badge badge-red">${esc(d.open_gaps)}</span>` : '<span style="color:var(--muted)">0</span>'}</td>
        <td><span class="badge ${esc(CADENCE_BADGE[d.cadence] || 'badge-blue')}">${esc(CADENCE_LABEL[d.cadence] || d.cadence)}</span>
            ${d.framework_definition_drift ? '<div style="font-size:10.5px;color:var(--warn);margin-top:3px">framework definitions changed</div>' : ''}</td>
        <td style="font-size:11.5px;color:var(--muted)">${esc((d.latest_scanned_at||'').slice(0,10))}</td>
        <td style="white-space:nowrap">
          <button class="btn btn-secondary btn-sm" data-action="viewAssessment" data-args="${esc(JSON.stringify([d.latest_assessment_id]))}">Open</button>
          <button class="btn btn-secondary btn-sm" data-action="downloadReportRow" data-args="${esc(JSON.stringify([d.latest_assessment_id, d.framework]))}">⬇</button>
          ${canManageVendors() && !d.watch_id ? `<button class="btn btn-secondary btn-sm" data-action="watchFromDoc" data-args="${esc(JSON.stringify([encodeURIComponent(d.filename), d.framework]))}">Track</button>` : ''}
        </td>
      </tr>`).join('');
  } catch (e) {
    tbody.innerHTML = '<tr><td colspan="8" style="text-align:center;color:var(--danger);padding:20px">Could not reach server</td></tr>';
  }
}

window.watchFromDoc = async (encodedFilename, framework) => {
  const filename = decodeURIComponent(encodedFilename);
  const res = await AudinexiaAuth.authFetch('/api/monitoring/watches', {
    method: 'POST', headers: {'Content-Type':'application/json'},
    body: JSON.stringify({ name: `${filename} (${framework})`, filename, framework, review_interval_days: 180 }),
  });
  const data = await res.json();
  showToast(res.ok ? `Now tracking ${filename}` : (data.error || 'Could not create watch'));
  if (res.ok) loadLibrary();
};

/* ── Configuration page ── */
async function loadConfig() {
  try {
    const me = await AudinexiaAuth.authFetch('/api/auth/me');
    if (me.ok) {
      const d = await me.json();
      document.getElementById('cfgName').textContent = d.user.name;
      document.getElementById('cfgEmail').textContent = d.user.email;
      document.getElementById('cfgRole').textContent = d.user.role.replace(/_/g,' ');
      document.getElementById('cfgOrg').textContent = d.organization.name;
      document.getElementById('cfgLastLogin').textContent = d.user.last_login_at
        ? d.user.last_login_at.slice(0,16).replace('T',' ') + ' UTC' : 'first session';
      document.getElementById('cfgSession').innerHTML =
        `Access tokens expire after <strong>${esc(d.token_expires_in_minutes)} minutes</strong> and refresh silently. ` +
        (d.user.must_change_password ? '<span style="color:var(--danger)">An administrator set your current password — change it below.</span>' : '');
      if (d.user.must_change_password) document.getElementById('pwForceNote').style.display = '';
    }
    const svc = await fetch('/').then(r => r.json());
    const policy = await fetch('/api/auth/password-policy').then(r => r.json());
    document.getElementById('pwRules').innerHTML =
      `Password must be: ${policy.rules.join('; ')}.`;
    const limits = document.getElementById('cfgLimits');
    limits.innerHTML = [
      ['Supported formats', (svc.supported_formats||[]).map(f=>'.'+f).join(', ')],
      ['Max upload size', (svc.max_file_size_mb||50) + ' MB'],
      ['Frameworks', `${(svc.frameworks||[]).length} (${Object.entries(svc.control_counts||{}).map(([k,v])=>k+':'+v).join(', ')})`],
      ['Version', svc.version || '—'],
    ].map(([k,v]) => `<div class="fw-stat-row" style="border-bottom:1px solid var(--border);padding:5px 0;display:flex;justify-content:space-between;gap:10px">
        <span>${esc(k)}</span><span style="font-weight:600;color:var(--text-2);text-align:right">${esc(v)}</span></div>`).join('');

    if (isOrgAdmin()) {
      const st = await AudinexiaAuth.authFetch('/api/admin/settings');
      if (st.ok) {
        const d = await st.json();
        document.getElementById('cfgPolicyInterval').value = d.default_policy_review_interval_days;
        document.getElementById('cfgVendorInterval').value = d.default_vendor_review_interval_days;
        document.getElementById('cfgOrgName').value = d.organization.name;
      }
    } else {
      ['cfgPolicyInterval','cfgVendorInterval','cfgOrgName'].forEach(id => {
        const el = document.getElementById(id);
        el.disabled = true; el.placeholder = 'org_admin only';
      });
      document.getElementById('cfgSaveBtn').style.display = 'none';
    }
  } catch (e) { /* page stays readable; each block fails independently */ }
}

window.saveOrgSettings = async () => {
  const res = await AudinexiaAuth.authFetch('/api/admin/settings', {
    method: 'PATCH', headers: {'Content-Type':'application/json'},
    body: JSON.stringify({
      default_policy_review_interval_days: Number(document.getElementById('cfgPolicyInterval').value),
      default_vendor_review_interval_days: Number(document.getElementById('cfgVendorInterval').value),
      name: document.getElementById('cfgOrgName').value.trim() || undefined,
    }),
  });
  const data = await res.json();
  showToast(res.ok ? 'Defaults saved' : (data.error || 'Could not save'));
};

window.changeOwnPassword = async () => {
  const res = await AudinexiaAuth.authFetch('/api/auth/change-password', {
    method: 'POST', headers: {'Content-Type':'application/json'},
    body: JSON.stringify({
      current_password: document.getElementById('pwCurrent').value,
      new_password: document.getElementById('pwNew').value,
    }),
  });
  const data = await res.json();
  if (!res.ok) { showToast(data.error || 'Could not change password'); return; }
  // The server invalidated every token for this account, so the client must not
  // pretend the session is still live.
  showToast('Password updated — sign in again');
  setTimeout(() => { AudinexiaAuth.clearSession(); window.location.href = '/login'; }, 1200);
};

/* ── Team roster ── */
async function loadTeam() {
  document.getElementById('newUserBtn').style.display = isOrgAdmin() ? '' : 'none';
  const tbody = document.getElementById('teamTableBody');
  try {
    const res = await AudinexiaAuth.authFetch('/api/admin/users');
    if (!res.ok) { tbody.innerHTML = `<tr><td colspan="7" style="text-align:center;color:var(--danger);padding:20px">User list requires org_admin, compliance_manager or auditor access (${esc(res.status)})</td></tr>`; return; }
    const users = (await res.json()).users || [];
    const me = AudinexiaAuth.getCurrentUser();
    if (!users.length) { tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;color:var(--muted);padding:20px">No members.</td></tr>'; return; }
    tbody.innerHTML = users.map(u => `
      <tr>
        <td style="font-weight:600">${esc(u.name)}${u.id === (me && me.id) ? ' <span style="font-size:10.5px;color:var(--muted)">(you)</span>' : ''}</td>
        <td style="font-size:12px;color:var(--muted)">${esc(u.email)}</td>
        <td><span class="badge ${esc(u.role==='org_admin'?'badge-accent':u.role==='read_only'?'badge-blue':'badge-green')}">${esc(u.role.replace(/_/g,' '))}</span></td>
        <td>${u.is_active ? '<span class="badge badge-green">Active</span>' : '<span class="badge badge-red">Disabled</span>'}
            ${u.must_change_password ? '<div style="font-size:10.5px;color:var(--warn)">temp password in use</div>' : ''}</td>
        <td>${esc(u.open_remediations || 0)}</td>
        <td style="font-size:11.5px;color:var(--muted)">${esc(u.last_login_at ? u.last_login_at.slice(0,10) : 'never')}</td>
        <td style="white-space:nowrap">${isOrgAdmin() && u.id !== (me && me.id) ? `
          <button class="btn btn-secondary btn-sm" data-action="openUserModal" data-args="${esc(JSON.stringify([u.id]))}">Manage</button>` : ''}</td>
      </tr>`).join('');
  } catch (e) {
    tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;color:var(--danger);padding:20px">Could not reach server</td></tr>';
  }
}

window.openUserModal = async (userId) => {
  let user = null;
  if (typeof userId === 'number') {
    const res = await AudinexiaAuth.authFetch('/api/admin/users');
    if (res.ok) user = ((await res.json()).users || []).find(u => u.id === userId) || null;
  }
  const roles = ['org_admin','compliance_manager','auditor','member','read_only'];
  const roleOptions = roles.map(r => `<option value="${esc(r)}" ${user && user.role===r?'selected':''}>${esc(r.replace(/_/g,' '))}</option>`).join('');
  document.getElementById('modalTitle').textContent = user ? `Manage ${user.name}` : 'Add team member';
  document.getElementById('modalBody').innerHTML = `
    ${user ? `
      <div class="modal-field"><div class="field-label">Role</div>
        <select id="uRole" style="width:100%;padding:6px">${roleOptions}</select></div>
      <div class="modal-field" style="margin-top:8px"><div class="field-label">New temp password (forces a change at next login)</div>
        <input id="uTempPw" type="text" style="width:100%;padding:6px" placeholder="min 10 characters">
        <button class="btn btn-secondary btn-sm" style="margin-top:8px" data-action="adminResetPw" data-args="${esc(JSON.stringify([user.id]))}">Set password</button></div>
      <div style="margin-top:12px;display:flex;gap:8px">
        <button class="btn btn-primary btn-sm" data-action="saveUserRole" data-args="${esc(JSON.stringify([user.id]))}">Save role</button>
        <button class="btn ${user.is_active?'btn-secondary':'btn-primary'} btn-sm" data-action="toggleUserActive" data-args="${esc(JSON.stringify([user.id, user.is_active]))}">${user.is_active?'Deactivate':'Reactivate'}</button>
      </div>
      <div style="font-size:11.5px;color:var(--muted);margin-top:10px">Deactivating invalidates this member's existing tokens immediately rather than at their next login.</div>`
    : `
      <div class="modal-field"><div class="field-label">Name</div><input id="uName" style="width:100%;padding:6px"></div>
      <div class="modal-field" style="margin-top:8px"><div class="field-label">Email</div><input id="uEmail" style="width:100%;padding:6px"></div>
      <div class="modal-field" style="margin-top:8px"><div class="field-label">Role</div><select id="uRole" style="width:100%;padding:6px">${roleOptions}</select></div>
      <div class="modal-field" style="margin-top:8px"><div class="field-label">Temporary password</div><input id="uTempPw" type="text" style="width:100%;padding:6px"></div>
      <div style="margin-top:12px"><button class="btn btn-primary btn-sm" data-action="createUser">Create account</button></div>`}`;
  document.getElementById('modal').classList.add('open');
};

window.createUser = async () => {
  const res = await AudinexiaAuth.authFetch('/api/admin/users', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({
      name: document.getElementById('uName').value.trim(),
      email: document.getElementById('uEmail').value.trim(),
      role: document.getElementById('uRole').value,
      temp_password: document.getElementById('uTempPw').value,
    }),
  });
  const data = await res.json();
  if (!res.ok) { showToast(data.error || 'Could not create user'); return; }
  showToast('Account created');
  document.getElementById('modal').classList.remove('open');
  loadTeam();
};

window.saveUserRole = async (userId) => {
  const res = await AudinexiaAuth.authFetch(`/api/admin/users/${userId}`, {
    method:'PATCH', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({ role: document.getElementById('uRole').value }),
  });
  const data = await res.json();
  showToast(res.ok ? 'Role updated' : (data.error || 'Could not update role'));
  loadTeam();
};

window.toggleUserActive = async (userId, currentlyActive) => {
  const res = await AudinexiaAuth.authFetch(`/api/admin/users/${userId}`, {
    method:'PATCH', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({ is_active: !currentlyActive }),
  });
  const data = await res.json();
  showToast(res.ok ? (currentlyActive ? 'Account deactivated' : 'Account reactivated') : (data.error || 'Could not update'));
  loadTeam();
};

window.adminResetPw = async (userId) => {
  const pw = document.getElementById('uTempPw').value;
  if (!pw) { showToast('Enter a temporary password'); return; }
  const res = await AudinexiaAuth.authFetch(`/api/admin/users/${userId}/password`, {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({ new_password: pw }),
  });
  const data = await res.json();
  showToast(res.ok ? 'Password reset; sessions invalidated' : (data.error || 'Could not reset'));
};

/* ── Recent activity (audit trail, not a mock feed) ── */
async function loadActivityFeed() {
  const feed = document.getElementById('activityFeed');
  try {
    const res = await AudinexiaAuth.authFetch('/api/admin/audit-trail?limit=6');
    if (!res.ok) {
      feed.innerHTML = '<div class="empty-state" style="padding:16px"><div class="empty-label" style="font-size:12px">' +
        (res.status === 403 ? 'Activity details are available to org_admin, compliance_manager and auditor roles.' : 'Could not load activity.') +
        '</div></div>';
      document.getElementById('activityCount').textContent = '—';
      return;
    }
    const data = await res.json();
    document.getElementById('activityCount').textContent = data.count;
    if (!data.events.length) {
      feed.innerHTML = '<div class="empty-state" style="padding:16px"><div class="empty-label" style="font-size:12px">No recorded activity yet.</div></div>';
      return;
    }
    const COLOR = { scan:'var(--accent)', review:'#7c3aed', vendor:'#0891b2', monitoring:'#f59e0b',
                    risk:'var(--danger)', audit:'var(--success)', auth:'var(--muted)', admin:'#d97706' };
    feed.innerHTML = data.events.map(e => {
      const family = (e.action || '').split('.')[0];
      return `<div class="activity-item">
        <div class="activity-dot" style="background:${esc(COLOR[family] || 'var(--muted)')}"></div>
        <div>
          <div class="activity-text">${esc(e.summary || e.action)}</div>
          <div class="activity-time">${esc((e.created_at||'').slice(0,16).replace('T',' '))} UTC · ${esc(e.actor || 'system')}</div>
        </div>
      </div>`;
    }).join('');
  } catch (err) {
    feed.innerHTML = '<div class="empty-state" style="padding:16px"><div class="empty-label" style="font-size:12px">Could not reach server.</div></div>';
  }
}

/* ── Sign-out (shared by the sidebar control and the config page) ── */
window.signOutNow = window.signOutNow || (() => AudinexiaAuth.logout());

/* ── Forced password change ── */
// The server refuses every tenant API while must_change_password is set
// (security.password_change_gate). This is the recovery path for that, wired two
// ways: on load (so an admin-created account lands on the form) and on the event
// auth.js raises if a 403 arrives mid-session (e.g. an admin resets a password
// while the user is working).
function forcePasswordChange() {
  navigate('config');
  const note = document.getElementById('pwForceNote');
  if (note) note.style.display = '';
  const current = document.getElementById('pwCurrent');
  if (current) current.focus();
  if (window.showToast) showToast('Set a new password to activate your account');
}
window.addEventListener('audinexia:password-required', forcePasswordChange);

/* ── Init ── */
setStep(1);
// Confirm the cookie session is really still valid and pick up any role or
// forced-password change made since login (redirects to /login if it isn't).
AudinexiaAuth.verifySession().then(ok => { if (!ok) window.location.href = '/login'; });
if (AudinexiaAuth.getCurrentUser()) {
  loadRealNotifications();
  loadActivityFeed();
  const forceParam = new URLSearchParams(window.location.search).get('force_password');
  if (forceParam === '1' || AudinexiaAuth.passwordChangeRequired()) {
    forcePasswordChange();
    // Drop the flag from the URL so a reload does not re-trigger the jump.
    if (window.history && history.replaceState) history.replaceState(null, '', '/dashboard');
  }
}
