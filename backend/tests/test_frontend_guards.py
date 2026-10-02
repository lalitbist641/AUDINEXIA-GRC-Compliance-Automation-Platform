"""Guards for the browser-side security posture.

The UI is plain JS building HTML strings, so the protections are conventions
(escape every interpolation, no inline script, delegated click handling). These
tests pin the conventions that can be checked mechanically so a later edit can't
quietly undo them. They don't replace reading a diff for a new `${...}` sink.
"""

import re
from pathlib import Path

BACKEND = Path(__file__).resolve().parent.parent
TEMPLATES = [BACKEND / 'templates' / 'dashboard.html', BACKEND / 'templates' / 'login.html']
DASHBOARD_JS = BACKEND / 'static' / 'js' / 'dashboard.js'


def _read(path):
    return path.read_text(encoding='utf-8')


def test_templates_have_no_inline_script_or_event_handler_attributes():
    for template in TEMPLATES + [BACKEND / 'templates' / 'error.html']:
        html = _read(template)
        inline_scripts = re.findall(r'<script(?![^>]*\bsrc=)[^>]*>', html, re.I)
        assert not inline_scripts, f'{template.name} has an inline <script>: a strict CSP would block it'
        handlers = re.findall(r'\son[a-z]+\s*=\s*["\']', html, re.I)
        assert not handlers, f'{template.name} has inline event-handler attributes: {handlers[:3]}'


def test_dashboard_js_builds_no_inline_handlers():
    js = _read(DASHBOARD_JS)
    assert not re.findall(r'\son(click|change|input|submit|error|load)\s*=\s*["\'\\]', js), (
        'dashboard.js generates an inline event-handler attribute; use data-action instead')
    assert 'javascript:' not in js


def test_every_data_action_resolves_to_a_global_function():
    # Collected from both the static template and the strings dashboard.js builds.
    text = _read(TEMPLATES[0]) + _read(DASHBOARD_JS)
    actions = set(re.findall(r'data-action="(\w+)"', text))
    assert len(actions) > 30, 'expected the dispatcher to be wired to the dashboard actions'
    js = _read(DASHBOARD_JS)
    missing = []
    for name in sorted(actions):
        defined = (re.search(rf'window\.{name}\s*=', js) or re.search(rf'\bfunction\s+{name}\s*\(', js))
        if not defined:
            missing.append(name)
    assert not missing, f'data-action names with no global handler: {missing}'


def test_dispatcher_only_runs_functions_found_on_window():
    js = _read(DASHBOARD_JS)
    assert "typeof fn !== 'function'" in js, 'the dispatcher must refuse names that are not functions'
    # data-args is parsed as JSON, never evaluated.
    assert 'JSON.parse(el.dataset.args)' in js
    assert 'eval(' not in js and 'new Function(' not in js


def test_csp_forbids_inline_and_eval_script(client):
    for path in ('/dashboard', '/login', '/healthz'):
        response = client.get(path)
        csp = response.headers.get('Content-Security-Policy', '')
        script_src = re.search(r"script-src ([^;]*)", csp)
        assert script_src, f'{path} has no script-src: {csp!r}'
        assert script_src.group(1).strip() == "'self'", (
            f"{path}: script-src must be exactly 'self', got {script_src.group(1)!r}")
        assert "'unsafe-eval'" not in csp
        assert "frame-ancestors 'none'" in csp and "object-src 'none'" in csp


def test_extracted_scripts_are_served(client):
    for name in ('auth.js', 'dashboard.js', 'login.js'):
        response = client.get(f'/static/js/{name}')
        assert response.status_code == 200, name
        assert b'<script' not in response.data[:200]
    page = client.get('/dashboard').get_data(as_text=True)
    assert '/static/js/dashboard.js' in page


def test_unknown_page_renders_a_404_page_not_a_500(client):
    response = client.get('/no-such-page')
    assert response.status_code == 404
    assert 'text/html' in response.headers['Content-Type']
    assert 'Not found' in response.get_data(as_text=True)


def test_unknown_page_echoes_the_path_escaped(client):
    response = client.get('/<script>alert(1)</script>')
    body = response.get_data(as_text=True)
    assert response.status_code == 404
    assert '<script>alert(1)</script>' not in body
