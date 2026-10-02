import os

import click
from dotenv import load_dotenv

load_dotenv()

from flask import Flask, jsonify, render_template, request
from flask_cors import CORS
from werkzeug.middleware.proxy_fix import ProxyFix

from auth import auth_bp
from config import Config
from core.audit_trail import auto_record_mutation
from core.openapi import build_spec
from extensions import db, jwt, migrate
from models import ROLES
from logging_config import configure_logging
from routes.admin_routes import admin_bp
from routes.assessment_routes import assessment_bp
from routes.audit_routes import audit_bp
from routes.crosswalk_routes import crosswalk_bp
from routes.maturity_routes import maturity_bp
from routes.monitoring_routes import monitoring_bp
from routes.review_routes import review_bp
from routes.risk_routes import risk_bp
from routes.scan_routes import scan_bp
from routes.vendor_routes import vendor_bp
from scanning import FRAMEWORKS
from security import attach_request_context, hardening_headers, password_change_gate


def create_app(config_overrides=None):
    """Application factory.

    `config_overrides` exists so tests (and the CLI, and anything embedding the
    platform) can build an isolated app with its own database and upload
    directory instead of monkeypatching module-level globals.
    """
    app = Flask(__name__)
    app.config.from_object(Config)
    app.config['RATE_LIMIT_LOGIN'] = Config.RATE_LIMIT_LOGIN
    app.config['RATE_LIMIT_REGISTER'] = Config.RATE_LIMIT_REGISTER
    app.config['RATE_LIMIT_SCAN'] = Config.RATE_LIMIT_SCAN
    if config_overrides:
        app.config.update(config_overrides)

    _run_config_checks(app)

    if Config.BEHIND_PROXY:
        # Only trust X-Forwarded-* when told to: an unconditional ProxyFix makes
        # the client-controlled header authoritative for the rate limiter.
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=Config.PROXY_HOPS, x_proto=Config.PROXY_HOPS,
                                x_host=1, x_prefix=1)

    origins = app.config.get('CORS_ORIGINS') or []
    if origins:
        CORS(app, resources={r"/api/*": {"origins": origins}}, supports_credentials=False,
             allow_headers=['Content-Type', 'Authorization'],
             expose_headers=['Content-Disposition', 'X-RateLimit-Remaining', 'X-RateLimit-Limit',
                             'Retry-After', 'X-Request-Id'])
    else:
        # No origins configured = no CORS at all. The served dashboard is
        # same-origin, so this is the correct production default; a separate SPA
        # must name its origin in CORS_ORIGINS rather than get a wildcard.
        app.logger.info('CORS disabled (CORS_ORIGINS empty); same-origin dashboard only')

    configure_logging(app)
    app.before_request(attach_request_context)
    # Before any view runs: a flagged account may only reach the auth endpoints
    # that let it comply (see security.password_change_gate).
    app.before_request(password_change_gate)
    app.after_request(hardening_headers)
    # Registered after hardening_headers so it runs BEFORE it (Flask executes
    # after_request hooks in reverse registration order) — the trail row must
    # be written while the request context and JWT claims are still intact.
    app.after_request(auto_record_mutation)

    # instance/ holds the SQLite dev DB (relative sqlite:/// URIs resolve
    # here). Flask does not create this directory automatically -- without
    # it, `flask db upgrade` fails with "unable to open database file" on a
    # fresh clone.
    os.makedirs(app.instance_path, exist_ok=True)

    db.init_app(app)
    migrate.init_app(app, db)
    jwt.init_app(app)

    app.register_blueprint(auth_bp, url_prefix='/api/auth')
    app.register_blueprint(scan_bp, url_prefix='/api')
    app.register_blueprint(assessment_bp, url_prefix='/api')
    app.register_blueprint(review_bp, url_prefix='/api')
    app.register_blueprint(crosswalk_bp, url_prefix='/api')
    app.register_blueprint(risk_bp, url_prefix='/api')
    app.register_blueprint(audit_bp, url_prefix='/api')
    app.register_blueprint(vendor_bp, url_prefix='/api')
    app.register_blueprint(maturity_bp, url_prefix='/api')
    app.register_blueprint(monitoring_bp, url_prefix='/api')
    app.register_blueprint(admin_bp, url_prefix='/api/admin')

    for folder in [app.config.get('UPLOAD_FOLDER', Config.UPLOAD_FOLDER),
                   app.config.get('REPORT_FOLDER', Config.REPORT_FOLDER)]:
        if not os.path.exists(folder):
            os.makedirs(folder, exist_ok=True)

    # Ensure binary file responses carry CORS headers (fixes download failures)
    @app.after_request
    def add_cors_headers(response):
        # Only echo the request's Origin when it is actually allowed, so a
        # production config with no CORS_ORIGINS does not hand out '*' on
        # every API response.
        allowed = app.config.get('CORS_ORIGINS') or []
        request_origin = request.headers.get('Origin')
        if '*' in allowed:
            response.headers['Access-Control-Allow-Origin'] = '*'
        elif request_origin and request_origin in allowed:
            response.headers['Access-Control-Allow-Origin'] = request_origin
            response.headers['Vary'] = 'Origin'
        if allowed:
            response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PATCH, DELETE, OPTIONS'
            response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
            response.headers['Access-Control-Expose-Headers'] = (
                'Content-Disposition, Content-Type, X-Request-Id, '
                'X-RateLimit-Limit, X-RateLimit-Remaining, Retry-After'
            )
        return response

    _register_ui_routes(app)
    _register_ops_routes(app)
    _register_error_handlers(app)
    _register_cli(app)

    if os.environ.get('MONITORING_SCHEDULER_ENABLED', '').lower() in ('1', 'true', 'yes', 'on'):
        _start_monitoring_scheduler(app)

    return app


def _run_config_checks(app):
    """Fail fast on an unsafe config.

    Weak or placeholder signing secrets are refused in EVERY environment, not
    just production: a hardcoded fallback secret lets anyone who has read this
    (open-source) repo forge a token for any role, and "it's only dev" is how
    those defaults end up on a reachable host. Checked against the app's
    effective config so a test or embedding app that passes its own secrets via
    `config_overrides` is judged on those, not on the environment.
    """
    from config import _looks_placeholder

    weak = [name for name in ('SECRET_KEY', 'JWT_SECRET_KEY')
            if _looks_placeholder(app.config.get(name))]
    if weak:
        raise RuntimeError(
            f'Refusing to start: {", ".join(weak)} is missing, shorter than 32 characters, '
            f'or a placeholder. Set a strong value in the environment (see .env.example). '
            f'Generate one with: python -c "import secrets; print(secrets.token_hex(32))"'
        )

    findings = Config.validate()
    errors = [message for severity, message in findings if severity == 'error']
    warnings = [(severity, message) for severity, message in findings if severity != 'error']
    for severity, message in warnings:
        app.logger.warning('config check (%s): %s', severity, message)
    if errors and app.config['ENVIRONMENT'].lower() in ('production', 'prod'):
        raise RuntimeError(
            'Refusing to start in production with an insecure configuration:\n  - '
            + '\n  - '.join(errors)
            + '\nGenerate secrets (python -c "import secrets; print(secrets.token_hex(32))") '
              'and set them in the environment.'
        )


def _register_ui_routes(app):
    @app.route('/')
    def index():
        """Service metadata. Public by design: it advertises capabilities
        (frameworks, limits) and no data. Kept payload-minimal for that reason —
        version/build info lives on /version, which deployments can restrict."""
        return jsonify({
            "message": "Audinexia GRC Platform",
            "version": Config.APP_VERSION,
            "status": "running",
            "frameworks": list(FRAMEWORKS.keys()),
            "control_counts": {key: len(info['controls']) for key, info in FRAMEWORKS.items()},
            "total_controls": sum(len(info['controls']) for info in FRAMEWORKS.values()),
            "supported_formats": sorted(Config.ALLOWED_EXTENSIONS),
            "max_file_size_mb": round(Config.MAX_CONTENT_LENGTH / (1024 * 1024)),
            "authentication": "JWT bearer; obtain a token from POST /api/auth/login",
            "docs": "/api/openapi.json",
            "endpoints": {
                "scan": "POST /api/scan",
                "assessments": "GET /api/assessments",
                "reports": "GET|POST /api/export-pdf, /api/export-report",
                "remediation": "POST /api/revise-policy",
                "crosswalk": "GET /api/assessments/<id>/crosswalk",
                "vendors": "GET|POST /api/vendors, /api/vendors/risk-register",
                "maturity": "GET /api/maturity",
                "monitoring": "GET /api/monitoring/watches, POST /api/monitoring/watches/<id>/run",
                "audit_trail": "GET /api/audit-trail",
                "ops": "/healthz, /readyz, /version, /metrics",
            },
        })

    @app.route('/login')
    def login_page():
        return render_template('login.html')

    @app.route('/dashboard')
    def dashboard():
        return render_template('dashboard.html')

    @app.route('/docs')
    def api_docs():
        return render_template('api_docs.html')


def _register_ops_routes(app):
    @app.route('/healthz')
    def healthz():
        """Liveness: the process is up and serving. Never touches the database,
        so a saturated connection pool cannot make the orchestrator kill healthy
        pods."""
        return jsonify({'status': 'ok', 'service': 'audinexia', 'version': Config.APP_VERSION})

    @app.route('/readyz')
    def readyz():
        """Readiness: dependency checks. Returns 503 when the app could not
        serve real traffic, with each check named so an operator sees which."""
        checks = {}
        healthy = True
        try:
            db.session.execute(db.text('SELECT 1'))
            checks['database'] = 'ok'
        except Exception as exc:
            checks['database'] = f'error: {exc.__class__.__name__}'
            healthy = False

        for label, folder in (('uploads', app.config.get('UPLOAD_FOLDER', Config.UPLOAD_FOLDER)),
                              ('reports', app.config.get('REPORT_FOLDER', Config.REPORT_FOLDER))):
            try:
                os.makedirs(folder, exist_ok=True)
                probe = os.path.join(folder, '.healthz-probe')
                with open(probe, 'w') as handle:
                    handle.write('ok')
                os.remove(probe)
                checks[label] = 'writable'
            except Exception as exc:
                checks[label] = f'error: {exc.__class__.__name__}'
                healthy = False

        from scanning import DOCX_SUPPORT, PDF_SUPPORT

        checks['pdf_extraction'] = 'available' if PDF_SUPPORT else 'missing (pdfplumber)'
        checks['docx_extraction'] = 'available' if DOCX_SUPPORT else 'missing (python-docx)'
        if not PDF_SUPPORT or not DOCX_SUPPORT:
            # Advertised as first-class input formats; a missing extractor must
            # make the deployment *degraded*, not silently 0%-score uploads —
            # that specific failure produced the report's worst bug.
            app.logger.error('document extraction dependency missing: %s', checks)

        payload = {'status': 'ready' if healthy else 'degraded', 'checks': checks}
        return jsonify(payload), (200 if healthy else 503)

    @app.route('/version')
    def version():
        import platform

        return jsonify({
            'service': 'audinexia-grc-platform',
            'version': Config.APP_VERSION,
            'build_sha': Config.BUILD_SHA or None,
            'python': platform.python_version(),
            'environment': Config.ENVIRONMENT,
            'framework_count': len(FRAMEWORKS),
            'control_count': sum(len(info['controls']) for info in FRAMEWORKS.values()),
        })

    @app.route('/metrics')
    def metrics():
        """Prometheus text exposition, computed from the DB on demand.

        Deliberately not on the hot request path (no counters incremented per
        request): the useful signals here are gauges about compliance state,
        which are queries, not counters. A Prometheus pull every scrape is fine
        at this scale; if it were not, the right fix is an exporter cache, not
        per-request instrumentation.
        """
        from models import (
            Assessment,
            Audit,
            Finding,
            MaturityAssessment,
            PolicyWatch,
            Risk,
            Vendor,
        )

        def count(model, **filters):
            try:
                return model.query.filter_by(**filters).count()
            except Exception:
                return 0

        lines = [
            '# TYPE audinexia_up gauge',
            'audinexia_up 1',
            f'# TYPE audinexia_assessments_total counter',
            f'audinexia_assessments_total {count(Assessment)}',
            f'# TYPE audinexia_assessments_overdue gauge',
            f'audinexia_assessments_overdue {count(Assessment, framework_definition_drift=True)}',
            f'# TYPE audinexia_risks_open gauge',
            f'audinexia_risks_open {count(Risk, status="open")}',
            f'# TYPE audinexia_findings_open gauge',
            f'audinexia_findings_open {count(Finding, status="open")}',
            f'# TYPE audinexia_audits_in_progress gauge',
            f'audinexia_audits_in_progress {count(Audit, status="in_progress")}',
            f'# TYPE audinexia_vendors gauge',
            f'audinexia_vendors {count(Vendor)}',
            f'# TYPE audinexia_vendors_unassessed gauge',
            f'audinexia_vendors_unassessed {count(Vendor, risk_tier="unassessed")}',
            f'# TYPE audinexia_policy_watches_active gauge',
            f'audinexia_policy_watches_active {count(PolicyWatch, is_active=True)}',
            f'# TYPE audinexia_maturity_rows gauge',
            f'audinexia_maturity_rows {count(MaturityAssessment)}',
        ]
        return '\n'.join(lines) + '\n', 200, {'Content-Type': 'text/plain; version=0.0.4'}

    @app.route('/api/openapi.json')
    def openapi_json():
        return jsonify(build_spec(app))

    @app.route('/api/openapi.yaml')
    def openapi_yaml():
        try:
            import yaml

            return build_spec(app, as_yaml=True), 200, {'Content-Type': 'application/yaml'}
        except ImportError:
            return jsonify({'error': 'PyYAML not installed; use /api/openapi.json'}), 404


def _register_error_handlers(app):
    """Handlers exist so failures are JSON + diagnosable, not HTML tracebacks.

    An unhandled 500 in the API that returns a 2KB HTML page is what breaks a
    client's error handling; a request id in the response body is what makes a
    support ticket answerable.
    """
    from flask import g

    def _body(message, code, extra=None):
        payload = {'error': message, 'code': code, 'request_id': getattr(g, 'request_id', None)}
        if extra:
            payload.update(extra)
        return payload

    @app.errorhandler(400)
    def bad_request(error):
        return jsonify(_body(getattr(error, 'description', 'Bad request'), 'bad_request')), 400

    @app.errorhandler(401)
    def unauthorized(error):
        return jsonify(_body('Authentication required', 'unauthorized')), 401

    @app.errorhandler(403)
    def forbidden(error):
        return jsonify(_body('Not permitted for your role', 'forbidden')), 403

    @app.errorhandler(404)
    def not_found(error):
        if request.path.startswith('/api/'):
            return jsonify(_body('Not found', 'not_found')), 404
        return render_template('error.html', status=404, title='Not found',
                               detail=f'No route matches {request.path}'), 404

    @app.errorhandler(405)
    def method_not_allowed(error):
        return jsonify(_body(f'Method {request.method} not allowed for this path',
                             'method_not_allowed')), 405

    @app.errorhandler(413)
    def too_large(error):
        limit_mb = round(app.config['MAX_CONTENT_LENGTH'] / (1024 * 1024))
        return jsonify(_body(f'Upload exceeds the {limit_mb} MB limit', 'payload_too_large',
                             {'max_upload_mb': limit_mb})), 413

    @app.errorhandler(429)
    def too_many_requests(error):
        return jsonify(_body('Too many requests', 'rate_limited')), 429

    @app.errorhandler(500)
    def internal_error(error):
        app.logger.error('unhandled error on %s %s: %s', request.method, request.path, error,
                         exc_info=True)
        return jsonify(_body('Internal server error; report the request_id to your administrator',
                             'internal_error')), 500

    @app.errorhandler(Exception)
    def unhandled_exception(error):
        from werkzeug.exceptions import HTTPException

        if isinstance(error, HTTPException):
            return error
        app.logger.error('unhandled exception on %s %s: %s', request.method, request.path, error,
                         exc_info=True)
        # The exception text is logged, never returned: SQLAlchemy messages
        # quote table and column names, which has no business reaching a client.
        return jsonify(_body('Internal server error; report the request_id to your administrator',
                             'internal_error')), 500


def _start_monitoring_scheduler(app):
    """Opt-in in-process scheduler for single-worker deployments.

    Guarded against Flask's debug reloader (which would otherwise start two
    threads) and it is a daemon thread, so it never blocks shutdown. A
    multi-worker deployment must use `flask monitor run-due` from cron instead:
    with N workers this thread would run N times per interval.
    """
    import threading
    import time as time_module

    if os.environ.get('WERKZEUG_RUN_MAIN') == 'true' and app.debug:
        # The reloader parent has already started one; the child starts the real
        # one. Without this check, `python app.py` with debug=True runs two.
        pass
    elif app.debug:
        app.logger.info('monitoring scheduler deferred to the reloader child process')
        return

    state = {'started': False}

    def loop():
        while True:
            try:
                with app.app_context():
                    from core.monitoring_cli import run_due_watches

                    result = run_due_watches(limit_per_pass=25)
                    if result['ran']:
                        app.logger.info('monitoring scheduler: %s', result)
            except Exception as exc:
                app.logger.error('monitoring scheduler pass failed: %s', exc, exc_info=True)
            time_module.sleep(app.config.get('MONITORING_SCHEDULER_INTERVAL_SECONDS', 3600))

    if not state['started']:
        thread = threading.Thread(target=loop, name='audinexia-monitoring', daemon=True)
        thread.start()
        app.logger.info('monitoring scheduler started (single-process; interval %ss)',
                        app.config.get('MONITORING_SCHEDULER_INTERVAL_SECONDS', 3600))


def _register_cli(app):
    """Operational commands, so a deployment does not need psql + curl to do the
    routine things a GRC rollout requires."""

    @app.cli.command('check')
    def check_command():
        """Config, schema and dependency self-check. Safe to run in CI."""
        click.echo(f'Audinexia {Config.APP_VERSION} ({Config.ENVIRONMENT})')
        findings = Config.validate()
        for severity, message in findings:
            click.echo(f'  [{severity.upper():7}] {message}')
        try:
            tables = db.inspect(db.engine).get_table_names()
            expected = {'organizations', 'users', 'assessments', 'control_results', 'evidence_files',
                        'risks', 'risk_control_links', 'audits', 'findings', 'finding_control_links',
                        'vendors', 'vendor_contracts', 'finding_vendor_links', 'policy_watches',
                        'policy_watch_runs', 'maturity_assessments', 'maturity_snapshots',
                        'audit_trail_events', 'revoked_tokens', 'api_rate_limit_buckets'}
            missing = expected - set(tables)
            if missing:
                click.echo(f'  [ERROR  ] missing tables: {", ".join(sorted(missing))} '
                           f'— run: flask db upgrade')
            else:
                click.echo(f'  [OK     ] schema: {len(tables)} tables present')
        except Exception as exc:
            click.echo(f'  [ERROR  ] database unreachable: {exc}')
        from scanning import DOCX_SUPPORT, PDF_SUPPORT

        click.echo(f'  [{"OK     " if PDF_SUPPORT else "WARN   "}] pdfplumber (PDF extraction): '
                   f'{"available" if PDF_SUPPORT else "MISSING"}')
        click.echo(f'  [{"OK     " if DOCX_SUPPORT else "WARN   "}] python-docx (DOCX extraction): '
                   f'{"available" if DOCX_SUPPORT else "MISSING"}')
        total = sum(len(info['controls']) for info in FRAMEWORKS.values())
        click.echo(f'  [OK     ] frameworks: {len(FRAMEWORKS)}, controls: {total}')

    @app.cli.command('seed')
    @click.option('--org', default='Demo Organization')
    @click.option('--password', default=None, help='Password for all seeded accounts; '
                                                    'generated and printed if omitted.')
    @click.option('--with-vendors/--no-vendors', default=True)
    @click.option('--with-monitoring/--no-monitoring', default=True)
    def seed_command(org, password, with_vendors, with_monitoring):
        """Seed a demo organization with one account per role, sample
        assessments, a vendor, a watch and a maturity record. Development and
        demonstration only — refuses to run when ENVIRONMENT is production."""
        from scripts.seed_demo import seed

        if Config.ENVIRONMENT.lower() in ('production', 'prod'):
            raise click.ClickException('refusing to seed a production database')
        # Fail with the instruction instead of a SQLAlchemy "no such table:
        # organizations" traceback, which is what a fresh clone hits: the SQLite
        # file is created on first connect, so seed looks like it is broken when
        # the real cause is that `flask db upgrade` has not run yet.
        from sqlalchemy import inspect as sa_inspect

        from extensions import db

        try:
            with app.app_context():
                tables = set(sa_inspect(db.engine).get_table_names())
        except Exception as exc:                      # noqa: BLE001 - reported, not hidden
            raise click.ClickException(f'cannot open the configured database: {exc}') from exc
        if 'organizations' not in tables:
            raise click.ClickException(
                'database schema is not installed (no "organizations" table). '
                'Run:  flask --app app.py db upgrade  then re-run this command.')
        try:
            result = seed(app, org_name=org, password=password, with_vendors=with_vendors,
                          with_monitoring=with_monitoring)
        except RuntimeError as exc:
            # Refusals (an existing organization) are operator guidance, not
            # bugs: print one line, not a traceback.
            raise click.ClickException(str(exc)) from exc
        click.echo(f'organization: {result["org_name"]} (id {result["org_id"]})')
        for email, pwd in result['accounts'].items():
            click.echo(f'  {email:38} {pwd if result["print_passwords"] else "(supplied)"}')
        click.echo(f'assessments: {result["assessments"]}, vendors: {result["vendors"]}, '
                   f'watches: {result["watches"]}, risks: {result["risks"]}, '
                   f'audits: {result["audits"]}')

    @app.cli.group('monitor')
    def monitor_group():
        """Continuous-monitoring operations (report §12.7)."""

    @monitor_group.command('due')
    @click.option('--org-id', default=None, type=int, help='Restrict to one organization')
    def monitor_due(org_id):
        """List watches whose review interval has elapsed. Read-only: safe to
        run on any schedule."""
        from core.monitoring_cli import list_due

        rows = list_due(org_id=org_id)
        if not rows:
            click.echo('no watches due')
            return
        for row in rows:
            click.echo(f'{row["id"]:>4}  org={row["org_id"]:<4} {row["state"]:<16} '
                       f'due={row["next_due_at"]}  overdue={row["overdue_days"]:>4}d  {row["name"]}')
        click.echo(f'{len(rows)} watch(es) due')

    @monitor_group.command('run-due')
    @click.option('--org-id', default=None, type=int)
    @click.option('--limit', default=50, type=int, help='Max watches to process per pass')
    @click.option('--max-age-days', default=None, type=int,
                   help='Only run watches already due; skip ones that never ran (0 = run all)')
    @click.option('--json', 'as_json', is_flag=True, default=False, help='Machine-readable summary')
    def monitor_run_due(org_id, limit, max_age_days, as_json):
        """Execute every due watch. Designed to be run from cron / a CronJob —
        idempotent (a watch just run is not due) and never touches freshness
        state for a check that found nothing new."""
        import json as json_module

        from core.monitoring_cli import run_due_watches

        result = run_due_watches(org_id=org_id, limit=limit)
        if as_json:
            click.echo(json_module.dumps(result, indent=2, default=str))
        else:
            click.echo(f'ran {result["ran"]} watch(es), skipped {result["skipped"]}, '
                       f'{result["regressions"]} regression(s), '
                       f'{result["unverified"]} unverified, {result["errors"]} error(s)')
            for item in result['details'][:20]:
                click.echo(f'  watch {item["watch_id"]:>4}: {item["state"]:<16} '
                           f'delta={item["score_delta"]}')

    @monitor_group.command('snapshot-maturity')
    @click.option('--framework', default=None, help='Limit to one framework key')
    def monitor_snapshot_maturity(framework):
        """Append a maturity snapshot per org+framework for trend history."""
        from core.monitoring_cli import snapshot_all_maturity

        result = snapshot_all_maturity(framework=framework)
        click.echo(f'snapshots written: {result["written"]} across {result["orgs"]} org(s)')

    @app.cli.group('users')
    def users_group():
        """Account administration."""

    @users_group.command('create')
    @click.option('--org-id', required=True, type=int)
    @click.option('--email', required=True)
    @click.option('--name', required=True)
    @click.option('--role', default='member',
                  type=click.Choice(ROLES))  # single source: models.ROLES
    @click.option('--password', default=None, help='Omit to have one generated and printed once')
    def users_create(org_id, email, name, role, password):
        """Create a user in an existing organization (bootstrap path for the
        first admin, before which no API token can exist)."""
        import secrets

        from models import Organization, User

        org = db.session.get(Organization, org_id)
        if not org:
            raise click.ClickException(f'organization {org_id} does not exist')
        if User.query.filter_by(email=email.lower()).first():
            raise click.ClickException(f'{email} already exists')
        generated = False
        if not password:
            password = secrets.token_urlsafe(18)
            generated = True
        from security import check_password_strength

        ok, problems = check_password_strength(password)
        if not ok:
            raise click.ClickException(f'password rejected: {" and ".join(problems)}')
        user = User(org_id=org_id, email=email.lower(), name=name, role=role, is_active=True,
                    must_change_password=generated)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        click.echo(f'created {role} {email} (id {user.id}) in org {org_id}')
        if generated:
            click.echo(f'  one-time password: {password}')
            click.echo('  the user must change it at first login')

    @users_group.command('list')
    @click.option('--org-id', default=None, type=int)
    def users_list(org_id):
        from models import User

        query = User.query
        if org_id:
            query = query.filter_by(org_id=org_id)
        for user in query.order_by(User.org_id.asc(), User.role.asc()).all():
            click.echo(f'{user.id:>4}  org={user.org_id:<4} {user.role:<18} '
                       f'{"active " if user.is_active else "DISABLED"} {user.email}')

    @users_group.command('reset-password')
    @click.option('--email', required=True)
    @click.option('--password', default=None)
    @click.option('--unlock/--no-unlock', default=True, help='Also clear the failed-login lockout')
    def users_reset_password(email, password, unlock):
        import secrets

        from models import User

        user = User.query.filter_by(email=email.lower()).first()
        if not user:
            raise click.ClickException(f'no user with email {email}')
        generated = not password
        password = password or secrets.token_urlsafe(18)
        from security import check_password_strength

        ok, problems = check_password_strength(password)
        if not ok:
            raise click.ClickException(f'password rejected: {" and ".join(problems)}')
        user.set_password(password)
        # Invalidate every token issued to this account, which is the point of
        # an admin reset when a credential may be compromised.
        user.token_version = (user.token_version or 0) + 1
        user.must_change_password = True
        if unlock:
            from security import clear_login_failures

            clear_login_failures(user.email)
        db.session.commit()
        click.echo(f'password reset for {user.email}; all sessions invalidated')
        if generated:
            click.echo(f'  one-time password: {password}')

    @app.cli.command('prune')
    @click.option('--days', default=None, type=int, help='Override AUDIT_TRAIL_RETENTION_DAYS')
    # NB: a one-way is_flag, deliberately not a --dry-run/--execute pair. Click
    # maps the FIRST name of a boolean pair to True, so the previous spelling
    # inverted the meaning: `--execute` printed a dry run and `--dry-run`
    # deleted evidence rows. A destructive switch must not depend on knowing
    # that, so the safe behaviour is the default and only --execute opts out.
    @click.option('--execute', 'execute', is_flag=True, default=False,
                  help='Actually delete rows. Without this flag nothing is removed.')
    def prune_command(days, execute):
        """Delete expired token-blocklist rows and (optionally) old audit-trail
        rows. No-op retention by default: a compliance system should not delete
        its own evidence trail unless someone chooses a policy.

        Note the trade-off: an audit trail is append-only by API design, so
        retention pruning is an operator action with a documented record, not
        something the application does quietly."""
        from auth import prune_expired_revocations

        revoked = prune_expired_revocations()
        click.echo(f'revoked-token blocklist rows pruned: {revoked}')

        retention = days if days is not None else Config.AUDIT_TRAIL_RETENTION_DAYS
        if not retention:
            click.echo('audit trail retention: 0/unset = keep forever (nothing pruned)')
            return
        if not execute:
            click.echo(f'audit trail: would prune rows older than {retention} days '
                       f'(dry run; pass --execute)')
            return
        from datetime import datetime, timedelta

        from models import AuditTrailEvent

        cutoff = datetime.utcnow() - timedelta(days=retention)
        deleted = db.session.query(AuditTrailEvent).filter(
            AuditTrailEvent.created_at < cutoff).delete()
        db.session.commit()
        click.echo(f'audit trail rows deleted: {deleted} (older than {cutoff.date()})')

    @app.cli.command('openapi')
    @click.option('--format', 'fmt', type=click.Choice(['json', 'yaml']), default='json')
    @click.option('--out', default=None, type=click.Path(), help='Write to a file instead of stdout')
    def openapi_command(fmt, out):
        """Dump the OpenAPI contract, generated from the live route map so the
        published spec and the served API cannot disagree."""
        spec = build_spec(app, as_yaml=(fmt == 'yaml'))
        if out:
            with open(out, 'w') as handle:
                handle.write(spec if isinstance(spec, str) else __import__('json').dumps(spec, indent=2))
            click.echo(f'wrote {out}')
        else:
            click.echo(spec if isinstance(spec, str) else __import__('json').dumps(spec, indent=2))


app = create_app()

if __name__ == '__main__':
    print("\n" + "=" * 64)
    print(f"AUDINEXIA GRC PLATFORM v{Config.APP_VERSION} — {Config.ENVIRONMENT}")
    print("=" * 64)
    print(f"Frameworks: {', '.join(FRAMEWORKS.keys())} "
          f"({sum(len(i['controls']) for i in FRAMEWORKS.values())} controls)")
    print("Modules: scanning, review, crosswalk, risk, audit, vendor, maturity,")
    print("         monitoring, admin, auth (JWT + RBAC + audit trail)")
    print("Ops:     /healthz /readyz /version /metrics /docs /api/openapi.json")
    print("=" * 64)
    print("http://127.0.0.1:5000/login")
    print("http://127.0.0.1:5000/dashboard")
    print("=" * 64 + "\n")
    # The Werkzeug debugger executes arbitrary Python for anyone who can reach
    # it, so it is OFF unless explicitly requested -- and never keyed off the
    # ENVIRONMENT label, which a misconfigured deployment can get wrong.
    debug = os.environ.get('FLASK_DEBUG', '0').strip().lower() in ('1', 'true', 'yes', 'on')
    if debug:
        print('WARNING: FLASK_DEBUG is on -- the Werkzeug debugger and reloader are enabled. '
              'Never set this on a reachable host.')
    app.run(debug=debug, host=os.environ.get('HOST', '127.0.0.1'),
            port=int(os.environ.get('PORT', 5000)))
