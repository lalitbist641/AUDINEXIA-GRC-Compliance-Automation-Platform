import os

from dotenv import load_dotenv

load_dotenv()

from flask import Flask, jsonify, render_template

from auth import auth_bp
from config import Config
from extensions import db, jwt, limiter, migrate
from routes.admin_routes import admin_bp
from routes.assessment_routes import assessment_bp
from routes.audit_routes import audit_bp
from routes.crosswalk_routes import crosswalk_bp
from routes.review_routes import review_bp
from routes.risk_routes import risk_bp
from routes.scan_routes import scan_bp
from scanning import FRAMEWORKS


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # instance/ holds the SQLite dev DB (relative sqlite:/// URIs resolve
    # here). Flask does not create this directory automatically -- without
    # it, `flask db upgrade` fails with "unable to open database file" on a
    # fresh clone.
    os.makedirs(app.instance_path, exist_ok=True)

    db.init_app(app)
    migrate.init_app(app, db)
    jwt.init_app(app)
    limiter.init_app(app)

    app.register_blueprint(auth_bp, url_prefix='/api/auth')
    app.register_blueprint(scan_bp, url_prefix='/api')
    app.register_blueprint(assessment_bp, url_prefix='/api')
    app.register_blueprint(review_bp, url_prefix='/api')
    app.register_blueprint(crosswalk_bp, url_prefix='/api')
    app.register_blueprint(risk_bp, url_prefix='/api')
    app.register_blueprint(audit_bp, url_prefix='/api')
    app.register_blueprint(admin_bp, url_prefix='/api/admin')

    for folder in [Config.UPLOAD_FOLDER, Config.REPORT_FOLDER]:
        if not os.path.exists(folder):
            os.makedirs(folder)

    # script-src still allows 'unsafe-inline' -- an honest interim state, NOT a
    # strict CSP: dashboard.html has ~50 inline onclick="..." handlers that a
    # strict policy would break, and migrating them to addEventListener is a
    # separate, regression-prone refactor (tracked in SECURITY.md). Everything
    # else here is locked down: no objects/plugins, no framing, no off-origin
    # form posts, and only Google Fonts as an external origin. The real XSS
    # defenses are the output escaping in dashboard.html/reports.py and the
    # httpOnly auth cookies; this header is defense in depth.
    csp = "; ".join([
        "default-src 'self'",
        "script-src 'self' 'unsafe-inline'",
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
        "font-src 'self' https://fonts.gstatic.com",
        "img-src 'self' data:",
        "connect-src 'self'",
        "object-src 'none'",
        "frame-ancestors 'none'",
        "base-uri 'self'",
        "form-action 'self'",
    ])

    @app.after_request
    def set_security_headers(response):
        response.headers.setdefault('Content-Security-Policy', csp)
        response.headers.setdefault('X-Content-Type-Options', 'nosniff')
        response.headers.setdefault('Referrer-Policy', 'same-origin')
        return response

    @app.route('/')
    def index():
        return jsonify({
            "message": "Audinexia GRC Engine v3.0", "status": "running",
            "frameworks": list(FRAMEWORKS.keys()),
            "supported_formats": list(Config.ALLOWED_EXTENSIONS),
            "max_file_size_mb": 50,
        })

    @app.route('/login')
    def login_page():
        return render_template('login.html')

    @app.route('/dashboard')
    def dashboard():
        return render_template('dashboard.html')

    return app


app = create_app()

if __name__ == '__main__':
    print("\n" + "=" * 60)
    print("AUDINEXIA GRC ENGINE v3.0")
    print("=" * 60)
    print("Frameworks: DPDPA, ISO 27001, GDPR, PCI DSS, HIPAA, NIST CSF")
    print("Auth: JWT (register/login at /api/auth/*), RBAC, org-scoped data")
    print("=" * 60)
    print("http://127.0.0.1:5000")
    print("http://127.0.0.1:5000/login")
    print("http://127.0.0.1:5000/dashboard")
    if Config.FLASK_DEBUG:
        print("WARNING: FLASK_DEBUG=1 -- the Werkzeug debugger and reloader are ON.")
        print("Never set this in a real deployment: the debugger's console can execute")
        print("arbitrary Python for anyone who can reach it.")
    print("=" * 60 + "\n")
    app.run(debug=Config.FLASK_DEBUG, port=5000)
