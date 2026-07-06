import os

from dotenv import load_dotenv

load_dotenv()

from flask import Flask, jsonify, render_template
from flask_cors import CORS

from auth import auth_bp
from config import Config
from extensions import db, jwt, migrate
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

    CORS(app, resources={r"/api/*": {"origins": "*"}}, supports_credentials=False)

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
    app.register_blueprint(admin_bp, url_prefix='/api/admin')

    for folder in [Config.UPLOAD_FOLDER, Config.REPORT_FOLDER]:
        if not os.path.exists(folder):
            os.makedirs(folder)

    # Ensure binary file responses carry CORS headers (fixes download failures)
    @app.after_request
    def add_cors_headers(response):
        response.headers['Access-Control-Allow-Origin'] = '*'
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
        response.headers['Access-Control-Expose-Headers'] = 'Content-Disposition, Content-Type'
        return response

    @app.route('/')
    def index():
        return jsonify({
            "message": "Audinexia GRC Engine v3.0", "status": "running",
            "frameworks": list(FRAMEWORKS.keys()),
            "supported_formats": list(Config.ALLOWED_EXTENSIONS),
            "max_file_size_mb": 50,
        })

    @app.route('/api/frontend-patch', methods=['GET'])
    def frontend_patch():
        """Returns the JS patch to update frontend file accept attribute."""
        return jsonify({
            "patch": "Change fileInput accept='.txt' to accept='.txt,.pdf,.docx' and update upload-zone-sub text to 'Supports .txt, .pdf, .docx · Max 50MB'",
            "file_size_limit": "50MB",
            "supported_formats": ["txt", "pdf", "docx"],
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
    print("AUDINEXIA GRC ENGINE v3.0 - Phase 1 (multi-tenant foundation)")
    print("=" * 60)
    print("Frameworks: DPDPA, ISO 27001, GDPR, PCI DSS, HIPAA, NIST CSF")
    print("Auth: JWT (register/login at /api/auth/*), RBAC, org-scoped data")
    print("=" * 60)
    print("http://127.0.0.1:5000")
    print("http://127.0.0.1:5000/login")
    print("http://127.0.0.1:5000/dashboard")
    print("=" * 60 + "\n")
    app.run(debug=True, port=5000)
