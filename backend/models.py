from datetime import datetime

from werkzeug.security import generate_password_hash, check_password_hash

from extensions import db

ROLES = ('org_admin', 'compliance_manager', 'auditor', 'member', 'read_only')


class Organization(db.Model):
    __tablename__ = 'organizations'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    users = db.relationship('User', backref='organization', lazy=True, cascade='all, delete-orphan')
    assessments = db.relationship('Assessment', backref='organization', lazy=True, cascade='all, delete-orphan')


class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    org_id = db.Column(db.Integer, db.ForeignKey('organizations.id'), nullable=False, index=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    name = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(30), nullable=False, default='member')
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    assessments = db.relationship('Assessment', backref='created_by', lazy=True)

    def set_password(self, raw_password):
        self.password_hash = generate_password_hash(raw_password)

    def check_password(self, raw_password):
        return check_password_hash(self.password_hash, raw_password)

    def to_dict(self):
        return {
            'id': self.id,
            'org_id': self.org_id,
            'email': self.email,
            'name': self.name,
            'role': self.role,
            'is_active': self.is_active,
        }


class Assessment(db.Model):
    __tablename__ = 'assessments'

    id = db.Column(db.Integer, primary_key=True)
    org_id = db.Column(db.Integer, db.ForeignKey('organizations.id'), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    framework = db.Column(db.String(50), nullable=False)
    filename = db.Column(db.String(500), nullable=False)
    stored_filename = db.Column(db.String(600), nullable=True)
    overall_score = db.Column(db.Float, nullable=False)
    compliant_count = db.Column(db.Integer, nullable=False, default=0)
    partial_count = db.Column(db.Integer, nullable=False, default=0)
    non_compliant_count = db.Column(db.Integer, nullable=False, default=0)
    report_id = db.Column(db.String(50), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)

    control_results = db.relationship(
        'ControlResult', backref='assessment', lazy=True, cascade='all, delete-orphan'
    )

    def to_summary_dict(self):
        return {
            'id': self.id,
            'framework': self.framework,
            'filename': self.filename,
            'overall_score': self.overall_score,
            'compliant_count': self.compliant_count,
            'partial_count': self.partial_count,
            'non_compliant_count': self.non_compliant_count,
            'report_id': self.report_id,
            'created_at': self.created_at.isoformat(),
            'created_by': self.created_by.name if self.created_by else None,
        }


class ControlResult(db.Model):
    __tablename__ = 'control_results'

    id = db.Column(db.Integer, primary_key=True)
    assessment_id = db.Column(db.Integer, db.ForeignKey('assessments.id'), nullable=False, index=True)
    control_id = db.Column(db.String(50), nullable=False)
    control_name = db.Column(db.String(300), nullable=False)
    score = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(30), nullable=False)
    evidence_text = db.Column(db.Text, nullable=True)
    missing_phrases = db.Column(db.JSON, nullable=True)
    found_phrases = db.Column(db.JSON, nullable=True)
