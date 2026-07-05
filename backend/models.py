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


REVIEWER_STATUSES = ('unreviewed', 'confirmed', 'overridden')
REMEDIATION_STATUSES = ('open', 'in_progress', 'closed')


class ControlResult(db.Model):
    __tablename__ = 'control_results'

    id = db.Column(db.Integer, primary_key=True)
    # Denormalized (also reachable via assessment.org_id) so every org-scoped
    # query on this table can filter by org_id directly, matching the pattern
    # used everywhere else in this codebase rather than requiring a join --
    # see rbac.py's org-scoping rule.
    org_id = db.Column(db.Integer, db.ForeignKey('organizations.id'), nullable=False, index=True)
    assessment_id = db.Column(db.Integer, db.ForeignKey('assessments.id'), nullable=False, index=True)
    control_id = db.Column(db.String(50), nullable=False)
    control_name = db.Column(db.String(300), nullable=False)
    score = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(30), nullable=False)
    evidence_text = db.Column(db.Text, nullable=True)
    missing_phrases = db.Column(db.JSON, nullable=True)
    found_phrases = db.Column(db.JSON, nullable=True)

    reviewer_status = db.Column(db.String(20), nullable=False, default='unreviewed')
    reviewer_note = db.Column(db.Text, nullable=True)
    reviewed_by_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    reviewed_at = db.Column(db.DateTime, nullable=True)
    assigned_to_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True, index=True)
    due_date = db.Column(db.Date, nullable=True)
    # None for a Compliant control (remediation not applicable); 'open' at
    # scan time otherwise; 'in_progress'/'closed' set via reviewer action.
    remediation_status = db.Column(db.String(20), nullable=True, index=True)

    reviewed_by = db.relationship('User', foreign_keys=[reviewed_by_id])
    assigned_to = db.relationship('User', foreign_keys=[assigned_to_id])
    evidence_files = db.relationship(
        'EvidenceFile', backref='control_result', lazy=True, cascade='all, delete-orphan'
    )

    def to_review_dict(self):
        return {
            'control_result_id': self.id,
            'control_id': self.control_id,
            'control_name': self.control_name,
            'status': self.status,
            'reviewer_status': self.reviewer_status,
            'reviewer_note': self.reviewer_note,
            'reviewed_by_id': self.reviewed_by_id,
            'reviewed_by_name': self.reviewed_by.name if self.reviewed_by else None,
            'reviewed_at': self.reviewed_at.isoformat() if self.reviewed_at else None,
            'assigned_to_id': self.assigned_to_id,
            'assigned_to_name': self.assigned_to.name if self.assigned_to else None,
            'due_date': self.due_date.isoformat() if self.due_date else None,
            'remediation_status': self.remediation_status,
        }


class EvidenceFile(db.Model):
    __tablename__ = 'evidence_files'

    id = db.Column(db.Integer, primary_key=True)
    org_id = db.Column(db.Integer, db.ForeignKey('organizations.id'), nullable=False, index=True)
    control_result_id = db.Column(db.Integer, db.ForeignKey('control_results.id'), nullable=False, index=True)
    uploaded_by_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    original_filename = db.Column(db.String(500), nullable=False)
    stored_filename = db.Column(db.String(600), nullable=False)
    file_size = db.Column(db.Integer, nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)

    uploaded_by = db.relationship('User', foreign_keys=[uploaded_by_id])

    def to_dict(self):
        return {
            'id': self.id,
            'control_result_id': self.control_result_id,
            'original_filename': self.original_filename,
            'uploaded_by_name': self.uploaded_by.name if self.uploaded_by else None,
            'file_size': self.file_size,
            'uploaded_at': self.uploaded_at.isoformat(),
        }
