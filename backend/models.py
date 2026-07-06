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
    # Nullable: a scan isn't necessarily conducted as part of a formal audit
    # engagement. Naturally many-to-one (one audit has many scans; a given
    # scan belongs to at most one audit), so a plain FK here rather than a
    # join table -- contrast with Risk/Finding <-> ControlResult, which are
    # genuine many-to-many and use a real link table instead.
    audit_id = db.Column(db.Integer, db.ForeignKey('audits.id'), nullable=True, index=True)
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


LIKELIHOOD_LEVELS = {1: 'Rare', 2: 'Unlikely', 3: 'Possible', 4: 'Likely', 5: 'Almost Certain'}
IMPACT_LEVELS = {1: 'Negligible', 2: 'Minor', 3: 'Moderate', 4: 'Major', 5: 'Severe'}
RISK_STATUSES = ('open', 'mitigating', 'accepted', 'closed')


def bucket_risk_score(score):
    """Standard 5x5 risk matrix bucketing (1-25). This is a distinct
    scale/vocabulary from ControlResult's scan-time risk_level (Low/Medium/
    High over a 0-100 score, 3 bands) -- Risk uses 4 bands since a 5x5
    matrix conventionally distinguishes a Critical band. Do not assume
    these two risk_level fields are directly comparable."""
    if score >= 16:
        return 'Critical'
    if score >= 10:
        return 'High'
    if score >= 5:
        return 'Medium'
    return 'Low'


class Risk(db.Model):
    __tablename__ = 'risks'

    id = db.Column(db.Integer, primary_key=True)
    org_id = db.Column(db.Integer, db.ForeignKey('organizations.id'), nullable=False, index=True)

    description = db.Column(db.Text, nullable=False)
    # Likelihood/impact are business judgment calls this system has no basis
    # to infer from scan data -- always explicit human input, never defaulted
    # (see routes/risk_routes.py's create validation). risk_score/risk_level
    # ARE safe to auto-compute: deterministic arithmetic on human-supplied
    # numbers, not fabrication.
    likelihood = db.Column(db.Integer, nullable=False)
    impact = db.Column(db.Integer, nullable=False)
    risk_score = db.Column(db.Integer, nullable=False)
    risk_level = db.Column(db.String(20), nullable=False, index=True)

    owner_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True, index=True)
    status = db.Column(db.String(20), nullable=False, default='open', index=True)
    mitigation = db.Column(db.Text, nullable=True)
    residual_likelihood = db.Column(db.Integer, nullable=True)
    residual_impact = db.Column(db.Integer, nullable=True)
    residual_risk_score = db.Column(db.Integer, nullable=True)
    residual_risk_level = db.Column(db.String(20), nullable=True)
    review_date = db.Column(db.Date, nullable=True)

    created_by_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    owner = db.relationship('User', foreign_keys=[owner_id])
    created_by = db.relationship('User', foreign_keys=[created_by_id])
    control_links = db.relationship(
        'RiskControlLink', backref='risk', lazy=True, cascade='all, delete-orphan'
    )

    def to_dict(self):
        return {
            'id': self.id,
            'description': self.description,
            'likelihood': self.likelihood,
            'impact': self.impact,
            'risk_score': self.risk_score,
            'risk_level': self.risk_level,
            'owner_id': self.owner_id,
            'owner_name': self.owner.name if self.owner else None,
            'status': self.status,
            'mitigation': self.mitigation,
            'residual_likelihood': self.residual_likelihood,
            'residual_impact': self.residual_impact,
            'residual_risk_score': self.residual_risk_score,
            'residual_risk_level': self.residual_risk_level,
            'review_date': self.review_date.isoformat() if self.review_date else None,
            'created_by_name': self.created_by.name if self.created_by else None,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
            'linked_controls': [
                {
                    'control_result_id': link.control_result_id,
                    'control_id': link.control_result.control_id,
                    'control_name': link.control_result.control_name,
                    'framework': link.control_result.assessment.framework,
                    'assessment_id': link.control_result.assessment_id,
                }
                for link in self.control_links
            ],
        }


class RiskControlLink(db.Model):
    __tablename__ = 'risk_control_links'

    id = db.Column(db.Integer, primary_key=True)
    org_id = db.Column(db.Integer, db.ForeignKey('organizations.id'), nullable=False, index=True)
    risk_id = db.Column(db.Integer, db.ForeignKey('risks.id'), nullable=False, index=True)
    control_result_id = db.Column(
        db.Integer, db.ForeignKey('control_results.id', ondelete='CASCADE'), nullable=False, index=True
    )
    linked_by_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    linked_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    control_result = db.relationship('ControlResult')

    __table_args__ = (db.UniqueConstraint('risk_id', 'control_result_id', name='uq_risk_control'),)


FINDING_SEVERITIES = ('critical', 'high', 'medium', 'low')
AUDIT_STATUSES = ('planned', 'in_progress', 'completed', 'closed')
FINDING_STATUSES = ('open', 'in_remediation', 'resolved', 'accepted_risk', 'closed')


class Audit(db.Model):
    __tablename__ = 'audits'

    id = db.Column(db.Integer, primary_key=True)
    org_id = db.Column(db.Integer, db.ForeignKey('organizations.id'), nullable=False, index=True)

    title = db.Column(db.String(300), nullable=False)
    scope_description = db.Column(db.Text, nullable=True)
    lead_auditor_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True, index=True)
    status = db.Column(db.String(20), nullable=False, default='planned', index=True)
    start_date = db.Column(db.Date, nullable=True)
    end_date = db.Column(db.Date, nullable=True)

    created_by_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    closed_at = db.Column(db.DateTime, nullable=True)
    closed_by_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)

    lead_auditor = db.relationship('User', foreign_keys=[lead_auditor_id])
    created_by = db.relationship('User', foreign_keys=[created_by_id])
    closed_by = db.relationship('User', foreign_keys=[closed_by_id])
    findings = db.relationship('Finding', backref='audit', lazy=True, cascade='all, delete-orphan')
    assessments = db.relationship('Assessment', backref='audit', lazy=True)

    def to_dict(self, include_findings=False):
        d = {
            'id': self.id,
            'title': self.title,
            'scope_description': self.scope_description,
            'lead_auditor_id': self.lead_auditor_id,
            'lead_auditor_name': self.lead_auditor.name if self.lead_auditor else None,
            'status': self.status,
            'start_date': self.start_date.isoformat() if self.start_date else None,
            'end_date': self.end_date.isoformat() if self.end_date else None,
            'created_by_name': self.created_by.name if self.created_by else None,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
            'closed_at': self.closed_at.isoformat() if self.closed_at else None,
            'closed_by_name': self.closed_by.name if self.closed_by else None,
            'finding_counts': {
                'total': len(self.findings),
                'critical': sum(1 for f in self.findings if f.severity == 'critical'),
                'high': sum(1 for f in self.findings if f.severity == 'high'),
                'medium': sum(1 for f in self.findings if f.severity == 'medium'),
                'low': sum(1 for f in self.findings if f.severity == 'low'),
                'open': sum(1 for f in self.findings if f.status not in ('resolved', 'accepted_risk', 'closed')),
            },
        }
        if include_findings:
            d['findings'] = [f.to_dict() for f in self.findings]
            d['linked_assessments'] = [
                {
                    'id': a.id, 'framework': a.framework, 'filename': a.filename,
                    'overall_score': a.overall_score,
                }
                for a in self.assessments
            ]
        return d


class Finding(db.Model):
    __tablename__ = 'findings'

    id = db.Column(db.Integer, primary_key=True)
    org_id = db.Column(db.Integer, db.ForeignKey('organizations.id'), nullable=False, index=True)
    audit_id = db.Column(db.Integer, db.ForeignKey('audits.id'), nullable=False, index=True)

    description = db.Column(db.Text, nullable=False)
    # Required, never defaulted -- severity is an auditor's categorical
    # judgment call, not something this system infers (see routes/
    # audit_routes.py's create validation, mirroring Risk's likelihood/impact
    # rule).
    severity = db.Column(db.String(20), nullable=False, index=True)
    recommendation = db.Column(db.Text, nullable=True)
    management_response = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(20), nullable=False, default='open', index=True)

    owner_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True, index=True)
    due_date = db.Column(db.Date, nullable=True)

    created_by_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    closed_at = db.Column(db.DateTime, nullable=True)
    closed_by_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)

    owner = db.relationship('User', foreign_keys=[owner_id])
    created_by = db.relationship('User', foreign_keys=[created_by_id])
    closed_by = db.relationship('User', foreign_keys=[closed_by_id])
    control_links = db.relationship(
        'FindingControlLink', backref='finding', lazy=True, cascade='all, delete-orphan'
    )

    def to_dict(self):
        return {
            'id': self.id,
            'audit_id': self.audit_id,
            'description': self.description,
            'severity': self.severity,
            'recommendation': self.recommendation,
            'management_response': self.management_response,
            'status': self.status,
            'owner_id': self.owner_id,
            'owner_name': self.owner.name if self.owner else None,
            'due_date': self.due_date.isoformat() if self.due_date else None,
            'created_by_name': self.created_by.name if self.created_by else None,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
            'closed_at': self.closed_at.isoformat() if self.closed_at else None,
            'closed_by_name': self.closed_by.name if self.closed_by else None,
            'linked_controls': [
                {
                    'control_result_id': link.control_result_id,
                    'control_id': link.control_result.control_id,
                    'control_name': link.control_result.control_name,
                    'framework': link.control_result.assessment.framework,
                    'assessment_id': link.control_result.assessment_id,
                }
                for link in self.control_links
            ],
        }


class FindingControlLink(db.Model):
    __tablename__ = 'finding_control_links'

    id = db.Column(db.Integer, primary_key=True)
    org_id = db.Column(db.Integer, db.ForeignKey('organizations.id'), nullable=False, index=True)
    finding_id = db.Column(db.Integer, db.ForeignKey('findings.id'), nullable=False, index=True)
    control_result_id = db.Column(
        db.Integer, db.ForeignKey('control_results.id', ondelete='CASCADE'), nullable=False, index=True
    )
    linked_by_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    linked_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    control_result = db.relationship('ControlResult')

    __table_args__ = (db.UniqueConstraint('finding_id', 'control_result_id', name='uq_finding_control'),)
