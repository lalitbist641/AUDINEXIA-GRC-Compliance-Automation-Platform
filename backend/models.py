from datetime import datetime

from sqlalchemy import Index
from werkzeug.security import generate_password_hash, check_password_hash

from extensions import db

ROLES = ('org_admin', 'compliance_manager', 'auditor', 'member', 'read_only')

# Every assessment is produced by one of these three paths. 'manual' is a
# human uploading a document from the dashboard/scanner; 'monitoring' is a
# scheduled re-verification run by a PolicyWatch (report §12.7); 'vendor_portal'
# is reserved for a future vendor-self-service upload and is accepted by the
# API today so the enum does not need a migration the first time it is used.
ASSESSMENT_SOURCES = ('manual', 'monitoring', 'vendor_portal')


class Organization(db.Model):
    __tablename__ = 'organizations'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    # Per-tenant review cadences. Stored on the organization rather than only in
    # config because DPDPA/GDPR-style regimes and internal policy standards
    # differ on how often a policy must be re-attested, and the default watch
    # interval is what determines whether something reads as "overdue".
    default_policy_review_interval_days = db.Column(db.Integer, nullable=True)
    default_vendor_review_interval_days = db.Column(db.Integer, nullable=True)

    users = db.relationship('User', backref='organization', lazy=True, cascade='all, delete-orphan')
    assessments = db.relationship('Assessment', backref='organization', lazy=True, cascade='all, delete-orphan')
    # Deleting an organization takes its vendors, watches and the audit-log
    # trail with it — a compliance record must never be orphaned (orphaned
    # rows are unreachable via the org-scoped queries, so they would become
    # undeletable dead data that still counts toward nothing but storage).
    vendors = db.relationship('Vendor', backref='organization', lazy=True, cascade='all, delete-orphan')
    policy_watches = db.relationship(
        'PolicyWatch', backref='organization', lazy=True, cascade='all, delete-orphan'
    )


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
    last_login_at = db.Column(db.DateTime, nullable=True)
    # Bumped by a password change / role change / deactivation. Tokens carry
    # the value they were issued with, and the blocklist loader rejects any
    # token whose embedded value is now stale — that is how "log the user out
    # everywhere" works without tracking every jti issued to them.
    token_version = db.Column(db.Integer, nullable=False, default=0)
    must_change_password = db.Column(db.Boolean, nullable=False, default=False)
    password_changed_at = db.Column(db.DateTime, nullable=True)
    # Single-use password-reset token. Only a SHA-256 hash is stored (never the
    # raw token), so a database read alone can't be used to take over an account.
    password_reset_token_hash = db.Column(db.String(64), nullable=True, index=True)
    password_reset_expires_at = db.Column(db.DateTime, nullable=True)

    assessments = db.relationship('Assessment', backref='created_by', lazy=True)

    def set_password(self, raw_password):
        self.password_hash = generate_password_hash(raw_password)
        self.password_changed_at = datetime.utcnow()

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
            'must_change_password': self.must_change_password,
            'last_login_at': self.last_login_at.isoformat() if self.last_login_at else None,
            'created_at': self.created_at.isoformat(),
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

    # ── Phase 6/7 ──────────────────────────────────────────────────────────
    # Set when this assessment evaluates a third party's document (report
    # §12.6); NULL for the organization's own policies. Separate FK from
    # audit_id because a vendor scan can be part of an audit engagement too.
    vendor_id = db.Column(db.Integer, db.ForeignKey('vendors.id'), nullable=True, index=True)
    source = db.Column(db.String(20), nullable=False, default='manual')
    # sha256 of the extracted policy text. Lets a re-scan of a byte-identical
    # document be recognized as "same input, same result" rather than
    # misreported as a no-change verification pass (see core/monitoring.py).
    content_hash = db.Column(db.String(64), nullable=True, index=True)
    # sha256 of the framework's control definitions as they existed at scan
    # time. If the current hash differs, the score is stale-by-definition:
    # it was measured against requirements that have since changed.
    framework_hash = db.Column(db.String(64), nullable=True)
    # Lineage for monitoring re-scans: points at the assessment this one was
    # compared against. NULL for a first-ever scan of a document.
    parent_assessment_id = db.Column(db.Integer, db.ForeignKey('assessments.id'), nullable=True, index=True)
    framework_definition_drift = db.Column(db.Boolean, nullable=False, default=False)

    control_results = db.relationship(
        'ControlResult', backref='assessment', lazy=True, cascade='all, delete-orphan'
    )
    parent = db.relationship('Assessment', remote_side=[id], foreign_keys=[parent_assessment_id])

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
            'vendor_id': self.vendor_id,
            'vendor_name': self.vendor.name if self.vendor else None,
            'source': self.source,
            'parent_assessment_id': self.parent_assessment_id,
            'framework_definition_drift': self.framework_definition_drift,
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
    # None when the required language was found (remediation not applicable); 'open' at
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

    # Soft delete: the underlying file IS removed from disk (storage can't grow
    # unboundedly with no retention job), but the DB row and its accountability
    # record (who uploaded, who deleted, when) are kept rather than erased.
    deleted_at = db.Column(db.DateTime, nullable=True, index=True)
    deleted_by_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)

    uploaded_by = db.relationship('User', foreign_keys=[uploaded_by_id])
    deleted_by = db.relationship('User', foreign_keys=[deleted_by_id])

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
    # Set once a request_risk_acceptance is approved -- distinct from
    # review_date (a general "check back" reminder) so the meanings don't collide.
    risk_acceptance_expires_at = db.Column(db.Date, nullable=True)

    # Segregation of duties: an owner can't set their own risk to 'accepted'.
    # They submit a request which a DIFFERENT manager must approve or reject.
    # One pending request at a time; pending_action is None when there isn't one.
    pending_action = db.Column(db.String(30), nullable=True)
    pending_reason = db.Column(db.Text, nullable=True)
    pending_expiry_date = db.Column(db.Date, nullable=True)
    pending_requested_by_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    pending_requested_at = db.Column(db.DateTime, nullable=True)

    created_by_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    deleted_at = db.Column(db.DateTime, nullable=True, index=True)
    deleted_by_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)

    owner = db.relationship('User', foreign_keys=[owner_id])
    created_by = db.relationship('User', foreign_keys=[created_by_id])
    deleted_by = db.relationship('User', foreign_keys=[deleted_by_id])
    pending_requested_by = db.relationship('User', foreign_keys=[pending_requested_by_id])
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
            'risk_acceptance_expires_at': (
                self.risk_acceptance_expires_at.isoformat() if self.risk_acceptance_expires_at else None
            ),
            'pending_action': self.pending_action,
            'pending_reason': self.pending_reason,
            'pending_expiry_date': self.pending_expiry_date.isoformat() if self.pending_expiry_date else None,
            'pending_requested_by_id': self.pending_requested_by_id,
            'pending_requested_by_name': (
                self.pending_requested_by.name if self.pending_requested_by else None
            ),
            'pending_requested_at': (
                self.pending_requested_at.isoformat() if self.pending_requested_at else None
            ),
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
AUDIT_STATUSES = ('planned', 'in_progress', 'completed', 'closed', 'withdrawn')
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
    deleted_at = db.Column(db.DateTime, nullable=True, index=True)
    deleted_by_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)

    lead_auditor = db.relationship('User', foreign_keys=[lead_auditor_id])
    created_by = db.relationship('User', foreign_keys=[created_by_id])
    closed_by = db.relationship('User', foreign_keys=[closed_by_id])
    deleted_by = db.relationship('User', foreign_keys=[deleted_by_id])
    findings = db.relationship('Finding', backref='audit', lazy=True, cascade='all, delete-orphan')
    assessments = db.relationship('Assessment', backref='audit', lazy=True)

    def to_dict(self, include_findings=False):
        # self.findings is the raw ORM relationship: soft-deleted findings stay
        # in it (that's the point of a soft delete), so every view of findings
        # here filters deleted_at explicitly rather than relying on a default.
        live_findings = [f for f in self.findings if f.deleted_at is None]
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
                'total': len(live_findings),
                'critical': sum(1 for f in live_findings if f.severity == 'critical'),
                'high': sum(1 for f in live_findings if f.severity == 'high'),
                'medium': sum(1 for f in live_findings if f.severity == 'medium'),
                'low': sum(1 for f in live_findings if f.severity == 'low'),
                'open': sum(1 for f in live_findings if f.status not in ('resolved', 'accepted_risk', 'closed')),
            },
        }
        if include_findings:
            d['findings'] = [f.to_dict() for f in live_findings]
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
    deleted_at = db.Column(db.DateTime, nullable=True, index=True)
    deleted_by_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)

    # Segregation-of-duties workflow -- see Risk's identical fields. A finding's
    # pending_action holds the closing status being proposed.
    pending_action = db.Column(db.String(30), nullable=True)
    pending_reason = db.Column(db.Text, nullable=True)
    pending_requested_by_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    pending_requested_at = db.Column(db.DateTime, nullable=True)

    owner = db.relationship('User', foreign_keys=[owner_id])
    created_by = db.relationship('User', foreign_keys=[created_by_id])
    closed_by = db.relationship('User', foreign_keys=[closed_by_id])
    deleted_by = db.relationship('User', foreign_keys=[deleted_by_id])
    pending_requested_by = db.relationship('User', foreign_keys=[pending_requested_by_id])
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
            'pending_action': self.pending_action,
            'pending_reason': self.pending_reason,
            'pending_requested_by_id': self.pending_requested_by_id,
            'pending_requested_by_name': (
                self.pending_requested_by.name if self.pending_requested_by else None
            ),
            'pending_requested_at': (
                self.pending_requested_at.isoformat() if self.pending_requested_at else None
            ),
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

# ─────────────────────────────────────────────────────────────────────────────
# Phase 6-8 additions (report §12.1 audit trail, §12.4 maturity, §12.6 vendor
# risk, §12.7 continuous monitoring). See migrations/ for the schema history.
# ─────────────────────────────────────────────────────────────────────────────

VENDOR_RISK_TIERS = ('critical', 'high', 'medium', 'low', 'unassessed')
VENDOR_STATUSES = ('onboarding', 'active', 'under_review', 'suspended', 'offboarded')


class Vendor(db.Model):
    """A third party that processes data on the organization's behalf.

    Vendor risk here is deliberately a *document-derived* assessment (report
    §2.2): it reflects what the vendor's own policy documentation covers, not
    an independent audit of the vendor's controls. The rollup fields below are
    recomputed from linked assessments, never hand-entered, so a stale number
    cannot be mistaken for a fresh finding.
    """
    __tablename__ = 'vendors'

    id = db.Column(db.Integer, primary_key=True)
    org_id = db.Column(db.Integer, db.ForeignKey('organizations.id'), nullable=False, index=True)

    name = db.Column(db.String(300), nullable=False)
    service_description = db.Column(db.Text, nullable=True)
    contact_name = db.Column(db.String(200), nullable=True)
    contact_email = db.Column(db.String(255), nullable=True)
    # What the vendor actually does for us drives inherent impact — a payments
    # processor and a marketing analytics tool are not the same exposure.
    data_sensitivity = db.Column(db.String(20), nullable=False, default='internal')
    status = db.Column(db.String(20), nullable=False, default='onboarding', index=True)

    owner_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True, index=True)
    # Denormalized convenience mirror of the earliest VendorContract expiry, so
    # "renewals due this quarter" is one indexed query instead of a join across
    # every contract row. Recomputed whenever a contract is added/removed.
    contract_start = db.Column(db.Date, nullable=True)
    contract_end = db.Column(db.Date, nullable=True)
    notes = db.Column(db.Text, nullable=True)
    review_frequency_days = db.Column(db.Integer, nullable=False, default=365)
    last_reviewed_at = db.Column(db.DateTime, nullable=True)
    # Denormalized rollup, recomputed on every assessment attached to this
    # vendor (see routes/vendor_routes.py::_refresh_vendor_rollup). Stored, not
    # derived per-request, so the vendor register is a single cheap indexed
    # query even with thousands of vendors.
    latest_overall_score = db.Column(db.Float, nullable=True)
    risk_tier = db.Column(db.String(20), nullable=False, default='unassessed', index=True)
    open_gap_count = db.Column(db.Integer, nullable=False, default=0)
    last_assessment_id = db.Column(db.Integer, db.ForeignKey('assessments.id'), nullable=True)

    notes = db.Column(db.Text, nullable=True)
    created_by_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    owner = db.relationship('User', foreign_keys=[owner_id])
    created_by = db.relationship('User', foreign_keys=[created_by_id])
    last_assessment = db.relationship('Assessment', foreign_keys=[last_assessment_id])
    assessments = db.relationship('Assessment', backref='vendor', lazy=True, foreign_keys='Assessment.vendor_id')

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'service_description': self.service_description,
            'contact_name': self.contact_name,
            'contact_email': self.contact_email,
            'data_sensitivity': self.data_sensitivity,
            'status': self.status,
            'notes': self.notes,
            'owner_id': self.owner_id,
            'owner_name': self.owner.name if self.owner else None,
            'contract_start': self.contract_start.isoformat() if self.contract_start else None,
            'contract_end': self.contract_end.isoformat() if self.contract_end else None,
            'review_frequency_days': self.review_frequency_days,
            'last_reviewed_at': self.last_reviewed_at.isoformat() if self.last_reviewed_at else None,
            'latest_overall_score': self.latest_overall_score,
            'risk_tier': self.risk_tier,
            'open_gap_count': self.open_gap_count,
            'last_assessment_id': self.last_assessment_id,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
        }


class VendorContract(db.Model):
    """A vendor's processing arrangements — the contractual side of TPRM.

    Kept separate from Vendor because a vendor typically has several
    concurrent agreements (MSA, DPA, sub-processor addendum) with different
    expiry dates and different frameworks in scope, and because "no data
    processing agreement in place" is itself a reportable GRC finding, not a
    vendor attribute.
    """
    __tablename__ = 'vendor_contracts'

    id = db.Column(db.Integer, primary_key=True)
    org_id = db.Column(db.Integer, db.ForeignKey('organizations.id'), nullable=False, index=True)
    vendor_id = db.Column(db.Integer, db.ForeignKey('vendors.id'), nullable=False, index=True)

    title = db.Column(db.String(300), nullable=False)
    contract_type = db.Column(db.String(40), nullable=False, default='msa')
    frameworks = db.Column(db.JSON, nullable=True)
    signed_on = db.Column(db.Date, nullable=True)
    expires_on = db.Column(db.Date, nullable=True, index=True)
    auto_renews = db.Column(db.Boolean, nullable=False, default=False)
    breach_notification_hours = db.Column(db.Integer, nullable=True)
    audit_rights = db.Column(db.Boolean, nullable=True)
    sub_processors_permitted = db.Column(db.Boolean, nullable=True)
    notes = db.Column(db.Text, nullable=True)

    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    vendor = db.relationship('Vendor', backref=db.backref('contracts', lazy=True, cascade='all, delete-orphan'))

    def to_dict(self):
        return {
            'id': self.id,
            'vendor_id': self.vendor_id,
            'title': self.title,
            'contract_type': self.contract_type,
            'frameworks': self.frameworks or [],
            'signed_on': self.signed_on.isoformat() if self.signed_on else None,
            'expires_on': self.expires_on.isoformat() if self.expires_on else None,
            'auto_renews': self.auto_renews,
            'breach_notification_hours': self.breach_notification_hours,
            'audit_rights': self.audit_rights,
            'sub_processors_permitted': self.sub_processors_permitted,
            'notes': self.notes,
        }


class PolicyWatch(db.Model):
    """Continuous-monitoring subscription for one policy document (report §12.7).

    A watch answers two questions this system can actually answer from stored
    data: (1) has this document been re-verified within its review interval,
    and (2) has the most recent scan moved the score or flipped a control
    status relative to the previous scan (drift). It deliberately does NOT claim
    to monitor live systems — it monitors the evidence already in the platform.
    """
    __tablename__ = 'policy_watches'

    id = db.Column(db.Integer, primary_key=True)
    org_id = db.Column(db.Integer, db.ForeignKey('organizations.id'), nullable=False, index=True)

    name = db.Column(db.String(300), nullable=False)
    # The document to re-scan: matched on filename, and pinned to a framework.
    filename = db.Column(db.String(500), nullable=False)
    framework = db.Column(db.String(50), nullable=False)
    review_interval_days = db.Column(db.Integer, nullable=False, default=180)
    # Drift sensitivity: a re-scan must move the weighted score by at least
    # this many points to be recorded as drift. 0 would flag rounding noise.
    drift_threshold_points = db.Column(db.Float, nullable=False, default=5.0)
    is_active = db.Column(db.Boolean, nullable=False, default=True, index=True)

    # Denormalized freshness, recomputed on run/creation — the whole point of a
    # watch is that the "is it overdue?" query stays cheap.
    last_run_at = db.Column(db.DateTime, nullable=True)
    next_due_at = db.Column(db.DateTime, nullable=True, index=True)
    last_score = db.Column(db.Float, nullable=True)
    previous_score = db.Column(db.Float, nullable=True)
    last_state = db.Column(db.String(20), nullable=True)
    consecutive_overdue_runs = db.Column(db.Integer, nullable=False, default=0)
    # Which assessment the last check compared *from*. The next run scores the
    # newest scan of this document and diffs against this row, so a re-check
    # with no new document version is detectable as "nothing was verified"
    # instead of silently reporting the same score as a passing check.
    last_assessment_id = db.Column(db.Integer, db.ForeignKey('assessments.id'), nullable=True)
    last_content_hash = db.Column(db.String(64), nullable=True)
    last_framework_hash = db.Column(db.String(64), nullable=True)

    created_by_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    created_by = db.relationship('User', foreign_keys=[created_by_id])
    runs = db.relationship(
        'PolicyWatchRun', backref='watch', lazy=True, cascade='all, delete-orphan',
        order_by='PolicyWatchRun.run_at.desc()',
    )

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'filename': self.filename,
            'framework': self.framework,
            'review_interval_days': self.review_interval_days,
            'drift_threshold_points': self.drift_threshold_points,
            'is_active': self.is_active,
            'last_run_at': self.last_run_at.isoformat() if self.last_run_at else None,
            'next_due_at': self.next_due_at.isoformat() if self.next_due_at else None,
            'last_score': self.last_score,
            'previous_score': self.previous_score,
            'last_state': self.last_state,
            'last_assessment_id': self.last_assessment_id,
            'consecutive_overdue_runs': self.consecutive_overdue_runs,
            'created_by_name': self.created_by.name if self.created_by else None,
            'created_at': self.created_at.isoformat(),
        }


# 'no_new_version' and 'framework_updated' are distinct from 'stable' on
# purpose: all three can carry the same score, but only 'framework_updated' and
# a real re-scan constitute verification. Collapsing them would let an
# unreviewed policy report as checked.
WATCH_STATES = ('initial', 'stable', 'drift_up', 'drift_down', 'control_flip',
                'error', 'no_document', 'no_new_version', 'framework_updated')


class PolicyWatchRun(db.Model):
    """One execution of a PolicyWatch — the immutable history behind
    PolicyWatch's denormalized freshness fields."""
    __tablename__ = 'policy_watch_runs'

    id = db.Column(db.Integer, primary_key=True)
    org_id = db.Column(db.Integer, db.ForeignKey('organizations.id'), nullable=False, index=True)
    watch_id = db.Column(db.Integer, db.ForeignKey('policy_watches.id'), nullable=False, index=True)

    run_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    state = db.Column(db.String(20), nullable=False, default='initial')
    # 'scheduled' for runs triggered by the monitoring worker, 'manual' when a
    # user clicks Run Now — needed to tell a real drift event from a
    # human-triggered re-check in the audit history.
    trigger = db.Column(db.String(20), nullable=False, default='manual')
    baseline_assessment_id = db.Column(db.Integer, db.ForeignKey('assessments.id'), nullable=True)
    current_assessment_id = db.Column(db.Integer, db.ForeignKey('assessments.id'), nullable=True)
    previous_score = db.Column(db.Float, nullable=True)
    current_score = db.Column(db.Float, nullable=True)
    score_delta = db.Column(db.Float, nullable=True)
    controls_flipped = db.Column(db.JSON, nullable=True)
    message = db.Column(db.Text, nullable=True)
    duration_ms = db.Column(db.Integer, nullable=True)

    baseline_assessment = db.relationship('Assessment', foreign_keys=[baseline_assessment_id])
    current_assessment = db.relationship('Assessment', foreign_keys=[current_assessment_id])

    def to_dict(self):
        return {
            'id': self.id,
            'watch_id': self.watch_id,
            'run_at': self.run_at.isoformat(),
            'state': self.state,
            'trigger': self.trigger,
            'baseline_assessment_id': self.baseline_assessment_id,
            'current_assessment_id': self.current_assessment_id,
            'previous_score': self.previous_score,
            'current_score': self.current_score,
            'score_delta': self.score_delta,
            'controls_flipped': self.controls_flipped or [],
            'message': self.message,
            'duration_ms': self.duration_ms,
        }


class MaturityAssessment(db.Model):
    """Staged maturity self-assessment per framework (report §12.4).

    Maturity is scored on a CMMI-style 1-5 ladder, but each level is anchored
    to *observable evidence in this database* (per-control scores, reviewer
    confirmation coverage, overdue remediations, audit findings) rather than a
    free-text questionnaire answer — see core/maturity.py. The human-entered
    fields (self_score/notes/approval) record the organization's claimed level
    and who signed off on the claim, which is what makes this an auditable
    assertion rather than a number the tool invented.
    """
    __tablename__ = 'maturity_assessments'
    __table_args__ = (
        db.UniqueConstraint('org_id', 'framework', name='uq_maturity_org_framework'),
    )

    id = db.Column(db.Integer, primary_key=True)
    org_id = db.Column(db.Integer, db.ForeignKey('organizations.id'), nullable=False, index=True)
    framework = db.Column(db.String(50), nullable=False)

    current_level = db.Column(db.Integer, nullable=False, default=1)
    target_level = db.Column(db.Integer, nullable=False, default=3)
    # Evidence-derived level, computed by core/maturity.py and stored so the
    # trend chart has a history and so the claimed-vs-derived gap is visible.
    derived_level = db.Column(db.Integer, nullable=False, default=1)
    derived_score = db.Column(db.Float, nullable=False, default=0.0)
    level_rationale = db.Column(db.JSON, nullable=True)
    # Deliberate ceiling when evidence contradicts the claim (e.g. reviewer
    # confirmation coverage of 0% caps the level at 2 — see maturity.py).
    capped_by_evidence = db.Column(db.Boolean, nullable=False, default=False)

    self_assessment_notes = db.Column(db.Text, nullable=True)
    approved_by_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    approved_at = db.Column(db.DateTime, nullable=True)
    review_due_at = db.Column(db.DateTime, nullable=True)

    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    approved_by = db.relationship('User', foreign_keys=[approved_by_id])
    snapshots = db.relationship(
        'MaturitySnapshot', backref='maturity', lazy=True, cascade='all, delete-orphan',
        order_by='MaturitySnapshot.taken_at.desc()',
    )

    def to_dict(self, include_snapshots=False):
        d = {
            'id': self.id,
            'framework': self.framework,
            'framework_name': FRAMEWORK_NAMES.get(self.framework, self.framework),
            'current_level': self.current_level,
            'current_level_label': MATURITY_LEVELS.get(self.current_level, str(self.current_level)),
            'target_level': self.target_level,
            'target_level_label': MATURITY_LEVELS.get(self.target_level, str(self.target_level)),
            'derived_level': self.derived_level,
            'derived_score': self.derived_score,
            'level_rationale': self.level_rationale or {},
            'capped_by_evidence': self.capped_by_evidence,
            'self_assessment_notes': self.self_assessment_notes,
            'approved_by_id': self.approved_by_id,
            'approved_by_name': self.approved_by.name if self.approved_by else None,
            'approved_at': self.approved_at.isoformat() if self.approved_at else None,
            'review_due_at': self.review_due_at.isoformat() if self.review_due_at else None,
            'updated_at': self.updated_at.isoformat(),
        }
        if include_snapshots:
            d['snapshots'] = [s.to_dict() for s in self.snapshots]
        return d


MATURITY_LEVELS = {
    1: 'Initial',
    2: 'Managed',
    3: 'Defined',
    4: 'Quantitatively Managed',
    5: 'Optimizing',
}

# Import-safe reverse lookup for framework display names. Defined here rather
# than importing scanning.py into models.py: models.py must not depend on the
# engine layer (that would create an import cycle via routes/ -> models).
FRAMEWORK_NAMES = {
    'dpdpa': 'DPDPA 2023 (India)',
    'iso27001': 'ISO 27001:2022',
    'gdpr': 'GDPR (EU)',
    'pcidss': 'PCI DSS v4.0',
    'hipaa': 'HIPAA',
    'nistcsf': 'NIST CSF 2.0',
    'certin': 'CERT-In Directions 2022 (India)',
}


class MaturitySnapshot(db.Model):
    """Point-in-time record of a derived maturity level, for trend reporting.

    Append-only by convention (no update/delete endpoints exist for it) — a
    maturity trend is only meaningful if past data points cannot be rewritten.
    """
    __tablename__ = 'maturity_snapshots'

    id = db.Column(db.Integer, primary_key=True)
    org_id = db.Column(db.Integer, db.ForeignKey('organizations.id'), nullable=False, index=True)
    maturity_id = db.Column(db.Integer, db.ForeignKey('maturity_assessments.id'), nullable=False, index=True)

    taken_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    level = db.Column(db.Integer, nullable=False)
    score = db.Column(db.Float, nullable=False)
    metrics = db.Column(db.JSON, nullable=True)
    trigger = db.Column(db.String(20), nullable=False, default='recalculate')

    def to_dict(self):
        return {
            'id': self.id,
            'taken_at': self.taken_at.isoformat(),
            'level': self.level,
            'level_label': MATURITY_LEVELS.get(self.level, str(self.level)),
            'score': self.score,
            'metrics': self.metrics or {},
            'trigger': self.trigger,
        }


class AuditTrailEvent(db.Model):
    """Append-only trail of state-changing API calls (report §12.1).

    Written by a small service layer (core/audit_trail.py) called explicitly
    from route handlers, not by SQLAlchemy event hooks: hooking `after_flush`
    would capture ORM-level mutations but not the actor/intent (which endpoint,
    which role, what the caller asked for), and an audit record without the
    actor is not much of an audit record.

    No UPDATE/DELETE API path exists for this table, and org-scoping is applied
    on read. The trade-off is documented in SECURITY.md: the trail grows
    with usage and needs a retention policy at real-world scale.
    """
    __tablename__ = 'audit_trail_events'

    id = db.Column(db.Integer, primary_key=True)
    org_id = db.Column(db.Integer, db.ForeignKey('organizations.id'), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True, index=True)
    # Nullable user: a scheduled monitoring run has no human actor. Recording
    # it with user_id NULL and actor='system' is more honest than attributing a
    # background job to whoever created the watch.
    action = db.Column(db.String(60), nullable=False, index=True)
    entity_type = db.Column(db.String(40), nullable=False, index=True)
    entity_id = db.Column(db.Integer, nullable=True, index=True)
    summary = db.Column(db.String(500), nullable=True)
    detail = db.Column(db.JSON, nullable=True)
    ip_address = db.Column(db.String(60), nullable=True)
    request_id = db.Column(db.String(64), nullable=True, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    # Tamper evidence: each row's hash covers its own content plus the previous
    # row's hash for the same org (core/audit_trail.py). Altering or deleting a
    # past row breaks the chain from that point on in a way verify_chain()
    # detects. NULL on rows written before the chain existed.
    prev_hash = db.Column(db.String(64), nullable=True)
    hash = db.Column(db.String(64), nullable=True)

    user = db.relationship('User')

    __table_args__ = (
        Index('ix_audit_trail_entity', 'entity_type', 'entity_id', 'created_at'),
    )

    def to_dict(self):
        return {
            'id': self.id,
            'action': self.action,
            'entity_type': self.entity_type,
            'entity_id': self.entity_id,
            'summary': self.summary,
            'detail': self.detail or {},
            'actor': self.user.name if self.user else 'system',
            'actor_role': self.user.role if self.user else 'system',
            'ip_address': self.ip_address,
            'request_id': self.request_id,
            'created_at': self.created_at.isoformat(),
        }


class RevokedToken(db.Model):
    """Persistent JWT blocklist (upgrades the Phase 1 in-memory set).

    The pre-Phase-8 blocklist was a process-local Python set, which meant a
    token revoked by a logout on worker A was still valid on worker B, and every
    restart un-revoked everything. Storing the jti with its own expiry makes
    revocation correct under multiple gunicorn workers and survives restarts.
    Rows are pruned opportunistically (see auth.py) rather than by a scheduler.
    """
    __tablename__ = 'revoked_tokens'

    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(64), nullable=False, unique=True, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True, index=True)
    org_id = db.Column(db.Integer, db.ForeignKey('organizations.id'), nullable=True, index=True)
    reason = db.Column(db.String(40), nullable=False, default='logout')
    expires_at = db.Column(db.DateTime, nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    def to_dict(self):
        return {
            'id': self.id,
            'jti': self.jti,
            'user_id': self.user_id,
            'reason': self.reason,
            'expires_at': self.expires_at.isoformat(),
            'created_at': self.created_at.isoformat(),
        }


class ApiRateLimitBucket(db.Model):
    """Optional durable rate-limit store for multi-worker deployments.

    Default behavior is in-process (config.RATE_LIMIT_STORAGE_URI unset): the
    fast path stays in memory with no per-request DB write. This table is only
    written when `RATE_LIMIT_STORE=db` is configured, which is the single
    dependency-free way to share counters across gunicorn workers before Redis
    is available.
    """
    __tablename__ = 'api_rate_limit_buckets'

    id = db.Column(db.Integer, primary_key=True)
    bucket_key = db.Column(db.String(200), nullable=False, unique=True, index=True)
    count = db.Column(db.Integer, nullable=False, default=0)
    window_started_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    window_expires_at = db.Column(db.DateTime, nullable=False, index=True)

    def to_dict(self):
        return {
            'bucket_key': self.bucket_key,
            'count': self.count,
            'window_started_at': self.window_started_at.isoformat(),
            'window_expires_at': self.window_expires_at.isoformat(),
        }


class FindingVendorLink(db.Model):
    """Many-to-many between an audit finding and the vendor(s) it concerns.

    A finding about "no signed DPA with the analytics provider" belongs to the
    audit record AND the vendor register, so the vendor register's open-finding
    count comes from a link table rather than a nullable vendor_id on Finding —
    a finding about two vendors should count against both, and a vendor can be
    removed from the register without deleting audit history.
    """
    __tablename__ = 'finding_vendor_links'

    id = db.Column(db.Integer, primary_key=True)
    org_id = db.Column(db.Integer, db.ForeignKey('organizations.id'), nullable=False, index=True)
    finding_id = db.Column(db.Integer, db.ForeignKey('findings.id', ondelete='CASCADE'), nullable=False, index=True)
    vendor_id = db.Column(db.Integer, db.ForeignKey('vendors.id'), nullable=False, index=True)
    linked_by_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    linked_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    vendor = db.relationship('Vendor')
    finding = db.relationship('Finding')

    __table_args__ = (db.UniqueConstraint('finding_id', 'vendor_id', name='uq_finding_vendor'),)

    def to_dict(self):
        return {
            'id': self.id,
            'finding_id': self.finding_id,
            'vendor_id': self.vendor_id,
            'vendor_name': self.vendor.name if self.vendor else None,
            'finding_description': (self.finding.description[:160] if self.finding else None),
            'finding_severity': self.finding.severity if self.finding else None,
            'finding_status': self.finding.status if self.finding else None,
            'audit_id': self.finding.audit_id if self.finding else None,
            'linked_at': self.linked_at.isoformat(),
        }
