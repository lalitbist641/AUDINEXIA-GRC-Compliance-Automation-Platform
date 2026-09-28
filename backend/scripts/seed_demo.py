"""Demo/development data seeding.

Reachable via `flask seed` (refuses to run when ENVIRONMENT=production). The
point of seeding is that the workflows the platform actually sells — review,
remediation, risk, audit, vendor, monitoring, maturity — need related records to
be inspectable at all; an empty database shows you a scoring engine and nothing
else.

Everything created here goes through the same code paths as an API call (the
shared scan pipeline for scores, the same rollup helpers for vendors), not a
bespoke fixture writer, so seeded numbers are computed the way real ones are.
"""

import os
from datetime import datetime, timedelta

from core.vendor_risk import tier_from_coverage
from extensions import db
from models import (
    Assessment,
    Audit,
    ControlResult,
    Finding,
    MaturityAssessment,
    Organization,
    PolicyWatch,
    PolicyWatchRun,
    Risk,
    User,
    Vendor,
    VendorContract,
    bucket_risk_score,
)
from scanning import (
    FRAMEWORKS,
    analyze_control,
    calculate_weighted_score,
    extract_text,
    framework_content_hash,
    text_hash,
)

PASSWORD_NOTE = 'Seeded password — change it before any shared use.'

ROLE_ACCOUNTS = [
    ('org_admin', 'Priya Raghavan', 'priya@audinexia-demo.test'),
    ('compliance_manager', 'Marco Silva', 'marco@audinexia-demo.test'),
    ('auditor', 'Dana Whitfield', 'dana@audinexia-demo.test'),
    ('member', 'Samir Khan', 'samir@audinexia-demo.test'),
    ('read_only', 'Lee Tan', 'lee@audinexia-demo.test'),
]

SAMPLE_POLICIES = {
    'dpdpa': 'policies/compliant/Fully_Compliant_Policy.txt',
    'iso27001': 'policies/compliant/ISO27001_Compliant_Policy.txt',
    'nistcsf': 'policies/partial/Partially_Compliant_Policy.txt',
    'gdpr': 'policies/non_compliant/Non_Compliant_Policy.txt',
}


def _repo_root():
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _score_document(path, framework_key):
    """Score a bundled policy with the live engine — identical call sequence to
    core/scan_pipeline.scan_file, minus the persistence, because the caller
    persists through the same helper it uses in production."""
    text = extract_text(path)
    framework = FRAMEWORKS[framework_key]
    results = [analyze_control(text, control) for control in framework['controls']]
    return results, calculate_weighted_score(results), text


def _retain_copy(source_path, org_id):
    """Copy a bundled sample into the upload store so it behaves exactly like a
    user-uploaded document (re-scannable by the monitoring engine, downloadable
    by the reviewer). Returns the stored filename or None if the copy failed."""
    import shutil
    import uuid

    from config import Config

    try:
        os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)
        stored = f'{org_id}_{uuid.uuid4().hex}_{os.path.basename(source_path)}'
        shutil.copyfile(source_path, os.path.join(Config.UPLOAD_FOLDER, stored))
        return stored
    except OSError:
        return None


def seed(app, org_name='Audinexia Demo Organization', password=None, with_vendors=True,
         with_monitoring=True):
    """Create the demo dataset. Idempotent-ish by intent: it refuses if the
    organization name already exists, so running it twice cannot double up."""
    import secrets

    if Organization.query.filter_by(name=org_name).first():
        raise RuntimeError(f'organization "{org_name}" already exists; seed refused '
                           f'(delete it or pass a different --org)')

    supplied = bool(password)
    password = password or secrets.token_urlsafe(18)

    org = Organization(name=org_name, default_policy_review_interval_days=180,
                       default_vendor_review_interval_days=365)
    db.session.add(org)
    db.session.flush()

    users = {}
    for role, name, email in ROLE_ACCOUNTS:
        user = User(org_id=org.id, email=email, name=name, role=role, is_active=True,
                    must_change_password=not supplied)
        user.set_password(password)
        db.session.add(user)
        db.session.flush()
        users[role] = user

    # ── Assessments across the compliance spectrum ────────────────────────
    assessment_ids = []
    for framework_key, relative_path in SAMPLE_POLICIES.items():
        path = os.path.join(_repo_root(), relative_path)
        if not os.path.isfile(path):
            continue
        results, overall, _text = _score_document(path, framework_key)
        assessment = Assessment(
            org_id=org.id, user_id=users['member'].id, framework=framework_key,
            filename=os.path.basename(relative_path),
            overall_score=overall,
            compliant_count=sum(1 for r in results if r['status'] == 'Compliant'),
            partial_count=sum(1 for r in results if r['status'] == 'Partially Compliant'),
            non_compliant_count=sum(1 for r in results if r['status'] == 'Non-Compliant'),
            report_id=f'SEED-{framework_key.upper()}-{datetime.utcnow().strftime("%Y%m%d")}',
            source='manual', stored_filename=_retain_copy(path, org.id),
            content_hash=text_hash(extract_text(path)),
            framework_hash=framework_content_hash(framework_key),
        )
        db.session.add(assessment)
        db.session.flush()
        assessment_ids.append(assessment.id)

        for index, result in enumerate(results):
            cr = ControlResult(
                org_id=org.id, assessment_id=assessment.id, control_id=result['id'],
                control_name=result['name'], score=result['score'], status=result['status'],
                evidence_text=result['evidence'], missing_phrases=result['missing_phrases'],
                found_phrases=result['found_phrases'],
                remediation_status=None if result['status'] == 'Compliant' else 'open',
            )
            # Spread realistic workflow state across the seeded gaps rather than
            # leaving every row 'open/unreviewed', so the review and remediation
            # screens have something to show.
            if result['status'] == 'Non-Compliant' and index % 3 == 0:
                cr.reviewer_status = 'confirmed'
                cr.reviewed_by_id = users['auditor'].id
                cr.reviewed_at = datetime.utcnow() - timedelta(days=2)
                cr.assigned_to_id = users['member'].id
                cr.due_date = (datetime.utcnow() + timedelta(days=14)).date()
                cr.remediation_status = 'in_progress'
            elif result['status'] == 'Partially Compliant' and index % 4 == 0:
                cr.reviewer_status = 'overridden'
                cr.reviewer_note = ('Phrase matching missed an equivalent clause; '
                                    'manual read of the document confirms coverage.')
                cr.reviewed_by_id = users['compliance_manager'].id
                cr.reviewed_at = datetime.utcnow() - timedelta(days=1)
                cr.remediation_status = 'closed'
            db.session.add(cr)
        db.session.commit()

    # Real audit-trail entries for the seeded activity, written after the fact so
    # the trail screen has genuine content.
    from core.audit_trail import record

    for assessment_id in assessment_ids:
        record('scan.create', 'assessment', assessment_id,
               'Seeded demo assessment', {'seeded': True},
               user_id=users['member'].id, org_id=org.id)
    db.session.commit()

    # ── Risk register ─────────────────────────────────────────────────────
    risks = []
    for description, likelihood, impact, status in [
        ('Consent records are not retained in a queryable store, so a data-principal '
         'dispute cannot be evidenced.', 4, 5, 'mitigating'),
        ('Policy document set last reviewed 14 months ago; no owner assigned for the '
         'breach-notification clause.', 3, 4, 'open'),
        ('Vendor subprocessor list is unverified and may be out of date.', 3, 3, 'open'),
        ('Encryption-at-rest wording varies between three policies; auditors cannot tell '
         'which is authoritative.', 2, 3, 'accepted'),
    ]:
        score = likelihood * impact
        risk = Risk(
            org_id=org.id, description=description, likelihood=likelihood, impact=impact,
            risk_score=score, risk_level=bucket_risk_score(score), status=status,
            owner_id=users['compliance_manager'].id,
            review_date=(datetime.utcnow() + timedelta(days=45)).date(),
            created_by_id=users['org_admin'].id,
            mitigation=('Deploying an append-only consent log with 24-month retention; '
                        'contract clause added at renewal.') if status == 'mitigating' else None,
        )
        db.session.add(risk)
        db.session.flush()
        risks.append(risk)

    # Link the first risk to real non-compliant rows so the linkage UI is not empty.
    first_gap = (ControlResult.query.filter_by(org_id=org.id)
                 .filter(ControlResult.status == 'Non-Compliant').first())
    if first_gap:
        from models import RiskControlLink

        db.session.add(RiskControlLink(org_id=org.id, risk_id=risks[0].id,
                                       control_result_id=first_gap.id,
                                       linked_by_id=users['compliance_manager'].id))
    db.session.commit()

    # ── Audit engagement + findings ───────────────────────────────────────
    audit = Audit(
        org_id=org.id, title='Q3 internal DPDPA readiness review',
        scope_description='Documentation readiness across consent, rights handling and breach '
                         'notification, ahead of the Board inspection window.',
        lead_auditor_id=users['auditor'].id, status='in_progress',
        start_date=(datetime.utcnow() - timedelta(days=10)).date(),
        end_date=(datetime.utcnow() + timedelta(days=20)).date(),
        created_by_id=users['org_admin'].id,
    )
    db.session.add(audit)
    db.session.flush()
    finding_ids = []
    for description, severity, status, offset_days in [
        ('Breach-notification procedure names a mailbox but no 72-hour timeline.', 'critical',
         'in_remediation', 14),
        ('Data-principal erasure requests handled ad hoc by support, with no SLA.', 'high', 'open', 30),
        ('Retention schedule exists for customer records only; prospect data has none.', 'medium',
         'open', 60),
        ('Grievance officer contact is present in the policy but not on the public site.', 'low',
         'resolved', 7),
    ]:
        finding = Finding(
            org_id=org.id, audit_id=audit.id, description=description, severity=severity,
            status=status, owner_id=users['member'].id,
            due_date=(datetime.utcnow() + timedelta(days=offset_days)).date(),
            recommendation='Assign an owner, publish the timeline, and re-scan the revised '
                           'document so the gap closes in the system of record.',
            management_response='Accepted; remediation scheduled for this quarter.'
            if status == 'in_remediation' else None,
            created_by_id=users['auditor'].id,
        )
        if status == 'resolved':
            finding.closed_at = datetime.utcnow() - timedelta(days=1)
            finding.closed_by_id = users['auditor'].id
        db.session.add(finding)
        db.session.flush()
        finding_ids.append(finding.id)
    if assessment_ids:
        # Link the first seeded scan to the engagement through the nullable FK
        # (one audit, many scans) rather than a copy of its rows.
        first = db.session.get(Assessment, assessment_ids[0])
        first.audit_id = audit.id
    db.session.commit()

    vendors_created = 0
    if with_vendors:
        for name, sensitivity, status, doc, framework_key, score_override in [
            ('Northwind Analytics', 'personal_data', 'active',
             'policies/partial/Partially_Compliant_Policy.txt', 'dpdpa', None),
            ('Ledgerly Payments', 'cardholder_data', 'active',
             'policies/compliant/Fully_Compliant_Policy.txt', 'dpdpa', None),
            ('Cobalt Health Cloud', 'health_data', 'under_review', None, 'hipaa', None),
        ]:
            vendor = Vendor(
                org_id=org.id, name=name,
                service_description=('Customer analytics and enrichment' if 'Analytics' in name else
                                     'Payment processing' if 'Payments' in name else
                                     'Clinical data hosting'),
                contact_name='Vendor Compliance Desk',
                contact_email=f'compliance@{name.split()[0].lower()}.example',
                data_sensitivity=sensitivity, status=status,
                review_frequency_days=365,
                contract_start=(datetime.utcnow() - timedelta(days=400)).date(),
                contract_end=(datetime.utcnow() + timedelta(days=40 if 'Analytics' in name else 500)).date(),
                created_by_id=users['compliance_manager'].id,
            )
            db.session.add(vendor)
            db.session.flush()
            vendors_created += 1

            db.session.add(VendorContract(
                org_id=org.id, vendor_id=vendor.id,
                title=f'{name} — data processing addendum',
                contract_type='dpa', frameworks=[framework_key],
                signed_on=(datetime.utcnow() - timedelta(days=395)).date(),
                expires_on=vendor.contract_end,
                breach_notification_hours=24 if 'Payments' in name else 72,
                audit_rights=True, sub_processors_permitted=False,
            ))

            if doc:
                path = os.path.join(_repo_root(), doc)
                if os.path.isfile(path):
                    results, overall, _ = _score_document(path, framework_key)
                    assessment = Assessment(
                        org_id=org.id, user_id=users['compliance_manager'].id,
                        framework=framework_key, filename=f'{name} — {os.path.basename(doc)}',
                        overall_score=overall,
                        compliant_count=sum(1 for r in results if r['status'] == 'Compliant'),
                        partial_count=sum(1 for r in results if r['status'] == 'Partially Compliant'),
                        non_compliant_count=sum(1 for r in results if r['status'] == 'Non-Compliant'),
                        report_id=f'SEED-VND-{vendor.id}', vendor_id=vendor.id, source='manual',
                        stored_filename=_retain_copy(path, org.id),
                        framework_hash=framework_content_hash(framework_key),
                    )
                    db.session.add(assessment)
                    db.session.flush()
                    for result in results:
                        db.session.add(ControlResult(
                            org_id=org.id, assessment_id=assessment.id, control_id=result['id'],
                            control_name=result['name'], score=result['score'],
                            status=result['status'], evidence_text=result['evidence'],
                            missing_phrases=result['missing_phrases'],
                            found_phrases=result['found_phrases'],
                            remediation_status=None if result['status'] == 'Compliant' else 'open',
                        ))
                    vendor.latest_overall_score = overall
                    vendor.last_assessment_id = assessment.id
                    vendor.risk_tier = tier_from_coverage(overall)
                    vendor.open_gap_count = sum(1 for r in results if r['status'] != 'Compliant')
                    vendor.last_reviewed_at = datetime.utcnow() - timedelta(days=30)
            else:
                vendor.risk_tier = 'unassessed'
        db.session.commit()

    watches_created = 0
    if with_monitoring:
        for framework_key, relative_path, interval, overdue in [
            ('dpdpa', 'policies/compliant/Fully_Compliant_Policy.txt', 180, False),
            ('nistcsf', 'policies/partial/Partially_Compliant_Policy.txt', 90, True),
        ]:
            filename = os.path.basename(relative_path)
            anchor = (Assessment.query.filter_by(org_id=org.id, framework=framework_key)
                      .filter(Assessment.filename == filename)
                      .order_by(Assessment.created_at.desc()).first())
            if anchor is None:
                continue
            last_run = anchor.created_at
            next_due = last_run + timedelta(days=interval)
            if overdue:
                next_due = datetime.utcnow() - timedelta(days=12)
            watch = PolicyWatch(
                org_id=org.id, name=f'{filename} ({FRAMEWORKS[framework_key]["name"]})',
                filename=filename, framework=framework_key, review_interval_days=interval,
                drift_threshold_points=5.0, is_active=True,
                last_run_at=last_run, next_due_at=next_due, last_score=anchor.overall_score,
                previous_score=None, last_state='initial', last_assessment_id=anchor.id,
                last_framework_hash=anchor.framework_hash,
                created_by_id=users['compliance_manager'].id,
            )
            db.session.add(watch)
            db.session.flush()
            watches_created += 1
            db.session.add(PolicyWatchRun(
                org_id=org.id, watch_id=watch.id, state='initial', trigger='baseline',
                baseline_assessment_id=anchor.id, current_assessment_id=anchor.id,
                current_score=anchor.overall_score,
                message='Baseline anchored on the seeded assessment.',
            ))
        db.session.commit()

    # ── Maturity rows, derived by the real engine ─────────────────────────
    from routes.maturity_routes import snapshot_for_run

    for framework_key in {a.framework for a in Assessment.query.filter_by(org_id=org.id).all()}:
        snapshot_for_run(org.id, framework_key, 'seed')
        row = MaturityAssessment.query.filter_by(org_id=org.id, framework=framework_key).first()
        if row:
            row.target_level = 3
            row.self_assessment_notes = ('Baseline recorded for the demo dataset; the derived '
                                         'level reflects seeded workflow state, not a real '
                                         'programme.')
    db.session.commit()

    return {
        'org_id': org.id,
        'org_name': org.name,
        'accounts': {u.email: password for u in users.values()},
        'print_passwords': not supplied,
        'assessments': len(assessment_ids),
        'vendors': vendors_created,
        'watches': watches_created,
        'risks': len(risks),
        'audits': 1,
        'findings': len(finding_ids),
        'note': PASSWORD_NOTE,
    }
