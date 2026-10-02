"""Third-party / vendor risk routes (report §12.6).

Deliberately reuses the same scanning engine, review workflow and report
export as first-party assessments: a Vendor is just another owner of
Assessments. That means per-control evidence, reviewer override, evidence
attachments, remediation tracking, crosswalk projection and PDF export all
work on vendor documents with no parallel implementation to keep in sync.
"""

from datetime import datetime

from flask import Blueprint, current_app, jsonify, request
from sqlalchemy import func

from core.audit_trail import record
from core.scan_pipeline import ScanError, scan_file
from core.vendor_risk import escalate_tier, evaluate_vendor, register_summary, tier_from_coverage
from extensions import db
from models import (
    ROLES,
    Assessment,
    ControlResult,
    Finding,
    FindingVendorLink,
    User,
    Vendor,
    VendorContract,
    VENDOR_STATUSES,
)
from rbac import current_org_id, current_user_id, roles_required
from routes.scan_routes import _save_upload
from scanning import FRAMEWORKS

vendor_bp = Blueprint('vendor', __name__)

ALL_ROLES = ROLES  # single source: models.ROLES, never a re-typed literal
MANAGE_ROLES = ('org_admin', 'compliance_manager')
ASSESS_ROLES = ('org_admin', 'compliance_manager', 'auditor', 'member')

DATA_SENSITIVITIES = ('public', 'internal', 'confidential', 'personal_data',
                      'health_data', 'cardholder_data', 'restricted')
CONTRACT_TYPES = ('msa', 'dpa', 'sla', 'sub_processor_addendum', 'nda', 'order_form')


class BadDate(ValueError):
    """Raised by _parse_date so each handler chooses its own error message."""


def _parse_date(raw):
    if raw in (None, ''):
        return None
    try:
        return datetime.strptime(raw, '%Y-%m-%d').date()
    except (TypeError, ValueError):
        raise BadDate('expected YYYY-MM-DD')


def _get_org_vendor(vendor_id):
    return Vendor.query.filter_by(id=vendor_id, org_id=current_org_id()).first()


def _gap_counts_for(org_id, vendor_ids=None):
    """(open_gaps, critical_gaps) per vendor, in one query.

    "Critical gap" means a control the framework marks severity=critical that
    is not currently Compliant AND still has an open remediation item — the
    reviewer-override path can legitimately close a false positive, and the
    count must follow that decision rather than the original scan output.
    """
    query = (db.session.query(
                Assessment.vendor_id, Assessment.framework, ControlResult.control_id,
                ControlResult.status, ControlResult.remediation_status)
             .join(ControlResult, ControlResult.assessment_id == Assessment.id)
             .filter(Assessment.org_id == org_id, Assessment.vendor_id.isnot(None)))
    if vendor_ids is not None:
        query = query.filter(Assessment.vendor_id.in_(vendor_ids))

    counts = {}
    for vendor_id, framework, control_id, status, remediation_status in query.all():
        open_gaps, critical_gaps = counts.get(vendor_id, (0, 0))
        if remediation_status in ('open', 'in_progress'):
            open_gaps += 1
            framework_info = FRAMEWORKS.get(framework)
            control_def = next(
                (c for c in framework_info['controls'] if c['id'] == control_id), None
            ) if framework_info else None
            if control_def and control_def['severity'] == 'critical' and status != 'Language found':
                critical_gaps += 1
        counts[vendor_id] = (open_gaps, critical_gaps)
    return counts


def _refresh_rollup(vendor):
    """Recompute the denormalized register fields from linked assessments."""
    latest = (Assessment.query.filter_by(vendor_id=vendor.id)
              .order_by(Assessment.created_at.desc()).first())
    vendor.latest_overall_score = latest.overall_score if latest else None
    vendor.last_assessment_id = latest.id if latest else None
    open_gaps, critical_gaps = _gap_counts_for(vendor.org_id, [vendor.id]).get(vendor.id, (0, 0))
    vendor.open_gap_count = open_gaps
    if latest:
        tier = tier_from_coverage(latest.overall_score)
        if critical_gaps:
            # Bump a band rather than let a middling average hide a missing
            # breach-notification clause.
            tier = escalate_tier(tier)
        vendor.risk_tier = tier
    else:
        vendor.risk_tier = 'unassessed'


@vendor_bp.route('/vendors', methods=['GET'])
@roles_required(*ALL_ROLES)
def list_vendors():
    """Plain register listing (no rollup math) — cheap for large lists."""
    vendors = Vendor.query.filter_by(org_id=current_org_id()).order_by(Vendor.name.asc()).all()
    return jsonify({
        'vendors': [v.to_dict() for v in vendors],
        'statuses': list(VENDOR_STATUSES),
        'data_sensitivities': list(DATA_SENSITIVITIES),
    })


def _build_register(org_id, now=None):
    """Shared computation for the JSON register and the CSV export, so the two
    can never report different numbers for the same vendor."""
    now = now or datetime.utcnow()
    vendors = Vendor.query.filter_by(org_id=org_id).all()
    now = datetime.utcnow()

    # Batched lookups rather than one query per vendor — the register is the
    # page a CISO opens first, and it should stay one screenful of queries.
    latest_by_vendor = {}
    for assessment in (Assessment.query.filter_by(org_id=org_id)
                       .filter(Assessment.vendor_id.isnot(None))
                       .order_by(Assessment.vendor_id.asc(), Assessment.created_at.desc()).all()):
        latest_by_vendor.setdefault(assessment.vendor_id, assessment)

    worst_contract = {}
    for contract in VendorContract.query.filter_by(org_id=org_id).all():
        current = worst_contract.get(contract.vendor_id)
        if current is None:
            worst_contract[contract.vendor_id] = contract
            continue
        a, b = current.expires_on, contract.expires_on
        if a is None or (b is not None and b < a):
            worst_contract[contract.vendor_id] = contract

    open_findings = dict(
        db.session.query(FindingVendorLink.vendor_id, func.count(FindingVendorLink.id))
        .join(Finding, Finding.id == FindingVendorLink.finding_id)
        .filter(FindingVendorLink.org_id == org_id)
        .filter(Finding.deleted_at.is_(None))
        .filter(Finding.status.notin_(('resolved', 'closed')))
        .group_by(FindingVendorLink.vendor_id)
        .all()
    )
    gap_counts = _gap_counts_for(org_id)

    entries = []
    for vendor in vendors:
        vendor_gaps = gap_counts.get(vendor.id, (0, 0))
        entry = evaluate_vendor(
            vendor.to_dict(),
            latest=latest_by_vendor.get(vendor.id),
            open_gap_count=vendor_gaps[0],
            critical_gap_count=vendor_gaps[1],
            open_findings=open_findings.get(vendor.id, 0),
            contract=worst_contract[vendor.id].to_dict() if worst_contract.get(vendor.id) else None,
            now=now,
        )
        entries.append(entry)

    entries.sort(key=lambda e: (-e['risk_score'], (e['name'] or '').lower()))
    return {
        'vendors': entries,
        'summary': register_summary(entries),
        'methodology': (
            'risk_score = (100 - latest weighted coverage) x data-sensitivity multiplier, with a '
            'tier bump for an overdue review or open critical-severity gaps. Coverage comes from '
            'the same document engine used for first-party policies, so a vendor score and an '
            'internal score are directly comparable — and share the same limitation: they measure '
            'written policy, not implemented controls.'
        ),
    }


@vendor_bp.route('/vendors/risk-register', methods=['GET'])
@roles_required(*ALL_ROLES)
def risk_register():
    """The TPRM view: coverage, staleness and contract posture combined into a
    tier, sorted worst-first."""
    return jsonify(_build_register(current_org_id()))


@vendor_bp.route('/vendors', methods=['POST'])
@roles_required(*MANAGE_ROLES)
def create_vendor():
    data = request.get_json(silent=True) or {}
    name = (data.get('name') or '').strip()
    if not name:
        return jsonify({'error': 'name is required'}), 400

    status = data.get('status', 'onboarding')
    if status not in VENDOR_STATUSES:
        return jsonify({'error': f'status must be one of: {", ".join(VENDOR_STATUSES)}'}), 400
    sensitivity = data.get('data_sensitivity', 'internal')
    if sensitivity not in DATA_SENSITIVITIES:
        return jsonify({'error': f'data_sensitivity must be one of: {", ".join(DATA_SENSITIVITIES)}'}), 400
    try:
        frequency = int(data.get('review_frequency_days') or 365)
    except (TypeError, ValueError):
        return jsonify({'error': 'review_frequency_days must be a whole number of days'}), 400
    if not 30 <= frequency <= 3650:
        return jsonify({'error': 'review_frequency_days must be between 30 and 3650 days'}), 400

    if Vendor.query.filter_by(org_id=current_org_id(), name=name).first():
        return jsonify({'error': 'A vendor with this name already exists in your organization'}), 409

    try:
        contract_start = _parse_date(data.get('contract_start'))
        contract_end = _parse_date(data.get('contract_end'))
    except BadDate:
        return jsonify({'error': 'contract_start and contract_end must be YYYY-MM-DD'}), 400

    vendor = Vendor(
        org_id=current_org_id(), name=name,
        service_description=(data.get('service_description') or '').strip() or None,
        contact_name=(data.get('contact_name') or '').strip() or None,
        contact_email=(data.get('contact_email') or '').strip().lower() or None,
        notes=(data.get('notes') or '').strip() or None,
        data_sensitivity=sensitivity, status=status, review_frequency_days=frequency,
        contract_start=contract_start, contract_end=contract_end,
        created_by_id=current_user_id(), risk_tier='unassessed',
    )
    if data.get('owner_id') is not None:
        owner = User.query.filter_by(id=data['owner_id'], org_id=current_org_id()).first()
        if not owner:
            return jsonify({'error': 'owner_id must be a user in your organization'}), 400
        vendor.owner_id = owner.id

    db.session.add(vendor)
    db.session.flush()
    vendor_id = vendor.id
    db.session.commit()
    record('vendor.create', 'vendor', vendor_id, f'Registered vendor {name}',
           {'name': name, 'data_sensitivity': sensitivity, 'status': status})
    return jsonify({'success': True, 'vendor': vendor.to_dict()}), 201


@vendor_bp.route('/vendors/<int:vendor_id>', methods=['GET'])
@roles_required(*ALL_ROLES)
def get_vendor(vendor_id):
    vendor = _get_org_vendor(vendor_id)
    if not vendor:
        return jsonify({'error': 'Not found'}), 404

    assessments = (Assessment.query.filter_by(vendor_id=vendor.id)
                   .order_by(Assessment.created_at.desc()).all())
    open_gaps, critical_gaps = _gap_counts_for(vendor.org_id, [vendor.id]).get(vendor.id, (0, 0))
    contracts = [c.to_dict() for c in vendor.contracts]
    # The contract whose expiry bites first is the one that matters for risk.
    expiring = sorted((c for c in contracts if c['expires_on']), key=lambda c: c['expires_on'])
    linked_findings = (FindingVendorLink.query.filter_by(vendor_id=vendor.id, org_id=current_org_id())
                       .all())

    return jsonify({
        'vendor': vendor.to_dict(),
        'rollup': evaluate_vendor(
            vendor.to_dict(),
            latest=assessments[0] if assessments else None,
            open_gap_count=open_gaps,
            critical_gap_count=critical_gaps,
            open_findings=sum(1 for l in linked_findings
                              if l.finding.status not in ('resolved', 'closed')),
            contract=expiring[0] if expiring else (contracts[0] if contracts else None),
        ),
        'contracts': contracts,
        'findings': [l.to_dict() for l in linked_findings],
        'assessments': [a.to_summary_dict() for a in assessments],
    })


@vendor_bp.route('/vendors/<int:vendor_id>', methods=['PATCH'])
@roles_required(*MANAGE_ROLES)
def update_vendor(vendor_id):
    vendor = _get_org_vendor(vendor_id)
    if not vendor:
        return jsonify({'error': 'Not found'}), 404
    data = request.get_json(silent=True) or {}
    changes = {}

    for field in ('name', 'service_description', 'contact_name', 'contact_email', 'notes'):
        if field in data:
            value = (data[field] or '').strip() or None
            if field == 'contact_email' and value:
                value = value.lower()
            setattr(vendor, field, value)
            changes[field] = value

    if 'status' in data:
        if data['status'] not in VENDOR_STATUSES:
            return jsonify({'error': f'status must be one of: {", ".join(VENDOR_STATUSES)}'}), 400
        vendor.status = data['status']
        changes['status'] = data['status']

    if 'data_sensitivity' in data:
        if data['data_sensitivity'] not in DATA_SENSITIVITIES:
            return jsonify({'error': f'data_sensitivity must be one of: {", ".join(DATA_SENSITIVITIES)}'}), 400
        vendor.data_sensitivity = data['data_sensitivity']
        changes['data_sensitivity'] = data['data_sensitivity']
        # Sensitivity is the multiplier, so the tier must be recomputed rather
        # than left at whatever the previous weighting produced.
        _refresh_rollup(vendor)

    if 'review_frequency_days' in data:
        try:
            frequency = int(data['review_frequency_days'])
        except (TypeError, ValueError):
            return jsonify({'error': 'review_frequency_days must be a whole number of days'}), 400
        if not 30 <= frequency <= 3650:
            return jsonify({'error': 'review_frequency_days must be between 30 and 3650 days'}), 400
        vendor.review_frequency_days = frequency
        changes['review_frequency_days'] = frequency

    for date_field in ('contract_start', 'contract_end'):
        if date_field in data:
            try:
                setattr(vendor, date_field, _parse_date(data[date_field]))
            except BadDate:
                return jsonify({'error': f'{date_field} must be YYYY-MM-DD'}), 400
            changes[date_field] = data[date_field]

    if 'owner_id' in data:
        if data['owner_id'] is None:
            vendor.owner_id = None
        else:
            owner = User.query.filter_by(id=data['owner_id'], org_id=current_org_id()).first()
            if not owner:
                return jsonify({'error': 'owner_id must be a user in your organization'}), 400
            vendor.owner_id = owner.id
        changes['owner_id'] = data['owner_id']

    if 'last_reviewed_at' in data:
        if data['last_reviewed_at'] in (None, ''):
            vendor.last_reviewed_at = None
        else:
            try:
                vendor.last_reviewed_at = datetime.strptime(data['last_reviewed_at'][:10], '%Y-%m-%d')
            except (TypeError, ValueError):
                return jsonify({'error': 'last_reviewed_at must be YYYY-MM-DD'}), 400
        changes['last_reviewed_at'] = data['last_reviewed_at']

    db.session.commit()
    record('vendor.update', 'vendor', vendor.id, f'Updated vendor {vendor.name}', changes)
    return jsonify({'success': True, 'vendor': vendor.to_dict()})


@vendor_bp.route('/vendors/<int:vendor_id>', methods=['DELETE'])
@roles_required('org_admin')
def delete_vendor(vendor_id):
    vendor = _get_org_vendor(vendor_id)
    if not vendor:
        return jsonify({'error': 'Not found'}), 404
    # Deleting a vendor cascades to their assessments, i.e. to audit history a
    # regulator may later ask for. Requiring 'offboarded' first makes removal a
    # deliberate act rather than a misclick on a live relationship.
    if vendor.status != 'offboarded':
        return jsonify({
            'error': 'Set the vendor status to "offboarded" before deleting, so removal is a '
                     'deliberate act rather than an accident on a live relationship.',
            'vendor_assessment_count': len(vendor.assessments),
        }), 409
    name = vendor.name
    db.session.delete(vendor)
    db.session.commit()
    record('vendor.delete', 'vendor', vendor_id, f'Deleted vendor {name}', {'name': name})
    return jsonify({'success': True})


@vendor_bp.route('/vendors/<int:vendor_id>/assessments', methods=['POST'])
@roles_required(*ASSESS_ROLES)
def assess_vendor_document(vendor_id):
    """Score a vendor-supplied policy document with the first-party engine."""
    vendor = _get_org_vendor(vendor_id)
    if not vendor:
        return jsonify({'error': 'Not found'}), 404
    if 'file' not in request.files:
        return jsonify({'error': 'No file'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    framework = request.form.get('framework', 'dpdpa')
    if framework not in FRAMEWORKS:
        return jsonify({'error': f'Framework "{framework}" not supported'}), 400

    original_filename, stored_filename, filepath = _save_upload(file, current_org_id())
    try:
        outcome = scan_file(
            filepath, f'{vendor.name} — {original_filename}', framework,
            current_org_id(), current_user_id(), vendor_id=vendor.id, source='manual',
        )
    except ScanError as exc:
        return jsonify({'error': exc.message, **exc.detail}), exc.status

    assessment = outcome['assessment']
    assessment.stored_filename = stored_filename
    vendor.last_reviewed_at = datetime.utcnow()
    _refresh_rollup(vendor)
    db.session.commit()

    record('vendor.assess', 'vendor', vendor.id,
           f'Scanned {original_filename} for {vendor.name} against {framework} '
           f'({outcome["overall_score"]}%)',
           {'framework': framework, 'overall_score': outcome['overall_score'],
            'filename': original_filename})

    return jsonify({
        'success': True,
        'assessment_id': assessment.id,
        'report_id': assessment.report_id,
        'vendor_id': vendor.id,
        'framework': framework,
        'overall_score': outcome['overall_score'],
        'controls': outcome['results'],
        'compliant_count': outcome['compliant_count'],
        'partial_count': outcome['partial_count'],
        'non_compliant_count': outcome['non_compliant_count'],
        'vendor_risk_tier': vendor.risk_tier,
        'open_gap_count': vendor.open_gap_count,
        'assurance_note': (
            'Vendor policy-document coverage only. Not an independent assessment of the '
            'vendor\'s implemented controls, SOC 2 report or penetration test.'
        ),
    })


@vendor_bp.route('/vendors/<int:vendor_id>/contracts', methods=['POST'])
@roles_required(*MANAGE_ROLES)
def create_contract(vendor_id):
    vendor = _get_org_vendor(vendor_id)
    if not vendor:
        return jsonify({'error': 'Not found'}), 404
    data = request.get_json(silent=True) or {}
    title = (data.get('title') or '').strip()
    if not title:
        return jsonify({'error': 'title is required'}), 400
    contract_type = data.get('contract_type', 'msa')
    if contract_type not in CONTRACT_TYPES:
        return jsonify({'error': f'contract_type must be one of: {", ".join(CONTRACT_TYPES)}'}), 400
    try:
        signed_on = _parse_date(data.get('signed_on'))
        expires_on = _parse_date(data.get('expires_on'))
    except BadDate:
        return jsonify({'error': 'signed_on and expires_on must be YYYY-MM-DD'}), 400
    frameworks = data.get('frameworks') or []
    unknown = [f for f in frameworks if f not in FRAMEWORKS]
    if unknown:
        return jsonify({'error': f'Unknown framework(s): {", ".join(unknown)}'}), 400
    hours = data.get('breach_notification_hours')
    if hours is not None:
        try:
            hours = int(hours)
        except (TypeError, ValueError):
            return jsonify({'error': 'breach_notification_hours must be a whole number'}), 400
        if not 1 <= hours <= 24 * 30:
            return jsonify({'error': 'breach_notification_hours must be between 1 and 720'}), 400

    contract = VendorContract(
        org_id=current_org_id(), vendor_id=vendor.id, title=title,
        contract_type=contract_type, frameworks=frameworks or None,
        signed_on=signed_on, expires_on=expires_on,
        auto_renews=bool(data.get('auto_renews', False)),
        breach_notification_hours=hours,
        audit_rights=data.get('audit_rights'),
        sub_processors_permitted=data.get('sub_processors_permitted'),
        notes=(data.get('notes') or '').strip() or None,
    )
    db.session.add(contract)
    # Keep the vendor's denormalized expiry mirror in step with its contracts.
    if expires_on and (not vendor.contract_end or expires_on < vendor.contract_end):
        vendor.contract_end = expires_on
    db.session.commit()
    record('vendor_contract.create', 'vendor', vendor.id,
           f'Recorded {contract_type} "{title}" for {vendor.name}',
           {'contract_type': contract_type, 'expires_on': str(expires_on) if expires_on else None})
    return jsonify({'success': True, 'contract': contract.to_dict()}), 201


@vendor_bp.route('/vendors/<int:vendor_id>/contracts/<int:contract_id>', methods=['PATCH'])
@roles_required(*MANAGE_ROLES)
def update_contract(vendor_id, contract_id):
    contract = VendorContract.query.filter_by(
        id=contract_id, vendor_id=vendor_id, org_id=current_org_id()
    ).first()
    if not contract:
        return jsonify({'error': 'Not found'}), 404
    data = request.get_json(silent=True) or {}
    vendor = contract.vendor
    changes = {}
    try:
        if 'signed_on' in data:
            contract.signed_on = _parse_date(data['signed_on'])
            changes['signed_on'] = data['signed_on']
        if 'expires_on' in data:
            contract.expires_on = _parse_date(data['expires_on'])
            changes['expires_on'] = data['expires_on']
            # Re-derive the vendor's earliest expiry from the remaining set.
            remaining = [c.expires_on for c in vendor.contracts
                         if c.expires_on and c.id != contract.id]
            candidate = [d for d in remaining + [contract.expires_on] if d]
            vendor.contract_end = min(candidate) if candidate else None
    except BadDate:
        return jsonify({'error': 'signed_on and expires_on must be YYYY-MM-DD'}), 400

    for field in ('title', 'notes'):
        if field in data:
            setattr(contract, field, (data[field] or '').strip() or None)
            changes[field] = data[field]
    if 'contract_type' in data:
        if data['contract_type'] not in CONTRACT_TYPES:
            return jsonify({'error': f'contract_type must be one of: {", ".join(CONTRACT_TYPES)}'}), 400
        contract.contract_type = data['contract_type']
        changes['contract_type'] = data['contract_type']
    if 'auto_renews' in data:
        contract.auto_renews = bool(data['auto_renews'])
        changes['auto_renews'] = contract.auto_renews
    for field in ('audit_rights', 'sub_processors_permitted'):
        if field in data:
            setattr(contract, field, None if data[field] is None else bool(data[field]))
            changes[field] = data[field]

    db.session.commit()
    record('vendor_contract.update', 'vendor', vendor_id,
           f'Updated contract "{contract.title}"', changes)
    return jsonify({'success': True, 'contract': contract.to_dict()})


@vendor_bp.route('/vendors/<int:vendor_id>/contracts/<int:contract_id>', methods=['DELETE'])
@roles_required('org_admin')
def delete_contract(vendor_id, contract_id):
    contract = VendorContract.query.filter_by(
        id=contract_id, vendor_id=vendor_id, org_id=current_org_id()
    ).first()
    if not contract:
        return jsonify({'error': 'Not found'}), 404
    vendor = contract.vendor
    title = contract.title
    remaining = [c.expires_on for c in vendor.contracts if c.expires_on and c.id != contract.id]
    vendor.contract_end = min(remaining) if remaining else None
    db.session.delete(contract)
    db.session.commit()
    record('vendor_contract.delete', 'vendor', vendor_id, f'Removed contract "{title}"',
           {'title': title})
    return jsonify({'success': True})


@vendor_bp.route('/vendors/<int:vendor_id>/findings', methods=['POST'])
@roles_required(*MANAGE_ROLES)
def link_finding(vendor_id):
    """Associate an audit finding with a vendor, so "vendor X has N open
    findings" is a recorded relationship rather than a narrative in a note."""
    vendor = _get_org_vendor(vendor_id)
    if not vendor:
        return jsonify({'error': 'Not found'}), 404
    data = request.get_json(silent=True) or {}
    finding = Finding.query.filter_by(id=data.get('finding_id'),
                                      org_id=current_org_id(), deleted_at=None).first()
    if not finding:
        return jsonify({'error': 'finding_id not found in your organization'}), 400
    if FindingVendorLink.query.filter_by(finding_id=finding.id, vendor_id=vendor.id).first():
        return jsonify({'error': 'This finding is already linked to the vendor'}), 409

    link = FindingVendorLink(
        org_id=current_org_id(), finding_id=finding.id, vendor_id=vendor.id,
        linked_by_id=current_user_id(),
    )
    db.session.add(link)
    db.session.commit()
    record('vendor.finding_link', 'vendor', vendor.id,
           f'Linked finding #{finding.id} to {vendor.name}', {'finding_id': finding.id})
    return jsonify({'success': True, 'link': link.to_dict()}), 201


@vendor_bp.route('/vendors/<int:vendor_id>/findings/<int:finding_id>', methods=['DELETE'])
@roles_required(*MANAGE_ROLES)
def unlink_finding(vendor_id, finding_id):
    link = FindingVendorLink.query.filter_by(
        vendor_id=vendor_id, finding_id=finding_id, org_id=current_org_id()
    ).first()
    if not link:
        return jsonify({'error': 'Not found'}), 404
    db.session.delete(link)
    db.session.commit()
    record('vendor.finding_unlink', 'vendor', vendor_id,
           f'Unlinked finding #{finding_id} from vendor {vendor_id}', {'finding_id': finding_id})
    return jsonify({'success': True})


@vendor_bp.route('/vendors/export/register', methods=['GET'])
@roles_required(*ALL_ROLES)
def export_register():
    """CSV of the vendor register — the artifact a procurement or audit meeting
    actually consumes. Reuses _build_register() so the exported numbers are the
    ones the UI shows, not a second implementation that can drift."""
    import csv
    import io

    data = _build_register(current_org_id())
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow([
        'Vendor', 'Status', 'Data sensitivity', 'Coverage %', 'Risk tier', 'Risk score',
        'Open gaps', 'Open findings', 'Review overdue days', 'Contract state',
        'Basis', 'Assurance limitation',
    ])
    for entry in data['vendors']:
        writer.writerow([
            entry['name'], entry['status'], entry['data_sensitivity'],
            '' if entry['coverage_percent'] is None else entry['coverage_percent'],
            entry['risk_tier'], entry['risk_score'], entry['open_gap_count'],
            entry['open_findings'],
            '' if entry['review_overdue_days'] is None else entry['review_overdue_days'],
            (entry['contract'] or {}).get('label', ''),
            '; '.join(entry['reasons']),
            entry['assurance_note'],
        ])

    response = current_app.response_class(
        buffer.getvalue(), mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename="audinexia_vendor_register.csv"'},
    )
    response.headers['Access-Control-Expose-Headers'] = 'Content-Disposition'
    return response
