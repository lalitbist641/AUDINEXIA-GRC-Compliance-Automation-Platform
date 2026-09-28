"""Third-party / vendor risk rollup (report §12.6).

Reuses the same document-coverage engine the organization's own policies are
scored with — a vendor's privacy or security policy is just another document —
and then combines that coverage with two things a raw percentage ignores:
how much the vendor is actually trusted with (data sensitivity), and how stale
the last look at them is (review cadence).

Explicitly NOT claimed: this is not an independent assessment of a vendor's
controls. It reflects what the vendor's supplied documentation covers, exactly
as the first-party scan does. A vendor with a beautifully written policy and no
real controls scores well here; that limitation is stated in every payload via
`assurance_note` rather than left for the reader to infer.
"""

from datetime import datetime, timedelta

SENSITIVITY_WEIGHT = {
    'public': 0.5,
    'internal': 1.0,
    'confidential': 1.5,
    'restricted': 2.0,
    'cardholder_data': 2.0,
    'health_data': 2.0,
    'personal_data': 1.75,
}

TIER_THRESHOLDS = (
    (55.0, 'critical'),
    (70.0, 'high'),
    (85.0, 'medium'),
)


def tier_from_coverage(coverage_percent):
    """Map document coverage to a risk tier using the same 50/80 control
    banding vocabulary the scan engine uses, widened to four tiers so vendor
    registers line up with the risk register's Critical/High/Medium/Low."""
    if coverage_percent is None:
        return 'unassessed'
    for ceiling, tier in TIER_THRESHOLDS:
        if coverage_percent < ceiling:
            return tier
    return 'low'


def _sensitivity_multiplier(data_sensitivity):
    return SENSITIVITY_WEIGHT.get((data_sensitivity or 'internal').lower(), 1.0)


def staleness(last_reviewed_at, review_frequency_days, now=None):
    """How overdue the vendor review is, in days (negative = still in window)."""
    now = now or datetime.utcnow()
    if not last_reviewed_at:
        return None
    interval = review_frequency_days or 365
    due = last_reviewed_at + timedelta(days=int(interval))
    return (now - due).days


def evaluate_vendor(vendor, latest=None, open_gap_count=0, critical_gap_count=0,
                    open_findings=0, contract=None, now=None):
    """Combine a vendor's attributes and latest scan into a register entry.

    `latest` is the newest Assessment summary for this vendor (or None).
    Returns a plain dict — the route layer owns DB access, this owns judgment,
    so the whole tiering rule is unit-testable without a database.
    """
    now = now or datetime.utcnow()
    coverage = latest.overall_score if latest is not None else None

    tier = tier_from_coverage(coverage)
    reasons = []

    score = coverage
    if score is not None:
        reasons.append(
            f"Latest policy documentation scored {score}% against "
            f"{latest.framework if latest else 'unknown'}"
        )
    else:
        reasons.append('No policy document on file has been scanned for this vendor')

    multiplier = _sensitivity_multiplier(vendor.get('data_sensitivity'))
    if multiplier > 1.0:
        reasons.append(
            f"Handles {vendor.get('data_sensitivity')} — exposure multiplier "
            f"x{multiplier:g}, so gaps here matter more than the raw score suggests"
        )

    # Effective risk = coverage gap amplified by how much data they hold.
    # Kept as a transparent 0-100 number (not a black-box model) so a reviewer
    # can recompute it from the two inputs shown.
    if score is not None:
        shortfall = (100.0 - score) * multiplier
        risk_score = round(min(100.0, shortfall), 1)
    else:
        # Unassessed is treated as the worst case for register ordering only,
        # and is labelled as such — never silently blended into scored vendors.
        risk_score = 100.0

    overdue_days = staleness(
        _parse_dt(vendor.get('last_reviewed_at')), vendor.get('review_frequency_days'), now
    )
    if overdue_days and overdue_days > 0:
        tier = escalate_tier(tier)
        reasons.append(f'Review overdue by {overdue_days} day(s) — tier escalated one band')
    elif overdue_days is None and score is not None:
        reasons.append('No review cadence recorded — set a review interval to keep this current')

    if open_gap_count:
        reasons.append(f'{open_gap_count} open remediation item(s) from scans of their documents')
    if critical_gap_count:
        tier = escalate_tier(tier)
        reasons.append(
            f'{critical_gap_count} open gap(s) on controls the framework marks critical '
            '— tier escalated one band'
        )
    if open_findings:
        reasons.append(f'{open_findings} open audit finding(s) reference this vendor')

    contract_note = _contract_state(contract, now, reasons)

    return {
        'vendor_id': vendor.get('id'),
        'name': vendor.get('name'),
        'status': vendor.get('status'),
        'data_sensitivity': vendor.get('data_sensitivity'),
        'coverage_percent': coverage,
        'risk_tier': tier,
        'risk_score': risk_score,
        'risk_score_basis': (
            '(100 - coverage) x sensitivity multiplier; unassessed vendors are '
            'placed at the top of the register and labelled unassessed'
        ),
        'open_gap_count': open_gap_count,
        'critical_gap_count': critical_gap_count,
        'open_findings': open_findings,
        'review_overdue_days': overdue_days,
        'contract': contract_note,
        'reasons': reasons,
        'last_assessment_id': latest.id if latest is not None else None,
        'assurance_note': (
            'Documented-policy coverage only. This is not an independent assessment of '
            'the vendor\'s implemented controls, SOC 2 report, or pen-test results — '
            'those have to be reviewed separately and attached as evidence.'
        ),
    }


def escalate_tier(tier):
    order = ['low', 'medium', 'high', 'critical']
    if tier == 'unassessed':
        return 'unassessed'
    idx = order.index(tier) if tier in order else 0
    return order[min(idx + 1, len(order) - 1)]


def _parse_dt(raw):
    if not raw:
        return None
    if isinstance(raw, datetime):
        return raw
    try:
        return datetime.fromisoformat(raw)
    except (TypeError, ValueError):
        return None


def _contract_state(contract, now, reasons):
    """Contract posture is part of vendor risk: an expired DPA is a compliance
    gap regardless of how good the vendor's policy text is."""
    if not contract:
        return {'state': 'none', 'label': 'No contract recorded'}
    expires = _parse_dt(contract.get('expires_on'))
    if not expires:
        reasons.append('Contract has no recorded expiry date')
        return {'state': 'open_ended', 'label': 'No expiry recorded'}
    days_left = (expires - now).days
    if days_left < 0:
        reasons.append(f'Contract expired {abs(days_left)} day(s) ago')
        return {'state': 'expired', 'label': f'Expired {abs(days_left)} day(s) ago', 'days_left': days_left}
    if days_left <= 60:
        reasons.append(f'Contract expires in {days_left} day(s)')
        return {'state': 'expiring_soon', 'label': f'Expires in {days_left} day(s)', 'days_left': days_left}
    return {'state': 'active', 'label': f'{days_left} day(s) remaining', 'days_left': days_left}


def register_summary(entries):
    """Portfolio rollup for the vendor register header — counts and the
    unassessed list, which is the actionable number in a TPRM programme."""
    tiers = {}
    for e in entries:
        tiers[e['risk_tier']] = tiers.get(e['risk_tier'], 0) + 1
    unassessed = [e['name'] for e in entries if e['risk_tier'] == 'unassessed']
    overdue = [e['name'] for e in entries if (e.get('review_overdue_days') or 0) > 0]
    scored = [e['coverage_percent'] for e in entries if e.get('coverage_percent') is not None]
    return {
        'vendor_count': len(entries),
        'tier_counts': {
            'critical': tiers.get('critical', 0),
            'high': tiers.get('high', 0),
            'medium': tiers.get('medium', 0),
            'low': tiers.get('low', 0),
            'unassessed': tiers.get('unassessed', 0),
        },
        'average_coverage': round(sum(scored) / len(scored), 1) if scored else None,
        'unassessed_vendors': unassessed,
        'overdue_review_vendors': overdue,
        'note': (
            'average_coverage is computed over assessed vendors only — unassessed vendors '
            'are excluded rather than scored 0%, which would understate the register'
        ),
    }
