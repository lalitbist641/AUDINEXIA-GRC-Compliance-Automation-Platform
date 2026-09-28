"""Staged compliance-maturity model (report 12.4).

Why this exists as its own module with an explicit gate list rather than a
formula on the compliance percentage: a percentage answer to "does the policy
text say the right things", which says nothing about whether the compliance
programme around it works. A 92%-covered policy library that nobody has
reviewed, has no evidence attached, and has not been re-verified in two years
is not a mature programme, and reporting it as one would be the kind of
overclaiming the project report's  11 explicitly warns against.

So each level is a set of *gates* evaluated against observable state in the
database (reviewer confirmations, remediation closure, evidence attachments,
monitoring freshness, audit-finding resolution, score trend). A level is
awarded only when every gate below it is met, and every gate reports the
numbers it was judged on, so the answer is always explainable and falsifiable.

This is a self-assessment aid. It is not an ISO/IEC 33000 (SPICE) appraisal and
must not be presented as one: the inputs are document-derived coverage plus
this platform's own workflow records, not an independent process assessment.
"""

LEVEL_LABELS = {
    1: 'Initial',
    2: 'Managed',
    3: 'Defined',
    4: 'Quantitatively Managed',
    5: 'Optimizing',
}

# Thresholds are module-level constants so a deployment can document/adjust the
# bar in one place, and so tests assert against the same numbers the code uses.
THRESHOLDS = {
    'coverage_managed': 0.50,          # L2: policy coverage at least half
    'coverage_defined': 0.65,          # L3
    'coverage_quantitatively': 0.75,   # L4
    'coverage_optimizing': 0.90,       # L5
    'owner_assignment_managed': 0.50,  # L2: half of gaps have an owner or due date
    'review_coverage_defined': 0.60,   # L3: reviewer touched 60% of gaps
    'evidence_coverage_defined': 0.40,  # L3: evidence attached on 40% of gaps
    'remediation_closed_l4': 0.70,     # L4: closed on time
    'findings_resolved_l4': 0.70,      # L4: audit findings resolved/closed
    'monitoring_coverage_l3': 0.50,    # L3: half of scanned docs under review cadence
    'min_data_points_trend': 2,        # L4: needs a trend, not a single reading
    'fresh_docs_optimizing': 0.90,     # L5: essentially nothing overdue
}


def _pct(numerator, denominator):
    """Ratio in 0..1, or None when there is no population to judge.

    None (not 0.0) is deliberate: "0 of 0 gaps reviewed" means the reviewer
    gate is not applicable, whereas scoring it 0% would punish an
    organization that has genuinely zero gaps — the exact opposite of the
    signal the gate is meant to carry.
    """
    if not denominator:
        return None
    return round(numerator / denominator, 4)


def _gate(name, label, metric, threshold, detail):
    """A gate passes when the metric clears the threshold, or when the metric
    is None because the population it measures is empty (nothing to fail)."""
    if metric is None:
        return {
            'name': name, 'label': label, 'met': True, 'not_applicable': True,
            'value': None, 'threshold': threshold,
            'detail': f'{detail} — no population to assess, gate is vacuously satisfied',
        }
    return {
        'name': name, 'label': label, 'met': metric >= threshold, 'not_applicable': False,
        'value': metric, 'threshold': threshold,
        'detail': f'{detail} ({round(metric * 100, 1)}% vs {(threshold * 100):.0f}% required)',
    }


def compute_metrics(coverage_fraction, gap_count, reviewed_gap_count, evidenced_gap_count,
                    owned_gap_count, closed_gap_count, overdue_gap_count,
                    document_count, monitored_document_count, overdue_document_count,
                    assessment_data_points, finding_count, resolved_finding_count,
                    overdue_finding_count, framework_drift_count,
                    latest_score_delta=None):
    """Turn raw counts (gathered from the DB by routes/maturity_routes.py) into
    the normalized ratios the gates operate on.

    Kept separate from evaluate() so the arithmetic is unit-testable without a
    database, and so the route layer contains no scoring logic at all.
    """
    t = THRESHOLDS
    open_gaps = max(gap_count - closed_gap_count, 0)

    metrics = {
        'gap_count': gap_count,
        'coverage': round(min(max(coverage_fraction, 0.0), 1.0), 4),
        'owner_assignment': _pct(owned_gap_count, gap_count),
        'review_coverage': _pct(reviewed_gap_count, gap_count),
        'evidence_coverage': _pct(evidenced_gap_count, gap_count),
        'remediation_closure': _pct(closed_gap_count, gap_count),
        'overdue_burden': _pct(overdue_gap_count, open_gaps) if open_gaps else (0.0 if gap_count == 0 else None),
        'monitoring_coverage': _pct(monitored_document_count, document_count),
        'freshness': (
            1.0 if document_count == 0
            else _pct(document_count - overdue_document_count, document_count)
        ),
        'measurement_depth': min((assessment_data_points or 0) / max(t['min_data_points_trend'], 1), 1.0),
        'findings_resolution': _pct(resolved_finding_count, finding_count),
        'finding_overdue_burden': _pct(overdue_finding_count, finding_count - resolved_finding_count)
        if (finding_count - resolved_finding_count) > 0 else None,
        'framework_currency': 0.0 if framework_drift_count else 1.0,
        'improvement_trend': latest_score_delta,
    }

    # Dimension rollups shown in the UI — each is the weakest gate in its area,
    # so a strong number cannot mask a weak one inside the same dimension.
    def _weakest(*values):
        present = [v for v in values if v is not None]
        return min(present) if present else None

    dimensions = {
        'policy_coverage': metrics['coverage'],
        'review_discipline': _weakest(metrics['review_coverage'], metrics['evidence_coverage']),
        'remediation_discipline': _weakest(
            metrics['owner_assignment'], metrics['remediation_closure'],
            None if metrics['overdue_burden'] is None else 1.0 - metrics['overdue_burden'],
        ),
        'monitoring_discipline': _weakest(metrics['monitoring_coverage'], metrics['freshness']),
        'audit_discipline': _weakest(
            metrics['findings_resolution'],
            None if metrics['finding_overdue_burden'] is None else 1.0 - metrics['finding_overdue_burden'],
        ),
        'measurement_discipline': _weakest(metrics['measurement_depth'], metrics['framework_currency']),
    }
    scored = [v for v in dimensions.values() if v is not None]
    # Composite 0-100 for trending only; never used to award a level.
    metrics['composite_score'] = round((sum(scored) / len(scored)) * 100, 1) if scored else 0.0
    return metrics


def evaluate(metrics):
    """Return the awarded level plus every gate's verdict and the evidence.

    Level 1 is unconditional: if nothing below is true, the programme is
    ad-hoc, and saying so is the point of an honest model.
    """
    t = THRESHOLDS
    cov = metrics['coverage']

    level1 = {
        'level': 1,
        'label': LEVEL_LABELS[1],
        'gates': [{
            'name': 'baseline', 'label': 'Compliance is assessed at all', 'met': True,
            'not_applicable': False, 'value': cov, 'threshold': None,
            'detail': 'No repeatable process; assessments are ad-hoc',
        }],
    }

    level2 = {
        'level': 2,
        'label': LEVEL_LABELS[2],
        'gates': [
            _gate('coverage', 'Weighted policy coverage', cov, t['coverage_managed'],
                  'Latest scans cover half the required control language'),
            _gate('owner_assignment', 'Gaps have an owner or due date',
                  metrics['owner_assignment'], t['owner_assignment_managed'],
                  f"{metrics['gap_count']} identified gap(s) triaged"),
        ],
    }

    level3 = {
        'level': 3,
        'label': LEVEL_LABELS[3],
        'gates': [
            _gate('coverage', 'Weighted policy coverage', cov, t['coverage_defined'],
                  'Coverage above the defined-process bar'),
            _gate('review_coverage', 'Reviewer confirmation of assessed gaps',
                  metrics['review_coverage'], t['review_coverage_defined'],
                  'Human-in-the-loop review (report §12.3) applied to findings'),
            _gate('evidence_coverage', 'Objective evidence attached to gaps',
                  metrics['evidence_coverage'], t['evidence_coverage_defined'],
                  'Evidence files back up the recorded status'),
            _gate('monitoring_coverage', 'Documents under a defined review cadence',
                  metrics['monitoring_coverage'], t['monitoring_coverage_l3'],
                  'Policies tracked for re-verification (report §12.7)'),
        ],
    }

    level4 = {
        'level': 4,
        'label': LEVEL_LABELS[4],
        'gates': [
            _gate('coverage', 'Weighted policy coverage', cov, t['coverage_quantitatively'],
                  'Coverage high enough for quantitative management'),
            _gate('remediation_closure', 'Gaps remediated to closure',
                  metrics['remediation_closure'], t['remediation_closed_l4'],
                  'Remediation items completed rather than left open'),
            _gate('findings_resolution', 'Audit findings resolved',
                  metrics['findings_resolution'], t['findings_resolved_l4'],
                  'Internal audit findings driven to resolution'),
            _gate('measurement_depth', 'Multiple measurement points (trend exists)',
                  metrics['measurement_depth'], 1.0,
                  'At least two assessments per scope, so change is measurable'),
            _gate('framework_currency', 'Scores measured against current framework definitions',
                  metrics['framework_currency'], 1.0,
                  'No assessment scored against a superseded control set'),
        ],
    }

    level5 = {
        'level': 5,
        'label': LEVEL_LABELS[5],
        'gates': [
            _gate('coverage', 'Weighted policy coverage', cov, t['coverage_optimizing'],
                  'Near-complete documented coverage'),
            _gate('freshness', 'No overdue re-verifications', metrics['freshness'],
                  t['fresh_docs_optimizing'], 'Every tracked policy verified inside its interval'),
            _gate('overdue_burden', 'No overdue remediation items',
                  None if metrics['overdue_burden'] is None else 1.0 - metrics['overdue_burden'],
                  1.0, 'Open remediation items are all inside their due dates'),
            _gate('improvement_trend', 'Most recent re-scan did not regress',
                  None if metrics['improvement_trend'] is None
                  else (1.0 if metrics['improvement_trend'] >= 0 else 0.0),
                  1.0, 'Continuous improvement is visible in the score trend'),
        ],
    }

    ladder = [level1, level2, level3, level4, level5]
    awarded = 1
    for rung in ladder[1:]:
        if all(gate['met'] for gate in rung['gates']):
            awarded = rung['level']
        else:
            # Levels are cumulative: a failed gate at N means N and above are
            # both unavailable, so stop rather than skipping to N+1.
            break

    blockers = []
    for rung in ladder:
        if rung['level'] == awarded:
            continue
        for gate in rung['gates']:
            if not gate['met']:
                blockers.append({
                    'level': rung['level'], 'level_label': rung['label'],
                    'gate': gate['label'], 'detail': gate['detail'],
                })

    return {
        'derived_level': awarded,
        'derived_level_label': LEVEL_LABELS[awarded],
        'derived_score': metrics['composite_score'],
        'levels': ladder,
        'blockers': blockers,
        'methodology': (
            'Level awarded = highest rung whose gates are ALL satisfied, judged on this '
            'platform\'s own records (document coverage, reviewer confirmations, evidence '
            'attachments, remediation closure, monitoring freshness, audit-finding '
            'resolution). A gate with no population to judge is treated as not applicable '
            'rather than failed. Not an ISO/IEC 33000 appraisal.'
        ),
    }


def build(claimed_level=None, target_level=3, **raw_counts):
    """Convenience wrapper: compute metrics, evaluate gates, and fold in the
    organization's own claimed level as a comparison, never as the answer."""
    metrics = compute_metrics(**raw_counts)
    result = evaluate(metrics)
    result['metrics'] = metrics
    if claimed_level is not None:
        claimed = int(claimed_level)
        result['claimed_level'] = claimed
        result['claimed_level_label'] = LEVEL_LABELS.get(claimed, str(claimed))
        result['claim_overstates'] = claimed > result['derived_level']
        # The claim never moves the derived level; the gap is surfaced instead.
        result['claim_gap_note'] = (
            f'Claimed {LEVEL_LABELS.get(claimed, claimed)} vs evidence-supported '
            f'{result["derived_level_label"]}'
            + (' — the claim is ahead of the recorded evidence; resolve the listed '
               'blockers before reporting this level externally'
               if claimed > result['derived_level'] else
               (' — evidence supports a higher level than claimed'
                if claimed < result['derived_level'] else ' — claim and evidence agree'))
        )
    result['target_level'] = int(target_level)
    result['target_level_label'] = LEVEL_LABELS.get(int(target_level), str(target_level))
    result['levels_to_target'] = max(int(target_level) - result['derived_level'], 0)
    return result


def project_multi_framework(per_framework_results):
    """Roll several per-framework maturity evaluations into one view.

    The organization-level figure is the *minimum* across frameworks in scope,
    not an average: reporting an average would let a strong NIST CSF score hide
    a weak HIPAA one, which is precisely the masking that makes maturity
    percentages untrustworthy in vendor assessments.
    """
    if not per_framework_results:
        return None
    levels = [r['derived_level'] for r in per_framework_results]
    scores = [r['derived_score'] for r in per_framework_results]
    weakest = min(per_framework_results, key=lambda r: (r['derived_level'], r['derived_score']))
    return {
        'frameworks_in_scope': len(per_framework_results),
        'portfolio_level': min(levels),
        'portfolio_level_label': LEVEL_LABELS[min(levels)],
        'portfolio_score_average': round(sum(scores) / len(scores), 1),
        'weakest_framework': weakest['framework'],
        'weakest_framework_level': weakest['derived_level'],
        'aggregation_note': (
            'Portfolio level is the minimum across in-scope frameworks (weakest link), '
            'not the average — averaging lets one strong framework mask a weak one.'
        ),
    }
