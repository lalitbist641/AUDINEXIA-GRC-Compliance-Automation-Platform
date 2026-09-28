"""Risk contextualization for a scored control.

History of this module (worth recording, because the project report described it
as an active component while it was not): through Phase 7 the tier bands lived
here AND in `scanning.score_control_result()`, and nothing imported this file —
a scan's `risk_level` came from the copy in scanning.py, while this copy drifted
(four tiers including a "Critical" band, Chinese text pasted into one business
impact string, attack scenarios for 8 of the 12 DPDPA controls).

Two options: delete it, or make it the single source of truth. This is now the
single source: `scanning.score_control_result()` calls `RiskEngine.tier()` and
`risk_context()` rather than carrying its own copy of the thresholds, so a
reviewer reading Section 7 of the report and reading the code see the same
bands.

The bands are a labeling rule, not a measurement. They translate "this control
matched 2 of its 4 required phrases" into language a manager acts on; they do
not add information about actual exposure, and the `attack_scenario` strings are
illustrative examples of what a gap of that shape is typically used for — not
threat intelligence specific to the assessed organization.
"""

# Control-score bands, 0-100. Kept in one dict so the report's Section 7 table
# and the code have a single source.
TIERS = (
    # (upper_bound_exclusive, level, color, priority, window, impact, likelihood)
    (30.0, 'Critical', '#dc2626', 'Immediate', '0-7 days',
     'Severe — the control is effectively undocumented, so a regulator or '
     'court reviewing this policy would find no stated commitment at all',
     'Very High'),
    (50.0, 'High', '#f97316', 'High', '7-30 days',
     'Significant — the obligation is acknowledged but key elements are missing, '
     'so a challenge to this practice would be hard to defend',
     'High'),
    (70.0, 'Medium', '#eab308', 'Medium', '30-60 days',
     'Moderate — the substance is present with gaps in specificity or scope',
     'Medium'),
    (100.0001, 'Low', '#10b981', 'Low', '60-90 days',
     'Minimal — the requirement is documented; improvements are editorial',
     'Low'),
)

# Status thresholds used by the scanner (Compliant / Partially / Non-Compliant)
# are a coarser 3-band cut of the same score, and are defined in
# scanning.score_control_result(). The two vocabularies intentionally differ:
# a 55%-covered control is "Partially Compliant" AND "Medium" risk. See the
# report §7 note on Risk vs ControlResult scales.

BUSINESS_IMPACT_BY_STATUS = {
    'Compliant': 'Documented — residual risk is that practice diverges from policy, which a document scan cannot detect.',
    'Partially Compliant': 'Partially documented — an assessor will ask for the missing element.',
    'Non-Compliant': 'Not documented — treat as an open finding with regulatory exposure.',
}

# Illustrative exploit patterns, keyed by the shape of the gap rather than by
# control id, because 55 controls x per-id narrative is how this module ended up
# covering only 8 of them. A per-control override can still be supplied.
SCENARIOS_BY_PHRASE = {
    'explicit consent': 'Personal data is processed on a consent basis the policy never '
                        'establishes, so a data principal complaint has no documented basis to rebut.',
    'withdrawal mechanism': 'Users have no stated way to withdraw consent, which is a defect in '
                            'the consent itself rather than a missing convenience feature.',
    'retention period': 'Data accumulates without a stated deletion point, expanding both breach '
                        'exposure and the scope of any access or erasure request.',
    'deletion after purpose': 'Data is kept past the purpose that justified it, so a request to '
                               'erase has no policy basis to act on.',
    'encryption': 'Data in transit or at rest has no stated cryptographic protection, making an '
                  'endpoint compromise or stolen media a reportable breach.',
    'access control': 'Access is not role-scoped in policy, so a single compromised account has '
                      'no stated boundary.',
    'mfa': 'Administrative access depends on a single factor, which is the usual second step in '
           'a credential-stuffing chain.',
    'breach response': 'A breach has no stated owner, timeline or notification path, so the '
                       'first hours are improvised.',
    'notification': 'Regulators and affected individuals are not promised a timeline, so late '
                    'notice becomes a separate violation on top of the incident.',
    'grievance officer': 'A data principal with a complaint has no named escalation route, which '
                         'is itself a statutory requirement in several frameworks.',
    'dpo': 'No accountable person is named for data protection, so findings have no owner and '
           'regulator correspondence has no addressee.',
    'data principal rights': 'Rights requests arrive with no documented handling path, so '
                             'deadlines are missed by process rather than by intent.',
    'privacy notice': 'Processing purposes are not disclosed up front, undermining the lawful '
                      'basis for everything downstream.',
    'audit trail': 'Actions are not logged in a way the policy commits to, so a dispute about who '
                   'did what cannot be resolved.',
    'logging': 'Events are not retained or reviewed, so a breach is likely to be discovered by an '
               'outside party rather than internally.',
    'backup': 'Recovery commitments are undocumented, so ransomware response is improvised.',
    'business continuity': 'No documented continuity or recovery commitment, so outage impact '
                           'assessment cannot be evidenced.',
    'training': 'Personnel obligations are not established, so insider error is unmanaged and '
                'unaddressable in a disciplinary process.',
    'vendor': 'Third-party processing has no stated security or oversight requirement, extending '
              'breach exposure to systems the organization cannot see.',
    'third-party': 'Data shared with processors has no documented contractual floor, so a vendor '
                   'incident becomes the organization\'s regulatory incident.',
    'cross-border': 'International transfers are not documented, leaving transfer mechanisms '
                     'unasserted.',
    'transfer': 'A cross-border flow is asserted without safeguards, which is a standalone '
                'violation under several frameworks.',
    'record of consent': 'Consent cannot be evidenced for a specific individual at a specific time, '
                         'which is what a regulator actually asks for.',
    'consent records': 'Consent cannot be evidenced for a specific individual at a specific time.',
    'data minimization': 'Collection is broader than the stated purpose, so every subsequent '
                         'incident is larger than it needed to be.',
    'storage limitation': 'Retention is open-ended, which converts a minor inquiry into a '
                          'full data inventory exercise.',
    'children': 'Age verification and parental consent are unstated, which several frameworks treat '
                'as an aggravating factor rather than a technical gap.',
    'security measures': 'Safeguards are described in aspirational terms with no named control, so '
                         'an auditor records it as unimplemented.',
}


class RiskEngine:
    """Maps a control's coverage score to a risk tier and its narrative."""

    @staticmethod
    def calculate_risk(score, control_weight=None):
        """Tier for a 0-100 coverage score.

        `control_weight` is accepted but deliberately NOT used to adjust the
        tier: severity already drives the weighted overall score, and folding it
        in again here would double-count it and make a per-control label depend
        on an invisible parameter. It stays in the signature because callers
        have it handy and the alternative is callers silently pre-adjusting.
        """
        for upper, level, color, priority, window, impact, likelihood in TIERS:
            if score < upper:
                return {
                    'level': level,
                    'color': color,
                    'priority': priority,
                    'timeframe': window,
                    'business_impact': impact,
                    'attack_likelihood': likelihood,
                }
        # Unreachable given the open-ended final band, kept so a future edit to
        # TIERS that leaves a gap fails loudly rather than returning None.
        raise ValueError(f'score {score} did not match any risk tier')

    @staticmethod
    def generate_attack_scenario(control_id, control_name, missing_phrases=None):
        """An illustrative exploit/finding pattern for the shape of this gap.

        Derived from which required phrases are missing (shared vocabulary
        across frameworks) rather than from a per-control id table, so every one
        of the 55 controls gets a real description instead of a fallback string.
        """
        candidates = []
        for phrase in (missing_phrases or []):
            key = phrase.lower().strip()
            if key in SCENARIOS_BY_PHRASE:
                candidates.append(SCENARIOS_BY_PHRASE[key])
        if candidates:
            # Deduplicate while preserving order: several missing phrases can map
            # to the same sentence, and repeating it reads like a bug.
            seen = []
            for text in candidates:
                if text not in seen:
                    seen.append(text)
            return seen[0] if len(seen) == 1 else ' '.join(seen)
        return (f'"{control_name}" ({control_id}) has no documented commitment, so an assessor '
                f'records it as an unmanaged obligation with no stated owner or process.')

    @staticmethod
    def generate_remediation(control_id, score):
        """Priority and timeframe for closing the gap."""
        tier = RiskEngine.calculate_risk(score)
        return (f'{tier["priority"].upper()} — target {tier["timeframe"]}. '
                f'{_NEXT_STEP_BY_TIER[tier["level"]]}')

    @staticmethod
    def risk_context(score, missing_phrases=None, control_id=None, control_name=None,
                     remediation_example=None):
        """Everything the report's Section 6.5 promises, in one call: the tier
        label and color plus the impact narrative, an illustrative scenario, and
        a remediation priority line.

        Returns a dict of strings only — no numbers are invented here.
        """
        tier = RiskEngine.calculate_risk(score)
        context = {
            'risk_level': tier['level'],
            'risk_color': tier['color'],
            'risk_priority': tier['priority'],
            'remediation_window': tier['timeframe'],
            'business_impact': tier['business_impact'],
            'attack_likelihood': tier['attack_likelihood'],
            'attack_scenario': RiskEngine.generate_attack_scenario(
                control_id or '?', control_name or 'this control', missing_phrases),
            'remediation_priority': RiskEngine.generate_remediation(control_id or '?', score),
        }
        if remediation_example:
            context['suggested_language'] = remediation_example
        return context


_NEXT_STEP_BY_TIER = {
    'Critical': 'Draft the missing clause now and route it for legal review; a control with no '
                'documented commitment cannot be evidenced at all.',
    'High': 'Add the missing elements with specifics (owner, timeline, threshold). Generic '
            'aspirational language will not close this finding.',
    'Medium': 'Tighten scope and wording at the next scheduled policy revision.',
    'Low': 'Editorial improvement only; no action required before the next review cycle.',
}
