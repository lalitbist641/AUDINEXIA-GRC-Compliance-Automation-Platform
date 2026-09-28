"""OpenAPI 3.0 contract, generated from the live Flask route map.

Why generated rather than hand-authored: a hand-written spec for an API this
size drifts the moment one endpoint changes, and a drifted contract is worse
than none because people trust it. Paths, methods, parameters, auth roles and
summaries come from the running app; only the human-supplied description and
schema text below is written by hand, keyed by `endpoint + method`.

Served at /api/openapi.json and dumped by `flask openapi`; tests assert that
every registered route appears, so drift fails CI instead of shipping.
"""

import re

OPENAPI_VERSION = '3.0.3'

DESCRIPTION = """
Audinexia is a multi-tenant GRC compliance platform. It ingests an organization's
written policy documents (.txt/.pdf/.docx), scores them against structured control
frameworks (DPDPA 2023, ISO 27001:2022, GDPR, PCI DSS v4.0, HIPAA, NIST CSF 2.0),
and carries the result through review, remediation, risk, audit, vendor and
maturity workflows with an append-only audit trail.

**What the scores mean.** Coverage is measured from *document text* against each
control's required phrases and their synonym sets. A high score means the policy
says the right things; it is not evidence that the control is implemented, and no
endpoint in this API should be represented to a regulator as an independent
assessment.

**Auth.** All `/api/*` routes except `/api/auth/*` and the ops endpoints require a
Bearer JWT from `POST /api/auth/login`. Access tokens are short-lived
(default 30 minutes); `POST /api/auth/refresh` mints a new one from a refresh
token. Roles: `org_admin`, `compliance_manager`, `auditor`, `member`, `read_only`.
Every read is scoped to the caller's organization — a resource belonging to
another tenant returns 404, not 403, so existence is not leaked.
""".strip()

# Per-endpoint human-written notes. Keys are "<endpoint>.<method>".
OPERATION_NOTES = {
    'auth.register': {
        'summary': 'Create an organization and its first org_admin',
        'description': 'Self-service tenant bootstrap. The caller always becomes `org_admin` '
                       'of the new organization; teammates are added afterwards via '
                       '`POST /api/admin/users`.',
        'body': {'org_name': 'string', 'name': 'string', 'email': 'string', 'password': 'string'},
        'response': {'access_token': 'string', 'refresh_token': 'string', 'user': 'User',
                     'organization': 'Organization'},
    },
    'auth.login': {
        'summary': 'Exchange credentials for a JWT pair',
        'description': 'Rate limited and throttled per email after repeated failures. The error '
                       'message is identical for an unknown email and a wrong password.',
        'body': {'email': 'string', 'password': 'string'},
        'response': {'access_token': 'string', 'refresh_token': 'string', 'user': 'User'},
    },
    'auth.refresh': {'summary': 'Mint a new access token from a refresh token'},
    'auth.logout': {'summary': 'Revoke the current access token (and the refresh token if supplied)',
                    'body': {'refresh_token': 'string (optional)'}},
    'auth.me': {'summary': 'Current session identity and organization'},
    'auth.change_password': {'summary': 'Change own password and invalidate all issued tokens',
                             'body': {'current_password': 'string', 'new_password': 'string'}},
    'auth.password_policy': {'summary': 'Password rules, for client-side validation before a 400'},
    'scan.scan_document': {
        'summary': 'Score a policy document against one framework',
        'description': 'multipart/form-data: `file` plus `framework`. Persists an Assessment and '
                       'one ControlResult row per control, each with matched/missing phrases and '
                       'an evidence snippet. A file whose text cannot be extracted returns 400 — '
                       'it is never scored as 0% compliance.',
        'body': {'file': 'binary', 'framework': 'dpdpa|iso27001|gdpr|pcidss|hipaa|nistcsf'},
        'response': {'assessment_id': 'integer', 'overall_score': 'number', 'controls': 'ControlResult[]'},
    },
    'scan.scan_sample_document': {'summary': 'Score a bundled reference policy by filename',
                                  'body': {'filename': 'string', 'framework': 'string'}},
    'scan.export_report': {'summary': 'Download the HTML compliance report for an assessment',
                           'body': {'assessment_id': 'integer'}, 'raw': 'text/html'},
    'scan.export_pdf': {'summary': 'Download the PDF compliance report for an assessment',
                        'body': {'assessment_id': 'integer'}, 'raw': 'application/pdf'},
    'scan.revise_policy': {
        'summary': 'Draft replacement policy language for every gap found',
        'description': 'Compiles each control\'s remediation template into a gap-remediation '
                       'document (JSON, or PDF with `pdf=true`). Suggested text is a drafting '
                       'starting point, not reviewed language.',
        'body': {'file': 'binary', 'framework': 'string', 'pdf': 'boolean string'},
    },
    'assessment.list_assessments': {'summary': 'Assessment history for the caller\'s organization'},
    'assessment.get_assessment': {'summary': 'One assessment with all per-control results'},
    'review.get_control_result': {'summary': 'Review state for one control result'},
    'review.update_control_result': {
        'summary': 'Confirm or override a detected score, assign, set due date, update remediation status',
        'description': 'The human-in-the-loop layer. A score is never overwritten: an override '
                       'records the reviewer, note and timestamp alongside the engine\'s original '
                       'status, and both remain readable.',
        'body': {'reviewer_status': 'unreviewed|confirmed|overridden', 'reviewer_note': 'string',
                 'assigned_to_id': 'integer', 'due_date': 'YYYY-MM-DD',
                 'remediation_status': 'open|in_progress|closed'},
    },
    'review.upload_evidence': {'summary': 'Attach an evidence file to a control result',
                               'body': {'file': 'binary'}},
    'review.list_evidence': {'summary': 'List evidence attached to a control result'},
    'review.download_evidence': {'summary': 'Download one evidence file'},
    'review.delete_evidence': {'summary': 'Remove an evidence file (org_admin, compliance_manager)'},
    'review.remediation_plan': {'summary': 'All open remediation items for an assessment, owner and due date included'},
    'crosswalk.get_crosswalk': {
        'summary': 'Project verified control overlap onto other frameworks',
        'description': 'Returns categorical projections only, each citing its source control. No '
                       'score is copied between frameworks, because a control score is only '
                       'meaningful against the exact phrase list it was computed from.',
        'query': {'target': 'framework key (optional; defaults to all others)'},
    },
    'risk.list_risks': {'summary': 'Risk register'},
    'risk.create_risk': {
        'summary': 'Add a risk with 5x5 likelihood/impact',
        'description': 'likelihood and impact are required human inputs and are never defaulted — '
                       'this system has no basis to infer them from scan data. Score and band are '
                       'derived from them by fixed arithmetic.',
        'body': {'description': 'string', 'likelihood': '1-5', 'impact': '1-5', 'owner_id': 'integer',
                 'status': 'open|mitigating|accepted|closed', 'mitigation': 'string',
                 'review_date': 'YYYY-MM-DD'},
    },
    'risk.get_risk': {'summary': 'One risk with its linked controls'},
    'risk.update_risk': {'summary': 'Update a risk, including residual score after mitigation',
                         'body': {'status': 'string', 'mitigation': 'string', 'residual_likelihood': '1-5',
                                  'residual_impact': '1-5', 'owner_id': 'integer', 'review_date': 'date'}},
    'risk.delete_risk': {'summary': 'Delete a risk'},
    'risk.link_control': {'summary': 'Link a risk to the control results that evidenced it',
                          'body': {'control_result_id': 'integer'}},
    'risk.unlink_control': {'summary': 'Remove a risk/control link'},
    'risk.risk_suggestion': {'summary': 'Pre-fill a risk description from a control gap'},
    'audit.list_audits': {'summary': 'Audit engagements'},
    'audit.create_audit': {'summary': 'Plan an audit engagement',
                           'body': {'title': 'string', 'scope_description': 'string',
                                    'lead_auditor_id': 'integer', 'start_date': 'date', 'end_date': 'date'}},
    'audit.get_audit': {'summary': 'One audit with findings and linked assessments'},
    'audit.update_audit': {'summary': 'Update audit fields or status (planned/in_progress/completed/closed)'},
    'audit.delete_audit': {'summary': 'Delete an audit and its findings'},
    'audit.create_finding': {'summary': 'Record a finding',
                             'body': {'description': 'string', 'severity': 'critical|high|medium|low',
                                      'recommendation': 'string', 'owner_id': 'integer', 'due_date': 'date'}},
    'audit.get_finding': {'summary': 'One finding'},
    'audit.update_finding': {'summary': 'Update a finding (status, response, owner, due date)'},
    'audit.delete_finding': {'summary': 'Delete a finding'},
    'audit.link_control': {'summary': 'Link a finding to control results'},
    'audit.unlink_control': {'summary': 'Remove a finding/control link'},
    'audit.risk_suggestion': {'summary': 'Pre-fill a risk from an audit finding'},
    'vendor.list_vendors': {'summary': 'Vendor register (flat listing, no rollup math)'},
    'vendor.risk_register': {
        'summary': 'Vendor risk register with tiers, staleness and contract posture',
        'description': 'risk_score = (100 - latest weighted coverage) x data-sensitivity '
                       'multiplier, escalated one band for an overdue review or open '
                       'critical-severity gaps. Document coverage only.',
    },
    'vendor.create_vendor': {'summary': 'Register a vendor',
                             'body': {'name': 'string', 'service_description': 'string',
                                      'contact_name': 'string', 'contact_email': 'string',
                                      'data_sensitivity': 'public|internal|confidential|personal_data|'
                                                          'health_data|cardholder_data|restricted',
                                      'status': 'onboarding|active|under_review|suspended|offboarded',
                                      'review_frequency_days': 'integer', 'owner_id': 'integer',
                                      'contract_start': 'date', 'contract_end': 'date'}},
    'vendor.get_vendor': {'summary': 'Vendor detail with rollup, contracts, findings and assessments'},
    'vendor.update_vendor': {'summary': 'Update vendor attributes; sensitivity changes recompute the tier'},
    'vendor.delete_vendor': {'summary': 'Delete a vendor (must be offboarded first, so removal is deliberate)'},
    'vendor.assess_vendor_document': {
        'summary': 'Score a vendor-supplied policy document',
        'description': 'The same engine as a first-party scan, attributed to the vendor and rolled '
                       'into the register.',
        'body': {'file': 'binary', 'framework': 'string'},
    },
    'vendor.create_contract': {'summary': 'Record a vendor contract (MSA/DPA/SLA/…)',
                               'body': {'title': 'string', 'contract_type': 'msa|dpa|sla|'
                                        'sub_processor_addendum|nda|order_form', 'frameworks': 'string[]',
                                        'signed_on': 'date', 'expires_on': 'date', 'auto_renews': 'boolean',
                                        'breach_notification_hours': 'integer', 'audit_rights': 'boolean',
                                        'sub_processors_permitted': 'boolean'}},
    'vendor.update_contract': {'summary': 'Update a vendor contract'},
    'vendor.delete_contract': {'summary': 'Remove a vendor contract record'},
    'vendor.link_finding': {'summary': 'Link an audit finding to a vendor',
                           'body': {'finding_id': 'integer'}},
    'vendor.unlink_finding': {'summary': 'Unlink an audit finding from a vendor'},
    'vendor.export_register': {'summary': 'Download the vendor register as CSV', 'raw': 'text/csv'},
    'maturity.list_maturity': {
        'summary': 'Per-framework maturity plus the portfolio view',
        'description': 'Each level is a set of gates evaluated against this platform\'s own records; '
                       'a level is awarded only when every gate below it passes, and each gate '
                       'reports the numbers it was judged on. A claimed level never overrides the '
                       'derived one.',
    },
    'maturity.get_maturity': {'summary': 'One framework\'s maturity with gates, blockers and trend'},
    'maturity.update_maturity': {'summary': 'Record claimed/target level, notes, approval',
                                 'body': {'current_level': '1-5', 'target_level': '1-5',
                                          'self_assessment_notes': 'string', 'approve': 'boolean',
                                          'review_due_at': 'date'}},
    'maturity.recalculate': {'summary': 'Re-derive from current records and append a trend snapshot'},
    'maturity.trend': {'summary': 'Maturity snapshot history for one framework'},
    'monitoring.list_watches': {'summary': 'Policy watches with computed freshness'},
    'monitoring.summary': {'summary': 'Monitoring headline counts and the attention list'},
    'monitoring.create_watch': {
        'summary': 'Track a policy document for re-verification',
        'description': 'Anchors on the newest existing scan of that filename+framework when one '
                       'exists, so adopting a two-year-old document starts overdue rather than '
                       'getting a fresh interval.',
        'body': {'name': 'string', 'filename': 'string', 'framework': 'string',
                 'review_interval_days': 'integer', 'drift_threshold_points': 'number'},
    },
    'monitoring.get_watch': {'summary': 'One watch with its run history'},
    'monitoring.update_watch': {'summary': 'Update interval, drift threshold, name or active flag'},
    'monitoring.delete_watch': {'summary': 'Delete a watch'},
    'monitoring.run_now': {
        'summary': 'Execute one monitoring check',
        'description': 'With a `file` part: scores that document as a new version and diffs it '
                       'against the baseline. Without one: re-measures the newest stored scan against '
                       'current framework definitions — and if neither the document nor the '
                       'yardstick changed, returns `no_new_version` and does NOT reset the due date.',
        'body': {'file': 'binary (optional)'},
    },
    'monitoring.due_watches': {'summary': 'Watches currently due (read-only, for schedulers)'},
    'admin.create_teammate': {'summary': 'Create a user in the caller\'s organization',
                              'body': {'email': 'string', 'name': 'string', 'temp_password': 'string',
                                       'role': 'org_admin|compliance_manager|auditor|member|read_only'}},
    'admin.list_teammates': {'summary': 'Organization users'},
    'admin.update_teammate': {'summary': 'Change role or activate/deactivate a user',
                              'body': {'role': 'string', 'is_active': 'boolean'}},
    'admin.reset_teammate_password': {'summary': 'Admin-set password; invalidates the user\'s tokens',
                                      'body': {'new_password': 'string'}},
    'admin.org_settings': {'summary': 'Organization settings (review intervals)'},
    'admin.update_org_settings': {'summary': 'Update organization settings',
                                   'body': {'default_policy_review_interval_days': 'integer',
                                            'default_vendor_review_interval_days': 'integer'}},
    'admin.audit_trail': {
        'summary': 'Append-only trail of state-changing calls',
        'description': 'Filter by entity_type/entity_id/action/user_id. There is no update or delete '
                       'route for trail rows by design.',
        'query': {'entity_type': 'string', 'entity_id': 'integer', 'action': 'string',
                  'user_id': 'integer', 'limit': 'integer (max 500)'},
    },
    'admin.audit_trail_stats': {'summary': 'Trail volume by action, for spotting activity patterns'},
}

_PATH_PARAM_RE = re.compile(r'<(?:(?:int|float|path|string|uuid):)?([A-Za-z_][A-Za-z_0-9]*)>')


def _path_to_openapi(rule_rule):
    """'/api/audits/<int:audit_id>/findings/<finding_id>' -> OpenAPI templated path."""
    return _PATH_PARAM_RE.sub(r'{\1}', rule_rule)


def _param_type(rule):
    """Map a werkzeug converter to a JSON Schema type, so a generated spec is
    actually usable by a code generator instead of all-strings."""
    name = type(rule).__name__.lower()
    if 'int' in name:
        return {'type': 'integer'}
    if 'float' in name:
        return {'type': 'number'}
    return {'type': 'string'}


def build_spec(app, as_yaml=False):
    """Assemble the spec from app.url_map + rbac role markers + OPERATION_NOTES."""
    paths = {}
    for rule in app.url_map.iter_rules():
        if rule.endpoint == 'static':
            continue
        methods = sorted(m for m in (rule.methods or set()) if m not in ('HEAD', 'OPTIONS'))
        if not methods:
            continue
        openapi_path = _path_to_openapi(rule.rule)
        entry = paths.setdefault(openapi_path, {})
        view = app.view_functions.get(rule.endpoint)
        notes = OPERATION_NOTES.get(rule.endpoint, {})
        roles = getattr(view, '__audinexia_roles__', None) if view else None

        for method in methods:
            operation = {
                'summary': notes.get('summary') or rule.endpoint.replace('.', ' ').replace('_', ' '),
                'description': notes.get('description') or '',
                'operationId': f'{rule.endpoint}_{method.lower()}',
                'tags': [rule.endpoint.split('.')[0]],
                'responses': _responses_for(notes, method, openapi_path),
            }
            if not operation['description']:
                operation.pop('description')

            parameters = [{'name': name, 'in': 'path', 'required': True,
                            'schema': _param_type(r)}
                           for r in [rule]
                           for name in _PATH_PARAM_RE.findall(r.rule)]
            for name in rule.arguments:
                if any(p['name'] == name for p in parameters):
                    continue
                parameters.append({'name': name, 'in': 'path', 'required': True,
                                   'schema': {'type': 'string'}})
            for name, description in (notes.get('query') or {}).items():
                parameters.append({'name': name, 'in': 'query', 'required': False,
                                   'description': description, 'schema': {'type': 'string'}})
            if parameters:
                operation['parameters'] = parameters

            if method == 'GET' or method == 'DELETE':
                operation['x-rate-limited'] = False
            if notes.get('body') and method in ('POST', 'PATCH', 'PUT'):
                content_key = 'multipart/form-data' if 'binary' in ' '.join(notes['body'].values()) \
                    else 'application/json'
                operation['requestBody'] = {
                    'required': method == 'POST',
                    'content': {content_key: {'schema': {
                        'type': 'object',
                        'properties': {k: {'type': 'string', 'description': v}
                                       if not isinstance(v, dict) else v
                                       for k, v in notes['body'].items()},
                    }}},
                }
            if roles is None:
                operation['security'] = []
                operation['x-authentication'] = 'none'
            else:
                operation['security'] = [{'bearerAuth': []}]
                operation['x-roles'] = list(roles)
            entry[method.lower()] = operation

    for path, operations in paths.items():
        for method, operation in operations.items():
            operation.setdefault('responses', {})
            for code, body in (('400', {'error': 'string'}), ('401', {'error': 'string'}),
                               ('403', {'error': 'Forbidden: insufficient role'}),
                               ('404', {'error': 'Not found'}), ('429', {'error': 'string'})):
                operation['responses'].setdefault(code, {'description': _code_note(code)})
            operation['responses'].setdefault('500', {'description': _code_note('500')})

    spec = {
        'openapi': OPENAPI_VERSION,
        'info': {
            'title': app.config.get('API_TITLE', 'Audinexia GRC Platform API'),
            'version': app.config.get('APP_VERSION', '1.0.0'),
            'description': DESCRIPTION,
            'contact': {'name': 'Audinexia', 'url': 'https://github.com/lalitbist641/'
                                                   'AUDINEXIA-GRC-Compliance-Automation-Platform'},
            'license': {'name': 'Proprietary'},
        },
        'servers': [{'url': '/', 'description': 'Same origin as the served dashboard'}],
        'security': [{'bearerAuth': []}],
        'tags': [
            {'name': 'auth', 'description': 'Sessions, tokens, password policy'},
            {'name': 'scan', 'description': 'Document ingestion, scoring, report and remediation export'},
            {'name': 'assessment', 'description': 'Stored assessment history'},
            {'name': 'review', 'description': 'Reviewer confirm/override, evidence files, remediation tracking'},
            {'name': 'crosswalk', 'description': 'Verified cross-framework projection'},
            {'name': 'risk', 'description': 'Risk register with 5x5 scoring and control linkage'},
            {'name': 'audit', 'description': 'Audit engagements and findings'},
            {'name': 'vendor', 'description': 'Third-party / vendor risk management'},
            {'name': 'maturity', 'description': 'Staged compliance maturity with evidence-gated levels'},
            {'name': 'monitoring', 'description': 'Re-verification scheduling and score drift'},
            {'name': 'admin', 'description': 'Users, organization settings, audit trail'},
        ],
        'paths': {k: paths[k] for k in sorted(paths)},
        'components': {
            'securitySchemes': {
                'bearerAuth': {'type': 'http', 'scheme': 'bearer', 'bearerFormat': 'JWT'},
            },
            'schemas': _schemas(),
        },
    }

    if as_yaml:
        try:
            import yaml
        except ImportError as exc:                       # pragma: no cover
            # A clear, actionable failure beats a 500 with a stack trace. The
            # dependency is pinned in requirements.txt, so this only fires in a
            # hand-built environment.
            raise RuntimeError(
                'PyYAML is required to render the specification as YAML; '
                'use /api/openapi.json or `pip install PyYAML`.'
            ) from exc
        return yaml.safe_dump(spec, sort_keys=False, width=100)
    return spec


def _code_note(code):
    return {
        '400': 'Invalid input (validation message in `error`)',
        '401': 'Missing, expired or revoked token',
        '403': 'Authenticated but insufficient role for this operation',
        '404': 'Not found in your organization — a resource belonging to another tenant also '
               'returns 404, deliberately, so existence is not leaked',
        '429': 'Rate limited or login-throttled; see Retry-After',
        '500': 'Internal error; `request_id` correlates with the server log',
    }.get(code, 'Error')


def _responses_for(notes, method, openapi_path):
    responses = {}
    if notes.get('raw'):
        responses['200'] = {'description': 'File download',
                            'content': {notes['raw']: {'schema': {'type': 'string', 'format': 'binary'}}}}
    elif notes.get('response'):
        responses['200'] = {'description': 'Success',
                            'content': {'application/json': {'schema': {
                                'type': 'object',
                                'properties': {k: {'type': 'string', 'description': v}
                                               for k, v in notes['response'].items()}}}}}
    else:
        responses['200'] = {'description': 'Success'}
    if method in ('GET', 'POST') and not notes.get('response') and not notes.get('raw'):
        responses['200'] = {'description': 'Success'}
    return responses


def _schemas():
    """Hand-written shapes for the objects clients actually consume. Kept
    minimal and accurate rather than exhaustive — every field described here
    exists in the corresponding to_dict()."""
    def obj(properties, required=()):
        return {
            'type': 'object',
            'properties': {k: (v if isinstance(v, dict) else {'type': 'string', 'description': v})
                           for k, v in properties.items()},
            'required': list(required),
        }

    return {
        'Organization': obj({'id': 'integer', 'name': 'string'}),
        'User': obj({
            'id': 'integer', 'org_id': 'integer', 'email': 'string', 'name': 'string',
            'role': 'org_admin | compliance_manager | auditor | member | read_only',
            'is_active': 'boolean', 'must_change_password': 'boolean',
            'last_login_at': 'ISO-8601 or null',
        }),
        'ControlResult': obj({
            'id': 'framework control id (e.g. DPDPA-1)',
            'control_result_id': 'integer — persisted row id; review endpoints key on this',
            'name': 'string', 'clause': 'string', 'owner': 'string',
            'severity': 'critical | major | minor', 'weight': 'number',
            'score': '0-100, matched required phrases / total x 100',
            'status': 'Compliant (>=80) | Partially Compliant (50-79) | Non-Compliant (<50)',
            'risk_level': 'Low | Medium | High', 'found_phrases': 'string[]',
            'missing_phrases': 'string[]', 'evidence': 'source sentence supporting the match',
            'fix_suggestion': 'string', 'reviewer_status': 'unreviewed | confirmed | overridden',
            'remediation_status': 'open | in_progress | closed | null',
        }),
        'AssessmentSummary': obj({
            'id': 'integer', 'framework': 'string', 'filename': 'string',
            'overall_score': 'weighted percentage 0-100', 'compliant_count': 'integer',
            'partial_count': 'integer', 'non_compliant_count': 'integer',
            'report_id': 'AUD-YYYYMMDD-HHMMSS', 'created_at': 'ISO-8601',
            'created_by': 'string', 'vendor_id': 'integer or null',
            'source': 'manual | monitoring | vendor_portal',
            'parent_assessment_id': 'integer or null — set for a monitoring re-scan',
            'framework_definition_drift': 'boolean — true when the framework moved under this score',
        }),
        'Vendor': obj({
            'id': 'integer', 'name': 'string', 'service_description': 'string',
            'data_sensitivity': 'public | internal | confidential | personal_data | health_data | '
                                'cardholder_data | restricted',
            'status': 'onboarding | active | under_review | suspended | offboarded',
            'review_frequency_days': 'integer', 'latest_overall_score': 'number or null',
            'risk_tier': 'unassessed | low | medium | high | critical',
            'open_gap_count': 'integer', 'last_reviewed_at': 'ISO-8601 or null',
        }),
        'VendorRegisterEntry': obj({
            'name': 'string', 'coverage_percent': 'number or null',
            'risk_tier': 'string', 'risk_score': '0-100 (higher is worse)',
            'open_gap_count': 'integer', 'critical_gap_count': 'integer',
            'review_overdue_days': 'integer or null', 'reasons': 'string[] — why the tier is what it is',
            'assurance_note': 'string — what this score does NOT establish',
        }),
        'PolicyWatch': obj({
            'id': 'integer', 'name': 'string', 'filename': 'string', 'framework': 'string',
            'review_interval_days': 'integer', 'drift_threshold_points': 'number',
            'next_due_at': 'ISO-8601', 'last_state': 'initial | stable | drift_up | drift_down | '
                                                    'control_flip | framework_updated | no_new_version | error',
            'freshness': '{status: current|due_soon|overdue|unscheduled, label, days_from_due}',
        }),
        'MaturityEvaluation': obj({
            'derived_level': '1-5, awarded only when every gate below it passes',
            'derived_level_label': 'Initial | Managed | Defined | Quantitatively Managed | Optimizing',
            'derived_score': '0-100 composite (trend indicator, never the basis of a level)',
            'levels': 'per-level gate list with met/value/threshold/detail',
            'blockers': 'the specific unmet gates blocking the next level',
            'claimed_level': 'integer or null — the organization\'s own assertion',
            'claim_overstates': 'boolean — true when the claim exceeds what the records support',
            'limitation': 'string — this is not an ISO/IEC 33000 appraisal',
        }),
        'AuditTrailEvent': obj({
            'id': 'integer', 'action': 'e.g. scan.create, vendor.assess, review.override',
            'entity_type': 'string', 'entity_id': 'integer', 'summary': 'human-readable one-liner',
            'actor': 'string', 'actor_role': 'string', 'request_id': 'string',
            'created_at': 'ISO-8601 UTC',
        }),
    }
