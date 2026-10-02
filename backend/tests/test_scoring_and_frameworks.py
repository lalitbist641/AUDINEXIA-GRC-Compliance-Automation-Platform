"""Scoring, framework definitions and text extraction.

These are the tests that protect the *numbers* the product publishes. Every
other suite can tolerate a wording change; none of them can tolerate a silent
change in how a score is computed, because the entire claim of the tool is that
a score is reproducible from the document alone.
"""

import io

import pytest

from scanning import (FRAMEWORKS, MIN_VALID_EXTRACTED_TEXT_LENGTH, allowed_file,
                      analyze_control, calculate_weighted_score, extract_text,
                      framework_content_hash, is_valid_extracted_text, text_hash)

EXPECTED_CONTROL_COUNTS = {
    'dpdpa': 12,
    'iso27001': 9,
    'gdpr': 8,
    'pcidss': 6,
    'hipaa': 6,
    'nistcsf': 14,
}

# Full sha256 over each framework's scoring-relevant definition, recorded when
# Phase 8 froze `_canonical_control`. They are regression anchors: editing a
# control or a synonym changes the digest, which is exactly the signal the
# "framework_updated" monitoring state reports to users — so the change has to
# be a deliberate one, made together with these constants.
#
# Re-anchored for Phase 0 (honest scanner): the synonym table was cleaned (four
# silently-shadowed duplicate keys merged, overly generic words such as "report"
# and "keep" removed) and matching became whole-word + negation-aware
# (MATCHER_VERSION 2). Both change what a policy must say to score, so every
# prior assessment is correctly flagged as scored against a superseded framework.
KNOWN_FRAMEWORK_HASHES = {
    'dpdpa': '157887db0aea243c175f482cd3f5b1fdd352780368fda735493f5efcc5d4be23',
    'gdpr': '86f0eba2f34f6d984f39ff945a127fc02ffea9dcda89bae8c3303156daf3f50d',
    'hipaa': 'ba4c9423085b338d9e458b45912b3eab64a0ac92b702e9b27d34ec8505da5c4b',
    'iso27001': '26392804ebb439e0af0d3c42eadd15deb41418dc09bf0a890967f9dbdc834290',
    'nistcsf': '186b86410b37ee46be6f3ac0b3d41d96c333effa8da48a8b0d06f318f57ad335',
    'pcidss': '28ea5aa440cce7530eaf3ae2365d24dfbc196237fec39fdddefc2a4219a6816f',
}


def overall_verdict(score):
    """The 3-band label the report publishes for an overall score."""
    if score >= 80:
        return 'Language found'
    if score >= 50:
        return 'Partially found'
    return 'Not found'


def synthetic_control(required, weight=1, severity='major', control_id='X-1'):
    """A control-shaped dict with no framework coupling, for tests that need a
    specific score rather than a specific framework's opinion."""
    return {'id': control_id, 'name': 'Synthetic Control', 'clause': 'Section 0',
            'owner': 'Testing', 'severity': severity, 'weight': weight,
            'why_matters': 'Because the test says so.',
            'remediation_example': 'State the commitment explicitly.',
            'required_text': list(required)}


# ── Framework definitions ───────────────────────────────────────────────────

@pytest.mark.parametrize('framework', sorted(FRAMEWORKS))
def test_framework_definition_is_self_consistent(framework):
    spec = FRAMEWORKS[framework]
    assert spec['name'] and spec['icon'] and spec['color']
    controls = spec['controls']
    assert len(controls) == EXPECTED_CONTROL_COUNTS[framework]
    ids = [c['id'] for c in controls]
    assert len(set(ids)) == len(ids), f'duplicate control id in {framework}'

    for control in controls:
        assert control['name'] and control['clause'] and control['owner']
        assert control['why_matters'], f'{control["id"]} has no rationale to show a reviewer'
        assert control['remediation_example'], f'{control["id"]} has no suggested wording'
        assert control['severity'] in ('critical', 'major')
        # A control with no required text would score 100% for any document,
        # including an empty one, so the requirement is structural.
        assert control['required_text'], f'{control["id"]} has no required_text'
        assert all(phrase.strip() for phrase in control['required_text'])
        assert control['required_text'] == list(dict.fromkeys(control['required_text'])), \
            f'{control["id"]} repeats a required phrase, which would deflate its score'
        assert 1 <= control['weight'] <= 10


def test_framework_hash_matches_recorded_anchors():
    actual = {key: framework_content_hash(key) for key in sorted(FRAMEWORKS)}
    assert actual == KNOWN_FRAMEWORK_HASHES


def test_framework_hash_is_deterministic_and_framework_specific():
    assert framework_content_hash('dpdpa') == framework_content_hash('dpdpa')
    hashes = {framework_content_hash(key) for key in FRAMEWORKS}
    assert len(hashes) == len(FRAMEWORKS), 'two frameworks hash identically'


def test_presentation_only_fields_do_not_change_the_hash(monkeypatch):
    """icon/color/currency are UI decoration. If they fed the digest, restyling
    the dashboard would mark every historical assessment as scored against a
    superseded framework."""
    before = framework_content_hash('dpdpa')
    monkeypatch.setitem(FRAMEWORKS['dpdpa'], 'icon', '🏛️')
    monkeypatch.setitem(FRAMEWORKS['dpdpa'], 'color', '#123456')
    assert framework_content_hash('dpdpa') == before


def test_weight_change_does_change_the_hash(monkeypatch):
    """The counterpart of the test above: weight is part of the yardstick."""
    before = framework_content_hash('dpdpa')
    original = FRAMEWORKS['dpdpa']['controls'][0]['weight']
    monkeypatch.setitem(FRAMEWORKS['dpdpa']['controls'][0], 'weight', original + 1)
    assert framework_content_hash('dpdpa') != before


# ── Scoring arithmetic ──────────────────────────────────────────────────────

def test_perfect_document_scores_100():
    control = FRAMEWORKS['dpdpa']['controls'][0]
    result = analyze_control('. '.join(control['required_text']), control)
    assert result['score'] == 100.0
    assert result['status'] == 'Language found'
    assert result['missing_phrases'] == []
    assert result['evidence'], 'a matched control must cite the sentence it matched on'


def test_empty_document_scores_zero_and_is_critical():
    result = analyze_control('', FRAMEWORKS['dpdpa']['controls'][0])
    assert result['score'] == 0.0
    assert result['status'] == 'Not found'
    assert result['risk_level'] == 'Critical'
    assert result['remediation_window'] == '0-7 days'
    assert result['evidence'] == ''


@pytest.mark.parametrize('found,total,expected', [
    (1, 4, 25.0), (2, 4, 50.0), (3, 4, 75.0), (4, 4, 100.0), (0, 4, 0.0),
])
def test_raw_score_is_matched_over_required(found, total, expected):
    """The score is coverage of stated requirements and nothing else: no keyword
    weighting, no TF-IDF, no proximity scoring. Boring on purpose — a number an
    auditor can recompute by hand from the document and the control list."""
    phrases = [f'unique alpha token {i}' for i in range(total)]
    control = synthetic_control(phrases)
    document = '. '.join(phrases[:found])
    assert analyze_control(document, control)['score'] == expected


@pytest.mark.parametrize('matched,expected_score,expected_status', [
    (4, 40.0, 'Not found'),
    (5, 50.0, 'Partially found'),
    (7, 70.0, 'Partially found'),
    (8, 80.0, 'Language found'),
])
def test_band_boundaries_are_inclusive_at_the_bottom(matched, expected_score, expected_status):
    """10 phrases makes the boundary values (50.0, 80.0) exactly reachable, so
    the `>=` comparisons are pinned rather than assumed."""
    control = synthetic_control([f'bravo phrase {i}' for i in range(10)])
    result = analyze_control('. '.join(f'bravo phrase {i}' for i in range(matched)), control)
    assert (result['score'], result['status']) == (expected_score, expected_status)


def test_weighted_overall_score_is_weighted_not_averaged():
    """Low-weight controls must not drag a report the way a plain mean would:
    100 on a weight-1 control and 0 on a weight-4 control is 20.0, not 50.0."""
    assert calculate_weighted_score([{'score': 100.0, 'weight': 1},
                                     {'score': 0.0, 'weight': 4}]) == 20.0
    assert calculate_weighted_score([]) == 0.0
    assert calculate_weighted_score([{'score': 73.4, 'weight': 7}]) == 73.4


def test_matching_is_case_insensitive_and_survives_reflow():
    """Word wrap is a property of how a PDF was laid out, not of whether the
    commitment exists. A scanner that missed a phrase because a newline landed
    mid-sentence would raise findings that vanish when the file is re-saved."""
    control = synthetic_control(['explicit consent mechanism'])
    assert analyze_control('WE OBTAIN EXPLICIT CONSENT MECHANISM HERE', control)['score'] == 100.0
    assert analyze_control('we obtain explicit\n   consent\n  mechanism here', control)['score'] == 100.0


def test_matching_is_whole_word():
    """The old matcher was `syn in text`, so a phrase inside a longer word counted
    ("nonaccess control" satisfied "access control"; a short acronym matched
    inside unrelated words). Matching is now word-bounded -- the limitation this
    test used to pin is fixed."""
    control = synthetic_control(['access control'])
    assert analyze_control('we maintain access control lists', control)['score'] == 100.0
    assert analyze_control('the nonaccess control policy applies', control)['score'] == 0.0
    assert analyze_control('accesscontrol is configured', control)['score'] == 0.0


@pytest.mark.parametrize('text,expected', [
    # Negated in the same sentence: must NOT count as evidence.
    ('We do not encrypt data at rest.', 0.0),
    ('Our systems lack proper encryption controls.', 0.0),
    ('Encryption is never applied to backups.', 100.0),  # negator AFTER the phrase
    ('There is no encryption of stored records.', 0.0),
    # Positive statements still count.
    ('All data is protected using encryption.', 100.0),
    # A negation in a PREVIOUS sentence must not suppress a separate, real one.
    ('We previously did not have it. As of this year we use encryption everywhere.', 100.0),
    # A document may describe both; one genuine non-negated mention is enough.
    ('We do not encrypt legacy exports. All production data uses encryption.', 100.0),
])
def test_negated_language_is_not_evidence(text, expected):
    """"We do not encrypt data" contains the word "encrypt" but is the opposite
    of a commitment to encryption; counting it would turn a stated gap into a
    reported strength. Interim heuristic (a negator earlier in the same
    sentence), pinned including its known blind spot: a negator AFTER the
    phrase is not detected."""
    control = synthetic_control(['encryption'])
    assert analyze_control(text, control)['score'] == expected


def test_status_labels_describe_coverage_not_compliance():
    """The scanner counts required phrases; it never judges whether a control is
    effective or true, so its labels must not claim compliance."""
    from scanning import score_control_result

    control = synthetic_control(['a', 'b'])
    statuses = {score_control_result(control, s, [], [], '')['status'] for s in (100.0, 60.0, 10.0)}
    assert statuses == {'Language found', 'Partially found', 'Not found'}
    assert not any('ompliant' in s for s in statuses)


def test_synonyms_are_accepted_for_a_required_phrase():
    """`PHRASE_SYNONYMS` is what stops "reasonable security measures" scoring 0%
    merely for not using the exact statutory wording."""
    control = synthetic_control(['encryption'])
    assert analyze_control('all data is protected using AES-256 cryptographic controls '
                           'and encryption of stored records', control)['score'] == 100.0


def test_control_evidence_is_a_real_sentence_from_the_document():
    sentence = ('Section 4. We obtain explicit consent from each data principal before '
                'processing personal data and record it.')
    result = analyze_control(sentence, synthetic_control(['explicit consent']))
    assert 'explicit consent' in result['evidence'].lower()
    assert len(result['evidence']) <= 200


# ── Risk labeling (report §7) ───────────────────────────────────────────────

def test_risk_tiers_follow_the_engine_not_the_status_label():
    """A 55%-documented control is "Partially found" AND "Medium" risk. The
    two vocabularies answer different questions and must not be collapsed into
    one another."""
    from core.risk_engine import RiskEngine

    assert RiskEngine.calculate_risk(0)['level'] == 'Critical'
    assert RiskEngine.calculate_risk(29.9)['level'] == 'Critical'
    assert RiskEngine.calculate_risk(30)['level'] == 'High'
    assert RiskEngine.calculate_risk(49.9)['level'] == 'High'
    assert RiskEngine.calculate_risk(50)['level'] == 'Medium'
    assert RiskEngine.calculate_risk(69.9)['level'] == 'Medium'
    assert RiskEngine.calculate_risk(70)['level'] == 'Low'
    with pytest.raises(ValueError):
        RiskEngine.calculate_risk(150)      # out-of-band input must not pass silently


def test_every_tier_carries_narrative_for_any_missing_phrase():
    """The retired orphan module only had scenario text for 8 DPDPA controls;
    generation is keyed by phrase, so all 55 controls get a real sentence."""
    from core.risk_engine import RiskEngine

    for framework, spec in FRAMEWORKS.items():
        for control in spec['controls']:
            context = RiskEngine.risk_context(10, missing_phrases=control['required_text'],
                                              control_id=control['id'],
                                              control_name=control['name'])
            for key in ('business_impact', 'attack_scenario', 'remediation_priority'):
                assert isinstance(context[key], str) and len(context[key]) > 30, \
                    f'{control["id"]} has no {key}'
            for key in ('attack_likelihood', 'risk_level', 'risk_color', 'remediation_window'):
                assert isinstance(context[key], str) and context[key], \
                    f'{control["id"]} has no {key}'


# ── Validation corpus and helpers ───────────────────────────────────────────

@pytest.mark.parametrize('fixture_name,framework,low,high,expected_verdict', [
    ('compliant/Fully_Compliant_Policy.txt', 'dpdpa', 95, 100, 'Language found'),
    ('compliant/ISO27001_Compliant_Policy.txt', 'iso27001', 95, 100, 'Language found'),
    ('partial/Partially_Compliant_Policy.txt', 'dpdpa', 60, 95, 'Compliant or Partially Compliant'),
    ('non_compliant/Non_Compliant_Policy.txt', 'dpdpa', 0, 49.9, 'Not found'),
])
def test_bundled_validation_fixtures_stay_in_their_documented_band(
        fixture_name, framework, low, high, expected_verdict, policy_dir):
    """`backend/policies/` is the validation set the project report cites for
    accuracy claims, so the band each fixture must land in is pinned here.

    Two honest caveats, both of which are product properties rather than test
    weaknesses:
      * the non-compliant fixture measures in the forties, not near zero, because
        matching is substring coverage of generic words ("purpose", "review")
        that even a bad policy uses. The useful invariant is that it stays under
        the 50.0 Non-Compliant cut.
      * the bands were re-measured in Phase 9 after two fixes: whitespace-tolerant
        phrase matching, and adding the backup/incident-response sections that the
        ISO fixture was missing (it scored 77.3 while being named "Language found").
    """
    text = (policy_dir / fixture_name).read_text(encoding='utf-8', errors='replace')
    results = [analyze_control(text, control) for control in FRAMEWORKS[framework]['controls']]
    score = calculate_weighted_score(results)
    assert low <= score <= high, f'{fixture_name} scored {score}, outside [{low}, {high}]'
    if expected_verdict in ('Language found', 'Not found'):
        assert overall_verdict(score) == expected_verdict, \
            f'{fixture_name} scored {score} and reads as {overall_verdict(score)}'
    else:
        assert score >= 50.0, f'{fixture_name} fell below the Compliant/Partial cut'


def test_text_hash_ignores_whitespace_only_differences():
    assert text_hash('a  b\nc') == text_hash('a b c')
    assert text_hash('A B') == text_hash('a b')
    assert text_hash('a b c') != text_hash('a b d')


def test_extracted_text_guard_rejects_error_sentinels(tmp_path):
    """`extract_text` returns an error *string* rather than raising, so a caller
    that forgot to check would score the error message as if it were the
    document. That bug was real (pdfplumber missing from requirements while PDF
    support was advertised); the guard is what keeps it from coming back."""
    assert is_valid_extracted_text('Unsupported file format.') is False
    assert is_valid_extracted_text('Error reading PDF: nope') is False
    assert is_valid_extracted_text('PDF support not available. Install pdfplumber') is False
    assert is_valid_extracted_text('too short to be a real policy document') is False
    assert is_valid_extracted_text('x' * (MIN_VALID_EXTRACTED_TEXT_LENGTH + 1)) is True

    (tmp_path / 'policy.xyz').write_text('content here')
    assert extract_text(str(tmp_path / 'policy.xyz')) == 'Unsupported file format.'
    assert allowed_file('policy.pdf') is True
    assert allowed_file('policy.exe') is False
    assert allowed_file('noextension') is False


def test_extraction_backends_are_available():
    """A missing optional dependency silently degrades every PDF scan; failing
    loudly at test time is cheaper than shipping a broken format."""
    from scanning import DOCX_SUPPORT, PDF_SUPPORT

    assert PDF_SUPPORT, 'pdfplumber is not importable — PDF scans would degrade'
    assert DOCX_SUPPORT, 'python-docx is not importable — DOCX scans would degrade'


def test_docx_round_trip(tmp_path):
    docx = pytest.importorskip('docx')
    text = 'We obtain explicit consent from the data principal before processing personal data.'
    document = docx.Document()
    document.add_paragraph(text)
    path = tmp_path / 'policy.docx'
    document.save(str(path))
    extracted = extract_text(str(path))
    assert text in extracted
    assert is_valid_extracted_text(extracted) is True


# ── API surface of the scanner ──────────────────────────────────────────────

def test_scan_endpoint_reports_its_methodology(client, auth, policy_dir):
    """A published score must state how it was produced; methodology with no
    method attached is the thing auditors reject first."""
    payload = {'file': (io.BytesIO((policy_dir / 'compliant/Fully_Compliant_Policy.txt')
                                   .read_bytes()), 'Fully_Compliant_Policy.txt'),
               'framework': 'dpdpa'}
    result = client.post('/api/scan', data=payload, headers=auth,
                         content_type='multipart/form-data')
    assert result.status_code == 200
    body = result.get_json()
    assert 'sum(weight' in body['methodology']['overall']
    assert 'not implemented controls' in body['methodology']['matching']
    assert body['assessment_id'] and body['report_id']
    assert len(body['controls']) == EXPECTED_CONTROL_COUNTS['dpdpa']


def test_scan_control_payload_carries_risk_narrative(client, auth, policy_dir):
    """Report §6.5 promises business impact, an exposure pattern and a
    remediation window per control; the API must actually emit them."""
    payload = {'file': (io.BytesIO((policy_dir / 'non_compliant/Non_Compliant_Policy.txt')
                                   .read_bytes()), 'Non_Compliant_Policy.txt'),
               'framework': 'dpdpa'}
    result = client.post('/api/scan', data=payload, headers=auth,
                         content_type='multipart/form-data')
    worst = min(result.get_json()['controls'], key=lambda c: c['score'])
    assert worst['business_impact']
    assert worst['attack_scenario']
    assert worst['remediation_window'].endswith('days')
    assert worst['risk_priority'] in ('Immediate', 'High', 'Medium', 'Low')


def test_scan_rejects_unsupported_extension(client, auth):
    result = client.post('/api/scan', data={
        'file': (io.BytesIO(b'policy text'), 'policy.exe'), 'framework': 'dpdpa',
    }, headers=auth, content_type='multipart/form-data')
    assert result.status_code == 400


def test_scan_rejects_unknown_framework(client, auth, policy_dir):
    result = client.post('/api/scan', data={
        'file': (io.BytesIO((policy_dir / 'compliant/Fully_Compliant_Policy.txt').read_bytes()),
                 'policy.txt'),
        'framework': 'soc2',
    }, headers=auth, content_type='multipart/form-data')
    assert result.status_code == 400
    assert 'soc2' in result.get_json()['error']
