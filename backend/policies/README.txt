AUDINEXIA - REFERENCE POLICY SET
=================================

These documents are the project's validation corpus: the samples the scanner is
judged against, the fixtures /api/scan/sample serves, and the input to
backend/tests/test_scoring_and_frameworks.py. They are deliberately synthetic.

STRUCTURE
---------
policies/
├── compliant/
│   ├── Fully_Compliant_Policy.txt         DPDPA 2023, scores 100.0
│   └── ISO27001_Compliant_Policy.txt      ISO 27001:2022, scores 100.0
├── partial/
│   └── Partially_Compliant_Policy.txt     DPDPA 2023, scores 86.1
├── non_compliant/
│   └── Non_Compliant_Policy.txt           DPDPA 2023, scores 45.5
└── Comprehensive_Multi_Framework_Policy.txt
        One document written to satisfy as many frameworks as possible;
        dpdpa 93.1 / iso27001 100.0 / gdpr 75.6 / pcidss 80.7 / hipaa 68.2 /
        nistcsf 65.6.

HOW TO USE THEM
---------------
1. Start the server:  cd backend && flask --app app.py run --port 5001
2. Open the dashboard and pick a framework.
3. Upload the matching file above (or POST /api/scan/sample with
   {"filename": "Partially_Compliant_Policy.txt", "framework": "dpdpa"}).

WHAT THE SCORES MEAN — AND WHAT THEY DO NOT
-------------------------------------------
The scanner scores *document coverage*: how many of a control's required
statements appear in the text. Two consequences to keep in mind when using these
files as a demo or as a test oracle:

* A score is not an assessment of implemented controls. A policy that says the
  right things scores well whether or not the organization does them.
* Matching is substring coverage of short required phrases, so generic words
  ("purpose", "review", "training") count even in a weak document. That is why
  Non_Compliant_Policy.txt measures 45.5 rather than near zero: it is still
  below the 50.0 Non-Compliant cut, which is the property that matters, and
  pytest asserts exactly that. Do not present the 45.5 as "45% compliant".

Scores move when a framework definition changes. The definitions are hashed
(scanning.framework_content_hash, pinned in the test suite) so a re-scan after
such a change is reported as a framework update rather than as policy drift.

If you edit a file here, re-run:  cd backend && python -m pytest tests -q
The framework/fixture bands in test_scoring_and_frameworks.py are the contract.
