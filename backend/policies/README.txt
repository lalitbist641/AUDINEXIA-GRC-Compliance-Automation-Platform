========================================
AUDINEXIA - POLICY TESTING GUIDE
========================================

📁 FOLDER STRUCTURE:
-------------------
policies/
├── compliant/
│   ├── Fully_Compliant_Policy.txt (DPDPA)
│   └── ISO27001_Compliant_Policy.txt (ISO 27001)
├── partial/
│   └── Partially_Compliant_Policy.txt
└── non_compliant/
    └── Non_Compliant_Policy.txt

========================================
HOW TO DEMONSTRATE TO YOUR TEACHER
========================================

1. START THE SERVER:
   cd backend
   python app.py

2. OPEN DASHBOARD:
   http://127.0.0.1:5001/dashboard

3. TEST COMPLIANT POLICY (✓):
   - Select DPDPA 2023 framework
   - Upload: policies\compliant\Fully_Compliant_Policy.txt
   - Expected: High score (75-100%), mostly Compliant status

4. TEST PARTIALLY COMPLIANT POLICY (⚠):
   - Select DPDPA 2023 framework
   - Upload: policies\partial\Partially_Compliant_Policy.txt
   - Expected: Medium score (40-74%), Mixed status

5. TEST NON-COMPLIANT POLICY (✗):
   - Select DPDPA 2023 framework
   - Upload: policies\non_compliant\Non_Compliant_Policy.txt
   - Expected: Low score (0-39%), Non-Compliant status

6. TEST ISO 27001:
   - Select ISO 27001:2022 framework
   - Upload: policies\compliant\ISO27001_Compliant_Policy.txt
   - Expected: High compliance score

========================================
EXPECTED RESULTS:
========================================

Policy Type              | Expected Score | Expected Status
------------------------|----------------|------------------
Fully Compliant         | 85-100%        | ✓ Compliant
Partially Compliant     | 40-70%         | ⚠ Partially Compliant
Non-Compliant           | 0-30%          | ✗ Non-Compliant

========================================
