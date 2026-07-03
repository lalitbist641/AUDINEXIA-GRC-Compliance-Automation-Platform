"""Compliance scanning engine: framework/control definitions, phrase matching,
scoring, and document text extraction. Moved verbatim out of app.py (Phase 1
package split) except for the analyze_control()/score_control_result() split
noted below."""
import re

from config import Config

try:
    import pdfplumber
    PDF_SUPPORT = True
except ImportError:
    PDF_SUPPORT = False

try:
    from docx import Document as DocxDocument
    DOCX_SUPPORT = True
except ImportError:
    DOCX_SUPPORT = False

PHRASE_SYNONYMS = {
    # CONSENT
    "explicit consent": [
        "explicit consent", "informed consent", "opt-in", "clear affirmative action",
        "explicit permission", "valid consent", "free consent", "specific consent",
        "unambiguous consent", "consent is obtained", "consent obtained", "obtain consent",
        "obtaining consent", "consent before", "prior consent", "user consent",
        "double opt-in", "affirmative consent"
    ],
    "withdrawal mechanism": [
        "withdraw consent", "revoke consent", "opt-out", "unsubscribe", "withdrawal",
        "withdraw", "revoke", "consent withdrawal", "right to withdraw",
        "withdraw at any time", "unsubscribe at any time", "account settings"
    ],
    "informed consent": [
        "informed", "explain", "disclose", "transparent", "aware", "notice",
        "informed consent", "transparency", "disclosed", "awareness", "notice is provided",
        "clear and accessible notice", "accessible notice"
    ],
    "record of consent": [
        "record consent", "log consent", "timestamp", "audit trail", "consent log",
        "record of consent", "consent records", "records are maintained",
        "documented", "records", "audit records", "retention"
    ],

    # NOTICE & PURPOSE
    "privacy notice": [
        "privacy notice", "privacy policy", "notice", "disclosure", "transparency notice",
        "clear and accessible notice", "clear notice", "notice includes", "notice provided"
    ],
    "purpose": [
        "purpose", "reason", "intended use", "objective", "goal", "why we collect",
        "specified purpose", "explicit purpose", "legitimate purpose", "purpose of processing",
        "specified, explicit", "categories of data"
    ],
    "retention period": [
        "retention", "how long", "keep", "store", "retain", "period", "duration",
        "retained for", "retention period", "years", "months", "6 years", "12 months",
        "storage", "stored for", "data retention"
    ],
    "data principal rights": [
        "rights", "access", "correction", "erasure", "delete", "object", "portability",
        "grievance", "right to access", "right to correction", "right to erasure",
        "data subjects have the right", "data principals have the right",
        "data subject rights", "right to be forgotten"
    ],
    "deletion after purpose": [
        "delete after", "erase when", "remove when", "no longer needed", "destroy", "purge",
        "deletion", "securely deleted", "deleted", "erased", "no longer necessary",
        "after last interaction", "upon request", "without undue delay"
    ],
    "storage limitation": [
        "storage limit", "not store longer", "retention limit", "time limit",
        "storage limitation", "limited to", "retain only", "minimum necessary",
        "data minimization", "no longer than"
    ],

    # SECURITY
    "encryption": [
        "encryption", "encrypt", "aes", "tls", "ssl", "cryptographic", "cipher",
        "aes-256", "tls 1.3", "tls 1.2", "encrypted", "at rest", "in transit",
        "data at rest", "data in transit", "transmission security"
    ],
    "access control": [
        "access control", "authorization", "permission", "rbac", "role based",
        "least privilege", "role-based", "access rights", "user access",
        "principle of least privilege", "access policy", "access management"
    ],
    "mfa": [
        "mfa", "multi-factor", "two-factor", "2fa", "authenticator", "multifactor",
        "multi-factor authentication", "two-factor authentication",
        "multi-factor", "strong authentication"
    ],
    "breach response": [
        "breach response", "incident response", "data breach", "security incident", "compromise",
        "breach", "incident", "response plan", "incident response plan",
        "security incident response", "breach notification", "breach procedures"
    ],
    "notification": [
        "notify", "alert", "report", "inform", "72 hours", "within hours",
        "notification", "notified", "notification procedures", "within 72",
        "60 days", "without undue delay", "supervisory authority", "hhs"
    ],

    # CHILDREN'S DATA
    "parental consent": [
        "parental consent", "parent permission", "guardian consent", "legal guardian",
        "verifiable consent", "parental", "guardian", "parent"
    ],
    "age verification": [
        "age verification", "verify age", "confirm age", "age gate",
        "age verification", "minor", "minors", "children", "child"
    ],
    "verifiable consent": [
        "verifiable consent", "verified consent", "otp", "double opt-in",
        "verifiable", "verified", "parental consent via"
    ],

    # CROSS-BORDER
    "localization": [
        "india", "within india", "local storage", "domestic", "indian server",
        "data localization", "stored in india", "data stored in india"
    ],
    "safeguards": [
        "safeguards", "scc", "standard contractual clauses", "binding corporate rules",
        "adequacy decision", "appropriate safeguards", "transfer mechanism",
        "security safeguards", "reasonable security safeguards"
    ],

    # GDPR SPECIFIC
    "lawful basis": [
        "lawful basis", "legal basis", "consent", "contract", "legal obligation",
        "legitimate interest", "lawful", "legal basis for processing",
        "based on lawful basis", "lawful processing"
    ],
    "data subject rights": [
        "data subject rights", "access", "rectification", "erasure", "restrict",
        "portability", "object", "right to access", "right to erasure",
        "data subject", "data subjects have the right"
    ],
    "data protection officer": [
        "dpo", "data protection officer", "privacy officer",
        "data protection officer (dpo)", "dpo is appointed", "dpo appointed",
        "dpo contact"
    ],
    "security measures": [
        "security measures", "encryption", "pseudonymization", "confidentiality",
        "integrity", "availability", "appropriate technical", "organisational measures",
        "organizational measures", "technical and organizational"
    ],
    "purpose limitation": [
        "purpose limitation", "specified, explicit", "legitimate purposes",
        "not further processed", "collected for specified", "purpose of processing",
        "explicit, and legitimate"
    ],

    # HIPAA SPECIFIC
    "risk analysis": [
        "risk analysis", "risk assessment", "security assessment", "threat assessment",
        "formal risk assessment", "risk analysis is conducted", "threats and vulnerabilities",
        "annual risk"
    ],
    "risk management": [
        "risk management", "risk management policies", "reduce risks", "risk reduction",
        "mitigate risk", "risk treatment", "risk mitigation"
    ],
    "sanction policy": [
        "sanction policy", "sanctions", "disciplinary", "consequences", "enforcement",
        "corrective action", "workforce sanctions"
    ],
    "information system activity review": [
        "information system activity review", "activity review", "system activity",
        "log review", "audit review", "system monitoring", "logs are reviewed",
        "review logs", "reviewed weekly", "reviewed daily"
    ],
    "security reminders": [
        "security reminders", "reminders", "periodic reminders", "awareness training",
        "security awareness", "phishing awareness", "training includes", "malware protection"
    ],
    "malware protection": [
        "malware protection", "malware", "anti-malware", "antivirus", "anti-virus",
        "malware protection", "virus protection", "phishing"
    ],
    "response and reporting": [
        "response and reporting", "reporting", "reported immediately", "report",
        "incident reporting", "breach reporting", "response procedures"
    ],
    "unique user identification": [
        "unique user identification", "unique user id", "unique id", "unique user",
        "user identification", "unique identification", "individual user id"
    ],
    "emergency access": [
        "emergency access", "emergency procedures", "emergency access procedures",
        "break-glass", "emergency access to ephi"
    ],
    "automatic logoff": [
        "automatic logoff", "auto logoff", "session timeout", "logoff", "logout",
        "automatically log", "inactivity timeout", "idle timeout", "session expiry"
    ],
    "audit logs": [
        "audit logs", "activity review", "recording access", "log review",
        "audit records", "audit trail", "logs record", "access to ephi",
        "log all access", "all access to"
    ],
    "recording access": [
        "recording access", "record access", "logs record", "access logged",
        "audit logs record", "log all access", "all access is logged"
    ],
    "tls": [
        "tls", "tls 1.3", "tls 1.2", "ssl", "transport layer security",
        "encrypted using tls", "tls encryption"
    ],
    "secure transmission": [
        "secure transmission", "encrypted transmission", "encrypted over", "encryption",
        "tls", "transmitted over open networks", "secure channel", "in transit"
    ],

    # ISO 27001 SPECIFIC
    "information security policy": [
        "information security policy", "security policy", "policy approved",
        "policy reviewed", "isms policy", "established a comprehensive",
        "approved by executive management", "approved by management"
    ],
    "approved": [
        "approved", "executive management", "management approval",
        "approved by", "management approved", "signed off"
    ],
    "reviewed": [
        "reviewed", "review", "annual review", "reviewed annually",
        "reviewed at planned intervals", "reviewed and updated"
    ],
    "communicated": [
        "communicated", "communication", "communicated to all employees",
        "all employees", "awareness", "distributed"
    ],
    "annual review": [
        "annual review", "annually", "annually by management", "annual",
        "reviewed annually", "each year", "yearly"
    ],
    "management review": [
        "management review", "reviewed by management", "management approval",
        "management approved", "executive management"
    ],
    "segregation of duties": [
        "segregation of duties", "separation of duties", "conflicting duties",
        "segregated", "dual control", "segregate", "separate duties"
    ],
    "separation of duties": [
        "separation of duties", "segregation of duties", "conflicting duties",
        "separated", "dual control"
    ],
    "conflicting duties": [
        "conflicting duties", "segregation of duties", "separation of duties",
        "conflicting", "areas of responsibility are segregated"
    ],
    "training": [
        "training", "awareness training", "security awareness training",
        "all employees complete", "workforce members complete", "trained",
        "education", "security reminders"
    ],
    "awareness": [
        "awareness", "security awareness", "training", "phishing awareness",
        "awareness training", "security reminders"
    ],
    "education": [
        "education", "training", "awareness", "security education",
        "educate", "learning", "annual training"
    ],
    "asset inventory": [
        "asset inventory", "asset register", "asset list", "catalog of assets",
        "inventory of all information assets", "complete inventory",
        "asset management", "information assets"
    ],
    "asset register": [
        "asset register", "asset inventory", "asset list",
        "inventory of assets", "complete inventory"
    ],
    "asset list": [
        "asset list", "asset inventory", "asset register",
        "list of assets", "inventory of all information assets"
    ],
    "authorization": [
        "authorization", "authorised", "authorized", "access control",
        "permission", "rbac", "role-based", "role based"
    ],
    "role based": [
        "role based", "role-based", "rbac", "role-based access",
        "principle of least privilege", "least privilege"
    ],
    "strong authentication": [
        "strong authentication", "multi-factor", "mfa", "strong password",
        "two-factor", "authentication", "strong password policy"
    ],
    "password": [
        "password", "passwords", "password policy", "password management",
        "strong password", "password minimum", "password expiration"
    ],
    "backup": [
        "backup", "backups", "regular backups", "data backup", "offsite backup",
        "backups are performed", "backed up", "daily backups"
    ],
    "recovery": [
        "recovery", "restore", "restore capability", "recovery capability",
        "data recovery", "restore functionality", "recovery procedures"
    ],
    "restore": [
        "restore", "recovery", "restore capability", "tested quarterly",
        "restore functionality", "backup restore"
    ],
    "incident response": [
        "incident response", "incident response plan", "security incident",
        "response procedures", "response plan", "incident management",
        "response team", "documented incident response"
    ],
    "breach": [
        "breach", "data breach", "security breach", "breach notification",
        "breach procedures", "breach of ephi", "security incident"
    ],
    "reporting": [
        "reporting", "reported", "report", "notify", "notification",
        "breach reporting", "incident reporting", "reported immediately"
    ],

    # PCI DSS SPECIFIC
    "firewall": [
        "firewall", "firewalls", "network security", "access control list", "acl",
        "segmentation", "deny all", "deny-all rule", "network device", "firewall configuration"
    ],
    "network segmentation": [
        "network segmentation", "segmentation", "segmented", "cde", "cardholder data environment",
        "properly segmented", "network segment", "isolated"
    ],
    "inbound/outbound rules": [
        "inbound", "outbound", "inbound and outbound", "traffic is restricted",
        "restrict traffic", "rule set", "firewall rules", "deny-all"
    ],
    "masking": [
        "masking", "masked", "mask", "only last 4 digits", "display mask",
        "data masking", "pan masked"
    ],
    "truncation": [
        "truncation", "truncate", "truncated", "only last 4", "last four digits"
    ],
    "tokenization": [
        "tokenization", "tokenize", "token", "tokenization", "cardholder data"
    ],
    "vulnerability scan": [
        "vulnerability scan", "security scan", "penetration test", "assessment",
        "vulnerability scans", "automated vulnerability", "quarterly scans",
        "vulnerability management", "internal vulnerability"
    ],
    "secure coding": [
        "secure coding", "owasp", "secure development", "code review",
        "secure coding guidelines", "owasp top 10", "code reviews"
    ],
    "patch management": [
        "patch management", "patches", "patching", "patch", "remediated within",
        "critical vulnerabilities are remediated", "apply critical patches",
        "within 15 days", "within 30 days"
    ],
    "unique IDs": [
        "unique ids", "unique user ids", "unique user id", "unique id",
        "unique identifiers", "individual user id", "unique user identification"
    ],
    "password complexity": [
        "password complexity", "complexity requirements", "password minimum",
        "12 characters", "password requirements", "strong password", "password policy"
    ],
    "session timeout": [
        "session timeout", "15-minute timeout", "timeout", "automatic logoff",
        "session expiry", "inactivity", "idle timeout", "auto logoff"
    ],
    "logging": [
        "logging", "logs", "log", "logged", "audit logs", "all access is logged",
        "access is logged", "authentication attempts", "event logging"
    ],
    "audit trail": [
        "audit trail", "audit logs", "audit records", "log", "logging",
        "all access", "authentication attempts", "activity logs"
    ],
    "log review": [
        "log review", "reviewed daily", "reviewed weekly", "logs are reviewed",
        "review logs", "daily review", "security team"
    ],
    "log retention": [
        "log retention", "retained for", "minimum 12 months", "12 months",
        "logs are retained", "retention", "6 years"
    ],
    "penetration test": [
        "penetration test", "penetration tests", "pen test", "pen testing",
        "annual internal penetration", "annual external penetration",
        "annual penetration"
    ],
    "IDS/IPS": [
        "ids/ips", "ids", "ips", "intrusion detection", "intrusion prevention",
        "intrusion detection system", "intrusion prevention system"
    ],

    # GDPR ADDITIONAL
    "lawful": [
        "lawful", "lawfully", "legal basis", "lawful basis", "lawful processing",
        "processed lawfully"
    ],
    "fair": [
        "fair", "fairly", "transparent", "lawful, fair", "fairly and in a transparent"
    ],
    "transparent": [
        "transparent", "transparency", "transparently", "fair and transparent",
        "transparent manner"
    ],
    "erasure": [
        "erasure", "right to erasure", "right to be forgotten", "delete",
        "deletion", "erasure requests", "request erasure"
    ],
    "right to be forgotten": [
        "right to be forgotten", "right to erasure", "erasure", "delete",
        "forgotten", "deletion"
    ],
    "delete": [
        "delete", "deletion", "erase", "erasure", "remove", "purge",
        "erasure requests", "right to erasure"
    ],
    "portability": [
        "portability", "data portability", "portable", "structured format",
        "machine-readable", "transfer data", "receive their data"
    ],
    "transfer": [
        "transfer", "portability", "data transfer", "machine-readable",
        "structured format", "transmit", "receive"
    ],
    "machine-readable": [
        "machine-readable", "structured format", "csv", "json", "xml",
        "machine readable", "portable format"
    ],
    "pseudonymization": [
        "pseudonymization", "pseudonymised", "pseudonymize", "anonymization",
        "anonymise", "de-identification", "pseudonymous"
    ],
    "confidentiality": [
        "confidentiality", "confidential", "confidentiality and integrity",
        "ongoing confidentiality", "ensure confidentiality"
    ],
    "integrity": [
        "integrity", "data integrity", "confidentiality and integrity",
        "integrity controls", "improperly modified"
    ],
    "supervisory authority": [
        "supervisory authority", "dpa", "data protection authority",
        "supervisory", "regulatory authority", "hhs", "data protection board"
    ],
    "dpo": [
        "dpo", "data protection officer", "privacy officer",
        "dpo is appointed", "dpo appointed", "dpo contact"
    ],
    "contact": [
        "contact", "contact information", "contact details", "email",
        "phone", "contact info", "published"
    ],

    # DPDPA ADDITIONAL
    "grievance officer": [
        "grievance officer", "grievance", "complaint officer",
        "grievance redressal", "complaint process"
    ],
    "complaint process": [
        "complaint process", "complaint", "grievance", "redressal",
        "grievance mechanism", "complaints", "grievance redressal mechanism"
    ],
    "timeline": [
        "timeline", "within 15 days", "15 days", "30 days", "days",
        "response time", "timeframe", "within"
    ],
    "responsibilities": [
        "responsibilities", "responsible", "responsible for",
        "compliance", "duties", "obligations"
    ],
    "necessary": [
        "necessary", "only necessary", "what is necessary", "minimum necessary",
        "required", "needed", "limited to what is necessary"
    ],
    "adequate": [
        "adequate", "adequate, relevant", "adequate and relevant",
        "limited", "proportionate"
    ],
    "relevant": [
        "relevant", "adequate, relevant", "relevant and limited",
        "pertinent", "applicable"
    ],
    "minimization": [
        "minimization", "data minimization", "minimum", "minimal",
        "only collect", "limited to", "minimise", "minimize"
    ],
    "right to access": [
        "right to access", "access their data", "access to their data",
        "data subjects have the right to access", "access their personal data",
        "obtain confirmation", "right to obtain"
    ],
    "right to correction": [
        "right to correction", "right to rectification", "correction",
        "rectification", "correct their data", "right to correct"
    ],
    "right to erasure": [
        "right to erasure", "right to be forgotten", "erasure",
        "delete", "deletion", "right to deletion"
    ],
    "grievance": [
        "grievance", "complaint", "redressal", "grievance mechanism",
        "grievance redressal", "grievance redressal mechanism"
    ],
    "legitimate purpose": [
        "legitimate purpose", "specified purposes", "lawful purpose",
        "legitimate", "specified, explicit", "legitimate interests"
    ],
    "no secondary use": [
        "no secondary use", "secondary use", "further processing",
        "not used for other", "collected only for", "not repurpose",
        "purpose specification"
    ],

    # ── NIST CSF 2.0 SYNONYMS ────────────────────────────────────
    "organizational mission": [
        "organizational mission", "organisation mission", "mission", "vision",
        "strategic objectives", "business objectives", "cybersecurity objectives",
        "mission and vision"
    ],
    "stakeholders": [
        "stakeholders", "stakeholder", "leadership", "regulators", "customers",
        "third-party", "partners", "internal stakeholders", "external stakeholders"
    ],
    "cybersecurity risk": [
        "cybersecurity risk", "cyber risk", "information security risk",
        "security risk", "risk management", "risk governance"
    ],
    "governance": [
        "governance", "cybersecurity governance", "risk governance",
        "governance structure", "roles and responsibilities", "accountability"
    ],
    "risk tolerance": [
        "risk tolerance", "risk appetite", "tolerance level",
        "acceptable risk", "risk threshold", "risk criteria"
    ],
    "risk management strategy": [
        "risk management strategy", "risk strategy", "cybersecurity risk management",
        "risk management policy", "risk management framework"
    ],
    "risk appetite": [
        "risk appetite", "risk tolerance", "risk threshold",
        "appetite for risk", "acceptable level of risk"
    ],
    "priorities": [
        "priorities", "prioritization", "priority", "risk prioritization",
        "risk treatment priority", "critical assets"
    ],
    "supply chain": [
        "supply chain", "supply chain risk", "supplier", "third-party",
        "vendor", "service provider", "supply chain security"
    ],
    "third-party": [
        "third-party", "third party", "vendor", "supplier",
        "service provider", "external party", "contractors"
    ],
    "vendor risk": [
        "vendor risk", "third-party risk", "supplier risk",
        "vendor assessment", "third-party assessment", "due diligence"
    ],
    "supplier": [
        "supplier", "vendor", "third-party", "service provider",
        "supply chain", "contractor", "outsourced"
    ],
    "cybersecurity requirements": [
        "cybersecurity requirements", "security requirements",
        "security obligations", "contractual security", "supplier security"
    ],
    "hardware": [
        "hardware", "devices", "endpoints", "servers", "network devices",
        "physical assets", "equipment"
    ],
    "software": [
        "software", "applications", "systems", "services",
        "installed software", "application inventory"
    ],
    "data assets": [
        "data assets", "data", "information assets", "datasets",
        "sensitive data", "critical data"
    ],
    "asset classification": [
        "asset classification", "asset categorization", "data classification",
        "criticality", "asset criticality", "sensitivity classification"
    ],
    "threat identification": [
        "threat identification", "threats", "threat analysis",
        "threat landscape", "threat intelligence", "threat modeling"
    ],
    "vulnerability": [
        "vulnerability", "vulnerabilities", "security weakness",
        "security flaw", "vulnerability management", "vulnerability assessment"
    ],
    "likelihood": [
        "likelihood", "probability", "risk likelihood",
        "chance of occurrence", "probability of occurrence"
    ],
    "impact": [
        "impact", "consequences", "risk impact", "potential impact",
        "business impact", "severity", "magnitude"
    ],
    "identity management": [
        "identity management", "identity and access management", "iam",
        "identity governance", "user management", "account management"
    ],
    "authentication": [
        "authentication", "multi-factor authentication", "mfa", "two-factor",
        "strong authentication", "identity verification", "login"
    ],
    "authorization": [
        "authorization", "authorisation", "access rights", "permissions",
        "role-based", "privilege management", "access control"
    ],
    "least privilege": [
        "least privilege", "minimum necessary access", "need-to-know",
        "need-to-use", "principle of least privilege", "minimal access"
    ],
    "data protection": [
        "data protection", "data security", "information protection",
        "protecting data", "data safeguards", "data security policy"
    ],
    "data at rest": [
        "data at rest", "stored data", "at-rest encryption",
        "storage encryption", "encrypted at rest", "aes-256"
    ],
    "data in transit": [
        "data in transit", "data in motion", "in-transit encryption",
        "encrypted in transit", "tls", "transmission security"
    ],
    "data integrity": [
        "data integrity", "integrity controls", "data accuracy",
        "hash verification", "checksum", "data validation", "integrity"
    ],
    "configuration management": [
        "configuration management", "secure configuration",
        "configuration baselines", "hardening standards", "system hardening"
    ],
    "patch management": [
        "patch management", "patching", "software patches",
        "security patches", "patch policy", "apply patches"
    ],
    "secure configuration": [
        "secure configuration", "hardening", "configuration baseline",
        "security baseline", "configuration standards"
    ],
    "vulnerability management": [
        "vulnerability management", "vulnerability scanning", "vulnerability scan",
        "vulnerability assessment", "patch management", "remediation"
    ],
    "hardening": [
        "hardening", "system hardening", "secure configuration",
        "hardening standards", "baseline hardening"
    ],
    "resilience": [
        "resilience", "resiliency", "cyber resilience",
        "operational resilience", "business resilience", "continuity"
    ],
    "availability": [
        "availability", "high availability", "uptime",
        "system availability", "service availability", "redundancy"
    ],
    "business continuity": [
        "business continuity", "continuity plan", "bcp",
        "disaster recovery", "business continuity plan", "continuity of operations"
    ],
    "continuous monitoring": [
        "continuous monitoring", "security monitoring", "ongoing monitoring",
        "real-time monitoring", "siem", "event monitoring", "log monitoring"
    ],
    "security monitoring": [
        "security monitoring", "continuous monitoring", "network monitoring",
        "system monitoring", "siem", "security operations"
    ],
    "log monitoring": [
        "log monitoring", "log review", "log analysis",
        "audit log review", "siem", "event logging"
    ],
    "anomaly detection": [
        "anomaly detection", "threat detection", "intrusion detection",
        "ids", "ips", "behavioral analytics", "unusual activity"
    ],
    "network monitoring": [
        "network monitoring", "network traffic analysis", "nta",
        "network security monitoring", "traffic monitoring", "ids/ips"
    ],
    "event analysis": [
        "event analysis", "security event analysis", "log analysis",
        "event correlation", "incident analysis", "security events"
    ],
    "incident detection": [
        "incident detection", "threat detection", "anomaly detection",
        "security event detection", "intrusion detection"
    ],
    "security events": [
        "security events", "security incidents", "security alerts",
        "suspicious activity", "anomalies", "security notifications"
    ],
    "anomalies": [
        "anomalies", "anomaly", "unusual activity", "suspicious activity",
        "deviations", "abnormal behavior", "outliers"
    ],
    "correlation": [
        "correlation", "event correlation", "log correlation",
        "siem", "security correlation", "cross-system analysis"
    ],
    "incident management": [
        "incident management", "incident response", "incident handling",
        "incident response plan", "security incident management"
    ],
    "response plan": [
        "response plan", "incident response plan", "ir plan",
        "incident response procedure", "response procedure"
    ],
    "containment": [
        "containment", "incident containment", "isolate",
        "quarantine", "limiting spread", "contain the incident"
    ],
    "eradication": [
        "eradication", "remove threat", "malware removal",
        "threat removal", "clean systems", "eradicate"
    ],
    "incident communication": [
        "incident communication", "notification procedures",
        "stakeholder communication", "incident reporting", "communication plan"
    ],
    "notification": [
        "notification", "notify", "alert", "report",
        "inform", "disclosure", "72 hours", "60 days"
    ],
    "reporting": [
        "reporting", "incident reporting", "breach reporting",
        "regulatory reporting", "notification", "disclose"
    ],
    "stakeholder communication": [
        "stakeholder communication", "executive communication",
        "board reporting", "leadership communication", "crisis communication"
    ],
    "disclosure": [
        "disclosure", "public disclosure", "breach disclosure",
        "regulatory disclosure", "notification", "reporting"
    ],
    "recovery plan": [
        "recovery plan", "disaster recovery plan", "drp",
        "recovery procedures", "recovery playbook", "restoration plan"
    ],
    "restoration": [
        "restoration", "restore", "system restoration",
        "recover systems", "recovery", "bring back online"
    ],
    "recovery objectives": [
        "recovery objectives", "rto", "rpo", "recovery time objective",
        "recovery point objective", "recovery targets"
    ],
    "lessons learned": [
        "lessons learned", "post-incident review", "after action review",
        "incident debrief", "root cause analysis", "improvement actions"
    ],
}

def match_phrase(text, required_phrase):
    text_lower = text.lower()
    synonyms = PHRASE_SYNONYMS.get(required_phrase, [required_phrase])
    for syn in synonyms:
        if syn.lower() in text_lower:
            return True, syn
    return False, None

def extract_short_evidence(text, matched_synonym, max_chars=200):
    """Extract a clean sentence containing the matched synonym, avoiding separator lines."""
    idx = text.lower().find(matched_synonym.lower())
    if idx == -1:
        return ""
    # Search backward for start of sentence (period or newline)
    start = max(0, text.rfind('\n', 0, idx) + 1)
    period_start = text.rfind('.', 0, idx)
    if period_start > start:
        start = period_start + 1
    # Search forward for end of sentence
    end = text.find('.', idx + len(matched_synonym))
    if end == -1 or end - start > 300:
        end = min(len(text), idx + len(matched_synonym) + 100)
    sentence = text[start:end+1].strip()
    # Remove lines that are just separator characters (====, ----, etc.)
    lines = [l.strip() for l in sentence.split('\n')
             if l.strip() and not re.match(r'^[=\-\s]{5,}$', l.strip())]
    sentence = ' '.join(lines)
    sentence = re.sub(r'\s+', ' ', sentence).strip()
    if len(sentence) > max_chars:
        sentence = sentence[:max_chars] + "..."
    return sentence


def score_control_result(control, raw_score, found_phrases, missing_phrases, evidence):
    """Derive status/symbol/risk labeling and fix-suggestion text from a control's
    raw coverage score. Shared by analyze_control() (live scans) and the
    assessment-reconstruction path (routes/scan_routes.py export endpoints) so both
    produce identical labeling from the same persisted score instead of duplicating
    this logic and risking drift."""
    if raw_score >= 80:
        status = "Compliant";           symbol = "✅"; risk_level = "Low";    risk_color = "#10b981"
    elif raw_score >= 50:
        status = "Partially Compliant"; symbol = "⚠️"; risk_level = "Medium"; risk_color = "#f59e0b"
    else:
        status = "Non-Compliant";       symbol = "❌"; risk_level = "High";   risk_color = "#ef4444"

    if missing_phrases:
        missing_labels = ', '.join(m.replace('_', ' ').capitalize() for m in missing_phrases[:3])
        fix_suggestion = (f"Missing: {missing_labels}. "
                       f"Suggested addition: {control['remediation_example']}")
    else:
        fix_suggestion = "No action needed - control is adequately documented."

    return {
        "id": control["id"], "name": control["name"], "clause": control["clause"],
        "owner": control["owner"], "severity": control["severity"],
        "score": raw_score,
        "status": status, "symbol": symbol, "risk_level": risk_level, "risk_color": risk_color,
        "found_phrases": found_phrases, "missing_phrases": missing_phrases,
        "evidence": evidence, "why_matters": control["why_matters"],
        "fix_suggestion": fix_suggestion, "weight": control["weight"]
    }


def analyze_control(policy_text, control):
    required = control['required_text']
    found_phrases = []
    evidence_list = []
    for phrase in required:
        found, matched_syn = match_phrase(policy_text, phrase)
        if found:
            found_phrases.append(phrase)
            ev = extract_short_evidence(policy_text, matched_syn, 200)
            if ev:
                evidence_list.append(ev)
    total = len(required)
    found_count = len(found_phrases)

    # Raw coverage percentage (0-100) - used directly for per-control score
    raw_score = round((found_count / total) * 100, 1) if total else 0

    missing = [p for p in required if p not in found_phrases]
    best_evidence = evidence_list[0] if evidence_list else ""

    return score_control_result(control, raw_score, found_phrases, missing, best_evidence)


def calculate_weighted_score(controls):
    """Weighted average: each control's raw_score × its weight, divided by total weight."""
    total_weight = sum(c['weight'] for c in controls)
    earned = sum(c['weight'] * (c['score'] / 100) for c in controls)
    return round((earned / total_weight) * 100, 1) if total_weight else 0

FRAMEWORKS = {
    'dpdpa': {
        'name': 'DPDPA 2023 (India)', 'icon': '🇮🇳', 'color': '#d97706', 'currency': 'Rs.',
        'controls': [
            {"id": "DPDPA-1", "name": "Consent Obligation", "clause": "Section 6", "owner": "Product Team", "severity": "critical", "weight": 10,
             "required_text": ["explicit consent", "withdrawal mechanism", "informed consent", "record of consent"],
             "why_matters": "Without valid consent, all processing is illegal. Penalty up to Rs.250 crore.",
             "remediation_example": "We obtain explicit, informed consent via double opt-in. Users can withdraw anytime through account settings."},
            {"id": "DPDPA-2", "name": "Notice to Data Principal", "clause": "Section 5", "owner": "Legal Team", "severity": "major", "weight": 7,
             "required_text": ["privacy notice", "purpose", "retention period", "data principal rights"],
             "why_matters": "Data principals have the right to know how their data is used. Penalty up to Rs.50 crore.",
             "remediation_example": "Provide a clear privacy notice covering purpose, retention, rights, and contact details."},
            {"id": "DPDPA-3", "name": "Purpose Limitation", "clause": "Section 6", "owner": "Product Team", "severity": "critical", "weight": 10,
             "required_text": ["purpose", "legitimate purpose", "no secondary use"],
             "why_matters": "Using data beyond specified purpose is a breach of trust. Penalty up to Rs.250 crore.",
             "remediation_example": "Data collected only for specified purposes. No secondary use without additional consent."},
            {"id": "DPDPA-4", "name": "Data Minimization", "clause": "Section 6", "owner": "Product Team", "severity": "major", "weight": 7,
             "required_text": ["necessary", "adequate", "relevant", "minimization"],
             "why_matters": "Collecting unnecessary data increases risk and legal exposure.",
             "remediation_example": "We collect only data necessary for the purpose. Quarterly minimization reviews."},
            {"id": "DPDPA-5", "name": "Data Retention", "clause": "Section 9", "owner": "IT Team", "severity": "major", "weight": 7,
             "required_text": ["retention period", "deletion after purpose", "storage limitation"],
             "why_matters": "Keeping data forever violates DPDPA. Penalty for indefinite storage.",
             "remediation_example": "Data retained for 3 years after last interaction, then securely deleted."},
            {"id": "DPDPA-6", "name": "Data Principal Rights", "clause": "Section 12", "owner": "Legal Team", "severity": "major", "weight": 7,
             "required_text": ["right to access", "right to correction", "right to erasure", "grievance"],
             "why_matters": "Data principals have legal rights to access, correct, and erase their data.",
             "remediation_example": "Users can access, correct, erase data. Response within 15 days."},
            {"id": "DPDPA-7", "name": "Grievance Redressal", "clause": "Section 17", "owner": "Customer Support", "severity": "major", "weight": 6,
             "required_text": ["grievance officer", "complaint process", "timeline"],
             "why_matters": "Unresolved complaints lead to regulatory action and penalties.",
             "remediation_example": "Grievance officer: dpo@company.com. Resolution within 15 days."},
            {"id": "DPDPA-8", "name": "Data Protection Officer", "clause": "Section 9", "owner": "Legal Team", "severity": "major", "weight": 6,
             "required_text": ["dpo", "contact", "responsibilities"],
             "why_matters": "A DPO is mandatory for certain fiduciaries under DPDPA.",
             "remediation_example": "DPO: name, email, phone. Responsible for compliance and liaison with the Data Protection Board."},
            {"id": "DPDPA-9", "name": "Security Safeguards", "clause": "Section 10", "owner": "Security Team", "severity": "critical", "weight": 10,
             "required_text": ["encryption", "access control", "mfa", "security measures"],
             "why_matters": "Weak security leads to breaches and heavy penalties (Rs.250 crore).",
             "remediation_example": "AES-256 encryption, TLS 1.3, RBAC, MFA for admin access."},
            {"id": "DPDPA-10", "name": "Breach Notification", "clause": "Section 11", "owner": "Security Team", "severity": "critical", "weight": 10,
             "required_text": ["breach response", "notification", "72 hours"],
             "why_matters": "Delayed notification attracts Rs.250 crore penalty.",
             "remediation_example": "Notify Data Protection Board within 72 hours; notify affected users within 24 hours."},
            {"id": "DPDPA-11", "name": "Children's Data", "clause": "Section 13", "owner": "Product Team", "severity": "critical", "weight": 10,
             "required_text": ["parental consent", "age verification", "verifiable consent"],
             "why_matters": "Processing children's data without parental consent is a serious violation.",
             "remediation_example": "Parental consent via OTP, age verification gate, no profiling of minors under 18."},
            {"id": "DPDPA-12", "name": "Cross-border Transfer", "clause": "Section 17", "owner": "Legal Team", "severity": "major", "weight": 7,
             "required_text": ["localization", "safeguards", "consent"],
             "why_matters": "Unauthorized transfer can lead to data compromise and penalties.",
             "remediation_example": "Data stored in India. International transfer only with SCCs, adequacy decision, and consent."}
        ]
    },
    'iso27001': {
        'name': 'ISO 27001:2022', 'icon': '🌐', 'color': '#3b82f6', 'currency': '$',
        'controls': [
            {"id": "A.5.1", "name": "Information Security Policy", "clause": "Annex A.5.1", "owner": "Management", "severity": "critical", "weight": 10,
             "required_text": ["information security policy", "approved", "reviewed", "communicated"],
             "why_matters": "Without a formal policy, security governance is impossible. Certification risk.",
             "remediation_example": "Information security policy approved by management, reviewed annually, and communicated to all employees."},
            {"id": "A.5.2", "name": "Policy Review", "clause": "A.5.2", "owner": "Management", "severity": "major", "weight": 7,
             "required_text": ["review", "annual review", "management review"],
             "why_matters": "Outdated policies lead to non-conformities during audits.",
             "remediation_example": "Policy reviewed annually by management; changes documented."},
            {"id": "A.5.3", "name": "Segregation of Duties", "clause": "A.5.3", "owner": "IT Team", "severity": "major", "weight": 7,
             "required_text": ["segregation of duties", "separation of duties", "conflicting duties"],
             "why_matters": "Lack of segregation increases risk of fraud and error.",
             "remediation_example": "Separate duties to reduce risk of error or fraud. No single person has end-to-end control."},
            {"id": "A.7.2", "name": "Security Awareness", "clause": "A.7.2", "owner": "HR", "severity": "major", "weight": 7,
             "required_text": ["training", "awareness", "education"],
             "why_matters": "Human error is the leading cause of security incidents.",
             "remediation_example": "All employees receive security awareness training upon hire and annually."},
            {"id": "A.8.1", "name": "Asset Inventory", "clause": "A.8.1", "owner": "IT Team", "severity": "major", "weight": 7,
             "required_text": ["asset inventory", "asset register", "asset list"],
             "why_matters": "Unknown assets cannot be protected.",
             "remediation_example": "Maintain an inventory of all information assets with ownership and classification."},
            {"id": "A.9.1", "name": "Access Control Policy", "clause": "A.9.1", "owner": "IT Team", "severity": "critical", "weight": 10,
             "required_text": ["access control", "authorization", "role based"],
             "why_matters": "Unauthorized access is a major risk to confidentiality and integrity.",
             "remediation_example": "Implement role-based access control (RBAC) following the principle of least privilege."},
            {"id": "A.9.2", "name": "Authentication", "clause": "A.9.2", "owner": "IT Team", "severity": "critical", "weight": 10,
             "required_text": ["mfa", "strong authentication", "password"],
             "why_matters": "Weak passwords are easily compromised.",
             "remediation_example": "Multi-factor authentication for all privileged accounts; strong password policy."},
            {"id": "A.12.2", "name": "Backup", "clause": "A.12.2", "owner": "IT Team", "severity": "major", "weight": 7,
             "required_text": ["backup", "recovery", "restore"],
             "why_matters": "Data loss can stop business operations.",
             "remediation_example": "Daily backups, stored offsite, tested quarterly for restore functionality."},
            {"id": "A.16.1", "name": "Incident Management", "clause": "A.16.1", "owner": "Security Team", "severity": "critical", "weight": 10,
             "required_text": ["incident response", "breach", "reporting"],
             "why_matters": "Undetected breaches can go unnoticed for months.",
             "remediation_example": "Documented incident response plan, report to management within 24 hours."}
        ]
    },
    'gdpr': {
        'name': 'GDPR (EU)', 'icon': '🇪🇺', 'color': '#14b8a6', 'currency': '€',
        'controls': [
            {"id": "Art-5", "name": "Principles of Processing", "clause": "Article 5", "owner": "Legal Team", "severity": "critical", "weight": 10,
             "required_text": ["lawful", "fair", "transparent", "purpose limitation"],
             "why_matters": "Violation can lead to €20M or 4% of global revenue fine.",
             "remediation_example": "Processing is lawful, fair, transparent. Data collected for specified, explicit purposes."},
            {"id": "Art-6", "name": "Lawful Basis", "clause": "Article 6", "owner": "Legal Team", "severity": "critical", "weight": 10,
             "required_text": ["lawful basis", "consent", "contract", "legal obligation", "legitimate interest"],
             "why_matters": "Without a lawful basis, all processing is illegal.",
             "remediation_example": "We rely on consent, contract necessity, legal obligation, or legitimate interest."},
            {"id": "Art-15", "name": "Right to Access", "clause": "Article 15", "owner": "Legal Team", "severity": "major", "weight": 7,
             "required_text": ["access", "copy", "rectification"],
             "why_matters": "Data subjects have the right to know what data is held about them.",
             "remediation_example": "Users can request access to their data and receive a copy within one month."},
            {"id": "Art-17", "name": "Right to Erasure", "clause": "Article 17", "owner": "Legal Team", "severity": "major", "weight": 7,
             "required_text": ["erasure", "right to be forgotten", "delete"],
             "why_matters": "Individuals can request deletion when data is no longer necessary.",
             "remediation_example": "Users can request deletion of their data when no longer necessary or consent withdrawn."},
            {"id": "Art-20", "name": "Data Portability", "clause": "Article 20", "owner": "Legal Team", "severity": "major", "weight": 6,
             "required_text": ["portability", "transfer", "machine-readable"],
             "why_matters": "Data subjects have the right to receive their data in a structured format.",
             "remediation_example": "Users can receive their data in a structured, machine-readable format (e.g., CSV)."},
            {"id": "Art-32", "name": "Security of Processing", "clause": "Article 32", "owner": "Security Team", "severity": "critical", "weight": 10,
             "required_text": ["encryption", "pseudonymization", "confidentiality", "integrity"],
             "why_matters": "Inadequate security can lead to data breaches and massive fines.",
             "remediation_example": "AES-256 encryption, pseudonymization, access controls, regular testing."},
            {"id": "Art-33", "name": "Breach Notification", "clause": "Article 33", "owner": "Security Team", "severity": "critical", "weight": 10,
             "required_text": ["breach", "notification", "72 hours", "supervisory authority"],
             "why_matters": "Late notification can result in fines up to €10M.",
             "remediation_example": "Notify DPA within 72 hours, affected individuals if high risk."},
            {"id": "Art-37", "name": "Data Protection Officer", "clause": "Article 37", "owner": "Legal Team", "severity": "major", "weight": 7,
             "required_text": ["dpo", "data protection officer", "contact"],
             "why_matters": "Certain controllers must appoint a DPO.",
             "remediation_example": "DPO appointed: name@company.com. Responsibilities include monitoring compliance."}
        ]
    },
    'pcidss': {
        'name': 'PCI DSS v4.0', 'icon': '💳', 'color': '#f97316', 'currency': '$',
        'controls': [
            {"id": "Req-1", "name": "Firewall Configuration", "clause": "Requirement 1", "owner": "Network Team", "severity": "critical", "weight": 10,
             "required_text": ["firewall", "network segmentation", "inbound/outbound rules"],
             "why_matters": "Weak firewall rules can lead to cardholder data exposure.",
             "remediation_example": "Firewall restricts traffic, implements segmentation, reviews rules quarterly."},
            {"id": "Req-3", "name": "Protect Stored Cardholder Data", "clause": "Requirement 3", "owner": "Security Team", "severity": "critical", "weight": 10,
             "required_text": ["encryption", "masking", "truncation", "tokenization"],
             "why_matters": "Stored PAN is a prime target for attackers.",
             "remediation_example": "Encrypt stored PAN, mask when displayed, truncate or tokenize."},
            {"id": "Req-6", "name": "Secure Development", "clause": "Requirement 6", "owner": "DevOps", "severity": "major", "weight": 7,
             "required_text": ["vulnerability scan", "secure coding", "patch management"],
             "why_matters": "Unpatched vulnerabilities are a leading cause of breaches.",
             "remediation_example": "Run vulnerability scans quarterly, apply critical patches within 30 days."},
            {"id": "Req-8", "name": "Authentication", "clause": "Requirement 8", "owner": "Security Team", "severity": "critical", "weight": 10,
             "required_text": ["mfa", "unique IDs", "password complexity", "session timeout"],
             "why_matters": "Weak authentication can lead to account takeover.",
             "remediation_example": "MFA for all access, strong passwords, 15-minute timeout."},
            {"id": "Req-10", "name": "Logging and Monitoring", "clause": "Requirement 10", "owner": "Security Team", "severity": "major", "weight": 7,
             "required_text": ["logging", "audit trail", "log review", "log retention"],
             "why_matters": "Without logs, breaches may go undetected.",
             "remediation_example": "Log all access, review daily, retain logs for 12 months."},
            {"id": "Req-11", "name": "Regular Testing", "clause": "Requirement 11", "owner": "Security Team", "severity": "major", "weight": 7,
             "required_text": ["penetration test", "vulnerability scan", "IDS/IPS"],
             "why_matters": "Regular testing finds weaknesses before attackers do.",
             "remediation_example": "Annual penetration test, quarterly scans, deploy IDS/IPS."}
        ]
    },
    'hipaa': {
        'name': 'HIPAA', 'icon': '🏥', 'color': '#ec4899', 'currency': '$',
        'controls': [
            {"id": "164.308(a)(1)", "name": "Security Management Process", "clause": "45 CFR 164.308(a)(1)", "owner": "Security Team", "severity": "critical", "weight": 10,
             "required_text": ["risk analysis", "risk management", "sanction policy", "information system activity review"],
             "why_matters": "Failure to conduct risk analysis is the most common HIPAA violation.",
             "remediation_example": "Conduct annual risk analysis, implement risk management, review system activity logs."},
            {"id": "164.308(a)(5)", "name": "Security Awareness Training", "clause": "45 CFR 164.308(a)(5)", "owner": "HR", "severity": "major", "weight": 7,
             "required_text": ["training", "awareness", "security reminders", "malware protection"],
             "why_matters": "Untrained employees are a major security risk.",
             "remediation_example": "All employees receive annual security awareness training."},
            {"id": "164.308(a)(6)", "name": "Security Incident Procedures", "clause": "45 CFR 164.308(a)(6)", "owner": "Security Team", "severity": "critical", "weight": 10,
             "required_text": ["incident response", "breach", "response and reporting"],
             "why_matters": "Delayed breach reporting can lead to massive fines.",
             "remediation_example": "Incident response plan, report breaches to HHS within 60 days."},
            {"id": "164.312(a)", "name": "Access Control", "clause": "45 CFR 164.312(a)", "owner": "IT Team", "severity": "critical", "weight": 10,
             "required_text": ["unique user identification", "emergency access", "automatic logoff", "encryption"],
             "why_matters": "Unauthorized access to ePHI is a direct violation.",
             "remediation_example": "Unique IDs, role-based access, automatic logoff after inactivity."},
            {"id": "164.312(b)", "name": "Audit Controls", "clause": "45 CFR 164.312(b)", "owner": "IT Team", "severity": "major", "weight": 7,
             "required_text": ["audit logs", "activity review", "recording access"],
             "why_matters": "Without audit trails, you cannot detect inappropriate access.",
             "remediation_example": "Record and review all access to ePHI."},
            {"id": "164.312(e)", "name": "Transmission Security", "clause": "45 CFR 164.312(e)", "owner": "IT Team", "severity": "critical", "weight": 10,
             "required_text": ["encryption", "tls", "secure transmission"],
             "why_matters": "Unencrypted ePHI in transit can be intercepted.",
             "remediation_example": "Encrypt all ePHI in transit using TLS 1.2 or higher."}
        ]
    },
    'nistcsf': {
        'name': 'NIST CSF 2.0', 'icon': '🛡️', 'color': '#6366f1', 'currency': '$',
        'controls': [
            {"id": "GV.OC-01", "name": "Organizational Context", "clause": "Govern (GV.OC)", "owner": "Leadership", "severity": "critical", "weight": 10,
             "required_text": ["organizational mission", "stakeholders", "cybersecurity risk", "governance", "risk tolerance"],
             "why_matters": "Without clear organizational context, cybersecurity objectives cannot be aligned to business goals.",
             "remediation_example": "Define organizational mission, identify stakeholders, document cybersecurity risk governance, and establish risk tolerance levels."},
            {"id": "GV.RM-01", "name": "Risk Management Strategy", "clause": "Govern (GV.RM)", "owner": "Risk Management", "severity": "critical", "weight": 10,
             "required_text": ["risk management strategy", "risk appetite", "risk tolerance", "cybersecurity risk management", "priorities"],
             "why_matters": "A documented risk management strategy ensures consistent cybersecurity decisions across the organization.",
             "remediation_example": "Establish and document risk management strategy, define risk appetite and risk tolerance, integrate cybersecurity into enterprise risk management."},
            {"id": "GV.SC-01", "name": "Supply Chain Risk Management", "clause": "Govern (GV.SC)", "owner": "Procurement", "severity": "major", "weight": 7,
             "required_text": ["supply chain", "third-party", "vendor risk", "supplier", "cybersecurity requirements"],
             "why_matters": "Third-party and supply chain vulnerabilities are a leading attack vector in modern cybersecurity incidents.",
             "remediation_example": "Establish supply chain risk management policy, assess third-party vendors, enforce cybersecurity requirements in supplier contracts."},
            {"id": "ID.AM-01", "name": "Asset Management", "clause": "Identify (ID.AM)", "owner": "IT Team", "severity": "major", "weight": 7,
             "required_text": ["asset inventory", "hardware", "software", "data assets", "asset classification"],
             "why_matters": "You cannot protect what you cannot see. Asset visibility is the foundation of cybersecurity.",
             "remediation_example": "Maintain a comprehensive asset inventory covering hardware, software, data assets, and services. Classify all assets by criticality."},
            {"id": "ID.RA-01", "name": "Risk Assessment", "clause": "Identify (ID.RA)", "owner": "Security Team", "severity": "critical", "weight": 10,
             "required_text": ["risk assessment", "threat identification", "vulnerability", "likelihood", "impact"],
             "why_matters": "Risk assessments identify and prioritize cybersecurity threats before they can be exploited.",
             "remediation_example": "Conduct regular risk assessments to identify threats and vulnerabilities, analyze likelihood and impact, and prioritize remediation."},
            {"id": "PR.AA-01", "name": "Identity and Access Management", "clause": "Protect (PR.AA)", "owner": "IT Team", "severity": "critical", "weight": 10,
             "required_text": ["identity management", "access control", "authentication", "authorization", "least privilege"],
             "why_matters": "Unauthorized access is the primary pathway for data breaches and system compromise.",
             "remediation_example": "Implement identity management, enforce access control and authorization, apply least privilege principles, require multi-factor authentication."},
            {"id": "PR.DS-01", "name": "Data Security", "clause": "Protect (PR.DS)", "owner": "Security Team", "severity": "critical", "weight": 10,
             "required_text": ["data protection", "encryption", "data at rest", "data in transit", "data integrity"],
             "why_matters": "Data is the primary target of cyber attacks. Failure to protect data leads to breaches and regulatory penalties.",
             "remediation_example": "Encrypt data at rest and data in transit, enforce data protection policies, ensure data integrity controls are implemented."},
            {"id": "PR.PS-01", "name": "Platform Security", "clause": "Protect (PR.PS)", "owner": "IT Team", "severity": "major", "weight": 7,
             "required_text": ["configuration management", "patch management", "secure configuration", "vulnerability management", "hardening"],
             "why_matters": "Misconfigured or unpatched systems are the most commonly exploited vulnerabilities.",
             "remediation_example": "Implement configuration management and hardening standards, maintain patch management processes, conduct vulnerability management reviews."},
            {"id": "PR.IR-01", "name": "Technology Infrastructure Resilience", "clause": "Protect (PR.IR)", "owner": "IT Team", "severity": "major", "weight": 7,
             "required_text": ["resilience", "backup", "recovery", "availability", "business continuity"],
             "why_matters": "Infrastructure resilience ensures availability and minimizes the impact of cybersecurity incidents.",
             "remediation_example": "Implement backup and recovery procedures, ensure availability of critical systems, document and test business continuity plans."},
            {"id": "DE.CM-01", "name": "Continuous Monitoring", "clause": "Detect (DE.CM)", "owner": "Security Team", "severity": "critical", "weight": 10,
             "required_text": ["continuous monitoring", "security monitoring", "log monitoring", "anomaly detection", "network monitoring"],
             "why_matters": "Early detection of cybersecurity events reduces dwell time and limits damage from attacks.",
             "remediation_example": "Implement continuous monitoring of networks, systems, and applications. Configure anomaly detection and log monitoring alerts."},
            {"id": "DE.AE-01", "name": "Adverse Event Analysis", "clause": "Detect (DE.AE)", "owner": "Security Team", "severity": "major", "weight": 7,
             "required_text": ["event analysis", "incident detection", "security events", "anomalies", "correlation"],
             "why_matters": "Analyzing security events enables timely identification of incidents before they escalate.",
             "remediation_example": "Establish processes for collecting, correlating, and analyzing security events. Define thresholds for incident detection and escalation."},
            {"id": "RS.MA-01", "name": "Incident Management", "clause": "Respond (RS.MA)", "owner": "Security Team", "severity": "critical", "weight": 10,
             "required_text": ["incident response", "incident management", "response plan", "containment", "eradication"],
             "why_matters": "A documented incident response capability minimizes the impact of cybersecurity incidents on operations.",
             "remediation_example": "Document and test incident response plan covering detection, containment, eradication, recovery, and post-incident review."},
            {"id": "RS.CO-01", "name": "Incident Communication", "clause": "Respond (RS.CO)", "owner": "Leadership", "severity": "major", "weight": 7,
             "required_text": ["incident communication", "notification", "reporting", "stakeholder communication", "disclosure"],
             "why_matters": "Timely communication during incidents limits reputational damage and meets regulatory notification obligations.",
             "remediation_example": "Define incident communication procedures including internal notification, stakeholder communication, regulatory reporting, and public disclosure protocols."},
            {"id": "RC.RP-01", "name": "Incident Recovery", "clause": "Recover (RC.RP)", "owner": "IT Team", "severity": "critical", "weight": 10,
             "required_text": ["recovery plan", "restoration", "recovery objectives", "resilience", "lessons learned"],
             "why_matters": "A tested recovery plan minimizes downtime and ensures return to normal operations after a cybersecurity incident.",
             "remediation_example": "Develop and test recovery plans with defined recovery objectives (RTO/RPO). Document lessons learned from incidents to continuously improve resilience."}
        ]
    }
}


# ============================================================
# FIX 4: MULTI-FORMAT TEXT EXTRACTION (TXT, PDF, DOCX)
# ============================================================

def extract_text(filepath):
    """Extract text from TXT, PDF, or DOCX files."""
    ext = filepath.rsplit('.', 1)[-1].lower()

    if ext == 'txt':
        try:
            with open(filepath, 'r', encoding='utf-8-sig') as f:
                return f.read()
        except Exception:
            with open(filepath, 'r', encoding='latin-1') as f:
                return f.read()

    elif ext == 'pdf':
        if not PDF_SUPPORT:
            return "PDF support not available. Install pdfplumber: pip install pdfplumber"
        try:
            import pdfplumber
            text_parts = []
            with pdfplumber.open(filepath) as pdf:
                for page in pdf.pages:
                    page_text = page.extract_text()
                    if page_text:
                        text_parts.append(page_text)
            return '\n'.join(text_parts)
        except Exception as e:
            return f"Error reading PDF: {str(e)}"

    elif ext == 'docx':
        if not DOCX_SUPPORT:
            return "DOCX support not available. Install python-docx: pip install python-docx"
        try:
            from docx import Document as DocxDoc
            doc = DocxDoc(filepath)
            text_parts = []
            for para in doc.paragraphs:
                if para.text.strip():
                    text_parts.append(para.text)
            # Also extract tables
            for table in doc.tables:
                for row in table.rows:
                    for cell in row.cells:
                        if cell.text.strip():
                            text_parts.append(cell.text)
            return '\n'.join(text_parts)
        except Exception as e:
            return f"Error reading DOCX: {str(e)}"

    return "Unsupported file format."


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in Config.ALLOWED_EXTENSIONS
