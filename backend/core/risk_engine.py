"""Enterprise Risk Assessment Engine for Audinexia"""

class RiskEngine:
    """Calculates risk levels based on control scores"""
    
    @staticmethod
    def calculate_risk(score, control_weight):
        """Calculate risk level from score"""
        if score < 30:
            return {
                "level": "Critical",
                "color": "#dc2626",
                "priority": "Immediate",
                "timeframe": "0-7 days",
                "business_impact": "Severe -可能导致 data breach, regulatory fines up to ₹250 crore",
                "attack_likelihood": "Very High"
            }
        elif score < 50:
            return {
                "level": "High",
                "color": "#f97316",
                "priority": "High",
                "timeframe": "7-30 days",
                "business_impact": "Significant - Compliance gaps, potential data exposure",
                "attack_likelihood": "High"
            }
        elif score < 70:
            return {
                "level": "Medium",
                "color": "#eab308",
                "priority": "Medium",
                "timeframe": "30-60 days",
                "business_impact": "Moderate - Partial compliance gaps",
                "attack_likelihood": "Medium"
            }
        else:
            return {
                "level": "Low",
                "color": "#10b981",
                "priority": "Low",
                "timeframe": "60-90 days",
                "business_impact": "Minimal - Minor improvements needed",
                "attack_likelihood": "Low"
            }
    
    @staticmethod
    def generate_attack_scenario(control_id, control_name):
        """Generate realistic attack scenarios for controls"""
        scenarios = {
            "DPDPA-1": "A malicious website could obtain consent through dark patterns without user understanding",
            "DPDPA-2": "Users may unknowingly share personal data if privacy notices are hidden or unclear",
            "DPDPA-3": "Data subjects cannot verify or delete their data, leading to loss of control",
            "DPDPA-4": "No accountable person for data protection decisions, leading to compliance failures",
            "DPDPA-5": "Attacker intercepts unencrypted data transmission or gains unauthorized access",
            "DPDPA-6": "Breach remains undetected for months, allowing data exfiltration",
            "DPDPA-7": "Children's data collected without parental consent, violating legal requirements",
            "DPDPA-8": "Personal data transferred to countries with weak privacy laws"
        }
        return scenarios.get(control_id, f"Attacker could exploit missing {control_name} controls")
    
    @staticmethod
    def generate_remediation(control_id, score):
        """Generate specific remediation steps based on score"""
        if score < 30:
            return "CRITICAL: Immediate implementation required. Engage legal and security teams to develop complete solution."
        elif score < 50:
            return "HIGH PRIORITY: Develop and implement within 30 days. Assign responsible team and track progress."
        elif score < 70:
            return "MEDIUM PRIORITY: Schedule for next sprint. Enhance documentation and controls."
        else:
            return "LOW PRIORITY: Minor improvements. Monitor and maintain current controls."