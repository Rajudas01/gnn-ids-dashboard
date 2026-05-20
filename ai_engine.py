import random

# =====================================================
# AI SECURITY RECOMMENDATIONS
# =====================================================

def get_ai_recommendations():

    recommendations = [

        "Enable firewall protection",

        "Block suspicious IP addresses",

        "Monitor unusual packet spikes",

        "Update IDS signatures regularly",

        "Enable multi-factor authentication",

        "Run malware scans frequently",

        "Restrict unused network ports",

        "Use encrypted communication channels"
    ]

    return random.sample(recommendations, 4)

# =====================================================
# THREAT SCORE CALCULATOR
# =====================================================

def calculate_threat_score(attack_percentage):

    if attack_percentage >= 70:
        return "CRITICAL"

    elif attack_percentage >= 40:
        return "HIGH"

    elif attack_percentage >= 20:
        return "MEDIUM"

    else:
        return "LOW"