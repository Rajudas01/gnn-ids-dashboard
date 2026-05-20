import random
import pandas as pd
from datetime import datetime

# =====================================================
# ATTACK SIMULATION ENGINE
# =====================================================

attack_types = [

    "DDoS Attack",

    "SQL Injection",

    "Brute Force",

    "Botnet Activity",

    "Port Scanning",

    "Malware Traffic",

    "Phishing Attempt",

    "Unauthorized Access"
]

severity_levels = [

    "LOW",

    "MEDIUM",

    "HIGH",

    "CRITICAL"
]

countries = [

    "Russia",

    "China",

    "USA",

    "Germany",

    "Brazil",

    "India",

    "North Korea"
]

# =====================================================
# GENERATE ATTACKS
# =====================================================

def generate_attack_logs():

    logs = []

    for i in range(10):

        logs.append({

            "Time": str(datetime.now()),

            "Attack Type": random.choice(
                attack_types
            ),

            "Severity": random.choice(
                severity_levels
            ),

            "Source Country": random.choice(
                countries
            ),

            "Packets": random.randint(
                100,
                10000
            )
        })

    return pd.DataFrame(logs)