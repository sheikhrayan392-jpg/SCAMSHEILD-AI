"""
ScamShield AI - Guardian Agent (Part 1 & Phase 2 Enhanced)
==========================================================
A transparent, rule-based cybersecurity defense prototype designed to detect
common scam patterns such as authority impersonation, "digital arrest" threats,
urgent financial demands, credential harvesting, panic/pressure tactics, utility
disconnections, advance-fee lottery/job fraud, and suspicious phishing links/APKs.

DISCLAIMER:
This rule-based prototype is an educational demonstration developed for a
cybersecurity hackathon. It does NOT guarantee 100% scam detection and must not
replace official law enforcement channels or user vigilance. If you suspect fraud,
contact official authorities (such as the National Cyber Crime Helpline: 1930 in India).
"""

import re
from typing import Dict, List, Any


# ---------------------------------------------------------------------------
# Rule Definitions: Detection Categories & Regex Patterns
# ---------------------------------------------------------------------------
# Each category contains:
# - 'name': Human-readable label for judges and users
# - 'weight': Contribution toward total risk score
# - 'patterns': Regex patterns targeting specific scam terminology
# ---------------------------------------------------------------------------

RULES = {
    "authority_impersonation": {
        "name": "Authority & Law Enforcement Impersonation",
        "weight": 15,
        "patterns": [
            r"\b(?:delhi|mumbai|state|national|traffic)?\s*police\b",
            r"\b(?:delhy|delhi)\s*polise\b|\boffiser\b",
            r"\bcbi\b|\bcentral bureau of investigation\b",
            r"\b(?:ed|enforcement directorate)\b",
            r"\bcrime branch\b",
            r"\b(?:ncb|narcotics control bureau)\b",
            r"\b(?:customs|customs department|customs officer|customs hub)\b",
            r"\b(?:cyber cell|cyber crime|cyber branch)\b",
            r"\b(?:trai|telecom regulatory authority)\b",
            r"\b(?:supreme court|high court|magistrate|district court)\b",
            r"\binterpol\b",
            r"\bincome tax (?:department|officer|raid)\b",
            r"\b(?:electricity (?:board|department|office|officer)|state electricity|power department|bijli (?:office|board|vibhag))\b",
            r"\b(?:fedex|dhl|bluedart|delhivery|courier hub)\b",
            r"(?:\bदिल्ली पुलिस\b|\bसीबीआई\b|\bक्राइम ब्रांच\b|\bकस्टम्स\b|\bइनकम टैक्स\b)",
            r"\b(?:delhi|mumbai)?\s*police se bol rahe\b|\bcbi se\b",
        ],
    },
    "arrest_legal_threats": {
        "name": "Arrest, Custody & Criminal Prosecution Threats",
        "weight": 25,
        "patterns": [
            r"\b(?:digitel|digital)\s*(?:arest|arrest)\b",
            r"\b(?:arrest warrant|warrant has been issued|warrant issued|warrent|warent)\b",
            r"\b(?:under arrest|avoid arrest|evade arrest|prevent arrest|get arrested)\b",
            r"\bnon[- ]bailable warrant\b",
            r"\b(?:taken into custody|in police custody|detained|detention)\b",
            r"\b(?:intercepted|seized|confiscated).{0,35}(?:parcel|package|shipment|consignment)\b",
            r"\b(?:parcel|package|shipment|consignment).{0,35}(?:intercepted|seized|confiscated)\b",
            r"\b(?:drugs|narcotics|contraband|mdma|cocaine|illegal passports?)\b",
            r"\bparcel mein (?:drugs|charas|narcotics|ganja|illegal)\b",
            r"\bmoney laundering\b",
            r"\b(?:fir (?:lodged|registered|filed)|case registered)\b",
            r"\b(?:police|officers|team|they) (?:dispatched|on the way|reaching|are raiding|raiding)\b",
            r"\b(?:raid|raiding)\s*(?:your|ur)?\s*(?:house|home|flat|premises)\b",
            r"\b(?:legal|court|criminal)\s*(?:action|prosecution|proceeding|notice)\b",
            r"\b(?:criminal|police)\s*complaint\b",
            r"(?:\bडिजिटल अरेस्ट\b|\bवारंट\b|\bअरेस्ट वारंट\b|\bगिरफ्तार\b|\bहिरासत\b|\bमनी लॉन्ड्रिंग\b|\bअवैध पार्सल\b)",
            r"\b(?:arrest warrant nikla|arrest karenge|police ghar bhej)\b",
        ],
    },
    "financial_demands": {
        "name": "Urgent Financial Demands & Transfers",
        "weight": 25,
        "patterns": [
            r"\b(?:tranfer|trnsfer|transfer) (?:money|funds|amount|cash)\b",
            r"\b(?:tranfer|transfer) immediately\b",
            r"\b(?:deposit|send) (?:money|funds|amount|rs|inr|cash)\b",
            r"\bpay (?:the )?(?:fine|penalty|fee|charges|bail|clearance)\b",
            r"\b(?:security|verification|clearance|refundable) deposit\b",
            r"\b(?:transfer|pay|deposit|send|tranfer)\s*(?:rs\.?|inr|₹|\$)\s*[\d,]+k?\b",
            r"\b(?:send|pay|transfer)\s*[\d,]+k\s*now\b",
            r"\b(?:pay|send|transfer|deposit)\s*(?:via|through|using|to)?\s*(?:upi|rtgs|imps|wire transfer|bank transfer)\b",
            r"\b(?:pay|transfer|send)\s*(?:to\s*)?(?:upi id|vpa|upi handle)\b",
            r"\b(?:verification|clearing|reserve|safe) account\b",
            r"\b(?:file processing|registration|claim|clearance)\s*(?:fee|charge|deposit|penalty)\b",
            r"\b(?:paise|rupaye|amount)\s*(?:transfer|bhejo|bhejiye|jama karein|deposit karo)\b",
            r"\b(?:50,000|[\d,]+)\s*(?:रुपये|rupaye)\s*(?:ट्रांसफर|transfer|jama)\b",
            r"(?:\bट्रांसफर करें\b|\bजमा करें\b|\bपेनल्टी\b|\bजुर्माना\b)",
        ],
    },
    "credential_harvesting": {
        "name": "Credential & Sensitive Data Harvesting",
        "weight": 35,
        "patterns": [
            r"\b(?:otp|one[- ]time password)\b",
            r"\b(?:atm pin|upi pin|mpin|security pin)\b",
            r"\b(?:netbanking|banking|account|acount|login) (?:password|passward)\b",
            r"\b(?:cvv|cvv2|card verification value)\b",
            r"\b(?:share|send|provide|give)\s*(?:your|ur)?\s*(?:otp|pin|password|passward|credentials)\b",
            r"\b(?:credit|debit) card (?:number|details|expiry)\b",
            r"\bverify (?:your|ur)?\s*(?:kyc|bank account|pan card|aadhaar)\b",
            r"\b(?:update|link)\s*(?:your|ur)?\s*(?:pan details|pan card|aadhaar|kyc)\b",
            r"\b(?:download|install)\s*(?:our\s*)?(?:official\s*)?[a-z0-9_-]+\.apk\b",
            r"\b[a-z0-9_-]+-kyc\.apk\b|\b[a-z0-9_-]+\.apk\b",
            r"\bhttps?:\/\/(?:bit\.ly|tinyurl\.com|is\.gd|t\.me|rb\.gy|cutt\.ly)\/[a-zA-Z0-9_-]+\b",
            r"\bhttps?:\/\/[a-z0-9_-]*(?:kyc|verify|secure|update|bank|pnb|sbi|incometax)[a-z0-9_-]*\.(?:link|online|site|live|xyz|top|info)\b",
        ],
    },
    "panic_urgency_isolation": {
        "name": "Panic, Artificial Urgency & Isolation Tactics",
        "weight": 15,
        "patterns": [
            r"\b(?:immediately|urgently|right now|at once|without delay|immedately|immediatly|urjent|urgent)\b",
            r"\bwithin \d+\s*(?:minutes|mins|hours|hrs)\b",
            r"\b(?:sim|mobile number|phone line)\s*(?:will be|is)\s*(?:blocked|disconnected|deactivated|suspended)\b",
            r"\b(?:electricity|power|power supply|bijli|connection)\s*(?:will be|is)\s*(?:disconnected|cut|suspended|stopped)\b",
            r"\b(?:disconnected|cut off)\s*(?:tonight|today|within \d+)\b",
            r"\b(?:bank account|account|acount)\s*(?:has been|is|will be)\s*(?:frozen|blocked|suspended|disabled|bloked)\b",
            r"\b(?:do not|don't)\s*(?:hang up|disconnect|cut the call|tell anyone)\b",
            r"\b(?:stay on|remain on)\s*(?:the\s*)?(?:video call|skype|call)\b",
            r"\b(?:keep|turn on)\s*(?:your|ur)?\s*camera\b",
            r"\b(?:strictly confidential|secret investigation)\b",
            r"(?:\bतुरंत\b|\bturant\b|\b2 ghante mein\b|\baaj raat\b|\bcamera on\b)",
        ],
    },
    "investment_lottery_scam": {
        "name": "Fake Investment, Lottery & Job Task Fraud",
        "weight": 35,
        "patterns": [
            r"\b(?:kbc|jio|mega|festival)?\s*lucky draw\b",
            r"\b(?:won|winner of)\s*(?:rs\.?|inr|₹)?\s*[\d,]+(?:\s*lakh|\s*crore)?\b",
            r"\b(?:won a|win a)\s*(?:new\s*)?(?:car|tata safari|tata|safari|iphone|cash prize)\b",
            r"\bclaim (?:your\s*)?(?:prize|lottery|reward|vehicle|winnings)\b",
            r"\b(?:guaranteed return|100% risk free|double your money)\b",
            r"\bearn\s*(?:rs\.?|inr|₹)?\s*[\d,]+\s*(?:to\s*[\d,]+)?\s*daily\b",
            r"\b(?:part[- ]time job|work from home|video liking task|telegram task)\b",
            r"\bjoin telegram\s*(?:channel|group)?\s*(?:at\s*)?t\.me\/[a-zA-Z0-9_-]+\b",
        ],
    },
}


# ---------------------------------------------------------------------------
# Core Analysis Function
# ---------------------------------------------------------------------------

def analyze_message(message: Any) -> Dict[str, Any]:
    """
    Analyzes a text message or call transcript for scam indicators.

    Parameters:
        message (str): Text message or call transcript to evaluate.

    Returns:
        dict: Structured assessment containing:
            - risk_level (str): "LOW", "MEDIUM", or "HIGH"
            - risk_score (int): Score between 0 and 100
            - suspicious_indicators (List[str]): Detected indicator descriptions
            - explanation (str): Human-readable explanation of findings
            - recommended_action (str): Safe guidance for the user
    """
    # 1. Graceful handling of empty or invalid input
    if message is None or not isinstance(message, str) or not message.strip():
        return {
            "risk_level": "LOW",
            "risk_score": 0,
            "suspicious_indicators": [],
            "explanation": "No valid message content was provided to analyze.",
            "recommended_action": "Provide a text message or call transcript for safety evaluation.",
        }

    cleaned_text = message.strip()
    lowered_text = cleaned_text.lower()

    # 2. Check for Legitimate Informational Receipts (Bank, Utility, Tax, Merchant)
    is_legit_receipt = bool(re.search(
        r"\b(?:debited (?:by|from)|credited (?:with|to|by)|spent on your|avail(?:able)? bal(?:ance)?|payment of rs\.?\s*[\d,]+ (?:for electricity|was successfully received)|successfully verified\. acknowledgement|paid successfully to)\b",
        lowered_text
    ))
    has_coercive_verbs = bool(re.search(
        r"\b(?:pay|deposit|transfer immediately|blocked|suspended|warrant|arrest|otp|password|kyc|verify your|dispatched|disconnected tonight|seized)\b",
        lowered_text
    ))
    if is_legit_receipt and not has_coercive_verbs:
        return {
            "risk_level": "LOW",
            "risk_score": 0,
            "suspicious_indicators": [],
            "explanation": "LOW RISK: Legitimate informational transaction confirmation. No unauthorized credential requests, coercion, or scam demands detected.",
            "recommended_action": "Message appears to be an official automated receipt or transaction record. Standard monitoring recommended.",
        }

    detected_indicators: List[str] = []
    matched_categories: List[str] = []
    category_matches: Dict[str, List[str]] = {}
    raw_score = 0

    # 3. Rule evaluation across each category
    for category_key, category_data in RULES.items():
        matches_in_cat = []
        for pattern in category_data["patterns"]:
            found = re.findall(pattern, lowered_text, flags=re.IGNORECASE)
            if found:
                for match in found:
                    match_str = match if isinstance(match, str) else match[0]
                    clean_match = match_str.strip()
                    if clean_match and clean_match not in matches_in_cat:
                        matches_in_cat.append(clean_match)

        if matches_in_cat:
            matched_categories.append(category_key)
            category_matches[category_key] = matches_in_cat
            raw_score += category_data["weight"]

            # Add descriptive indicator with matched examples
            indicator_desc = (
                f"{category_data['name']} (matched: {', '.join(repr(m) for m in matches_in_cat[:3])})"
            )
            detected_indicators.append(indicator_desc)

    # Contextual check for law enforcement vs commercial courier/logistics
    has_law_enforcement = bool(re.search(
        r"\b(?:police|cbi|ed|enforcement directorate|crime branch|ncb|court|interpol|magistrate|delhi police|mumbai police)\b",
        lowered_text
    ))
    has_disconnection = bool(re.search(
        r"\b(?:disconnect|cut|block|suspend|freeze|power|bijli|sim)\b",
        lowered_text
    ))

    # 4. Synergy Bonuses for Coercive Multi-Category Combinations
    synergy_bonus = 0

    # Synergy 1: Authority + Financial demands (if law enforcement or legal threats present)
    if "authority_impersonation" in matched_categories and "financial_demands" in matched_categories:
        if has_law_enforcement or "arrest_legal_threats" in matched_categories:
            synergy_bonus += 20
        # Unverified courier clearance fees without legal threats do not receive extortion synergy

    # Synergy 2: Legal threat + Financial demands (Direct extortion)
    if "arrest_legal_threats" in matched_categories and "financial_demands" in matched_categories:
        synergy_bonus += 20

    # Synergy 3: Authority + Arrest / Legal Threat (Active Digital Arrest / Police Coercion)
    if "authority_impersonation" in matched_categories and "arrest_legal_threats" in matched_categories:
        synergy_bonus += 20

    # Synergy 4: Credential harvesting + Urgency/Threat (Phishing / Account takeover)
    if "credential_harvesting" in matched_categories and "panic_urgency_isolation" in matched_categories:
        synergy_bonus += 20

    # Synergy 5: Authority Impersonation + Credential Harvesting (Official Phishing Impersonation)
    if "authority_impersonation" in matched_categories and "credential_harvesting" in matched_categories:
        synergy_bonus += 20

    # Synergy 6: Service disconnection threat + Financial demand (Electricity bill extortion)
    if has_disconnection and "financial_demands" in matched_categories:
        synergy_bonus += 25

    # Synergy 7: Authority impersonation combined with service disconnection (TRAI/Electricity scam)
    if "authority_impersonation" in matched_categories and has_disconnection and "financial_demands" not in matched_categories:
        synergy_bonus += 15

    # Synergy 8: Investment/Lottery fraud combined with financial demand or panic
    if "investment_lottery_scam" in matched_categories and "financial_demands" in matched_categories:
        synergy_bonus += 25
    if "investment_lottery_scam" in matched_categories and "panic_urgency_isolation" in matched_categories:
        synergy_bonus += 15

    # Synergy 9: General multi-category compounding (3+ categories with arrest or credentials present)
    if len(matched_categories) >= 3 and ("arrest_legal_threats" in matched_categories or "credential_harvesting" in matched_categories):
        synergy_bonus += 10

    total_score = min(100, max(0, raw_score + synergy_bonus))

    # 5. Determine Risk Level based on calibrated thresholds
    if total_score >= 70:
        risk_level = "HIGH"
    elif total_score >= 35:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    # 6. Build Human-Readable Explanation
    if risk_level == "HIGH":
        reasons = []
        if "authority_impersonation" in matched_categories:
            reasons.append("law enforcement, utility, or agency impersonation")
        if "arrest_legal_threats" in matched_categories:
            reasons.append("threats of arrest, prosecution, or digital custody")
        if "financial_demands" in matched_categories:
            reasons.append("urgent financial transfer demands")
        if "credential_harvesting" in matched_categories:
            reasons.append("harvesting of sensitive banking credentials, OTPs, or suspicious APK links")
        if "panic_urgency_isolation" in matched_categories:
            reasons.append("high-pressure panic and isolation tactics")
        if "investment_lottery_scam" in matched_categories:
            reasons.append("advance-fee lottery, fake prize, or guaranteed-return investment fraud")

        explanation = (
            f"HIGH RISK: This communication exhibits strong hallmarks of an extortion, phishing, or advance-fee scam, "
            f"combining {', '.join(reasons)}. Legitimate government, police, or banking authorities do not "
            f"demand immediate money transfers, ask for OTPs/PINs, or place citizens under 'digital arrest'."
        )
    elif risk_level == "MEDIUM":
        reasons = []
        if "authority_impersonation" in matched_categories and has_disconnection:
            reasons.append("utility or telecom notice referencing impending disconnection")
        elif "authority_impersonation" in matched_categories and "financial_demands" in matched_categories:
            reasons.append("courier shipment clearance fee demand without legal threats")
        elif "investment_lottery_scam" in matched_categories:
            reasons.append("unsolicited part-time task or high-return investment solicitation")
        elif "financial_demands" in matched_categories:
            reasons.append("unverified financial transfer requests")
        elif "credential_harvesting" in matched_categories:
            reasons.append("requests for sensitive account verification or links")
        elif "authority_impersonation" in matched_categories:
            reasons.append("unverified authority impersonation or legal allegations")
        else:
            reasons.append("suspicious pressure terminology")

        explanation = (
            f"MEDIUM RISK: Detected suspicious patterns ({', '.join(reasons)}). "
            f"While this may not be a confirmed extortion attempt, it requests sensitive actions "
            f"or uses urgent wording that warrants strict verification before proceeding."
        )
    else:
        if detected_indicators:
            explanation = (
                "LOW RISK: Isolated keywords were identified, but the message lacks corroborating "
                "threats, financial demands, or credential requests typical of scam campaigns."
            )
        else:
            explanation = "LOW RISK: No suspicious patterns, pressure tactics, or scam indicators were detected."

    # 7. Determine Actionable Recommendation
    if risk_level == "HIGH":
        recommended_action = (
            "DO NOT transfer any funds, share OTPs, or click provided links. Disconnect immediately. "
            "Remember that 'digital arrest' is an illegal extortion tactic—police never detain people over video calls. "
            "Report this incident to the National Cyber Crime portal (cybercrime.gov.in) or call the helpline at 1930."
        )
    elif risk_level == "MEDIUM":
        recommended_action = (
            "Exercise caution. Do not click unverified links, install APKs, or share credentials. Contact the official entity "
            "directly using a known, verified phone number or official website before taking any action."
        )
    else:
        if detected_indicators:
            recommended_action = (
                "Informational or peer message. If someone is requesting money or credentials, verify their identity independently."
            )
        else:
            recommended_action = "Message appears normal. Standard cybersecurity awareness is recommended."

    return {
        "risk_level": risk_level,
        "risk_score": total_score,
        "suspicious_indicators": detected_indicators,
        "explanation": explanation,
        "recommended_action": recommended_action,
    }


# ---------------------------------------------------------------------------
# Object-Oriented Interface Wrapper
# ---------------------------------------------------------------------------

class GuardianAgent:
    """
    Guardian Agent class wrapper for integration into ScamShield AI pipelines.
    """

    def __init__(self):
        self.name = "GuardianAgent"

    def analyze(self, message: Any) -> Dict[str, Any]:
        """Runs the rule-based detection engine on the given message."""
        return analyze_message(message)


# ---------------------------------------------------------------------------
# Direct Execution Demonstration
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import json

    print("=" * 80)
    print("ScamShield AI - Guardian Agent Demonstration")
    print("Defensive Cybersecurity Prototype (Rule-Based Detection)")
    print("=" * 80)

    # Test Cases
    test_cases = [
        {
            "id": "Case A (Police Impersonation & Digital Arrest Scam)",
            "message": (
                "This is Officer Sharma from Delhi Police Crime Branch. A digital arrest warrant "
                "has been issued against your name for an illegal parcel and money laundering. "
                "Transfer Rs 50,000 immediately to the clearance account to unfreeze your identity, "
                "or police officers will be dispatched within 30 minutes. Do not disconnect the call."
            ),
        },
        {
            "id": "Case B (Normal Message from Friend)",
            "message": (
                "Hey! Are we still meeting for lunch at 1 PM today? Let me know if you want to grab coffee afterwards."
            ),
        },
        {
            "id": "Case C (Empty Input)",
            "message": "",
        },
        {
            "id": "Case D (Casual Authority Mention - Avoid False Positive)",
            "message": (
                "I was driving home and noticed the local police conducting regular traffic checks near the mall."
            ),
        },
        {
            "id": "Case E (Banking OTP Phishing)",
            "message": (
                "URGENT: Your SBI bank account will be blocked within 2 hours due to expired KYC. "
                "Share your OTP and NetBanking password immediately to avoid permanent deactivation."
            ),
        },
    ]

    for case in test_cases:
        print(f"\n--- {case['id']} ---")
        print(f"Input: {repr(case['message'])}")
        result = analyze_message(case["message"])
        print(f"Risk Level          : {result['risk_level']}")
        print(f"Risk Score          : {result['risk_score']} / 100")
        print(f"Indicators Detected : {len(result['suspicious_indicators'])}")
        for ind in result["suspicious_indicators"]:
            print(f"  * {ind}")
        print(f"Explanation         : {result['explanation']}")
        print(f"Recommended Action  : {result['recommended_action']}")

    print("\n" + "=" * 80)
    print("Demonstration completed successfully.")
    print("=" * 80)
