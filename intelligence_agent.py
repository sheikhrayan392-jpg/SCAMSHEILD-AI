"""
ScamShield AI - Intelligence Agent (Part 3)
===========================================
Defensive cybersecurity threat intelligence extractor designed to analyze
conversation transcripts generated during simulated scam interactions (such as
those from the Decoy Agent).

Extracts and organizes:
- Identifiers: Phone numbers, UPI IDs, bank references
- Unverified Claims: Claimed names, departments, badge IDs, demanded amounts
- Observed Tactics: Coercive tactics, legal intimidation, urgency, video pressure
- Gap Analysis: Missing authentications (lack of official email, FIR doc, verified ID)
- Actionable Recommendations: Safe next steps for reporting and evidence preservation

SAFETY & COMPLIANCE NOTICE:
---------------------------
- UNVERIFIED INTELLIGENCE ONLY: All names, numbers, credentials, and affiliations
  extracted are unverified caller claims. They must NEVER be treated as confirmed
  facts or used to label any individual as a criminal without official investigation.
- SIMULATION PROTOCOL: Developed strictly for educational and defense prototype purposes.
- NO EXTERNAL ACTIONS: Never transmits reports, contacts targets, or accesses accounts.
- NO SENSITIVE DATA STORAGE: Never extracts or stores OTPs, PINs, or real credentials.
"""

import re
import uuid
from datetime import datetime
from typing import Dict, List, Any, Optional


# ---------------------------------------------------------------------------
# Regex Patterns for Entity Extraction
# ---------------------------------------------------------------------------

PATTERNS = {
    # UPI IDs (e.g., police.clearance@sbi, officer9482@icici, helpdesk@paytm)
    "upi_id": re.compile(
        r"\b([a-zA-Z0-9.\-_]{2,50}@[a-zA-Z]{2,20})\b", re.IGNORECASE
    ),

    # Phone numbers (Indian mobile and landline patterns)
    "phone": re.compile(
        r"(?:\+91[\s-]?)?[6-9]\d{9}\b|\b0\d{2,4}[\s-]?\d{6,8}\b"
    ),

    # Bank account references & IFSC codes
    "bank_account": re.compile(
        r"\b(?:account|acct|a/c)\s*(?:no\.?|number)?\s*[:#-]?\s*(\d{9,18})\b", re.IGNORECASE
    ),
    "ifsc_code": re.compile(
        r"\b([A-Z]{4}0[A-Z0-9]{6})\b"
    ),
    "bank_name": re.compile(
        r"\b(sbi|state bank of india|hdfc|icici|axis bank|punjab national bank|pnb|canara bank|bank of baroda|rbi|reserve bank of india)\b",
        re.IGNORECASE,
    ),

    # Badge IDs (e.g., Badge #DL-9482, Badge ID: POL-104)
    "badge_id": re.compile(
        r"\b(?:badge|badge id|officer id)\s*(?:no\.?|number)?\s*[:#]?\s*([A-Za-z0-9\-]{4,15})\b",
        re.IGNORECASE,
    ),

    # Claimed Official Names (strictly title-cased names following official rank)
    "claimed_name": re.compile(
        r"(?i:\b(?:inspector|officer|sub-inspector|si|dsp|sp|acp|dcp|constable|advocate|judge)\s+)([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)\b"
    ),

    # Claimed Departments & Agencies
    "department": re.compile(
        r"\b(delhi police|mumbai police|cyber crime branch|cyber cell|new delhi cyber cell|cbi|central bureau of investigation|enforcement directorate|ed|customs(?: department)?|narcotics control bureau|ncb|trai|supreme court|high court|crime branch|fedex|dhl)\b",
        re.IGNORECASE,
    ),

    # Demanded Financial Amounts (including Rs, INR, Rupees, and Hinglish Rupaye)
    "amount": re.compile(
        r"(?:rs\.?|inr|₹|\$)\s*([\d,]+k?(?:\.\d{2})?)\b|\b([\d,]+k?)\s*(?:rupees|rupaye|inr|rs)\b",
        re.IGNORECASE,
    ),
}

# Tactic Definitions with targeted keyword checks
TACTIC_RULES = {
    "Authority Impersonation": {
        "regex": r"\b(police|cbi|ed|crime branch|cyber cell|customs|ncb|inspector|officer|magistrate|trai)\b",
        "desc": "Claimed affiliation with law enforcement, judicial, or regulatory bodies.",
    },
    "Arrest & Custody Threat": {
        "regex": r"\b(digital arrest|arrest warrant|custody|warrant issued|under arrest|narcotics|contraband|money laundering)\b",
        "desc": "Intimidation through threats of immediate arrest, detention, or criminal case.",
    },
    "Urgent Financial Demand": {
        "regex": r"\b(transfer|pay|deposit|security deposit|clearance account|penalty|fine|fee)\b",
        "desc": "Coercive demand for immediate money transfer or clearance deposit.",
    },
    "Artificial Urgency & Coercion": {
        "regex": r"\b(immediately|right now|within \d+|do not hang up|do not disconnect|urgent|without delay)\b",
        "desc": "High-pressure tactics designed to induce panic and prevent consultation.",
    },
    "Surveillance / Video Intimidation": {
        "regex": r"\b(video camera|keep.*camera|turn on.*camera|video call|skype)\b",
        "desc": "Demanding continuous video surveillance under guise of 'digital custody'.",
    },
    "Credential Harvesting": {
        "regex": r"\b(otp|one[- ]time password|pin|password|cvv)\b",
        "desc": "Attempting to obtain authentication credentials or banking security codes.",
    },
}


# ---------------------------------------------------------------------------
# Helper Extraction Functions
# ---------------------------------------------------------------------------

def _extract_snippets(text: str, regex: re.Pattern) -> List[Dict[str, str]]:
    """Finds matches and pairs each with its surrounding sentence evidence."""
    results = []
    seen = set()

    # Split text into sentences for evidence extraction
    sentences = re.split(r"(?<=[.!?\n])\s+", text)

    for match in regex.finditer(text):
        # Determine the matched string
        groups = [g for g in match.groups() if g is not None]
        val = groups[0].strip() if groups else match.group(0).strip()
        # Clean up any trailing prepositions
        val = re.sub(r"\s+(?:from|of|at|in|with|here)$", "", val, flags=re.IGNORECASE).strip()

        if not val or val.lower() in seen:
            continue
        seen.add(val.lower())

        # Locate sentence containing the match for original context
        evidence_sentence = text
        for s in sentences:
            if val.lower() in s.lower():
                evidence_sentence = s.strip()
                break

        results.append({
            "value": val,
            "evidence_quote": evidence_sentence,
        })

    return results


def _extract_tactics(text: str) -> List[Dict[str, str]]:
    """Identifies observed tactics and extracts the exact evidence sentence."""
    detected = []
    sentences = re.split(r"(?<=[.!?\n])\s+", text)

    for tactic_name, tactic_info in TACTIC_RULES.items():
        pattern = re.compile(tactic_info["regex"], re.IGNORECASE)
        for s in sentences:
            if pattern.search(s):
                detected.append({
                    "tactic": tactic_name,
                    "confidence": "HIGH",
                    "details": tactic_info["desc"],
                    "evidence_quote": s.strip(),
                })
                break  # Record once per tactic

    return detected


# ---------------------------------------------------------------------------
# Core Intelligence Extraction Function
# ---------------------------------------------------------------------------

def extract_intelligence(conversation_history: Any) -> Dict[str, Any]:
    """
    Analyzes conversation history from the Decoy Agent and produces a
    structured intelligence report with supporting quotes and risk analysis.

    Parameters:
        conversation_history (list): Transcript list containing turn dictionaries.

    Returns:
        dict: Comprehensive intelligence report structured for dashboard display.
    """
    timestamp = datetime.now().isoformat()
    report_id = f"RPT-{datetime.now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"

    # 1. Gracefully handle empty or malformed conversation history
    if not conversation_history or not isinstance(conversation_history, list):
        report = {
            "report_id": report_id,
            "timestamp": timestamp,
            "status": "EMPTY_CONVERSATION",
            "conversation_summary": {
                "total_turns": 0,
                "caller_messages_analyzed": 0,
                "decoy_messages_included": 0,
                "primary_threat_type": "None",
                "executive_summary": "No conversation history was provided to analyze.",
            },
            "unverified_caller_claims": {
                "claimed_names": "Not found",
                "claimed_departments": "Not found",
                "claimed_badge_ids": "Not found",
                "claimed_payment_amounts": "Not found",
            },
            "extracted_indicators": {
                "upi_ids": "Not found",
                "phone_numbers": "Not found",
                "bank_accounts": "Not found",
                "ifsc_codes": "Not found",
            },
            "detected_tactics": [],
            "risk_assessment": {
                "risk_level": "LOW",
                "risk_score": 0,
                "rationale": "Empty or invalid conversation transcript provided.",
            },
            "missing_information": [
                "Full conversation history is missing.",
            ],
            "recommended_next_steps": [
                "Provide a valid conversation transcript from the Decoy Agent to generate an intelligence report.",
            ],
            "formatted_text_report": "",
            "simulation_disclaimer": (
                "SIMULATION INTELLIGENCE REPORT: Educational defensive cybersecurity prototype. "
                "All items represent unverified claims within a simulation environment."
            ),
        }
        report["formatted_text_report"] = format_text_report(report)
        return report

    # 2. Separate and aggregate caller (scammer) vs decoy messages
    caller_messages: List[str] = []
    decoy_messages: List[str] = []

    for entry in conversation_history:
        if isinstance(entry, dict):
            role = entry.get("role", "").lower()
            msg = str(entry.get("message", "")).strip()
            if not msg:
                continue
            if role in ["scammer", "caller", "suspect"]:
                caller_messages.append(msg)
            elif role in ["decoy", "victim", "user"]:
                decoy_messages.append(msg)
            else:
                # Default unknown roles to caller for intelligence parsing
                caller_messages.append(msg)

    # If no caller messages were specifically flagged, analyze all messages
    combined_caller_text = " ".join(caller_messages) if caller_messages else " ".join(decoy_messages)
    full_conversation_text = " ".join([str(e.get("message", "")) for e in conversation_history if isinstance(e, dict)])

    # 3. Extract Unverified Caller Claims (Strictly from input text)
    claimed_names = _extract_snippets(combined_caller_text, PATTERNS["claimed_name"])
    claimed_depts = _extract_snippets(combined_caller_text, PATTERNS["department"])
    claimed_badges = _extract_snippets(combined_caller_text, PATTERNS["badge_id"])
    claimed_amounts = _extract_snippets(combined_caller_text, PATTERNS["amount"])

    # 4. Extract Actionable Indicators
    upi_ids = _extract_snippets(combined_caller_text, PATTERNS["upi_id"])
    phone_numbers = _extract_snippets(combined_caller_text, PATTERNS["phone"])
    bank_accounts = _extract_snippets(combined_caller_text, PATTERNS["bank_account"])
    ifsc_codes = _extract_snippets(combined_caller_text, PATTERNS["ifsc_code"])

    # Filter out potential email false positives from UPI if domain has standard email TLD like .com
    # Keep typical banking VPA extensions (e.g., @sbi, @icici, @paytm, @okaxis)
    filtered_upi = []
    for item in upi_ids:
        val = item["value"]
        # Valid UPI format: handle@provider
        if not val.endswith((".com", ".org", ".net", ".edu")):
            filtered_upi.append(item)
        elif "upi" in item["evidence_quote"].lower() or "pay" in item["evidence_quote"].lower():
            filtered_upi.append(item)

    # 5. Extract Tactics & Evidence
    detected_tactics = _extract_tactics(combined_caller_text)

    # 6. Gap Analysis: Missing Information
    # In fraud investigations, identifying what the caller FAILED to provide is vital
    missing_info: List[str] = []
    if not claimed_badges:
        missing_info.append("Official police or agency badge / identification number")
    if not ifsc_codes and not bank_accounts:
        missing_info.append("Official department treasury account or IFSC code")
    if not phone_numbers:
        missing_info.append("Originating caller telephone number or official landline")
    missing_info.append("Official government domain email verification (@gov.in or @nic.in)")
    missing_info.append("Formal court FIR registration docket or signed physical notice")

    # 7. Risk Assessment & Threat Classification
    score = 0
    if claimed_depts:
        score += 20
    if any(t["tactic"] == "Arrest & Custody Threat" for t in detected_tactics):
        score += 25
    if claimed_amounts or any(t["tactic"] == "Urgent Financial Demand" for t in detected_tactics):
        score += 25
    if filtered_upi:
        score += 15
    if any(t["tactic"] == "Artificial Urgency & Coercion" for t in detected_tactics):
        score += 15

    total_risk_score = min(100, max(0, score))
    if total_risk_score >= 70:
        risk_level = "HIGH"
        primary_threat = "Digital Arrest & Financial Extortion"
        rationale = (
            "High-risk multi-indicator extortion attempt combining authority impersonation, "
            "threats of digital arrest, urgent financial demands, and unverified digital payment channels."
        )
    elif total_risk_score >= 35:
        risk_level = "MEDIUM"
        primary_threat = "Suspicious Impersonation / Pressure Solicitation"
        rationale = (
            "Moderate risk indicators detected. Communication exhibits pressure tactics or unverified "
            "identity claims without definitive confirmation of financial fraud."
        )
    else:
        risk_level = "LOW"
        primary_threat = "Informational / Low Threat"
        rationale = "Minimal or isolated suspicious indicators found in the conversation transcript."

    # 8. Executive Summary Generation
    summary_parts = []
    if claimed_depts:
        summary_parts.append(f"Caller claimed affiliation with {', '.join(d['value'].title() for d in claimed_depts)}")
    if any(t["tactic"] == "Arrest & Custody Threat" for t in detected_tactics):
        summary_parts.append("threatened the recipient with arrest or criminal prosecution")
    if claimed_amounts:
        summary_parts.append(f"demanded payment of {', '.join(a['value'] for a in claimed_amounts)}")
    if filtered_upi:
        summary_parts.append(f"directed funds to UPI handle ({', '.join(u['value'] for u in filtered_upi)})")

    if summary_parts:
        exec_summary = "; ".join(summary_parts) + "."
    else:
        exec_summary = "Conversation transcript analyzed; no high-pressure coercion or financial demands detected."

    # 9. Recommended Defensive Next Steps
    recommended_steps: List[str] = []
    if filtered_upi:
        for u in filtered_upi:
            recommended_steps.append(
                f"DO NOT transfer any funds to the unverified UPI ID: {u['value']}."
            )
        recommended_steps.append(
            "Report the flagged UPI ID to the National Payments Corporation of India (NPCI) and your bank."
        )
    if risk_level == "HIGH":
        recommended_steps.append(
            "File an official complaint on the National Cyber Crime Reporting Portal (cybercrime.gov.in) "
            "or contact the national cyber helpline at 1930."
        )
        recommended_steps.append(
            "Preserve this complete conversation transcript, timestamps, and caller evidence for law enforcement."
        )
    elif risk_level == "MEDIUM":
        recommended_steps.append(
            "Independently verify the caller's credentials through official publicly listed phone numbers."
        )
        recommended_steps.append("Never share OTPs, banking credentials, or personal identity documents.")
    else:
        recommended_steps.append("No immediate defensive action required. Maintain standard cybersecurity awareness.")

    # 10. Assemble Final Structured Report
    report: Dict[str, Any] = {
        "report_id": report_id,
        "timestamp": timestamp,
        "status": "ANALYSIS_COMPLETE",
        "conversation_summary": {
            "total_turns": len(conversation_history),
            "caller_messages_analyzed": len(caller_messages),
            "decoy_messages_included": len(decoy_messages),
            "primary_threat_type": primary_threat,
            "executive_summary": exec_summary,
        },
        "unverified_caller_claims": {
            "claimed_names": claimed_names if claimed_names else "Not found",
            "claimed_departments": claimed_depts if claimed_depts else "Not found",
            "claimed_badge_ids": claimed_badges if claimed_badges else "Not found",
            "claimed_payment_amounts": claimed_amounts if claimed_amounts else "Not found",
        },
        "extracted_indicators": {
            "upi_ids": filtered_upi if filtered_upi else "Not found",
            "phone_numbers": phone_numbers if phone_numbers else "Not found",
            "bank_accounts": bank_accounts if bank_accounts else "Not found",
            "ifsc_codes": ifsc_codes if ifsc_codes else "Not found",
        },
        "detected_tactics": detected_tactics,
        "risk_assessment": {
            "risk_level": risk_level,
            "risk_score": total_risk_score,
            "rationale": rationale,
        },
        "missing_information": missing_info,
        "recommended_next_steps": recommended_steps,
        "simulation_disclaimer": (
            "SIMULATION INTELLIGENCE REPORT: Educational cybersecurity prototype demonstration. "
            "Extracted details are unverified caller claims and do not constitute legal proof."
        ),
    }

    # Generate readable text report and attach to dict
    report["formatted_text_report"] = format_text_report(report)
    return report


# ---------------------------------------------------------------------------
# Human-Readable Text Report Formatter
# ---------------------------------------------------------------------------

def format_text_report(report: Dict[str, Any]) -> str:
    """Formats the structured intelligence dictionary into an executive ASCII report."""
    lines = []
    sep = "=" * 80
    subsep = "-" * 80

    lines.append(sep)
    lines.append("SCAMSHIELD AI - DEFENSIVE CYBER THREAT INTELLIGENCE REPORT")
    lines.append("CONFIDENTIALITY: SIMULATION / DEFENSIVE RESEARCH PROTOTYPE")
    lines.append(sep)

    lines.append(f"Report ID       : {report.get('report_id', 'N/A')}")
    lines.append(f"Generated At    : {report.get('timestamp', 'N/A')}")
    lines.append(f"Analysis Status : {report.get('status', 'N/A')}")

    # Risk Assessment
    risk = report.get("risk_assessment", {})
    lines.append(subsep)
    lines.append("1. THREAT & RISK ASSESSMENT")
    lines.append(subsep)
    lines.append(f"Risk Level      : {risk.get('risk_level', 'UNKNOWN')}")
    lines.append(f"Risk Score      : {risk.get('risk_score', 0)} / 100")
    lines.append(f"Primary Threat  : {report.get('conversation_summary', {}).get('primary_threat_type', 'None')}")
    lines.append(f"Rationale       : {risk.get('rationale', 'N/A')}")

    # Executive Summary
    summary = report.get("conversation_summary", {})
    lines.append(subsep)
    lines.append("2. CONVERSATION SUMMARY")
    lines.append(subsep)
    lines.append(f"Total Turns     : {summary.get('total_turns', 0)} (Caller: {summary.get('caller_messages_analyzed', 0)}, Decoy: {summary.get('decoy_messages_included', 0)})")
    lines.append(f"Executive Summary:\n  {summary.get('executive_summary', 'N/A')}")

    # Unverified Caller Claims
    claims = report.get("unverified_caller_claims", {})
    lines.append(subsep)
    lines.append("3. UNVERIFIED CALLER CLAIMS (EVIDENCE PRESERVED)")
    lines.append(subsep)

    def _format_claim_section(label: str, items: Any):
        lines.append(f"{label}:")
        if isinstance(items, list) and items:
            for it in items:
                lines.append(f"  * Value : {it['value']}")
                lines.append(f"    Quote : \"{it['evidence_quote']}\"")
        else:
            lines.append("  * Not found")

    _format_claim_section("Claimed Official Names", claims.get("claimed_names"))
    _format_claim_section("Claimed Departments/Agencies", claims.get("claimed_departments"))
    _format_claim_section("Claimed Badge IDs", claims.get("claimed_badge_ids"))
    _format_claim_section("Demanded Payment Amounts", claims.get("claimed_payment_amounts"))

    # Extracted Actionable Indicators
    indicators = report.get("extracted_indicators", {})
    lines.append(subsep)
    lines.append("4. EXTRACTED ACTIONABLE INDICATORS")
    lines.append(subsep)
    _format_claim_section("Flagged UPI IDs", indicators.get("upi_ids"))
    _format_claim_section("Flagged Phone Numbers", indicators.get("phone_numbers"))
    _format_claim_section("Bank Accounts", indicators.get("bank_accounts"))
    _format_claim_section("IFSC Codes", indicators.get("ifsc_codes"))

    # Observed Tactics
    tactics = report.get("detected_tactics", [])
    lines.append(subsep)
    lines.append("5. OBSERVED SCAM TACTICS")
    lines.append(subsep)
    if tactics:
        for t in tactics:
            lines.append(f"  * [{t['tactic']}] - Confidence: {t['confidence']}")
            lines.append(f"    Evidence : \"{t['evidence_quote']}\"")
    else:
        lines.append("  * No coercive or pressure tactics detected.")

    # Gap Analysis
    missing = report.get("missing_information", [])
    lines.append(subsep)
    lines.append("6. GAP ANALYSIS (MISSING OFFICIAL CREDENTIALS)")
    lines.append(subsep)
    for m in missing:
        lines.append(f"  [!] Missing: {m}")

    # Recommended Next Steps
    steps = report.get("recommended_next_steps", [])
    lines.append(subsep)
    lines.append("7. RECOMMENDED DEFENSIVE NEXT STEPS")
    lines.append(subsep)
    for idx, s in enumerate(steps, 1):
        lines.append(f"  {idx}. {s}")

    lines.append(sep)
    lines.append(f"DISCLAIMER: {report.get('simulation_disclaimer', '')}")
    lines.append(sep)

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Object-Oriented Wrapper
# ---------------------------------------------------------------------------

class IntelligenceAgent:
    """
    Intelligence Agent class wrapper for pipeline integration.
    """

    def __init__(self):
        self.name = "IntelligenceAgent"

    def analyze(self, conversation_history: Any) -> Dict[str, Any]:
        """Generates an intelligence report from conversation history."""
        return extract_intelligence(conversation_history)


# ---------------------------------------------------------------------------
# Direct Execution Demonstration & Test Suite
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 80)
    print("ScamShield AI - Intelligence Agent Demonstration & Test Suite")
    print("Defensive Cyber Threat Intelligence Extractor")
    print("=" * 80)

    agent = IntelligenceAgent()

    # -----------------------------------------------------------------------
    # Test Case 1: Multi-turn Police Impersonation with UPI & Extortion
    # -----------------------------------------------------------------------
    test_case_1 = [
        {
            "turn": 1,
            "role": "scammer",
            "message": "This is Inspector Vikram Rathore from Delhi Police Cyber Crime Branch. A digital arrest warrant has been issued in your name for illegal narcotics tracking. Do not hang up or officers will reach your residence!",
        },
        {
            "turn": 1,
            "role": "decoy",
            "message": "Oh God, please don't arrest me! I will cooperate fully. Could you please tell me your officer badge ID?",
        },
        {
            "turn": 2,
            "role": "scammer",
            "message": "I am Officer Vikram, Badge #DL-9482, New Delhi Cyber Cell. You must immediately pay a security deposit of Rs 75,000 to the court clearance account to freeze the arrest warrant, or you will be taken into custody in 1 hour.",
        },
        {
            "turn": 2,
            "role": "decoy",
            "message": "I noted your badge ID, officer. Exactly which UPI ID or bank account should I send the payment to?",
        },
        {
            "turn": 3,
            "role": "scammer",
            "message": "Send Rs 75,000 right now to our RBI clearing UPI ID: police.clearance@sbi. Transfer it immediately and keep your video camera turned on.",
        },
    ]

    # -----------------------------------------------------------------------
    # Test Case 2: Conversation without UPI ID or Phone Number
    # -----------------------------------------------------------------------
    test_case_2 = [
        {
            "turn": 1,
            "role": "scammer",
            "message": "This is Officer Sharma from Crime Branch. Your identity was found in an illegal shipment. Pay the fine immediately or face court action.",
        },
        {
            "turn": 1,
            "role": "decoy",
            "message": "Sir, which court is this? How can I pay?",
        },
    ]

    # -----------------------------------------------------------------------
    # Test Case 3: Empty Conversation History
    # -----------------------------------------------------------------------
    test_case_3 = []

    # Run and verify tests
    tests = [
        ("TEST 1: Digital Arrest Extortion with Police Claims & UPI", test_case_1),
        ("TEST 2: Threat Conversation Without UPI or Phone Number", test_case_2),
        ("TEST 3: Empty Conversation History", test_case_3),
    ]

    test_results = []

    for test_name, history in tests:
        print(f"\n{'#' * 80}")
        print(f"RUNNING: {test_name}")
        print(f"{'#' * 80}")

        report = agent.analyze(history)
        print(report["formatted_text_report"])

        # Automatic Assertions
        passed = True
        failure_reasons = []

        if test_name.startswith("TEST 1"):
            # Check UPI extracted
            upi_found = any(
                item["value"] == "police.clearance@sbi"
                for item in (report["extracted_indicators"]["upi_ids"] if isinstance(report["extracted_indicators"]["upi_ids"], list) else [])
            )
            if not upi_found:
                passed = False
                failure_reasons.append("Failed to extract UPI ID 'police.clearance@sbi'")

            # Check Badge extracted
            badge_found = any(
                item["value"] == "DL-9482"
                for item in (report["unverified_caller_claims"]["claimed_badge_ids"] if isinstance(report["unverified_caller_claims"]["claimed_badge_ids"], list) else [])
            )
            if not badge_found:
                passed = False
                failure_reasons.append("Failed to extract Badge ID 'DL-9482'")

            # Check Amount extracted
            amount_found = any(
                "75,000" in item["value"]
                for item in (report["unverified_caller_claims"]["claimed_payment_amounts"] if isinstance(report["unverified_caller_claims"]["claimed_payment_amounts"], list) else [])
            )
            if not amount_found:
                passed = False
                failure_reasons.append("Failed to extract Demanded Amount '75,000'")

            # Check Risk Level is HIGH
            if report["risk_assessment"]["risk_level"] != "HIGH":
                passed = False
                failure_reasons.append(f"Expected HIGH risk level, got {report['risk_assessment']['risk_level']}")

        elif test_name.startswith("TEST 2"):
            # Should have "Not found" for UPI and Phone
            if report["extracted_indicators"]["upi_ids"] != "Not found":
                passed = False
                failure_reasons.append(f"Expected 'Not found' for UPI ID, got {report['extracted_indicators']['upi_ids']}")
            if report["extracted_indicators"]["phone_numbers"] != "Not found":
                passed = False
                failure_reasons.append(f"Expected 'Not found' for Phone, got {report['extracted_indicators']['phone_numbers']}")

        elif test_name.startswith("TEST 3"):
            # Empty should return EMPTY_CONVERSATION and LOW risk
            if report["status"] != "EMPTY_CONVERSATION":
                passed = False
                failure_reasons.append(f"Expected status 'EMPTY_CONVERSATION', got {report['status']}")
            if report["risk_assessment"]["risk_level"] != "LOW":
                passed = False
                failure_reasons.append(f"Expected risk_level 'LOW', got {report['risk_assessment']['risk_level']}")

        test_results.append((test_name, passed, failure_reasons))

    # Summary of Test Execution
    print("\n" + "=" * 80)
    print("INTELLIGENCE AGENT TEST EXECUTION SUMMARY")
    print("=" * 80)
    all_passed = True
    for name, passed, reasons in test_results:
        status_str = "PASSED [OK]" if passed else "FAILED [X]"
        print(f"  * {name}: {status_str}")
        if not passed:
            all_passed = False
            for r in reasons:
                print(f"      - Reason: {r}")

    print("-" * 80)
    if all_passed:
        print("ALL TESTS PASSED SUCCESSFULLY! Ready for dashboard integration.")
    else:
        print("SOME TESTS FAILED.")
    print("=" * 80)
