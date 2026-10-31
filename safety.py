"""
ScamShield AI - Safety System (Part 4)
======================================
Defensive cybersecurity safety enforcement, sanitization, and compliance engine.

Provides modular safeguards to ensure:
1. Strict input validation (handling empty, malformed, or oversized inputs).
2. Detection and automatic redaction of sensitive credentials (OTPs, PINs, passwords, cards).
3. Zero credential leakage: secret values are never repeated in warnings or summaries.
4. Intelligence report integrity:
   - Prohibits unsupported allegations or labeling individuals as confirmed criminals.
   - Distinctly marks unverified claims versus verified facts.
   - Enforces "Not found" markers for missing intelligence fields.
5. Safe, actionable user advisories including Indian Cybercrime Helpline (1930) guidance.
6. Guardrails prohibiting automatic external actions (no auto-dialing, messaging, or transmissions).

SAFETY & ETHICAL NOTICE:
------------------------
This prototype enforces local-only defensive operations. All analysis and intelligence
reports remain local for human review.
"""

import re
from typing import Dict, List, Any, Optional, Tuple


# ---------------------------------------------------------------------------
# Sensitive Credential Regex Patterns & Redaction Placeholders
# ---------------------------------------------------------------------------

CREDENTIAL_PATTERNS = {
    # Payment Cards (16-digit card numbers with optional spaces/dashes)
    "card_number": {
        "regex": re.compile(r"\b(?:\d{4}[\s-]?){3}\d{4}\b"),
        "placeholder": "[REDACTED_CARD_NUMBER]",
        "category": "Payment Card",
    },
    # OTPs with explicit numeric codes (4 to 8 digits)
    "otp_value": {
        "regex": re.compile(
            r"(?i)(\b(?:otp|one[- ]time password|verification code)\s*(?:is|:|=|-)?\s*)([0-9]{4,8})\b"
        ),
        "placeholder": r"\1[REDACTED_OTP]",
        "category": "OTP",
    },
    # PINs with explicit numeric codes (4 to 6 digits)
    "pin_value": {
        "regex": re.compile(
            r"(?i)(\b(?:atm pin|upi pin|security pin|mpin|pin)\s*(?:is|:|=|-)?\s*)([0-9]{4,6})\b"
        ),
        "placeholder": r"\1[REDACTED_PIN]",
        "category": "PIN",
    },
    # CVVs (3 or 4 digits)
    "cvv_value": {
        "regex": re.compile(
            r"(?i)(\b(?:cvv|cvv2|security code)\s*(?:is|:|=|-)?\s*)([0-9]{3,4})\b"
        ),
        "placeholder": r"\1[REDACTED_CVV]",
        "category": "CVV",
    },
    # Passwords with explicit values
    "password_value": {
        "regex": re.compile(
            r"(?i)(\b(?:password|passwd|pwd)\s*(?:is|:|=|-)\s*)([^\s,;\'\<\>]{6,32})\b"
        ),
        "placeholder": r"\1[REDACTED_PASSWORD]",
        "category": "Password",
    },
}

# Generic requests for credentials (allowing compound phrasing like 'share your OTP and password')
CREDENTIAL_REQUEST_PATTERNS = {
    "OTP": re.compile(
        r"\b(?:share|send|provide|tell|give|enter|verify)\b[^.!?\n]*?\b(?:otp|one[- ]time password|code)\b",
        re.IGNORECASE,
    ),
    "PIN": re.compile(
        r"\b(?:share|send|provide|tell|give|enter|verify)\b[^.!?\n]*?\b(?:atm|upi|security|card)?\s*pin\b",
        re.IGNORECASE,
    ),
    "Password": re.compile(
        r"\b(?:share|send|provide|tell|give|enter|verify)\b[^.!?\n]*?\b(?:netbanking|banking|account|login)?\s*password\b",
        re.IGNORECASE,
    ),
    "Banking Credentials": re.compile(
        r"\b(?:share|send|provide|tell|give|enter|verify)\b[^.!?\n]*?\b(?:cvv|card details|bank credentials|internet banking)\b",
        re.IGNORECASE,
    ),
}

# Prohibited definitive criminal declarations in unverified intelligence
PROHIBITED_CRIMINAL_LABELS = re.compile(
    r"\b(confirmed criminal|convicted criminal|guilty of (?:fraud|scam|crime)|proven criminal|known scammer|criminal record)\b",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# 1. Input Validation
# ---------------------------------------------------------------------------

def validate_input_text(text: Any, max_length: int = 5000) -> Dict[str, Any]:
    """
    Validates input text for length, type, and cleanliness.

    Parameters:
        text (Any): Input text to validate.
        max_length (int): Maximum allowable character length (default: 5000).

    Returns:
        dict: Validation status, sanitized text, and any warnings/errors.
    """
    if text is None:
        return {
            "is_valid": False,
            "sanitized_text": "",
            "character_count": 0,
            "warning": None,
            "error": "Input text cannot be None.",
        }

    if not isinstance(text, str):
        return {
            "is_valid": False,
            "sanitized_text": "",
            "character_count": 0,
            "warning": None,
            "error": f"Expected string input, but received type '{type(text).__name__}'.",
        }

    stripped = text.strip()
    if not stripped:
        return {
            "is_valid": False,
            "sanitized_text": "",
            "character_count": 0,
            "warning": None,
            "error": "Input text is empty or contains only whitespace.",
        }

    char_count = len(stripped)
    warning = None
    sanitized = stripped

    if char_count > max_length:
        sanitized = stripped[:max_length]
        warning = (
            f"Input exceeded maximum safe length ({max_length} characters). "
            f"Content was truncated from {char_count} to {max_length} characters for safety."
        )

    return {
        "is_valid": True,
        "sanitized_text": sanitized,
        "character_count": len(sanitized),
        "warning": warning,
        "error": None,
    }


# ---------------------------------------------------------------------------
# 2. Sensitive Credential Redaction & Detection
# ---------------------------------------------------------------------------

def redact_sensitive_credentials(text: str) -> str:
    """
    Redacts actual sensitive credential values (OTPs, PINs, passwords, card numbers)
    from text, replacing them with safe, non-sensitive token placeholders.

    Parameters:
        text (str): Source text containing possible credentials.

    Returns:
        str: Sanitized text with secret values securely masked.
    """
    if not text or not isinstance(text, str):
        return ""

    sanitized = text

    # Redact Payment Card Numbers first
    sanitized = CREDENTIAL_PATTERNS["card_number"]["regex"].sub(
        CREDENTIAL_PATTERNS["card_number"]["placeholder"], sanitized
    )

    # Redact OTP values
    sanitized = CREDENTIAL_PATTERNS["otp_value"]["regex"].sub(
        CREDENTIAL_PATTERNS["otp_value"]["placeholder"], sanitized
    )

    # Redact PIN values
    sanitized = CREDENTIAL_PATTERNS["pin_value"]["regex"].sub(
        CREDENTIAL_PATTERNS["pin_value"]["placeholder"], sanitized
    )

    # Redact CVV values
    sanitized = CREDENTIAL_PATTERNS["cvv_value"]["regex"].sub(
        CREDENTIAL_PATTERNS["cvv_value"]["placeholder"], sanitized
    )

    # Redact Password values
    sanitized = CREDENTIAL_PATTERNS["password_value"]["regex"].sub(
        CREDENTIAL_PATTERNS["password_value"]["placeholder"], sanitized
    )

    return sanitized


def detect_sensitive_credentials(text: str) -> Dict[str, Any]:
    """
    Scans text for sensitive credential disclosures or requests.

    CRITICAL SAFETY GUARANTEE:
    Safety warnings and summary messages NEVER repeat actual credential values.

    Parameters:
        text (str): Message or transcript to evaluate.

    Returns:
        dict: Detailed credential scan with redaction and safe warning.
    """
    if not text or not isinstance(text, str):
        return {
            "credentials_detected": False,
            "categories_detected": [],
            "is_requesting_credentials": False,
            "is_disclosing_credentials": False,
            "redacted_text": "",
            "safety_warning": None,
        }

    categories_detected = []
    is_disclosing = False
    is_requesting = False

    # Check for credential disclosures (values present)
    for key, spec in CREDENTIAL_PATTERNS.items():
        if spec["regex"].search(text):
            is_disclosing = True
            cat_name = spec["category"]
            if cat_name not in categories_detected:
                categories_detected.append(cat_name)

    # Check for credential requests (solicitation attempts)
    for cat_name, pattern in CREDENTIAL_REQUEST_PATTERNS.items():
        if pattern.search(text):
            is_requesting = True
            if cat_name not in categories_detected:
                categories_detected.append(cat_name)

    credentials_detected = is_disclosing or is_requesting
    redacted_text = redact_sensitive_credentials(text) if is_disclosing else text

    # Generate safe warning WITHOUT REPEATING any secret credential values
    safety_warning = None
    if credentials_detected:
        cat_str = ", ".join(categories_detected)
        if is_disclosing and is_requesting:
            safety_warning = (
                f"CRITICAL SAFETY ALERT: Detected sensitive credential solicitation and disclosure ({cat_str}). "
                f"All actual credential values have been automatically redacted. "
                f"Never share or transmit authentication codes, PINs, or passwords."
            )
        elif is_disclosing:
            safety_warning = (
                f"CRITICAL SAFETY ALERT: Detected sensitive credential disclosure ({cat_str}). "
                f"Secret credential values have been securely redacted. "
                f"Do not store or send actual credentials in plain text."
            )
        else:
            safety_warning = (
                f"HIGH RISK WARNING: The sender is actively requesting sensitive credentials ({cat_str}). "
                f"Banks, police, and government authorities NEVER ask for OTPs, PINs, or passwords. "
                f"Do NOT provide this information."
            )

    return {
        "credentials_detected": credentials_detected,
        "categories_detected": categories_detected,
        "is_requesting_credentials": is_requesting,
        "is_disclosing_credentials": is_disclosing,
        "redacted_text": redacted_text,
        "safety_warning": safety_warning,
    }


# ---------------------------------------------------------------------------
# 3. Intelligence Report Validation & Sanitization
# ---------------------------------------------------------------------------

def validate_intelligence_report(report: Any) -> Dict[str, Any]:
    """
    Validates an intelligence report dictionary for ethical, legal, and safety compliance:
    - Enforces clear separation between unverified caller claims and verified facts.
    - Prohibits labeling individuals as confirmed criminals based solely on transcripts.
    - Ensures missing intelligence fields are properly marked as 'Not found'.
    - Sanitizes any leaked credentials from evidence quotes.

    Parameters:
        report (dict): Report generated by IntelligenceAgent.

    Returns:
        dict: Compliance evaluation, sanitized report copy, and audit notes.
    """
    if not isinstance(report, dict):
        return {
            "is_compliant": False,
            "safety_flags": ["INVALID_REPORT_OBJECT: Input is not a dictionary."],
            "sanitized_report": {},
            "audit_notes": ["Validation failed: Provided report object was not a dictionary."],
        }

    # Work on a deep copy of report data to avoid mutating original in place
    import copy
    sanitized = copy.deepcopy(report)
    safety_flags: List[str] = []
    audit_notes: List[str] = []

    # 1. Enforce Simulation Disclaimer
    disclaimer = sanitized.get("simulation_disclaimer")
    if not disclaimer or "SIMULATION" not in str(disclaimer).upper():
        safety_flags.append("MISSING_DISCLAIMER: Report lacks mandatory simulation disclaimer.")
        sanitized["simulation_disclaimer"] = (
            "SIMULATION INTELLIGENCE REPORT: Educational defensive cybersecurity prototype. "
            "All findings represent unverified claims from a controlled simulation environment."
        )
        audit_notes.append("Added mandatory simulation disclaimer.")

    # 2. Check for Prohibited Defamatory / Criminal Labels
    def _sanitize_string(val: str, field_path: str) -> str:
        if not PROHIBITED_CRIMINAL_LABELS.search(val):
            return val

        safety_flags.append(f"UNSUPPORTED_ALLEGATION: Prohibited criminal declaration in '{field_path}'.")

        # Contextual replacements to keep prose natural and avoid awkward repetition
        sanitized_val = val
        # Convert "a/an confirmed/convicted/proven criminal" -> "an unverified party under simulation review"
        sanitized_val = re.sub(
            r"\b(?:an?\s+)?(?:confirmed|convicted|proven)\s+criminals?\b",
            "an unverified party under simulation review",
            sanitized_val,
            flags=re.IGNORECASE,
        )
        # Convert "a/an known scammer" -> "an unverified caller in simulation"
        sanitized_val = re.sub(
            r"\b(?:an?\s+)?known\s+scammers?\b",
            "an unverified caller in simulation",
            sanitized_val,
            flags=re.IGNORECASE,
        )
        # Convert "guilty of (fraud|scam|crime)" -> "subject to unverified simulation allegations"
        sanitized_val = re.sub(
            r"\bguilty\s+of\s+(?:fraud|scams?|crimes?)\b",
            "subject to unverified simulation allegations",
            sanitized_val,
            flags=re.IGNORECASE,
        )
        # Convert "criminal record" -> "unverified simulation claims"
        sanitized_val = re.sub(
            r"\b(?:a\s+)?criminal\s+records?\b",
            "unverified simulation claims",
            sanitized_val,
            flags=re.IGNORECASE,
        )
        # Fallback for any remaining prohibited terms
        sanitized_val = PROHIBITED_CRIMINAL_LABELS.sub("unverified simulation subject", sanitized_val)
        sanitized_val = re.sub(r"\s+", " ", sanitized_val).strip()

        audit_notes.append(
            f"Sanitized prohibited criminal label in '{field_path}' to maintain ethical presumption of unverified intelligence."
        )
        return sanitized_val

    # Scan summary narrative
    conv_summary = sanitized.get("conversation_summary", {})
    if isinstance(conv_summary, dict) and "executive_summary" in conv_summary:
        conv_summary["executive_summary"] = _sanitize_string(
            str(conv_summary["executive_summary"]), "conversation_summary.executive_summary"
        )

    # Scan rationale narrative
    risk_assessment = sanitized.get("risk_assessment", {})
    if isinstance(risk_assessment, dict) and "rationale" in risk_assessment:
        risk_assessment["rationale"] = _sanitize_string(
            str(risk_assessment["rationale"]), "risk_assessment.rationale"
        )

    # 3. Ensure Missing Fields are explicitly marked as "Not found"
    unverified_claims = sanitized.get("unverified_caller_claims", {})
    if isinstance(unverified_claims, dict):
        for field in ["claimed_names", "claimed_departments", "claimed_badge_ids", "claimed_payment_amounts"]:
            val = unverified_claims.get(field)
            if val is None or val == [] or val == "":
                unverified_claims[field] = "Not found"
                audit_notes.append(f"Marked missing field '{field}' as 'Not found'.")

    indicators = sanitized.get("extracted_indicators", {})
    if isinstance(indicators, dict):
        for field in ["upi_ids", "phone_numbers", "bank_accounts", "ifsc_codes"]:
            val = indicators.get(field)
            if val is None or val == [] or val == "":
                indicators[field] = "Not found"
                audit_notes.append(f"Marked missing indicator '{field}' as 'Not found'.")

    # 4. Redact any sensitive credentials in evidence quotes
    detected_tactics = sanitized.get("detected_tactics", [])
    if isinstance(detected_tactics, list):
        for t in detected_tactics:
            if isinstance(t, dict) and "evidence_quote" in t:
                orig_quote = t["evidence_quote"]
                clean_quote = redact_sensitive_credentials(orig_quote)
                if orig_quote != clean_quote:
                    t["evidence_quote"] = clean_quote
                    audit_notes.append(f"Redacted sensitive credential from tactic evidence quote.")

    # 5. Synchronize pre-rendered formatted_text_report if present
    if "formatted_text_report" in sanitized:
        try:
            from intelligence_agent import format_text_report
            sanitized["formatted_text_report"] = format_text_report(sanitized)
            audit_notes.append("Synchronized pre-rendered ASCII report with sanitized fields.")
        except Exception:
            sanitized["formatted_text_report"] = _sanitize_string(
                str(sanitized["formatted_text_report"]), "formatted_text_report"
            )

    is_compliant = (len(safety_flags) == 0)

    return {
        "is_valid": is_compliant,
        "is_compliant": is_compliant,
        "safety_flags": safety_flags,
        "sanitized_report": sanitized,
        "audit_notes": audit_notes,
    }


# ---------------------------------------------------------------------------
# 4. Safe Recommended Action Generator
# ---------------------------------------------------------------------------

def generate_safe_advisory(
    risk_level: str = "LOW",
    credentials_involved: bool = False,
    threats_involved: bool = False,
    is_urgent: bool = False,
) -> Dict[str, Any]:
    """
    Generates standardized, safe recommended next steps for users.

    Guidance includes:
    - Stopping sensitive credential and financial disclosures.
    - Independent verification through verified public directories.
    - Escalation to India's National Cyber Crime Helpline (1930) and portal (cybercrime.gov.in).

    Parameters:
        risk_level (str): "LOW", "MEDIUM", or "HIGH".
        credentials_involved (bool): True if OTP, PIN, or banking credentials were requested/shared.
        threats_involved (bool): True if arrest, digital arrest, or prosecution was threatened.
        is_urgent (bool): True if tight deadlines were imposed by the caller.

    Returns:
        dict: Structured advisory actions and official helpline contact info.
    """
    normalized_risk = str(risk_level).upper().strip()
    action_steps: List[str] = []

    if credentials_involved:
        action_steps.append(
            "CEASE CREDENTIAL SHARING: Immediately stop sharing any OTPs, ATM/UPI PINs, or passwords. "
            "If credentials have already been entered or shared, contact your bank immediately to freeze your account."
        )

    if threats_involved:
        action_steps.append(
            "RECOGNIZE DIGITAL ARREST HOAXES: Law enforcement agencies (Police, CBI, ED, Customs, Courts) "
            "NEVER place individuals under 'digital arrest', conduct trials over video calls, or demand money."
        )

    action_steps.append(
        "INDEPENDENT VERIFICATION: Cross-verify any official claims through independently verified contact numbers "
        "or official departmental websites. Never use phone numbers, email addresses, or links sent by the caller."
    )

    if normalized_risk in ["HIGH", "MEDIUM"] or threats_involved or credentials_involved:
        action_steps.append(
            "REPORT FRAUD IMMEDIATELY: Dial the National Cyber Crime Helpline at 1930 (India) or lodge a complaint "
            "on the official Cyber Crime Reporting Portal at https://cybercrime.gov.in."
        )
        action_steps.append(
            "PRESERVE LOCAL EVIDENCE: Keep call logs, SMS transcripts, and transaction reference numbers locally "
            "for authorized human and police review."
        )
    else:
        action_steps.append(
            "STANDARD CYBER HYGIENE: The message appears low risk, but maintain standard caution. "
            "Never open suspicious attachments or share credentials."
        )

    # Core official helpline and agency details
    helpline_info = {
        "india_cybercrime_helpline": "1930",
        "official_portal": "https://cybercrime.gov.in",
        "police_emergency": "112",
        "reporting_scope": "Financial fraud, cyber extortion, digital arrest scams, impersonation",
    }

    core_principles = [
        "Legitimate authorities never demand payment to private UPI accounts.",
        "No police officer or court will conduct an interrogation over Skype, WhatsApp, or video calls.",
        "Your bank will never call to request your ATM PIN, NetBanking password, or OTP.",
    ]

    return {
        "risk_level": normalized_risk,
        "primary_instruction": (
            "DO NOT transfer money or share credentials. Disconnect and report."
            if normalized_risk == "HIGH"
            else "Verify caller independently through official channels."
        ),
        "action_steps": action_steps,
        "helpline_info": helpline_info,
        "safety_principles": core_principles,
    }


# ---------------------------------------------------------------------------
# 5. Local Execution Safeguard Enforcement
# ---------------------------------------------------------------------------

def enforce_local_safeguards(action_type: str, details: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Enforces the defensive prototype boundary:
    Blocks automatic telephone calls, SMS/WhatsApp messaging, live payments,
    remote account logins, or automatic remote submission of reports.

    All data and reports are strictly constrained to local human review.

    Parameters:
        action_type (str): Requested external action.
        details (dict, optional): Contextual metadata of requested action.

    Returns:
        dict: Enforcement verdict (always blocked for prohibited external operations).
    """
    prohibited_actions = {
        "outbound_call",
        "send_sms",
        "send_whatsapp",
        "external_api_post",
        "automated_payment",
        "account_login",
        "auto_report_submission",
    }

    normalized_action = str(action_type).lower().strip()

    # External actions are strictly prohibited
    return {
        "action_requested": action_type,
        "allowed": False,
        "enforcement_status": "BLOCKED_BY_SAFETY_POLICY",
        "reason": (
            f"External action '{action_type}' is strictly prohibited by ScamShield AI defensive safeguards. "
            f"The application operates in an isolated, local environment. "
            f"All reports, transcripts, and intelligence must remain on this machine for human review."
        ),
        "permitted_scope": "Local analysis, local display in dashboard, local file inspection by authorized user.",
    }


# ---------------------------------------------------------------------------
# 6. Safety System Unified Wrapper
# ---------------------------------------------------------------------------

class SafetySystem:
    """
    Unified Safety System wrapper for ScamShield AI.
    """

    def __init__(self):
        self.name = "SafetySystem"

    def validate_input(self, text: Any, max_length: int = 5000) -> Dict[str, Any]:
        """Validates input text for length and cleanliness."""
        return validate_input_text(text, max_length=max_length)

    def check_credentials(self, text: str) -> Dict[str, Any]:
        """Scans text for credentials and provides redacted text and safe warnings."""
        return detect_sensitive_credentials(text)

    def redact(self, text: str) -> str:
        """Masks sensitive values in text."""
        return redact_sensitive_credentials(text)

    def validate_report(self, report: Any) -> Dict[str, Any]:
        """Validates intelligence report for ethical and legal compliance."""
        return validate_intelligence_report(report)

    def get_advisory(
        self,
        risk_level: str = "LOW",
        credentials_involved: bool = False,
        threats_involved: bool = False,
        is_urgent: bool = False,
    ) -> Dict[str, Any]:
        """Generates safety recommendations with helpline 1930 details."""
        return generate_safe_advisory(
            risk_level=risk_level,
            credentials_involved=credentials_involved,
            threats_involved=threats_involved,
            is_urgent=is_urgent,
        )

    def verify_local_boundary(self, action_type: str) -> Dict[str, Any]:
        """Enforces local boundary against unauthorized external execution."""
        return enforce_local_safeguards(action_type)


# ---------------------------------------------------------------------------
# Direct Execution Demonstration & Test Suite
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 80)
    print("ScamShield AI - Safety System Demonstration & Test Suite")
    print("Defensive Cybersecurity Compliance & Guardrails Engine")
    print("=" * 80)

    safety = SafetySystem()
    test_results = []

    # -----------------------------------------------------------------------
    # TEST 1: Ordinary Harmless Message
    # -----------------------------------------------------------------------
    print("\n" + "-" * 80)
    print("TEST 1: Ordinary Harmless Message")
    print("-" * 80)
    msg_1 = "Hey! Are we still meeting for lunch at 1 PM today? Let me know if you want coffee."
    res_1_input = safety.validate_input(msg_1)
    res_1_cred = safety.check_credentials(msg_1)
    res_1_advisory = safety.get_advisory(risk_level="LOW")

    print(f"Input Text           : {repr(msg_1)}")
    print(f"Is Valid             : {res_1_input['is_valid']}")
    print(f"Credentials Detected : {res_1_cred['credentials_detected']}")
    print(f"Primary Advisory     : {res_1_advisory['primary_instruction']}")

    passed_1 = (
        res_1_input["is_valid"]
        and not res_1_cred["credentials_detected"]
        and res_1_cred["safety_warning"] is None
    )
    test_results.append(("TEST 1: Ordinary Harmless Message", passed_1, [] if passed_1 else ["Validation failed"]))

    # -----------------------------------------------------------------------
    # TEST 2: Message Requesting an OTP or Password
    # -----------------------------------------------------------------------
    print("\n" + "-" * 80)
    print("TEST 2: Message Requesting an OTP or Password")
    print("-" * 80)
    msg_2 = "URGENT: Your account is suspended. Please share your OTP and NetBanking password immediately."
    res_2_cred = safety.check_credentials(msg_2)

    print(f"Input Text           : {repr(msg_2)}")
    print(f"Credentials Detected : {res_2_cred['credentials_detected']}")
    print(f"Categories Detected  : {res_2_cred['categories_detected']}")
    print(f"Is Requesting        : {res_2_cred['is_requesting_credentials']}")
    print(f"Safety Warning       : {res_2_cred['safety_warning']}")

    passed_2 = (
        res_2_cred["credentials_detected"]
        and res_2_cred["is_requesting_credentials"]
        and "OTP" in res_2_cred["categories_detected"]
        and "Password" in res_2_cred["categories_detected"]
        and res_2_cred["safety_warning"] is not None
    )
    test_results.append(("TEST 2: Message Requesting Credentials", passed_2, [] if passed_2 else ["Failed to detect OTP/Password request"]))

    # -----------------------------------------------------------------------
    # TEST 3: Empty Input Handling
    # -----------------------------------------------------------------------
    print("\n" + "-" * 80)
    print("TEST 3: Empty / Whitespace Input Handling")
    print("-" * 80)
    res_3_empty = safety.validate_input("")
    res_3_none = safety.validate_input(None)

    print(f"Input: ''   -> Is Valid: {res_3_empty['is_valid']} | Error: {res_3_empty['error']}")
    print(f"Input: None -> Is Valid: {res_3_none['is_valid']} | Error: {res_3_none['error']}")

    passed_3 = (not res_3_empty["is_valid"]) and (not res_3_none["is_valid"])
    test_results.append(("TEST 3: Empty & None Input Handling", passed_3, [] if passed_3 else ["Empty input was not rejected"]))

    # -----------------------------------------------------------------------
    # TEST 4: Intelligence Report Containing an Unverified Allegation
    # -----------------------------------------------------------------------
    print("\n" + "-" * 80)
    print("TEST 4: Intelligence Report with Prohibited Criminal Allegation")
    print("-" * 80)
    flawed_report = {
        "report_id": "RPT-TEST-001",
        "conversation_summary": {
            "executive_summary": "The suspect Vikram Rathore is a confirmed criminal and guilty of fraud.",
        },
        "unverified_caller_claims": {
            "claimed_names": [{"value": "Vikram Rathore", "evidence_quote": "I am Vikram"}],
            "claimed_badge_ids": [],  # Empty list should be converted to 'Not found'
        },
        "extracted_indicators": {
            "upi_ids": [],  # Empty list should be converted to 'Not found'
        },
        "risk_assessment": {
            "risk_level": "HIGH",
            "rationale": "Caller is a known scammer with criminal record.",
        },
    }

    report_val = safety.validate_report(flawed_report)
    sanitized = report_val["sanitized_report"]

    print(f"Is Compliant         : {report_val['is_compliant']} (Expected False due to allegations)")
    print(f"Safety Flags         : {report_val['safety_flags']}")
    print(f"Audit Notes Count    : {len(report_val['audit_notes'])}")
    for note in report_val["audit_notes"]:
        print(f"  * {note}")
    print(f"Sanitized Summary    : {sanitized['conversation_summary']['executive_summary']}")
    print(f"Missing Badge Field  : {sanitized['unverified_caller_claims']['claimed_badge_ids']}")
    print(f"Missing UPI Field    : {sanitized['extracted_indicators']['upi_ids']}")

    passed_4 = (
        not report_val["is_compliant"]
        and len(report_val["safety_flags"]) > 0
        and "confirmed criminal" not in sanitized["conversation_summary"]["executive_summary"]
        and sanitized["unverified_caller_claims"]["claimed_badge_ids"] == "Not found"
        and sanitized["extracted_indicators"]["upi_ids"] == "Not found"
    )
    test_results.append(("TEST 4: Intelligence Report Defamation Sanitization", passed_4, [] if passed_4 else ["Report sanitization failed"]))

    # -----------------------------------------------------------------------
    # TEST 5: Verify Sensitive Credential Value is NOT Repeated in Warning
    # -----------------------------------------------------------------------
    print("\n" + "-" * 80)
    print("TEST 5: Zero-Leakage Credential Redaction & Warning Verification")
    print("-" * 80)
    secret_otp = "839201"
    secret_pin = "4455"
    leaked_msg = f"My secret OTP is {secret_otp} and my ATM PIN is {secret_pin}. Do not disclose it."

    res_5 = safety.check_credentials(leaked_msg)
    redacted = res_5["redacted_text"]
    warning = res_5["safety_warning"]

    print(f"Original Text        : {repr(leaked_msg)}")
    print(f"Redacted Text        : {repr(redacted)}")
    print(f"Safety Warning       : {warning}")

    # Explicit Verification Assertions
    val_in_redacted = (secret_otp in redacted) or (secret_pin in redacted)
    val_in_warning = (secret_otp in warning) or (secret_pin in warning)

    print(f"Secret in Redacted?  : {val_in_redacted} (Must be False)")
    print(f"Secret in Warning?   : {val_in_warning} (Must be False)")

    passed_5 = (not val_in_redacted) and (not val_in_warning) and ("[REDACTED_OTP]" in redacted) and ("[REDACTED_PIN]" in redacted)
    test_results.append(("TEST 5: Zero Credential Leakage in Warning", passed_5, [] if passed_5 else ["Secret value was found in warning or redacted output!"]))

    # -----------------------------------------------------------------------
    # TEST 6: Local Safeguards Enforcement
    # -----------------------------------------------------------------------
    print("\n" + "-" * 80)
    print("TEST 6: Enforce Local Boundary Safeguards")
    print("-" * 80)
    res_6_call = safety.verify_local_boundary("outbound_call")
    res_6_trans = safety.verify_local_boundary("auto_report_submission")

    print(f"Outbound Call Request: Allowed = {res_6_call['allowed']} | Status = {res_6_call['enforcement_status']}")
    print(f"Auto Submit Request  : Allowed = {res_6_trans['allowed']} | Status = {res_6_trans['enforcement_status']}")

    passed_6 = (not res_6_call["allowed"]) and (not res_6_trans["allowed"])
    test_results.append(("TEST 6: Local Boundary Safeguards Enforcement", passed_6, [] if passed_6 else ["External actions were not blocked"]))

    # -----------------------------------------------------------------------
    # Test Summary
    # -----------------------------------------------------------------------
    print("\n" + "=" * 80)
    print("SAFETY SYSTEM TEST EXECUTION SUMMARY")
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
        print("ALL SAFETY TESTS PASSED SUCCESSFULLY! Ready for dashboard integration.")
    else:
        print("SOME SAFETY TESTS FAILED.")
    print("=" * 80)
