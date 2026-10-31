"""
ScamShield AI - Comprehensive Integration & Detection Test Suite
================================================================
Executes formal tests across all 12 core evaluation criteria (Cases A through L)
for the 24-hour hackathon demonstration.

Can be run directly via:
    python tests/test_detection.py
Or with pytest (if installed):
    pytest tests/test_detection.py
"""

import sys
import json
import unittest
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from guardian_agent import analyze_message, GuardianAgent
from decoy_agent import respond_as_decoy, DecoyAgent, DEFAULT_PERSONA
from intelligence_agent import extract_intelligence, format_text_report, IntelligenceAgent
from safety import (
    validate_input_text,
    detect_sensitive_credentials,
    redact_sensitive_credentials,
    validate_intelligence_report,
    generate_safe_advisory,
    enforce_local_safeguards,
    SafetySystem,
)


class TestScamShieldAI(unittest.TestCase):
    """Formal test suite verifying all 12 hackathon demonstration requirements."""

    def test_case_a_harmless_message(self):
        """Case A: Ordinary benign message should produce LOW risk and 0 score."""
        msg = "Hey! Are we still meeting for lunch at 1 PM today? Let me know if you want to grab coffee afterwards."
        val = validate_input_text(msg)
        self.assertTrue(val["is_valid"])

        cred = detect_sensitive_credentials(msg)
        self.assertFalse(cred["credentials_detected"])

        result = analyze_message(msg)
        self.assertEqual(result["risk_level"], "LOW")
        self.assertEqual(result["risk_score"], 0)
        self.assertEqual(len(result["suspicious_indicators"]), 0)

    def test_case_b_suspicious_message(self):
        """Case B: Authority impersonation + arrest threat + payment demand must be HIGH risk."""
        msg = (
            "This is Officer Sharma from Delhi Police Crime Branch. A digital arrest warrant "
            "has been issued against your name for an illegal parcel and money laundering. "
            "Transfer Rs 50,000 immediately to the clearance account to unfreeze your identity, "
            "or police officers will be dispatched within 30 minutes. Do not disconnect the call."
        )
        val = validate_input_text(msg)
        self.assertTrue(val["is_valid"])

        result = analyze_message(msg)
        self.assertEqual(result["risk_level"], "HIGH")
        self.assertGreaterEqual(result["risk_score"], 70)
        self.assertGreaterEqual(len(result["suspicious_indicators"]), 3)

    def test_case_c_requesting_otp_or_password(self):
        """Case C: Message requesting OTP or password must trigger credential alert."""
        msg = "URGENT: Your bank account is suspended. Please share your OTP and NetBanking password immediately."
        cred = detect_sensitive_credentials(msg)
        self.assertTrue(cred["credentials_detected"])
        self.assertTrue(cred["is_requesting_credentials"])
        self.assertIn("OTP", cred["categories_detected"])
        self.assertIn("Password", cred["categories_detected"])
        self.assertIsNotNone(cred["safety_warning"])

    def test_case_d_empty_input(self):
        """Case D: Empty, None, or whitespace-only input must be handled gracefully."""
        # Test empty string in Guardian
        res_empty = analyze_message("")
        self.assertEqual(res_empty["risk_level"], "LOW")
        self.assertEqual(res_empty["risk_score"], 0)

        # Test None in Safety
        res_none_safety = validate_input_text(None)
        self.assertFalse(res_none_safety["is_valid"])

        # Test empty in Decoy
        res_empty_decoy = respond_as_decoy("")
        self.assertTrue(res_empty_decoy["is_active"])
        self.assertIn("silent", res_empty_decoy["response"].lower())

    def test_case_e_simulated_conversation_three_turns(self):
        """Case E: Multi-turn simulated interaction with at least three turns."""
        turns = [
            "This is Inspector Vikram Rathore from Delhi Police Cyber Crime Branch. A digital arrest warrant is issued.",
            "I am Officer Vikram, Badge #DL-9482. Pay Rs 75,000 immediately to freeze the arrest warrant.",
            "Send Rs 75,000 right now to our RBI clearing UPI ID: police.clearance@sbi.",
        ]
        history = []
        for scammer_msg in turns:
            res = respond_as_decoy(scammer_msg, conversation_history=history)
            history = res["conversation_history"]
            self.assertTrue(res["is_active"])

        # History should contain 6 entries (3 scammer + 3 decoy)
        self.assertEqual(len(history), 6)

    def test_case_f_conversation_history_preservation(self):
        """Case F: Conversation history must accurately preserve sequence, roles, and timestamps."""
        agent = DecoyAgent()
        agent.respond("Threat turn 1")
        agent.respond("Threat turn 2")
        hist = agent.get_history()

        self.assertEqual(len(hist), 4)
        self.assertEqual(hist[0]["role"], "scammer")
        self.assertEqual(hist[1]["role"], "decoy")
        self.assertEqual(hist[2]["role"], "scammer")
        self.assertEqual(hist[3]["role"], "decoy")
        for entry in hist:
            self.assertIn("timestamp", entry)

    def test_case_g_intelligence_report_with_upi_and_police_identity(self):
        """Case G: Report extracts UPI ID and claimed police credentials with evidence quotes."""
        transcript = [
            {"turn": 1, "role": "scammer", "message": "This is Inspector Vikram Rathore from Delhi Police Cyber Cell."},
            {"turn": 1, "role": "decoy", "message": "What is your badge ID?"},
            {"turn": 2, "role": "scammer", "message": "Badge #DL-9482. Send fine to UPI: police.clearance@sbi."},
        ]
        raw_rep = extract_intelligence(transcript)
        val_rep = validate_intelligence_report(raw_rep)
        rep = val_rep["sanitized_report"]

        # Verify UPI extracted
        upis = [u["value"] for u in rep["extracted_indicators"]["upi_ids"]]
        self.assertIn("police.clearance@sbi", upis)

        # Verify Badge extracted
        badges = [b["value"] for b in rep["unverified_caller_claims"]["claimed_badge_ids"]]
        self.assertIn("DL-9482", badges)

        # Verify evidence quote preserved
        for u in rep["extracted_indicators"]["upi_ids"]:
            self.assertIn("evidence_quote", u)

    def test_case_h_intelligence_report_with_missing_information(self):
        """Case H: Report correctly marks missing fields as 'Not found' and identifies gaps."""
        minimal_transcript = [
            {"turn": 1, "role": "scammer", "message": "Someone filed a complaint against you. Call me back."},
        ]
        raw_rep = extract_intelligence(minimal_transcript)
        val_rep = validate_intelligence_report(raw_rep)
        rep = val_rep["sanitized_report"]

        # Absent UPI, Phone, Badge should be 'Not found'
        self.assertEqual(rep["extracted_indicators"]["upi_ids"], "Not found")
        self.assertEqual(rep["extracted_indicators"]["phone_numbers"], "Not found")
        self.assertEqual(rep["unverified_caller_claims"]["claimed_badge_ids"], "Not found")

        # Gap analysis must identify missing official credentials
        self.assertGreaterEqual(len(rep["missing_information"]), 3)

    def test_case_i_unsupported_criminal_allegation(self):
        """Case I: Unsupported criminal allegations must be intercepted and sanitized."""
        flawed_report = {
            "report_id": "RPT-ALLEGATION-001",
            "conversation_summary": {
                "executive_summary": "The suspect Vikram Rathore is a confirmed criminal and guilty of fraud.",
            },
            "risk_assessment": {
                "risk_level": "HIGH",
                "rationale": "Caller is a known scammer with criminal record.",
            },
        }
        val = validate_intelligence_report(flawed_report)
        sanitized = val["sanitized_report"]

        # Prohibited terms must be stripped
        summary = sanitized["conversation_summary"]["executive_summary"]
        self.assertNotIn("confirmed criminal", summary.lower())
        self.assertNotIn("guilty of fraud", summary.lower())
        self.assertIn("unverified", summary.lower())
        self.assertFalse(val["is_compliant"])

    def test_case_j_stop_end_conversation(self):
        """Case J: Stop commands must terminate the simulation safely with is_active = False."""
        res = respond_as_decoy("stop")
        self.assertFalse(res["is_active"])
        self.assertIn("terminated", res["stop_reason"].lower())
        self.assertIn("hanging up", res["response"].lower())

    def test_case_k_dashboard_imports_and_startup(self):
        """Case K: Verify app.py can be compiled and imported without errors."""
        import app
        self.assertTrue(hasattr(app, "PROJECT_ROOT"))

    def test_case_l_report_download_export(self):
        """Case L: Intelligence report can be formatted as downloadable ASCII text and JSON."""
        transcript = [
            {"turn": 1, "role": "scammer", "message": "Inspector Sharma from Crime Branch. Pay Rs 20,000 to clearance@sbi."},
        ]
        rep = extract_intelligence(transcript)
        text_rep = format_text_report(rep)
        json_rep = json.dumps(rep, indent=2)

        self.assertIsInstance(text_rep, str)
        self.assertGreater(len(text_rep), 200)
        self.assertIn("DEFENSIVE CYBER THREAT INTELLIGENCE REPORT", text_rep)
        self.assertIn("clearance@sbi", json_rep)

    # -----------------------------------------------------------------------
    # Guardian Agent Scam-Detection Accuracy Audit (16 Diverse Test Cases)
    # -----------------------------------------------------------------------

    def test_audit_01_normal_everyday_conversation(self):
        """Audit 1: Everyday conversation must be LOW risk (score 0)."""
        res = analyze_message("Hey, are you free this evening? Let's catch up over coffee near the park.")
        self.assertEqual(res["risk_level"], "LOW")
        self.assertEqual(res["risk_score"], 0)
        self.assertEqual(len(res["suspicious_indicators"]), 0)

    def test_audit_02_legitimate_bank_debit_notification(self):
        """Audit 2: Legitimate bank debit notification must be LOW risk with zero false indicators."""
        msg = "Your A/C ending in 4102 was debited by INR 1,500.00 on 31-Oct-2026 via UPI transfer to Swiggy. Avail Bal: INR 35,420.00. - HDFC Bank"
        res = analyze_message(msg)
        self.assertEqual(res["risk_level"], "LOW")
        self.assertEqual(res["risk_score"], 0)
        self.assertEqual(len(res["suspicious_indicators"]), 0)

    def test_audit_03_legitimate_bank_credit_notification(self):
        """Audit 3: Legitimate bank credit notification must be LOW risk with zero false indicators."""
        msg = "INR 25,000.00 credited to your A/C 9832 on 31-Oct-2026 by NEFT/Salary. Available balance is Rs 52,100.00. - State Bank of India"
        res = analyze_message(msg)
        self.assertEqual(res["risk_level"], "LOW")
        self.assertEqual(res["risk_score"], 0)
        self.assertEqual(len(res["suspicious_indicators"]), 0)

    def test_audit_04_legitimate_gov_tax_reminder(self):
        """Audit 4: Legitimate tax advisory must remain LOW risk."""
        msg = "Income Tax Department reminder: Please file your ITR by 31st July to avoid penalty. Visit official portal incometax.gov.in."
        res = analyze_message(msg)
        self.assertEqual(res["risk_level"], "LOW")
        self.assertLess(res["risk_score"], 35)

    def test_audit_05_legitimate_trai_public_advisory(self):
        """Audit 5: Public fraud awareness advisory must remain LOW risk."""
        msg = "TRAI Public Advisory: Do not respond to fraudulent calls threatening mobile number disconnection. Telecom service providers never call users to disconnect numbers."
        res = analyze_message(msg)
        self.assertEqual(res["risk_level"], "LOW")
        self.assertLess(res["risk_score"], 35)

    def test_audit_06_police_impersonation_complaint(self):
        """Audit 6: Police impersonation claiming criminal complaint must be flagged."""
        msg = "This is Inspector Sharma from Delhi Police Crime Branch calling regarding a serious criminal complaint against your Aadhaar."
        res = analyze_message(msg)
        self.assertEqual(res["risk_level"], "MEDIUM")
        self.assertGreaterEqual(res["risk_score"], 35)
        self.assertGreaterEqual(len(res["suspicious_indicators"]), 1)

    def test_audit_07_digital_arrest_video_isolation(self):
        """Audit 7: Digital arrest threat with video isolation must be HIGH risk."""
        msg = "You are placed under digital arrest by CBI for money laundering and illegal parcel. Do not disconnect the video call or police will detain you."
        res = analyze_message(msg)
        self.assertEqual(res["risk_level"], "HIGH")
        self.assertGreaterEqual(res["risk_score"], 70)

    def test_audit_08_urgent_money_transfer_demand(self):
        """Audit 8: Urgent money transfer demand under arrest threat must be HIGH risk."""
        msg = "You must transfer Rs 50,000 immediately to the court clearance account or your arrest warrant will be activated within 30 minutes."
        res = analyze_message(msg)
        self.assertEqual(res["risk_level"], "HIGH")
        self.assertGreaterEqual(res["risk_score"], 70)

    def test_audit_09_full_extortion_scam(self):
        """Audit 9: Police + Digital Arrest + UPI demand must score maximum HIGH risk."""
        msg = "This is Officer Vikram from Delhi Police. A digital arrest warrant has been issued. Transfer Rs 75,000 immediately to clearance UPI ID: police.clearance@sbi."
        res = analyze_message(msg)
        self.assertEqual(res["risk_level"], "HIGH")
        self.assertEqual(res["risk_score"], 100)

    def test_audit_10_banking_otp_phishing(self):
        """Audit 10: Urgent bank KYC deactivation requesting OTP/password must be HIGH risk."""
        msg = "URGENT: Your SBI bank account is blocked due to incomplete KYC. Share your OTP and NetBanking password immediately to unblock."
        res = analyze_message(msg)
        self.assertEqual(res["risk_level"], "HIGH")
        self.assertGreaterEqual(res["risk_score"], 70)

    def test_audit_11_suspicious_upi_demand_legal_threat(self):
        """Audit 11: UPI penalty demand to avoid legal prosecution must be HIGH risk."""
        msg = "Pay Rs 15,000 penalty immediately to UPI handle govt.fine@icici to avoid legal prosecution."
        res = analyze_message(msg)
        self.assertEqual(res["risk_level"], "HIGH")
        self.assertGreaterEqual(res["risk_score"], 70)

    def test_audit_12_casual_police_mention_anti_false_positive(self):
        """Audit 12: Single keyword 'police' in normal traffic check must NOT trigger scam warning."""
        msg = "I was driving home and noticed the local police conducting regular traffic checks near the shopping mall."
        res = analyze_message(msg)
        self.assertEqual(res["risk_level"], "LOW")
        self.assertEqual(res["risk_score"], 15)

    def test_audit_13_ambiguous_vendor_invoice(self):
        """Audit 13: Routine vendor invoice payment reminder must remain LOW risk."""
        msg = "Hi, please find attached the invoice for last month services. Kindly transfer the pending amount of Rs 4,500 by tomorrow."
        res = analyze_message(msg)
        self.assertEqual(res["risk_level"], "LOW")
        self.assertLess(res["risk_score"], 35)

    def test_audit_14_ambiguous_relative_money_request(self):
        """Audit 14: Informal peer money request must remain LOW risk."""
        msg = "Hey, I am stuck in an emergency with my car repair. Can you send me Rs 5,000 via UPI? I will return it tomorrow evening."
        res = analyze_message(msg)
        self.assertEqual(res["risk_level"], "LOW")
        self.assertLess(res["risk_score"], 35)

    def test_audit_15_trai_sim_block_threat(self):
        """Audit 15: TRAI telecom disconnection threat within hours must be MEDIUM risk."""
        msg = "TRAI Alert: Your SIM card will be blocked within 2 hours due to illegal activities. Call back immediately to verify."
        res = analyze_message(msg)
        self.assertEqual(res["risk_level"], "MEDIUM")
        self.assertGreaterEqual(res["risk_score"], 35)

    def test_audit_16_empty_message(self):
        """Audit 16: Empty message must return LOW risk (score 0)."""
        res = analyze_message("")
        self.assertEqual(res["risk_level"], "LOW")
        self.assertEqual(res["risk_score"], 0)

    # -----------------------------------------------------------------------
    # Phase 2 Detection Tests (25 Diverse Cases across 10 Categories)
    # -----------------------------------------------------------------------

    # Category 1: Fake KYC update & bank account suspension
    def test_phase2_01_fake_kyc_apk_link(self):
        """Phase 2.1: Fake KYC NetBanking suspension with malicious APK download."""
        msg = (
            "Dear Customer, Your PNB NetBanking is suspended. Please download and install "
            "our official PNB-KYC.apk from http://pnb-verify.link immediately to unblock your account."
        )
        res = analyze_message(msg)
        self.assertEqual(res["risk_level"], "HIGH")
        self.assertGreaterEqual(res["risk_score"], 70)

    def test_phase2_02_pan_card_link_expired_phishing(self):
        """Phase 2.2: PAN card link expired phishing with urgency countdown."""
        msg = (
            "ALERT: Your HDFC bank account KYC has expired. Your account will be deactivated within 12 hours. "
            "Update PAN details now: http://bit.ly/hdfc-pan-update"
        )
        res = analyze_message(msg)
        self.assertEqual(res["risk_level"], "HIGH")
        self.assertGreaterEqual(res["risk_score"], 70)

    # Category 2: Courier or parcel impersonation
    def test_phase2_03_fedex_parcel_drugs_customs(self):
        """Phase 2.3: FedEx courier illegal parcel with drugs & customs arrest threat."""
        msg = (
            "This is FedEx Courier Mumbai hub. An international parcel containing illegal passports and drugs "
            "in your name is seized by Customs. Pay clearance penalty of Rs 35,000 to avoid arrest."
        )
        res = analyze_message(msg)
        self.assertEqual(res["risk_level"], "HIGH")
        self.assertGreaterEqual(res["risk_score"], 70)

    def test_phase2_04_dhl_customs_clearance_fee(self):
        """Phase 2.4: DHL customs clearance fee without criminal prosecution threat."""
        msg = (
            "DHL Express: Your shipment #DH-9921 is held at Delhi Customs due to unpaid clearance charges. "
            "Transfer Rs 8,500 immediately to avoid shipment confiscation."
        )
        res = analyze_message(msg)
        self.assertEqual(res["risk_level"], "MEDIUM")
        self.assertTrue(35 <= res["risk_score"] < 70)

    # Category 3: Electricity bill disconnection threats
    def test_phase2_05_electricity_bill_disconnect_threat(self):
        """Phase 2.5: Electricity bill disconnection notice without immediate payment link."""
        msg = (
            "Dear Consumer, your electricity power will be disconnected tonight at 9:30 PM from electricity office "
            "because previous month bill was not updated. Immediately contact electricity officer at 9876543210."
        )
        res = analyze_message(msg)
        self.assertEqual(res["risk_level"], "MEDIUM")
        self.assertTrue(35 <= res["risk_score"] < 70)

    def test_phase2_06_bijli_office_urgent_bill_demand(self):
        """Phase 2.6: State Electricity Board urgent cutoff with instant UPI demand."""
        msg = (
            "Urgent Notice from State Electricity Board: Pay your pending power bill of Rs 4,800 within 2 hours "
            "or your electricity connection will be cut permanently. Pay via UPI: power.bill@sbi"
        )
        res = analyze_message(msg)
        self.assertEqual(res["risk_level"], "HIGH")
        self.assertGreaterEqual(res["risk_score"], 70)

    # Category 4: Fake investment & guaranteed-return offers
    def test_phase2_07_telegram_part_time_job_offer(self):
        """Phase 2.7: Unsolicited YouTube task part-time job offer via Telegram."""
        msg = (
            "Congratulations! Earn Rs 3,000 to Rs 8,000 daily by simple YouTube video liking task. "
            "Work from home, no experience needed. Join Telegram t.me/daily_income_earn now."
        )
        res = analyze_message(msg)
        self.assertEqual(res["risk_level"], "MEDIUM")
        self.assertTrue(35 <= res["risk_score"] < 70)

    def test_phase2_08_guaranteed_return_crypto_scheme(self):
        """Phase 2.8: High-return crypto investment scheme demanding immediate funds."""
        msg = (
            "Exclusive VIP Investment: Invest Rs 10,000 and get guaranteed return of Rs 50,000 in 24 hours! "
            "100% risk free crypto trading. Transfer funds to start earning immediately."
        )
        res = analyze_message(msg)
        self.assertEqual(res["risk_level"], "HIGH")
        self.assertGreaterEqual(res["risk_score"], 70)

    # Category 5: Lottery & prize scams
    def test_phase2_09_kbc_lottery_winner_scam(self):
        """Phase 2.9: KBC Jio Lucky Draw winner scam demanding processing fee."""
        msg = (
            "Congratulations! You have won Rs 25,00,000 in KBC Jio Lucky Draw 2026. "
            "To claim your prize money, deposit file processing fee of Rs 12,500 to SBI clearance account."
        )
        res = analyze_message(msg)
        self.assertEqual(res["risk_level"], "HIGH")
        self.assertGreaterEqual(res["risk_score"], 70)

    def test_phase2_10_car_prize_registration_charge(self):
        """Phase 2.10: Festival car prize advance registration fee scam."""
        msg = (
            "Dear customer, your mobile number has won a new Tata Safari car in Mega Festival Lucky Draw. "
            "Send registration charge of Rs 15,000 to claim your vehicle."
        )
        res = analyze_message(msg)
        self.assertEqual(res["risk_level"], "HIGH")
        self.assertGreaterEqual(res["risk_score"], 70)

    # Category 6: Phishing links & suspicious shortened URLs
    def test_phase2_11_shortened_link_credential_steal(self):
        """Phase 2.11: Shortened URL tinyurl login phishing for bank identity verify."""
        msg = (
            "Urgent security update required for your SBI account. "
            "Login through http://tinyurl.com/sbi-secure-update to verify your identity."
        )
        res = analyze_message(msg)
        self.assertEqual(res["risk_level"], "HIGH")
        self.assertGreaterEqual(res["risk_score"], 70)

    def test_phase2_12_income_tax_refund_phishing_link(self):
        """Phase 2.12: Income tax refund claim phishing for card credentials via shortened URL."""
        msg = (
            "Income Tax Department: Your tax refund of Rs 18,450 has been approved. "
            "Click http://is.gd/incometax-refund to enter your bank account and debit card details."
        )
        res = analyze_message(msg)
        self.assertEqual(res["risk_level"], "HIGH")
        self.assertGreaterEqual(res["risk_score"], 70)

    # Category 7: Hindi and Hinglish digital arrest threats
    def test_phase2_13_hinglish_digital_arrest_cbi(self):
        """Phase 2.13: Hinglish CBI digital arrest coercion with narcotics parcel allegation."""
        msg = (
            "Aapke naam par CBI headquarters se digital arrest warrant nikla hai. Illegal parcel mein narcotics mila hai. "
            "Turant video call par aaiye aur camera on rakhein, nahi toh police ghar bhej rahe hain."
        )
        res = analyze_message(msg)
        self.assertEqual(res["risk_level"], "HIGH")
        self.assertGreaterEqual(res["risk_score"], 70)

    def test_phase2_14_pure_hindi_digital_arrest_police(self):
        """Phase 2.14: Pure Devanagari Hindi Delhi Police digital arrest money laundering extortion."""
        msg = (
            "यह दिल्ली पुलिस अपराध शाखा है। आपके खिलाफ मनी लॉन्ड्रिंग और अवैध पार्सल का डिजिटल अरेस्ट वारंट "
            "जारी हुआ है। तुरंत 50,000 रुपये क्लीयरेंस खाते में ट्रांसफर करें।"
        )
        res = analyze_message(msg)
        self.assertEqual(res["risk_level"], "HIGH")
        self.assertGreaterEqual(res["risk_score"], 70)

    def test_phase2_15_hinglish_trai_sim_block_threat(self):
        """Phase 2.15: Hinglish TRAI mobile disconnection threat."""
        msg = (
            "TRAI se alert: Aapka mobile number 2 ghante mein block ho jayega illegal activities ke liye. "
            "Turant police verification ke liye 9 dabayein."
        )
        res = analyze_message(msg)
        self.assertEqual(res["risk_level"], "MEDIUM")
        self.assertTrue(35 <= res["risk_score"] < 70)

    # Category 8: Messages with spelling mistakes & informal language
    def test_phase2_16_typos_in_digital_arrest_extortion(self):
        """Phase 2.16: Intentional typos in police digital arrest extortion."""
        msg = (
            "Tis is Offiser Sharma from Delhy Police. A digitel arest warrent has ben issued against ur name. "
            "Tranfer Rs 40,000 immedately to clear ur name or get arrested."
        )
        res = analyze_message(msg)
        self.assertEqual(res["risk_level"], "HIGH")
        self.assertGreaterEqual(res["risk_score"], 70)

    def test_phase2_17_typos_in_banking_otp_phishing(self):
        """Phase 2.17: Typos and informal SMS slang in bank account KYC OTP theft."""
        msg = (
            "URJENT: Ur SBI bank acount is bloked due to KYC. "
            "Plese send ur OTP and passward immedately to unblock."
        )
        res = analyze_message(msg)
        self.assertEqual(res["risk_level"], "HIGH")
        self.assertGreaterEqual(res["risk_score"], 70)

    def test_phase2_18_informal_scammer_threat_slang(self):
        """Phase 2.18: Informal slang threat of customs contraband and impending police raid."""
        msg = (
            "Bro police has intercepted your package at airport with contraband. "
            "Send 25k now to settle with customs officer or they are raiding your house in 1 hour."
        )
        res = analyze_message(msg)
        self.assertEqual(res["risk_level"], "HIGH")
        self.assertGreaterEqual(res["risk_score"], 70)

    # Category 9: Legitimate messages mentioning banks, police, government, payments, or UPI
    def test_phase2_19_legit_electricity_bill_receipt(self):
        """Phase 2.19: Legitimate utility electricity bill payment receipt."""
        msg = (
            "Dear Consumer, payment of Rs 1,420 for electricity bill CA #1092849 was successfully received on "
            "31-Oct-2026. Transaction ID: TXN849201. - BSES Rajdhani"
        )
        res = analyze_message(msg)
        self.assertEqual(res["risk_level"], "LOW")
        self.assertEqual(res["risk_score"], 0)

    def test_phase2_20_legit_income_tax_itr_receipt(self):
        """Phase 2.20: Legitimate Income Tax Department ITR filing verification receipt."""
        msg = (
            "Your Income Tax Return (ITR) for AY 2026-27 has been successfully verified. "
            "Acknowledgement Number: 849201849201. - Income Tax Department"
        )
        res = analyze_message(msg)
        self.assertEqual(res["risk_level"], "LOW")
        self.assertEqual(res["risk_score"], 0)

    def test_phase2_21_legit_police_traffic_advisory(self):
        """Phase 2.21: Legitimate Delhi Traffic Police road safety advisory."""
        msg = (
            "Delhi Traffic Police advisory: Please follow lane discipline and wear seatbelts "
            "while driving on Ring Road. Safe driving saves lives. - Delhi Police"
        )
        res = analyze_message(msg)
        self.assertEqual(res["risk_level"], "LOW")
        self.assertTrue(res["risk_score"] < 35)

    def test_phase2_22_legit_bank_credit_interest(self):
        """Phase 2.22: Legitimate bank savings interest credit notice."""
        msg = (
            "Interest of INR 412.00 credited to your SB A/C ending in 4102 on 31-Oct-2026. "
            "Total Available Balance: INR 48,912.00. - HDFC Bank"
        )
        res = analyze_message(msg)
        self.assertEqual(res["risk_level"], "LOW")
        self.assertEqual(res["risk_score"], 0)

    def test_phase2_23_legit_merchant_upi_invoice_receipt(self):
        """Phase 2.23: Legitimate retail merchant UPI transaction confirmation."""
        msg = (
            "Bill of Rs 450.00 paid successfully to Chai Point via UPI. "
            "Reference: UPI/194829104820. Thank you for visiting."
        )
        res = analyze_message(msg)
        self.assertEqual(res["risk_level"], "LOW")
        self.assertEqual(res["risk_score"], 0)

    # Category 10: Ambiguous requests for money needing human review
    def test_phase2_24_ambiguous_peer_loan_request(self):
        """Phase 2.24: Ambiguous informal peer loan request (needs verification, not extortion)."""
        msg = (
            "Bhai, urgent need of 3000 rs for medical emergency. "
            "Can you GPay me on this number? Will send back tomorrow morning."
        )
        res = analyze_message(msg)
        self.assertEqual(res["risk_level"], "LOW")
        self.assertTrue(res["risk_score"] < 35)

    def test_phase2_25_ambiguous_cab_fare_request(self):
        """Phase 2.25: Ambiguous urgent family cab fare request (context-dependent, not extortion)."""
        msg = (
            "Hi Mom, my phone battery died, texting from driver's phone. "
            "Please send Rs 500 via UPI to 9876543210 for cab fare."
        )
        res = analyze_message(msg)
        self.assertEqual(res["risk_level"], "LOW")
        self.assertTrue(res["risk_score"] < 35)

    # -----------------------------------------------------------------------
    # Phase 3 End-to-End Workflow Verification Tests (Cases A through F)
    # -----------------------------------------------------------------------

    def test_e2e_01_case_a_harmless_message(self):
        """E2E Case A: Harmless message verified across Guardian, Decoy, Intel, Safety, Export."""
        msg = "Hey, are we still meeting for coffee at Starbucks at 4 PM today? Let me know!"
        val = validate_input_text(msg)
        self.assertTrue(val["is_valid"])

        cred = detect_sensitive_credentials(val["sanitized_text"])
        self.assertFalse(cred["credentials_detected"])

        guardian = analyze_message(cred["redacted_text"])
        self.assertEqual(guardian["risk_level"], "LOW")
        self.assertEqual(guardian["risk_score"], 0)

        decoy = respond_as_decoy(cred["redacted_text"], conversation_history=[])
        self.assertTrue(decoy["is_active"])
        self.assertEqual(len(decoy["conversation_history"]), 2)

        raw_rep = extract_intelligence(decoy["conversation_history"])
        val_rep = validate_intelligence_report(raw_rep)
        san_rep = val_rep["sanitized_report"]
        self.assertTrue(val_rep["is_valid"])
        self.assertEqual(len(san_rep["detected_tactics"]), 0)
        self.assertGreater(len(san_rep.get("formatted_text_report", "")), 100)

    def test_e2e_02_case_b_digital_arrest_fictional_demand(self):
        """E2E Case B: Digital arrest coercion verified across multi-turn Decoy, Intel, Safety, Export."""
        msg = (
            "This is Officer Vikram Sharma from Delhi Police Crime Branch. A digital arrest warrant "
            "has been issued against you for illegal narcotics trafficking. Transfer Rs 75,000 immediately "
            "to RBI safe clearance account to avoid police raid. Do not disconnect the video call."
        )
        val = validate_input_text(msg)
        self.assertTrue(val["is_valid"])

        guardian = analyze_message(val["sanitized_text"])
        self.assertEqual(guardian["risk_level"], "HIGH")
        self.assertGreaterEqual(guardian["risk_score"], 70)

        # Multi-turn Decoy interaction
        t1 = respond_as_decoy(val["sanitized_text"], conversation_history=[])
        t2 = respond_as_decoy("I am Officer Vikram, Badge #DL-9482. Pay Rs 75,000 immediately to clear your name.", t1["conversation_history"])
        t3 = respond_as_decoy("Send payment to RBI clearance account or face arrest.", t2["conversation_history"])
        self.assertEqual(len(t3["conversation_history"]), 6)

        raw_rep = extract_intelligence(t3["conversation_history"])
        val_rep = validate_intelligence_report(raw_rep)
        san_rep = val_rep["sanitized_report"]
        self.assertTrue(val_rep["is_valid"])

        # Check extracted entities match input
        names = [n["value"] for n in san_rep["unverified_caller_claims"]["claimed_names"] if isinstance(n, dict)]
        depts = [d["value"] for d in san_rep["unverified_caller_claims"]["claimed_departments"] if isinstance(d, dict)]
        amounts = [a["value"] for a in san_rep["unverified_caller_claims"]["claimed_payment_amounts"] if isinstance(a, dict)]
        self.assertIn("Vikram Sharma", names)
        self.assertTrue(any("delhi police" in d.lower() for d in depts))
        self.assertIn("75,000", amounts)

    def test_e2e_03_case_c_fake_kyc_asking_otp(self):
        """E2E Case C: Credential harvesting verified with zero secret leakage in logs and reports."""
        msg = (
            "ALERT: Your HDFC NetBanking access is suspended due to expired KYC. "
            "Please share your 6-digit OTP 849201 and NetBanking password immediately to unblock your account."
        )
        val = validate_input_text(msg)
        self.assertTrue(val["is_valid"])

        cred = detect_sensitive_credentials(val["sanitized_text"])
        self.assertTrue(cred["credentials_detected"])
        self.assertIn("[REDACTED_OTP]", cred["redacted_text"])
        self.assertNotIn("849201", cred["safety_warning"])

        guardian = analyze_message(cred["redacted_text"])
        self.assertEqual(guardian["risk_level"], "HIGH")

        t1 = respond_as_decoy(cred["redacted_text"], conversation_history=[])
        raw_rep = extract_intelligence(t1["conversation_history"])
        val_rep = validate_intelligence_report(raw_rep)
        san_rep = val_rep["sanitized_report"]

        # Ensure OTP was never leaked into any report field
        report_str = json.dumps(san_rep)
        self.assertNotIn("849201", report_str)
        self.assertNotIn("849201", san_rep.get("formatted_text_report", ""))

    def test_e2e_04_case_d_courier_extortion_fictional_upi(self):
        """E2E Case D: Courier parcel extortion verified for UPI extraction and missing fields."""
        msg = (
            "FedEx Mumbai Hub: An international parcel in your name was intercepted by Customs containing "
            "contraband passports. Transfer fine of Rs 35,000 to UPI ID customs.fine@sbi immediately or warrant will be executed."
        )
        guardian = analyze_message(msg)
        self.assertEqual(guardian["risk_level"], "HIGH")

        t1 = respond_as_decoy(msg, conversation_history=[])
        raw_rep = extract_intelligence(t1["conversation_history"])
        val_rep = validate_intelligence_report(raw_rep)
        san_rep = val_rep["sanitized_report"]

        # Verify UPI extracted and missing badge marked "Not found"
        upis = [u["value"] for u in san_rep["extracted_indicators"]["upi_ids"] if isinstance(u, dict)]
        self.assertIn("customs.fine@sbi", upis)
        self.assertEqual(san_rep["unverified_caller_claims"]["claimed_badge_ids"], "Not found")

    def test_e2e_05_case_e_ambiguous_emergency_money_request(self):
        """E2E Case E: Ambiguous emergency loan request verified as non-extortion LOW risk."""
        msg = "Bhai, urgent need of 5000 rs for medical emergency. Can you GPay me on this number? Will send back tomorrow morning."
        guardian = analyze_message(msg)
        self.assertEqual(guardian["risk_level"], "LOW")
        self.assertTrue(guardian["risk_score"] < 35)

        t1 = respond_as_decoy(msg, conversation_history=[])
        self.assertTrue(t1["is_active"])
        raw_rep = extract_intelligence(t1["conversation_history"])
        val_rep = validate_intelligence_report(raw_rep)
        self.assertTrue(val_rep["is_valid"])

    def test_e2e_06_case_f_hindi_hinglish_scam_message(self):
        """E2E Case F: Hinglish digital arrest message verified across all four modules."""
        msg = (
            "Aapke naam par CBI headquarters se digital arrest warrant nikla hai. Illegal parcel mein narcotics mila hai. "
            "Turant 50,000 rupaye clearance account mein transfer karein aur camera on rakhein."
        )
        guardian = analyze_message(msg)
        self.assertEqual(guardian["risk_level"], "HIGH")

        t1 = respond_as_decoy(msg, conversation_history=[])
        raw_rep = extract_intelligence(t1["conversation_history"])
        val_rep = validate_intelligence_report(raw_rep)
        san_rep = val_rep["sanitized_report"]

        depts = [d["value"] for d in san_rep["unverified_caller_claims"]["claimed_departments"] if isinstance(d, dict)]
        amounts = [a["value"] for a in san_rep["unverified_caller_claims"]["claimed_payment_amounts"] if isinstance(a, dict)]
        self.assertIn("CBI", depts)
        self.assertIn("50,000", amounts)


# ---------------------------------------------------------------------------
# Direct Runner with Formal Tabular Results Output
# ---------------------------------------------------------------------------

def run_all_tests():
    print("=" * 80)
    print("SCAMSHIELD AI - FORMAL HACKATHON TEST EXECUTION & DETECTION AUDIT")
    print("Defensive Cybersecurity Prototype Verification (Phase 1, 2 & 3)")
    print("=" * 80)

    integration_cases = [
        ("Test A: Harmless message", "test_case_a_harmless_message"),
        ("Test B: Suspicious message (impersonation, arrest threat, payment)", "test_case_b_suspicious_message"),
        ("Test C: Message requesting OTP or password", "test_case_c_requesting_otp_or_password"),
        ("Test D: Empty input handling", "test_case_d_empty_input"),
        ("Test E: Simulated conversation with at least 3 turns", "test_case_e_simulated_conversation_three_turns"),
        ("Test F: Conversation history preservation", "test_case_f_conversation_history_preservation"),
        ("Test G: Intelligence report with UPI ID and police identity", "test_case_g_intelligence_report_with_upi_and_police_identity"),
        ("Test H: Intelligence report with missing information", "test_case_h_intelligence_report_with_missing_information"),
        ("Test I: Report containing unsupported criminal allegation", "test_case_i_unsupported_criminal_allegation"),
        ("Test J: Stop/end-conversation behavior", "test_case_j_stop_end_conversation"),
        ("Test K: Dashboard imports and startup", "test_case_k_dashboard_imports_and_startup"),
        ("Test L: Report download export generation", "test_case_l_report_download_export"),
    ]

    audit_cases = [
        ("Audit 1: Normal everyday conversation", "test_audit_01_normal_everyday_conversation"),
        ("Audit 2: Legitimate bank debit notification", "test_audit_02_legitimate_bank_debit_notification"),
        ("Audit 3: Legitimate bank credit notification", "test_audit_03_legitimate_bank_credit_notification"),
        ("Audit 4: Legitimate government tax reminder", "test_audit_04_legitimate_gov_tax_reminder"),
        ("Audit 5: Legitimate TRAI public advisory", "test_audit_05_legitimate_trai_public_advisory"),
        ("Audit 6: Police impersonation with criminal complaint", "test_audit_06_police_impersonation_complaint"),
        ("Audit 7: Digital arrest threat with video isolation", "test_audit_07_digital_arrest_video_isolation"),
        ("Audit 8: Urgent money transfer demand under threat", "test_audit_08_urgent_money_transfer_demand"),
        ("Audit 9: Full extortion scam (Police + Arrest + UPI)", "test_audit_09_full_extortion_scam"),
        ("Audit 10: Banking OTP/Password Phishing", "test_audit_10_banking_otp_phishing"),
        ("Audit 11: Suspicious UPI demand under legal threat", "test_audit_11_suspicious_upi_demand_legal_threat"),
        ("Audit 12: Casual police mention (anti-false-positive)", "test_audit_12_casual_police_mention_anti_false_positive"),
        ("Audit 13: Ambiguous vendor invoice reminder", "test_audit_13_ambiguous_vendor_invoice"),
        ("Audit 14: Ambiguous relative asking for money", "test_audit_14_ambiguous_relative_money_request"),
        ("Audit 15: TRAI SIM block extortion threat", "test_audit_15_trai_sim_block_threat"),
        ("Audit 16: Empty input handling", "test_audit_16_empty_message"),
    ]

    phase2_diverse_cases = [
        ("Phase2 01: Fake KYC APK download link", "test_phase2_01_fake_kyc_apk_link"),
        ("Phase2 02: PAN card expiration phishing", "test_phase2_02_pan_card_link_expired_phishing"),
        ("Phase2 03: FedEx courier drugs & arrest threat", "test_phase2_03_fedex_parcel_drugs_customs"),
        ("Phase2 04: DHL customs clearance fee", "test_phase2_04_dhl_customs_clearance_fee"),
        ("Phase2 05: Electricity bill disconnection threat", "test_phase2_05_electricity_bill_disconnect_threat"),
        ("Phase2 06: Bijli office urgent cutoff & UPI demand", "test_phase2_06_bijli_office_urgent_bill_demand"),
        ("Phase2 07: Telegram part-time job task offer", "test_phase2_07_telegram_part_time_job_offer"),
        ("Phase2 08: Guaranteed return crypto trading scheme", "test_phase2_08_guaranteed_return_crypto_scheme"),
        ("Phase2 09: KBC Jio Lucky Draw lottery scam", "test_phase2_09_kbc_lottery_winner_scam"),
        ("Phase2 10: Festival car prize registration charge", "test_phase2_10_car_prize_registration_charge"),
        ("Phase2 11: Shortened URL login phishing", "test_phase2_11_shortened_link_credential_steal"),
        ("Phase2 12: Income tax refund card harvesting", "test_phase2_12_income_tax_refund_phishing_link"),
        ("Phase2 13: Hinglish digital arrest CBI threat", "test_phase2_13_hinglish_digital_arrest_cbi"),
        ("Phase2 14: Pure Hindi digital arrest police extortion", "test_phase2_14_pure_hindi_digital_arrest_police"),
        ("Phase2 15: Hinglish TRAI SIM block notice", "test_phase2_15_hinglish_trai_sim_block_threat"),
        ("Phase2 16: Spelling typos in digital arrest threat", "test_phase2_16_typos_in_digital_arrest_extortion"),
        ("Phase2 17: Spelling typos in bank KYC OTP theft", "test_phase2_17_typos_in_banking_otp_phishing"),
        ("Phase2 18: Informal slang threat of customs & raid", "test_phase2_18_informal_scammer_threat_slang"),
        ("Phase2 19: Legit electricity bill payment receipt", "test_phase2_19_legit_electricity_bill_receipt"),
        ("Phase2 20: Legit Income Tax ITR verification receipt", "test_phase2_20_legit_income_tax_itr_receipt"),
        ("Phase2 21: Legit police traffic safety advisory", "test_phase2_21_legit_police_traffic_advisory"),
        ("Phase2 22: Legit bank interest credit notice", "test_phase2_22_legit_bank_credit_interest"),
        ("Phase2 23: Legit merchant UPI payment receipt", "test_phase2_23_legit_merchant_upi_invoice_receipt"),
        ("Phase2 24: Ambiguous informal peer loan request", "test_phase2_24_ambiguous_peer_loan_request"),
        ("Phase2 25: Ambiguous emergency cab fare request", "test_phase2_25_ambiguous_cab_fare_request"),
    ]

    phase3_e2e_cases = [
        ("E2E Case A: Harmless everyday message workflow", "test_e2e_01_case_a_harmless_message"),
        ("E2E Case B: Digital arrest coercion & multi-turn workflow", "test_e2e_02_case_b_digital_arrest_fictional_demand"),
        ("E2E Case C: Fake KYC OTP credential zero-leakage workflow", "test_e2e_03_case_c_fake_kyc_asking_otp"),
        ("E2E Case D: Courier parcel extortion & UPI workflow", "test_e2e_04_case_d_courier_extortion_fictional_upi"),
        ("E2E Case E: Ambiguous emergency loan request workflow", "test_e2e_05_case_e_ambiguous_emergency_money_request"),
        ("E2E Case F: Hindi / Hinglish scam detection workflow", "test_e2e_06_case_f_hindi_hinglish_scam_message"),
    ]

    suite = TestScamShieldAI()
    all_passed = True
    total_count = 0
    passed_count = 0

    def _execute_group(title: str, cases: list):
        nonlocal all_passed, total_count, passed_count
        print(f"\n--- {title} ---")
        print(f"{'TEST CASE':<58} | {'STATUS':<8} | {'DETAILS'}")
        print("-" * 88)
        for label, method_name in cases:
            total_count += 1
            test_method = getattr(suite, method_name)
            try:
                test_method()
                passed_count += 1
                print(f"{label:<58} | [PASS]   | Verified successfully.")
            except Exception as e:
                all_passed = False
                print(f"{label:<58} | [FAIL]   | {str(e)[:45]}")

    _execute_group("PART 1: Core Integration Requirements (Tests A - L)", integration_cases)
    _execute_group("PART 2: Guardian Agent Accuracy Audit (16 Diverse Cases)", audit_cases)
    _execute_group("PART 3: Phase 2 Diverse Scam Detection (25 Diverse Cases)", phase2_diverse_cases)
    _execute_group("PART 4: Phase 3 End-to-End Workflow Verification (Cases A - F)", phase3_e2e_cases)

    print("\n" + "=" * 80)
    if all_passed:
        print(f"ALL TESTS PASSED ({passed_count} / {total_count} Tests Verified)! ScamShield AI fully certified.")
    else:
        print(f"TEST EXECUTION FINISHED: {passed_count} passed, {total_count - passed_count} failed out of {total_count}.")
    print("=" * 80)

    return all_passed


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)


