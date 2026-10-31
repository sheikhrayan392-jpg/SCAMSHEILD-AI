"""
ScamShield AI - Decoy Agent (Part 2)
====================================
An educational, defensive cybersecurity decoy simulation designed to engage
simulated scammers in multi-turn conversations. The agent uses a fictional,
non-sensitive persona to safely elicit clarifying details (such as claimed authority,
case docket number, or payment destination) while maintaining context across turns.

SAFETY & COMPLIANCE NOTICE:
---------------------------
- SIMULATION ONLY: Designed exclusively for controlled demonstrations, tests,
  and hackathon evaluations.
- NEVER contacts real persons, phone numbers, WhatsApp, or external systems.
- NEVER collects, stores, or transmits real credentials, OTPs, or financial data.
- NEVER impersonates real officials or threatens callers.
- Extracted statements are simulated artifacts and do NOT constitute legal proof
  of criminal activity.
"""

import re
from datetime import datetime
from typing import Dict, List, Any, Optional


# ---------------------------------------------------------------------------
# Fictional Persona Configuration
# ---------------------------------------------------------------------------

DEFAULT_PERSONA = {
    "name": "Ramesh Kumar",
    "age": 68,
    "background": "Retired government accounts clerk living in Pune",
    "demeanor": "Polite, compliant-seeming, technologically hesitant, and anxious to follow rules",
    "safety_rule": "Never disclose actual banking credentials, OTPs, passwords, or personal identity documents.",
}


# ---------------------------------------------------------------------------
# Core Decoy Response Engine
# ---------------------------------------------------------------------------

def respond_as_decoy(
    scammer_message: Any,
    conversation_history: Optional[List[Dict[str, Any]]] = None,
    stop_requested: bool = False,
    persona: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Generates a context-aware decoy response to a simulated scammer message
    while preserving and updating multi-turn conversation history.

    Parameters:
        scammer_message (str): The latest message from the simulated scammer.
        conversation_history (list, optional): Previous turns in the conversation.
        stop_requested (bool, optional): Explicit flag to terminate the conversation.
        persona (dict, optional): Custom fictional persona dictionary.

    Returns:
        dict: Structured response containing:
            - response (str): Decoy's reply text
            - persona (dict): Persona details used
            - turn_number (int): Current 1-based turn count
            - conversation_history (list): Full updated conversation transcript
            - is_active (bool): Whether the simulation is still running
            - stop_reason (str or None): Explanation if stopped
            - clarification_target (str): Specific details sought in this turn
            - simulation_notice (str): Safety notice for judges and users
    """
    active_persona = persona or DEFAULT_PERSONA
    simulation_notice = (
        "SIMULATION ONLY: Educational cybersecurity decoy prototype. "
        "Operates strictly in an isolated environment without external communication."
    )

    # 1. Gracefully validate and normalize conversation history
    history: List[Dict[str, Any]] = []
    if isinstance(conversation_history, list):
        for entry in conversation_history:
            if isinstance(entry, dict) and "role" in entry and "message" in entry:
                history.append(entry)

    # Calculate current turn index (based on scammer turns + 1)
    past_scammer_turns = sum(1 for item in history if item.get("role") == "scammer")
    current_turn = past_scammer_turns + 1

    # 2. Check for explicit stop request or stop keywords
    stop_keywords = {"stop", "exit", "quit", "end", "hang up", "bye", "terminate", "cancel"}
    user_text = str(scammer_message).strip() if scammer_message is not None else ""

    if stop_requested or (user_text and user_text.lower() in stop_keywords):
        exit_reply = (
            f"Sir, this is {active_persona['name']}. I am feeling unwell and uncomfortable "
            f"with this conversation. I am hanging up now to consult my family and legal advisor. Goodbye."
        )
        updated_history = list(history)
        if user_text:
            updated_history.append({
                "turn": current_turn,
                "role": "scammer",
                "message": user_text,
                "timestamp": datetime.now().isoformat(),
            })
        updated_history.append({
            "turn": current_turn,
            "role": "decoy",
            "message": exit_reply,
            "timestamp": datetime.now().isoformat(),
        })

        return {
            "response": exit_reply,
            "persona": active_persona,
            "turn_number": current_turn,
            "conversation_history": updated_history,
            "is_active": False,
            "stop_reason": "Conversation terminated by user stop command.",
            "clarification_target": "Safe Exit & Disconnection",
            "simulation_notice": simulation_notice,
        }

    # 3. Handle empty or whitespace-only messages gracefully
    if not user_text:
        empty_reply = (
            "Hello? Sir, are you still there? The line went silent and I did not hear what you said. "
            "Please repeat, I am getting very worried."
        )
        return {
            "response": empty_reply,
            "persona": active_persona,
            "turn_number": current_turn,
            "conversation_history": history,
            "is_active": True,
            "stop_reason": None,
            "clarification_target": "Input Clarification (Empty Input)",
            "simulation_notice": simulation_notice,
        }

    # 4. Contextual analysis of incoming scammer message
    lowered_msg = user_text.lower()

    # Detect credential harvesting attempts (OTP, PIN, Password)
    has_credential_demand = bool(re.search(
        r"\b(?:otp|one[- ]time password|atm pin|upi pin|password|cvv|pin)\b", lowered_msg
    ))
    # Detect payment / fine / transfer demands
    has_payment_demand = bool(re.search(
        r"\b(?:transfer|deposit|pay|payment|fine|penalty|fee|rs\.?|inr|₹|upi|bank account|cash)\b", lowered_msg
    ))
    # Detect law enforcement / legal prosecution threats
    has_legal_threat = bool(re.search(
        r"\b(?:police|cbi|ed|crime branch|arrest|warrant|custody|fir|illegal|narcotics|customs)\b", lowered_msg
    ))
    # Detect high urgency / panic triggers
    has_urgency = bool(re.search(
        r"\b(?:immediately|urgent|right now|hurry|fast|minutes|hours|hang up)\b", lowered_msg
    ))

    # 5. Multi-turn dialogue progression strategy
    # Turn 1: Panic compliance & Request for Authority / Officer details
    # Turn 2: Request for Case / FIR / Warrant Docket number
    # Turn 3: Request for Payment / Account / UPI recipient details
    # Turn 4: Request for Official Receipt & Resolution protocol
    # Turn 5+: Safe graceful wrap-up / exit

    if has_credential_demand:
        # Strict deflection: Decoy never gives credentials
        decoy_reply = (
            f"Sir, I am {active_persona['name']}, an elderly person. My spectacles are in the other room "
            f"and my phone screen is very blurry. Why would an official department ask for an OTP or PIN? "
            f"Could you please give me the official complaint reference number and your branch address so I can visit in person?"
        )
        clarification_target = "Credential Deflection & Branch Reference"

    elif current_turn == 1:
        if has_legal_threat or has_urgency:
            decoy_reply = (
                f"Oh God, please don't arrest me! I am {active_persona['name']}, a 68-year-old retired clerk, "
                f"and I have never broken any law. I will cooperate fully, sir. Could you please tell me your full name, "
                f"your officer badge ID, and which exact police station or headquarters you are calling from? "
                f"Let me write it down in my diary."
            )
        else:
            decoy_reply = (
                f"Hello sir, I am {active_persona['name']}. I am having trouble understanding this call. "
                f"Which department or agency are you representing, and what is your designation? "
                f"Please speak slowly so I can note it down."
            )
        clarification_target = "Authority Identity & Police Station Verification"

    elif current_turn == 2:
        if has_payment_demand:
            decoy_reply = (
                f"I noted your name, sir. You mentioned a payment or clearance amount. Before I speak to my bank, "
                f"what is the official FIR number or court case docket registered against my name? "
                f"My son told me every police matter has an official FIR number for reference."
            )
        else:
            decoy_reply = (
                f"Yes officer, I am listening very carefully. Could you please give me the official FIR number "
                f"or formal warrant reference number? I need to note down the exact case docket number to clear my record."
            )
        clarification_target = "FIR Docket & Case Reference Number"

    elif current_turn == 3:
        if has_payment_demand or "account" in lowered_msg or "upi" in lowered_msg:
            decoy_reply = (
                f"Understood, officer. Before any transfer is considered, what is the official government "
                f"Department Treasury title or court clearance handle for this verification deposit? "
                f"Please provide the official government department account title so my family can review it."
            )
        else:
            decoy_reply = (
                f"Sir, I want to clarify this through official channels. What is the official department "
                f"Treasury or designated government account title for this case?"
            )
        clarification_target = "Official Department Treasury & Clearance Channel Clarification"

    elif current_turn == 4:
        decoy_reply = (
            f"I have noted down the payment details, sir. Once I transfer this amount, will you issue an official "
            f"stamped receipt and written clearance certificate from your department to close this case permanently? "
            f"How long does the clearance verification take?"
        )
        clarification_target = "Official Receipt & Case Resolution Protocol"

    else:
        # Turn 5+: Conclude conversation safely
        decoy_reply = (
            f"Officer, my son and our family advocate have just arrived at my home. They are reviewing the case notes "
            f"I wrote down. They have advised me that we will visit the district headquarters in person to complete this. "
            f"Thank you for your time, I am disconnecting now."
        )
        clarification_target = "Simulation Max Turns Reached (Safe Conclusion)"

        # Update and stop
        updated_history = list(history)
        updated_history.append({
            "turn": current_turn,
            "role": "scammer",
            "message": user_text,
            "timestamp": datetime.now().isoformat(),
        })
        updated_history.append({
            "turn": current_turn,
            "role": "decoy",
            "message": decoy_reply,
            "timestamp": datetime.now().isoformat(),
        })

        return {
            "response": decoy_reply,
            "persona": active_persona,
            "turn_number": current_turn,
            "conversation_history": updated_history,
            "is_active": False,
            "stop_reason": "Maximum safe demonstration turns reached. Safe exit executed.",
            "clarification_target": clarification_target,
            "simulation_notice": simulation_notice,
        }

    # 6. Build updated conversation history
    updated_history = list(history)
    updated_history.append({
        "turn": current_turn,
        "role": "scammer",
        "message": user_text,
        "timestamp": datetime.now().isoformat(),
    })
    updated_history.append({
        "turn": current_turn,
        "role": "decoy",
        "message": decoy_reply,
        "timestamp": datetime.now().isoformat(),
    })

    return {
        "response": decoy_reply,
        "persona": active_persona,
        "turn_number": current_turn,
        "conversation_history": updated_history,
        "is_active": True,
        "stop_reason": None,
        "clarification_target": clarification_target,
        "simulation_notice": simulation_notice,
    }


# ---------------------------------------------------------------------------
# Object-Oriented Interface Wrapper
# ---------------------------------------------------------------------------

class DecoyAgent:
    """
    Decoy Agent stateful wrapper for multi-turn simulation sessions.
    """

    def __init__(self, persona: Optional[Dict[str, Any]] = None):
        self.persona = persona or DEFAULT_PERSONA
        self.conversation_history: List[Dict[str, Any]] = []
        self.is_active: bool = True

    def respond(self, scammer_message: Any) -> Dict[str, Any]:
        """Processes a simulated scammer message and updates session history."""
        result = respond_as_decoy(
            scammer_message=scammer_message,
            conversation_history=self.conversation_history,
            stop_requested=False,
            persona=self.persona,
        )
        self.conversation_history = result["conversation_history"]
        self.is_active = result["is_active"]
        return result

    def stop(self, reason: str = "User initiated stop") -> Dict[str, Any]:
        """Safely terminates the active simulation session."""
        result = respond_as_decoy(
            scammer_message=None,
            conversation_history=self.conversation_history,
            stop_requested=True,
            persona=self.persona,
        )
        self.conversation_history = result["conversation_history"]
        self.is_active = False
        return result

    def get_history(self) -> List[Dict[str, Any]]:
        """Returns a copy of the preserved conversation history."""
        return list(self.conversation_history)

    def reset(self) -> None:
        """Resets the agent to clean initial state."""
        self.conversation_history = []
        self.is_active = True


# ---------------------------------------------------------------------------
# Direct Execution Demonstration
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 80)
    print("ScamShield AI - Decoy Agent Demonstration")
    print("Defensive Cybersecurity Prototype (Multi-Turn Simulation)")
    print("=" * 80)

    # 1. Initialize Decoy Agent
    agent = DecoyAgent()
    print(f"\n[Persona Loaded] Name: {agent.persona['name']}, Demeanor: {agent.persona['demeanor']}")

    # 2. Test 3 Consecutive Multi-Turn Simulated Exchanges
    simulated_scammer_turns = [
        (
            "Turn 1 (Scammer Opening Threat)",
            "This is Inspector Vikram Rathore from Delhi Police Cyber Crime Branch. "
            "A digital arrest warrant has been issued in your name for illegal narcotics tracking. "
            "Do not hang up or officers will reach your residence!"
        ),
        (
            "Turn 2 (Scammer Escalation & Fine Demand)",
            "I am Officer Vikram, Badge #DL-9482, New Delhi Cyber Cell. "
            "You must immediately pay a security deposit of Rs 75,000 to the court clearance account "
            "to freeze the arrest warrant, or you will be taken into custody in 1 hour."
        ),
        (
            "Turn 3 (Scammer Payment Instructions)",
            "Send Rs 75,000 right now to our RBI clearing UPI ID: police.clearance@sbi. "
            "Transfer it immediately and keep your video camera turned on."
        ),
    ]

    print("\n" + "-" * 80)
    print("SCENARIO 1: Three Consecutive Multi-Turn Simulated Exchanges")
    print("-" * 80)

    for label, msg in simulated_scammer_turns:
        print(f"\n>>> [{label}]")
        print(f"Scammer : {msg}")
        result = agent.respond(msg)
        print(f"Decoy   : {result['response']}")
        print(f"Target  : {result['clarification_target']}")
        print(f"Active  : {result['is_active']} | Turn Count: {result['turn_number']}")

    # 3. Verify Conversation History Preservation
    print("\n" + "-" * 80)
    print("SCENARIO 2: Verifying Conversation History Preservation")
    print("-" * 80)
    history = agent.get_history()
    print(f"Total History Entries: {len(history)} (Expected 6 entries: 3 scammer + 3 decoy)")
    for idx, entry in enumerate(history, 1):
        print(f"  [{idx}] Turn {entry['turn']} - {entry['role'].upper()}: {entry['message'][:65]}...")

    # 4. Verify Empty Input Handling
    print("\n" + "-" * 80)
    print("SCENARIO 3: Empty / Whitespace Input Handling")
    print("-" * 80)
    empty_result = respond_as_decoy("", conversation_history=agent.get_history())
    print(f"Input   : '' (Empty string)")
    print(f"Decoy   : {empty_result['response']}")
    print(f"Target  : {empty_result['clarification_target']}")
    print(f"Active  : {empty_result['is_active']}")

    # 5. Verify Stop / End-Conversation Handling
    print("\n" + "-" * 80)
    print("SCENARIO 4: Stop / End-Conversation Handling")
    print("-" * 80)
    stop_result = agent.respond("stop")
    print(f"Input   : 'stop'")
    print(f"Decoy   : {stop_result['response']}")
    print(f"Active  : {stop_result['is_active']}")
    print(f"Reason  : {stop_result['stop_reason']}")

    print("\n" + "=" * 80)
    print("Decoy Agent demonstration completed successfully.")
    print("=" * 80)
