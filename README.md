# 🛡️ ScamShield AI
### *Detect the Scam. Outsmart the Scammer.*

A defensive cybersecurity hackathon prototype engineered to detect, de-escalate, and extract actionable threat intelligence from high-pressure cyber extortion and fraud attempts (including "digital arrest" scams, authority impersonation, and banking phishing).

---

## 📌 Project Overview

Digital arrest extortion, law enforcement impersonation (Delhi Police, CBI, ED, Customs), and banking KYC phishing have surged across India and global digital networks. Threat actors exploit panic, legal intimidation, and isolation to coerce victims into making instant fund transfers.

**ScamShield AI** is an autonomous, rule-based cybersecurity defense platform featuring five modular components:
1. **Guardian Agent**: Transparent, rule-based detection engine identifying multi-indicator scam patterns without false-positive traps.
2. **Decoy Agent**: Interactive counter-extortion honeypot that engages simulated threat callers using a fictional persona (**Ramesh Kumar**, 68, retired clerk) to elicit case references and payment channels.
3. **Intelligence Agent**: Forensic analysis engine extracting claimed official identities, badge IDs, demanded amounts, UPI handles, and missing credentials (gap analysis).
4. **Recorded Call Analysis**: Pluggable audio ingestion, format validation (WAV/MP3 $\le$ 25 MB), acoustic metadata inspection, and speech-to-text transcription integrating with Guardian threat scoring and Intelligence reporting.
5. **Safety System**: Strict input validation, zero-leakage credential masking (OTPs, PINs, passwords, card numbers), ethical presumption of unverified intelligence, and local execution boundaries.

---

## ✨ Key Features

- **Recorded Call Extortion Analysis**: Ingests WAV and MP3 call recordings with binary container checks, acoustic signal inspection (RMS, peak amplitude, duration), offline neural transcription via `faster-whisper`, quality assessment warnings, timestamped segments, Guardian threat scoring, and structured intelligence reporting.
- **Configurable Offline Speech Engine**: Defaults to `base` model (141 MB) for rapid CPU int8 inference and enhanced phonetic accuracy on Indian accents and Devanagari script, with support for `small` and `tiny` via environment variable (`SCAMSHIELD_WHISPER_MODEL`).
- **Resilient Device Resolution**: End-to-end device detection validating CUDA and cuBLAS runtime viability, gracefully defaulting to CPU `int8` quantization when GPU runtime libraries are unavailable.
- **Multilingual Language Mode Selection**: Interactive UI dropdown allowing users to select `Auto-Detect`, `Hindi (हिन्दी / Devanagari Script)`, or `English (Indian & Global Accents)` to guide tokenization and prevent cross-language script pollution.
- **Anti-Hallucination Audio Controls**: Integrated Silero VAD (`vad_filter=True`) eliminating background clicks, `condition_on_previous_text=False` preventing hallucination loops, and cybercrime domain vocabulary priming (`initial_prompt`).
- **Transcript Quality Alerts & Timestamped Segments**: Transparent feedback on acoustic confidence, code-switching detection, speech rate anomalies, and interactive expansion of segmented timestamped text.
- **Transparent Rule-Based Detection**: Fully explainable scoring (`0–100`) and risk classification (`LOW`, `MEDIUM`, `HIGH`) calibrated across diverse scam categories.
- **Anti-False Positive Thresholds**: Isolated keywords (e.g., casually mentioning "police" in traffic) are properly recognized as low-risk.
- **Context-Aware Decoy Dialogue**: Preserves conversation history across turns while deflecting credential demands and safely eliciting official case dockets and department accounts.
- **Zero-Leakage Credential Shield**: Automatically redacts sensitive authentication codes (`[REDACTED_OTP]`, `[REDACTED_PIN]`) and guarantees secret values never leak into alerts or summaries.
- **Forensic Gap Analysis**: Identifies what the fraudster failed to provide (lack of `@gov.in` domain email, missing physical signed notice, missing official treasury account).
- **Exportable Intelligence Reports**: Generates structured JSON and formatted executive ASCII threat reports ready for download.
- **Offline & Private**: Built entirely on standard Python without paid external APIs, API keys, or remote telemetry. All audio and text analysis remains strictly local for human review.
- **Official Emergency Integration**: Direct guidance and escalation links to **National Cyber Crime Helpline (1930)** and **cybercrime.gov.in**.

---

## 🛠️ Technology Stack

- **Core Logic**: Python 3.10+ (Standard Library: `re`, `json`, `datetime`, `uuid`, `typing`, `unittest`, `wave`, `struct`, `math`, `pathlib`)
- **Speech-to-Text Engine**: `faster-whisper` (CTranslate2, ONNX Runtime, Silero VAD, PyAV)
- **Offline Models**: Multilingual `base` (default), `small`, and `tiny` cached locally for 100% offline inference
- **Web Dashboard**: Streamlit
- **Architecture**: Modular Agentic Pipeline (Guardian, Decoy, Intelligence, Safety, Audio Transcriber)
- **External API Dependencies**: **None** (100% offline, privacy-preserving)

---

## 📁 Project Structure

```text
ScamShield-AI/
├── app.py                         # Streamlit interactive cybersecurity dashboard (5 tabs)
├── audio_transcription.py         # Audio validation, signal analysis, quality check & faster-whisper STT
├── guardian_agent.py              # Rule-based scam & extortion detection engine
├── decoy_agent.py                 # Multi-turn counter-extortion simulation
├── intelligence_agent.py          # Structured threat intelligence & gap analysis
├── safety.py                      # Credential redaction, input validation & guardrails
├── requirements.txt               # Project dependencies
├── README.md                      # Comprehensive project documentation
├── data/
│   └── sample_scam_messages.json  # Curated dataset of scam & benign test samples
└── tests/
    ├── test_detection.py          # 59-test suite (Core, diverse scams, E2E audit)
    ├── test_audio_analysis.py     # 29-test suite (Audio validation, STT backends, signal check, AppTest UI flow)
    ├── smoke_test_real_audio.py   # 3-test suite (Real speech WAV/MP3 STT & agent pipelines)
    └── fixtures/                  # Authentic spoken audio recordings for smoke testing
```

---

## 🚀 Installation & Quickstart

### 1. Prerequisites
- Python 3.10+ (tested and verified with Python 3.14.2)
- Windows PowerShell or command prompt

### 2. Virtual Environment Setup & Dependencies
The project uses an isolated virtual environment (`.venv`) for speech recognition dependencies (`faster-whisper`, `ctranslate2`, `av`, `streamlit`):

```powershell
# Create an isolated virtual environment
python -m venv .venv

# Activate and install dependencies
.\.venv\Scripts\pip install -r requirements.txt
.\.venv\Scripts\pip install streamlit faster-whisper
```

### 3. Speech Recognition Model Configuration (Optional)
By default, ScamShield AI uses the multilingual **`base`** model (~141 MB) for optimal balance of speed and transcription quality on CPU. You can customize the model size via environment variable:
```powershell
# Options: 'base' (default, recommended), 'small' (~480 MB, higher accuracy), 'tiny' (~75 MB, ultra-light)
$env:SCAMSHIELD_WHISPER_MODEL = "base"
```

### 4. Launch the Dashboard
Run the dashboard using the project's virtual environment:
```powershell
.\.venv\Scripts\streamlit run app.py
```
The dashboard will open automatically in your browser at `http://localhost:8501`.

### 5. Run the Automated Test Suites
Run all **91 automated tests** (88 unit/integration tests + 3 real-speech smoke tests) across the complete defensive pipeline:
```powershell
# 1. Run Guardian, Decoy, Intelligence & Safety Tests (59 tests)
.\.venv\Scripts\python tests/test_detection.py

# 2. Run Audio Signal, Quality Checks, STT Engine & Tab 4 AppTests (29 tests)
.\.venv\Scripts\python tests/test_audio_analysis.py

# 3. Run Real-Speech Audio Transcription Smoke Tests (3 tests)
.\.venv\Scripts\python tests/smoke_test_real_audio.py

# 4. Or run complete discovery suite (88 tests)
.\.venv\Scripts\python -m unittest discover tests
```

---

## 🎬 Hackathon Demo Script (5-Minute Walkthrough)

Follow these steps for a live demonstration in front of judges:

1. **Phase 1: Guardian Agent Detection (Tab 1)**
   - Click the preset button: **"🚨 Police Digital Arrest"**.
   - Click **"🔍 Analyze Message"**.
   - Show judges the output:
     - **Threat Level**: `HIGH RISK` (Score: `100/100`).
     - **Detected Indicators**: Authority Impersonation, Arrest Threats, Financial Demands, Urgency/Isolation.
     - **Anti-False Positive Check**: Click **"🚓 Casual Police Mention"** to prove an isolated keyword scores only `15/100` and remains `LOW RISK`.

2. **Phase 2: Decoy Agent Simulation (Tab 2)**
   - Click **"Turn 1: Opening Digital Arrest Threat"** then **"💬 Send to Decoy Agent"**.
   - Point out how the persona (**Ramesh Kumar**) expresses compliance while asking for the officer's badge ID and police station.
   - Click **"Turn 2: Badge & Court Fine Demand"** then **"💬 Send to Decoy Agent"**.
   - Notice the Decoy elicits the formal FIR docket number.
   - Click **"Turn 3: Payment Demand to UPI"** then **"💬 Send to Decoy Agent"**.
   - The Decoy elicits the department Treasury handle (`police.clearance@sbi`).

3. **Phase 3: Threat Intelligence & Gap Analysis (Tab 3)**
   - Click **"📊 Generate Intelligence Report from Current Dialogue"**.
   - Show judges the structured report:
     - **Extracted UPI**: `police.clearance@sbi` (with preserved verbatim evidence quote).
     - **Claimed Badge**: `DL-9482`.
     - **Gap Analysis**: Highlights missing official credentials (no `@gov.in` domain, no physical notice).
     - Click **"📄 Download Formatted Text Report (.txt)"** to show report export.

4. **Phase 4: Recorded Call Extortion Analysis (Tab 4)**
   - View the active engine banner: **⚡ Offline Neural STT Active: `FasterWhisperBackend(base)` (Model: `base`, Device: `cpu`, Quantization: `int8`)**.
   - Select Spoken Language Mode: **"Auto-Detect"**, **"Hindi (हिन्दी)"**, or **"English"**.
   - Click preset **"🚨 CBI Arrest (Hindi)"** or **"🚨 Police Arrest"** (or upload a custom WAV/MP3 recording $\le$ 25 MB).
   - Demonstrate the **audio playback player** and **acoustic metadata** metrics (Format, Duration, Sample Rate, Channels).
   - Click **"🎙️ Run Speech-to-Text"**:
     - Inspect quality assessment notices and ratings.
     - Expand **"⏱️ View Timestamped Audio Segments"** to review segmented speech timestamps.
     - Use the human-in-the-loop review box to edit any misheard words if needed.
   - Click **"🚨 Analyze Recorded Call"**:
     - Observe end-to-end Guardian threat classification, extracted caller claims, and actionable indicators extracted directly from the call transcript.
     - Click **"📦 Download Structured Report (.json)"** to show the JSON intelligence payload.

5. **Phase 5: Safety & Zero Credential Leakage (Tab 5)**
   - Under the Interactive Safety Test Playground, enter:
     `"My secret OTP is 482910 and PIN is 1234."`
   - Click **"🛡️ Test Safety Shield Redaction"**.
   - Show judges that the secret numbers are masked (`[REDACTED_OTP]`, `[REDACTED_PIN]`) and **never leak into the safety warning**.

---

## 🔒 Safety & Ethical Guardrails

- **Simulation Only**: Designed exclusively for controlled educational and competition demonstrations.
- **Local Audio Storage & Processing**: Uploaded audio files are inspected in-memory and transcribed strictly on the local machine with CPU inference; zero external API uploads.
- **No Outbound Actions**: Automated phone calls, SMS/WhatsApp messaging, live financial transfers, and remote report submissions are hard-blocked by policy.
- **Unverified Intelligence**: All extracted names, departments, badge IDs, and UPI handles are labeled as **unverified caller assertions**, protecting individuals against unsubstantiated criminal allegations. Callers are never categorized as "confirmed criminals" based solely on risk scores.
- **Credential Protection**: Real OTPs, passwords, and banking PINs are never stored or requested.

---

## ⚠️ Known Limitations & Multilingual Boundaries

1. **Hinglish & Code-Switching Technical Boundaries**: Whisper does not have a dedicated `hinglish` token. Audio that switches between Hindi and English is decoded into Devanagari script when Hindi is selected, or Latin script when English is selected. Code-switching quality warnings advise human review before risk scoring.
2. **Rule-Based Detection Engine**: Targets known terminology, coercion patterns, and regulatory impersonations; highly sophisticated or novel obfuscations may require supplementary LLM semantic classification.
3. **Speech Recognition Language Coverage**: The multilingual `base` model is verified with 100% word accuracy on spoken English extortion recordings. Spoken Hindi and mixed Hinglish voice inputs have not yet been evaluated with authentic speech audio datasets and are explicitly cataloged as `NOT TESTED`.
4. **CPU Inference Latency**: Offline transcription with `faster-whisper` on CPU (int8) takes ~1.5–3.0 seconds for a 5-second audio clip depending on host CPU load.
5. **Simulated Dialogue**: The Decoy Agent operates on structured rule-based dialogue paths rather than an open-ended conversational LLM.
6. **No Legal Finality**: Extracted intelligence constitutes preliminary forensic leads and does not replace official police investigation or judicial proceedings.

---

## 📞 Emergency Assistance

If you or someone you know is facing an active cyber scam or extortion attempt:
- **National Cyber Crime Helpline (India)**: Dial **`1930`** (Toll-Free, 24/7)
- **Official Cyber Crime Portal**: [https://cybercrime.gov.in](https://cybercrime.gov.in)
- **Emergency Police Dispatch**: Dial **`112`**

