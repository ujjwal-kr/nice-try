# Deep Research Agent: Hunter & Auditor

**A self-correcting cybersecurity research tool that maps informal descriptions to professional frameworks (MITRE ATT&CK & NICE).**

This repository implements a dual-agent architecture to ensure high-fidelity mappings of hacker activities to standardized industry frameworks. It leverages Google's Generative AI for reasoning and a local "source of truth" for verification.

## 🏗 Architecture

The system operates on a **Hunter-Auditor** loop to minimize hallucinations and ensure accuracy.

### 1. The Hunter (Research Agent)
The Hunter analyzes raw, informal, or "hood" descriptions of cyber threats. Its job is to:
- **Translate** slang and informal text into professional terminology.
- **Map** activities to specific **MITRE ATT&CK** Technique IDs (e.g., `T1490`).
- **Identify** relevant **NICE Framework** Knowledge, Skills, Abilities, and Tasks (KSAs).
- **Output** a structured JSON draft.

### 2. The Auditor (Verification Agent)
The Auditor acts as a strict quality control gate. It does **not** trust the Hunter's output blindly. Instead, it:
- **Extracts** IDs from the Hunter's draft.
- **Searches** a local internal knowledge base (`data/` directory) using `ripgrep` to find the official definitions.
- **Verifies** that the Hunter's usage matches the official source of truth.
- **Rejects** hallucinations (e.g., non-existent codes) or mismatched descriptions.
- **Provides Feedback** to the Hunter if errors are found.

### 3. The Orchestrator
The system manages a feedback loop (up to 3 retries). If the Auditor fails a draft, the feedback is sent back to the Hunter for a revised attempt. This ensures that the final output is both semantically relevant and factually correct.

## ✨ Features

- **Strict JSON Output**: All results are returned in a clean, machine-readable JSON format.
- **Fact-Checking**: Uses `ripgrep` to validate every ID against a local dataset, preventing "AI hallucinations."
- **Flexible Focus**: You can tell the agent to prioritize:
    - `mitre`: Focus on ATT&CK Techniques.
    - `ksa`: Focus on NICE Knowledge, Skills, and Abilities.
    - `both`: Balance both frameworks (Default).
- **Batch Processing**: Supports loading input from local files for processing large datasets.

## 🚀 Setup

1. **Clone the repository** and navigate to the project root.

2. **Configure Environment**:
   Create a `.env` file and add your Google Gemini API key.
   ```bash
   cp .env.example .env
   # Edit .env and set GEMINI_API_KEY=your_key_here
   ```

3. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   # Ensure ripgrep is installed on your system (e.g., sudo apt install ripgrep)
   ```

4. **Prepare Data**:
   Ensure your `data/` directory contains the JSON source files for MITRE and NICE frameworks. The Auditor uses these files to verify codes.

## 💻 Usage

Start the agent:
```bash
python main.py
```

### Interactive Mode
Simply type your query at the prompt:
```text
INPUT >> I want to shut down the system to stop them from recovering data
```

### File Mode
To process a long description from a file, type `file`:
```text
INPUT >> file
Enter file path to load: /path/to/incident_report.txt
```

### Focus Selection
The agent will ask for your preferred focus area for each session:
- **mitre**: Prioritizes T-codes.
- **ksa**: Prioritizes Workforce Framework codes.
- **both**: Comprehensive mapping.

## 🛠 Requirements
- Python 3.8+
- `ripgrep` (rg) installed and accessible in PATH.
- A valid Google Gemini API Key.