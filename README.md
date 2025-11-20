# Nice Try

A silly agent to convert natural language cyber threats into corporate terms.

## 🔍 Overview

The system employs a dual-phase approach to ensure high accuracy and relevance:

### 1. Analysis & Translation
The agent first analyzes raw or informal descriptions of cyber threats. It translates colloquial terms into professional cybersecurity terminology and identifies relevant mappings within:
- **MITRE ATT&CK**: For adversarial tactics and techniques.
- **NICE Framework**: For workforce roles, knowledge, skills, and abilities.

### 2. Verification & Quality Assurance
To maintain data integrity, the system cross-references all identified codes against an official internal database. This verification step ensures that every mapped technique or skill is valid and accurately described, preventing errors in the final report.

## ✨ Key Capabilities

- **Automated Framework Mapping**: Instantly converts text into structured MITRE and NICE references.
- **Fact-Based Verification**: Validates all outputs against official definitions to ensure accuracy.
- **Customizable Focus**: Allows users to tailor the output to emphasize specific frameworks based on their reporting needs.
- **Batch Processing**: Supports processing of bulk data from files for efficient workflow management.

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
INPUT >> Massive ransomware attack
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
- `python-dotenv`
- `google-generativeai`
- A valid Google Gemini API Key.