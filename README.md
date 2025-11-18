# Nice Try Deep Research Agent

This repository runs the **Hunter + Auditor** research loop using Google's Generative AI models. The service requires a valid `GEMINI_API_KEY`, which should never be checked into source control.

## Setup

1. Create a `.env` file next to the repository root and populate it from the example:
   ```bash
   cp .env.example .env
   ```
2. Edit `.env` and add your key:
   ```bash
   echo "GEMINI_API_KEY=your-real-gemini-key" > .env
   ```
3. Install dependencies:
   ```bash
   env/bin/pip install -r requirements.txt
   ```

## Running

Launch the agent:
```bash
env/bin/python main.py
```

The script will read `GEMINI_API_KEY` from the environment (or `.env` via `python-dotenv`). It exits early if the key is missing, protecting you from accidentally shipping secrets.

When interacting with the agent, you can also type `file` at the prompt to load the contents of a local file. The program will ask for the file path, read it in text mode (`"r"`), and use the file text as the input for the Hunter/Auditor loop. This keeps you from having to paste long logs directly into the console.

When running, the agent now asks whether to emphasize MITRE ATT&CK descriptions, Knowledge/Skill/Ability/Task mappings, or both. The final report highlights the selected focus with the requested KSA breakdown, omitting job-role listings entirely.