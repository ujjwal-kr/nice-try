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